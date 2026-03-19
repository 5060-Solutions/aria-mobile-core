//! DNS SRV resolver for SIP server discovery (RFC 2782 / RFC 3263).
//!
//! Performs SRV lookups (`_sip._udp`, `_sip._tcp`, `_sips._tcp`) with
//! fallback to A/AAAA records. Results are cached with TTL.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::SRV;
use hickory_resolver::TokioAsyncResolver;

/// A resolved SIP server target with priority/weight from SRV records.
#[derive(Debug, Clone)]
pub struct SrvTarget {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
    pub addr: SocketAddr,
}

/// SIP transport type for SRV lookup name construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

/// Cached SRV result with expiry.
struct CacheEntry {
    targets: Vec<SrvTarget>,
    expires: Instant,
}

/// DNS SRV resolver with TTL-based caching.
pub struct SrvResolver {
    resolver: TokioAsyncResolver,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Timeout for individual DNS queries.
    query_timeout: Duration,
}

impl SrvResolver {
    /// Create a new resolver using system DNS configuration.
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 2;

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Self {
            resolver,
            cache: Mutex::new(HashMap::new()),
            query_timeout: Duration::from_secs(3),
        }
    }

    /// Resolve a SIP server domain using SRV records with A/AAAA fallback.
    ///
    /// Returns a list of resolved targets sorted by RFC 2782 priority (lowest
    /// first), then shuffled within each priority group by weight.
    ///
    /// If SRV lookup fails or times out, falls back to A/AAAA resolution
    /// with the given `fallback_port`.
    pub async fn resolve_sip_server(
        &self,
        domain: &str,
        transport: SipTransport,
        fallback_port: u16,
    ) -> Result<Vec<SrvTarget>, String> {
        let srv_name = match transport {
            SipTransport::Udp => format!("_sip._udp.{}", domain),
            SipTransport::Tcp => format!("_sip._tcp.{}", domain),
            SipTransport::Tls => format!("_sips._tcp.{}", domain),
        };

        // Check cache first
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(&srv_name) {
                if entry.expires > Instant::now() {
                    log::debug!("SRV cache hit for {}", srv_name);
                    return Ok(entry.targets.clone());
                }
            }
        }

        // Try SRV lookup with timeout
        let srv_result = tokio::time::timeout(
            self.query_timeout,
            self.lookup_srv(&srv_name),
        )
        .await;

        match srv_result {
            Ok(Ok(targets)) if !targets.is_empty() => {
                log::info!(
                    "SRV resolved {} -> {} targets (first: {}:{})",
                    srv_name,
                    targets.len(),
                    targets[0].host,
                    targets[0].port,
                );

                // Cache with 5 minute TTL
                self.cache_targets(&srv_name, &targets, Duration::from_secs(300));
                Ok(targets)
            }
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                // SRV failed or empty — fall back to A/AAAA
                if let Err(ref e) = srv_result {
                    log::debug!("SRV lookup timed out for {}: {}", srv_name, e);
                } else {
                    log::debug!("SRV lookup returned no results for {}", srv_name);
                }

                self.fallback_a_record(domain, fallback_port, &srv_name).await
            }
        }
    }

    /// Perform the actual SRV DNS query and resolve each target to an address.
    async fn lookup_srv(&self, srv_name: &str) -> Result<Vec<SrvTarget>, String> {
        let lookup = self
            .resolver
            .srv_lookup(srv_name)
            .await
            .map_err(|e| format!("SRV lookup failed for {}: {}", srv_name, e))?;

        let mut records: Vec<&SRV> = lookup.iter().collect();

        // Sort by priority (ascending), then by weight (descending) within same priority
        records.sort_by(|a, b| {
            a.priority()
                .cmp(&b.priority())
                .then_with(|| b.weight().cmp(&a.weight()))
        });

        let mut targets = Vec::new();

        for record in &records {
            let host = record.target().to_string().trim_end_matches('.').to_string();
            let port = record.port();

            // Resolve the SRV target hostname to an IP address
            match tokio::time::timeout(
                self.query_timeout,
                self.resolver.lookup_ip(&host),
            )
            .await
            {
                Ok(Ok(ips)) => {
                    if let Some(ip) = ips.iter().next() {
                        targets.push(SrvTarget {
                            host: host.clone(),
                            port,
                            priority: record.priority(),
                            weight: record.weight(),
                            addr: SocketAddr::new(ip, port),
                        });
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to resolve SRV target {}: {}", host, e);
                }
                Err(_) => {
                    log::warn!("Timeout resolving SRV target {}", host);
                }
            }
        }

        // RFC 2782 weighted selection within each priority group.
        // For simplicity we do a weighted shuffle: within each priority,
        // sort by weight descending so higher-weight targets come first.
        // A full RFC 2782 implementation would use randomized weighted
        // selection, but this is sufficient for failover.
        targets.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.weight.cmp(&a.weight))
        });

        Ok(targets)
    }

    /// Fallback: resolve the domain directly via A/AAAA records.
    async fn fallback_a_record(
        &self,
        domain: &str,
        port: u16,
        cache_key: &str,
    ) -> Result<Vec<SrvTarget>, String> {
        log::debug!("Falling back to A/AAAA record for {}:{}", domain, port);

        let addr_str = format!("{}:{}", domain, port);
        let resolved = tokio::time::timeout(
            self.query_timeout,
            tokio::net::lookup_host(&addr_str),
        )
        .await
        .map_err(|_| format!("DNS lookup timed out for {}", addr_str))?
        .map_err(|e| format!("DNS resolve failed for {}: {}", addr_str, e))?;

        let targets: Vec<SrvTarget> = resolved
            .map(|addr| SrvTarget {
                host: domain.to_string(),
                port,
                priority: 0,
                weight: 0,
                addr,
            })
            .collect();

        if targets.is_empty() {
            return Err(format!("No address found for {}", addr_str));
        }

        log::info!("A/AAAA resolved {} -> {}", addr_str, targets[0].addr);

        // Cache A-record fallback with shorter TTL (2 minutes)
        self.cache_targets(cache_key, &targets, Duration::from_secs(120));

        Ok(targets)
    }

    /// Store targets in the cache with a given TTL.
    fn cache_targets(&self, key: &str, targets: &[SrvTarget], ttl: Duration) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            key.to_string(),
            CacheEntry {
                targets: targets.to_vec(),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Clear the DNS cache (useful after network changes).
    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        log::debug!("DNS SRV cache cleared");
    }
}

/// Global shared resolver instance.
static RESOLVER: once_cell::sync::OnceCell<SrvResolver> = once_cell::sync::OnceCell::new();

/// Get or initialize the global SRV resolver.
pub fn resolver() -> &'static SrvResolver {
    RESOLVER.get_or_init(SrvResolver::new)
}

/// Convenience function: resolve a SIP server and return the best address.
///
/// This is the primary entry point used by `gateway_client` and registration
/// code. Returns the first (highest-priority) resolved address, or an error
/// if resolution fails entirely.
pub async fn resolve_sip_server(
    domain: &str,
    transport: SipTransport,
    fallback_port: u16,
) -> Result<Vec<SrvTarget>, String> {
    resolver()
        .resolve_sip_server(domain, transport, fallback_port)
        .await
}
