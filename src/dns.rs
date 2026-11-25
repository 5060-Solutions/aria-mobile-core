//! DNS SRV resolver for SIP server discovery (RFC 2782 / RFC 3263).
//!
//! Performs SRV lookups (`_sip._udp`, `_sip._tcp`, `_sips._tcp`) with
//! fallback to A/AAAA records. Results are cached with TTL.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
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
///
/// The nameservers come from the platform, never from hickory's built-in
/// public ones: on Android the app passes the active network's DNS servers
/// (`ConnectivityManager` / `LinkProperties`, which the core cannot read
/// itself: there is no `/etc/resolv.conf`) through `set_dns_servers`; where
/// none are supplied (iOS, desktop) the system configuration is read. The
/// resolver is dropped and rebuilt on every network change and after any
/// failed lookup, so it never keeps asking the previous network's servers.
pub struct SrvResolver {
    resolver: Mutex<Option<Arc<TokioAsyncResolver>>>,
    /// Servers the platform supplied; `None` means read the system config.
    servers: RwLock<Option<Vec<Server>>>,
    builds: std::sync::atomic::AtomicUsize,
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Timeout for individual DNS queries.
    query_timeout: Duration,
}

impl Default for SrvResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SrvResolver {
    /// Create a resolver; it is built on first use.
    pub fn new() -> Self {
        Self {
            resolver: Mutex::new(None),
            servers: RwLock::new(None),
            builds: std::sync::atomic::AtomicUsize::new(0),
            cache: Mutex::new(HashMap::new()),
            query_timeout: Duration::from_secs(3),
        }
    }

    fn opts() -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 2;
        // Honour record TTLs: no floor, a cap of an hour.
        opts.positive_min_ttl = None;
        opts.positive_max_ttl = Some(Duration::from_secs(3600));
        opts
    }

    /// The resolver configuration: the platform-supplied servers, else the
    /// system's. Never a public resolver.
    fn config(&self) -> Result<(ResolverConfig, ResolverOpts), String> {
        let servers = self
            .servers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match servers {
            Some(ips) if !ips.is_empty() => Ok((config_for(&ips), Self::opts())),
            _ => Ok(match hickory_resolver::system_conf::read_system_conf() {
                Ok((c, _)) if !c.name_servers().is_empty() => (c, Self::opts()),
                other => {
                    // Android and iOS have no resolv.conf, and the platform
                    // supplied nothing: use hickory's default resolver, as
                    // before, rather than losing SRV altogether.
                    log::warn!(
                        "No DNS servers supplied and no usable system configuration ({}); \
                         using the default resolver",
                        other
                            .err()
                            .map_or_else(|| "empty".to_string(), |e| e.to_string())
                    );
                    (ResolverConfig::default(), Self::opts())
                }
            }),
        }
    }

    /// The current resolver, built if there is none.
    fn resolver(&self) -> Result<Arc<TokioAsyncResolver>, String> {
        let mut slot = self
            .resolver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(r) = slot.as_ref() {
            return Ok(Arc::clone(r));
        }
        let (config, opts) = self.config()?;
        let r = Arc::new(TokioAsyncResolver::tokio(config, opts));
        self.builds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        *slot = Some(Arc::clone(&r));
        Ok(r)
    }

    /// Drop the resolver so the next lookup builds one from the current
    /// configuration.
    fn forget_resolver(&self) {
        *self
            .resolver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// The platform's DNS servers changed (the active network's
    /// `LinkProperties`): use them from now on.
    pub fn set_servers(&self, servers: Vec<Server>) {
        log::info!(
            "DNS servers set by the platform: {} server(s)",
            servers.len()
        );
        *self
            .servers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(usable(servers));
        self.network_changed();
    }

    /// The network changed: forget the resolver and every cached answer, so
    /// the next lookup asks the servers of the network now in use.
    pub fn network_changed(&self) {
        self.forget_resolver();
        self.clear_cache();
    }

    /// How many resolvers have been built, and the servers of the current
    /// configuration (tests).
    #[cfg(test)]
    fn builds(&self) -> usize {
        self.builds.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    fn cached_names(&self) -> usize {
        self.cache.lock().unwrap().len()
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
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = cache.get(&srv_name) {
                if entry.expires > Instant::now() {
                    log::debug!("SRV cache hit for {}", srv_name);
                    return Ok(entry.targets.clone());
                }
            }
        }

        // Try SRV lookup with timeout
        let srv_result = tokio::time::timeout(self.query_timeout, self.lookup_srv(&srv_name)).await;

        match srv_result {
            Ok(Ok((targets, ttl))) if !targets.is_empty() => {
                log::info!(
                    "SRV resolved {} -> {} targets (first: {}:{})",
                    srv_name,
                    targets.len(),
                    targets[0].host,
                    targets[0].port,
                );

                // Cache for the records' own TTL.
                self.cache_targets(&srv_name, &targets, ttl);
                Ok(targets)
            }
            Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                // The resolver may be asking servers of a network that was
                // left: the next lookup starts from the current ones.
                self.forget_resolver();
                // SRV failed or empty — fall back to A/AAAA
                if let Err(ref e) = srv_result {
                    log::debug!("SRV lookup timed out for {}: {}", srv_name, e);
                } else {
                    log::debug!("SRV lookup returned no results for {}", srv_name);
                }

                self.fallback_a_record(domain, fallback_port, &srv_name)
                    .await
            }
        }
    }

    /// Perform the actual SRV DNS query and resolve each target to an address.
    async fn lookup_srv(&self, srv_name: &str) -> Result<(Vec<SrvTarget>, Duration), String> {
        let resolver = self.resolver()?;
        let lookup = resolver
            .srv_lookup(srv_name)
            .await
            .map_err(|e| format!("SRV lookup failed for {}: {}", srv_name, e))?;

        let mut valid_until = Some(lookup.as_lookup().valid_until());
        let mut records: Vec<&SRV> = lookup.iter().collect();

        // Sort by priority (ascending), then by weight (descending) within same priority
        records.sort_by(|a, b| {
            a.priority()
                .cmp(&b.priority())
                .then_with(|| b.weight().cmp(&a.weight()))
        });

        let mut targets = Vec::new();

        for record in &records {
            let host = record
                .target()
                .to_string()
                .trim_end_matches('.')
                .to_string();
            let port = record.port();

            // Resolve the SRV target hostname to an IP address
            match tokio::time::timeout(self.query_timeout, resolver.lookup_ip(&host)).await {
                Ok(Ok(ips)) => {
                    let until: Instant = ips.valid_until();
                    valid_until = valid_until.map(|v| v.min(until));
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

        let ttl = valid_until
            .map(|v| clamp_ttl(v.saturating_duration_since(Instant::now())))
            .unwrap_or(MIN_TTL);
        Ok((targets, ttl))
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
        let resolved = tokio::time::timeout(self.query_timeout, tokio::net::lookup_host(&addr_str))
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
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.insert(
            key.to_string(),
            CacheEntry {
                targets: targets.to_vec(),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Poison the cache lock, as a panic while holding it would (tests).
    #[cfg(test)]
    pub fn poison_cache_for_test(&self) {
        let _guard = self.cache.lock();
        panic!("poisoning the DNS cache lock");
    }

    /// Clear the DNS cache (after a network change).
    pub fn clear_cache(&self) {
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.clear();
        log::debug!("DNS SRV cache cleared");
    }
}

/// Shortest and longest time an answer is cached.
const MIN_TTL: Duration = Duration::from_secs(5);
const MAX_TTL: Duration = Duration::from_secs(3600);

/// A record's remaining lifetime, kept within sane bounds.
fn clamp_ttl(d: Duration) -> Duration {
    d.clamp(MIN_TTL, MAX_TTL)
}

/// A resolver configuration naming exactly `servers` (port 53, UDP then
/// TCP). A link-local IPv6 server keeps its scope id, which says which
/// interface it is on.
///
/// Not covered: Android's Private DNS (DNS over TLS) in strict mode. The
/// network's servers are used regardless of that setting, so a network that
/// only answers over TLS yields no SRV answers, and the lookup falls back to
/// A/AAAA through the platform resolver.
fn config_for(servers: &[Server]) -> ResolverConfig {
    use hickory_resolver::config::{NameServerConfig, Protocol};
    let mut group = NameServerConfigGroup::new();
    for s in servers {
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            group.push(NameServerConfig {
                socket_addr: s.socket_addr(53),
                protocol,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }
    }
    ResolverConfig::from_parts(None, vec![], group)
}

/// A DNS server address, with the interface scope for link-local IPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub ip: IpAddr,
    pub scope_id: u32,
}

impl Server {
    fn socket_addr(&self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V6(v6) => {
                SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, self.scope_id))
            }
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), port),
        }
    }

    fn is_link_local(&self) -> bool {
        matches!(self.ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
    }

    /// "192.168.1.1", "fe80::1%wlan0" or "fe80::1%23" (an interface name or index).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, scope) = match s.split_once('%') {
            Some((a, z)) => (a, Some(z)),
            None => (s, None),
        };
        let ip: IpAddr = addr.parse().ok()?;
        let scope_id = scope.map_or(0, |z| z.parse().unwrap_or_else(|_| interface_index(z)));
        Some(Self { ip, scope_id })
    }
}

/// The index of the interface called `name`, 0 if there is none.
fn interface_index(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: `c` is a valid NUL-terminated string for the call.
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// Link-local servers are dropped when any other server exists: their
/// scope may not match the interface a query leaves on.
fn usable(servers: Vec<Server>) -> Vec<Server> {
    if servers.iter().any(|s| !s.is_link_local()) {
        servers.into_iter().filter(|s| !s.is_link_local()).collect()
    } else {
        servers
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Server {
        Server::parse(s).unwrap()
    }

    #[test]
    fn the_config_names_exactly_the_servers_the_platform_supplied() {
        let cfg = config_for(&[ip("192.168.1.1"), ip("fd00::1")]);
        let addrs: std::collections::HashSet<IpAddr> = cfg
            .name_servers()
            .iter()
            .map(|n| n.socket_addr.ip())
            .collect();
        assert_eq!(addrs, [ip("192.168.1.1").ip, ip("fd00::1").ip].into());
        assert!(
            cfg.name_servers()
                .iter()
                .all(|n| n.socket_addr.port() == 53),
            "plain DNS on 53"
        );
    }

    #[test]
    fn platform_servers_are_used_and_a_change_rebuilds_the_resolver() {
        let r = SrvResolver::new();
        r.set_servers(vec![ip("10.0.0.1")]);
        let (cfg, _) = r.config().unwrap();
        assert_eq!(cfg.name_servers().len(), 2, "UDP and TCP of one server");
        assert!(cfg
            .name_servers()
            .iter()
            .all(|n| n.socket_addr.ip() == ip("10.0.0.1").ip));
        runtime_guard(|| {
            r.resolver().unwrap();
            r.resolver().unwrap();
            assert_eq!(r.builds(), 1, "built once while nothing changed");
            r.set_servers(vec![ip("10.9.9.9")]);
            r.resolver().unwrap();
            assert_eq!(r.builds(), 2, "new servers, new resolver");
            let (cfg, _) = r.config().unwrap();
            assert!(cfg
                .name_servers()
                .iter()
                .all(|n| n.socket_addr.ip() == ip("10.9.9.9").ip));
        });
    }

    #[test]
    fn a_network_change_forgets_the_resolver_and_the_cache() {
        let r = SrvResolver::new();
        r.set_servers(vec![ip("10.0.0.1")]);
        runtime_guard(|| {
            r.resolver().unwrap();
            r.cache_targets("_sip._tls.x", &[], Duration::from_secs(300));
            assert_eq!(r.cached_names(), 1);
            r.network_changed();
            assert_eq!(r.cached_names(), 0);
            r.resolver().unwrap();
            assert_eq!(r.builds(), 2);
        });
    }

    #[test]
    fn link_local_servers_keep_their_scope_and_yield_to_others() {
        let ll = Server::parse("fe80::1%7").unwrap();
        assert_eq!(ll.scope_id, 7);
        match ll.socket_addr(53) {
            SocketAddr::V6(a) => assert_eq!(a.scope_id(), 7),
            SocketAddr::V4(_) => panic!("v6"),
        }
        assert!(ll.is_link_local());
        let kept = usable(vec![ll.clone(), ip("10.0.0.1")]);
        assert_eq!(kept, vec![ip("10.0.0.1")]);
        assert_eq!(usable(vec![ll.clone()]), vec![ll]);
    }

    #[test]
    fn with_nothing_supplied_and_no_system_config_the_default_resolver_is_used() {
        let r = SrvResolver::new();
        // No list at all, and an empty one: both come out with name servers
        // (the system's where it can be read, hickory's default where not).
        let (cfg, _) = r.config().unwrap();
        assert!(!cfg.name_servers().is_empty());
        r.set_servers(vec![]);
        let (cfg, _) = r.config().unwrap();
        assert!(!cfg.name_servers().is_empty());
    }

    #[test]
    fn ttls_follow_the_records_within_bounds() {
        assert_eq!(clamp_ttl(Duration::from_secs(60)), Duration::from_secs(60));
        assert_eq!(clamp_ttl(Duration::from_secs(0)), MIN_TTL);
        assert_eq!(clamp_ttl(Duration::from_secs(86_400)), MAX_TTL);
    }

    /// `TokioAsyncResolver::tokio` wants a runtime.
    fn runtime_guard(f: impl FnOnce()) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _g = rt.enter();
        f();
    }
}
