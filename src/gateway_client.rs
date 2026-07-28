//! HTTP client for the Aria push gateway REST API.
//!
//! When the gateway base URL contains a domain name, the client resolves it
//! via DNS SRV records before connecting. If the primary server fails, it
//! automatically tries the next target in the SRV priority list.

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::time::Duration;

use crate::dns;
use crate::types::*;

/// Maximum size of a gateway JSON response we will buffer. Gateway payloads are
/// small (tokens, SDP, call metadata); anything larger is treated as hostile.
/// Bounding this prevents a malicious or MITM'd gateway from OOM-ing the app by
/// streaming an unbounded body.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Read and deserialize a JSON response body, aborting if it exceeds
/// [`MAX_RESPONSE_BYTES`]. Rejects up front on an oversized declared
/// `Content-Length`, and also streams the body so a chunked response with no
/// (or a lying) `Content-Length` is capped as it arrives rather than after the
/// whole thing is buffered.
async fn read_json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, MobileError> {
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            log::warn!("gateway response declared {len} bytes, exceeds cap; rejecting");
            return Err(MobileError::GatewayError);
        }
    }

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| MobileError::NetworkError)?;
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            log::warn!("gateway response exceeded {MAX_RESPONSE_BYTES} byte cap; aborting");
            return Err(MobileError::GatewayError);
        }
        buf.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&buf).map_err(|_| MobileError::GatewayError)
}

pub struct GatewayClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
    /// Resolved gateway failover targets from SRV lookup, ordered by priority.
    /// First entry is the primary; rest are failover targets.
    resolved_targets: RwLock<Vec<ResolvedTarget>>,
}

/// A resolved SRV failover target.
///
/// The `url` keeps the **original gateway hostname** as its host so TLS SNI and
/// certificate validation are performed against the domain (matching the cert's
/// SANs), while `client` is pinned so the connection actually goes to the
/// resolved IP address. Building the URL as `https://<ip>:<port>` instead —
/// as the code previously did — makes rustls reject the certificate on a
/// hostname mismatch, which silently broke HTTPS failover entirely.
struct ResolvedTarget {
    url: String,
    client: reqwest::Client,
}

/// Build a failover URL that keeps `domain` as the host (so TLS validates
/// against it) using the target `port`. The port is omitted when it is the
/// scheme default, mirroring how the base URL is normally written.
fn build_target_url(scheme: &str, domain: &str, port: u16, path_prefix: &str) -> String {
    let is_tls = scheme == "https";
    let host_port = if (is_tls && port == 443) || (!is_tls && port == 80) {
        domain.to_string()
    } else {
        format!("{domain}:{port}")
    };
    format!("{scheme}://{host_port}{path_prefix}")
}

#[derive(Serialize)]
struct TokenRequest {
    user_id: String,
    api_key: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    /// Token lifetime in seconds, as reported by the gateway. Used by the
    /// caller to schedule a transparent refresh before expiry.
    expires_in: u64,
}

#[derive(Serialize)]
struct RegisterDeviceRequest {
    platform: String,
    push_token: String,
    bundle_id: Option<String>,
    sip_username: String,
    sip_password: String,
    sip_domain: String,
    sip_registrar: Option<String>,
    sip_transport: String,
    sip_port: u16,
    sip_auth_username: Option<String>,
    sip_display_name: String,
}

#[derive(Deserialize)]
struct RegisterDeviceResponse {
    device_id: String,
    #[allow(dead_code)]
    status: String,
}

#[derive(Deserialize)]
struct GatewayCallOffer {
    call_token: String,
    caller_uri: String,
    caller_name: Option<String>,
    sdp_offer: String,
}

#[derive(Serialize)]
struct AcceptCallRequest {
    sdp_answer: String,
}

#[derive(Serialize)]
struct MakeCallRequest {
    destination_uri: String,
    sdp_offer: String,
    sip_username: String,
    sip_password: String,
    sip_domain: String,
    sip_registrar: Option<String>,
    sip_transport: String,
    sip_port: u16,
    sip_auth_username: Option<String>,
    sip_display_name: String,
}

#[derive(Deserialize)]
struct MakeCallResponse {
    call_token: String,
    sdp_answer: String,
}

/// Enforce TLS on the gateway base URL to protect the SIP password and JWT
/// bearer token in transit. A `http://` URL to a non-loopback host is upgraded
/// to `https://` (an on-path attacker on a cleartext link could otherwise
/// capture full account credentials). Cleartext is tolerated only for local
/// development against loopback / `.local` hosts.
fn enforce_https(base_url: String) -> String {
    if let Some(rest) = base_url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        let is_local = host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host.ends_with(".local");
        if !is_local {
            log::warn!(
                "Gateway base_url used cleartext http://; upgrading to https:// to protect credentials"
            );
            return format!("https://{rest}");
        }
    }
    base_url
}

impl GatewayClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: enforce_https(base_url),
            api_key,
            http,
            resolved_targets: RwLock::new(Vec::new()),
        }
    }

    /// Build an HTTP client pinned so that `domain` resolves to `addr`. This
    /// lets us connect to a specific SRV-resolved IP while TLS still validates
    /// the certificate against the original hostname (SNI + cert SANs).
    fn build_pinned_client(domain: &str, addr: std::net::SocketAddr) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .resolve(domain, addr)
            .build()
            .expect("Failed to create pinned HTTP client")
    }

    /// Check if the api_key looks like a JWT (starts with "eyJ").
    pub fn api_key_is_jwt(&self) -> bool {
        self.api_key.starts_with("eyJ")
    }

    /// Get the raw api_key value.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// Select the (client, url) to use for a given failover target index.
    ///
    /// For a resolved SRV target this returns a client pinned to that target's
    /// IP together with a URL whose host is the original gateway domain, so TLS
    /// validation uses the domain while the connection reaches the resolved IP.
    /// Falls back to the base client and base_url when no targets are resolved.
    fn target_request(&self, target_idx: usize, path: &str) -> (reqwest::Client, String) {
        let resolved = self.resolved_targets.read().unwrap();
        if let Some(t) = resolved.get(target_idx) {
            (
                t.client.clone(),
                format!("{}{}", t.url.trim_end_matches('/'), path),
            )
        } else {
            (self.http.clone(), self.url(path))
        }
    }

    /// Resolve the gateway domain via SRV records and populate the
    /// `resolved_urls` list. Should be called once before the first API
    /// request (typically during `register_device`).
    ///
    /// The base_url is expected to be an HTTP(S) URL like
    /// `https://gateway.example.com` or `https://gateway.example.com:8443`.
    pub async fn resolve_gateway(&self) -> Result<(), String> {
        let url = match reqwest::Url::parse(&self.base_url) {
            Ok(u) => u,
            Err(_) => {
                log::debug!("Gateway base_url is not a parseable URL, skipping SRV resolution");
                return Ok(());
            }
        };

        let domain = match url.host_str() {
            Some(h) => h.to_string(),
            None => return Ok(()),
        };

        // If the host is already an IP address, skip SRV resolution
        if domain.parse::<std::net::IpAddr>().is_ok() {
            log::debug!("Gateway URL uses IP address, skipping SRV resolution");
            return Ok(());
        }

        let is_tls = url.scheme() == "https";
        let default_port = if is_tls { 443 } else { 80 };
        let port = url.port().unwrap_or(default_port);

        let transport = if is_tls {
            dns::SipTransport::Tls
        } else {
            dns::SipTransport::Tcp
        };

        match dns::resolve_sip_server(&domain, transport, port).await {
            Ok(targets) if !targets.is_empty() => {
                let scheme = url.scheme();
                let path_prefix = url.path().trim_end_matches('/');

                // For each SRV target, keep the ORIGINAL domain in the URL (so
                // TLS validates against it) and pin the client's DNS to the
                // resolved IP. This is what makes HTTPS failover work: a URL
                // with a bare IP host would fail rustls hostname verification.
                let resolved_targets: Vec<ResolvedTarget> = targets
                    .iter()
                    .map(|t| ResolvedTarget {
                        url: build_target_url(scheme, &domain, t.port, path_prefix),
                        client: Self::build_pinned_client(&domain, t.addr),
                    })
                    .collect();

                log::info!(
                    "Gateway SRV resolved {} -> {} targets (primary: {} via {})",
                    domain,
                    resolved_targets.len(),
                    resolved_targets[0].url,
                    targets[0].addr,
                );

                let mut resolved = self.resolved_targets.write().unwrap();
                *resolved = resolved_targets;
            }
            Ok(_) => {
                log::debug!("No SRV targets for gateway domain {}", domain);
            }
            Err(e) => {
                log::debug!("Gateway SRV resolution failed: {} (will use base_url directly)", e);
            }
        }

        Ok(())
    }

    /// Get the number of resolved gateway targets available for failover.
    #[allow(dead_code)]
    pub fn resolved_target_count(&self) -> usize {
        let resolved = self.resolved_targets.read().unwrap();
        if resolved.is_empty() { 1 } else { resolved.len() }
    }

    /// Obtain a JWT auth token from the gateway, with SRV failover.
    ///
    /// Returns the token together with its lifetime in seconds (`expires_in`)
    /// so the caller can schedule a transparent refresh before expiry.
    pub async fn create_token(&self, user_id: &str) -> Result<(String, u64), MobileError> {
        // Resolve gateway via SRV on first use
        let _ = self.resolve_gateway().await;

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let (client, url) = self.target_request(idx, "/v1/auth/token");
            match client
                .post(&url)
                .json(&TokenRequest {
                    user_id: user_id.to_string(),
                    api_key: self.api_key.clone(),
                })
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        log::error!("Token request failed: {}", resp.status());
                        return Err(MobileError::AuthenticationError);
                    }
                    let body: TokenResponse = read_json_capped(resp).await?;
                    return Ok((body.token, body.expires_in));
                }
                Err(e) => {
                    log::warn!("Token request to {} failed: {} (trying next)", url, e);
                    last_err = e.into();
                }
            }
        }

        Err(last_err)
    }

    /// Register a device with the push gateway, with SRV failover.
    ///
    /// The SIP registrar domain from the credentials is resolved via SRV
    /// to populate the `sip_registrar` field sent to the gateway, so the
    /// gateway knows which server to send SIP REGISTER to.
    pub async fn register_device(
        &self,
        token: &str,
        registration: &DeviceRegistration,
    ) -> Result<DeviceRegistrationResponse, MobileError> {
        // Let the gateway handle SIP registrar resolution itself —
        // passing a resolved IP:port can break the gateway's DNS parser.
        let req = RegisterDeviceRequest {
            platform: registration.platform.clone(),
            push_token: registration.push_token.clone(),
            bundle_id: registration.bundle_id.clone(),
            sip_username: registration.sip.username.clone(),
            sip_password: registration.sip.password.clone(),
            sip_domain: registration.sip.domain.clone(),
            sip_registrar: registration.sip.registrar.clone(),
            sip_transport: registration.sip.transport.clone(),
            sip_port: registration.sip.port,
            sip_auth_username: registration.sip.auth_username.clone(),
            sip_display_name: registration.sip.display_name.clone(),
        };

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let (client, url) = self.target_request(idx, "/v1/devices");
            match client
                .post(&url)
                .bearer_auth(token)
                .json(&req)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        log::error!("Device registration failed: {}", resp.status());
                        return Err(MobileError::RegistrationFailed);
                    }
                    let body: RegisterDeviceResponse = read_json_capped(resp).await?;
                    return Ok(DeviceRegistrationResponse {
                        device_id: body.device_id,
                        auth_token: token.to_string(),
                    });
                }
                Err(e) => {
                    log::warn!("Device registration to {} failed: {} (trying next)", url, e);
                    last_err = e.into();
                }
            }
        }

        Err(last_err)
    }



    /// Send a device heartbeat — forces SIP re-registration after network change.
    pub async fn device_heartbeat(
        &self,
        token: &str,
        device_id: &str,
    ) -> Result<(), MobileError> {
        let target_count = self.resolved_target_count();
        for idx in 0..target_count {
            let (client, url) =
                self.target_request(idx, &format!("/v1/devices/{}/heartbeat", device_id));
            match client.post(&url).bearer_auth(token).send().await {
                Ok(resp) if resp.status().is_success() || resp.status() == 204 => {
                    log::info!("Device heartbeat successful for {}", device_id);
                    return Ok(());
                }
                Ok(resp) => {
                    log::warn!("Device heartbeat failed: {}", resp.status());
                }
                Err(e) => {
                    log::warn!("Device heartbeat to {} failed: {}", url, e);
                }
            }
        }
        Err(MobileError::NetworkError)
    }

    /// Unregister a device.
    pub async fn unregister_device(
        &self,
        token: &str,
        device_id: &str,
    ) -> Result<(), MobileError> {
        let resp = self
            .http
            .delete(self.url(&format!("/v1/devices/{}", device_id)))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Device unregister failed: {}", resp.status());
            return Err(MobileError::GatewayError);
        }

        Ok(())
    }

    /// Get the call offer for a pending incoming call.
    pub async fn get_call_offer(
        &self,
        token: &str,
        call_token: &str,
    ) -> Result<CallOffer, MobileError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/calls/{}", call_token)))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Get call offer failed: {}", resp.status());
            return Err(MobileError::CallFailed);
        }

        let body: GatewayCallOffer = read_json_capped(resp).await?;
        Ok(CallOffer {
            call_token: body.call_token,
            caller_uri: body.caller_uri,
            caller_name: body.caller_name,
            sdp_offer: body.sdp_offer,
        })
    }

    /// Accept an incoming call by sending the SDP answer.
    pub async fn accept_call(
        &self,
        token: &str,
        call_token: &str,
        sdp_answer: &str,
    ) -> Result<(), MobileError> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/calls/{}/accept", call_token)))
            .bearer_auth(token)
            .json(&AcceptCallRequest {
                sdp_answer: sdp_answer.to_string(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Accept call failed: {}", resp.status());
            return Err(MobileError::CallFailed);
        }

        Ok(())
    }

    /// Reject an incoming call.
    pub async fn reject_call(
        &self,
        token: &str,
        call_token: &str,
    ) -> Result<(), MobileError> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/calls/{}/reject", call_token)))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Reject call failed: {}", resp.status());
            return Err(MobileError::CallFailed);
        }

        Ok(())
    }

    /// Initiate an outgoing call via the gateway, with SRV failover.
    /// The gateway acts as a B2BUA — it sends the SIP INVITE on our behalf
    /// and returns the SDP answer from the remote party.
    pub async fn make_call(
        &self,
        token: &str,
        destination_uri: &str,
        sdp_offer: &str,
        credentials: &crate::types::SipCredentials,
    ) -> Result<(String, String), MobileError> {
        // Let the gateway handle DNS resolution — passing pre-resolved
        // IP:port breaks the gateway's DNS parser.
        let req = MakeCallRequest {
            destination_uri: destination_uri.to_string(),
            sdp_offer: sdp_offer.to_string(),
            sip_username: credentials.username.clone(),
            sip_password: credentials.password.clone(),
            sip_domain: credentials.domain.clone(),
            sip_registrar: credentials.registrar.clone(),
            sip_transport: credentials.transport.clone(),
            sip_port: credentials.port,
            sip_auth_username: credentials.auth_username.clone(),
            sip_display_name: credentials.display_name.clone(),
        };

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let (client, url) = self.target_request(idx, "/v1/calls");
            match client
                .post(&url)
                .bearer_auth(token)
                .json(&req)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        log::error!("Make call failed: {}", resp.status());
                        return Err(MobileError::CallFailed);
                    }
                    let body: MakeCallResponse = read_json_capped(resp).await?;
                    return Ok((body.call_token, body.sdp_answer));
                }
                Err(e) => {
                    log::warn!("Make call to {} failed: {} (trying next)", url, e);
                    last_err = e.into();
                }
            }
        }

        Err(last_err)
    }

    /// Poll the status of a call. Returns "active", "ended", "cancelled", etc.
    pub async fn get_call_status(
        &self,
        token: &str,
        call_token: &str,
    ) -> Result<CallStatusResponse, MobileError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/calls/{}/status", call_token)))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(MobileError::CallFailed);
        }

        let body: CallStatusResponse = read_json_capped(resp).await?;
        Ok(body)
    }

    /// Hang up an active call via the gateway.
    pub async fn hangup_call(
        &self,
        token: &str,
        call_token: &str,
    ) -> Result<(), MobileError> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/calls/{}/hangup", call_token)))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Hangup call failed: {}", resp.status());
            return Err(MobileError::CallFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test for the SRV-failover TLS hostname bug: failover URLs must
    // keep the ORIGINAL domain as the host (never a bare IP), otherwise rustls
    // rejects the certificate on a hostname mismatch and HTTPS failover breaks.
    #[test]
    fn failover_url_keeps_domain_not_ip() {
        // Default TLS port -> host only, no explicit port.
        assert_eq!(
            build_target_url("https", "gw.example.com", 443, ""),
            "https://gw.example.com"
        );
        // Non-default TLS port -> domain:port, path preserved.
        assert_eq!(
            build_target_url("https", "gw.example.com", 8443, "/api"),
            "https://gw.example.com:8443/api"
        );
        // Default plain-HTTP port -> host only.
        assert_eq!(
            build_target_url("http", "gw.local", 80, ""),
            "http://gw.local"
        );
        // Non-default plain-HTTP port -> domain:port.
        assert_eq!(
            build_target_url("http", "127.0.0.1", 8080, ""),
            "http://127.0.0.1:8080"
        );
    }

    // The pinned client must build successfully so TLS can validate against the
    // domain while connecting to the resolved IP.
    #[test]
    fn pinned_client_builds() {
        let addr: std::net::SocketAddr = "203.0.113.10:443".parse().unwrap();
        let _ = GatewayClient::build_pinned_client("gw.example.com", addr);
    }
}
