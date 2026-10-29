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

/// The error for a failed gateway response: `AuthenticationError` when the
/// gateway rejected the bearer token (401), otherwise `otherwise`.
///
/// A 401 always means the token is missing, expired or revoked, and the app
/// must fetch a new one from the PBX, so every route reports it the same way.
fn status_error(status: reqwest::StatusCode, otherwise: MobileError) -> MobileError {
    if status == reqwest::StatusCode::UNAUTHORIZED {
        MobileError::AuthenticationError
    } else {
        otherwise
    }
}

pub struct GatewayClient {
    base_url: String,
    http: reqwest::Client,
    /// Resolved gateway failover targets from SRV lookup, ordered by priority.
    /// First entry is the primary; rest are failover targets.
    ///
    /// Each keeps the **original gateway hostname** as its URL host so TLS SNI
    /// and certificate validation are performed against the domain, while its
    /// client is pinned so the connection goes to the resolved IP address.
    /// Building the URL as `https://<ip>:<port>` instead makes rustls reject
    /// the certificate on a hostname mismatch, which broke HTTPS failover.
    resolved_targets: RwLock<Vec<Route>>,
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
    /// Our reference for the call, so it can be cancelled while it rings,
    /// before the gateway has assigned a call token.
    client_ref: String,
}

/// The JSON body of a gateway error response.
#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Serialize)]
struct CancelCallRequest<'a> {
    client_ref: &'a str,
}

#[derive(Serialize)]
struct TransferCallRequest<'a> {
    target: &'a str,
}

/// The body of an attended transfer: the token of the other call.
#[derive(Serialize)]
struct AttendedTransferRequest<'a> {
    replaces: &'a str,
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
        // Take the authority, then drop any userinfo before reading the host.
        //
        // Splitting straight on ':' treated "localhost:80@evil.example.com" as
        // the host "localhost", so the loopback exemption applied and the URL
        // was left cleartext — while reqwest's WHATWG parser resolves the real
        // host as evil.example.com. base_url comes from the PBX's device
        // registration response, and the bodies sent to it carry the SIP
        // password in the clear, so this handed an attacker those credentials
        // over plain HTTP.
        let authority = rest.split('/').next().unwrap_or("");
        let host_port = authority.rsplit('@').next().unwrap_or("");
        let host = host_port.split(':').next().unwrap_or("");
        let is_local =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".local");
        // Userinfo has no business in a gateway URL; if it is present, do not
        // grant the exemption whatever the host looks like.
        let has_userinfo = authority.contains('@');
        if !is_local || has_userinfo {
            log::warn!(
                "Gateway base_url used cleartext http://; upgrading to https:// to protect credentials"
            );
            return format!("https://{rest}");
        }
    }
    base_url
}

/// One gateway instance: the base URL requests to it use, and a client that
/// connects to it.
///
/// For an SRV target the URL keeps the gateway's domain (so TLS validates
/// against it) while the client is pinned to the resolved address. Calls live
/// on one gateway instance, so everything about a call after it is placed or
/// offered (accept, reject, cancel, status, hangup, transfer) is sent on the
/// route that placed or offered it, never re-chosen.
#[derive(Clone)]
pub struct Route {
    url: String,
    client: reqwest::Client,
}

impl std::fmt::Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Route").field(&self.url).finish()
    }
}

impl Route {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.url.trim_end_matches('/'), path)
    }

    /// The base URL this route sends to.
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.url
    }
}

/// Where `make_call` places a call, and how it reports the attempt.
pub struct Placement<'a> {
    /// Sent with the call so it can be cancelled before it has a token.
    pub client_ref: &'a str,
    /// Set to each route before the request is sent on it, so a cancel
    /// issued while the request is in flight goes to the instance ringing
    /// the call.
    pub attempt: &'a std::sync::Mutex<Option<Route>>,
    /// Place the call on this route only, with no failover: if it cannot be
    /// reached the call fails. `None` tries every route in turn.
    pub pin: Option<&'a Route>,
}

impl<'a> Placement<'a> {
    /// A placement on any route, failing over on connect errors.
    #[cfg(test)]
    pub fn any(client_ref: &'a str, attempt: &'a std::sync::Mutex<Option<Route>>) -> Self {
        Self {
            client_ref,
            attempt,
            pin: None,
        }
    }
}

/// How long `POST /v1/calls` may take. Longer than the gateway's 30 s INVITE
/// timeout, so the gateway, not the client, decides that an unanswered call
/// has failed; a client that gave up first would orphan a call answered at
/// the last moment.
const MAKE_CALL_TIMEOUT: Duration = Duration::from_secs(45);

/// How long a hangup request may take. It runs in the background after the
/// call has already ended locally, so it must not hang around.
pub const HANGUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Default timeout for every other request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

impl GatewayClient {
    pub fn new(base_url: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: enforce_https(base_url),
            http,
            resolved_targets: RwLock::new(Vec::new()),
        }
    }

    /// Build an HTTP client pinned so that `domain` resolves to `addr`. This
    /// lets us connect to a specific SRV-resolved IP while TLS still validates
    /// the certificate against the original hostname (SNI + cert SANs).
    fn build_pinned_client(domain: &str, addr: std::net::SocketAddr) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .resolve(domain, addr)
            .build()
            .expect("Failed to create pinned HTTP client")
    }

    /// The routes to try, in priority order: the SRV targets when resolved,
    /// otherwise the base URL alone.
    pub fn routes(&self) -> Vec<Route> {
        let resolved = self
            .resolved_targets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if resolved.is_empty() {
            vec![self.primary_route()]
        } else {
            resolved.clone()
        }
    }

    /// Replace the failover routes, standing in for SRV resolution in tests.
    #[cfg(test)]
    pub fn set_test_routes(&self, urls: &[&str]) {
        *self.resolved_targets.write().unwrap() = urls
            .iter()
            .map(|u| Route {
                url: u.to_string(),
                client: self.http.clone(),
            })
            .collect();
    }

    /// The base URL as a route, for calls whose instance is not known.
    pub fn primary_route(&self) -> Route {
        let resolved = self
            .resolved_targets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        resolved.first().cloned().unwrap_or_else(|| Route {
            url: self.base_url.clone(),
            client: self.http.clone(),
        })
    }

    /// Send a request on each route in turn until one is connected to.
    ///
    /// Moves to the next route only when the connection could not be
    /// established, so the request was certainly never delivered. Any later
    /// failure (a timeout, a reset after sending) is returned as is: the
    /// request may have reached the gateway, and sending a non-idempotent
    /// request such as `POST /v1/calls` again could act twice, ringing the
    /// callee twice. Returns the response and the route that produced it.
    async fn send(
        &self,
        what: &str,
        build: impl Fn(&Route) -> reqwest::RequestBuilder,
    ) -> Result<(reqwest::Response, Route), MobileError> {
        Self::send_on(self.routes(), what, build).await
    }

    /// [`send`](Self::send) over the given routes rather than all of them.
    async fn send_on(
        routes: Vec<Route>,
        what: &str,
        build: impl Fn(&Route) -> reqwest::RequestBuilder,
    ) -> Result<(reqwest::Response, Route), MobileError> {
        let mut last_err = MobileError::NetworkError;
        for route in routes {
            match build(&route).send().await {
                Ok(resp) => return Ok((resp, route)),
                Err(e) if e.is_connect() => {
                    log::warn!(
                        "{what}: could not connect to {} ({e}); trying next",
                        route.url
                    );
                    last_err = e.into();
                }
                Err(e) => {
                    log::warn!("{what} to {} failed: {e}", route.url);
                    return Err(e.into());
                }
            }
        }
        Err(last_err)
    }

    /// Resolve the gateway domain via SRV records and populate the
    /// failover routes. Called before registering.
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
                let routes: Vec<Route> = targets
                    .iter()
                    .map(|t| Route {
                        url: build_target_url(scheme, &domain, t.port, path_prefix),
                        client: Self::build_pinned_client(&domain, t.addr),
                    })
                    .collect();

                log::info!(
                    "Gateway SRV resolved {} -> {} targets (primary: {} via {})",
                    domain,
                    routes.len(),
                    routes[0].url,
                    targets[0].addr,
                );

                *self
                    .resolved_targets
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = routes;
            }
            Ok(_) => {
                log::debug!("No SRV targets for gateway domain {}", domain);
            }
            Err(e) => {
                log::debug!(
                    "Gateway SRV resolution failed: {} (will use base_url directly)",
                    e
                );
            }
        }

        Ok(())
    }

    /// Register a device with the push gateway, with SRV failover.
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

        let (resp, _) = self
            .send("Device registration", |r| {
                r.client
                    .post(r.url("/v1/devices"))
                    .bearer_auth(token)
                    .json(&req)
            })
            .await?;
        if !resp.status().is_success() {
            log::error!("Device registration failed: {}", resp.status());
            return Err(status_error(resp.status(), MobileError::RegistrationFailed));
        }
        let body: RegisterDeviceResponse = read_json_capped(resp).await?;
        Ok(DeviceRegistrationResponse {
            device_id: body.device_id,
            auth_token: token.to_string(),
        })
    }

    /// Send a device heartbeat — forces SIP re-registration after network change.
    pub async fn device_heartbeat(&self, token: &str, device_id: &str) -> Result<(), MobileError> {
        let path = format!("/v1/devices/{device_id}/heartbeat");
        let (resp, _) = self
            .send("Device heartbeat", |r| {
                r.client.post(r.url(&path)).bearer_auth(token)
            })
            .await?;
        if resp.status().is_success() {
            log::info!("Device heartbeat successful for {}", device_id);
            return Ok(());
        }
        log::warn!("Device heartbeat failed: {}", resp.status());
        Err(status_error(resp.status(), MobileError::NetworkError))
    }

    /// Unregister a device.
    pub async fn unregister_device(&self, token: &str, device_id: &str) -> Result<(), MobileError> {
        let path = format!("/v1/devices/{device_id}");
        let (resp, _) = self
            .send("Device unregister", |r| {
                r.client.delete(r.url(&path)).bearer_auth(token)
            })
            .await?;

        if !resp.status().is_success() {
            log::error!("Device unregister failed: {}", resp.status());
            return Err(status_error(resp.status(), MobileError::GatewayError));
        }

        Ok(())
    }

    /// Get the call offer for a pending incoming call, together with the
    /// route of the gateway instance that holds it.
    pub async fn get_call_offer(
        &self,
        token: &str,
        call_token: &str,
    ) -> Result<(CallOffer, Route), MobileError> {
        let path = format!("/v1/calls/{call_token}");
        let (resp, route) = self
            .send("Get call offer", |r| {
                r.client.get(r.url(&path)).bearer_auth(token)
            })
            .await?;

        if !resp.status().is_success() {
            log::error!("Get call offer failed: {}", resp.status());
            return Err(status_error(
                resp.status(),
                MobileError::CallFailed(format!("no call offer (HTTP {})", resp.status())),
            ));
        }

        let body: GatewayCallOffer = read_json_capped(resp).await?;
        Ok((
            CallOffer {
                call_token: body.call_token,
                caller_uri: body.caller_uri,
                caller_name: body.caller_name,
                sdp_offer: body.sdp_offer,
            },
            route,
        ))
    }

    /// Accept an incoming call by sending the SDP answer.
    pub async fn accept_call(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
        sdp_answer: &str,
    ) -> Result<(), MobileError> {
        let resp = route
            .client
            .post(route.url(&format!("/v1/calls/{call_token}/accept")))
            .bearer_auth(token)
            .json(&AcceptCallRequest {
                sdp_answer: sdp_answer.to_string(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Accept call failed: {}", resp.status());
            return Err(status_error(
                resp.status(),
                MobileError::CallFailed(format!("accept refused (HTTP {})", resp.status())),
            ));
        }

        Ok(())
    }

    /// Reject an incoming call.
    pub async fn reject_call(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
    ) -> Result<(), MobileError> {
        let resp = route
            .client
            .post(route.url(&format!("/v1/calls/{call_token}/reject")))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Reject call failed: {}", resp.status());
            return Err(status_error(
                resp.status(),
                MobileError::CallFailed(format!("reject refused (HTTP {})", resp.status())),
            ));
        }

        Ok(())
    }

    /// Initiate an outgoing call via the gateway, with SRV failover on
    /// connect errors only. The gateway acts as a B2BUA — it sends the SIP
    /// INVITE on our behalf and returns the SDP answer from the remote party.
    ///
    /// See [`Placement`] for where the call goes. Returns the call token, the
    /// SDP answer, and the route.
    pub async fn make_call(
        &self,
        token: &str,
        destination_uri: &str,
        sdp_offer: &str,
        credentials: &crate::types::SipCredentials,
        placement: Placement<'_>,
    ) -> Result<(String, String, Route), MobileError> {
        let Placement {
            client_ref,
            attempt,
            pin,
        } = placement;
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
            client_ref: client_ref.to_string(),
        };

        let routes = match pin {
            Some(route) => vec![route.clone()],
            None => self.routes(),
        };
        let (resp, route) = Self::send_on(routes, "Make call", |r| {
            *attempt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(r.clone());
            r.client
                .post(r.url("/v1/calls"))
                .timeout(MAKE_CALL_TIMEOUT)
                .bearer_auth(token)
                .json(&req)
        })
        .await?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            // 409 carries a reason. Only `cancelled` means the call was
            // cancelled through `cancel_call` while it rang; anything else
            // (such as `client_ref_in_use`) is a gateway-side refusal.
            let body: Option<ErrorBody> = read_json_capped(resp).await.ok();
            return Err(match body.as_ref().map(|b| b.error.as_str()) {
                Some("cancelled") => {
                    log::info!("Outgoing call cancelled at the gateway");
                    MobileError::Cancelled
                }
                other => {
                    log::error!("Make call refused with 409: {:?}", other);
                    MobileError::GatewayError
                }
            });
        }
        if !resp.status().is_success() {
            log::error!("Make call failed: {}", resp.status());
            return Err(status_error(
                resp.status(),
                MobileError::CallFailed(format!(
                    "the call did not connect (HTTP {})",
                    resp.status()
                )),
            ));
        }
        let body: MakeCallResponse = read_json_capped(resp).await?;
        Ok((body.call_token, body.sdp_answer, route))
    }

    /// Cancel an outgoing call that is still ringing, by the `client_ref` it
    /// was placed with. The gateway sends a SIP CANCEL and the blocked
    /// `make_call` then fails with `Cancelled` (HTTP 409).
    ///
    /// Returns `Ok(true)` when the gateway sent the CANCEL (202) and
    /// `Ok(false)` when it has no ringing call with that ref (404): not
    /// registered yet, already answered, unknown, or a gateway that predates
    /// the route.
    pub async fn cancel_call(
        &self,
        route: &Route,
        token: &str,
        client_ref: &str,
    ) -> Result<bool, MobileError> {
        let resp = route
            .client
            .post(route.url("/v1/calls/cancel"))
            .bearer_auth(token)
            .json(&CancelCallRequest { client_ref })
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(true);
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        log::error!("Cancel call failed: {}", status);
        Err(status_error(status, MobileError::GatewayError))
    }

    /// Poll the status of a call. Returns "active", "ended", "cancelled", etc.
    pub async fn get_call_status(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
    ) -> Result<CallStatusResponse, MobileError> {
        let resp = route
            .client
            .get(route.url(&format!("/v1/calls/{call_token}/status")))
            .bearer_auth(token)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(status_error(
                resp.status(),
                MobileError::CallFailed(format!("no call status (HTTP {})", resp.status())),
            ));
        }

        let body: CallStatusResponse = read_json_capped(resp).await?;
        Ok(body)
    }

    /// Hang up an active call via the gateway. Bounded by [`HANGUP_TIMEOUT`].
    ///
    /// A 404 means the gateway has no such call and is reported as
    /// `InvalidState`.
    pub async fn hangup_call(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
    ) -> Result<(), MobileError> {
        let resp = route
            .client
            .post(route.url(&format!("/v1/calls/{call_token}/hangup")))
            .timeout(HANGUP_TIMEOUT)
            .bearer_auth(token)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        log::error!("Hangup call failed: {}", status);
        Err(if status == reqwest::StatusCode::NOT_FOUND {
            MobileError::InvalidState
        } else {
            status_error(
                status,
                MobileError::CallFailed(format!("hangup refused (HTTP {status})")),
            )
        })
    }

    /// Blind-transfer an active call via the gateway, which sends a SIP REFER
    /// to the PBX.
    ///
    /// Status mapping: 202 (or any 2xx) is success; 400 means the gateway
    /// refused the target; 404 means the gateway has no active call for the
    /// token (unknown, or not answered yet) or, on a gateway that predates the
    /// route, has no such route; 502 means the PBX rejected the REFER; 504
    /// means the PBX did not answer the REFER in time.
    ///
    /// The gateway can hold this request for up to 8 s while it waits on the
    /// PBX, which the client's 30 s timeout covers.
    pub async fn transfer_call(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
        target: &str,
    ) -> Result<(), MobileError> {
        let resp = route
            .client
            .post(route.url(&format!("/v1/calls/{call_token}/transfer")))
            .bearer_auth(token)
            .json(&TransferCallRequest { target })
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        log::error!("Transfer call failed: {}", status);
        Err(match status.as_u16() {
            400 => MobileError::InvalidTarget,
            401 | 403 => MobileError::AuthenticationError,
            404 => MobileError::InvalidState,
            502 => MobileError::CallFailed("the PBX refused the transfer".into()),
            504 => MobileError::Timeout,
            _ => MobileError::GatewayError,
        })
    }

    /// Attended-transfer: join the far ends of two of the user's calls and
    /// drop this phone from both. The gateway sends a REFER with `Replaces`
    /// on whichever of the two the phone received, so the token order does
    /// not matter; both calls must be on this route's gateway instance.
    ///
    /// Status mapping, in line with [`transfer_call`](Self::transfer_call):
    /// 202 (or any 2xx) is success; 400 (`same_call`, or a body the gateway
    /// could not read), 404 (either call unknown here) and 409
    /// `call_not_established` mean the calls cannot be transferred as they
    /// are (`InvalidState`); 409 `unsupported_by_pbx` means both calls go
    /// the same way (`TransferUnsupported`); any other 409 (a transfer of
    /// either call already in progress) is a `GatewayError`; 502 and 504 are
    /// as for a blind transfer.
    pub async fn transfer_attended(
        &self,
        route: &Route,
        token: &str,
        call_token: &str,
        replaces_token: &str,
    ) -> Result<(), MobileError> {
        let resp = route
            .client
            .post(route.url(&format!("/v1/calls/{call_token}/transfer")))
            .bearer_auth(token)
            .json(&AttendedTransferRequest {
                replaces: replaces_token,
            })
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        log::error!("Attended transfer failed: {}", status);
        Err(match status.as_u16() {
            400 | 404 => MobileError::InvalidState,
            401 | 403 => MobileError::AuthenticationError,
            409 => {
                let body: Option<ErrorBody> = read_json_capped(resp).await.ok();
                match body.as_ref().map(|b| b.error.as_str()) {
                    Some("call_not_established") => MobileError::InvalidState,
                    Some("unsupported_by_pbx") => MobileError::TransferUnsupported,
                    _ => MobileError::GatewayError,
                }
            }
            502 => MobileError::CallFailed("the PBX refused the transfer".into()),
            504 => MobileError::Timeout,
            _ => MobileError::GatewayError,
        })
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

#[cfg(test)]
mod enforce_https_tests {
    use super::enforce_https;

    /// The regression: splitting the authority on ':' before '@' read
    /// "localhost:80@evil.example.com" as the host "localhost", so the
    /// loopback exemption applied and the URL stayed cleartext — while the
    /// HTTP client resolves the real host as evil.example.com. The request
    /// bodies carry the SIP password in the clear.
    #[test]
    fn userinfo_cannot_forge_the_loopback_exemption() {
        assert_eq!(
            enforce_https("http://localhost:80@evil.example.com/v1".to_string()),
            "https://localhost:80@evil.example.com/v1",
            "a userinfo-disguised remote host must still be upgraded"
        );
    }

    #[test]
    fn a_remote_host_is_upgraded() {
        assert_eq!(
            enforce_https("http://gw.example.com/v1".to_string()),
            "https://gw.example.com/v1"
        );
    }

    /// Genuine local development must keep working.
    #[test]
    fn real_loopback_is_left_alone() {
        for url in [
            "http://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "http://dev.local/v1",
        ] {
            assert_eq!(enforce_https(url.to_string()), url);
        }
    }

    #[test]
    fn https_is_untouched() {
        assert_eq!(
            enforce_https("https://gw.example.com/v1".to_string()),
            "https://gw.example.com/v1"
        );
    }
}

#[cfg(test)]
mod transfer_tests {
    use super::{GatewayClient, Placement};
    use crate::mock_gateway::MockGateway;
    use crate::types::MobileError;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn transfer_posts_the_target_to_the_call_route() {
        let gw = MockGateway::start(|_| (202, "{}".into()));
        let client = GatewayClient::new(gw.base_url.clone());

        block_on(client.transfer_call(
            &client.primary_route(),
            "jwt",
            "tok-1",
            "sip:1002@pbx.example.com",
        ))
        .unwrap();

        let reqs = gw.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/v1/calls/tok-1/transfer");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer jwt"));
        let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "target": "sip:1002@pbx.example.com" })
        );
    }

    #[test]
    fn transfer_maps_gateway_statuses_to_errors() {
        let cases = [
            (400, "InvalidTarget"),
            (401, "AuthenticationError"),
            (404, "InvalidState"),
            (502, "CallFailed"),
            (504, "Timeout"),
            (500, "GatewayError"),
        ];
        for (status, expected) in cases {
            let gw = MockGateway::start(move |_| (status, "{}".into()));
            let client = GatewayClient::new(gw.base_url.clone());
            let err = block_on(client.transfer_call(&client.primary_route(), "jwt", "tok", "1002"))
                .unwrap_err();
            let got = match err {
                MobileError::InvalidTarget => "InvalidTarget",
                MobileError::AuthenticationError => "AuthenticationError",
                MobileError::InvalidState => "InvalidState",
                MobileError::CallFailed(_) => "CallFailed",
                MobileError::GatewayError => "GatewayError",
                MobileError::Timeout => "Timeout",
                other => panic!("unexpected error for {status}: {other:?}"),
            };
            assert_eq!(got, expected, "HTTP {status}");
        }
    }

    #[test]
    fn attended_transfer_posts_the_other_calls_token_as_replaces() {
        let gw = MockGateway::start(|_| (202, "{}".into()));
        let client = GatewayClient::new(gw.base_url.clone());

        block_on(client.transfer_attended(&client.primary_route(), "jwt", "tok-1", "tok-2"))
            .unwrap();

        let reqs = gw.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/v1/calls/tok-1/transfer");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer jwt"));
        let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(body, serde_json::json!({ "replaces": "tok-2" }));
    }

    #[test]
    fn attended_transfer_maps_gateway_statuses_to_errors() {
        let cases = [
            (400, r#"{"error":"same_call"}"#, "InvalidState"),
            (401, "{}", "AuthenticationError"),
            (404, "{}", "InvalidState"),
            (409, r#"{"error":"call_not_established"}"#, "InvalidState"),
            (
                409,
                r#"{"error":"unsupported_by_pbx"}"#,
                "TransferUnsupported",
            ),
            // No body: a transfer of either call is already in progress.
            (409, "", "GatewayError"),
            (502, "{}", "CallFailed"),
            (504, "{}", "Timeout"),
            (500, "{}", "GatewayError"),
        ];
        for (status, body, expected) in cases {
            let gw = MockGateway::start(move |_| (status, body.into()));
            let client = GatewayClient::new(gw.base_url.clone());
            let err =
                block_on(client.transfer_attended(&client.primary_route(), "jwt", "tok", "tok-2"))
                    .unwrap_err();
            let got = match err {
                MobileError::AuthenticationError => "AuthenticationError",
                MobileError::InvalidState => "InvalidState",
                MobileError::TransferUnsupported => "TransferUnsupported",
                MobileError::CallFailed(_) => "CallFailed",
                MobileError::GatewayError => "GatewayError",
                MobileError::Timeout => "Timeout",
                other => panic!("unexpected error for {status}: {other:?}"),
            };
            assert_eq!(got, expected, "HTTP {status} {body}");
        }
    }

    /// A pinned call goes to its route even when another comes first.
    #[test]
    fn a_pinned_call_goes_only_to_its_route() {
        let answer = || (200, r#"{"call_token":"ct","sdp_answer":""}"#.to_string());
        let first = MockGateway::start(move |_| answer());
        let second = MockGateway::start(move |_| answer());
        let client = GatewayClient::new(first.base_url.clone());
        client.set_test_routes(&[&first.base_url, &second.base_url]);
        let pin = client.routes()[1].clone();
        let attempt = std::sync::Mutex::new(None);

        let (_, _, route) = block_on(client.make_call(
            "jwt",
            "1002",
            "v=0",
            &creds(),
            Placement {
                client_ref: "ref",
                attempt: &attempt,
                pin: Some(&pin),
            },
        ))
        .unwrap();

        assert_eq!(route.base_url(), second.base_url);
        assert!(first.requests().is_empty());
        assert_eq!(second.requests().len(), 1);
    }

    /// A pinned route that cannot be connected to fails the call instead of
    /// failing over.
    #[test]
    fn a_pinned_call_does_not_fail_over() {
        let gw = MockGateway::start(|_| (200, r#"{"call_token":"ct","sdp_answer":""}"#.into()));
        let client = GatewayClient::new(gw.base_url.clone());
        client.set_test_routes(&["http://127.0.0.1:9", &gw.base_url]);
        let pin = client.routes()[0].clone();
        let attempt = std::sync::Mutex::new(None);

        let err = block_on(client.make_call(
            "jwt",
            "1002",
            "v=0",
            &creds(),
            Placement {
                client_ref: "ref",
                attempt: &attempt,
                pin: Some(&pin),
            },
        ))
        .unwrap_err();

        assert!(matches!(err, MobileError::NetworkError), "{err:?}");
        assert!(gw.requests().is_empty(), "the pinned call failed over");
    }

    #[test]
    fn a_cancelled_outgoing_call_is_a_cancelled_error() {
        let gw = MockGateway::start(|_| (409, r#"{"error":"cancelled"}"#.into()));
        let client = GatewayClient::new(gw.base_url.clone());
        let creds = crate::types::SipCredentials {
            username: "1001".into(),
            password: "pw".into(),
            domain: "pbx.example.com".into(),
            registrar: None,
            transport: "udp".into(),
            port: 5060,
            auth_username: None,
            display_name: "Alice".into(),
        };
        let err = block_on(client.make_call(
            "jwt",
            "1002",
            "v=0",
            &creds,
            Placement::any("ref1", &Default::default()),
        ))
        .unwrap_err();
        assert!(matches!(err, MobileError::Cancelled), "{err:?}");
        let body: serde_json::Value = serde_json::from_str(&gw.requests()[0].body).unwrap();
        assert_eq!(body["client_ref"], "ref1");
    }

    #[test]
    fn cancel_posts_the_ref_and_maps_statuses() {
        for (status, expected) in [
            (202, Ok(true)),
            (404, Ok(false)),
            (401, Err("AuthenticationError")),
            (500, Err("GatewayError")),
        ] {
            let gw = MockGateway::start(move |_| (status, "{}".into()));
            let client = GatewayClient::new(gw.base_url.clone());
            let got =
                block_on(client.cancel_call(&client.primary_route(), "jwt", "ref1")).map_err(|e| {
                    match e {
                        MobileError::AuthenticationError => "AuthenticationError",
                        MobileError::GatewayError => "GatewayError",
                        other => panic!("unexpected error for {status}: {other:?}"),
                    }
                });
            assert_eq!(got, expected, "HTTP {status}");
            let reqs = gw.requests();
            assert_eq!(reqs[0].path, "/v1/calls/cancel");
            assert_eq!(reqs[0].body, r#"{"client_ref":"ref1"}"#);
            assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer jwt"));
        }
    }

    fn creds() -> crate::types::SipCredentials {
        crate::types::SipCredentials {
            username: "1001".into(),
            password: "pw".into(),
            domain: "pbx.example.com".into(),
            registrar: None,
            transport: "udp".into(),
            port: 5060,
            auth_username: None,
            display_name: "Alice".into(),
        }
    }

    /// The client must outlast the gateway's 30 s INVITE timeout, or an
    /// answer at the last moment arrives after the client has given up.
    #[test]
    fn make_call_outlasts_the_gateways_invite_timeout() {
        assert!(super::MAKE_CALL_TIMEOUT > std::time::Duration::from_secs(30));
    }

    /// A route that cannot be connected to is skipped.
    #[test]
    fn make_call_fails_over_when_it_cannot_connect() {
        let gw = MockGateway::start(|_| (200, r#"{"call_token":"ct","sdp_answer":""}"#.into()));
        let client = GatewayClient::new(gw.base_url.clone());
        client.set_test_routes(&["http://127.0.0.1:9", &gw.base_url]);
        let attempt = std::sync::Mutex::new(None);

        let (token, _, route) = block_on(client.make_call(
            "jwt",
            "1002",
            "v=0",
            &creds(),
            Placement::any("ref", &attempt),
        ))
        .unwrap();

        assert_eq!(token, "ct");
        assert_eq!(route.base_url(), gw.base_url);
        assert_eq!(
            attempt.lock().unwrap().as_ref().unwrap().base_url(),
            gw.base_url
        );
    }

    /// Once the request may have been delivered, it is never sent to another
    /// route: a second `POST /v1/calls` would ring the callee twice.
    #[test]
    fn make_call_never_resends_a_request_that_may_have_been_delivered() {
        use std::io::Read;
        // Accepts, reads the request, then hangs up without answering.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dropping = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
            }
        });
        let second = MockGateway::start(|_| (200, r#"{"call_token":"ct","sdp_answer":""}"#.into()));
        let client = GatewayClient::new(dropping.clone());
        client.set_test_routes(&[&dropping, &second.base_url]);

        let result = block_on(client.make_call(
            "jwt",
            "1002",
            "v=0",
            &creds(),
            Placement::any("ref", &Default::default()),
        ));

        assert!(result.is_err());
        assert!(second.requests().is_empty(), "the call was sent twice");
    }

    #[test]
    fn only_a_cancelled_409_is_a_cancel() {
        for (body, cancelled) in [
            (r#"{"error":"cancelled"}"#, true),
            (r#"{"error":"client_ref_in_use"}"#, false),
            ("{}", false),
            ("not json", false),
        ] {
            let body = body.to_string();
            let gw = MockGateway::start(move |_| (409, body.clone()));
            let client = GatewayClient::new(gw.base_url.clone());
            let err = block_on(client.make_call(
                "jwt",
                "1002",
                "v=0",
                &creds(),
                Placement::any("ref", &Default::default()),
            ))
            .unwrap_err();
            if cancelled {
                assert!(matches!(err, MobileError::Cancelled), "{err:?}");
            } else {
                assert!(matches!(err, MobileError::GatewayError), "{err:?}");
            }
        }
    }
}
