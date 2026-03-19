//! HTTP client for the Aria push gateway REST API.
//!
//! When the gateway base URL contains a domain name, the client resolves it
//! via DNS SRV records before connecting. If the primary server fails, it
//! automatically tries the next target in the SRV priority list.

use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use std::time::Duration;

use crate::dns;
use crate::types::*;

pub struct GatewayClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
    /// Resolved gateway URLs from SRV lookup, ordered by priority.
    /// First entry is the primary; rest are failover targets.
    resolved_urls: RwLock<Vec<String>>,
}

#[derive(Serialize)]
struct TokenRequest {
    user_id: String,
    api_key: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    #[allow(dead_code)]
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

impl GatewayClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            api_key,
            http,
            resolved_urls: RwLock::new(Vec::new()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// Build a URL using one of the resolved SRV targets instead of the
    /// original base_url. Falls back to the original base_url if no resolved
    /// targets are available.
    fn url_for_target(&self, target_idx: usize, path: &str) -> String {
        let resolved = self.resolved_urls.read().unwrap();
        if let Some(base) = resolved.get(target_idx) {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else {
            self.url(path)
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

                let urls: Vec<String> = targets
                    .iter()
                    .map(|t| {
                        let host_port = if (is_tls && t.port == 443)
                            || (!is_tls && t.port == 80)
                        {
                            t.addr.ip().to_string()
                        } else {
                            format!("{}:{}", t.addr.ip(), t.port)
                        };
                        format!("{}://{}{}", scheme, host_port, path_prefix)
                    })
                    .collect();

                log::info!(
                    "Gateway SRV resolved {} -> {} targets (primary: {})",
                    domain,
                    urls.len(),
                    urls[0],
                );

                let mut resolved = self.resolved_urls.write().unwrap();
                *resolved = urls;
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
        let resolved = self.resolved_urls.read().unwrap();
        if resolved.is_empty() { 1 } else { resolved.len() }
    }

    /// Obtain a JWT auth token from the gateway, with SRV failover.
    pub async fn create_token(&self, user_id: &str) -> Result<String, MobileError> {
        // Resolve gateway via SRV on first use
        let _ = self.resolve_gateway().await;

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let url = self.url_for_target(idx, "/v1/auth/token");
            match self
                .http
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
                    let body: TokenResponse = resp.json().await?;
                    return Ok(body.token);
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
        // Resolve the SIP registrar domain via SRV so we can tell the
        // gateway which server handles this domain.
        let resolved_registrar = self
            .resolve_sip_registrar(&registration.sip)
            .await;

        let mut req = RegisterDeviceRequest {
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

        // If SRV resolved a different registrar, use it
        if let Some(ref addr) = resolved_registrar {
            req.sip_registrar = Some(addr.clone());
        }

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let url = self.url_for_target(idx, "/v1/devices");
            match self
                .http
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
                    let body: RegisterDeviceResponse = resp.json().await?;
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

    /// Resolve the SIP registrar/domain via SRV and return the best address
    /// as a "host:port" string for the gateway to use.
    async fn resolve_sip_registrar(&self, creds: &SipCredentials) -> Option<String> {
        let domain = creds.registrar.as_deref().unwrap_or(&creds.domain);

        // Skip if already an IP address
        if domain.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        let transport = match creds.transport.to_lowercase().as_str() {
            "udp" => dns::SipTransport::Udp,
            "tcp" => dns::SipTransport::Tcp,
            "tls" => dns::SipTransport::Tls,
            _ => dns::SipTransport::Udp,
        };

        match dns::resolve_sip_server(domain, transport, creds.port).await {
            Ok(targets) if !targets.is_empty() => {
                let best = &targets[0];
                log::info!(
                    "SIP registrar SRV resolved {} -> {}:{} (priority={}, weight={})",
                    domain,
                    best.host,
                    best.port,
                    best.priority,
                    best.weight,
                );
                Some(format!("{}:{}", best.addr.ip(), best.port))
            }
            _ => None,
        }
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

        let body: GatewayCallOffer = resp.json().await?;
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
        // Resolve the SIP registrar for the call credentials
        let resolved_registrar = self.resolve_sip_registrar(credentials).await;

        let req = MakeCallRequest {
            destination_uri: destination_uri.to_string(),
            sdp_offer: sdp_offer.to_string(),
            sip_username: credentials.username.clone(),
            sip_password: credentials.password.clone(),
            sip_domain: credentials.domain.clone(),
            sip_registrar: resolved_registrar.or_else(|| credentials.registrar.clone()),
            sip_transport: credentials.transport.clone(),
            sip_port: credentials.port,
            sip_auth_username: credentials.auth_username.clone(),
            sip_display_name: credentials.display_name.clone(),
        };

        let target_count = self.resolved_target_count();
        let mut last_err = MobileError::NetworkError;

        for idx in 0..target_count {
            let url = self.url_for_target(idx, "/v1/calls");
            match self
                .http
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
                    let body: MakeCallResponse = resp.json().await?;
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
