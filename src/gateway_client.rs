//! HTTP client for the Aria push gateway REST API.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::types::*;

pub struct GatewayClient {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
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
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    /// Obtain a JWT auth token from the gateway.
    pub async fn create_token(&self, user_id: &str) -> Result<String, MobileError> {
        let resp = self
            .http
            .post(self.url("/v1/auth/token"))
            .json(&TokenRequest {
                user_id: user_id.to_string(),
                api_key: self.api_key.clone(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Token request failed: {}", resp.status());
            return Err(MobileError::AuthenticationError);
        }

        let body: TokenResponse = resp.json().await?;
        Ok(body.token)
    }

    /// Register a device with the push gateway.
    pub async fn register_device(
        &self,
        token: &str,
        registration: &DeviceRegistration,
    ) -> Result<DeviceRegistrationResponse, MobileError> {
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

        let resp = self
            .http
            .post(self.url("/v1/devices"))
            .bearer_auth(token)
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Device registration failed: {}", resp.status());
            return Err(MobileError::RegistrationFailed);
        }

        let body: RegisterDeviceResponse = resp.json().await?;
        Ok(DeviceRegistrationResponse {
            device_id: body.device_id,
            auth_token: token.to_string(),
        })
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

    /// Initiate an outgoing call via the gateway.
    /// The gateway acts as a B2BUA — it sends the SIP INVITE on our behalf
    /// and returns the SDP answer from the remote party.
    pub async fn make_call(
        &self,
        token: &str,
        destination_uri: &str,
        sdp_offer: &str,
        credentials: &crate::types::SipCredentials,
    ) -> Result<(String, String), MobileError> {
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

        let resp = self
            .http
            .post(self.url("/v1/calls"))
            .bearer_auth(token)
            .json(&req)
            .send()
            .await?;

        if !resp.status().is_success() {
            log::error!("Make call failed: {}", resp.status());
            return Err(MobileError::CallFailed);
        }

        let body: MakeCallResponse = resp.json().await?;
        Ok((body.call_token, body.sdp_answer))
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
