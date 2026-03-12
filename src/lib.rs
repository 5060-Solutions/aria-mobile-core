//! Aria Mobile Core — shared Rust engine for iOS and Android softphone apps.
//!
//! Provides:
//! - Push gateway HTTP client (device registration, call signaling)
//! - SDP generation/parsing for RTP media
//! - RTP media session management (codec encode/decode, SRTP)
//! - UniFFI bindings for Swift (iOS) and Kotlin (Android)

mod gateway_client;
mod media;
mod types;

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use types::*;

uniffi::include_scaffolding!("aria_mobile");

// ── Global Runtime ──────────────────────────────────────────────────────────

static RUNTIME: once_cell::sync::OnceCell<tokio::runtime::Runtime> =
    once_cell::sync::OnceCell::new();

/// Initialize the tokio async runtime. Call once at app startup.
fn init_runtime() {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    });
    log::info!("Aria mobile core initialized");
}

/// Shut down the runtime.
fn shutdown_runtime() {
    log::info!("Aria mobile core shutting down");
    // OnceCell doesn't support take, runtime will drop on process exit
}

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get().expect("Runtime not initialized — call init_runtime() first")
}

// ── Event Handler ───────────────────────────────────────────────────────────

/// Callback interface implemented by the platform (Swift/Kotlin).
pub trait MobileEventHandler: Send + Sync + 'static {
    fn on_registration_changed(&self, device_id: String, status: String, error: Option<String>);
    fn on_incoming_call(&self, offer: CallOffer);
    fn on_call_state_changed(&self, info: CallInfo);
    fn on_media_stats(&self, call_id: String, stats: MediaStats);
    fn on_error(&self, context: String, message: String);
}

// ── Main Engine ─────────────────────────────────────────────────────────────

pub struct AriaMobileEngine {
    gateway: gateway_client::GatewayClient,
    event_handler: RwLock<Option<Box<dyn MobileEventHandler>>>,
    /// Active calls keyed by call_id
    calls: Mutex<HashMap<String, ActiveCallState>>,
    /// Auth token from gateway
    auth_token: RwLock<Option<String>>,
    /// Registered device ID
    device_id: RwLock<Option<String>>,
    /// Preferred codecs
    codec_prefs: RwLock<Vec<AudioCodec>>,
}

struct ActiveCallState {
    info: CallInfo,
    media: Option<media::MobileMediaSession>,
    /// For gateway-routed calls
    call_token: Option<String>,
}

impl AriaMobileEngine {
    pub fn new(gateway_config: GatewayConfig) -> Self {
        Self {
            gateway: gateway_client::GatewayClient::new(
                gateway_config.base_url,
                gateway_config.api_key,
            ),
            event_handler: RwLock::new(None),
            calls: Mutex::new(HashMap::new()),
            auth_token: RwLock::new(None),
            device_id: RwLock::new(None),
            codec_prefs: RwLock::new(vec![
                AudioCodec::Opus,
                AudioCodec::Pcmu,
                AudioCodec::Pcma,
            ]),
        }
    }

    pub fn set_event_handler(&self, handler: Box<dyn MobileEventHandler>) {
        let mut eh = self.event_handler.write().unwrap();
        *eh = Some(handler);
    }

    fn emit_call_state(&self, info: &CallInfo) {
        if let Some(handler) = self.event_handler.read().unwrap().as_ref() {
            handler.on_call_state_changed(info.clone());
        }
    }

    #[allow(dead_code)]
    fn emit_error(&self, context: &str, message: &str) {
        if let Some(handler) = self.event_handler.read().unwrap().as_ref() {
            handler.on_error(context.to_string(), message.to_string());
        }
    }

    fn get_token(&self) -> Result<String, MobileError> {
        self.auth_token
            .read()
            .unwrap()
            .clone()
            .ok_or(MobileError::AuthenticationError)
    }

    // ── Device Registration ─────────────────────────────────────────

    pub fn register_device(
        &self,
        registration: DeviceRegistration,
    ) -> Result<DeviceRegistrationResponse, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            // First get an auth token
            let token = self
                .gateway
                .create_token(
                    &format!("{}@{}", registration.sip.username, registration.sip.domain),
                )
                .await?;

            // Register the device
            let resp = self.gateway.register_device(&token, &registration).await?;

            // Store auth state
            {
                let mut t = self.auth_token.write().unwrap();
                *t = Some(token);
            }
            {
                let mut d = self.device_id.write().unwrap();
                *d = Some(resp.device_id.clone());
            }

            if let Some(handler) = self.event_handler.read().unwrap().as_ref() {
                handler.on_registration_changed(
                    resp.device_id.clone(),
                    "registered".to_string(),
                    None,
                );
            }

            Ok(resp)
        })
    }

    pub fn unregister_device(&self, device_id: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.get_token()?;
            self.gateway.unregister_device(&token, &device_id).await?;

            {
                let mut d = self.device_id.write().unwrap();
                *d = None;
            }

            if let Some(handler) = self.event_handler.read().unwrap().as_ref() {
                handler.on_registration_changed(
                    device_id,
                    "unregistered".to_string(),
                    None,
                );
            }

            Ok(())
        })
    }

    pub fn update_push_token(
        &self,
        _device_id: String,
        _new_token: String,
    ) -> Result<(), MobileError> {
        // Re-register with new push token
        // For now, the app should call unregister + register with the new token
        log::info!("Push token update — re-registration required");
        Ok(())
    }

    // ── Incoming Call Handling ───────────────────────────────────────

    pub fn handle_push_notification(
        &self,
        payload: PushCallPayload,
    ) -> Result<CallOffer, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.get_token()?;
            let offer = self
                .gateway
                .get_call_offer(&token, &payload.call_token)
                .await?;

            if let Some(handler) = self.event_handler.read().unwrap().as_ref() {
                handler.on_incoming_call(offer.clone());
            }

            Ok(offer)
        })
    }

    pub fn accept_incoming_call(
        &self,
        call_token: String,
        preferred_codecs: Vec<AudioCodec>,
    ) -> Result<CallInfo, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.get_token()?;

            // Get the call offer to know what codecs the remote supports
            let offer = self
                .gateway
                .get_call_offer(&token, &call_token)
                .await?;

            // Start local media and generate SDP answer
            let codecs = if preferred_codecs.is_empty() {
                self.codec_prefs.read().unwrap().clone()
            } else {
                preferred_codecs
            };

            let (media_session, sdp_answer) =
                media::create_answer_session(&offer.sdp_offer, &codecs).await?;

            // Send the answer to the gateway
            self.gateway
                .accept_call(&token, &call_token, &sdp_answer)
                .await?;

            let call_id = format!("incoming-{}", &call_token[..8.min(call_token.len())]);
            let info = CallInfo {
                call_id: call_id.clone(),
                remote_uri: offer.caller_uri,
                remote_name: offer.caller_name,
                state: CallState::Connected,
                direction: CallDirection::Inbound,
                muted: false,
                on_hold: false,
                duration_secs: 0,
            };

            {
                let mut calls = self.calls.lock().unwrap();
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        media: Some(media_session),
                        call_token: Some(call_token),
                    },
                );
            }

            self.emit_call_state(&info);
            Ok(info)
        })
    }

    pub fn reject_incoming_call(&self, call_token: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.get_token()?;
            self.gateway.reject_call(&token, &call_token).await?;
            Ok(())
        })
    }

    // ── Outgoing Calls ──────────────────────────────────────────────

    pub fn make_call(
        &self,
        uri: String,
        credentials: SipCredentials,
        preferred_codecs: Vec<AudioCodec>,
    ) -> Result<CallInfo, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.get_token()?;

            let codecs = if preferred_codecs.is_empty() {
                self.codec_prefs.read().unwrap().clone()
            } else {
                preferred_codecs
            };

            // Allocate RTP port and build SDP offer
            let (mut media_session, sdp_offer) =
                media::create_offer_session(&codecs).await?;

            let call_id = format!("outgoing-{}", uuid::Uuid::new_v4().as_simple());

            // Emit ringing state so UI updates immediately
            let mut info = CallInfo {
                call_id: call_id.clone(),
                remote_uri: uri.clone(),
                remote_name: None,
                state: CallState::Ringing,
                direction: CallDirection::Outbound,
                muted: false,
                on_hold: false,
                duration_secs: 0,
            };
            self.emit_call_state(&info);

            // Route the call through the gateway B2BUA — it sends the SIP
            // INVITE on our behalf and returns the SDP answer + call_token.
            let (call_token, sdp_answer) = self
                .gateway
                .make_call(&token, &uri, &sdp_offer, &credentials)
                .await?;

            // Parse the SDP answer to get the remote RTP address
            if let Some((remote_addr, _codec)) = media::parse_sdp_remote_pub(&sdp_answer) {
                media_session.update_remote(remote_addr);
            }

            // Transition to connected
            info.state = CallState::Connected;

            {
                let mut calls = self.calls.lock().unwrap();
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        media: Some(media_session),
                        call_token: Some(call_token),
                    },
                );
            }

            self.emit_call_state(&info);
            log::info!("Outgoing call to {} connected via gateway", uri);

            Ok(info)
        })
    }

    // ── Mid-call Controls ───────────────────────────────────────────

    pub fn hangup(&self, call_id: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let call = {
                let mut calls = self.calls.lock().unwrap();
                calls.remove(&call_id)
            };

            let Some(mut call) = call else {
                return Err(MobileError::InvalidState);
            };

            // Stop media
            if let Some(media) = call.media.take() {
                media.stop();
            }

            // If gateway-routed, send hangup to gateway
            if let Some(call_token) = &call.call_token {
                if let Ok(token) = self.get_token() {
                    let _ = self.gateway.hangup_call(&token, call_token).await;
                }
            }

            let mut info = call.info.clone();
            info.state = CallState::Ended;
            self.emit_call_state(&info);

            Ok(())
        })
    }

    pub fn set_mute(&self, call_id: String, muted: bool) -> Result<(), MobileError> {
        let mut calls = self.calls.lock().unwrap();
        let call = calls.get_mut(&call_id).ok_or(MobileError::InvalidState)?;

        if let Some(media) = &call.media {
            media.set_mute(muted);
        }

        call.info.muted = muted;
        let info = call.info.clone();
        drop(calls);
        self.emit_call_state(&info);
        Ok(())
    }

    pub fn set_hold(&self, call_id: String, on_hold: bool) -> Result<(), MobileError> {
        let mut calls = self.calls.lock().unwrap();
        let call = calls.get_mut(&call_id).ok_or(MobileError::InvalidState)?;

        if let Some(media) = &call.media {
            media.set_hold(on_hold);
        }

        call.info.on_hold = on_hold;
        call.info.state = if on_hold {
            CallState::OnHold
        } else {
            CallState::Connected
        };
        let info = call.info.clone();
        drop(calls);
        self.emit_call_state(&info);
        Ok(())
    }

    pub fn send_dtmf(&self, call_id: String, digit: String) -> Result<(), MobileError> {
        let calls = self.calls.lock().unwrap();
        let call = calls.get(&call_id).ok_or(MobileError::InvalidState)?;

        if let Some(media) = &call.media {
            media.send_dtmf(&digit);
        }

        Ok(())
    }

    // ── State Queries ───────────────────────────────────────────────

    pub fn get_active_call(&self) -> Option<CallInfo> {
        let calls = self.calls.lock().unwrap();
        calls
            .values()
            .find(|c| !matches!(c.info.state, CallState::Ended | CallState::Idle))
            .map(|c| c.info.clone())
    }

    pub fn get_media_stats(&self, call_id: String) -> Option<MediaStats> {
        let calls = self.calls.lock().unwrap();
        calls
            .get(&call_id)
            .and_then(|c| c.media.as_ref())
            .map(|m| m.stats())
    }

    pub fn set_codec_preferences(&self, codecs: Vec<AudioCodec>) {
        let mut prefs = self.codec_prefs.write().unwrap();
        *prefs = codecs;
    }
}
