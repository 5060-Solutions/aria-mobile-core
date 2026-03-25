//! Aria Mobile Core — shared Rust engine for iOS and Android softphone apps.
//!
//! Provides:
//! - Push gateway HTTP client (device registration, call signaling)
//! - SDP generation/parsing for RTP media
//! - RTP media session management (codec encode/decode, SRTP)
//! - UniFFI bindings for Swift (iOS) and Kotlin (Android)

pub mod dns;
mod gateway_client;
mod media;
mod types;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

use types::*;
pub use media::PlatformAudioBridge;

uniffi::include_scaffolding!("aria_mobile");

// ── Global Runtime ──────────────────────────────────────────────────────────

static RUNTIME: once_cell::sync::OnceCell<tokio::runtime::Runtime> =
    once_cell::sync::OnceCell::new();

/// Initialize the tokio async runtime. Call once at app startup.
fn init_runtime() {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("aria_mobile"),
    );

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
    /// Platform audio bridge for mic/speaker I/O
    audio_bridge: RwLock<Option<Arc<dyn media::PlatformAudioBridge>>>,
    /// Active calls keyed by call_id
    calls: Mutex<HashMap<String, ActiveCallState>>,
    /// Auth token from gateway
    auth_token: RwLock<Option<String>>,
    /// Registered device ID
    device_id: RwLock<Option<String>>,
    /// Preferred codecs
    codec_prefs: RwLock<Vec<AudioCodec>>,
    /// Call IDs that were ended by the remote party (detected via polling).
    /// The app checks this via `check_remote_hangup()`.
    remote_ended: Arc<Mutex<Vec<String>>>,
}

struct ActiveCallState {
    info: CallInfo,
    media: Option<media::MobileMediaSession>,
    /// For gateway-routed calls
    call_token: Option<String>,
    /// Set to true to stop the status polling loop
    poll_stop: Arc<AtomicBool>,
}

impl AriaMobileEngine {
    pub fn new(gateway_config: GatewayConfig) -> Self {
        Self {
            gateway: gateway_client::GatewayClient::new(
                gateway_config.base_url,
                gateway_config.api_key,
            ),
            event_handler: RwLock::new(None),
            audio_bridge: RwLock::new(None),
            calls: Mutex::new(HashMap::new()),
            auth_token: RwLock::new(None),
            device_id: RwLock::new(None),
            codec_prefs: RwLock::new(vec![
                AudioCodec::Opus,
                AudioCodec::Pcmu,
                AudioCodec::Pcma,
            ]),
            remote_ended: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_event_handler(&self, handler: Box<dyn MobileEventHandler>) {
        let mut eh = self.event_handler.write().unwrap();
        *eh = Some(handler);
    }

    pub fn set_audio_bridge(&self, bridge: Box<dyn media::PlatformAudioBridge>) {
        let mut ab = self.audio_bridge.write().unwrap();
        *ab = Some(Arc::from(bridge));
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
            // Use pre-existing token if the api_key looks like a JWT (starts with "eyJ"),
            // otherwise obtain a new token from the gateway's /v1/auth/token endpoint.
            let token = if self.gateway.api_key_is_jwt() {
                log::info!("Using pre-supplied JWT as gateway auth token");
                self.gateway.api_key().to_string()
            } else {
                self.gateway
                    .create_token(
                        &format!("{}@{}", registration.sip.username, registration.sip.domain),
                    )
                    .await?
            };

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

            let poll_stop = Arc::new(AtomicBool::new(false));

            {
                let mut calls = self.calls.lock().unwrap();
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        media: Some(media_session),
                        call_token: Some(call_token.clone()),
                        poll_stop: poll_stop.clone(),
                    },
                );
            }

            // Start polling for remote hangup
            self.start_call_status_poll(call_id.clone(), call_token, poll_stop);

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
            let (media_session, sdp_offer) =
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

            // Start RTP processing with platform audio bridge
            if let Some(bridge) = self.audio_bridge.read().unwrap().clone() {
                media_session.start_with_bridge(bridge);
                log::info!("Started RTP media session with audio bridge");
            } else {
                log::warn!("No audio bridge set — call will have no audio");
            }

            // Transition to connected
            info.state = CallState::Connected;

            let poll_stop = Arc::new(AtomicBool::new(false));

            {
                let mut calls = self.calls.lock().unwrap();
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        media: Some(media_session),
                        call_token: Some(call_token.clone()),
                        poll_stop: poll_stop.clone(),
                    },
                );
            }

            // Start polling for remote hangup
            self.start_call_status_poll(call_id.clone(), call_token, poll_stop);

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

            // Stop status polling
            call.poll_stop.store(true, Ordering::Relaxed);

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

    // ── Call Status Polling ────────────────────────────────────────

    /// Spawn a background task that polls the gateway for call status changes.
    /// Detects remote hangup (BYE from PBX) and ends the local call.
    fn start_call_status_poll(
        &self,
        call_id: String,
        call_token: String,
        stop: Arc<AtomicBool>,
    ) {
        let base_url = self.gateway.base_url().to_string();
        let api_key = self.gateway.api_key().to_string();
        let auth_token = self.auth_token.read().unwrap().clone().unwrap_or_default();
        let remote_ended = Arc::clone(&self.remote_ended);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let gateway = gateway_client::GatewayClient::new(base_url, api_key);

            rt.block_on(async {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                    if stop.load(Ordering::Relaxed) {
                        log::debug!("Call status poll stopped for {}", call_id);
                        break;
                    }

                    match gateway.get_call_status(&auth_token, &call_token).await {
                        Ok(status) => {
                            if status.status == "ended" || status.status == "unknown" {
                                log::info!(
                                    "Remote hangup detected for {} (reason: {:?})",
                                    call_id,
                                    status.reason,
                                );
                                stop.store(true, Ordering::Relaxed);
                                remote_ended.lock().unwrap().push(call_id.clone());
                                break;
                            }
                        }
                        Err(e) => {
                            log::warn!("Call status poll error: {}", e);
                        }
                    }
                }
            });
        });
    }

    /// Check if any active call was ended by the remote party.
    /// Returns the call_id if so, and cleans up the call state.
    /// The app should call this periodically (e.g., from a UI timer).
    pub fn check_remote_hangup(&self) -> Option<String> {
        let ended_id = {
            let mut ended = self.remote_ended.lock().unwrap();
            ended.pop()
        };

        if let Some(ref call_id) = ended_id {
            let call = {
                let mut calls = self.calls.lock().unwrap();
                calls.remove(call_id)
            };

            if let Some(mut call) = call {
                call.poll_stop.store(true, Ordering::Relaxed);
                if let Some(media) = call.media.take() {
                    media.stop();
                }
                let mut info = call.info.clone();
                info.state = CallState::Ended;
                self.emit_call_state(&info);
            }
        }

        ended_id
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

    /// Get RX audio level (0.0 = silence, ~4000+ = loud speech).
    pub fn get_rx_audio_level(&self, call_id: String) -> f32 {
        let calls = self.calls.lock().unwrap();
        calls
            .get(&call_id)
            .and_then(|c| c.media.as_ref())
            .map(|m| m.rx_audio_level())
            .unwrap_or(0.0)
    }

    /// Get TX audio level (0.0 = silence, ~4000+ = loud speech).
    pub fn get_tx_audio_level(&self, call_id: String) -> f32 {
        let calls = self.calls.lock().unwrap();
        calls
            .get(&call_id)
            .and_then(|c| c.media.as_ref())
            .map(|m| m.tx_audio_level())
            .unwrap_or(0.0)
    }

    pub fn set_codec_preferences(&self, codecs: Vec<AudioCodec>) {
        let mut prefs = self.codec_prefs.write().unwrap();
        *prefs = codecs;
    }

    /// Notify the core that the network has changed (WiFi→cellular, reconnect, etc.).
    ///
    /// Called by the platform (Android/iOS) when it detects a connectivity change.
    /// Re-registers the device with the push gateway if a device_id is set,
    /// and notifies active media sessions to rebind their sockets.
    pub fn notify_network_change(&self) {
        log::info!("Network change detected by platform");

        // Send heartbeat to push gateway — re-registers SIP with fresh socket
        let device_id = self.device_id.read().unwrap().clone();
        let token = self.auth_token.read().unwrap().clone();
        if let (Some(did), Some(tok)) = (device_id, token) {
            log::info!("Sending heartbeat for device {} after network change", did);
            // Build heartbeat URL and send via a simple HTTP POST.
            // We avoid cloning GatewayClient by constructing the request directly.
            let base_url = self.gateway.base_url().to_string();
            let url = format!("{}/v1/devices/{}/heartbeat", base_url, did);
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async {
                        let client = reqwest::Client::new();
                        match client.post(&url).bearer_auth(&tok).send().await {
                            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 204 => {
                                log::info!("Gateway heartbeat successful after network change");
                            }
                            Ok(resp) => {
                                log::warn!("Gateway heartbeat failed: HTTP {}", resp.status());
                            }
                            Err(e) => {
                                log::warn!("Gateway heartbeat failed: {}", e);
                            }
                        }
                    });
                }
            });
        }

        let active_count = self.calls.lock().unwrap().len();
        if active_count > 0 {
            log::info!(
                "Network change with {} active call(s) — media sockets will rebind on next packet",
                active_count
            );
        }
    }
}
