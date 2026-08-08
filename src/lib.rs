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
use std::time::{Duration, Instant};

/// Refresh the gateway auth token this many seconds before it actually expires,
/// so an in-flight request never races the expiry boundary.
const TOKEN_REFRESH_SKEW_SECS: u64 = 60;

pub mod ai;

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
    /// Deadline after which `auth_token` is considered expired, computed from
    /// the gateway's `expires_in`. `None` means "unknown lifetime" (e.g. an
    /// app-supplied JWT) and disables automatic refresh.
    token_expires_at: RwLock<Option<Instant>>,
    /// Registered device ID
    device_id: RwLock<Option<String>>,
    /// On-device AI, created by `ai_init`. `None` until a host asks for it, so
    /// a build with the feature on still costs nothing until it is used.
    ai: RwLock<Option<Arc<ai::AiState>>>,
    /// Preferred codecs
    codec_prefs: RwLock<Vec<AudioCodec>>,
    /// The most recent device registration, retained so `update_push_token`
    /// can re-register with a rotated push token without the app re-supplying
    /// the full SIP credentials.
    last_registration: RwLock<Option<DeviceRegistration>>,
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
            token_expires_at: RwLock::new(None),
            device_id: RwLock::new(None),
            ai: RwLock::new(None),
            codec_prefs: RwLock::new(vec![
                AudioCodec::Opus,
                AudioCodec::Pcmu,
                AudioCodec::Pcma,
            ]),
            last_registration: RwLock::new(None),
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
        // Recover from a poisoned lock rather than panicking across the FFI
        // boundary, and run the foreign callback inside catch_unwind so a
        // panicking host callback cannot unwind across FFI (UB) or poison the
        // lock for every subsequent caller.
        let guard = self
            .event_handler
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(handler) = guard.as_ref() {
            let info = info.clone();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_call_state_changed(info);
            }));
        }
    }

    #[allow(dead_code)]
    fn emit_error(&self, context: &str, message: &str) {
        let guard = self
            .event_handler
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(handler) = guard.as_ref() {
            let (context, message) = (context.to_string(), message.to_string());
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_error(context, message);
            }));
        }
    }

    fn get_token(&self) -> Result<String, MobileError> {
        self.auth_token
            .read()
            .unwrap()
            .clone()
            .ok_or(MobileError::AuthenticationError)
    }

    /// Store a freshly minted token and, when known, the deadline at which it
    /// expires (derived from the gateway's `expires_in` seconds). Passing
    /// `None` for `expires_in` disables automatic refresh for this token
    /// (used for app-supplied JWTs whose lifetime we don't manage).
    fn store_token(&self, token: String, expires_in: Option<u64>) {
        {
            let mut t = self.auth_token.write().unwrap();
            *t = Some(token);
        }
        let mut e = self.token_expires_at.write().unwrap();
        *e = expires_in.map(|secs| Instant::now() + Duration::from_secs(secs));
    }

    /// Return a currently-valid auth token, transparently refreshing it first
    /// if it is missing or within [`TOKEN_REFRESH_SKEW_SECS`] of expiry.
    ///
    /// For a non-JWT `api_key` a new token is minted via the gateway's
    /// `/v1/auth/token` endpoint (using the retained registration to rebuild
    /// the `user_id`). App-supplied JWTs cannot be refreshed by us — the app is
    /// responsible for supplying a fresh one — so those are returned as-is with
    /// no refresh attempt (and no loop).
    ///
    /// Callable only from an async context; it never holds a lock across an
    /// `.await`.
    async fn ensure_valid_token(&self) -> Result<String, MobileError> {
        // App-supplied JWT: we can't re-mint it, so just use what we have.
        if self.gateway.api_key_is_jwt() {
            return self.get_token();
        }

        let needs_refresh = {
            let have_token = self.auth_token.read().unwrap().is_some();
            let expires_at = *self.token_expires_at.read().unwrap();
            match (have_token, expires_at) {
                // No token yet — must obtain one.
                (false, _) => true,
                // Known deadline — refresh once we're inside the skew window.
                (true, Some(deadline)) => {
                    Instant::now() + Duration::from_secs(TOKEN_REFRESH_SKEW_SECS) >= deadline
                }
                // Have a token but no known expiry — assume it's still valid.
                (true, None) => false,
            }
        };

        if !needs_refresh {
            return self.get_token();
        }

        // Rebuild the user_id from the retained registration to re-mint.
        let user_id = {
            let last = self
                .last_registration
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match last.as_ref() {
                Some(reg) => format!("{}@{}", reg.sip.username, reg.sip.domain),
                // Nothing to refresh from — fall back to whatever we hold.
                None => return self.get_token(),
            }
        };

        match self.gateway.create_token(&user_id).await {
            Ok((token, expires_in)) => {
                log::info!("Refreshed gateway auth token (expires_in={}s)", expires_in);
                self.store_token(token.clone(), Some(expires_in));
                Ok(token)
            }
            Err(e) => {
                log::warn!("Auth token refresh failed: {}", e);
                // Fall back to the existing token if we still have one, so a
                // transient refresh failure doesn't break an otherwise-usable
                // (possibly still-valid) token; otherwise surface the error.
                self.get_token().map_err(|_| e)
            }
        }
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
            // `expires_in` is `None` for a JWT (lifetime managed by the app) and
            // `Some(secs)` for a minted token, which drives transparent refresh.
            let (token, expires_in) = if self.gateway.api_key_is_jwt() {
                log::info!("Using pre-supplied JWT as gateway auth token");
                (self.gateway.api_key().to_string(), None)
            } else {
                let (token, expires_in) = self
                    .gateway
                    .create_token(
                        &format!("{}@{}", registration.sip.username, registration.sip.domain),
                    )
                    .await?;
                (token, Some(expires_in))
            };

            // Register the device
            let resp = self.gateway.register_device(&token, &registration).await?;

            // Retain the registration so a later push-token rotation can
            // re-register without the app re-supplying SIP credentials.
            {
                let mut last = self
                    .last_registration
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *last = Some(registration.clone());
            }

            // Store auth state (token + its expiry deadline for auto-refresh)
            self.store_token(token, expires_in);
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
            let token = self.ensure_valid_token().await?;
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
        new_token: String,
    ) -> Result<(), MobileError> {
        // Re-register with the rotated push token. Previously this was a silent
        // no-op that returned Ok, so after the OS rotated the push token the
        // device would stop receiving call pushes entirely. We re-use the
        // retained registration, swap in the new token, and register again
        // (the gateway treats registration as an upsert keyed by device).
        let mut registration = {
            let last = self
                .last_registration
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            last.clone().ok_or(MobileError::InvalidState)?
        };
        registration.push_token = new_token;
        self.register_device(registration).map(|_| ())
    }

    // ── Incoming Call Handling ───────────────────────────────────────

    pub fn handle_push_notification(
        &self,
        payload: PushCallPayload,
    ) -> Result<CallOffer, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.ensure_valid_token().await?;
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
            let token = self.ensure_valid_token().await?;

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

            // Use the full call token, not a truncated prefix: two concurrent
            // incoming calls whose tokens share the first 8 chars would collide
            // on the same HashMap key, orphaning one call's media/poll threads.
            let call_id = format!("incoming-{call_token}");
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

            // Start RTP processing with the platform audio bridge. Without this
            // the media session is created and stored but its RX/TX threads
            // never run, so an ANSWERED INBOUND CALL HAS NO AUDIO in either
            // direction. (The remote RTP address is already set by
            // `create_answer_session` from the caller's SDP offer, so unlike the
            // outbound path there is no separate `update_remote` step here.)
            if let Some(bridge) = self
                .audio_bridge
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                media_session.start_with_bridge(bridge);
                log::info!("Started RTP media session with audio bridge (inbound)");
            } else {
                log::warn!("No audio bridge set — inbound call will have no audio");
            }

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
            let token = self.ensure_valid_token().await?;
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
            let token = self.ensure_valid_token().await?;

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

            // Enable SRTP if the far end accepted our crypto line. Applied
            // before the RTP threads start, so no frame is ever sent in the
            // clear on a call that negotiated encryption.
            if let Err(e) = media_session.apply_remote_sdp(&sdp_answer) {
                log::warn!("SRTP negotiation failed, continuing without it: {e:?}");
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
                if let Ok(token) = self.ensure_valid_token().await {
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

    // ── On-device AI ────────────────────────────────────────────────

    /// Was this binary built with transcription support?
    /// Whether this call's media is encrypted, as negotiated.
    #[must_use]
    pub fn call_is_encrypted(&self, call_id: String) -> bool {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&call_id)
            .and_then(|c| c.media.as_ref())
            .is_some_and(|m| m.srtp_active())
    }

    pub fn ai_available(&self) -> bool {
        cfg!(feature = "ai")
    }

    /// Prepare on-device AI, storing models under `storage_dir`.
    pub fn ai_init(
        &self,
        storage_dir: String,
        insight_key: Option<Vec<u8>>,
    ) -> Result<(), MobileError> {
        // A wrong-length key would fail deep inside the cipher, so reject it
        // here where the message can say what was actually wrong.
        if let Some(k) = insight_key.as_ref() {
            if k.len() != 32 {
                log::error!("insight key must be 32 bytes, got {}", k.len());
                return Err(MobileError::InvalidState);
            }
        }
        let state = ai::AiState::new(&storage_dir, insight_key.as_deref())?;
        *self
            .ai
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(state));
        log::info!("on-device AI initialised at {storage_dir}");
        Ok(())
    }

    fn ai_state(&self) -> Result<Arc<ai::AiState>, MobileError> {
        self.ai
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(MobileError::InvalidState)
    }

    pub fn ai_models(&self) -> Vec<AiModel> {
        self.ai_state().map(|s| s.models()).unwrap_or_default()
    }

    pub fn ai_start_download(&self, model_id: String) -> Result<(), MobileError> {
        self.ai_state()?.start_download(&model_id)
    }

    pub fn ai_download_progress(&self, model_id: String) -> Option<AiDownloadProgress> {
        self.ai_state().ok()?.download_progress(&model_id)
    }

    pub fn ai_cancel_download(&self, model_id: String) {
        if let Ok(s) = self.ai_state() {
            s.cancel_download(&model_id);
        }
    }

    pub fn ai_delete_model(&self, model_id: String) -> Result<(), MobileError> {
        self.ai_state()?.delete_model(&model_id)
    }

    /// Begin capturing this call's audio.
    ///
    /// The tap is attached to the live media session, so audio starts flowing
    /// to the AI from the next RTP packet and never crosses the FFI boundary.
    #[cfg(feature = "ai")]
    pub fn ai_start_capture(&self, call_id: String) -> Result<(), MobileError> {
        let state = self.ai_state()?;
        let session = state.start_capture(&call_id)?;
        let calls = self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let call = calls.get(&call_id).ok_or(MobileError::InvalidState)?;
        let media = call.media.as_ref().ok_or(MobileError::MediaError)?;
        media.set_ai_tap(Some(session));
        log::info!("AI capture started for {call_id}");
        Ok(())
    }

    #[cfg(not(feature = "ai"))]
    pub fn ai_start_capture(&self, _call_id: String) -> Result<(), MobileError> {
        Err(MobileError::InvalidState)
    }

    /// Stop feeding the AI, without discarding what was captured.
    pub fn ai_stop_capture(&self, call_id: String) {
        #[cfg(feature = "ai")]
        {
            let calls = self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(media) = calls.get(&call_id).and_then(|c| c.media.as_ref()) {
                media.set_ai_tap(None);
            }
        }
        if let Ok(s) = self.ai_state() {
            s.stop_capture(&call_id);
        }
    }

    /// Transcribe a captured call, summarising it when an LLM is installed.
    ///
    /// Runs inference, so this blocks for seconds to minutes. Call it off the
    /// UI thread.
    pub fn ai_transcribe(&self, call_id: String) -> Result<AiCallInsight, MobileError> {
        self.ai_stop_capture(call_id.clone());
        self.ai_state()?.transcribe(&call_id)
    }

    /// Past insights, newest first, for a history list.
    ///
    /// Returns an empty list rather than an error when no store is open, since
    /// "AI is off" and "no calls yet" are the same thing to a caller drawing a
    /// list.
    pub fn ai_insights(&self, limit: u32, offset: u32) -> Vec<AiInsightSummary> {
        self.ai_state()
            .map_or_else(|_| Vec::new(), |s| s.insights(limit, offset))
    }

    /// One stored insight with its transcript, or `None` if it was not stored.
    pub fn ai_insight(&self, call_id: String) -> Option<AiCallInsight> {
        self.ai_state().ok().and_then(|s| s.insight(&call_id))
    }

    /// Delete one stored insight. True if a row was removed.
    pub fn ai_delete_insight(&self, call_id: String) -> bool {
        self.ai_state().is_ok_and(|s| s.delete_insight(&call_id))
    }

    /// Delete every stored insight. Returns how many were removed.
    pub fn ai_clear_insights(&self) -> u64 {
        self.ai_state().map_or(0, |s| s.clear_insights())
    }

    /// Throw away a capture without transcribing it.
    pub fn ai_discard_capture(&self, call_id: String) {
        self.ai_stop_capture(call_id.clone());
        if let Ok(s) = self.ai_state() {
            s.discard(&call_id);
        }
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
