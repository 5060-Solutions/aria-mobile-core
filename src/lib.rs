//! Aria Mobile Core — shared Rust engine for iOS and Android softphone apps.
//!
//! Provides:
//! - Push gateway HTTP client (device registration, call signaling)
//! - SDP generation/parsing for RTP media
//! - RTP media session management (codec encode/decode, SRTP)
//! - UniFFI bindings for Swift (iOS) and Kotlin (Android)

mod auth;
pub mod dns;
mod gateway_client;
mod media;
mod types;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod ai;

pub use media::PlatformAudioBridge;
use types::*;

// The UniFFI-generated scaffolding leaves a blank line after a doc comment,
// which clippy flags. That file is regenerated on every build, so the lint is
// silenced for the generated module only rather than patched by hand.
#[allow(clippy::empty_line_after_doc_comments)]
mod uniffi_scaffolding {
    use super::*;
    uniffi::include_scaffolding!("aria_mobile");
}
pub use uniffi_scaffolding::*;

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
    RUNTIME
        .get()
        .expect("Runtime not initialized — call init_runtime() first")
}

// ── Event Handler ───────────────────────────────────────────────────────────

/// Callback interface implemented by the platform (Swift/Kotlin).
pub trait MobileEventHandler: Send + Sync + 'static {
    fn on_registration_changed(&self, device_id: String, status: String, error: Option<String>);
    fn on_incoming_call(&self, offer: CallOffer);
    fn on_call_state_changed(&self, info: CallInfo);
    fn on_media_stats(&self, call_id: String, stats: MediaStats);
    fn on_error(&self, context: String, message: String);
    fn on_auth_required(&self);
}

/// The installed event handler, shared with the background status-poll
/// threads so they can report a remote hangup themselves.
type HandlerSlot = Arc<RwLock<Option<Arc<dyn MobileEventHandler>>>>;

/// Active calls keyed by call_id, shared with the status-poll threads.
type CallMap = Arc<Mutex<HashMap<String, ActiveCallState>>>;

/// How many remotely ended call IDs `check_remote_hangup` keeps for apps that
/// still poll it. An event-driven app never drains the queue, so it is capped.
const REMOTE_ENDED_BACKLOG: usize = 16;

/// How long an unanswered incoming call is watched for a caller cancel before
/// the watch gives up. Well past any ring timeout a PBX would apply.
const PENDING_INCOMING_MAX_WATCH: Duration = Duration::from_secs(10 * 60);

/// How often a call's status is polled at the gateway.
const CALL_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Invoke the platform handler, if one is installed.
///
/// The handler is cloned out of the lock before it is called, so a callback
/// that re-enters the engine (including `set_event_handler`) cannot deadlock,
/// and a poisoned lock is recovered rather than panicking across the FFI
/// boundary. The callback runs inside `catch_unwind` so a panicking host
/// callback cannot unwind across FFI.
fn with_handler(slot: &HandlerSlot, f: impl FnOnce(&dyn MobileEventHandler)) {
    let handler = slot
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(handler) = handler {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(handler.as_ref())));
    }
}

fn emit_call_state_to(slot: &HandlerSlot, info: &CallInfo) {
    let info = info.clone();
    with_handler(slot, |h| h.on_call_state_changed(info));
}

/// Tell the app that background work had the gateway token of `generation`
/// rejected, unless it has already been told about this token.
fn report_auth_rejected(auth: &auth::GatewayAuth, slot: &HandlerSlot, generation: u64) {
    if auth.report_rejection(generation) {
        log::warn!("Gateway rejected the token; asking the app for a new one");
        with_handler(slot, |h| h.on_auth_required());
    }
}

/// Remove a call from the map and stop its status poll and media.
///
/// Removal is the single point that decides who ends a call: whichever of
/// local hangup, transfer, or the remote-hangup poll removes the entry first
/// owns the `Ended` event, so it fires exactly once per call.
fn take_call(calls: &CallMap, call_id: &str) -> Option<ActiveCallState> {
    let mut call = calls
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(call_id)?;
    call.poll_stop.store(true, Ordering::Relaxed);
    if let Some(media) = call.media.take() {
        media.stop();
    }
    Some(call)
}

/// Report a call that has been taken out of the map as ended.
fn emit_ended(slot: &HandlerSlot, call: &ActiveCallState) {
    let mut info = call.info.clone();
    info.state = CallState::Ended;
    emit_call_state_to(slot, &info);
}

/// Tear a call down locally and emit `Ended`, unless it was already gone.
/// Returns whether this call did the teardown.
fn end_call_locally(calls: &CallMap, slot: &HandlerSlot, call_id: &str) -> bool {
    match take_call(calls, call_id) {
        Some(call) => {
            emit_ended(slot, &call);
            true
        }
        None => false,
    }
}

/// A call status that means the gateway no longer has a live call.
fn status_means_ended(status: &str) -> bool {
    status == "ended" || status == "unknown"
}

/// Check a blind-transfer target before it is sent to the gateway.
///
/// The gateway places the target in a SIP Refer-To header. CR/LF would let a
/// caller inject headers, and angle brackets would break out of the
/// `<...>` that wraps the URI, so both are refused here.
fn validate_transfer_target(target: &str) -> Result<(), MobileError> {
    if target.trim().is_empty() {
        return Err(MobileError::InvalidTarget);
    }
    if target.chars().any(|c| matches!(c, '\r' | '\n' | '<' | '>')) {
        return Err(MobileError::InvalidTarget);
    }
    Ok(())
}

// ── Main Engine ─────────────────────────────────────────────────────────────

pub struct AriaMobileEngine {
    gateway: gateway_client::GatewayClient,
    event_handler: HandlerSlot,
    /// Platform audio bridge for mic/speaker I/O
    audio_bridge: RwLock<Option<Arc<dyn media::PlatformAudioBridge>>>,
    /// Active calls keyed by call_id
    calls: CallMap,
    /// Incoming calls that have been offered but not yet accepted or
    /// rejected, keyed by call_token, each with the stop flag of the poll
    /// that watches for the caller cancelling.
    pending_incoming: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    /// The PBX-issued gateway token. Shared with the status-poll threads so
    /// they pick up a token replaced by `set_gateway_token`.
    auth: Arc<auth::GatewayAuth>,
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
    /// Kept for apps that still poll `check_remote_hangup()`; the `Ended`
    /// event has already been emitted by the time an ID lands here.
    remote_ended: Arc<Mutex<Vec<String>>>,
    /// Interval between call-status polls. A field so tests can shorten it.
    poll_interval: Duration,
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
            gateway: gateway_client::GatewayClient::new(gateway_config.base_url),
            event_handler: Arc::new(RwLock::new(None)),
            audio_bridge: RwLock::new(None),
            calls: Arc::new(Mutex::new(HashMap::new())),
            pending_incoming: Arc::new(Mutex::new(HashMap::new())),
            auth: Arc::new(auth::GatewayAuth::new(gateway_config.api_key)),
            device_id: RwLock::new(None),
            ai: RwLock::new(None),
            codec_prefs: RwLock::new(vec![AudioCodec::Opus, AudioCodec::Pcmu, AudioCodec::Pcma]),
            last_registration: RwLock::new(None),
            remote_ended: Arc::new(Mutex::new(Vec::new())),
            poll_interval: CALL_STATUS_POLL_INTERVAL,
        }
    }

    pub fn set_event_handler(&self, handler: Box<dyn MobileEventHandler>) {
        let mut eh = self
            .event_handler
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *eh = Some(Arc::from(handler));
    }

    pub fn set_audio_bridge(&self, bridge: Box<dyn media::PlatformAudioBridge>) {
        let mut ab = self.audio_bridge.write().unwrap();
        *ab = Some(Arc::from(bridge));
    }

    fn emit_call_state(&self, info: &CallInfo) {
        emit_call_state_to(&self.event_handler, info);
    }

    #[allow(dead_code)]
    fn emit_error(&self, context: &str, message: &str) {
        let (context, message) = (context.to_string(), message.to_string());
        with_handler(&self.event_handler, |h| h.on_error(context, message));
    }

    /// Replace the bearer token used for every gateway request.
    ///
    /// The app gets the token from the PBX, at device registration and later
    /// from `POST /api/v1/devices/{id}/gateway-token`; the core never mints
    /// one. Background polls pick the new token up on their next request.
    pub fn set_gateway_token(&self, token: String) {
        self.auth.set(token);
    }

    // ── Device Registration ─────────────────────────────────────────

    pub fn register_device(
        &self,
        registration: DeviceRegistration,
    ) -> Result<DeviceRegistrationResponse, MobileError> {
        let rt = runtime();
        rt.block_on(async {
            // The token is the one the PBX issued, from `GatewayConfig.api_key`
            // or `set_gateway_token`. The core does not mint tokens.
            let token = self.auth.token()?;

            // Pick up SRV failover targets before the first request.
            let _ = self.gateway.resolve_gateway().await;

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

            {
                let mut d = self.device_id.write().unwrap();
                *d = Some(resp.device_id.clone());
            }

            let device_id = resp.device_id.clone();
            with_handler(&self.event_handler, |h| {
                h.on_registration_changed(device_id, "registered".to_string(), None);
            });

            Ok(resp)
        })
    }

    pub fn unregister_device(&self, device_id: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            self.gateway.unregister_device(&token, &device_id).await?;

            {
                let mut d = self.device_id.write().unwrap();
                *d = None;
            }

            with_handler(&self.event_handler, |h| {
                h.on_registration_changed(device_id, "unregistered".to_string(), None);
            });

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
            let token = self.auth.token()?;
            let offer = self
                .gateway
                .get_call_offer(&token, &payload.call_token)
                .await?;

            // Watch for the caller giving up before the user answers. A push
            // can be delivered more than once for the same call; only one
            // watcher runs per call_token.
            self.start_pending_incoming_poll(&offer);

            let for_handler = offer.clone();
            with_handler(&self.event_handler, |h| h.on_incoming_call(for_handler));

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
            let token = self.auth.token()?;

            // Get the call offer to know what codecs the remote supports
            let offer = self.gateway.get_call_offer(&token, &call_token).await?;

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
            self.clear_pending_incoming(&call_token);

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
            // Report Connected before the poll starts, so a remote hangup
            // can never be reported ahead of it.
            self.emit_call_state(&info);
            self.start_call_status_poll(call_id.clone(), call_token, poll_stop);
            Ok(info)
        })
    }

    pub fn reject_incoming_call(&self, call_token: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            self.gateway.reject_call(&token, &call_token).await?;
            self.clear_pending_incoming(&call_token);
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
            let token = self.auth.token()?;

            let codecs = if preferred_codecs.is_empty() {
                self.codec_prefs.read().unwrap().clone()
            } else {
                preferred_codecs
            };

            // Allocate RTP port and build SDP offer
            let (media_session, sdp_offer) = media::create_offer_session(&codecs).await?;

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
            //
            // `Ringing` has already been reported for this call_id, so a
            // failure here must close it with `Ended`; otherwise an
            // event-driven app is left showing a call that never connects.
            let (call_token, sdp_answer) = match self
                .gateway
                .make_call(&token, &uri, &sdp_offer, &credentials)
                .await
            {
                Ok(answer) => answer,
                Err(e) => {
                    info.state = CallState::Ended;
                    self.emit_call_state(&info);
                    return Err(e);
                }
            };

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
            // Report Connected before the poll starts, so a remote hangup
            // can never be reported ahead of it.
            self.emit_call_state(&info);
            self.start_call_status_poll(call_id.clone(), call_token, poll_stop);
            log::info!("Outgoing call to {} connected via gateway", uri);

            Ok(info)
        })
    }

    // ── Mid-call Controls ───────────────────────────────────────────

    pub fn hangup(&self, call_id: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            // Taking the call out of the map stops its poll and media, and
            // means a racing remote-hangup poll cannot also report it.
            let call = take_call(&self.calls, &call_id).ok_or(MobileError::InvalidState)?;

            // If gateway-routed, send hangup to gateway. Other gateway
            // failures are ignored as before: the call is over locally either
            // way, and the gateway also ends it when the PBX sends BYE.
            let mut result = Ok(());
            if let Some(call_token) = &call.call_token {
                let sent = match self.auth.token() {
                    Ok(token) => self.gateway.hangup_call(&token, call_token).await,
                    Err(e) => Err(e),
                };
                if let Err(MobileError::AuthenticationError) = sent {
                    // The local call still ends, but the far end may stay up
                    // until the PBX times it out, so the app must know.
                    result = Err(MobileError::AuthenticationError);
                }
            }

            emit_ended(&self.event_handler, &call);

            result
        })
    }

    /// Blind-transfer an active call to `target`.
    ///
    /// The gateway sends the REFER; once it has accepted the transfer this
    /// handset is out of the call, so the local call and media are torn down
    /// and `Ended` is emitted exactly as for a remote hangup. On any error the
    /// call is left as it was.
    pub fn transfer_call(&self, call_id: String, target: String) -> Result<(), MobileError> {
        let target = target.trim();
        validate_transfer_target(target)?;

        let call_token = {
            let calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let call = calls.get(&call_id).ok_or(MobileError::InvalidState)?;
            // Only gateway-routed calls can be transferred: the REFER is sent
            // by the gateway on the call it holds.
            call.call_token.clone().ok_or(MobileError::InvalidState)?
        };

        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            self.gateway
                .transfer_call(&token, &call_token, target)
                .await?;
            log::info!("Call {} transferred", call_id);

            // The PBX may already have sent the BYE that ends our leg, in which
            // case the status poll has torn the call down and reported it.
            // Either way `Ended` is emitted once.
            end_call_locally(&self.calls, &self.event_handler, &call_id);
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

    /// Spawn a background thread that polls the gateway for a call's status
    /// every `poll_interval` until `stop` is set, `on_status` returns true, or
    /// `max_age` (when given) has elapsed.
    ///
    /// The thread reads the current gateway token on every poll, so a token
    /// replaced by `set_gateway_token` is picked up rather than polling with
    /// an expired one.
    fn spawn_status_poll(
        &self,
        call_token: String,
        stop: Arc<AtomicBool>,
        max_age: Option<Duration>,
        mut on_status: impl FnMut(&CallStatusResponse) -> bool + Send + 'static,
    ) {
        let started = Instant::now();
        let base_url = self.gateway.base_url().to_string();
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.event_handler);
        let interval = self.poll_interval;

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Could not start call status poll: {}", e);
                    return;
                }
            };

            let gateway = gateway_client::GatewayClient::new(base_url);

            rt.block_on(async {
                loop {
                    tokio::time::sleep(interval).await;

                    if stop.load(Ordering::Relaxed) {
                        log::debug!("Call status poll stopped for {}", call_token);
                        break;
                    }
                    if max_age.is_some_and(|age| started.elapsed() >= age) {
                        log::debug!("Call status poll expired for {}", call_token);
                        break;
                    }

                    // With no token at all the request goes out unauthenticated,
                    // so the gateway's 401 reaches the app the same way.
                    let (token, generation) = auth.current().unwrap_or_default();
                    match gateway.get_call_status(&token, &call_token).await {
                        Ok(status) => {
                            if on_status(&status) {
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        // An expired token says nothing about the call, so the
                        // poll keeps the call up and keeps polling; it resumes
                        // with the next token from `set_gateway_token`.
                        Err(MobileError::AuthenticationError) => {
                            report_auth_rejected(&auth, &handler, generation);
                        }
                        Err(e) => {
                            log::warn!("Call status poll error: {}", e);
                        }
                    }
                }
            });
        });
    }

    /// Poll an established call for a remote hangup (BYE from the PBX).
    ///
    /// When the gateway reports the call gone, the poll thread tears the call
    /// down and emits `Ended` itself, so apps learn of a remote hangup through
    /// `on_call_state_changed` without polling `check_remote_hangup`.
    fn start_call_status_poll(&self, call_id: String, call_token: String, stop: Arc<AtomicBool>) {
        let calls = Arc::clone(&self.calls);
        let handler = Arc::clone(&self.event_handler);
        let remote_ended = Arc::clone(&self.remote_ended);

        self.spawn_status_poll(call_token, stop, None, move |status| {
            if !status_means_ended(&status.status) {
                return false;
            }
            log::info!(
                "Remote hangup detected for {} (reason: {:?})",
                call_id,
                status.reason,
            );
            if end_call_locally(&calls, &handler, &call_id) {
                let mut ended = remote_ended
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                ended.push(call_id.clone());
                if ended.len() > REMOTE_ENDED_BACKLOG {
                    let excess = ended.len() - REMOTE_ENDED_BACKLOG;
                    ended.drain(..excess);
                }
            }
            true
        });
    }

    /// Watch an offered incoming call for the caller hanging up before it is
    /// answered (a CANCEL at the PBX).
    ///
    /// If that happens while the call is still unanswered, `Ended` is emitted
    /// for the call_id the call would have had (`incoming-<call_token>`), so
    /// the app can dismiss its ringing UI. The watch stops as soon as the call
    /// is accepted or rejected.
    fn start_pending_incoming_poll(&self, offer: &CallOffer) {
        let call_token = offer.call_token.clone();
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut pending = self
                .pending_incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending.contains_key(&call_token) {
                return;
            }
            pending.insert(call_token.clone(), Arc::clone(&stop));
        }

        let info = CallInfo {
            call_id: format!("incoming-{call_token}"),
            remote_uri: offer.caller_uri.clone(),
            remote_name: offer.caller_name.clone(),
            state: CallState::Ended,
            direction: CallDirection::Inbound,
            muted: false,
            on_hold: false,
            duration_secs: 0,
        };
        let pending = Arc::clone(&self.pending_incoming);
        let handler = Arc::clone(&self.event_handler);
        let token = call_token.clone();
        // While the gateway hands a call from pending to active it can briefly
        // report "unknown", so only several in a row count as gone. "ended" is
        // definitive: the gateway records a CANCEL that way.
        let mut unknown_streak = 0u32;

        let deadline = Some(PENDING_INCOMING_MAX_WATCH);
        self.spawn_status_poll(call_token, stop, deadline, move |status| {
            let gone = match status.status.as_str() {
                "ended" => true,
                "unknown" => {
                    unknown_streak += 1;
                    unknown_streak >= 3
                }
                // Answered, here or on another device: nothing to report.
                "active" => {
                    pending
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&token);
                    return true;
                }
                _ => {
                    unknown_streak = 0;
                    false
                }
            };
            if !gone {
                return false;
            }
            // Removing the entry decides the race with accept/reject: if they
            // got there first, the app already knows the outcome.
            let still_pending = pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&token)
                .is_some();
            if still_pending {
                log::info!(
                    "Incoming call {} ended before answer (reason: {:?})",
                    token,
                    status.reason,
                );
                emit_call_state_to(&handler, &info);
            }
            true
        });
    }

    /// Stop watching an offered incoming call; it has been accepted or rejected.
    fn clear_pending_incoming(&self, call_token: &str) {
        let removed = self
            .pending_incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(call_token);
        if let Some(stop) = removed {
            stop.store(true, Ordering::Relaxed);
        }
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
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let ended_id = self
            .remote_ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();

        // The poll thread has normally torn the call down and emitted `Ended`
        // already; this only acts if it somehow has not.
        if let Some(call_id) = &ended_id {
            end_call_locally(&self.calls, &self.event_handler, call_id);
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
        let current = self.auth.current();
        if let (Some(did), Some((tok, generation))) = (device_id, current) {
            log::info!("Sending heartbeat for device {} after network change", did);
            // A fresh client on its own thread and runtime, as for the status
            // polls: this runs in the background and must not block the caller.
            let base_url = self.gateway.base_url().to_string();
            let auth = Arc::clone(&self.auth);
            let handler = Arc::clone(&self.event_handler);
            std::thread::spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    let gateway = gateway_client::GatewayClient::new(base_url);
                    match rt.block_on(gateway.device_heartbeat(&tok, &did)) {
                        Ok(()) => log::info!("Gateway heartbeat successful after network change"),
                        Err(MobileError::AuthenticationError) => {
                            report_auth_rejected(&auth, &handler, generation);
                        }
                        Err(e) => log::warn!("Gateway heartbeat failed: {}", e),
                    }
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

/// A minimal HTTP/1.1 server standing in for the push gateway in tests.
///
/// The crate has no HTTP mocking dependency, and adding one for a handful of
/// canned responses is not worth it: this answers each request from a
/// caller-supplied function and records what it received.
#[cfg(test)]
pub(crate) mod mock_gateway {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub authorization: Option<String>,
        pub body: String,
    }

    pub struct MockGateway {
        pub base_url: String,
        requests: Arc<Mutex<Vec<Request>>>,
    }

    impl MockGateway {
        /// Serve until the test process exits, answering each request with
        /// `respond(&request) -> (status, json body)`.
        pub fn start(respond: impl Fn(&Request) -> (u16, String) + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock gateway");
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&requests);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let Some(req) = read_request(&mut stream) else {
                        continue;
                    };
                    let (status, body) = respond(&req);
                    seen.lock().unwrap().push(req);
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            });
            Self { base_url, requests }
        }

        pub fn requests(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Option<Request> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let mut parts = line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();

        let mut content_length = 0usize;
        let mut authorization = None;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).ok()?;
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':')?;
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.parse().ok()?,
                "authorization" => authorization = Some(value.to_string()),
                _ => {}
            }
        }

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok()?;
        Some(Request {
            method,
            path,
            authorization,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mock_gateway::MockGateway;

    /// Records every callback so tests can assert on the event stream.
    #[derive(Default, Clone)]
    struct Recorder {
        states: Arc<Mutex<Vec<CallInfo>>>,
        auth_required: Arc<Mutex<u32>>,
    }

    impl Recorder {
        fn states(&self) -> Vec<CallInfo> {
            self.states.lock().unwrap().clone()
        }

        fn auth_required(&self) -> u32 {
            *self.auth_required.lock().unwrap()
        }

        /// Wait for at least `n` call-state events, for events emitted from
        /// a poll thread.
        fn wait_for(&self, n: usize) -> Vec<CallInfo> {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.states.lock().unwrap().len() >= n {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            self.states()
        }
    }

    impl MobileEventHandler for Recorder {
        fn on_registration_changed(&self, _: String, _: String, _: Option<String>) {}
        fn on_incoming_call(&self, _: CallOffer) {}
        fn on_call_state_changed(&self, info: CallInfo) {
            self.states.lock().unwrap().push(info);
        }
        fn on_media_stats(&self, _: String, _: MediaStats) {}
        fn on_error(&self, _: String, _: String) {}
        fn on_auth_required(&self) {
            *self.auth_required.lock().unwrap() += 1;
        }
    }

    fn engine(base_url: &str) -> (AriaMobileEngine, Recorder) {
        init_runtime();
        let mut engine = AriaMobileEngine::new(GatewayConfig {
            base_url: base_url.to_string(),
            api_key: "jwt".to_string(),
        });
        engine.poll_interval = Duration::from_millis(20);
        let recorder = Recorder::default();
        engine.set_event_handler(Box::new(recorder.clone()));
        (engine, recorder)
    }

    /// Put a connected, gateway-routed call in the engine without media.
    fn insert_call(engine: &AriaMobileEngine, call_id: &str, call_token: &str) -> Arc<AtomicBool> {
        let poll_stop = Arc::new(AtomicBool::new(false));
        engine.calls.lock().unwrap().insert(
            call_id.to_string(),
            ActiveCallState {
                info: CallInfo {
                    call_id: call_id.to_string(),
                    remote_uri: "sip:1001@pbx.example.com".to_string(),
                    remote_name: None,
                    state: CallState::Connected,
                    direction: CallDirection::Outbound,
                    muted: false,
                    on_hold: false,
                    duration_secs: 0,
                },
                media: None,
                call_token: Some(call_token.to_string()),
                poll_stop: Arc::clone(&poll_stop),
            },
        );
        poll_stop
    }

    /// An address nothing listens on, for tests that must not reach a gateway.
    const NO_GATEWAY: &str = "http://127.0.0.1:9";

    #[test]
    fn transfer_target_validation() {
        for ok in ["1002", "sip:1002@pbx.example.com", "+15551234567"] {
            assert!(
                validate_transfer_target(ok).is_ok(),
                "{ok:?} should be accepted"
            );
        }
        for bad in [
            "",
            "   ",
            "1002\r\nX-Injected: 1",
            "1002\n",
            "<sip:1002@pbx>",
            "sip:1002@pbx>;foo",
        ] {
            assert!(
                matches!(
                    validate_transfer_target(bad),
                    Err(MobileError::InvalidTarget)
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn invalid_target_is_refused_before_the_gateway_and_keeps_the_call() {
        let (engine, recorder) = engine(NO_GATEWAY);
        insert_call(&engine, "c1", "tok");

        let err = engine
            .transfer_call("c1".into(), "1002\r\nVia: evil".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::InvalidTarget));
        assert!(engine.get_active_call().is_some());
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn transfer_of_an_unknown_call_is_invalid_state() {
        let (engine, _) = engine(NO_GATEWAY);
        let err = engine
            .transfer_call("nope".into(), "1002".into())
            .unwrap_err();
        assert!(matches!(err, MobileError::InvalidState));
    }

    #[test]
    fn successful_transfer_ends_the_call_and_emits_ended_once() {
        let gw = MockGateway::start(|_| (202, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);
        let poll_stop = insert_call(&engine, "c1", "tok-42");

        engine
            .transfer_call("c1".into(), " sip:1002@pbx.example.com ".into())
            .unwrap();

        let reqs = gw.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].path, "/v1/calls/tok-42/transfer");
        // The target is trimmed before it is sent.
        assert_eq!(reqs[0].body, r#"{"target":"sip:1002@pbx.example.com"}"#);

        assert!(engine.get_active_call().is_none());
        assert!(
            poll_stop.load(Ordering::Relaxed),
            "status poll must be stopped"
        );
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "c1");
        assert_eq!(states[0].state, CallState::Ended);
    }

    #[test]
    fn failed_transfer_leaves_the_call_up() {
        for (status, check) in [
            (
                400,
                (|e| matches!(e, MobileError::InvalidTarget)) as fn(&MobileError) -> bool,
            ),
            (404, |e| matches!(e, MobileError::InvalidState)),
            (502, |e| matches!(e, MobileError::CallFailed)),
        ] {
            let gw = MockGateway::start(move |_| (status, "{}".into()));
            let (engine, recorder) = engine(&gw.base_url);
            insert_call(&engine, "c1", "tok");

            let err = engine
                .transfer_call("c1".into(), "1002".into())
                .unwrap_err();

            assert!(check(&err), "HTTP {status} gave {err:?}");
            assert!(engine.get_active_call().is_some(), "HTTP {status}");
            assert!(recorder.states().is_empty(), "HTTP {status}");
        }
    }

    #[test]
    fn remote_hangup_is_emitted_without_check_remote_hangup() {
        let polls = Arc::new(Mutex::new(0u32));
        let counter = Arc::clone(&polls);
        let gw = MockGateway::start(move |req| {
            assert_eq!(req.path, "/v1/calls/tok-7/status");
            let mut n = counter.lock().unwrap();
            *n += 1;
            if *n < 3 {
                (200, r#"{"status":"active"}"#.into())
            } else {
                (200, r#"{"status":"ended","reason":"bye"}"#.into())
            }
        });
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok-7");

        engine.start_call_status_poll("c1".into(), "tok-7".into(), stop);

        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "c1");
        assert_eq!(states[0].state, CallState::Ended);
        assert!(engine.get_active_call().is_none());

        // Apps that still poll keep working, and see no second event.
        assert_eq!(engine.check_remote_hangup().as_deref(), Some("c1"));
        assert_eq!(engine.check_remote_hangup(), None);
        assert_eq!(recorder.states().len(), 1);
    }

    #[test]
    fn hangup_after_remote_end_does_not_emit_twice() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok");
        engine.start_call_status_poll("c1".into(), "tok".into(), stop);
        recorder.wait_for(1);

        assert!(matches!(
            engine.hangup("c1".into()),
            Err(MobileError::InvalidState)
        ));
        assert_eq!(recorder.states().len(), 1);
    }

    #[test]
    fn local_hangup_emits_ended() {
        let gw = MockGateway::start(|_| (200, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        engine.hangup("c1".into()).unwrap();

        assert_eq!(gw.requests()[0].path, "/v1/calls/tok/hangup");
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
    }

    #[test]
    fn remote_ended_backlog_is_bounded() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);
        let n = REMOTE_ENDED_BACKLOG + 4;
        for i in 0..n {
            let id = format!("c{i}");
            let stop = insert_call(&engine, &id, &format!("tok{i}"));
            engine.start_call_status_poll(id, format!("tok{i}"), stop);
        }
        assert_eq!(recorder.wait_for(n).len(), n);
        assert_eq!(
            engine.remote_ended.lock().unwrap().len(),
            REMOTE_ENDED_BACKLOG
        );
    }

    fn offer(token: &str) -> CallOffer {
        CallOffer {
            call_token: token.to_string(),
            caller_uri: "sip:1001@pbx.example.com".to_string(),
            caller_name: Some("Alice".to_string()),
            sdp_offer: String::new(),
        }
    }

    #[test]
    fn caller_cancel_before_answer_emits_ended() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended","reason":"cancelled"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-9"));

        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "incoming-tok-9");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].direction, CallDirection::Inbound);
        assert_eq!(states[0].remote_name.as_deref(), Some("Alice"));
        assert!(engine.pending_incoming.lock().unwrap().is_empty());
    }

    #[test]
    fn answered_or_rejected_call_is_not_reported_as_cancelled() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-1"));
        engine.clear_pending_incoming("tok-1");

        std::thread::sleep(Duration::from_millis(200));
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn a_brief_unknown_during_answer_is_not_a_cancel() {
        let polls = Arc::new(Mutex::new(0u32));
        let counter = Arc::clone(&polls);
        let gw = MockGateway::start(move |_| {
            let mut n = counter.lock().unwrap();
            *n += 1;
            match *n {
                1 => (200, r#"{"status":"pending"}"#.into()),
                2 => (200, r#"{"status":"unknown"}"#.into()),
                _ => (200, r#"{"status":"active"}"#.into()),
            }
        });
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-2"));

        let deadline = Instant::now() + Duration::from_secs(5);
        while !engine.pending_incoming.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(engine.pending_incoming.lock().unwrap().is_empty());
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn duplicate_push_starts_one_watch() {
        let (engine, _) = engine(NO_GATEWAY);
        engine.start_pending_incoming_poll(&offer("tok-3"));
        let first = Arc::clone(
            engine
                .pending_incoming
                .lock()
                .unwrap()
                .get("tok-3")
                .unwrap(),
        );
        engine.start_pending_incoming_poll(&offer("tok-3"));
        let second = Arc::clone(
            engine
                .pending_incoming
                .lock()
                .unwrap()
                .get("tok-3")
                .unwrap(),
        );
        assert!(Arc::ptr_eq(&first, &second));
        engine.clear_pending_incoming("tok-3");
    }

    fn registration() -> DeviceRegistration {
        DeviceRegistration {
            platform: "android".into(),
            push_token: "push".into(),
            bundle_id: None,
            sip: SipCredentials {
                username: "1001".into(),
                password: "pw".into(),
                domain: "pbx.example.com".into(),
                registrar: None,
                transport: "udp".into(),
                port: 5060,
                auth_username: None,
                display_name: "Alice".into(),
            },
        }
    }

    #[test]
    fn registration_uses_the_pbx_token_and_never_mints_one() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/devices" => (200, r#"{"device_id":"d1","status":"ok"}"#.into()),
            _ => (200, "{}".into()),
        });
        let (engine, _) = engine(&gw.base_url);

        let resp = engine.register_device(registration()).unwrap();
        assert_eq!(resp.device_id, "d1");
        assert_eq!(resp.auth_token, "jwt");

        engine.set_gateway_token("rotated".into());
        engine
            .update_push_token("d1".into(), "push2".into())
            .unwrap();
        insert_call(&engine, "c1", "tok");
        engine.hangup("c1".into()).unwrap();

        let reqs = gw.requests();
        assert!(reqs.iter().all(|r| r.path != "/v1/auth/token"));
        let auth: Vec<_> = reqs
            .iter()
            .map(|r| (r.path.as_str(), r.authorization.as_deref()))
            .collect();
        assert_eq!(
            auth,
            [
                ("/v1/devices", Some("Bearer jwt")),
                ("/v1/devices", Some("Bearer rotated")),
                ("/v1/calls/tok/hangup", Some("Bearer rotated")),
            ]
        );
    }

    #[test]
    fn without_a_token_registration_fails_without_a_request() {
        let gw = MockGateway::start(|_| (200, "{}".into()));
        init_runtime();
        let engine = AriaMobileEngine::new(GatewayConfig {
            base_url: gw.base_url.clone(),
            api_key: String::new(),
        });
        assert!(matches!(
            engine.register_device(registration()),
            Err(MobileError::AuthenticationError)
        ));
        assert!(gw.requests().is_empty());
    }

    fn is_auth_error<T>(r: Result<T, MobileError>) -> bool {
        matches!(r, Err(MobileError::AuthenticationError))
    }

    #[test]
    fn a_401_from_the_gateway_is_an_authentication_error() {
        let gw = MockGateway::start(|_| (401, "{}".into()));
        let (engine, _) = engine(&gw.base_url);

        assert!(is_auth_error(engine.register_device(registration())));
        assert!(is_auth_error(engine.unregister_device("d1".into())));
        assert!(is_auth_error(engine.handle_push_notification(
            PushCallPayload {
                call_token: "tok".into(),
                caller_uri: "sip:1001@pbx.example.com".into(),
                caller_name: None,
                gateway_url: gw.base_url.clone(),
            }
        )));
        assert!(is_auth_error(
            engine.accept_incoming_call("tok".into(), vec![])
        ));
        assert!(is_auth_error(engine.reject_incoming_call("tok".into())));
        insert_call(&engine, "c1", "tok");
        assert!(is_auth_error(
            engine.transfer_call("c1".into(), "1002".into())
        ));
        // A refused transfer leaves the call up.
        assert!(engine.get_active_call().is_some());
    }

    #[test]
    fn hangup_with_a_rejected_token_still_ends_the_call() {
        let gw = MockGateway::start(|_| (401, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        assert!(is_auth_error(engine.hangup("c1".into())));

        assert!(engine.get_active_call().is_none());
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        // Synchronous methods report through the error, not the callback.
        assert_eq!(recorder.auth_required(), 0);
    }

    /// Wait until `f` holds, for state changed by a poll thread.
    fn eventually(mut f: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        f()
    }

    #[test]
    fn a_rejected_poll_asks_for_a_token_once_and_keeps_the_call() {
        // Reject every token except "fresh"; with "fresh" the call is live.
        let gw = MockGateway::start(|req| {
            if req.authorization.as_deref() == Some("Bearer fresh") {
                (200, r#"{"status":"active"}"#.into())
            } else {
                (401, "{}".into())
            }
        });
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok");
        engine.start_call_status_poll("c1".into(), "tok".into(), Arc::clone(&stop));

        // Many rejected polls, one callback.
        assert!(eventually(|| gw.requests().len() >= 5));
        assert_eq!(recorder.auth_required(), 1);
        assert!(engine.get_active_call().is_some());
        assert!(recorder.states().is_empty());

        // A new token that is also rejected is reported again, once.
        engine.set_gateway_token("also-expired".into());
        let seen = gw.requests().len();
        assert!(eventually(|| gw.requests().len() >= seen + 5));
        assert_eq!(recorder.auth_required(), 2);

        // A working token resumes polling, and the call is still up.
        engine.set_gateway_token("fresh".into());
        assert!(eventually(|| gw
            .requests()
            .iter()
            .any(|r| r.authorization.as_deref() == Some("Bearer fresh"))));
        assert_eq!(recorder.auth_required(), 2);
        assert!(engine.get_active_call().is_some());
        assert!(recorder.states().is_empty());
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn a_rejected_cancel_watch_asks_for_a_token_and_reports_no_cancel() {
        let gw = MockGateway::start(|_| (401, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-5"));

        assert!(eventually(|| gw.requests().len() >= 5));
        assert_eq!(recorder.auth_required(), 1);
        assert!(recorder.states().is_empty());
        engine.clear_pending_incoming("tok-5");
    }

    /// A callback that re-enters the engine must not deadlock: the handler is
    /// cloned out of its lock before it is invoked.
    #[test]
    fn handler_can_replace_itself_from_a_callback() {
        struct Reentrant {
            engine: Arc<AriaMobileEngine>,
            fired: Arc<AtomicBool>,
        }
        impl MobileEventHandler for Reentrant {
            fn on_registration_changed(&self, _: String, _: String, _: Option<String>) {}
            fn on_incoming_call(&self, _: CallOffer) {}
            fn on_call_state_changed(&self, _: CallInfo) {
                self.fired.store(true, Ordering::Relaxed);
                self.engine.set_event_handler(Box::new(Recorder::default()));
            }
            fn on_media_stats(&self, _: String, _: MediaStats) {}
            fn on_error(&self, _: String, _: String) {}
            fn on_auth_required(&self) {}
        }

        let (engine, _) = engine(NO_GATEWAY);
        let engine = Arc::new(engine);
        let fired = Arc::new(AtomicBool::new(false));
        engine.set_event_handler(Box::new(Reentrant {
            engine: Arc::clone(&engine),
            fired: Arc::clone(&fired),
        }));
        insert_call(&engine, "c1", "tok");

        end_call_locally(&engine.calls, &engine.event_handler, "c1");

        assert!(fired.load(Ordering::Relaxed));
        // Break the Arc cycle (engine -> handler -> engine).
        engine.event_handler.write().unwrap().take();
    }
}
