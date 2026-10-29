//! Aria Mobile Core — shared Rust engine for iOS and Android softphone apps.
//!
//! Provides:
//! - Push gateway HTTP client (device registration, call signaling)
//! - SDP generation/parsing for RTP media
//! - RTP media session management (codec encode/decode, SRTP)
//! - UniFFI bindings for Swift (iOS) and Kotlin (Android)

mod auth;
pub mod dns;
mod events;
mod gateway_client;
mod media;
mod types;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub mod ai;

use events::{CallEvents, Dispatcher};
use gateway_client::Route;
pub use media::PlatformAudioBridge;
/// The API's public types (`CallInfo`, `MobileError`, `SipCredentials`, ...),
/// re-exported so Rust crates can use the engine directly, not only through
/// the generated bindings.
pub use types::*;

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

/// Active calls keyed by call_id, shared with the status-poll threads.
type CallMap = Arc<Mutex<HashMap<String, ActiveCallState>>>;

/// How many calls can be live at once: connected (held or not), outgoing and
/// ringing, or incoming and being accepted. One call plus one waiting call.
///
/// Offered incoming calls are not counted. They have not been answered, so
/// they cost no media, and the app must still be able to show (and decline)
/// a call that arrives while two are up; only accepting it is refused.
const MAX_LIVE_CALLS: usize = 2;

/// How many remotely ended call IDs `check_remote_hangup` keeps for apps that
/// still poll it. An event-driven app never drains the queue, so it is capped.
const REMOTE_ENDED_BACKLOG: usize = 16;

/// How long an unanswered incoming call is watched for a caller cancel before
/// the watch gives up. Well past any ring timeout a PBX would apply.
const PENDING_INCOMING_MAX_WATCH: Duration = Duration::from_secs(10 * 60);

/// How often `transfer_call` polls for the outcome of an accepted transfer.
const TRANSFER_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// How long `transfer_call` waits for that outcome before giving up.
///
/// Longer than the gateway's own 30 s NOTIFY watchdog, which reports a
/// transfer with no outcome as failed with 408, so the gateway's verdict
/// normally arrives first; this only covers a gateway that stops answering.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(35);

/// Once one call of an attended transfer is reported transferred, how long
/// the other has to be reported ended too before it is ended here.
const TRANSFER_SETTLE: Duration = Duration::from_secs(5);

/// One call of a transfer whose outcome is awaited.
struct TransferLeg<'a> {
    call_id: &'a str,
    call_token: &'a str,
    route: &'a Route,
}

/// How often a call's status is polled at the gateway.
const CALL_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Tell the app that background work had the gateway token of `generation`
/// rejected, unless it has already been told about this token.
fn report_auth_rejected(auth: &auth::GatewayAuth, events: &Dispatcher, generation: u64) {
    if auth.report_rejection(generation) {
        log::warn!("Gateway rejected the token; asking the app for a new one");
        events.auth_required();
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
    stop_call(&mut call);
    Some(call)
}

/// Stop a call's status poll and media once it is out of the map.
fn stop_call(call: &mut ActiveCallState) {
    call.poll_stop.store(true, Ordering::Relaxed);
    if let Some(media) = call.media.take() {
        media.stop();
    }
}

/// Hang a call up at the gateway, in the background after it has already
/// ended locally.
///
/// A failure other than a rejected token is retried once on the call's own
/// gateway instance: a 404 there means the gateway does not know the call
/// (it lost it, or the app is talking to it with the wrong token), and the
/// far end may still be connected. If the retry fails too, the app is told
/// through `on_error`, since nothing else would notice. A rejected token is
/// reported through `on_auth_required`.
async fn hang_up_at_gateway(
    gateway: &gateway_client::GatewayClient,
    auth: &auth::GatewayAuth,
    events: &Dispatcher,
    route: &Route,
    call_id: &str,
    call_token: &str,
) {
    let mut last = MobileError::NetworkError;
    for attempt in 0..2 {
        let (token, generation) = auth.snapshot();
        match gateway.hangup_call(route, &token, call_token).await {
            Ok(()) => {
                log::info!("Call {call_id} hung up at the gateway");
                return;
            }
            Err(MobileError::AuthenticationError) => {
                report_auth_rejected(auth, events, generation);
                return;
            }
            Err(e) => {
                log::warn!("Hangup of {call_id} failed (attempt {}): {e}", attempt + 1);
                last = e;
            }
        }
    }
    let why = match last {
        MobileError::InvalidState => "the gateway does not know the call".to_string(),
        other => other.to_string(),
    };
    events.error(
        "hangup".into(),
        format!(
            "Call {call_id} ended here, but the gateway did not confirm the hangup ({why}). \
             The other party may still be connected."
        ),
    );
}

/// Delays between cancel attempts that get 404 while `POST /v1/calls` is
/// still in flight: the gateway may not have registered the call's
/// `client_ref` yet.
const CANCEL_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
];

/// What `cancel_at_gateway` needs to know about a ringing call.
struct CancelTarget<'a> {
    call_id: &'a str,
    client_ref: &'a str,
    /// The instance `POST /v1/calls` was sent to, once it has been.
    route: &'a Mutex<Option<Route>>,
    request_done: tokio::sync::watch::Receiver<bool>,
}

/// Cancel a ringing outgoing call at the gateway. Returns whether the
/// gateway accepted the cancel (202).
async fn cancel_at_gateway(
    gateway: &gateway_client::GatewayClient,
    auth: &auth::GatewayAuth,
    events: &Dispatcher,
    pending: CancelTarget<'_>,
) -> bool {
    let mut request_done = pending.request_done.clone();
    let mut delays = CANCEL_RETRY_DELAYS.iter();
    loop {
        // Read each time: a connect failure may have moved the request on.
        let route = pending
            .route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| gateway.primary_route());
        let (token, generation) = auth.snapshot();
        match gateway
            .cancel_call(&route, &token, pending.client_ref)
            .await
        {
            Ok(true) => {
                log::info!("Outgoing call {} cancelled at the gateway", pending.call_id);
                return true;
            }
            Ok(false) => {
                // Unknown ref: either not registered yet, or the call has
                // been answered (or the gateway predates the route). Retry
                // only while `POST /v1/calls` is still in flight.
                let Some(delay) = delays.next() else {
                    log::info!("Gateway never knew the call to cancel; hanging up on answer");
                    return false;
                };
                if *request_done.borrow() {
                    log::info!("Call already answered or failed; nothing to cancel");
                    return false;
                }
                tokio::select! {
                    _ = tokio::time::sleep(*delay) => {}
                    _ = request_done.wait_for(|done| *done) => return false,
                }
            }
            Err(MobileError::AuthenticationError) => {
                report_auth_rejected(auth, events, generation);
                return false;
            }
            Err(e) => {
                log::warn!("Cancel failed ({e}); hanging up on answer");
                return false;
            }
        }
    }
}

/// Report a call that has been taken out of the map as ended.
fn emit_ended(events: &Dispatcher, call: &ActiveCallState, reason: EndReason) {
    call.events.emit_ended(events, &call.info, reason);
}

/// Tear a call down locally and emit `Ended`, unless it was already gone.
/// Returns whether this call did the teardown.
fn end_call_locally(
    calls: &CallMap,
    events: &Dispatcher,
    call_id: &str,
    reason: EndReason,
) -> bool {
    match take_call(calls, call_id) {
        Some(call) => {
            emit_ended(events, &call, reason);
            true
        }
        None => false,
    }
}

/// Put a connected call on or off hold here (no re-INVITE): its media and its
/// reported state. Returns whether its hold state changed; the caller queues
/// the event.
fn apply_hold(call: &mut ActiveCallState, on_hold: bool) -> bool {
    if let Some(media) = &call.media {
        media.set_hold(on_hold);
    }
    let changed = call.info.on_hold != on_hold;
    call.info.on_hold = on_hold;
    call.info.state = if on_hold {
        CallState::OnHold
    } else {
        CallState::Connected
    };
    changed
}

/// Hold every connected call except `keep` that is not held already, and
/// report each one that changed.
///
/// Called under the call-map lock just before `keep` becomes the un-held
/// call, which keeps the invariant that at most one connected call is off
/// hold: only that call plays to the speaker and reads the microphone.
fn hold_others(calls: &mut HashMap<String, ActiveCallState>, keep: &str, events: &Dispatcher) {
    for (call_id, call) in calls.iter_mut() {
        if call_id != keep && apply_hold(call, true) {
            log::info!("Holding {call_id}: {keep} is now the active call");
            call.events.emit(events, call.info.clone());
        }
    }
}

/// How many calls count against [`MAX_LIVE_CALLS`].
fn live_call_count(
    calls: &HashMap<String, ActiveCallState>,
    outgoing: &OutgoingCalls,
    accepting: &HashSet<String>,
) -> usize {
    calls.len() + outgoing.ringing.len() + accepting.len()
}

/// The gateway route of the oldest live call whose route is known: a
/// connected call, or a ringing outgoing call once it has been sent.
fn live_call_route(
    calls: &HashMap<String, ActiveCallState>,
    outgoing: &OutgoingCalls,
) -> Option<Route> {
    let connected = calls.values().map(|c| (c.seq, Some(c.route.clone())));
    let ringing = outgoing.ringing.values().map(|p| {
        let route = p
            .route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (p.seq, route)
    });
    connected
        .chain(ringing)
        .filter_map(|(seq, route)| Some((seq, route?)))
        .min_by_key(|(seq, _)| *seq)
        .map(|(_, route)| route)
}

/// Every live call with its creation order: connected calls and ringing
/// outgoing ones.
fn live_calls(
    calls: &HashMap<String, ActiveCallState>,
    outgoing: &OutgoingCalls,
) -> Vec<(u64, CallInfo)> {
    let mut live: Vec<(u64, CallInfo)> = calls
        .values()
        .map(|c| (c.seq, c.info.clone()))
        .chain(outgoing.ringing.values().map(|p| (p.seq, p.info.clone())))
        .collect();
    live.sort_by_key(|(seq, _)| *seq);
    live
}

/// How many consecutive `unknown` statuses count as the gateway having lost
/// a call. A single one can be a transient answer (a gateway instance
/// restarting, or briefly between states) and must not drop a live call.
const UNKNOWN_STATUSES_BEFORE_ENDED: u32 = 3;

/// Tracks status answers for one call and says when they mean it is gone:
/// at once for `ended`, and after [`UNKNOWN_STATUSES_BEFORE_ENDED`]
/// consecutive `unknown`s.
#[derive(Default)]
struct GoneDetector {
    unknown_streak: u32,
}

impl GoneDetector {
    fn is_gone(&mut self, status: &str) -> bool {
        match status {
            "ended" => true,
            "unknown" => {
                self.unknown_streak += 1;
                self.unknown_streak >= UNKNOWN_STATUSES_BEFORE_ENDED
            }
            _ => {
                self.unknown_streak = 0;
                false
            }
        }
    }
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
    gateway: Arc<gateway_client::GatewayClient>,
    /// Delivers every callback on its own thread.
    events: Arc<Dispatcher>,
    /// Platform audio bridge for mic/speaker I/O
    audio_bridge: RwLock<Option<Arc<dyn media::PlatformAudioBridge>>>,
    /// Active calls keyed by call_id
    calls: CallMap,
    /// Incoming calls that have been offered but not yet accepted or
    /// rejected, keyed by call_token, each with the stop flag of the poll
    /// that watches for the caller cancelling.
    pending_incoming: Arc<Mutex<HashMap<String, PendingIncoming>>>,
    /// Outgoing calls that are ringing, keyed by call_id. A call moves from
    /// here to `calls` when it is answered. When both locks are held, `calls`
    /// is taken first.
    pending_outgoing: Mutex<OutgoingCalls>,
    /// Call tokens `accept_incoming_call` is accepting, counted against
    /// [`MAX_LIVE_CALLS`] until the call is in `calls` or the accept failed.
    /// Lock order: `calls`, then `pending_outgoing`, then this.
    accepting: Mutex<HashSet<String>>,
    /// Creation order of calls, for `get_calls`.
    next_seq: AtomicU64,
    /// The PBX-issued gateway token. Shared with the status-poll threads so
    /// they pick up a token replaced by `set_gateway_token`.
    auth: Arc<auth::GatewayAuth>,
    /// Registered device ID
    device_id: Arc<RwLock<Option<String>>>,
    /// Network-change heartbeats: at most one in flight, latest wins.
    heartbeat: Arc<Mutex<HeartbeatState>>,
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
    /// How often, and for how long, `transfer_call` polls for the outcome
    /// after the PBX accepted the REFER. Fields so tests can shorten them.
    transfer_poll_interval: Duration,
    transfer_timeout: Duration,
}

/// An offered incoming call that has not been accepted or rejected yet.
struct PendingIncoming {
    /// Stops the poll that watches the call.
    stop: Arc<AtomicBool>,
    /// The gateway instance that offered the call.
    route: Route,
    /// The call as it would be reported, under `incoming-<call_token>`.
    info: CallInfo,
    /// Shared with the active call if it is accepted, so the offer and the
    /// call get exactly one `Ended` between them.
    events: Arc<CallEvents>,
    /// `accept_incoming_call` is sending the accept, so an `active` status
    /// is this handset answering, not another device.
    accepting: bool,
    /// The accept may or may not have reached the gateway (it timed out or
    /// the connection dropped), and the app has been told the call ended.
    /// The watch hangs the call up if it turns out to have been answered,
    /// and rejects it if it is still ringing.
    abandoned: bool,
    /// The watch has already rejected the abandoned call.
    rejected: bool,
}

/// A slot under [`MAX_LIVE_CALLS`] held by `accept_incoming_call` for one
/// call token, released when dropped.
struct AcceptReservation<'a> {
    accepting: &'a Mutex<HashSet<String>>,
    call_token: String,
}

impl Drop for AcceptReservation<'_> {
    fn drop(&mut self) {
        self.accepting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.call_token);
    }
}

/// Coalesces network-change heartbeats.
#[derive(Default)]
struct HeartbeatState {
    /// A heartbeat task is running.
    running: bool,
    /// Another network change arrived since the running task last started a
    /// heartbeat; it sends one more, with the state current at that time.
    requested: bool,
}

/// What a status poll does after a status answer.
enum PollAction {
    /// Keep polling.
    Continue,
    /// Stop polling.
    Stop,
    /// Reject the (still ringing) call, then keep polling.
    Reject,
    /// Hang the (answered) call up, then stop polling.
    HangUp,
}

/// How many outgoing call_ids are remembered once used, so that a late
/// hangup or a reused id is recognised rather than treated as new.
const USED_OUTGOING_IDS: usize = 256;

/// Outgoing calls that are not active (yet), and the ids already used.
#[derive(Default)]
struct OutgoingCalls {
    /// Ringing calls, keyed by call_id. A call moves to the call map when it
    /// is answered.
    ringing: HashMap<String, PendingOutgoing>,
    /// Recently used ids, oldest first, with whether each was hung up before
    /// `make_call_with_id` was called for it.
    used: VecDeque<(String, bool)>,
}

impl OutgoingCalls {
    fn used(&mut self, call_id: &str) -> Option<&mut bool> {
        self.used
            .iter_mut()
            .find(|(id, _)| id == call_id)
            .map(|(_, precancelled)| precancelled)
    }

    fn mark_used(&mut self, call_id: &str, precancelled: bool) {
        self.used.push_back((call_id.to_string(), precancelled));
        if self.used.len() > USED_OUTGOING_IDS {
            self.used.pop_front();
        }
    }
}

/// The `client_ref` part of a valid outgoing call_id: `outgoing-` followed by
/// 1-64 characters from `[A-Za-z0-9_-]`, the gateway's rule for a ref.
fn outgoing_client_ref(call_id: &str) -> Option<&str> {
    let client_ref = call_id.strip_prefix("outgoing-")?;
    let valid = (1..=64).contains(&client_ref.len())
        && client_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    valid.then_some(client_ref)
}

/// A fresh outgoing call_id for `make_call_with_id`.
fn new_outgoing_call_id() -> String {
    format!("outgoing-{}", uuid::Uuid::new_v4().as_simple())
}

/// An outgoing call that has been reported `Ringing` and not answered yet.
struct PendingOutgoing {
    info: CallInfo,
    /// Creation order, carried over to the call once it is answered.
    seq: u64,
    events: Arc<CallEvents>,
    /// Sent with `POST /v1/calls` so the gateway can cancel the call by it
    /// before it has assigned a call token.
    client_ref: String,
    /// Set by `dial`, under the pending-map lock, just before it sends the
    /// call to the gateway. A hangup that finds it unset has nothing to
    /// cancel at the gateway.
    dialing: bool,
    /// Tells `dial` that `hangup` has taken the call.
    cancel: tokio::sync::oneshot::Sender<()>,
    /// The gateway instance `POST /v1/calls` was last sent to, which is the
    /// one ringing the call; a cancel goes there.
    route: Arc<Mutex<Option<Route>>>,
    /// Becomes true when `POST /v1/calls` has returned, however it ended.
    request_done: tokio::sync::watch::Receiver<bool>,
    /// What came of `hangup`'s cancel request: `Some(true)` when the gateway
    /// sent a CANCEL, `Some(false)` otherwise. Read before hanging up a call
    /// that was answered anyway, because the gateway ends a call whose answer
    /// crossed an accepted CANCEL itself.
    cancel_outcome: tokio::sync::watch::Sender<Option<bool>>,
}

/// How long a cancelled call that was answered anyway waits for the outcome
/// of the cancel request before hanging up. Longer than the HTTP timeout, so
/// the outcome is always known unless something is badly wrong.
const CANCEL_OUTCOME_WAIT: Duration = Duration::from_secs(35);

/// What `hangup` found for a call_id.
enum TakenCall {
    Active(Box<ActiveCallState>),
    Ringing(PendingOutgoing),
    /// An outgoing id `make_call_with_id` has not been called for yet.
    NotYetMade,
    Missing,
}

/// A reserved outgoing call, as `dial` carries it on.
struct ReservedOutgoing {
    info: CallInfo,
    client_ref: String,
    events: Arc<CallEvents>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    outcome_rx: tokio::sync::watch::Receiver<Option<bool>>,
    attempt: Arc<Mutex<Option<Route>>>,
    done_tx: tokio::sync::watch::Sender<bool>,
    /// The route of the other live call, which this one must use too (see
    /// `reserve_outgoing`).
    pin: Option<Route>,
}

struct ActiveCallState {
    info: CallInfo,
    /// Creation order, for `get_calls`.
    seq: u64,
    media: Option<media::MobileMediaSession>,
    /// For gateway-routed calls
    call_token: Option<String>,
    /// The gateway instance holding the call.
    route: Route,
    /// Set to true to stop the status polling loop
    poll_stop: Arc<AtomicBool>,
    /// Orders this call's events and stops anything after `Ended`.
    events: Arc<CallEvents>,
}

impl AriaMobileEngine {
    pub fn new(gateway_config: GatewayConfig) -> Self {
        Self {
            gateway: Arc::new(gateway_client::GatewayClient::new(gateway_config.base_url)),
            events: Arc::new(Dispatcher::new()),
            audio_bridge: RwLock::new(None),
            calls: Arc::new(Mutex::new(HashMap::new())),
            pending_incoming: Arc::new(Mutex::new(HashMap::new())),
            pending_outgoing: Mutex::new(OutgoingCalls::default()),
            accepting: Mutex::new(HashSet::new()),
            next_seq: AtomicU64::new(0),
            auth: Arc::new(auth::GatewayAuth::new(gateway_config.api_key)),
            device_id: Arc::new(RwLock::new(None)),
            heartbeat: Arc::default(),
            ai: RwLock::new(None),
            codec_prefs: RwLock::new(vec![AudioCodec::Opus, AudioCodec::Pcmu, AudioCodec::Pcma]),
            last_registration: RwLock::new(None),
            remote_ended: Arc::new(Mutex::new(Vec::new())),
            poll_interval: CALL_STATUS_POLL_INTERVAL,
            transfer_poll_interval: TRANSFER_POLL_INTERVAL,
            transfer_timeout: TRANSFER_TIMEOUT,
        }
    }

    pub fn set_event_handler(&self, handler: Box<dyn MobileEventHandler>) {
        self.events.set_handler(Some(Arc::from(handler)));
    }

    pub fn set_audio_bridge(&self, bridge: Box<dyn media::PlatformAudioBridge>) {
        let mut ab = self.audio_bridge.write().unwrap();
        *ab = Some(Arc::from(bridge));
    }

    #[allow(dead_code)]
    fn emit_error(&self, context: &str, message: &str) {
        let (context, message) = (context.to_string(), message.to_string());
        self.events.error(context, message);
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
            self.events
                .registration_changed(device_id, "registered".to_string(), None);

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

            self.events
                .registration_changed(device_id, "unregistered".to_string(), None);

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
            let (offer, route) = self
                .gateway
                .get_call_offer(&token, &payload.call_token)
                .await?;

            // Watch for the caller giving up before the user answers. A push
            // can be delivered more than once for the same call; only one
            // watcher runs per call_token.
            self.start_pending_incoming_poll(&offer, route);

            let for_handler = offer.clone();
            self.events.incoming_call(for_handler);

            Ok(offer)
        })
    }

    pub fn accept_incoming_call(
        &self,
        call_token: String,
        preferred_codecs: Vec<AudioCodec>,
    ) -> Result<CallInfo, MobileError> {
        // Before anything else, so a refused accept has no side effects.
        let _reservation = self.reserve_accept(&call_token)?;
        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;

            // Get the call offer to know what codecs the remote supports. The
            // instance that returns it holds the call, so the accept, the
            // status poll and everything after go there.
            let (offer, route) = self.gateway.get_call_offer(&token, &call_token).await?;

            // Start local media and generate SDP answer
            let codecs = if preferred_codecs.is_empty() {
                self.codec_prefs.read().unwrap().clone()
            } else {
                preferred_codecs
            };

            let (media_session, sdp_answer) =
                media::create_answer_session(&offer.sdp_offer, &codecs).await?;

            self.answer_offer(&token, offer, route, Some(media_session), sdp_answer)
                .await
        })
    }

    /// Count an accept of `call_token` against [`MAX_LIVE_CALLS`].
    ///
    /// Refuses (`InvalidState`) when two calls are already live, and an
    /// accept of a call that is already being accepted or is connected.
    /// Offered calls are not counted (see [`MAX_LIVE_CALLS`]), so the app
    /// can still show and decline a third call; it cannot answer it until
    /// one of the others ends.
    fn reserve_accept(&self, call_token: &str) -> Result<AcceptReservation<'_>, MobileError> {
        // Lock order: calls, then pending_outgoing, then accepting.
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let outgoing = self
            .pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut accepting = self
            .accepting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if accepting.contains(call_token) || calls.contains_key(&format!("incoming-{call_token}")) {
            return Err(MobileError::InvalidState);
        }
        if live_call_count(&calls, &outgoing, &accepting) >= MAX_LIVE_CALLS {
            log::warn!("Refusing to accept {call_token}: {MAX_LIVE_CALLS} calls are live");
            return Err(MobileError::InvalidState);
        }
        accepting.insert(call_token.to_string());
        Ok(AcceptReservation {
            accepting: &self.accepting,
            call_token: call_token.to_string(),
        })
    }

    /// Start a call's RTP loops with the platform audio bridge. Without this
    /// the media session exists but has no audio in either direction.
    fn start_media(&self, media: Option<&media::MobileMediaSession>, call_id: &str) {
        let Some(media) = media else { return };
        match self
            .audio_bridge
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            Some(bridge) => {
                media.start_with_bridge(bridge);
                log::info!("Started RTP media for {call_id} with the audio bridge");
            }
            None => log::warn!("No audio bridge set; {call_id} will have no audio"),
        }
    }

    /// Send the answer for an offered call and make it the active call.
    ///
    /// If the accept fails with a timeout or a transport error, the gateway
    /// may have accepted the call anyway. The app is told the call ended
    /// (exactly one `Ended` for `incoming-<call_token>`), and the call is
    /// handed to the incoming watch as abandoned: it hangs the call up if it
    /// shows up `active`, and rejects it while it still rings, so it is never
    /// left connected with nobody on this end. A refusal from the gateway
    /// leaves the call offered, as before. `media` is `None` only in tests.
    async fn answer_offer(
        &self,
        token: &str,
        offer: CallOffer,
        route: Route,
        media: Option<media::MobileMediaSession>,
        sdp_answer: String,
    ) -> Result<CallInfo, MobileError> {
        let call_token = offer.call_token.clone();
        let call_id = format!("incoming-{call_token}");
        let info = CallInfo {
            call_id: call_id.clone(),
            remote_uri: offer.caller_uri.clone(),
            remote_name: offer.caller_name.clone(),
            state: CallState::Connected,
            direction: CallDirection::Inbound,
            muted: false,
            on_hold: false,
            duration_secs: 0,
            end_reason: None,
        };

        // From here an `active` status is this handset answering.
        let events = {
            let mut pending = self
                .pending_incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match pending.get_mut(&call_token) {
                Some(entry) => {
                    entry.accepting = true;
                    Arc::clone(&entry.events)
                }
                None => Arc::default(),
            }
        };

        match self
            .gateway
            .accept_call(&route, token, &call_token, &sdp_answer)
            .await
        {
            Ok(()) => {}
            Err(e @ (MobileError::Timeout | MobileError::NetworkError)) => {
                log::warn!("Accept of {call_id} has an unknown outcome ({e}); abandoning it");
                if let Some(media) = &media {
                    media.stop();
                }
                self.watch_incoming(&offer, route, true);
                events.emit_ended(&self.events, &info, EndReason::Failed);
                return Err(e);
            }
            Err(e) => {
                // Refused: the call is still offered and still watched.
                if let Some(entry) = self
                    .pending_incoming
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_mut(&call_token)
                {
                    entry.accepting = false;
                }
                if let Some(media) = &media {
                    media.stop();
                }
                return Err(e);
            }
        }
        self.clear_pending_incoming(&call_token);

        let poll_stop = Arc::new(AtomicBool::new(false));
        let connected = {
            let mut calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // The call now counts as connected rather than being accepted.
            self.accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&call_token);
            // Queued while the call-map lock is held, so nothing done to the
            // call afterwards can be delivered ahead of it. Refused when the
            // offer was already reported ended (the caller hung up as it
            // was answered). Any other connected call is put on hold, and
            // reported, first.
            let connected = events.emit_after(&self.events, info.clone(), || {
                hold_others(&mut calls, &call_id, &self.events);
            });
            if connected {
                // Started only now that the other calls are held, so two
                // calls never share the speaker and microphone. (The remote
                // RTP address was set by `create_answer_session` from the
                // caller's SDP offer.)
                self.start_media(media.as_ref(), &call_id);
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        seq: self.next_seq.fetch_add(1, Ordering::Relaxed),
                        media,
                        call_token: Some(call_token.clone()),
                        route: route.clone(),
                        poll_stop: poll_stop.clone(),
                        events: Arc::clone(&events),
                    },
                );
            } else if let Some(media) = &media {
                media.stop();
            }
            connected
        };
        if !connected {
            log::info!("{call_id} ended as it was answered; hanging up");
            let (gateway, auth, handler) = (
                Arc::clone(&self.gateway),
                Arc::clone(&self.auth),
                Arc::clone(&self.events),
            );
            runtime().spawn(async move {
                hang_up_at_gateway(&gateway, &auth, &handler, &route, &call_id, &call_token).await;
            });
            return Err(MobileError::InvalidState);
        }

        // Start polling for remote hangup only after Connected is queued,
        // so a remote hangup can never be reported ahead of it.
        self.start_call_status_poll(call_id, call_token, route, poll_stop);
        Ok(info)
    }

    pub fn reject_incoming_call(&self, call_token: String) -> Result<(), MobileError> {
        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            let route = self
                .pending_incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&call_token)
                .map(|p| p.route.clone())
                .unwrap_or_else(|| self.gateway.primary_route());
            self.gateway
                .reject_call(&route, &token, &call_token)
                .await?;
            // The app learned the call's id from the offer, so it gets the
            // call's one `Ended`, unless the caller had already hung up.
            if let Some(entry) = self.take_pending_incoming(&call_token) {
                entry
                    .events
                    .emit_ended(&self.events, &entry.info, EndReason::Rejected);
            }
            Ok(())
        })
    }

    // ── Outgoing Calls ──────────────────────────────────────────────

    /// Make an outgoing call with a call_id the core picks. The id is first
    /// learned from the `Ringing` event; `make_call_with_id` lets the app
    /// know it before dialing.
    pub fn make_call(
        &self,
        uri: String,
        credentials: SipCredentials,
        preferred_codecs: Vec<AudioCodec>,
    ) -> Result<CallInfo, MobileError> {
        self.make_call_with_id(new_outgoing_call_id(), uri, credentials, preferred_codecs)
    }

    /// Make an outgoing call under `call_id`, which the app chose (normally
    /// from `new_outgoing_call_id`), so that it can hang the call up at any
    /// point, even before this is called.
    pub fn make_call_with_id(
        &self,
        call_id: String,
        uri: String,
        credentials: SipCredentials,
        preferred_codecs: Vec<AudioCodec>,
    ) -> Result<CallInfo, MobileError> {
        let codecs = if preferred_codecs.is_empty() {
            self.codec_prefs.read().unwrap().clone()
        } else {
            preferred_codecs
        };
        let rt = runtime();
        rt.block_on(async {
            // Allocate RTP port and build SDP offer, once the call is
            // reserved, so a hangup meanwhile still finds it.
            let offer = async {
                let (media_session, sdp_offer) = media::create_offer_session(&codecs).await?;
                Ok((Some(media_session), sdp_offer))
            };
            self.dial(call_id, uri, credentials, offer).await
        })
    }

    /// Reserve `call_id` for a new outgoing call and report it `Ringing`.
    ///
    /// Refuses an id that is malformed, in use or used recently
    /// (`InvalidState`), and one that was hung up before the call was made
    /// (`Cancelled`; its `Ended` has already been reported). Also refuses,
    /// with `InvalidState` and without using up the id, a call that would
    /// exceed [`MAX_LIVE_CALLS`].
    ///
    /// While another call is live, the new call is pinned to that call's
    /// gateway route: it is placed on the same gateway instance, with no
    /// failover to another SRV target, and fails if that instance cannot be
    /// reached. The PBX joins two calls in an attended transfer only when
    /// both reach it from the same gateway (the same source IP), and the
    /// gateway can only refer a pair of calls it holds itself, so a second
    /// call placed through a different instance could never be transferred
    /// to the first. Failing it is better than a consultation call that
    /// silently cannot complete the transfer the user placed it for.
    fn reserve_outgoing(
        &self,
        call_id: &str,
        uri: &str,
    ) -> Result<(String, ReservedOutgoing), MobileError> {
        let client_ref = outgoing_client_ref(call_id)
            .ok_or(MobileError::InvalidState)?
            .to_string();
        // Read before the other locks, which it is never taken under. Only
        // used below if the call is still being accepted then.
        let accepting_routes: Vec<(String, Route)> = self
            .pending_incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, p)| p.accepting)
            .map(|(token, p)| (token.clone(), p.route.clone()))
            .collect();
        // Lock order: calls, then pending_outgoing.
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut outgoing = self
            .pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(precancelled) = outgoing.used(call_id) {
            if std::mem::take(precancelled) {
                log::info!("Outgoing call {call_id} was hung up before it was made");
                return Err(MobileError::Cancelled);
            }
            return Err(MobileError::InvalidState);
        }
        if calls.contains_key(call_id) || outgoing.ringing.contains_key(call_id) {
            return Err(MobileError::InvalidState);
        }
        let (live, pin) = {
            let accepting = self
                .accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pin = live_call_route(&calls, &outgoing).or_else(|| {
                accepting_routes
                    .into_iter()
                    .find(|(token, _)| accepting.contains(token))
                    .map(|(_, route)| route)
            });
            (live_call_count(&calls, &outgoing, &accepting), pin)
        };
        if live >= MAX_LIVE_CALLS {
            log::warn!("Refusing to dial {call_id}: {MAX_LIVE_CALLS} calls are live");
            return Err(MobileError::InvalidState);
        }
        if let Some(route) = &pin {
            log::info!("Dialing {call_id} on {route:?}, the route of the other live call");
        }
        let token = self.auth.token()?;

        let events = Arc::new(CallEvents::default());
        let info = CallInfo {
            call_id: call_id.to_string(),
            remote_uri: uri.to_string(),
            remote_name: None,
            state: CallState::Ringing,
            direction: CallDirection::Outbound,
            muted: false,
            on_hold: false,
            duration_secs: 0,
            end_reason: None,
        };
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let (outcome_tx, outcome_rx) = tokio::sync::watch::channel(None);
        let attempt: Arc<Mutex<Option<Route>>> = Arc::default();
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        outgoing.mark_used(call_id, false);
        outgoing.ringing.insert(
            call_id.to_string(),
            PendingOutgoing {
                info: info.clone(),
                seq: self.next_seq.fetch_add(1, Ordering::Relaxed),
                events: Arc::clone(&events),
                client_ref: client_ref.clone(),
                dialing: false,
                cancel: cancel_tx,
                route: Arc::clone(&attempt),
                request_done: done_rx,
                cancel_outcome: outcome_tx,
            },
        );
        // Queued under the lock, so a hangup's `Ended` follows it.
        events.emit(&self.events, info.clone());
        Ok((
            token,
            ReservedOutgoing {
                info,
                client_ref,
                events,
                cancel_rx,
                outcome_rx,
                attempt,
                done_tx,
                pin,
            },
        ))
    }

    /// Place an outgoing call through the gateway and follow it to
    /// `Connected`, a failure, or a hangup while it rings.
    ///
    /// The call is reserved and reported `Ringing` before anything else,
    /// and stays in `pending_outgoing` until it is answered, so `hangup` can
    /// find it at any point. Whichever of this method and `hangup` removes it
    /// from there owns its next transition. `offer` opens the media session
    /// and builds the SDP offer; tests pass one without media, which needs
    /// network access.
    async fn dial(
        &self,
        call_id: String,
        uri: String,
        credentials: SipCredentials,
        offer: impl std::future::Future<
            Output = Result<(Option<media::MobileMediaSession>, String), MobileError>,
        >,
    ) -> Result<CallInfo, MobileError> {
        let (
            token,
            ReservedOutgoing {
                mut info,
                client_ref,
                events,
                mut cancel_rx,
                outcome_rx,
                attempt,
                done_tx,
                pin,
            },
        ) = self.reserve_outgoing(&call_id, &uri)?;

        // Opening media includes STUN, which can take a while. A hangup
        // meanwhile returns at once; dropping the unfinished offer drops any
        // session it had opened, which was never started.
        let offer = tokio::select! {
            offer = offer => offer,
            _ = &mut cancel_rx => {
                log::info!("Outgoing call {} hung up while setting up media", call_id);
                return Err(MobileError::Cancelled);
            }
        };
        let (media, sdp_offer) = match offer {
            Ok(offer) => offer,
            Err(e) => {
                // `Ringing` has been reported, so close the call, unless a
                // hangup already has.
                return match self.take_ringing(&call_id) {
                    Some(pending) => {
                        pending
                            .events
                            .emit_ended(&self.events, &pending.info, EndReason::Failed);
                        Err(e)
                    }
                    None => Err(MobileError::Cancelled),
                };
            }
        };

        // Mark the call as sent, unless it has already been hung up: then
        // nothing has been sent and there is nothing to cancel at the
        // gateway. Done under the lock `hangup` takes the call under, so a
        // hangup either sees the mark and cancels at the gateway, or removed
        // the call first and is seen here.
        let hung_up = {
            let mut pending = self
                .pending_outgoing
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match pending.ringing.get_mut(&call_id) {
                Some(call) => {
                    call.dialing = true;
                    false
                }
                None => true,
            }
        };
        if hung_up {
            if let Some(media) = &media {
                media.stop();
            }
            return Err(MobileError::Cancelled);
        }

        // Route the call through the gateway B2BUA — it sends the SIP
        // INVITE on our behalf and returns the SDP answer + call_token.
        //
        // The request runs as its own task so that a hangup can unblock
        // this method without abandoning it. `hangup` cancels the call by
        // its `client_ref`, after which the gateway fails this request with
        // 409; but a gateway without the cancel route, or a call answered
        // first, means the call can only be hung up once its token arrives.
        let gateway = Arc::clone(&self.gateway);
        let destination = uri.clone();
        let mut request = tokio::spawn(async move {
            let result = gateway
                .make_call(
                    &token,
                    &destination,
                    &sdp_offer,
                    &credentials,
                    gateway_client::Placement {
                        client_ref: &client_ref,
                        attempt: &attempt,
                        pin: pin.as_ref(),
                    },
                )
                .await;
            let _ = done_tx.send(true);
            result
        });

        let answer = tokio::select! {
            joined = &mut request => joined.unwrap_or_else(|_| Err(MobileError::CallFailed("call request aborted".into()))),
            _ = &mut cancel_rx => {
                // `hangup` took the call while it was ringing and has
                // reported `Ended`.
                log::info!("Outgoing call {} cancelled while ringing", call_id);
                if let Some(media) = &media {
                    media.stop();
                }
                let answered = async move { request.await.ok()?.ok().map(|(t, _, r)| (t, r)) };
                self.hang_up_if_answered(call_id.clone(), answered, outcome_rx);
                return Err(MobileError::Cancelled);
            }
        };

        let (call_token, sdp_answer, route) = match answer {
            Ok(answer) => answer,
            Err(e) => {
                if let Some(media) = &media {
                    media.stop();
                }
                // `Ringing` has been reported, so the failure must close the
                // call with `Ended`, unless a hangup already has.
                return match self.take_ringing(&call_id) {
                    Some(pending) => {
                        pending
                            .events
                            .emit_ended(&self.events, &pending.info, EndReason::Failed);
                        Err(e)
                    }
                    None => Err(MobileError::Cancelled),
                };
            }
        };

        if let Some(media_session) = &media {
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
        }

        // Transition to connected
        info.state = CallState::Connected;
        let poll_stop = Arc::new(AtomicBool::new(false));

        // Move the call from pending to active in one step with respect to
        // `hangup`, which also holds the call map while it checks the
        // pending map, so a hangup always finds the call in one of them.
        let unclaimed = {
            let mut calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut pending = self
                .pending_outgoing
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ringing) = pending.ringing.remove(&call_id) {
                // Any other connected call goes on hold, and is reported,
                // before this one connects and its media starts, so two
                // calls never share the speaker and microphone.
                hold_others(&mut calls, &call_id, &self.events);
                self.start_media(media.as_ref(), &call_id);
                calls.insert(
                    call_id.clone(),
                    ActiveCallState {
                        info: info.clone(),
                        seq: ringing.seq,
                        media,
                        call_token: Some(call_token.clone()),
                        route: route.clone(),
                        poll_stop: poll_stop.clone(),
                        events: Arc::clone(&events),
                    },
                );
                // Queued under the lock: a hold or hangup that finds the call
                // now is queued after this.
                events.emit(&self.events, info.clone());
                None
            } else {
                Some(media)
            }
        };
        if let Some(media) = unclaimed {
            // Hung up after the gateway answered but before the call was
            // active here; `Ended` has been reported.
            log::info!("Outgoing call {} answered after it was cancelled", call_id);
            if let Some(media) = media {
                media.stop();
            }
            self.hang_up_if_answered(
                call_id.clone(),
                std::future::ready(Some((call_token, route))),
                outcome_rx,
            );
            return Err(MobileError::Cancelled);
        }

        // The poll starts after Connected is queued, so a remote hangup can
        // never be reported ahead of it.
        self.start_call_status_poll(call_id.clone(), call_token, route, poll_stop);
        log::info!("Outgoing call to {} connected via gateway", uri);

        Ok(info)
    }

    /// Hang up an outgoing call cancelled by `hangup` if `answered` yields a
    /// call token, in the background; `make_call` has already returned.
    ///
    /// The call is left alone when the gateway accepted the cancel, since it
    /// ends a call whose answer crossed the CANCEL itself. Otherwise (the call
    /// was answered first, or the gateway has no cancel route) it is hung up
    /// here.
    fn hang_up_if_answered(
        &self,
        call_id: String,
        answered: impl std::future::Future<Output = Option<(String, Route)>> + Send + 'static,
        mut cancel_outcome: tokio::sync::watch::Receiver<Option<bool>>,
    ) {
        let gateway = Arc::clone(&self.gateway);
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.events);
        runtime().spawn(async move {
            // A 409 (cancelled) or any other failure leaves nothing to hang up.
            let Some((call_token, route)) = answered.await else {
                return;
            };
            let accepted = tokio::time::timeout(
                CANCEL_OUTCOME_WAIT,
                cancel_outcome.wait_for(Option::is_some),
            )
            .await
            .is_ok_and(|outcome| outcome.is_ok_and(|o| *o == Some(true)));
            if accepted {
                log::info!("Cancelled call was answered; the gateway ends it");
                return;
            }
            log::info!("Cancelled outgoing call was answered; hanging it up");
            hang_up_at_gateway(&gateway, &auth, &handler, &route, &call_id, &call_token).await;
        });
    }

    // ── Mid-call Controls ───────────────────────────────────────────

    /// Hang up a call. Never waits on the gateway.
    ///
    /// The call is torn down locally and `Ended` is queued at once; the
    /// gateway request (hangup for an active call, cancel for a ringing one)
    /// runs in the background. Returns `AuthenticationError` without sending
    /// anything when there is no gateway token; a token the gateway rejects
    /// is reported through `on_auth_required`, and any other failure through
    /// `on_error`, since the far end may then still be connected.
    pub fn hangup(&self, call_id: String) -> Result<(), MobileError> {
        let call = match self.take_for_hangup(&call_id) {
            TakenCall::Active(call) => call,
            TakenCall::Ringing(pending) => return self.cancel_ringing(pending),
            TakenCall::NotYetMade => {
                // Reported now: the app chose the id, so it knows it. The
                // later `make_call_with_id` returns `Cancelled` and sends
                // nothing.
                CallEvents::default().emit_ended(
                    &self.events,
                    &CallInfo {
                        call_id: call_id.clone(),
                        remote_uri: String::new(),
                        remote_name: None,
                        state: CallState::Ended,
                        direction: CallDirection::Outbound,
                        muted: false,
                        on_hold: false,
                        duration_secs: 0,
                        end_reason: None,
                    },
                    EndReason::Cancelled,
                );
                return Ok(());
            }
            TakenCall::Missing => return Err(MobileError::InvalidState),
        };
        emit_ended(&self.events, &call, EndReason::LocalHangup);

        let Some(call_token) = call.call_token.clone() else {
            return Ok(());
        };
        if self.auth.current().is_none() {
            log::warn!("No gateway token; call {call_id} was not hung up at the gateway");
            return Err(MobileError::AuthenticationError);
        }
        let gateway = Arc::clone(&self.gateway);
        let auth = Arc::clone(&self.auth);
        let events = Arc::clone(&self.events);
        let route = call.route.clone();
        runtime().spawn(async move {
            hang_up_at_gateway(&gateway, &auth, &events, &route, &call_id, &call_token).await;
        });
        Ok(())
    }

    /// Hang up an outgoing call that is still ringing.
    ///
    /// `Ended` is queued and `make_call` is released with `Cancelled` at once.
    /// The call is then cancelled at the gateway by its `client_ref`, in the
    /// background. If the gateway has no ringing call by that ref yet (the
    /// cancel overtook `POST /v1/calls`), the cancel is retried with backoff
    /// while that request is in flight. If it never lands (answered meanwhile,
    /// or a gateway without the route), `make_call`'s background task hangs
    /// the call up once its token arrives.
    fn cancel_ringing(&self, pending: PendingOutgoing) -> Result<(), MobileError> {
        pending
            .events
            .emit_ended(&self.events, &pending.info, EndReason::Cancelled);
        let _ = pending.cancel.send(());
        if !pending.dialing {
            return Ok(());
        }
        if self.auth.current().is_none() {
            // Nothing to cancel with; the call is hung up if it is answered,
            // and that request's 401 asks the app for a token.
            let _ = pending.cancel_outcome.send(Some(false));
            return Err(MobileError::AuthenticationError);
        }

        let gateway = Arc::clone(&self.gateway);
        let auth = Arc::clone(&self.auth);
        let events = Arc::clone(&self.events);
        let PendingOutgoing {
            info,
            client_ref,
            route,
            request_done,
            cancel_outcome,
            ..
        } = pending;
        runtime().spawn(async move {
            let target = CancelTarget {
                call_id: &info.call_id,
                client_ref: &client_ref,
                route: &route,
                request_done,
            };
            let accepted = cancel_at_gateway(&gateway, &auth, &events, target).await;
            let _ = cancel_outcome.send(Some(accepted));
        });
        Ok(())
    }

    /// Take a call out of the engine for `hangup`: an active call (with its
    /// poll and media stopped) or an outgoing call that is still ringing.
    fn take_for_hangup(&self, call_id: &str) -> TakenCall {
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut call) = calls.remove(call_id) {
            drop(calls);
            stop_call(&mut call);
            return TakenCall::Active(Box::new(call));
        }
        // Still holding the call map, so `dial` cannot move the call from
        // pending to active between the two lookups.
        let mut outgoing = self
            .pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pending) = outgoing.ringing.remove(call_id) {
            return TakenCall::Ringing(pending);
        }
        // An outgoing id the core has not seen: the app is hanging up a call
        // it is about to make. Remember that, so the call is never dialed.
        if outgoing_client_ref(call_id).is_some() && outgoing.used(call_id).is_none() {
            outgoing.mark_used(call_id, true);
            return TakenCall::NotYetMade;
        }
        TakenCall::Missing
    }

    /// Remove a ringing outgoing call, if a hangup has not already.
    fn take_ringing(&self, call_id: &str) -> Option<PendingOutgoing> {
        self.pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ringing
            .remove(call_id)
    }

    /// Blind-transfer an active call to `target`, and wait for the outcome.
    ///
    /// The gateway sends the REFER and answers 202 once the PBX has accepted
    /// it. That is not yet success: the PBX reports the outcome later, so the
    /// call's status is then polled until it shows one.
    /// - Ended with reason `transferred`: this handset is out of the call; the
    ///   call and media are torn down, `Ended` is emitted, and this returns.
    /// - `transfer: failed`: `CallFailed` with the SIP status in the message.
    ///   The call stays fully up.
    /// - No outcome within `transfer_timeout`: `Timeout`, call still up.
    /// - The call ended for another reason meanwhile: `InvalidState`, and the
    ///   call is reported `Ended` like any remote hangup.
    /// - A gateway that does not report transfer outcomes (no `transfer` field
    ///   on the active call): the call is ended on the 202, as before.
    ///
    /// Any error from the REFER itself leaves the call as it was.
    pub fn transfer_call(&self, call_id: String, target: String) -> Result<(), MobileError> {
        let target = target.trim();
        validate_transfer_target(target)?;

        let (call_token, route) = {
            let calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let call = calls.get(&call_id).ok_or(MobileError::InvalidState)?;
            // Only gateway-routed calls can be transferred: the REFER is sent
            // by the gateway on the call it holds.
            let call_token = call.call_token.clone().ok_or(MobileError::InvalidState)?;
            (call_token, call.route.clone())
        };

        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            self.gateway
                .transfer_call(&route, &token, &call_token, target)
                .await?;
            log::info!(
                "Transfer of {} accepted by the PBX; waiting for the outcome",
                call_id
            );
            let leg = TransferLeg {
                call_id: &call_id,
                call_token: &call_token,
                route: &route,
            };
            self.await_transfer_outcome(&[leg]).await
        })
    }

    /// Attended-transfer: join the far ends of `call_id` and
    /// `consult_call_id` (typically a call to the transfer target the user
    /// placed while `call_id` was on hold) and drop this phone from both,
    /// then wait for the outcome. See `transfer_call` for how the outcome is
    /// followed; here it is followed on both calls.
    ///
    /// - Success: both calls end, each reported `Ended` once with reason
    ///   `Transferred`.
    /// - `transfer: failed`: `CallFailed` (or `Timeout` for 408), and both
    ///   calls stay up, as they were (either may be on hold here).
    /// - Either call ended for another reason meanwhile: `InvalidState`; that
    ///   call is reported `Ended`, and the other stays up.
    ///
    /// Checked here before anything is sent, leaving both calls as they
    /// were: `InvalidState` unless both are distinct connected
    /// gateway-routed calls, and `TransferUnsupported` unless one is
    /// incoming and the other outgoing (the PBX accepts the REFER only on a
    /// call the phone received, with `Replaces` naming one it placed). Any
    /// error from the REFER itself also leaves both calls as they were.
    pub fn transfer_attended(
        &self,
        call_id: String,
        consult_call_id: String,
    ) -> Result<(), MobileError> {
        if call_id == consult_call_id {
            return Err(MobileError::InvalidState);
        }
        let (call_token, route, consult_token, consult_route) = {
            let calls = self
                .calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let call = calls.get(&call_id).ok_or(MobileError::InvalidState)?;
            let consult = calls
                .get(&consult_call_id)
                .ok_or(MobileError::InvalidState)?;
            let call_token = call.call_token.clone().ok_or(MobileError::InvalidState)?;
            let consult_token = consult
                .call_token
                .clone()
                .ok_or(MobileError::InvalidState)?;
            if call.info.direction == consult.info.direction {
                log::warn!(
                    "Attended transfer of {call_id} with {consult_call_id}: both are {:?}",
                    call.info.direction
                );
                return Err(MobileError::TransferUnsupported);
            }
            (
                call_token,
                call.route.clone(),
                consult_token,
                consult.route.clone(),
            )
        };

        let rt = runtime();
        rt.block_on(async {
            let token = self.auth.token()?;
            self.gateway
                .transfer_attended(&route, &token, &call_token, &consult_token)
                .await?;
            log::info!(
                "Attended transfer of {call_id} with {consult_call_id} accepted by the PBX; \
                 waiting for the outcome"
            );
            let legs = [
                TransferLeg {
                    call_id: &call_id,
                    call_token: &call_token,
                    route: &route,
                },
                TransferLeg {
                    call_id: &consult_call_id,
                    call_token: &consult_token,
                    route: &consult_route,
                },
            ];
            self.await_transfer_outcome(&legs).await
        })
    }

    /// Poll the calls of a transfer after the PBX accepted it until the
    /// outcome is known. See `transfer_call` and `transfer_attended`.
    ///
    /// The gateway reports an attended transfer's outcome on both calls, so
    /// the first verdict on either decides. On success each call ends with
    /// its own `Ended`; once one has, the others get
    /// [`TRANSFER_SETTLE`] to follow before they are ended here (and hung up
    /// at the gateway, in case they are somehow still up there).
    async fn await_transfer_outcome(&self, legs: &[TransferLeg<'_>]) -> Result<(), MobileError> {
        let deadline = Instant::now() + self.transfer_timeout;
        let mut gone: Vec<GoneDetector> = legs.iter().map(|_| GoneDetector::default()).collect();
        let mut transferred = vec![false; legs.len()];
        // Set once the first call is reported transferred.
        let mut settle_by: Option<Instant> = None;
        loop {
            tokio::time::sleep(self.transfer_poll_interval).await;
            let token = self.auth.token()?;
            for (i, leg) in legs.iter().enumerate() {
                if transferred[i] {
                    continue;
                }
                let call_id = leg.call_id;
                let status = match self
                    .gateway
                    .get_call_status(leg.route, &token, leg.call_token)
                    .await
                {
                    Ok(status) => status,
                    // The calls are still up; the app must fetch a new token.
                    Err(MobileError::AuthenticationError) => {
                        return Err(MobileError::AuthenticationError)
                    }
                    Err(e) => {
                        log::warn!("Transfer status poll for {call_id} failed: {e}");
                        continue;
                    }
                };
                let succeeded = transferred.iter().any(|t| *t);
                if gone[i].is_gone(&status.status) {
                    // The call is over at the gateway. Whoever removes it
                    // from the map (this, the status poll, or a hangup)
                    // reports `Ended`, once. After another call of the
                    // transfer was transferred, this one ending is the
                    // transfer completing, whatever the gateway calls it.
                    let reason = if succeeded {
                        EndReason::Transferred
                    } else {
                        EndReason::from_gateway(status.reason.as_deref(), EndReason::RemoteHangup)
                    };
                    end_call_locally(&self.calls, &self.events, call_id, reason);
                    if reason == EndReason::Transferred {
                        log::info!("Call {call_id} transferred");
                        transferred[i] = true;
                        continue;
                    }
                    log::info!(
                        "Call {call_id} ended during its transfer (reason: {:?})",
                        status.reason
                    );
                    return Err(MobileError::InvalidState);
                }
                // Once a call has been transferred, the transfer succeeded;
                // the others are only waited on to end.
                if status.status != "active" || succeeded {
                    continue;
                }
                match status.transfer.as_deref() {
                    None => {
                        // A gateway that does not report outcomes: the 202
                        // is all there is.
                        log::info!("Gateway reports no transfer outcome; ending the call");
                        for leg in legs {
                            end_call_locally(
                                &self.calls,
                                &self.events,
                                leg.call_id,
                                EndReason::Transferred,
                            );
                        }
                        return Ok(());
                    }
                    // 408 means no outcome: the gateway's NOTIFY watchdog
                    // gave up, or the PBX itself timed out. The transfer did
                    // not happen, and the calls are still up.
                    Some("failed") if status.transfer_code == Some(408) => {
                        log::warn!("Transfer of {call_id} timed out (SIP 408)");
                        return Err(MobileError::Timeout);
                    }
                    Some("failed") => {
                        let code = status
                            .transfer_code
                            .map_or_else(|| "unknown".to_string(), |c| c.to_string());
                        log::warn!("Transfer of {call_id} failed: SIP {code}");
                        let still_up = if legs.len() > 1 {
                            "the calls are still up"
                        } else {
                            "the call is still up"
                        };
                        return Err(MobileError::CallFailed(format!(
                            "the transfer failed (SIP {code}); {still_up}"
                        )));
                    }
                    _ => {}
                }
            }
            if transferred.iter().all(|t| *t) {
                return Ok(());
            }
            let now = Instant::now();
            if transferred.iter().any(|t| *t) {
                let settle_by =
                    *settle_by.get_or_insert(now + TRANSFER_SETTLE.min(self.transfer_timeout));
                if now >= settle_by {
                    for (leg, _) in legs.iter().zip(&transferred).filter(|(_, t)| !**t) {
                        self.end_transferred_leg(leg);
                    }
                    return Ok(());
                }
            } else if now >= deadline {
                log::warn!("No transfer outcome; the call is still up");
                return Err(MobileError::Timeout);
            }
        }
    }

    /// End a call of a transfer that succeeded but which the gateway still
    /// reports up: here at once, and at the gateway in the background.
    fn end_transferred_leg(&self, leg: &TransferLeg<'_>) {
        let call_id = leg.call_id.to_string();
        log::warn!("{call_id} is still up after its transfer succeeded; hanging it up");
        if !end_call_locally(&self.calls, &self.events, &call_id, EndReason::Transferred) {
            return;
        }
        let (gateway, auth, events) = (
            Arc::clone(&self.gateway),
            Arc::clone(&self.auth),
            Arc::clone(&self.events),
        );
        let (route, call_token) = (leg.route.clone(), leg.call_token.to_string());
        runtime().spawn(async move {
            hang_up_at_gateway(&gateway, &auth, &events, &route, &call_id, &call_token).await;
        });
    }

    pub fn set_mute(&self, call_id: String, muted: bool) -> Result<(), MobileError> {
        let mut calls = self.calls.lock().unwrap();
        let call = calls.get_mut(&call_id).ok_or(MobileError::InvalidState)?;

        if let Some(media) = &call.media {
            media.set_mute(muted);
        }

        call.info.muted = muted;
        // Queued under the call-map lock, so concurrent changes are
        // delivered in the order they were applied.
        call.events.emit(&self.events, call.info.clone());
        Ok(())
    }

    /// Hold or resume a call, locally (no re-INVITE).
    ///
    /// Resuming a call first holds every other connected call, so at most
    /// one is ever off hold; each call whose hold state changed is reported.
    pub fn set_hold(&self, call_id: String, on_hold: bool) -> Result<(), MobileError> {
        let mut calls = self.calls.lock().unwrap();
        if !calls.contains_key(&call_id) {
            return Err(MobileError::InvalidState);
        }
        if !on_hold {
            hold_others(&mut calls, &call_id, &self.events);
        }
        let call = calls.get_mut(&call_id).expect("checked above");
        apply_hold(call, on_hold);
        // Queued under the call-map lock, so concurrent changes are
        // delivered in the order they were applied.
        call.events.emit(&self.events, call.info.clone());
        Ok(())
    }

    /// Put `active_call_id` on hold and resume `held_call_id`, in one step
    /// with respect to every other call control.
    ///
    /// Throws `InvalidState` unless both are distinct connected calls. Each
    /// call whose hold state changed is reported, the one going on hold
    /// first.
    pub fn swap_calls(
        &self,
        active_call_id: String,
        held_call_id: String,
    ) -> Result<(), MobileError> {
        if active_call_id == held_call_id {
            return Err(MobileError::InvalidState);
        }
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !calls.contains_key(&active_call_id) || !calls.contains_key(&held_call_id) {
            return Err(MobileError::InvalidState);
        }
        let active = calls.get_mut(&active_call_id).expect("checked above");
        if apply_hold(active, true) {
            active.events.emit(&self.events, active.info.clone());
        }
        hold_others(&mut calls, &held_call_id, &self.events);
        let held = calls.get_mut(&held_call_id).expect("checked above");
        if apply_hold(held, false) {
            held.events.emit(&self.events, held.info.clone());
        }
        log::info!("Swapped calls: {active_call_id} held, {held_call_id} active");
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
        route: Route,
        call_token: String,
        stop: Arc<AtomicBool>,
        max_age: Option<Duration>,
        mut on_status: impl FnMut(&CallStatusResponse) -> PollAction + Send + 'static,
    ) {
        let started = Instant::now();
        let gateway = Arc::clone(&self.gateway);
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.events);
        let interval = self.poll_interval;

        // A task on the shared runtime rather than a thread with its own: no
        // thread per call, and the request goes out on the call's own route
        // with the engine's pinned clients. Callbacks it raises are delivered
        // on the dispatch thread, never on this task.
        runtime().spawn(async move {
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
                let (token, generation) = auth.snapshot();
                match gateway.get_call_status(&route, &token, &call_token).await {
                    Ok(status) => match on_status(&status) {
                        PollAction::Continue => {}
                        PollAction::Stop => {
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        PollAction::Reject => {
                            if let Err(e) = gateway.reject_call(&route, &token, &call_token).await {
                                log::warn!("Could not reject {}: {}", call_token, e);
                            }
                        }
                        PollAction::HangUp => {
                            stop.store(true, Ordering::Relaxed);
                            let call_id = format!("incoming-{call_token}");
                            hang_up_at_gateway(
                                &gateway,
                                &auth,
                                &handler,
                                &route,
                                &call_id,
                                &call_token,
                            )
                            .await;
                            break;
                        }
                    },
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
    }

    /// Poll an established call for a remote hangup (BYE from the PBX).
    ///
    /// When the gateway reports the call gone, the poll thread tears the call
    /// down and emits `Ended` itself, so apps learn of a remote hangup through
    /// `on_call_state_changed` without polling `check_remote_hangup`.
    fn start_call_status_poll(
        &self,
        call_id: String,
        call_token: String,
        route: Route,
        stop: Arc<AtomicBool>,
    ) {
        let calls = Arc::clone(&self.calls);
        let handler = Arc::clone(&self.events);
        let remote_ended = Arc::clone(&self.remote_ended);
        let mut gone = GoneDetector::default();

        self.spawn_status_poll(route, call_token, stop, None, move |status| {
            if !gone.is_gone(&status.status) {
                return PollAction::Continue;
            }
            log::info!(
                "Remote hangup detected for {} (reason: {:?})",
                call_id,
                status.reason,
            );
            let reason = EndReason::from_gateway(status.reason.as_deref(), EndReason::RemoteHangup);
            if end_call_locally(&calls, &handler, &call_id, reason) {
                let mut ended = remote_ended
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                ended.push(call_id.clone());
                if ended.len() > REMOTE_ENDED_BACKLOG {
                    let excess = ended.len() - REMOTE_ENDED_BACKLOG;
                    ended.drain(..excess);
                }
            }
            PollAction::Stop
        });
    }

    /// Watch an offered incoming call for the caller hanging up before it is
    /// answered (a CANCEL at the PBX).
    ///
    /// If that happens while the call is still unanswered, `Ended` is emitted
    /// for the call_id the call would have had (`incoming-<call_token>`), so
    /// the app can dismiss its ringing UI. The watch stops as soon as the call
    /// is accepted or rejected.
    fn start_pending_incoming_poll(&self, offer: &CallOffer, route: Route) {
        self.watch_incoming(offer, route, false);
    }

    /// Watch an offered call, or mark an existing watch `abandoned`. Returns
    /// the events shared by everything that can report the call.
    ///
    /// Until the call is accepted or rejected the watch reports, with one
    /// `Ended` for `incoming-<call_token>`, the caller hanging up (`ended`,
    /// or `unknown` three times in a row) and the call being answered on
    /// another device (`active` while this handset is not accepting). For an
    /// abandoned call it instead hangs the call up if it is `active`, and
    /// rejects it once while it still rings; the app has already been told
    /// it ended.
    fn watch_incoming(&self, offer: &CallOffer, route: Route, abandoned: bool) -> Arc<CallEvents> {
        let call_token = offer.call_token.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let events = {
            let mut pending = self
                .pending_incoming
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(existing) = pending.get_mut(&call_token) {
                existing.abandoned |= abandoned;
                existing.accepting &= !abandoned;
                return Arc::clone(&existing.events);
            }
            let events: Arc<CallEvents> = Arc::default();
            pending.insert(
                call_token.clone(),
                PendingIncoming {
                    stop: Arc::clone(&stop),
                    route: route.clone(),
                    info: CallInfo {
                        call_id: format!("incoming-{call_token}"),
                        remote_uri: offer.caller_uri.clone(),
                        remote_name: offer.caller_name.clone(),
                        state: CallState::Ended,
                        direction: CallDirection::Inbound,
                        muted: false,
                        on_hold: false,
                        duration_secs: 0,
                        end_reason: None,
                    },
                    events: Arc::clone(&events),
                    accepting: false,
                    abandoned,
                    rejected: false,
                },
            );
            events
        };

        let pending = Arc::clone(&self.pending_incoming);
        let handler = Arc::clone(&self.events);
        let token = call_token.clone();
        // While the gateway hands a call from pending to active it can briefly
        // report "unknown", so only several in a row count as gone. "ended" is
        // definitive: the gateway records a CANCEL that way.
        let mut gone = GoneDetector::default();

        let deadline = Some(PENDING_INCOMING_MAX_WATCH);
        self.spawn_status_poll(route, call_token, stop, deadline, move |status| {
            // Decided under the pending lock, against accept, reject and
            // abandonment.
            let mut pending = pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(entry) = pending.get_mut(&token) else {
                // Accepted or rejected meanwhile: the app knows the outcome.
                return PollAction::Stop;
            };
            if status.status == "active" {
                let accepting = entry.accepting;
                let entry = pending.remove(&token).expect("present");
                if accepting {
                    // This handset is answering; accept reports the outcome.
                    return PollAction::Stop;
                }
                if entry.abandoned {
                    log::info!("Abandoned incoming call {} was answered; hanging up", token);
                    return PollAction::HangUp;
                }
                log::info!("Incoming call {} answered elsewhere", token);
                entry
                    .events
                    .emit_ended(&handler, &entry.info, EndReason::AnsweredElsewhere);
                return PollAction::Stop;
            }
            if gone.is_gone(&status.status) {
                let entry = pending.remove(&token).expect("present");
                if !entry.abandoned {
                    log::info!(
                        "Incoming call {} ended before answer (reason: {:?})",
                        token,
                        status.reason,
                    );
                    let reason = EndReason::from_gateway(
                        status.reason.as_deref(),
                        EndReason::CallerCancelled,
                    );
                    entry.events.emit_ended(&handler, &entry.info, reason);
                }
                return PollAction::Stop;
            }
            if entry.abandoned && !entry.rejected {
                entry.rejected = true;
                return PollAction::Reject;
            }
            PollAction::Continue
        });
        events
    }

    /// Stop watching an offered incoming call; it has been accepted or rejected.
    fn clear_pending_incoming(&self, call_token: &str) {
        self.take_pending_incoming(call_token);
    }

    /// Stop watching an offered incoming call and return its entry.
    fn take_pending_incoming(&self, call_token: &str) -> Option<PendingIncoming> {
        let removed = self
            .pending_incoming
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(call_token);
        if let Some(pending) = &removed {
            pending.stop.store(true, Ordering::Relaxed);
        }
        removed
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
            end_call_locally(&self.calls, &self.events, call_id, EndReason::RemoteHangup);
        }

        ended_id
    }

    // ── State Queries ───────────────────────────────────────────────

    /// The connected call that is off hold, if there is one; otherwise the
    /// most recently created live call (held, or outgoing and ringing).
    pub fn get_active_call(&self) -> Option<CallInfo> {
        // Lock order: calls, then pending_outgoing.
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(call) = calls.values().find(|c| !c.info.on_hold) {
            return Some(call.info.clone());
        }
        let outgoing = self
            .pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live_calls(&calls, &outgoing).pop().map(|(_, info)| info)
    }

    /// Every live call (connected, held, or outgoing and ringing), oldest
    /// first. Offered incoming calls are not included until accepted.
    pub fn get_calls(&self) -> Vec<CallInfo> {
        // Lock order: calls, then pending_outgoing.
        let calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let outgoing = self
            .pending_outgoing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live_calls(&calls, &outgoing)
            .into_iter()
            .map(|(_, info)| info)
            .collect()
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

        // Send a heartbeat to the push gateway, which re-registers SIP with a
        // fresh socket. Network changes come in bursts, so heartbeats are
        // coalesced: at most one is in flight, and changes during it lead to
        // one more afterwards, using the device and token current then.
        {
            let mut heartbeat = self
                .heartbeat
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            heartbeat.requested = true;
            if heartbeat.running {
                log::debug!("Heartbeat already in flight; coalescing");
            } else {
                heartbeat.running = true;
                self.spawn_heartbeats();
            }
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

impl AriaMobileEngine {
    /// Send heartbeats until no network change is waiting for one.
    fn spawn_heartbeats(&self) {
        let state = Arc::clone(&self.heartbeat);
        let device_id = Arc::clone(&self.device_id);
        let gateway = Arc::clone(&self.gateway);
        let auth = Arc::clone(&self.auth);
        let handler = Arc::clone(&self.events);
        runtime().spawn(async move {
            loop {
                {
                    let mut state = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !state.requested {
                        state.running = false;
                        return;
                    }
                    state.requested = false;
                }
                let did = device_id
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let Some(did) = did else { continue };
                let (tok, generation) = auth.snapshot();
                log::info!("Sending heartbeat for device {} after network change", did);
                match gateway.device_heartbeat(&tok, &did).await {
                    Ok(()) => log::info!("Gateway heartbeat successful after network change"),
                    Err(MobileError::AuthenticationError) => {
                        report_auth_rejected(&auth, &handler, generation);
                    }
                    Err(e) => log::warn!("Gateway heartbeat failed: {}", e),
                }
            }
        });
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
        /// The status the mock answered with.
        pub status: u16,
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
            let respond = Arc::new(respond);
            // One thread per connection, so a response the test holds back
            // (an outgoing call that is still ringing) does not stall the
            // requests behind it.
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let respond = Arc::clone(&respond);
                    let seen = Arc::clone(&seen);
                    std::thread::spawn(move || {
                        let Some(mut req) = read_request(&mut stream) else {
                            return;
                        };
                        let (status, body) = respond(&req);
                        req.status = status;
                        seen.lock().unwrap().push(req);
                        // Status 0: drop the connection without answering,
                        // as a request lost after it was delivered.
                        if status == 0 {
                            return;
                        }
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    });
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
            status: 0,
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
        errors: Arc<Mutex<Vec<(String, String)>>>,
        /// Flushed before reading, since events are delivered on the
        /// dispatch thread. Weak, so the engine's handler slot holding this
        /// recorder does not keep the dispatcher alive.
        dispatcher: Arc<Mutex<std::sync::Weak<Dispatcher>>>,
    }

    impl Recorder {
        fn attach(&self, engine: &AriaMobileEngine) {
            *self.dispatcher.lock().unwrap() = Arc::downgrade(&engine.events);
        }

        fn flush(&self) {
            let dispatcher = self.dispatcher.lock().unwrap().upgrade();
            if let Some(d) = dispatcher {
                d.flush();
            }
        }

        fn states(&self) -> Vec<CallInfo> {
            self.flush();
            self.states.lock().unwrap().clone()
        }

        fn auth_required(&self) -> u32 {
            self.flush();
            *self.auth_required.lock().unwrap()
        }

        fn errors(&self) -> Vec<(String, String)> {
            self.flush();
            self.errors.lock().unwrap().clone()
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
        fn on_error(&self, context: String, message: String) {
            self.errors.lock().unwrap().push((context, message));
        }
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
        engine.transfer_poll_interval = Duration::from_millis(10);
        engine.transfer_timeout = Duration::from_millis(500);
        let recorder = Recorder::default();
        recorder.attach(&engine);
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
                    end_reason: None,
                },
                seq: engine.next_seq.fetch_add(1, Ordering::Relaxed),
                media: None,
                call_token: Some(call_token.to_string()),
                route: engine.gateway.primary_route(),
                poll_stop: Arc::clone(&poll_stop),
                events: Arc::default(),
            },
        );
        poll_stop
    }

    /// An address nothing listens on, for tests that must not reach a gateway.
    const NO_GATEWAY: &str = "http://127.0.0.1:9";

    /// Put a connected call in the engine, as `insert_call` does, going
    /// `direction` and held on `route`.
    fn insert_call_on(
        engine: &AriaMobileEngine,
        call_id: &str,
        call_token: &str,
        direction: CallDirection,
        route: Route,
    ) -> Arc<AtomicBool> {
        let stop = insert_call(engine, call_id, call_token);
        let mut calls = engine.calls.lock().unwrap();
        let call = calls.get_mut(call_id).unwrap();
        call.info.direction = direction;
        call.route = route;
        stop
    }

    /// An incoming call `incoming-tok-in` and an outgoing consultation call
    /// `outgoing-c` (token `tok-out`), as after placing a call to the
    /// transfer target from a call on hold. Returns their poll stop flags.
    fn insert_attended_pair(engine: &AriaMobileEngine) -> (Arc<AtomicBool>, Arc<AtomicBool>) {
        let route = engine.gateway.primary_route();
        let incoming = insert_call_on(
            engine,
            "incoming-tok-in",
            "tok-in",
            CallDirection::Inbound,
            route.clone(),
        );
        let consult = insert_call_on(
            engine,
            "outgoing-c",
            "tok-out",
            CallDirection::Outbound,
            route,
        );
        (incoming, consult)
    }

    /// A gateway that accepts a transfer with 202 and answers each call's
    /// status polls with that call's script in turn, repeating the last
    /// answer: `scripts` maps a call token to its script.
    fn attended_gateway(scripts: &[(&'static str, &[&'static str])]) -> MockGateway {
        let scripts: HashMap<String, (Vec<&'static str>, usize)> = scripts
            .iter()
            .map(|(token, script)| (token.to_string(), (script.to_vec(), 0)))
            .collect();
        let scripts = Mutex::new(scripts);
        MockGateway::start(move |req| {
            if req.path.ends_with("/transfer") {
                return (202, "{}".into());
            }
            let token = req
                .path
                .strip_prefix("/v1/calls/")
                .and_then(|p| p.strip_suffix("/status"));
            let mut scripts = scripts.lock().unwrap();
            match token.and_then(|t| scripts.get_mut(t)) {
                Some((script, n)) => {
                    let body = script[(*n).min(script.len() - 1)];
                    *n += 1;
                    (200, body.into())
                }
                None => (200, "{}".into()),
            }
        })
    }

    const PENDING: &str = r#"{"status":"active","transfer":"pending"}"#;
    const TRANSFERRED: &str = r#"{"status":"ended","reason":"transferred"}"#;

    fn ended_reasons(recorder: &Recorder, call_id: &str) -> Vec<Option<EndReason>> {
        recorder
            .states()
            .iter()
            .filter(|i| i.call_id == call_id && i.state == CallState::Ended)
            .map(|i| i.end_reason)
            .collect()
    }

    #[test]
    fn attended_transfer_sends_replaces_and_ends_both_calls_once() {
        let gw = attended_gateway(&[
            ("tok-in", &[PENDING, PENDING, TRANSFERRED]),
            ("tok-out", &[PENDING, TRANSFERRED]),
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let (in_stop, out_stop) = insert_attended_pair(&engine);
        // The regular remote-hangup polls run too, and also see the calls
        // end; between them and the transfer, one Ended each.
        let route = engine.gateway.primary_route();
        engine.start_call_status_poll(
            "incoming-tok-in".into(),
            "tok-in".into(),
            route.clone(),
            Arc::clone(&in_stop),
        );
        engine.start_call_status_poll(
            "outgoing-c".into(),
            "tok-out".into(),
            route,
            Arc::clone(&out_stop),
        );

        engine
            .transfer_attended("outgoing-c".into(), "incoming-tok-in".into())
            .unwrap();

        let transfers: Vec<_> = gw
            .requests()
            .into_iter()
            .filter(|r| r.path.ends_with("/transfer"))
            .collect();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].method, "POST");
        assert_eq!(transfers[0].path, "/v1/calls/tok-out/transfer");
        assert_eq!(transfers[0].body, r#"{"replaces":"tok-in"}"#);

        assert!(engine.get_calls().is_empty());
        assert!(in_stop.load(Ordering::Relaxed) && out_stop.load(Ordering::Relaxed));
        std::thread::sleep(Duration::from_millis(100));
        for id in ["incoming-tok-in", "outgoing-c"] {
            assert_eq!(
                ended_reasons(&recorder, id),
                [Some(EndReason::Transferred)],
                "{id}"
            );
        }
        assert_eq!(recorder.states().len(), 2);
        // Nothing was hung up: the gateway ended both calls itself.
        assert!(gw.requests().iter().all(|r| !r.path.ends_with("/hangup")));
    }

    #[test]
    fn a_failed_attended_transfer_keeps_both_calls_up() {
        let failed = r#"{"status":"active","transfer":"failed","transfer_code":503}"#;
        let gw = attended_gateway(&[
            ("tok-in", &[PENDING, failed]),
            ("tok-out", &[PENDING, failed]),
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let (in_stop, out_stop) = insert_attended_pair(&engine);

        let err = engine
            .transfer_attended("incoming-tok-in".into(), "outgoing-c".into())
            .unwrap_err();

        match &err {
            MobileError::CallFailed(message) => {
                assert!(message.contains("SIP 503"), "{message}");
                assert!(message.contains("still up"), "{message}");
            }
            other => panic!("expected CallFailed, got {other:?}"),
        }
        assert_eq!(engine.get_calls().len(), 2);
        assert!(!in_stop.load(Ordering::Relaxed) && !out_stop.load(Ordering::Relaxed));
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn an_attended_transfer_failed_with_408_is_a_timeout() {
        let failed = r#"{"status":"active","transfer":"failed","transfer_code":408}"#;
        let gw = attended_gateway(&[("tok-in", &[PENDING, failed]), ("tok-out", &[failed])]);
        let (engine, recorder) = engine(&gw.base_url);
        insert_attended_pair(&engine);

        let err = engine
            .transfer_attended("incoming-tok-in".into(), "outgoing-c".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::Timeout), "{err:?}");
        assert_eq!(engine.get_calls().len(), 2);
        assert!(recorder.states().is_empty());
    }

    /// The incoming call hangs up mid-transfer: it is reported ended, and
    /// the consultation call (released by the gateway with 487) stays up.
    #[test]
    fn a_call_that_ends_otherwise_during_an_attended_transfer_leaves_the_other_up() {
        let gw = attended_gateway(&[
            ("tok-in", &[PENDING, r#"{"status":"ended","reason":"bye"}"#]),
            (
                "tok-out",
                &[
                    PENDING,
                    r#"{"status":"active","transfer":"failed","transfer_code":487}"#,
                ],
            ),
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        insert_attended_pair(&engine);

        let err = engine
            .transfer_attended("incoming-tok-in".into(), "outgoing-c".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::InvalidState), "{err:?}");
        assert_eq!(
            ended_reasons(&recorder, "incoming-tok-in"),
            [Some(EndReason::RemoteHangup)]
        );
        assert_eq!(ids(&engine.get_calls()), ["outgoing-c"]);
    }

    /// A call the gateway still reports up after the other was transferred
    /// is ended here after a short wait, and hung up at the gateway.
    #[test]
    fn a_call_left_up_after_a_successful_attended_transfer_is_ended() {
        let gw = attended_gateway(&[("tok-in", &[PENDING, TRANSFERRED]), ("tok-out", &[PENDING])]);
        let (engine, recorder) = engine(&gw.base_url);
        insert_attended_pair(&engine);

        engine
            .transfer_attended("incoming-tok-in".into(), "outgoing-c".into())
            .unwrap();

        assert!(engine.get_calls().is_empty());
        for id in ["incoming-tok-in", "outgoing-c"] {
            assert_eq!(
                ended_reasons(&recorder, id),
                [Some(EndReason::Transferred)],
                "{id}"
            );
        }
        assert!(eventually(|| count(&gw, "/v1/calls/tok-out/hangup") == 1));
        assert_eq!(count(&gw, "/v1/calls/tok-in/hangup"), 0);
    }

    #[test]
    fn attended_transfer_is_checked_before_anything_is_sent() {
        let (engine, recorder) = engine(NO_GATEWAY);
        let route = engine.gateway.primary_route();
        insert_call_on(
            &engine,
            "incoming-a",
            "a",
            CallDirection::Inbound,
            route.clone(),
        );
        insert_call_on(
            &engine,
            "incoming-b",
            "b",
            CallDirection::Inbound,
            route.clone(),
        );
        insert_call_on(
            &engine,
            "outgoing-c",
            "c",
            CallDirection::Outbound,
            route.clone(),
        );
        insert_call_on(&engine, "outgoing-d", "d", CallDirection::Outbound, route);

        let invalid = [
            ("incoming-a", "incoming-a"),
            ("incoming-a", "nope"),
            ("nope", "outgoing-c"),
        ];
        for (a, b) in invalid {
            let err = engine.transfer_attended(a.into(), b.into()).unwrap_err();
            assert!(matches!(err, MobileError::InvalidState), "{a} {b}: {err:?}");
        }
        for (a, b) in [("incoming-a", "incoming-b"), ("outgoing-c", "outgoing-d")] {
            let err = engine.transfer_attended(a.into(), b.into()).unwrap_err();
            assert!(
                matches!(err, MobileError::TransferUnsupported),
                "{a} {b}: {err:?}"
            );
        }
        assert_eq!(engine.get_calls().len(), 4);
        assert!(recorder.states().is_empty());
    }

    /// A ringing outgoing call is not connected, so it cannot be one side.
    #[test]
    fn a_ringing_call_cannot_be_attended_transferred() {
        let gate = Gate::default();
        let opened = gate.clone();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                opened.wait();
                answer("ct-out")
            }
            _ => (200, r#"{"status":"active"}"#.into()),
        });
        let (engine, _) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        answer_here(&engine, "tok-1").unwrap();
        let ringing = dial_in_background(&engine);
        assert!(eventually(|| engine.get_calls().len() == 2));
        let out_id = engine.get_calls()[1].call_id.clone();

        let err = engine
            .transfer_attended("incoming-tok-1".into(), out_id)
            .unwrap_err();

        assert!(matches!(err, MobileError::InvalidState), "{err:?}");
        assert!(gw.requests().iter().all(|r| !r.path.ends_with("/transfer")));
        gate.open();
        ringing.recv().unwrap().unwrap();
    }

    #[test]
    fn attended_transfer_refusals_leave_both_calls_up() {
        // The gateway client's mapping is tested there; this checks that
        // every refusal leaves both calls alone.
        let cases = [
            (
                409,
                r#"{"error":"unsupported_by_pbx"}"#,
                "TransferUnsupported",
            ),
            (409, r#"{"error":"call_not_established"}"#, "InvalidState"),
            (409, "", "GatewayError"),
            (400, r#"{"error":"same_call"}"#, "InvalidState"),
            (404, "{}", "InvalidState"),
            (502, "{}", "CallFailed"),
        ];
        for (status, body, expected) in cases {
            let gw = MockGateway::start(move |_| (status, body.to_string()));
            let (engine, recorder) = engine(&gw.base_url);
            insert_attended_pair(&engine);

            let err = engine
                .transfer_attended("incoming-tok-in".into(), "outgoing-c".into())
                .unwrap_err();

            let got = match err {
                MobileError::TransferUnsupported => "TransferUnsupported",
                MobileError::InvalidState => "InvalidState",
                MobileError::GatewayError => "GatewayError",
                MobileError::CallFailed(_) => "CallFailed",
                other => panic!("HTTP {status} {body}: {other:?}"),
            };
            assert_eq!(got, expected, "HTTP {status} {body}");
            assert_eq!(engine.get_calls().len(), 2, "HTTP {status} {body}");
            assert!(recorder.states().is_empty(), "HTTP {status} {body}");
            assert_eq!(gw.requests().len(), 1, "HTTP {status} {body}");
        }
    }

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
        let gw = transfer_gateway(&[
            r#"{"status":"active","transfer":"pending"}"#,
            r#"{"status":"active","transfer":"pending"}"#,
            r#"{"status":"ended","reason":"transferred"}"#,
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let poll_stop = insert_call(&engine, "c1", "tok-42");

        engine
            .transfer_call("c1".into(), " sip:1002@pbx.example.com ".into())
            .unwrap();

        let reqs = gw.requests();
        assert_eq!(reqs[0].path, "/v1/calls/tok-42/transfer");
        assert_eq!(count(&gw, "/v1/calls/tok-42/status"), 3);
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
        assert_eq!(states[0].end_reason, Some(EndReason::Transferred));
    }

    /// A gateway that accepts a REFER with 202 and then answers status polls
    /// with `script` in turn, repeating the last answer.
    fn transfer_gateway(script: &[&'static str]) -> MockGateway {
        let script: Vec<&'static str> = script.to_vec();
        let polls = Arc::new(Mutex::new(0usize));
        MockGateway::start(move |req| {
            if req.path.ends_with("/transfer") {
                return (202, "{}".into());
            }
            let mut n = polls.lock().unwrap();
            let body = script[(*n).min(script.len() - 1)];
            *n += 1;
            (200, body.into())
        })
    }

    #[test]
    fn a_transfer_the_pbx_fails_keeps_the_call_up() {
        let gw = transfer_gateway(&[
            r#"{"status":"active","transfer":"pending"}"#,
            r#"{"status":"active","transfer":"failed","transfer_code":486}"#,
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let poll_stop = insert_call(&engine, "c1", "tok");

        let err = engine
            .transfer_call("c1".into(), "1002".into())
            .unwrap_err();

        match &err {
            MobileError::CallFailed(message) => assert!(message.contains("486"), "{message}"),
            other => panic!("expected CallFailed, got {other:?}"),
        }
        assert!(err.to_string().contains("486"));
        assert!(engine.get_active_call().is_some());
        assert!(!poll_stop.load(Ordering::Relaxed));
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn a_transfer_without_an_outcome_times_out_and_keeps_the_call_up() {
        let gw = transfer_gateway(&[r#"{"status":"active","transfer":"pending"}"#]);
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        let err = engine
            .transfer_call("c1".into(), "1002".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::Timeout), "{err:?}");
        assert!(engine.get_active_call().is_some());
        assert!(recorder.states().is_empty());
    }

    /// A 408 from the gateway (its NOTIFY watchdog, or a real 408 sipfrag)
    /// means no outcome, not a refusal: Timeout, with the call still up.
    #[test]
    fn a_transfer_failed_with_408_is_a_timeout() {
        let gw = transfer_gateway(&[
            r#"{"status":"active","transfer":"pending"}"#,
            r#"{"status":"active","transfer":"failed","transfer_code":408}"#,
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let poll_stop = insert_call(&engine, "c1", "tok");

        let err = engine
            .transfer_call("c1".into(), "1002".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::Timeout), "{err:?}");
        assert!(engine.get_active_call().is_some());
        assert!(!poll_stop.load(Ordering::Relaxed));
        assert!(recorder.states().is_empty());
    }

    /// The core's own deadline outlasts the gateway's 30 s watchdog, so the
    /// gateway's verdict normally wins.
    #[test]
    fn the_transfer_deadline_outlasts_the_gateways_watchdog() {
        assert!(TRANSFER_TIMEOUT > Duration::from_secs(30));
    }

    /// A gateway that predates transfer outcomes: the active call has no
    /// `transfer` field, and the call ends on the 202 as before.
    #[test]
    fn an_old_gateway_ends_the_call_on_the_202() {
        let gw = transfer_gateway(&[r#"{"status":"active"}"#]);
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        engine.transfer_call("c1".into(), "1002".into()).unwrap();

        assert!(engine.get_active_call().is_none());
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::Transferred));
    }

    #[test]
    fn a_call_that_ends_otherwise_during_a_transfer_is_reported_once() {
        let gw = transfer_gateway(&[
            r#"{"status":"active","transfer":"pending"}"#,
            r#"{"status":"ended","reason":"bye"}"#,
        ]);
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok");
        // The regular remote-hangup poll runs too; between them, one Ended.
        engine.start_call_status_poll(
            "c1".into(),
            "tok".into(),
            engine.gateway.primary_route(),
            stop,
        );

        let err = engine
            .transfer_call("c1".into(), "1002".into())
            .unwrap_err();

        assert!(matches!(err, MobileError::InvalidState), "{err:?}");
        std::thread::sleep(Duration::from_millis(100));
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::RemoteHangup));
    }

    #[test]
    fn failed_transfer_leaves_the_call_up() {
        for (status, check) in [
            (
                400,
                (|e| matches!(e, MobileError::InvalidTarget)) as fn(&MobileError) -> bool,
            ),
            (404, |e| matches!(e, MobileError::InvalidState)),
            (502, |e| matches!(e, MobileError::CallFailed(_))),
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

        engine.start_call_status_poll(
            "c1".into(),
            "tok-7".into(),
            engine.gateway.primary_route(),
            stop,
        );

        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "c1");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::RemoteHangup));
        assert!(engine.get_active_call().is_none());

        // Apps that still poll keep working, and see no second event.
        assert_eq!(engine.check_remote_hangup().as_deref(), Some("c1"));
        assert_eq!(engine.check_remote_hangup(), None);
        assert_eq!(recorder.states().len(), 1);
    }

    #[test]
    fn a_stray_unknown_status_does_not_end_a_live_call() {
        let polls = Arc::new(Mutex::new(0u32));
        let counter = Arc::clone(&polls);
        // unknown, active, unknown, unknown, active, ... then unknown x3.
        let script = [
            "unknown", "active", "unknown", "unknown", "active", "unknown", "unknown", "unknown",
        ];
        let gw = MockGateway::start(move |_| {
            let mut n = counter.lock().unwrap();
            let status = script.get(*n as usize).copied().unwrap_or("unknown");
            *n += 1;
            (200, format!(r#"{{"status":"{status}"}}"#))
        });
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok");
        engine.start_call_status_poll(
            "c1".into(),
            "tok".into(),
            engine.gateway.primary_route(),
            stop,
        );

        // Ended only after the third unknown in a row, the eighth answer.
        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        assert!(*polls.lock().unwrap() >= 8);
    }

    #[test]
    fn gone_detector_needs_consecutive_unknowns() {
        let mut d = GoneDetector::default();
        assert!(!d.is_gone("unknown"));
        assert!(!d.is_gone("unknown"));
        assert!(!d.is_gone("active"));
        assert!(!d.is_gone("unknown"));
        assert!(!d.is_gone("unknown"));
        assert!(d.is_gone("unknown"));
        assert!(GoneDetector::default().is_gone("ended"));
    }

    #[test]
    fn hangup_after_remote_end_does_not_emit_twice() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);
        let stop = insert_call(&engine, "c1", "tok");
        engine.start_call_status_poll(
            "c1".into(),
            "tok".into(),
            engine.gateway.primary_route(),
            stop,
        );
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

        assert!(eventually(|| count(&gw, "/v1/calls/tok/hangup") == 1));
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::LocalHangup));
    }

    /// hangup does not wait on the gateway: Ended is reported at once even
    /// when the gateway is slow to answer the hangup.
    #[test]
    fn hangup_does_not_wait_for_the_gateway() {
        let gw = MockGateway::start(|_| {
            std::thread::sleep(Duration::from_secs(2));
            (200, "{}".into())
        });
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        let started = Instant::now();
        engine.hangup("c1".into()).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(recorder.states()[0].state, CallState::Ended);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(eventually(|| count(&gw, "/v1/calls/tok/hangup") == 1));
    }

    /// A gateway that does not know the call is retried once on the call's
    /// own instance, then reported through on_error with the call id.
    #[test]
    fn a_hangup_the_gateway_does_not_know_is_retried_then_reported() {
        let gw = MockGateway::start(|_| (404, "{}".into()));
        let (engine, recorder) = engine(NO_GATEWAY);
        engine
            .gateway
            .set_test_routes(&[NO_GATEWAY, gw.base_url.as_str()]);
        let stop = insert_call(&engine, "c1", "tok");
        // The call lives on the second instance.
        engine.calls.lock().unwrap().get_mut("c1").unwrap().route =
            engine.gateway.routes()[1].clone();

        engine.hangup("c1".into()).unwrap();

        assert!(eventually(|| !recorder.errors().is_empty()));
        assert_eq!(count(&gw, "/v1/calls/tok/hangup"), 2);
        let (context, message) = recorder.errors()[0].clone();
        assert_eq!(context, "hangup");
        assert!(message.contains("c1"), "{message}");
        assert!(message.contains("may still be connected"), "{message}");
        assert_eq!(recorder.states().len(), 1);
        assert!(stop.load(Ordering::Relaxed));
    }

    #[test]
    fn a_hangup_that_succeeds_on_retry_is_not_reported() {
        let first = Arc::new(AtomicBool::new(true));
        let gw = MockGateway::start(move |_| {
            if first.swap(false, Ordering::SeqCst) {
                (404, "{}".into())
            } else {
                (200, "{}".into())
            }
        });
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        engine.hangup("c1".into()).unwrap();

        assert!(eventually(|| count(&gw, "/v1/calls/tok/hangup") == 2));
        std::thread::sleep(Duration::from_millis(100));
        assert!(recorder.errors().is_empty());
    }

    #[test]
    fn hangup_without_a_token_ends_the_call_and_says_so() {
        let gw = MockGateway::start(|_| (200, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);
        engine.set_gateway_token(String::new());
        insert_call(&engine, "c1", "tok");

        assert!(is_auth_error(engine.hangup("c1".into())));
        assert_eq!(recorder.states().len(), 1);
        std::thread::sleep(Duration::from_millis(100));
        assert!(gw.requests().is_empty());
    }

    #[test]
    fn remote_ended_backlog_is_bounded() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);
        let n = REMOTE_ENDED_BACKLOG + 4;
        for i in 0..n {
            let id = format!("c{i}");
            let stop = insert_call(&engine, &id, &format!("tok{i}"));
            engine.start_call_status_poll(
                id,
                format!("tok{i}"),
                engine.gateway.primary_route(),
                stop,
            );
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

        engine.start_pending_incoming_poll(&offer("tok-9"), engine.gateway.primary_route());

        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "incoming-tok-9");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::CallerCancelled));
        assert_eq!(states[0].direction, CallDirection::Inbound);
        assert_eq!(states[0].remote_name.as_deref(), Some("Alice"));
        assert!(engine.pending_incoming.lock().unwrap().is_empty());
    }

    #[test]
    fn answered_or_rejected_call_is_not_reported_as_cancelled() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"ended"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-1"), engine.gateway.primary_route());
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

        engine.start_pending_incoming_poll(&offer("tok-2"), engine.gateway.primary_route());
        // This handset is answering.
        engine
            .pending_incoming
            .lock()
            .unwrap()
            .get_mut("tok-2")
            .unwrap()
            .accepting = true;

        let deadline = Instant::now() + Duration::from_secs(5);
        while !engine.pending_incoming.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(engine.pending_incoming.lock().unwrap().is_empty());
        assert!(recorder.states().is_empty());
    }

    #[test]
    fn a_call_answered_on_another_device_is_reported_ended_once() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"active"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-o"), engine.gateway.primary_route());

        let states = recorder.wait_for(1);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "incoming-tok-o");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::AnsweredElsewhere));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(recorder.states().len(), 1);
        assert!(gw.requests().iter().all(|r| r.path.ends_with("/status")));
    }

    /// `answer_offer` with a mock gateway, without media.
    fn answer_here(engine: &AriaMobileEngine, token: &str) -> Result<CallInfo, MobileError> {
        runtime().block_on(engine.answer_offer(
            "jwt",
            offer(token),
            engine.gateway.primary_route(),
            None,
            "v=0".into(),
        ))
    }

    /// A gateway with one offered call, `tok-a`, whose accept the client
    /// never hears back about: the request arrives, the gateway acts on it
    /// (if `accepts`), and the connection drops without a response.
    fn gateway_that_drops_the_accept(accepts: bool) -> MockGateway {
        let state = Arc::new(Mutex::new("pending"));
        MockGateway::start(move |req| {
            let mut state = state.lock().unwrap();
            match req.path.as_str() {
                "/v1/calls/tok-a/accept" => {
                    if accepts {
                        *state = "active";
                    }
                    (0, String::new())
                }
                "/v1/calls/tok-a/status" => (200, format!(r#"{{"status":"{state}"}}"#)),
                "/v1/calls/tok-a/reject" | "/v1/calls/tok-a/hangup" => {
                    *state = "ended";
                    (200, "{}".into())
                }
                _ => (200, "{}".into()),
            }
        })
    }

    #[test]
    fn an_accept_that_reached_the_gateway_but_not_the_app_is_hung_up() {
        let gw = gateway_that_drops_the_accept(true);
        let (engine, recorder) = engine(&gw.base_url);
        engine.start_pending_incoming_poll(&offer("tok-a"), engine.gateway.primary_route());

        let err = answer_here(&engine, "tok-a").unwrap_err();
        assert!(
            matches!(err, MobileError::NetworkError | MobileError::Timeout),
            "{err:?}"
        );

        // The app hears the call ended, once, and the call is not left up.
        assert!(eventually(|| count(&gw, "/v1/calls/tok-a/hangup") == 1));
        std::thread::sleep(Duration::from_millis(100));
        let states = recorder.states();
        assert_eq!(states.len(), 1, "{states:?}");
        assert_eq!(states[0].call_id, "incoming-tok-a");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::Failed));
        assert!(engine.get_active_call().is_none());
        assert_eq!(count(&gw, "/v1/calls/tok-a/reject"), 0);
    }

    #[test]
    fn an_accept_that_never_arrived_is_rejected_not_left_ringing() {
        let gw = gateway_that_drops_the_accept(false);
        let (engine, recorder) = engine(&gw.base_url);
        engine.start_pending_incoming_poll(&offer("tok-a"), engine.gateway.primary_route());

        answer_here(&engine, "tok-a").unwrap_err();

        assert!(eventually(|| count(&gw, "/v1/calls/tok-a/reject") == 1));
        assert!(eventually(|| engine
            .pending_incoming
            .lock()
            .unwrap()
            .is_empty()));
        let states = recorder.states();
        assert_eq!(states.len(), 1, "{states:?}");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(count(&gw, "/v1/calls/tok-a/hangup"), 0);
    }

    /// Without a push (no watch yet), a lost accept still gets a watch that
    /// hangs the call up.
    #[test]
    fn a_lost_accept_without_a_push_is_still_hung_up() {
        let gw = gateway_that_drops_the_accept(true);
        let (engine, recorder) = engine(&gw.base_url);

        answer_here(&engine, "tok-a").unwrap_err();

        assert!(eventually(|| count(&gw, "/v1/calls/tok-a/hangup") == 1));
        assert_eq!(recorder.states().len(), 1);
    }

    #[test]
    fn a_refused_accept_leaves_the_call_offered() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/calls/tok-f/accept" => (404, "{}".into()),
            _ => (200, r#"{"status":"pending"}"#.into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        engine.start_pending_incoming_poll(&offer("tok-f"), engine.gateway.primary_route());

        let err = answer_here(&engine, "tok-f").unwrap_err();

        assert!(matches!(err, MobileError::CallFailed(_)), "{err:?}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(recorder.states().is_empty());
        let pending = engine.pending_incoming.lock().unwrap();
        assert!(!pending["tok-f"].accepting && !pending["tok-f"].abandoned);
        drop(pending);
        engine.clear_pending_incoming("tok-f");
    }

    #[test]
    fn an_accepted_call_shares_the_offers_single_ended() {
        let gw = MockGateway::start(|_| (200, r#"{"status":"pending"}"#.into()));
        let (engine, recorder) = engine(&gw.base_url);
        engine.start_pending_incoming_poll(&offer("tok-s"), engine.gateway.primary_route());

        let info = answer_here(&engine, "tok-s").unwrap();
        assert_eq!(info.call_id, "incoming-tok-s");
        assert!(engine.pending_incoming.lock().unwrap().is_empty());
        engine.hangup(info.call_id).unwrap();

        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Connected, CallState::Ended]);
    }

    #[test]
    fn rejecting_an_offered_call_reports_ended_rejected() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/calls/tok-r/reject" => (200, "{}".into()),
            _ => (200, r#"{"status":"pending"}"#.into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        engine.start_pending_incoming_poll(&offer("tok-r"), engine.gateway.primary_route());

        engine.reject_incoming_call("tok-r".into()).unwrap();

        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].call_id, "incoming-tok-r");
        assert_eq!(states[0].state, CallState::Ended);
        assert_eq!(states[0].end_reason, Some(EndReason::Rejected));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(recorder.states().len(), 1);
    }

    /// A remote hangup takes its reason from the gateway's `/status`.
    #[test]
    fn a_remote_end_takes_its_reason_from_the_gateway() {
        for (reason, expected) in [
            ("bye_from_remote", EndReason::RemoteHangup),
            ("transferred", EndReason::Transferred),
            ("no_ack", EndReason::Failed),
        ] {
            let gw = MockGateway::start(move |_| {
                (200, format!(r#"{{"status":"ended","reason":"{reason}"}}"#))
            });
            let (engine, recorder) = engine(&gw.base_url);
            let stop = insert_call(&engine, "c1", "tok");
            engine.start_call_status_poll(
                "c1".into(),
                "tok".into(),
                engine.gateway.primary_route(),
                stop,
            );
            let states = recorder.wait_for(1);
            assert_eq!(states[0].end_reason, Some(expected), "{reason}");
        }
    }

    #[test]
    fn gateway_reasons_map_to_end_reasons() {
        use EndReason::*;
        for (reason, fallback, expected) in [
            (Some("transferred"), RemoteHangup, Transferred),
            (Some("bye_from_remote"), CallerCancelled, RemoteHangup),
            (Some("bye"), CallerCancelled, RemoteHangup),
            (Some("cancelled"), RemoteHangup, CallerCancelled),
            (Some("rejected"), RemoteHangup, Rejected),
            (
                Some("answered_elsewhere"),
                CallerCancelled,
                AnsweredElsewhere,
            ),
            (Some("no_ack"), RemoteHangup, Failed),
            (Some("something_new"), RemoteHangup, RemoteHangup),
            (None, CallerCancelled, CallerCancelled),
        ] {
            assert_eq!(
                EndReason::from_gateway(reason, fallback),
                expected,
                "{reason:?}"
            );
        }
    }

    /// Only Ended carries a reason, even if one is set on a non-final event.
    #[test]
    fn only_ended_events_carry_a_reason() {
        let (engine, recorder) = engine(NO_GATEWAY);
        insert_call(&engine, "c1", "tok");
        engine
            .calls
            .lock()
            .unwrap()
            .get_mut("c1")
            .unwrap()
            .info
            .end_reason = Some(EndReason::Failed);
        engine.set_hold("c1".into(), true).unwrap();
        engine.hangup("c1".into()).unwrap_or(());
        let states = recorder.states();
        assert_eq!(states[0].end_reason, None);
        assert_eq!(states[1].end_reason, Some(EndReason::LocalHangup));
    }

    #[test]
    fn duplicate_push_starts_one_watch() {
        let (engine, _) = engine(NO_GATEWAY);
        engine.start_pending_incoming_poll(&offer("tok-3"), engine.gateway.primary_route());
        let first = Arc::clone(
            &engine
                .pending_incoming
                .lock()
                .unwrap()
                .get("tok-3")
                .unwrap()
                .stop,
        );
        engine.start_pending_incoming_poll(&offer("tok-3"), engine.gateway.primary_route());
        let second = Arc::clone(
            &engine
                .pending_incoming
                .lock()
                .unwrap()
                .get("tok-3")
                .unwrap()
                .stop,
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
        assert!(eventually(|| gw.requests().len() == 3));

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
    fn hangup_with_a_rejected_token_ends_the_call_and_asks_for_a_token() {
        let gw = MockGateway::start(|_| (401, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok");

        // The gateway request runs in the background, so its 401 arrives
        // through on_auth_required.
        engine.hangup("c1".into()).unwrap();

        assert!(engine.get_active_call().is_none());
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].state, CallState::Ended);
        assert!(eventually(|| recorder.auth_required() == 1));
        assert!(recorder.errors().is_empty());
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
        engine.start_call_status_poll(
            "c1".into(),
            "tok".into(),
            engine.gateway.primary_route(),
            Arc::clone(&stop),
        );

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
    fn a_poll_without_any_token_asks_for_one() {
        let gw = MockGateway::start(|req| match req.authorization.as_deref() {
            Some("Bearer fresh") => (200, r#"{"status":"active"}"#.into()),
            _ => (401, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        engine.set_gateway_token(String::new());
        let stop = insert_call(&engine, "c1", "tok");
        engine.start_call_status_poll(
            "c1".into(),
            "tok".into(),
            engine.gateway.primary_route(),
            Arc::clone(&stop),
        );

        assert!(eventually(|| recorder.auth_required() == 1));
        let seen = gw.requests().len();
        assert!(eventually(|| gw.requests().len() >= seen + 3));
        assert_eq!(recorder.auth_required(), 1);
        assert!(engine.get_active_call().is_some());
        stop.store(true, Ordering::Relaxed);
    }

    #[test]
    fn a_rejected_cancel_watch_asks_for_a_token_and_reports_no_cancel() {
        let gw = MockGateway::start(|_| (401, "{}".into()));
        let (engine, recorder) = engine(&gw.base_url);

        engine.start_pending_incoming_poll(&offer("tok-5"), engine.gateway.primary_route());

        assert!(eventually(|| gw.requests().len() >= 5));
        assert_eq!(recorder.auth_required(), 1);
        assert!(recorder.states().is_empty());
        engine.clear_pending_incoming("tok-5");
    }

    #[test]
    fn call_events_stop_after_ended() {
        let (engine, recorder) = engine(NO_GATEWAY);
        let events = CallEvents::default();
        let info = |state| CallInfo {
            call_id: "c1".into(),
            remote_uri: String::new(),
            remote_name: None,
            state,
            direction: CallDirection::Outbound,
            muted: false,
            on_hold: false,
            duration_secs: 0,
            end_reason: None,
        };
        assert!(events.emit(&engine.events, info(CallState::Ringing)));
        assert!(events.emit(&engine.events, info(CallState::Ended)));
        assert!(!events.emit(&engine.events, info(CallState::Connected)));
        assert!(!events.emit(&engine.events, info(CallState::Ended)));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
    }

    /// An event raised from inside a callback for the same call is delivered
    /// after that callback returns, not nested inside it, and the engine
    /// method the callback calls works (it is not inside the runtime).
    #[test]
    fn call_events_raised_from_a_callback_keep_their_order() {
        struct HangUpOnConnected {
            engine: Arc<AriaMobileEngine>,
            order: Arc<Mutex<Vec<(CallState, bool)>>>,
            in_callback: AtomicBool,
        }
        impl MobileEventHandler for HangUpOnConnected {
            fn on_registration_changed(&self, _: String, _: String, _: Option<String>) {}
            fn on_incoming_call(&self, _: CallOffer) {}
            fn on_call_state_changed(&self, info: CallInfo) {
                let nested = self.in_callback.swap(true, Ordering::SeqCst);
                self.order.lock().unwrap().push((info.state, nested));
                if info.state == CallState::Connected {
                    self.engine.hangup(info.call_id).unwrap();
                }
                self.in_callback.store(nested, Ordering::SeqCst);
            }
            fn on_media_stats(&self, _: String, _: MediaStats) {}
            fn on_error(&self, _: String, _: String) {}
            fn on_auth_required(&self) {}
        }

        let gw = MockGateway::start(|_| (200, "{}".into()));
        let (engine, _) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let order = Arc::new(Mutex::new(Vec::new()));
        engine.set_event_handler(Box::new(HangUpOnConnected {
            engine: Arc::clone(&engine),
            order: Arc::clone(&order),
            in_callback: AtomicBool::new(false),
        }));
        insert_call(&engine, "c1", "tok");
        engine.set_hold("c1".into(), false).unwrap();
        // Once for Connected, once more for the Ended its callback queued.
        engine.events.flush();
        engine.events.flush();

        assert_eq!(
            *order.lock().unwrap(),
            [(CallState::Connected, false), (CallState::Ended, false)]
        );
        engine.events.set_handler(None);
    }

    /// Held responses for `POST /v1/calls`: the far end "answers" when the
    /// test opens the gate.
    #[derive(Clone, Default)]
    struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Gate {
        fn open(&self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }

        fn wait(&self) {
            let mut open = self.0 .0.lock().unwrap();
            while !*open {
                open = self.0 .1.wait(open).unwrap();
            }
        }
    }

    fn answer(call_token: &str) -> (u16, String) {
        (
            200,
            format!(r#"{{"call_token":"{call_token}","sdp_answer":""}}"#),
        )
    }

    /// `make_call` without a media session, which needs network access.
    fn dial(engine: &AriaMobileEngine) -> Result<CallInfo, MobileError> {
        dial_with_id(engine, new_outgoing_call_id())
    }

    /// `make_call_with_id` without a media session.
    fn dial_with_id(engine: &AriaMobileEngine, call_id: String) -> Result<CallInfo, MobileError> {
        runtime().block_on(
            engine.dial(call_id, "1002".into(), registration().sip, async {
                Ok((None, "v=0".to_string()))
            }),
        )
    }

    /// Run `dial` on its own thread, as an app does while it rings.
    fn dial_in_background(
        engine: &Arc<AriaMobileEngine>,
    ) -> std::sync::mpsc::Receiver<Result<CallInfo, MobileError>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let engine = Arc::clone(engine);
        std::thread::spawn(move || {
            let _ = tx.send(dial(&engine));
        });
        rx
    }

    fn count(gw: &MockGateway, path: &str) -> usize {
        gw.requests().iter().filter(|r| r.path == path).count()
    }

    #[test]
    fn without_a_cancel_route_a_ringing_hangup_hangs_up_once_answered() {
        let gate = Gate::default();
        let held = gate.clone();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                held.wait();
                answer("ct-1")
            }
            // A gateway that predates the cancel route.
            "/v1/calls/cancel" => (404, "{}".into()),
            // The token has expired by the time the call is answered.
            _ => (401, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);

        let ringing = recorder.wait_for(1);
        assert_eq!(ringing[0].state, CallState::Ringing);
        let call_id = ringing[0].call_id.clone();
        assert!(call_id.starts_with("outgoing-"));

        engine.hangup(call_id.clone()).unwrap();

        // make_call returns without waiting for the far end.
        let result = result.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(result, Err(MobileError::Cancelled)), "{result:?}");
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
        assert!(recorder.states().iter().all(|i| i.call_id == call_id));
        assert_eq!(count(&gw, "/v1/calls/ct-1/hangup"), 0);
        // The 404 is retried while POST /v1/calls is in flight.
        assert!(eventually(|| count(&gw, "/v1/calls/cancel") >= 1));

        // Once answered, the call is hung up at the gateway, and the 401 for
        // that background request asks the app for a token.
        gate.open();
        assert!(eventually(|| count(&gw, "/v1/calls/ct-1/hangup") == 1));
        assert!(eventually(|| recorder.auth_required() == 1));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count(&gw, "/v1/calls/ct-1/hangup"), 1);
        assert_eq!(recorder.states().len(), 2);
        assert!(engine.get_active_call().is_none());
        assert!(matches!(
            engine.hangup(call_id),
            Err(MobileError::InvalidState)
        ));
    }

    /// A gateway's view of one outgoing call: it rings until it is answered
    /// or cancelled, whichever comes first.
    #[derive(Clone, Default)]
    struct RingingCall(Arc<(Mutex<Option<bool>>, std::sync::Condvar)>);

    impl RingingCall {
        /// Ring for up to `ring`, then answer. Returns false if the call was
        /// cancelled first.
        fn answer_after(&self, ring: Duration) -> bool {
            let (state, cv) = &*self.0;
            let state = state.lock().unwrap();
            let (mut state, _) = cv.wait_timeout_while(state, ring, |s| s.is_none()).unwrap();
            *state.get_or_insert(true)
        }

        /// Cancel the call if it is still ringing.
        fn cancel(&self) -> bool {
            let (state, cv) = &*self.0;
            let mut state = state.lock().unwrap();
            if state.is_some() {
                return false;
            }
            *state = Some(false);
            cv.notify_all();
            true
        }
    }

    /// A gateway with the cancel route, ringing for `ring` before answering.
    fn cancelling_gateway(call_token: &str, ring: Duration) -> MockGateway {
        let call = RingingCall::default();
        let token = call_token.to_string();
        MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                if call.answer_after(ring) {
                    answer(&token)
                } else {
                    (409, r#"{"error":"cancelled"}"#.into())
                }
            }
            "/v1/calls/cancel" if call.cancel() => (202, "{}".into()),
            "/v1/calls/cancel" => (404, "{}".into()),
            p if p.ends_with("/status") => (200, r#"{"status":"active"}"#.into()),
            _ => (200, "{}".into()),
        })
    }

    #[test]
    fn hangup_while_ringing_cancels_at_the_gateway() {
        let gw = cancelling_gateway("ct-c", Duration::from_secs(30));
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);

        let call_id = recorder.wait_for(1)[0].call_id.clone();
        engine.hangup(call_id.clone()).unwrap();

        let result = result.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(result, Err(MobileError::Cancelled)), "{result:?}");
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
        assert_eq!(recorder.states()[1].end_reason, Some(EndReason::Cancelled));

        // The call was placed and cancelled by the uuid part of its call_id.
        let client_ref = call_id.strip_prefix("outgoing-").unwrap();
        assert!(eventually(|| count(&gw, "/v1/calls") == 1));
        let reqs = gw.requests();
        let placed = reqs.iter().find(|r| r.path == "/v1/calls").unwrap();
        let placed: serde_json::Value = serde_json::from_str(&placed.body).unwrap();
        assert_eq!(placed["client_ref"], client_ref);
        let cancel = reqs.iter().find(|r| r.path == "/v1/calls/cancel").unwrap();
        assert_eq!(cancel.body, format!(r#"{{"client_ref":"{client_ref}"}}"#));
        assert_eq!(cancel.authorization.as_deref(), Some("Bearer jwt"));

        // The 409 leaves nothing to hang up.
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count(&gw, "/v1/calls/ct-c/hangup"), 0);
        assert_eq!(recorder.states().len(), 2);
    }

    /// A cancel that reaches the gateway before it has registered the call's
    /// client_ref gets 404; it is retried until it lands, so the callee stops
    /// ringing instead of ringing until the INVITE times out.
    #[test]
    fn an_early_cancel_is_retried_until_the_gateway_knows_the_call() {
        let call = RingingCall::default();
        let received = Arc::new(AtomicBool::new(false));
        let registered = Arc::new(AtomicBool::new(false));
        let (seen, known) = (Arc::clone(&received), Arc::clone(&registered));
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                seen.store(true, Ordering::SeqCst);
                // The gateway takes a while to register the ref.
                std::thread::sleep(Duration::from_millis(300));
                known.store(true, Ordering::SeqCst);
                if call.answer_after(Duration::from_secs(30)) {
                    answer("ct-e")
                } else {
                    (409, r#"{"error":"cancelled"}"#.into())
                }
            }
            "/v1/calls/cancel" if known.load(Ordering::SeqCst) && call.cancel() => {
                (202, "{}".into())
            }
            "/v1/calls/cancel" => (404, "{}".into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);

        let call_id = recorder.wait_for(1)[0].call_id.clone();
        assert!(eventually(|| received.load(Ordering::SeqCst)));
        engine.hangup(call_id).unwrap();

        assert!(matches!(
            result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(MobileError::Cancelled)
        ));
        // At least one 404 before the ref was known, then a 202, then the
        // ringing POST /v1/calls is answered with 409.
        assert!(eventually(|| gw
            .requests()
            .iter()
            .any(|r| r.path == "/v1/calls" && r.status == 409)));
        let cancels: Vec<_> = gw
            .requests()
            .iter()
            .filter(|r| r.path == "/v1/calls/cancel")
            .map(|r| r.status)
            .collect();
        assert_eq!(cancels.last(), Some(&202), "{cancels:?}");
        assert!(cancels.len() >= 2, "{cancels:?}");
        assert_eq!(count(&gw, "/v1/calls/ct-e/hangup"), 0);
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
    }

    /// A cancel that keeps getting 404 stops once POST /v1/calls returns.
    #[test]
    fn cancel_retries_stop_when_the_call_is_answered() {
        let gate = Gate::default();
        let held = gate.clone();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                held.wait();
                answer("ct-s")
            }
            "/v1/calls/cancel" => (404, "{}".into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);
        let call_id = recorder.wait_for(1)[0].call_id.clone();
        std::thread::sleep(Duration::from_millis(50));
        engine.hangup(call_id).unwrap();
        result
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap_err();
        std::thread::sleep(Duration::from_millis(150));
        gate.open();

        // Answered: hung up once, and the cancels stop.
        assert!(eventually(|| count(&gw, "/v1/calls/ct-s/hangup") == 1));
        let cancels = count(&gw, "/v1/calls/cancel");
        std::thread::sleep(Duration::from_millis(1600));
        assert_eq!(count(&gw, "/v1/calls/cancel"), cancels);
        assert!(cancels <= 1 + CANCEL_RETRY_DELAYS.len());
    }

    /// The gateway ends a call whose answer crossed an accepted CANCEL, so
    /// the core must not hang it up a second time.
    #[test]
    fn an_answer_that_crosses_an_accepted_cancel_is_left_to_the_gateway() {
        let gate = Gate::default();
        let held = gate.clone();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                held.wait();
                answer("ct-x")
            }
            "/v1/calls/cancel" => (202, "{}".into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);

        let call_id = recorder.wait_for(1)[0].call_id.clone();
        engine.hangup(call_id).unwrap();
        assert!(matches!(
            result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(MobileError::Cancelled)
        ));

        gate.open();
        assert!(eventually(|| count(&gw, "/v1/calls") == 1));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count(&gw, "/v1/calls/ct-x/hangup"), 0);
        assert_eq!(recorder.states().len(), 2);
    }

    #[test]
    fn a_rejected_cancel_still_ends_the_call_and_hangs_up_on_answer() {
        let gate = Gate::default();
        let held = gate.clone();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                held.wait();
                answer("ct-r")
            }
            "/v1/calls/cancel" => (401, "{}".into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let result = dial_in_background(&engine);

        let call_id = recorder.wait_for(1)[0].call_id.clone();
        engine.hangup(call_id).unwrap();
        assert!(eventually(|| recorder.auth_required() == 1));
        assert!(matches!(
            result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(MobileError::Cancelled)
        ));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);

        gate.open();
        assert!(eventually(|| count(&gw, "/v1/calls/ct-r/hangup") == 1));
        assert_eq!(recorder.states().len(), 2);
    }

    #[test]
    fn hangup_from_the_ringing_callback_ends_the_call_once() {
        struct HangUpOnRinging {
            engine: Mutex<Option<Arc<AriaMobileEngine>>>,
            recorder: Recorder,
        }
        impl MobileEventHandler for HangUpOnRinging {
            fn on_registration_changed(&self, _: String, _: String, _: Option<String>) {}
            fn on_incoming_call(&self, _: CallOffer) {}
            fn on_call_state_changed(&self, info: CallInfo) {
                self.recorder.on_call_state_changed(info.clone());
                let engine = self.engine.lock().unwrap().clone();
                if let (CallState::Ringing, Some(engine)) = (info.state, engine) {
                    engine.hangup(info.call_id).unwrap();
                }
            }
            fn on_media_stats(&self, _: String, _: MediaStats) {}
            fn on_error(&self, _: String, _: String) {}
            fn on_auth_required(&self) {}
        }

        let gw = MockGateway::start(|_| answer("ct-2"));
        let (engine, _) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let recorder = Recorder::default();
        recorder.attach(&engine);
        engine.set_event_handler(Box::new(HangUpOnRinging {
            engine: Mutex::new(Some(Arc::clone(&engine))),
            recorder: recorder.clone(),
        }));

        // `Ringing` is delivered on the dispatch thread, so the hangup races
        // the dial; either way the call ends exactly once.
        let result = dial(&engine);
        assert!(
            matches!(result, Ok(_) | Err(MobileError::Cancelled)),
            "{result:?}"
        );
        assert!(eventually(|| recorder
            .states()
            .last()
            .is_some_and(|i| i.state == CallState::Ended)));
        std::thread::sleep(Duration::from_millis(100));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states.first(), Some(&CallState::Ringing));
        assert_eq!(
            states.iter().filter(|s| **s == CallState::Ended).count(),
            1,
            "{states:?}"
        );
        engine.events.set_handler(None);
    }

    #[test]
    fn a_failed_outgoing_call_reports_ended_and_the_error() {
        for (status, check) in [
            (
                502,
                (|e| matches!(e, MobileError::CallFailed(_))) as fn(&MobileError) -> bool,
            ),
            (401, |e| matches!(e, MobileError::AuthenticationError)),
        ] {
            let gw = MockGateway::start(move |_| (status, "{}".into()));
            let (engine, recorder) = engine(&gw.base_url);

            let err = dial(&engine).unwrap_err();

            assert!(check(&err), "HTTP {status} gave {err:?}");
            let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
            assert_eq!(
                states,
                [CallState::Ringing, CallState::Ended],
                "HTTP {status}"
            );
            let states = recorder.states();
            assert_eq!(states[0].end_reason, None, "Ringing has no reason");
            assert_eq!(states[1].end_reason, Some(EndReason::Failed));
            assert!(engine.pending_outgoing.lock().unwrap().ringing.is_empty());
        }
    }

    #[test]
    fn an_answered_call_connects_and_hangs_up_through_the_gateway() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/calls" => answer("ct-3"),
            "/v1/calls/ct-3/status" => (200, r#"{"status":"active"}"#.into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);

        let info = dial(&engine).unwrap();
        assert_eq!(info.state, CallState::Connected);
        assert!(engine.pending_outgoing.lock().unwrap().ringing.is_empty());
        engine.hangup(info.call_id.clone()).unwrap();

        assert!(eventually(|| count(&gw, "/v1/calls/ct-3/hangup") == 1));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(
            states,
            [CallState::Ringing, CallState::Connected, CallState::Ended]
        );
    }

    /// Hang up at a random moment around the answer, many times over. Whoever
    /// wins, the call gets exactly one `Ended`, nothing after it, and exactly
    /// one hangup at the gateway.
    #[test]
    fn hangup_racing_the_answer_ends_the_call_exactly_once() {
        use rand::Rng;

        // A cancel the gateway accepted; it then fails the call with 409.
        fn cancels_accepted(gw: &MockGateway) -> bool {
            gw.requests()
                .iter()
                .any(|r| r.path == "/v1/calls/cancel" && r.status == 202)
        }

        for round in 0..60 {
            let call_token = format!("ct-race-{round}");
            let hangup_path = format!("/v1/calls/{call_token}/hangup");
            let ring = Duration::from_micros(rand::rng().random_range(0..4000));
            let gw = cancelling_gateway(&call_token, ring);
            let (engine, recorder) = engine(&gw.base_url);
            let engine = Arc::new(engine);
            let result = dial_in_background(&engine);

            // Spin rather than `wait_for`, whose 10 ms step would let the
            // answer win almost every round.
            let deadline = Instant::now() + Duration::from_secs(5);
            while recorder.states().is_empty() && Instant::now() < deadline {
                std::thread::yield_now();
            }
            let call_id = recorder.states()[0].call_id.clone();
            std::thread::sleep(Duration::from_micros(rand::rng().random_range(0..4000)));
            engine.hangup(call_id.clone()).unwrap();

            let result = result.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(
                matches!(result, Ok(_) | Err(MobileError::Cancelled)),
                "round {round}: {result:?}"
            );

            // Exactly one of: a CANCEL the gateway accepted, or a hangup.
            let ended_at_gateway = || {
                gw.requests()
                    .iter()
                    .filter(|r| r.path == hangup_path)
                    .count()
                    + usize::from(cancels_accepted(&gw))
            };
            assert!(
                eventually(|| ended_at_gateway() == 1),
                "round {round}: the call was never ended at the gateway"
            );
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(ended_at_gateway(), 1, "round {round}");

            let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
            assert!(recorder.states().iter().all(|i| i.call_id == call_id));
            assert_eq!(states.first(), Some(&CallState::Ringing), "round {round}");
            assert_eq!(states.last(), Some(&CallState::Ended), "round {round}");
            assert_eq!(
                states.iter().filter(|s| **s == CallState::Ended).count(),
                1,
                "round {round}: {states:?}"
            );
            let connected = states.contains(&CallState::Connected);
            assert!(
                states.len() == 2 || (states.len() == 3 && connected),
                "round {round}: {states:?}"
            );
            if result.is_ok() {
                assert!(connected, "round {round}");
            }
            assert!(engine.get_active_call().is_none(), "round {round}");
            assert!(engine.pending_outgoing.lock().unwrap().ringing.is_empty());
        }
    }

    /// Every callback type, including those raised inside `block_on` and on
    /// the status-poll tasks, can call the blocking engine methods. They used
    /// to run inline inside the runtime, where `block_on` panics.
    #[test]
    fn engine_methods_work_from_every_callback() {
        #[derive(Default)]
        struct Reenter {
            engine: Mutex<Option<Arc<AriaMobileEngine>>>,
            /// Callback kind -> what each engine method returned.
            ran: Mutex<HashMap<&'static str, Vec<String>>>,
        }
        impl Reenter {
            fn battery(&self, kind: &'static str) {
                let Some(engine) = self.engine.lock().unwrap().clone() else {
                    return;
                };
                if self.ran.lock().unwrap().contains_key(kind) {
                    return;
                }
                let run = |f: &dyn Fn() -> String| {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
                        .unwrap_or_else(|_| "PANIC".to_string())
                };
                let results = vec![
                    run(&|| format!("{:?}", engine.hangup("c-none".into()).err())),
                    run(&|| {
                        format!(
                            "{:?}",
                            engine.accept_incoming_call("t".into(), vec![]).err()
                        )
                    }),
                    run(&|| format!("{:?}", engine.reject_incoming_call("t".into()).err())),
                    run(&|| {
                        format!(
                            "{:?}",
                            engine.transfer_call("c-none".into(), "1002".into()).err()
                        )
                    }),
                    run(&|| {
                        // Without a token make_call stops before opening media.
                        engine.set_gateway_token(String::new());
                        let r = engine.make_call("1002".into(), registration().sip, vec![]);
                        engine.set_gateway_token("jwt".into());
                        format!("{:?}", r.err())
                    }),
                ];
                self.ran.lock().unwrap().insert(kind, results);
            }
        }
        struct Handler(Arc<Reenter>);
        impl MobileEventHandler for Handler {
            fn on_registration_changed(&self, _: String, _: String, _: Option<String>) {
                self.0.battery("registration");
            }
            fn on_incoming_call(&self, _: CallOffer) {
                self.0.battery("incoming");
            }
            fn on_call_state_changed(&self, info: CallInfo) {
                match info.state {
                    CallState::Connected => self.0.battery("connected"),
                    CallState::Ended => self.0.battery("ended-by-poll"),
                    _ => {}
                }
            }
            fn on_media_stats(&self, _: String, _: MediaStats) {}
            fn on_error(&self, _: String, _: String) {}
            fn on_auth_required(&self) {
                self.0.battery("auth-required-by-poll");
            }
        }

        let gw = MockGateway::start(|req| {
            match req.path.as_str() {
            "/v1/devices" => (200, r#"{"device_id":"d1","status":"ok"}"#.into()),
            "/v1/calls/tok-in" => (
                200,
                r#"{"call_token":"tok-in","caller_uri":"sip:a@b","caller_name":null,"sdp_offer":""}"#
                    .into(),
            ),
            "/v1/calls/tok-in/status" => (200, r#"{"status":"pending"}"#.into()),
            "/v1/calls" => answer("ct-r"),
            "/v1/calls/ct-r/status" => (200, r#"{"status":"ended"}"#.into()),
            _ => (401, "{}".into()),
        }
        });
        let (engine, _) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let reenter = Arc::new(Reenter::default());
        *reenter.engine.lock().unwrap() = Some(Arc::clone(&engine));
        engine.set_event_handler(Box::new(Handler(Arc::clone(&reenter))));

        engine.register_device(registration()).unwrap();
        engine
            .handle_push_notification(PushCallPayload {
                call_token: "tok-in".into(),
                caller_uri: "sip:a@b".into(),
                caller_name: None,
                gateway_url: gw.base_url.clone(),
            })
            .unwrap();
        dial(&engine).unwrap();
        // Let the poll end that call first, so the call below is the only
        // one up and the accept in its callback is not refused by the
        // two-call limit before it reaches the gateway.
        assert!(eventually(|| engine.get_calls().is_empty()));
        let stop = insert_call(&engine, "c-401", "tok-401");
        engine.start_call_status_poll(
            "c-401".into(),
            "tok-401".into(),
            engine.gateway.primary_route(),
            Arc::clone(&stop),
        );

        let kinds = [
            "registration",
            "incoming",
            "connected",
            "ended-by-poll",
            "auth-required-by-poll",
        ];
        assert!(
            eventually(|| kinds
                .iter()
                .all(|k| reenter.ran.lock().unwrap().contains_key(k))),
            "ran: {:?}",
            reenter.ran.lock().unwrap().keys().collect::<Vec<_>>()
        );
        for (kind, results) in reenter.ran.lock().unwrap().iter() {
            assert!(!results.iter().any(|r| r == "PANIC"), "{kind}: {results:?}");
            // Each method reached its own logic: the unknown call is refused
            // locally, the rest are refused by the gateway or for no token.
            assert_eq!(
                results,
                &[
                    "Some(InvalidState)",
                    "Some(AuthenticationError)",
                    "Some(AuthenticationError)",
                    "Some(InvalidState)",
                    "Some(AuthenticationError)",
                ],
                "{kind}"
            );
        }
        stop.store(true, Ordering::Relaxed);
        engine.clear_pending_incoming("tok-in");
        *reenter.engine.lock().unwrap() = None;
        engine.events.set_handler(None);
    }

    /// Concurrent mute/hold changes are delivered in the order they were
    /// applied, so the last event always matches the call's final state.
    #[test]
    fn concurrent_mute_and_hold_deliver_the_final_state_last() {
        let (engine, recorder) = engine(NO_GATEWAY);
        let engine = Arc::new(engine);
        insert_call(&engine, "c1", "tok");
        for round in 0..30 {
            let threads: Vec<_> = (0..4)
                .map(|t| {
                    let engine = Arc::clone(&engine);
                    std::thread::spawn(move || {
                        for i in 0..50 {
                            let on = (i + t + round) % 2 == 0;
                            if t % 2 == 0 {
                                engine.set_hold("c1".into(), on).unwrap();
                            } else {
                                engine.set_mute("c1".into(), on).unwrap();
                            }
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
            let last = recorder.states().last().cloned().unwrap();
            let current = engine.get_active_call().unwrap();
            assert_eq!(
                (last.on_hold, last.muted, last.state),
                (current.on_hold, current.muted, current.state),
                "round {round}"
            );
        }
    }

    /// Everything about a call goes to the gateway instance that placed it,
    /// not to the primary route.
    #[test]
    fn an_outgoing_call_stays_on_the_instance_that_placed_it() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/calls" => answer("ct-pin"),
            "/v1/calls/ct-pin/status" => (200, r#"{"status":"active"}"#.into()),
            _ => (200, "{}".into()),
        });
        // Neither the base URL nor the primary route accepts connections, so
        // the call can only work on the second route.
        let (engine, _) = engine(NO_GATEWAY);
        engine
            .gateway
            .set_test_routes(&[NO_GATEWAY, gw.base_url.as_str()]);

        let info = dial(&engine).unwrap();
        assert!(eventually(|| count(&gw, "/v1/calls/ct-pin/status") >= 2));
        engine.hangup(info.call_id).unwrap();

        assert!(eventually(|| count(&gw, "/v1/calls/ct-pin/hangup") == 1));
    }

    #[test]
    fn an_incoming_call_stays_on_the_instance_that_offered_it() {
        let gw = MockGateway::start(|req| {
            match req.path.as_str() {
            "/v1/calls/tok-pin" => (
                200,
                r#"{"call_token":"tok-pin","caller_uri":"sip:a@b","caller_name":null,"sdp_offer":""}"#
                    .into(),
            ),
            "/v1/calls/tok-pin/status" => (200, r#"{"status":"pending"}"#.into()),
            _ => (200, "{}".into()),
        }
        });
        let (engine, _) = engine(NO_GATEWAY);
        engine
            .gateway
            .set_test_routes(&[NO_GATEWAY, gw.base_url.as_str()]);

        engine
            .handle_push_notification(PushCallPayload {
                call_token: "tok-pin".into(),
                caller_uri: "sip:a@b".into(),
                caller_name: None,
                gateway_url: gw.base_url.clone(),
            })
            .unwrap();
        assert!(eventually(|| count(&gw, "/v1/calls/tok-pin/status") >= 2));
        engine.reject_incoming_call("tok-pin".into()).unwrap();
        assert_eq!(count(&gw, "/v1/calls/tok-pin/reject"), 1);
    }

    /// A second call goes to the gateway instance holding the first, even
    /// when another instance comes first in the SRV order, so the two can
    /// be joined by an attended transfer.
    #[test]
    fn a_call_placed_while_another_is_up_uses_the_same_gateway() {
        let first = call_waiting_gateway();
        let held = call_waiting_gateway();
        let (engine, _) = engine(&first.base_url);
        engine
            .gateway
            .set_test_routes(&[first.base_url.as_str(), held.base_url.as_str()]);
        let held_route = engine.gateway.routes()[1].clone();
        insert_call_on(
            &engine,
            "incoming-tok-1",
            "tok-1",
            CallDirection::Inbound,
            held_route,
        );

        let out = dial(&engine).unwrap();

        assert_eq!(count(&held, "/v1/calls"), 1);
        assert_eq!(count(&first, "/v1/calls"), 0);
        assert_eq!(
            engine.calls.lock().unwrap()[&out.call_id].route.base_url(),
            held.base_url
        );
    }

    /// If the instance holding the other call cannot be reached, the new
    /// call fails rather than going to another instance.
    #[test]
    fn a_call_pinned_to_an_unreachable_gateway_fails_without_failover() {
        let other = call_waiting_gateway();
        let (engine, recorder) = engine(&other.base_url);
        engine
            .gateway
            .set_test_routes(&[NO_GATEWAY, other.base_url.as_str()]);
        let dead_route = engine.gateway.routes()[0].clone();
        insert_call_on(
            &engine,
            "incoming-tok-1",
            "tok-1",
            CallDirection::Inbound,
            dead_route,
        );

        let err = dial(&engine).unwrap_err();

        assert!(matches!(err, MobileError::NetworkError), "{err:?}");
        assert_eq!(count(&other, "/v1/calls"), 0);
        let ended: Vec<_> = recorder
            .states()
            .into_iter()
            .filter(|i| i.state == CallState::Ended)
            .collect();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].end_reason, Some(EndReason::Failed));
        assert_eq!(ids(&engine.get_calls()), ["incoming-tok-1"]);
    }

    /// With no other call, a call still fails over between instances.
    #[test]
    fn a_lone_call_still_fails_over() {
        let gw = call_waiting_gateway();
        let (engine, _) = engine(&gw.base_url);
        engine
            .gateway
            .set_test_routes(&[NO_GATEWAY, gw.base_url.as_str()]);

        dial(&engine).unwrap();

        assert_eq!(count(&gw, "/v1/calls"), 1);
    }

    /// `make_call_with_id` with an offer (media setup) that takes `setup`.
    fn dial_slowly(
        engine: &AriaMobileEngine,
        call_id: String,
        setup: Duration,
    ) -> Result<CallInfo, MobileError> {
        runtime().block_on(
            engine.dial(call_id, "1002".into(), registration().sip, async move {
                tokio::time::sleep(setup).await;
                Ok((None, "v=0".to_string()))
            }),
        )
    }

    fn ended_count(recorder: &Recorder, call_id: &str) -> usize {
        recorder
            .states()
            .iter()
            .filter(|i| i.call_id == call_id && i.state == CallState::Ended)
            .count()
    }

    #[test]
    fn outgoing_ids_are_validated() {
        let gw = MockGateway::start(|_| answer("ct-v"));
        let (engine, _) = engine(&gw.base_url);
        for bad in [
            "",
            "incoming-x",
            "outgoing-",
            "outgoing-a b",
            "outgoing-a/b",
        ] {
            assert!(
                matches!(
                    dial_with_id(&engine, bad.into()),
                    Err(MobileError::InvalidState)
                ),
                "{bad:?}"
            );
        }
        let long = format!("outgoing-{}", "a".repeat(65));
        assert!(matches!(
            dial_with_id(&engine, long),
            Err(MobileError::InvalidState)
        ));
        assert!(gw.requests().is_empty());

        let id = new_outgoing_call_id();
        assert!(outgoing_client_ref(&id).is_some());
        dial_with_id(&engine, id.clone()).unwrap();
        // In use, and later already used: both refused.
        assert!(matches!(
            dial_with_id(&engine, id.clone()),
            Err(MobileError::InvalidState)
        ));
        engine.hangup(id.clone()).unwrap();
        assert!(matches!(
            dial_with_id(&engine, id.clone()),
            Err(MobileError::InvalidState)
        ));
        assert!(matches!(engine.hangup(id), Err(MobileError::InvalidState)));
    }

    /// A hangup while media is being set up (STUN can take a long time)
    /// returns from make_call at once, without dialing.
    #[test]
    fn hangup_during_media_setup_returns_at_once() {
        let gw = MockGateway::start(|_| answer("ct-m"));
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let id = new_outgoing_call_id();
        let (tx, result) = std::sync::mpsc::channel();
        let (e, i) = (Arc::clone(&engine), id.clone());
        std::thread::spawn(move || {
            let r = runtime().block_on(e.dial(
                i,
                "1002".into(),
                registration().sip,
                // An offer that never finishes, like STUN that never answers.
                std::future::pending(),
            ));
            let _ = tx.send(r);
        });

        assert_eq!(recorder.wait_for(1)[0].state, CallState::Ringing);
        let started = Instant::now();
        engine.hangup(id).unwrap();
        let r = result.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(matches!(r, Err(MobileError::Cancelled)), "{r:?}");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
        assert!(gw.requests().is_empty());
    }

    /// STUN that never answers is cut off at the budget, and the SDP gets the
    /// local interface address instead.
    #[test]
    fn stun_that_never_answers_falls_back_to_the_interface_address() {
        let started = Instant::now();
        let ip = runtime().block_on(media::advertised_ip(
            std::future::pending(),
            Duration::from_millis(100),
        ));
        assert!(started.elapsed() < Duration::from_millis(1000));
        assert!(ip.parse::<std::net::IpAddr>().is_ok(), "{ip}");

        // A failed STUN falls back too, and a working one wins.
        let ip = runtime().block_on(media::advertised_ip(
            async { None },
            Duration::from_millis(100),
        ));
        assert!(ip.parse::<std::net::IpAddr>().is_ok(), "{ip}");
        let ip = runtime().block_on(media::advertised_ip(
            async { Some("203.0.113.7".to_string()) },
            Duration::from_millis(100),
        ));
        assert_eq!(ip, "203.0.113.7");
        assert!(media::STUN_BUDGET <= Duration::from_secs(4));
    }

    #[test]
    fn hangup_before_make_call_means_it_is_never_dialed() {
        let gw = MockGateway::start(|_| answer("ct-b"));
        let (engine, recorder) = engine(&gw.base_url);
        let id = new_outgoing_call_id();

        engine.hangup(id.clone()).unwrap();
        let states = recorder.states();
        assert_eq!(states.len(), 1);
        assert_eq!(
            (states[0].call_id.as_str(), states[0].state),
            (id.as_str(), CallState::Ended)
        );
        assert_eq!(states[0].end_reason, Some(EndReason::Cancelled));

        assert!(matches!(
            dial_with_id(&engine, id.clone()),
            Err(MobileError::Cancelled)
        ));
        // Only once; the id is used up after that.
        assert!(matches!(
            dial_with_id(&engine, id.clone()),
            Err(MobileError::InvalidState)
        ));
        assert!(matches!(
            engine.hangup(id.clone()),
            Err(MobileError::InvalidState)
        ));

        std::thread::sleep(Duration::from_millis(100));
        assert!(gw.requests().is_empty());
        assert_eq!(recorder.states().len(), 1);
    }

    #[test]
    fn hangup_during_the_post_cancels_with_one_ended() {
        let received = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&received);
        let call = RingingCall::default();
        let gw = MockGateway::start(move |req| match req.path.as_str() {
            "/v1/calls" => {
                seen.store(true, Ordering::SeqCst);
                if call.answer_after(Duration::from_secs(30)) {
                    answer("ct-p")
                } else {
                    (409, r#"{"error":"cancelled"}"#.into())
                }
            }
            "/v1/calls/cancel" if call.cancel() => (202, "{}".into()),
            "/v1/calls/cancel" => (404, "{}".into()),
            _ => (200, "{}".into()),
        });
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let id = new_outgoing_call_id();
        let (tx, result) = std::sync::mpsc::channel();
        let (e, i) = (Arc::clone(&engine), id.clone());
        std::thread::spawn(move || {
            let _ = tx.send(dial_with_id(&e, i));
        });

        assert!(eventually(|| received.load(Ordering::SeqCst)));
        engine.hangup(id.clone()).unwrap();

        assert!(matches!(
            result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(MobileError::Cancelled)
        ));
        assert!(eventually(|| count(&gw, "/v1/calls") == 1));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
        assert_eq!(ended_count(&recorder, &id), 1);
    }

    #[test]
    fn hangup_after_ringing_with_a_chosen_id_cancels_with_one_ended() {
        let gw = cancelling_gateway("ct-a", Duration::from_secs(30));
        let (engine, recorder) = engine(&gw.base_url);
        let engine = Arc::new(engine);
        let id = new_outgoing_call_id();
        let (tx, result) = std::sync::mpsc::channel();
        let (e, i) = (Arc::clone(&engine), id.clone());
        std::thread::spawn(move || {
            let _ = tx.send(dial_slowly(&e, i, Duration::from_millis(50)));
        });

        assert_eq!(recorder.wait_for(1)[0].call_id, id);
        engine.hangup(id.clone()).unwrap();

        assert!(matches!(
            result.recv_timeout(Duration::from_secs(5)).unwrap(),
            Err(MobileError::Cancelled)
        ));
        std::thread::sleep(Duration::from_millis(100));
        let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
        assert_eq!(states, [CallState::Ringing, CallState::Ended]);
    }

    /// Hang up at a random point from before make_call_with_id until after
    /// the answer. Every round gets exactly one Ended, nothing after it, and
    /// at most one cancel or hangup at the gateway (none when it never
    /// dialed).
    #[test]
    fn hangup_at_any_point_ends_a_chosen_id_exactly_once() {
        use rand::Rng;

        for round in 0..60 {
            let mut rng = rand::rng();
            let ring = Duration::from_micros(rng.random_range(0..4000));
            let start = Duration::from_micros(rng.random_range(0..3000));
            let setup = Duration::from_micros(rng.random_range(0..3000));
            let hang = Duration::from_micros(rng.random_range(0..12000));
            let call_token = format!("ct-any-{round}");
            let gw = cancelling_gateway(&call_token, ring);
            let (engine, recorder) = engine(&gw.base_url);
            let engine = Arc::new(engine);
            let id = new_outgoing_call_id();

            let (tx, result) = std::sync::mpsc::channel();
            let (e, i) = (Arc::clone(&engine), id.clone());
            std::thread::spawn(move || {
                std::thread::sleep(start);
                let _ = tx.send(dial_slowly(&e, i, setup));
            });
            std::thread::sleep(hang);
            engine.hangup(id.clone()).unwrap();

            let result = result.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(
                matches!(result, Ok(_) | Err(MobileError::Cancelled)),
                "round {round}: {result:?}"
            );
            assert!(
                eventually(|| ended_count(&recorder, &id) == 1),
                "round {round}"
            );

            // Let the ringing POST (at most a few ms, or a 409) and any
            // background cancel or hangup finish.
            std::thread::sleep(Duration::from_millis(150));
            let ended_at_gateway = || {
                gw.requests()
                    .iter()
                    .filter(|r| {
                        r.path == format!("/v1/calls/{call_token}/hangup")
                            || (r.path == "/v1/calls/cancel" && r.status == 202)
                    })
                    .count()
            };
            if gw.requests().iter().any(|r| r.path == "/v1/calls") {
                assert!(
                    eventually(|| ended_at_gateway() == 1),
                    "round {round}: the dialed call was not ended at the gateway"
                );
            } else {
                assert_eq!(ended_at_gateway(), 0, "round {round}");
                assert!(gw.requests().is_empty(), "round {round}");
            }
            let states: Vec<_> = recorder.states().iter().map(|i| i.state).collect();
            assert_eq!(ended_count(&recorder, &id), 1, "round {round}: {states:?}");
            assert_eq!(states.last(), Some(&CallState::Ended), "round {round}");
            if result.is_ok() {
                assert!(states.contains(&CallState::Connected), "round {round}");
            }
            assert!(engine.get_active_call().is_none(), "round {round}");
            assert!(engine.pending_outgoing.lock().unwrap().ringing.is_empty());
        }
    }

    /// A burst of network changes sends at most one heartbeat at a time,
    /// plus one more for the changes during it, not one per change.
    #[test]
    fn network_change_heartbeats_are_coalesced() {
        let gw = MockGateway::start(|req| match req.path.as_str() {
            "/v1/devices" => (200, r#"{"device_id":"d1","status":"ok"}"#.into()),
            _ => {
                std::thread::sleep(Duration::from_millis(200));
                (200, "{}".into())
            }
        });
        let (engine, _) = engine(&gw.base_url);
        engine.register_device(registration()).unwrap();

        for _ in 0..50 {
            engine.notify_network_change();
        }
        assert!(eventually(|| !engine.heartbeat.lock().unwrap().running));
        let sent = count(&gw, "/v1/devices/d1/heartbeat");
        assert!((1..=2).contains(&sent), "{sent} heartbeats for one burst");

        // A later change sends a fresh one.
        engine.notify_network_change();
        assert!(eventually(
            || count(&gw, "/v1/devices/d1/heartbeat") == sent + 1
        ));
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

        end_call_locally(&engine.calls, &engine.events, "c1", EndReason::LocalHangup);
        engine.events.flush();

        assert!(fired.load(Ordering::Relaxed));
        // Break the Arc cycle (engine -> handler -> engine).
        engine.events.set_handler(None);
    }

    // ── Call waiting ────────────────────────────────────────────────

    /// A gateway on which every call is up and every request succeeds, and
    /// an outgoing call is answered with `ct-out`.
    fn call_waiting_gateway() -> MockGateway {
        MockGateway::start(|req| match req.path.as_str() {
            "/v1/calls" => answer("ct-out"),
            p if p.ends_with("/status") => (200, r#"{"status":"active"}"#.into()),
            _ => (200, "{}".into()),
        })
    }

    /// (call_id, state, on_hold) of each call-state event, in order.
    fn holds(recorder: &Recorder) -> Vec<(String, CallState, bool)> {
        recorder
            .states()
            .into_iter()
            .map(|i| (i.call_id, i.state, i.on_hold))
            .collect()
    }

    fn ids(calls: &[CallInfo]) -> Vec<&str> {
        calls.iter().map(|c| c.call_id.as_str()).collect()
    }

    #[test]
    fn two_calls_can_be_up_at_once() {
        let gw = call_waiting_gateway();
        let (engine, _recorder) = engine(&gw.base_url);
        answer_here(&engine, "tok-1").unwrap();
        let out = dial(&engine).unwrap();

        let calls = engine.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls.contains_key("incoming-tok-1"));
        assert!(calls.contains_key(&out.call_id));
    }

    #[test]
    fn an_answered_outgoing_call_holds_the_connected_one_first() {
        let gw = call_waiting_gateway();
        let (engine, recorder) = engine(&gw.base_url);
        answer_here(&engine, "tok-1").unwrap();
        let out = dial(&engine).unwrap();
        assert!(!out.on_hold);

        assert_eq!(
            holds(&recorder),
            [
                ("incoming-tok-1".to_string(), CallState::Connected, false),
                (out.call_id.clone(), CallState::Ringing, false),
                ("incoming-tok-1".to_string(), CallState::OnHold, true),
                (out.call_id.clone(), CallState::Connected, false),
            ]
        );
        assert_eq!(engine.get_active_call().unwrap().call_id, out.call_id);
    }

    #[test]
    fn an_accepted_call_holds_the_connected_one_first() {
        let gw = call_waiting_gateway();
        let (engine, recorder) = engine(&gw.base_url);
        let out = dial(&engine).unwrap();
        answer_here(&engine, "tok-2").unwrap();

        assert_eq!(
            holds(&recorder)[2..],
            [
                (out.call_id.clone(), CallState::OnHold, true),
                ("incoming-tok-2".to_string(), CallState::Connected, false),
            ]
        );
        let calls = engine.get_calls();
        assert_eq!(ids(&calls), [out.call_id.as_str(), "incoming-tok-2"]);
        assert!(calls[0].on_hold && !calls[1].on_hold);
        assert_eq!(engine.get_active_call().unwrap().call_id, "incoming-tok-2");
    }

    #[test]
    fn an_accept_of_a_call_that_already_ended_holds_nothing() {
        let gw = call_waiting_gateway();
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok-c1");
        // The offer is reported ended (the caller hung up) as it is answered.
        let entry_events =
            engine.watch_incoming(&offer("tok-x"), engine.gateway.primary_route(), false);
        let info = engine.pending_incoming.lock().unwrap()["tok-x"]
            .info
            .clone();
        entry_events.emit_ended(&engine.events, &info, EndReason::CallerCancelled);

        assert!(matches!(
            answer_here(&engine, "tok-x"),
            Err(MobileError::InvalidState)
        ));
        assert!(!engine.calls.lock().unwrap()["c1"].info.on_hold);
        assert_eq!(holds(&recorder).len(), 1, "only the offer's Ended");
    }

    #[test]
    fn get_calls_lists_live_calls_oldest_first() {
        let (engine, _recorder) = engine(NO_GATEWAY);
        assert!(engine.get_calls().is_empty());
        assert!(engine.get_active_call().is_none());

        insert_call(&engine, "c1", "tok-1");
        let ringing = "outgoing-ringing".to_string();
        engine.reserve_outgoing(&ringing, "1003").unwrap();
        assert_eq!(ids(&engine.get_calls()), ["c1", ringing.as_str()]);
        // The un-held connected call wins over a newer ringing one...
        assert_eq!(engine.get_active_call().unwrap().call_id, "c1");
        // ...and with every connected call held, the newest live call.
        engine.set_hold("c1".into(), true).unwrap();
        assert_eq!(engine.get_active_call().unwrap().call_id, ringing);

        // Order is by creation, not by map order or id.
        let (engine, _recorder) = self::engine(NO_GATEWAY);
        for id in ["z", "a", "m"] {
            insert_call(&engine, id, id);
        }
        engine.calls.lock().unwrap().remove("a");
        insert_call(&engine, "a", "a");
        assert_eq!(ids(&engine.get_calls()), ["z", "m", "a"]);
    }

    #[test]
    fn a_third_call_is_refused_without_side_effects() {
        let gw = call_waiting_gateway();
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok-1");
        insert_call(&engine, "c2", "tok-2");
        let before = gw.requests().len();

        let id = new_outgoing_call_id();
        assert!(matches!(
            dial_with_id(&engine, id.clone()),
            Err(MobileError::InvalidState)
        ));
        assert!(matches!(
            engine.accept_incoming_call("tok-3".into(), vec![]),
            Err(MobileError::InvalidState)
        ));
        assert_eq!(gw.requests().len(), before, "nothing sent");
        assert!(recorder.states().is_empty(), "nothing reported");
        assert!(engine.accepting.lock().unwrap().is_empty());
        assert_eq!(engine.get_calls().len(), 2);

        // The refused id was not used up: once a call ends it can be dialed.
        engine.hangup("c2".into()).unwrap();
        assert_eq!(
            dial_with_id(&engine, id).unwrap().state,
            CallState::Connected
        );
    }

    #[test]
    fn ringing_and_accepting_calls_count_against_the_cap() {
        let (engine, _recorder) = engine(NO_GATEWAY);
        insert_call(&engine, "c1", "tok-1");
        engine.reserve_outgoing("outgoing-ring", "1003").unwrap();
        assert!(matches!(
            engine.reserve_accept("tok-3"),
            Err(MobileError::InvalidState)
        ));
        assert!(matches!(
            engine.reserve_outgoing("outgoing-third", "1004"),
            Err(MobileError::InvalidState)
        ));

        let (engine, _recorder) = self::engine(NO_GATEWAY);
        insert_call(&engine, "c1", "tok-1");
        let reservation = engine.reserve_accept("tok-2").unwrap();
        // The same call cannot be accepted twice at once.
        assert!(engine.reserve_accept("tok-2").is_err());
        assert!(matches!(
            engine.reserve_outgoing("outgoing-third", "1004"),
            Err(MobileError::InvalidState)
        ));
        // A failed accept gives its slot back.
        drop(reservation);
        assert!(engine.reserve_outgoing("outgoing-third", "1004").is_ok());
    }

    #[test]
    fn a_third_call_can_still_be_offered() {
        let gw = MockGateway::start(|req| {
            match req.path.as_str() {
            "/v1/calls/tok-3" => (
                200,
                r#"{"call_token":"tok-3","caller_uri":"sip:1003@pbx","caller_name":null,"sdp_offer":"v=0"}"#
                    .into(),
            ),
            _ => (200, r#"{"status":"pending"}"#.into()),
        }
        });
        let (engine, _recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok-1");
        insert_call(&engine, "c2", "tok-2");
        let offer = engine
            .handle_push_notification(PushCallPayload {
                call_token: "tok-3".into(),
                caller_uri: "sip:1003@pbx".into(),
                caller_name: None,
                gateway_url: gw.base_url.clone(),
            })
            .unwrap();
        assert_eq!(offer.call_token, "tok-3");
        engine.clear_pending_incoming("tok-3");
    }

    #[test]
    fn resuming_a_call_holds_the_other_first() {
        let (engine, recorder) = engine(NO_GATEWAY);
        insert_call(&engine, "c1", "tok-1");
        insert_call(&engine, "c2", "tok-2");
        engine.set_hold("c1".into(), true).unwrap();
        engine.set_hold("c1".into(), false).unwrap();

        assert_eq!(
            holds(&recorder),
            [
                ("c1".to_string(), CallState::OnHold, true),
                ("c2".to_string(), CallState::OnHold, true),
                ("c1".to_string(), CallState::Connected, false),
            ]
        );
        // A call that is already held is not reported again.
        engine.set_hold("c1".into(), false).unwrap();
        assert_eq!(holds(&recorder).len(), 4);
        assert_eq!(engine.get_active_call().unwrap().call_id, "c1");
    }

    #[test]
    fn swap_holds_one_call_and_resumes_the_other() {
        let gw = call_waiting_gateway();
        let (engine, recorder) = engine(&gw.base_url);
        insert_call(&engine, "c1", "tok-1");
        insert_call(&engine, "c2", "tok-2");
        engine.set_hold("c1".into(), true).unwrap();
        let skip = holds(&recorder).len();

        engine.swap_calls("c2".into(), "c1".into()).unwrap();
        assert_eq!(
            holds(&recorder)[skip..],
            [
                ("c2".to_string(), CallState::OnHold, true),
                ("c1".to_string(), CallState::Connected, false),
            ]
        );
        let calls = engine.get_calls();
        assert!(!calls[0].on_hold && calls[1].on_hold);
        assert_eq!(engine.get_active_call().unwrap().call_id, "c1");

        for (a, b) in [("c1", "c1"), ("c1", "nope"), ("nope", "c1")] {
            assert!(matches!(
                engine.swap_calls(a.into(), b.into()),
                Err(MobileError::InvalidState)
            ));
        }
        assert_eq!(
            holds(&recorder).len(),
            skip + 2,
            "a refused swap reports nothing"
        );

        // Both hang up cleanly, with one Ended each.
        engine.hangup("c1".into()).unwrap();
        engine.hangup("c2".into()).unwrap();
        assert_eq!(ended_count(&recorder, "c1"), 1);
        assert_eq!(ended_count(&recorder, "c2"), 1);
        assert!(engine.get_calls().is_empty());
    }
}
