//! Where the device is registered, and keeping it registered.
//!
//! A gateway instance only pushes, and only places calls for, devices
//! registered on it, and instances share nothing. So the device is
//! registered on exactly one instance at a time, the one [`Registrar`]
//! tracks (`GatewayClient::registered_route`):
//!
//! - **Failover.** When that instance cannot be connected to (a heartbeat
//!   after a network change, or a new call), the device is registered on the
//!   next instance in SRV order and everything new goes there.
//! - **Failback.** While the device is on a lower-priority instance, the
//!   preferred one (the first SRV target) is probed with `GET /health`,
//!   after 30 s, then 60 s, ... up to 5 min, each ±20 %. Once it answers and
//!   no call is live, the device registers there again and the registration
//!   on the instance it leaves is removed. A live call is never moved: it
//!   stays on the instance that holds it until it ends.
//! - **Network change.** [`Registrar::recover`] re-resolves the gateway SRV
//!   name, then heartbeats the registered instance, re-registering if the
//!   instance no longer knows the device or cannot be reached, and reports
//!   each step through `on_registration_changed`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use crate::auth::GatewayAuth;
use crate::events::Dispatcher;
use crate::gateway_client::{GatewayClient, HeartbeatOutcome, Route};
use crate::types::{DeviceRegistration, DeviceRegistrationResponse, MobileError};

/// `on_registration_changed` statuses.
pub(crate) mod status {
    /// Registered on a gateway instance (also after a move or failback,
    /// with the new `device_id`).
    pub const REGISTERED: &str = "registered";
    /// After `unregister_device`.
    pub const UNREGISTERED: &str = "unregistered";
    /// A network change is being recovered from.
    pub const RECOVERING: &str = "recovering";
    /// Recovery failed; `error` says why. Calls cannot be received until a
    /// later network change or `register_device` succeeds.
    pub const FAILED: &str = "failed";
    /// The gateway refused the token: `on_auth_required` has fired, and
    /// recovery runs again by itself once `set_gateway_token` is called.
    pub const AUTH_REQUIRED: &str = "auth_required";
}

/// Failback probe timing.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailbackTiming {
    pub first: Duration,
    pub max: Duration,
}

impl Default for FailbackTiming {
    fn default() -> Self {
        Self {
            first: Duration::from_secs(30),
            max: Duration::from_secs(300),
        }
    }
}

/// Keepalive and retry timing of the supervisor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SupervisorTiming {
    /// Between heartbeats while all is well.
    pub keepalive: Duration,
    /// First retry after a failure; doubles up to `max`.
    pub first: Duration,
    pub max: Duration,
}

impl Default for SupervisorTiming {
    fn default() -> Self {
        Self {
            keepalive: Duration::from_secs(300),
            first: Duration::from_secs(5),
            max: Duration::from_secs(300),
        }
    }
}

impl SupervisorTiming {
    /// The wait before the next attempt after `failures` failures in a row.
    fn delay(&self, failures: u32) -> Duration {
        if failures == 0 {
            return self.keepalive;
        }
        let exp = self.first.saturating_mul(1u32 << (failures - 1).min(16));
        exp.min(self.max)
    }
}

/// `d` scaled by a random factor in 0.8..1.2.
fn jittered(d: Duration) -> Duration {
    d.mul_f64(0.8 + 0.4 * rand::random::<f64>())
}

pub(crate) struct Registrar {
    pub gateway: Arc<GatewayClient>,
    pub auth: Arc<GatewayAuth>,
    pub events: Arc<Dispatcher>,
    pub device_id: Arc<RwLock<Option<String>>>,
    pub last: Arc<RwLock<Option<DeviceRegistration>>>,
    /// A failback task is running.
    failback_running: AtomicBool,
    pub failback_timing: RwLock<FailbackTiming>,
    /// The last recovery stopped at a 401; `set_gateway_token` resumes it.
    pub auth_blocked: AtomicBool,
    /// Whether a call is live (set by the engine); a registration never
    /// moves then.
    busy: RwLock<Option<Busy>>,
    me: Weak<Registrar>,
    pub supervisor_timing: RwLock<SupervisorTiming>,
    supervisor_running: AtomicBool,
    /// Failed attempts in a row since the last good heartbeat.
    failures: AtomicU32,
    /// `failed` or `recovering` was reported and `registered` has not been
    /// since: the next success is reported too.
    degraded: AtomicBool,
    /// Wakes the supervisor when a recovery fails, so it retries on the
    /// backoff, not at the next keepalive.
    wake: Arc<tokio::sync::Notify>,
    /// One recovery at a time, whoever asks (network change, keepalive).
    gate: tokio::sync::Mutex<()>,
}

type Busy = Arc<dyn Fn() -> bool + Send + Sync>;

impl Registrar {
    pub fn new(
        gateway: Arc<GatewayClient>,
        auth: Arc<GatewayAuth>,
        events: Arc<Dispatcher>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            busy: RwLock::new(None),
            me: me.clone(),
            gateway,
            auth,
            events,
            device_id: Arc::default(),
            last: Arc::default(),
            failback_running: AtomicBool::new(false),
            failback_timing: RwLock::new(FailbackTiming::default()),
            auth_blocked: AtomicBool::new(false),
            supervisor_timing: RwLock::new(SupervisorTiming::default()),
            supervisor_running: AtomicBool::new(false),
            failures: AtomicU32::new(0),
            degraded: AtomicBool::new(false),
            wake: Arc::default(),
            gate: tokio::sync::Mutex::new(()),
        })
    }

    /// Tell the registrar how to see whether a call is live.
    pub fn set_busy(&self, busy: impl Fn() -> bool + Send + Sync + 'static) {
        *self
            .busy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(busy));
    }

    fn is_busy(&self) -> bool {
        self.busy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|b| b())
    }

    pub fn device_id(&self) -> Option<String> {
        self.device_id
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn last_registration(&self) -> Option<DeviceRegistration> {
        self.last
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn report(&self, status: &str, error: Option<String>) {
        match status {
            status::RECOVERING | status::FAILED | status::AUTH_REQUIRED => {
                self.degraded.store(true, Ordering::Relaxed);
            }
            status::REGISTERED => self.degraded.store(false, Ordering::Relaxed),
            _ => {}
        }
        log::info!(
            "Registration status: {status}{}",
            error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        );
        let did = self.device_id().unwrap_or_default();
        self.events
            .registration_changed(did, status.to_string(), error);
    }

    /// Register `registration` on the first of `routes` that answers, and
    /// make that the device's instance.
    pub async fn register_on(
        &self,
        routes: Vec<Route>,
        registration: &DeviceRegistration,
    ) -> Result<DeviceRegistrationResponse, MobileError> {
        let token = self.auth.token()?;
        let (resp, _route) = self
            .gateway
            .register_device_on(routes, &token, registration)
            .await?;
        *self
            .last
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(registration.clone());
        *self
            .device_id
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(resp.device_id.clone());
        self.auth_blocked.store(false, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.report(status::REGISTERED, None);
        self.ensure_failback();
        self.ensure_supervisor();
        Ok(resp)
    }

    /// Move the registration off `dead` (it could not be connected to) to
    /// the next instance that answers. The dead instance is not asked to
    /// unregister.
    pub async fn move_off(&self, dead: &Route) -> Result<(), MobileError> {
        let registration = self.last_registration().ok_or(MobileError::InvalidState)?;
        let routes: Vec<Route> = self
            .gateway
            .srv_routes()
            .into_iter()
            .filter(|r| !r.same(dead))
            .collect();
        if routes.is_empty() {
            return Err(MobileError::NetworkError);
        }
        log::warn!(
            "Gateway instance {} is unreachable; moving the registration",
            dead.target()
        );
        self.register_on(routes, &registration).await.map(|_| ())
    }

    /// After a network change: look the gateway up again, then make sure
    /// the device is registered, reporting `recovering` and then
    /// `registered`, `failed` or `auth_required`.
    pub async fn recover(&self) -> Result<(), MobileError> {
        self.recover_inner(false).await
    }

    /// `periodic`: a keepalive, silent while all is well.
    async fn recover_inner(&self, periodic: bool) -> Result<(), MobileError> {
        let Some(device_id) = self.device_id() else {
            // Never registered: nothing to recover.
            return Ok(());
        };
        // Single flight: a keepalive that finds a recovery running leaves
        // it to that one; a network change waits its turn.
        let _gate = if periodic {
            match self.gate.try_lock() {
                Ok(g) => g,
                Err(_) => return Ok(()),
            }
        } else {
            self.gate.lock().await
        };
        let degraded = self.degraded.load(Ordering::Relaxed);
        let quiet = periodic && !degraded;
        if !quiet {
            self.report(status::RECOVERING, None);
            // A network change, or a retry after a failure: start DNS
            // afresh. A healthy keepalive keeps its resolver and cache.
            crate::dns::resolver().network_changed();
        }
        let _ = self.gateway.resolve_gateway().await;

        let route = self
            .gateway
            .registered_route()
            .unwrap_or_else(|| self.gateway.primary_route());
        let (token, generation) = self.auth.snapshot();
        let outcome = self.gateway.heartbeat_on(&route, &token, &device_id).await;
        log::info!("Heartbeat on {}: {outcome:?}", route.target());
        let result = match outcome {
            HeartbeatOutcome::Ok => {
                if !quiet {
                    self.report(status::REGISTERED, None);
                }
                Ok(())
            }
            HeartbeatOutcome::Unauthorized => {
                self.auth_blocked.store(true, Ordering::Relaxed);
                if self.auth.report_rejection(generation) {
                    self.events.auth_required();
                }
                self.report(
                    status::AUTH_REQUIRED,
                    Some("the gateway refused the token".into()),
                );
                return Err(MobileError::AuthenticationError);
            }
            HeartbeatOutcome::UnknownDevice => {
                // The instance lost the device (restarted, or the device was
                // replaced): register again, on it first.
                match self.last_registration() {
                    Some(reg) => self
                        .register_on(self.gateway.routes(), &reg)
                        .await
                        .map(|_| ()),
                    None => Err(MobileError::InvalidState),
                }
            }
            HeartbeatOutcome::Unreachable => self.move_off(&route).await,
            HeartbeatOutcome::Failed(why) => Err(MobileError::CallFailed(why)),
        };
        match &result {
            Ok(()) => self.failures.store(0, Ordering::Relaxed),
            Err(MobileError::AuthenticationError) => {}
            Err(_) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                self.wake.notify_one();
            }
        }
        if let Err(e) = &result {
            if matches!(e, MobileError::AuthenticationError) {
                self.auth_blocked.store(true, Ordering::Relaxed);
                self.report(
                    status::AUTH_REQUIRED,
                    Some("the gateway refused the token".into()),
                );
            } else {
                self.report(status::FAILED, Some(e.to_string()));
            }
        }
        result
    }

    /// Start the supervisor (one task): a heartbeat every `keepalive`, and
    /// after a failed recovery, by whatever trigger, a retry on a capped
    /// exponential backoff that never gives up. A 401 waits for
    /// `set_gateway_token`, which recovers by itself.
    pub fn ensure_supervisor(&self) {
        if self.supervisor_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.me.clone();
        let wake = Arc::clone(&self.wake);
        crate::runtime().spawn(async move {
            Self::supervise(me.clone(), wake).await;
            if let Some(r) = me.upgrade() {
                r.supervisor_running.store(false, Ordering::SeqCst);
            }
        });
    }

    /// Holds only a `Weak`: the task ends when the engine (and its
    /// registrar) is dropped, or the device is unregistered.
    async fn supervise(me: Weak<Registrar>, wake: Arc<tokio::sync::Notify>) {
        loop {
            let Some(this) = me.upgrade() else { return };
            let timing = *this
                .supervisor_timing
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let failures = this.failures.load(Ordering::Relaxed);
            drop(this);
            let wait = jittered(timing.delay(failures));
            log::debug!("Next registration check in {wait:?} ({failures} failures)");
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = wake.notified() => {
                    // A recovery just failed: wait the backoff, not the
                    // keepalive, then try again.
                    let Some(this) = me.upgrade() else { return };
                    let failures = this.failures.load(Ordering::Relaxed);
                    drop(this);
                    tokio::time::sleep(jittered(timing.delay(failures))).await;
                }
            }
            let Some(this) = me.upgrade() else { return };
            if this.device_id().is_none() {
                return;
            }
            if this.auth_blocked.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(e) = this.recover_inner(true).await {
                log::warn!("Registration check failed: {e}");
            }
            this.ensure_failback();
        }
    }

    /// Start the failback probe if the device is off its preferred instance
    /// (one probe task at a time). A live call postpones the move.
    pub fn ensure_failback(&self) {
        if self.gateway.registered_on_preferred() {
            return;
        }
        let Some(me) = self.me.upgrade() else { return };
        if self.failback_running.swap(true, Ordering::SeqCst) {
            return;
        }
        crate::runtime().spawn(async move {
            me.failback_loop().await;
            me.failback_running.store(false, Ordering::SeqCst);
        });
    }

    async fn failback_loop(&self) {
        let timing = *self
            .failback_timing
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut wait = timing.first;
        loop {
            tokio::time::sleep(jittered(wait)).await;
            if self.gateway.registered_on_preferred() || self.device_id().is_none() {
                return;
            }
            if self.is_busy() {
                // Never move while a call is live; look again shortly after.
                wait = timing.first.min(timing.max);
                continue;
            }
            let Some(preferred) = self.gateway.srv_routes().into_iter().next() else {
                return;
            };
            if self.gateway.health(&preferred).await && self.fail_back(&preferred).await {
                return;
            }
            wait = (wait * 2).min(timing.max);
        }
    }

    /// Register on `preferred` and remove the registration from the
    /// instance the device leaves. True on success.
    async fn fail_back(&self, preferred: &Route) -> bool {
        let (Some(reg), Some(old_id), Some(old_route)) = (
            self.last_registration(),
            self.device_id(),
            self.gateway.registered_route(),
        ) else {
            return false;
        };
        match self.register_on(vec![preferred.clone()], &reg).await {
            Ok(_) => {
                log::info!(
                    "Failed back to gateway instance {} from {}",
                    preferred.target(),
                    old_route.target()
                );
                if let Ok(token) = self.auth.token() {
                    self.gateway
                        .unregister_device_on(&old_route, &token, &old_id)
                        .await;
                }
                true
            }
            Err(e) => {
                log::warn!("Failback to {} failed: {e}", preferred.target());
                false
            }
        }
    }
}
