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

use std::sync::atomic::{AtomicBool, Ordering};
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
        self.report(status::REGISTERED, None);
        self.ensure_failback();
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
        let Some(device_id) = self.device_id() else {
            // Never registered: nothing to recover.
            return Ok(());
        };
        self.report(status::RECOVERING, None);
        crate::dns::resolver().clear_cache();
        let _ = self.gateway.resolve_gateway().await;

        let route = self
            .gateway
            .registered_route()
            .unwrap_or_else(|| self.gateway.primary_route());
        let (token, generation) = self.auth.snapshot();
        let outcome = self.gateway.heartbeat_on(&route, &token, &device_id).await;
        log::info!(
            "Heartbeat on {} after network change: {outcome:?}",
            route.target()
        );
        let result = match outcome {
            HeartbeatOutcome::Ok => {
                self.report(status::REGISTERED, None);
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
