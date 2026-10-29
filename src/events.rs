//! Delivery of `MobileEventHandler` callbacks.
//!
//! Every callback runs on one dedicated thread, never on a thread that is
//! inside the tokio runtime. A callback can therefore call any engine method,
//! including the ones that block on the runtime, without the "cannot start a
//! runtime from within a runtime" panic that delivering inline from
//! `block_on` or a runtime worker would cause.
//!
//! Events are delivered in the order they were queued. Queueing never runs
//! app code and never blocks, so the engine queues a call's events while it
//! still holds the lock that decided the transition, which makes the delivered
//! order the order in which the state actually changed.

use std::sync::{mpsc, Arc, Mutex, RwLock};

use crate::types::{CallInfo, CallOffer, CallState, EndReason};
use crate::MobileEventHandler;

/// The installed event handler.
pub(crate) type HandlerSlot = Arc<RwLock<Option<Arc<dyn MobileEventHandler>>>>;

enum Event {
    CallState(CallInfo),
    Incoming(CallOffer),
    Registration {
        device_id: String,
        status: String,
        error: Option<String>,
    },
    AuthRequired,
    Error {
        context: String,
        message: String,
    },
    /// Acknowledged once everything queued before it has been delivered.
    #[cfg(test)]
    Flush(mpsc::Sender<()>),
}

/// Queues events for the dispatch thread.
pub(crate) struct Dispatcher {
    handler: HandlerSlot,
    tx: Mutex<mpsc::Sender<Event>>,
    #[cfg(test)]
    thread: std::thread::ThreadId,
}

impl Dispatcher {
    /// Start the dispatch thread. It exits once the dispatcher is dropped.
    pub(crate) fn new() -> Self {
        let handler: HandlerSlot = Arc::new(RwLock::new(None));
        let (tx, rx) = mpsc::channel::<Event>();
        let slot = Arc::clone(&handler);
        let thread = std::thread::Builder::new()
            .name("aria-events".into())
            .spawn(move || {
                for event in rx {
                    deliver(&slot, event);
                }
            })
            .expect("spawn event dispatch thread");
        #[cfg(not(test))]
        let _ = thread;
        Self {
            handler,
            tx: Mutex::new(tx),
            #[cfg(test)]
            thread: thread.thread().id(),
        }
    }

    pub(crate) fn set_handler(&self, handler: Option<Arc<dyn MobileEventHandler>>) {
        *self
            .handler
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = handler;
    }

    fn send(&self, event: Event) {
        let _ = self
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(event);
    }

    /// Queue a call-state event. Engine code goes through [`CallEvents`] so
    /// that nothing follows a call's `Ended`; this is for that and for calls
    /// that have no per-call state.
    fn call_state(&self, info: CallInfo) {
        self.send(Event::CallState(info));
    }

    pub(crate) fn incoming_call(&self, offer: CallOffer) {
        self.send(Event::Incoming(offer));
    }

    pub(crate) fn registration_changed(
        &self,
        device_id: String,
        status: String,
        error: Option<String>,
    ) {
        self.send(Event::Registration {
            device_id,
            status,
            error,
        });
    }

    pub(crate) fn auth_required(&self) {
        self.send(Event::AuthRequired);
    }

    pub(crate) fn error(&self, context: String, message: String) {
        self.send(Event::Error { context, message });
    }

    /// Wait until everything queued so far has been delivered. A no-op on the
    /// dispatch thread itself, which would otherwise wait on itself.
    #[cfg(test)]
    pub(crate) fn flush(&self) {
        if std::thread::current().id() == self.thread {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.send(Event::Flush(tx));
        let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
    }
}

/// Run one event against the installed handler.
///
/// The handler is cloned out of its lock first, so a callback can replace it,
/// and the call runs inside `catch_unwind` so a panicking host callback cannot
/// take the dispatch thread down or unwind across FFI.
fn deliver(slot: &HandlerSlot, event: Event) {
    #[cfg(test)]
    if let Event::Flush(ack) = event {
        let _ = ack.send(());
        return;
    }
    let handler = slot
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(handler) = handler else { return };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match event {
        Event::CallState(info) => handler.on_call_state_changed(info),
        Event::Incoming(offer) => handler.on_incoming_call(offer),
        Event::Registration {
            device_id,
            status,
            error,
        } => handler.on_registration_changed(device_id, status, error),
        Event::AuthRequired => handler.on_auth_required(),
        Event::Error { context, message } => handler.on_error(context, message),
        #[cfg(test)]
        Event::Flush(_) => {}
    }));
}

/// Guards one call's `on_call_state_changed` events: once `Ended` has been
/// queued, nothing more is.
///
/// The check and the queueing happen under one lock, so two threads racing to
/// report the same call cannot both get past an `Ended`, and their events are
/// queued in the order they passed the check.
#[derive(Default)]
pub(crate) struct CallEvents {
    ended: Mutex<bool>,
}

impl CallEvents {
    /// Queue `info`. Returns false, queueing nothing, when the call has
    /// already been reported `Ended`.
    pub(crate) fn emit(&self, dispatcher: &Dispatcher, info: CallInfo) -> bool {
        let mut ended = self
            .ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *ended {
            return false;
        }
        *ended = info.state == CallState::Ended;
        let mut info = info;
        if !*ended {
            info.end_reason = None;
        }
        dispatcher.call_state(info);
        true
    }

    /// Queue `info` as `Ended` for `reason`, unless the call has already
    /// ended.
    pub(crate) fn emit_ended(
        &self,
        dispatcher: &Dispatcher,
        info: &CallInfo,
        reason: EndReason,
    ) -> bool {
        let mut info = info.clone();
        info.state = CallState::Ended;
        info.end_reason = Some(reason);
        self.emit(dispatcher, info)
    }
}
