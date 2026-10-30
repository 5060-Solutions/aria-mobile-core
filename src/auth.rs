//! The bearer token the core presents to the push gateway.
//!
//! The core never mints gateway tokens. Only the PBX holds the issuer key: it
//! hands the app a `gateway_token` at device registration and a fresh one from
//! `POST /api/v1/devices/{id}/gateway-token`. The app passes the first in
//! `GatewayConfig.api_key` and later ones to `set_gateway_token`.

use std::sync::Mutex;

use crate::types::MobileError;

/// The current gateway token, shared with the background poll threads so they
/// always use the latest one.
pub(crate) struct GatewayAuth {
    inner: Mutex<Inner>,
}

struct Inner {
    token: Option<String>,
    /// Bumped on every `set`, so a rejection can be tied to the token that
    /// was actually sent rather than whichever one is current when the
    /// response arrives.
    generation: u64,
    /// Whether background work has already reported this token as rejected,
    /// so `on_auth_required` fires at most once per token.
    rejection_reported: bool,
}

impl GatewayAuth {
    /// Start with `token`; an empty string means no token yet.
    pub(crate) fn new(token: String) -> Self {
        Self {
            inner: Mutex::new(Inner {
                token: Some(token).filter(|t| !t.is_empty()),
                generation: 0,
                rejection_reported: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replace the token used for every gateway request from now on.
    pub(crate) fn set(&self, token: String) {
        let mut inner = self.lock();
        inner.token = Some(token).filter(|t| !t.is_empty());
        inner.generation += 1;
        inner.rejection_reported = false;
    }

    /// The current token and its generation, if there is one.
    pub(crate) fn current(&self) -> Option<(String, u64)> {
        let inner = self.lock();
        inner.token.clone().map(|t| (t, inner.generation))
    }

    /// The current token (empty when there is none) and its generation, for
    /// background requests. They are sent even without a token, so that the
    /// gateway's 401 is reported against the right generation and the app is
    /// still asked for a token.
    pub(crate) fn snapshot(&self) -> (String, u64) {
        let inner = self.lock();
        (inner.token.clone().unwrap_or_default(), inner.generation)
    }

    /// The current token, or `AuthenticationError` when there is none.
    pub(crate) fn token(&self) -> Result<String, MobileError> {
        self.current()
            .map(|(t, _)| t)
            .ok_or(MobileError::AuthenticationError)
    }

    /// Record that background work had the token of `generation` rejected
    /// with 401. Returns true when the app should be told, which is only the
    /// first time for the current token: a rejection of a token that has
    /// since been replaced, or a repeat, returns false.
    pub(crate) fn report_rejection(&self, generation: u64) -> bool {
        let mut inner = self.lock();
        if inner.generation != generation || inner.rejection_reported {
            return false;
        }
        inner.rejection_reported = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_token_counts_as_none() {
        let auth = GatewayAuth::new(String::new());
        assert!(matches!(
            auth.token(),
            Err(MobileError::AuthenticationError)
        ));
        auth.set("t1".into());
        assert_eq!(auth.token().unwrap(), "t1");
        auth.set(String::new());
        assert!(auth.current().is_none());
    }

    #[test]
    fn set_bumps_the_generation() {
        let auth = GatewayAuth::new("t0".into());
        let (_, g0) = auth.current().unwrap();
        auth.set("t1".into());
        let (t, g1) = auth.current().unwrap();
        assert_eq!(t, "t1");
        assert!(g1 > g0);
    }

    #[test]
    fn a_rejection_is_reported_once_per_token() {
        let auth = GatewayAuth::new("t0".into());
        let (_, g0) = auth.current().unwrap();
        assert!(auth.report_rejection(g0));
        assert!(!auth.report_rejection(g0));

        auth.set("t1".into());
        // A late 401 for the replaced token says nothing about the new one.
        assert!(!auth.report_rejection(g0));
        let (_, g1) = auth.current().unwrap();
        assert!(auth.report_rejection(g1));
        assert!(!auth.report_rejection(g1));
    }

    /// Clearing the token is a new generation too: a 401 sent without a
    /// token must still be reported once.
    #[test]
    fn a_rejection_without_a_token_is_reported() {
        let auth = GatewayAuth::new("t0".into());
        auth.set(String::new());
        let (token, generation) = auth.snapshot();
        assert!(token.is_empty());
        assert!(auth.report_rejection(generation));
        assert!(!auth.report_rejection(generation));
    }
}
