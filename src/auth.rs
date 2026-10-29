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
}

impl GatewayAuth {
    /// Start with `token`; an empty string means no token yet.
    pub(crate) fn new(token: String) -> Self {
        Self {
            inner: Mutex::new(Inner {
                token: Some(token).filter(|t| !t.is_empty()),
                generation: 0,
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
    }

    /// The current token and its generation, if there is one.
    pub(crate) fn current(&self) -> Option<(String, u64)> {
        let inner = self.lock();
        inner.token.clone().map(|t| (t, inner.generation))
    }

    /// The current token, or `AuthenticationError` when there is none.
    pub(crate) fn token(&self) -> Result<String, MobileError> {
        self.current()
            .map(|(t, _)| t)
            .ok_or(MobileError::AuthenticationError)
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
}
