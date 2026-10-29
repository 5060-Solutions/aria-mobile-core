//! The engine's types are usable from another Rust crate, not only through
//! the generated bindings.

use aria_mobile_core::{
    AriaMobileEngine, AudioCodec, CallDirection, CallInfo, CallState, GatewayConfig, MobileError,
    SipCredentials,
};

#[test]
fn public_types_are_reachable() {
    let config = GatewayConfig {
        base_url: "https://gw.example.com".into(),
        api_key: String::new(),
    };
    let _engine = AriaMobileEngine::new(config);

    let info = CallInfo {
        call_id: "outgoing-x".into(),
        remote_uri: "sip:1002@pbx.example.com".into(),
        remote_name: None,
        state: CallState::Ringing,
        direction: CallDirection::Outbound,
        muted: false,
        on_hold: false,
        duration_secs: 0,
    };
    assert_eq!(info.state, CallState::Ringing);

    let _creds = SipCredentials {
        username: "1001".into(),
        password: "pw".into(),
        domain: "pbx.example.com".into(),
        registrar: None,
        transport: "udp".into(),
        port: 5060,
        auth_username: None,
        display_name: "Alice".into(),
    };
    assert_eq!(AudioCodec::Pcmu.payload_type(), 0);

    let err = MobileError::CallFailed("the transfer failed (SIP 486)".into());
    assert!(err.to_string().contains("486"));
}
