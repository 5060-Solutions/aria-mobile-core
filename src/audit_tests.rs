//! Follow-ups of docs/reviews/audit-2026-07-27.md that were still open.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;

fn engine_for(base_url: &str) -> AriaMobileEngine {
    init_runtime();
    AriaMobileEngine::new(GatewayConfig {
        base_url: base_url.to_string(),
        api_key: "jwt".into(),
    })
}

fn registration() -> DeviceRegistration {
    DeviceRegistration {
        platform: "ios".into(),
        push_token: "push".into(),
        bundle_id: None,
        alert_token: None,
        sip: SipCredentials {
            username: "1001".into(),
            password: "the-sip-password".into(),
            domain: "sip.example.com".into(),
            registrar: None,
            transport: "tls".into(),
            port: 5061,
            auth_username: None,
            display_name: String::new(),
        },
    }
}

/// A server answering every request with `head` (a status line and
/// headers), counting what it received.
fn server(head: impl Fn() -> String + Send + 'static) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            seen.fetch_add(1, Ordering::SeqCst);
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let _ = s.write_all(head().as_bytes());
        }
    });
    (url, hits)
}

/// Finding 1: a gateway (or anyone on its path) answering with a redirect
/// must not get the SIP password and token re-sent somewhere else, such as
/// a cleartext URL. Redirects are not followed.
#[test]
fn gateway_redirects_are_not_followed() {
    let (elsewhere, elsewhere_hits) =
        server(|| "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".into());
    let target = format!("{elsewhere}/v1/devices");
    let (gw, _) = server(move || {
        format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}\r\nContent-Length: 0\r\n\r\n"
        )
    });
    let engine = engine_for(&gw);
    assert!(engine.register_device(registration()).is_err());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        elsewhere_hits.load(Ordering::SeqCst),
        0,
        "the registration (with the SIP password) was re-sent to the redirect target"
    );
}

/// Finding 2: a lock poisoned by a panic elsewhere must not turn every later
/// engine call into a panic across the FFI boundary.
#[test]
fn a_poisoned_lock_does_not_brick_the_engine() {
    let engine = Arc::new(engine_for("https://gateway.invalid"));
    for poison in 0..3 {
        let e = Arc::clone(&engine);
        let _ = std::thread::spawn(move || match poison {
            0 => {
                let _g = e.calls.lock().unwrap();
                panic!("poison the call map");
            }
            1 => {
                let _g = e.codec_prefs.write().unwrap();
                panic!("poison the codec preferences");
            }
            _ => {
                let _g = e.audio_bridge.write().unwrap();
                panic!("poison the audio bridge");
            }
        })
        .join();
    }
    assert!(engine.calls.is_poisoned());
    // None of these may panic.
    assert!(engine.get_calls().is_empty());
    assert!(engine.get_active_call().is_none());
    assert!(engine.get_media_stats("nope".into()).is_none());
    assert_eq!(engine.get_rx_audio_level("nope".into()), 0.0);
    assert_eq!(engine.get_tx_audio_level("nope".into()), 0.0);
    engine.set_codec_preferences(vec![AudioCodec::Pcmu]);
    struct Silent;
    impl media::PlatformAudioBridge for Silent {
        fn on_playback_audio(&self, _s: Vec<i16>, _r: u32) {}
        fn on_capture_audio(&self, _r: u32, n: u32) -> Vec<i16> {
            vec![0; n as usize]
        }
    }
    engine.set_audio_bridge(Box::new(Silent));
}

/// Finding 2, DNS cache: a poisoned cache lock is tolerated too.
#[test]
fn a_poisoned_dns_cache_is_tolerated() {
    init_runtime();
    let resolver = Arc::new(dns::SrvResolver::new());
    let r = Arc::clone(&resolver);
    let _ = std::thread::spawn(move || r.poison_cache_for_test()).join();
    resolver.clear_cache();
    let got =
        runtime().block_on(resolver.resolve_sip_server("127.0.0.1", dns::SipTransport::Tls, 443));
    assert!(got.is_ok());
}

/// Finding 8: the runtime is there even if the host never called
/// `init_runtime()` first; an exported method must not panic for it.
#[test]
fn the_runtime_starts_on_first_use() {
    let rt = runtime();
    assert_eq!(rt.block_on(async { 7 }), 7);
}

/// Finding 13: the interface address is the one routing to the peer, not to
/// a hard-coded public resolver.
#[test]
fn the_advertised_interface_is_the_one_towards_the_peer() {
    init_runtime();
    let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let ip = runtime().block_on(media::local_interface_ip_towards(Some(peer)));
    assert_eq!(ip, "127.0.0.1");
}
