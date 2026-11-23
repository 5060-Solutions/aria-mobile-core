//! Setup-link tests against a stub HTTP server on 127.0.0.1. Nothing here
//! touches the network beyond loopback.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use super::*;

const SHORT: Duration = Duration::from_secs(3);

fn opts() -> Options {
    Options {
        allow_local_http: true,
        timeout: SHORT,
    }
}

/// How the stub answers a request.
#[derive(Clone)]
enum Reply {
    /// A full raw HTTP response.
    Raw(String),
    /// Read the request and never answer.
    Hang,
}

/// Answers `GET` with `get` and `POST` with `post`, and records every
/// request's method.
struct Stub {
    port: u16,
    methods: Arc<Mutex<Vec<String>>>,
}

impl Stub {
    fn start(get: Reply, post: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&methods);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (get, post, seen) = (get.clone(), post.clone(), Arc::clone(&seen));
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let method = head.split(' ').next().unwrap_or_default().to_string();
                    seen.lock().unwrap().push(method.clone());
                    match if method == "POST" { post } else { get } {
                        Reply::Raw(r) => {
                            let _ = stream.write_all(r.as_bytes());
                        }
                        Reply::Hang => std::thread::sleep(Duration::from_secs(30)),
                    }
                });
            }
        });
        Self { port, methods }
    }

    fn json(get: &serde_json::Value, post: &serde_json::Value) -> Self {
        Self::start(ok(get), ok(post))
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/provision/softphone/tok123", self.port)
    }

    fn link(&self) -> String {
        link_for(&self.url())
    }

    fn methods(&self) -> Vec<String> {
        self.methods.lock().unwrap().clone()
    }
}

fn link_for(url: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(url.as_bytes()).collect();
    format!("aria://provision?v=1&url={encoded}")
}

fn response(status: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn ok(body: &serde_json::Value) -> Reply {
    Reply::Raw(response("200 OK", "", &body.to_string()))
}

fn status(line: &str) -> Reply {
    Reply::Raw(response(line, "", "{}"))
}

fn preview_body() -> serde_json::Value {
    json!({
        "v": 1,
        "tenant_name": "Regular Test",
        "extension": "1001",
        "display_name": "Front Desk",
        "domain": "regular-test.ariaroute.com",
        "expires_at": "2026-11-05T12:00:00Z"
    })
}

fn redeem_body() -> serde_json::Value {
    json!({
        "v": 1,
        "tenant_name": "Regular Test",
        "display_name": "Front Desk",
        "username": "1001",
        "auth_username": "1001-auth",
        "password": "s3cret-pw",
        "domain": "regular-test.ariaroute.com",
        "outbound_proxy": "sip.ariaroute.com",
        "port": 5061,
        "transport": "tls",
        "voicemail": "*97"
    })
}

fn obj(v: serde_json::Value) -> JsonMap {
    match v {
        serde_json::Value::Object(m) => m,
        _ => unreachable!(),
    }
}

fn is_server_error(r: &Result<impl std::fmt::Debug, ProvisionError>) -> bool {
    matches!(r, Err(ProvisionError::Server(_)))
}

// ── Link and URL validation ────────────────────────────────────────────────

#[test]
fn accepts_an_https_link() {
    let url = redeem_url(
        &link_for("https://api.ariaroute.com/provision/softphone/abc"),
        false,
    )
    .unwrap();
    assert_eq!(server_host(&url), "api.ariaroute.com");
    assert_eq!(url.path(), "/provision/softphone/abc");
}

#[test]
fn link_prefix_and_parameters_follow_the_desktop_rules() {
    let good = "https%3A%2F%2Fapi.ariaroute.com%2Fprovision%2Fsoftphone%2Fabc";
    for link in [
        format!("aria://provision?v=1&url={good}"),
        format!("ARIA://Provision/?v=1&url={good}"),
        format!("  aria://provision?url={good}&v=1#frag  "),
    ] {
        assert!(redeem_url(&link, false).is_ok(), "{link}");
    }
    for link in [
        format!("aria://provisioning?v=1&url={good}"),
        format!("aria://provision?v=2&url={good}"),
        format!("aria://provision?v=1&v=1&url={good}"),
        format!("aria://provision?url={good}"),
        "aria://provision?v=1".to_string(),
        "aria://provision?v=1&url=".to_string(),
        format!("aria://provision?v=1&url={good}&url={good}"),
        format!("https://provision?v=1&url={good}"),
        // A legacy QR link: no `v`. The app falls back to its own parser.
        "aria://provision?server=pbx.example.com&user=1001&pass=cHc=".to_string(),
        String::new(),
    ] {
        assert_eq!(
            redeem_url(&link, false).unwrap_err(),
            ProvisionError::InvalidLink,
            "{link}"
        );
    }
}

#[test]
fn rejects_urls_outside_the_contract() {
    for (raw, local) in [
        ("http://api.ariaroute.com/provision/softphone/abc", true),
        ("http://localhost:8787/provision/softphone/abc", false),
        ("http://127.0.0.1/provision/softphone/abc", false),
        (
            "https://user:pw@api.ariaroute.com/provision/softphone/abc",
            false,
        ),
        (
            "https://user@api.ariaroute.com/provision/softphone/abc",
            false,
        ),
        ("https://api.ariaroute.com/provision/softphone/", false),
        ("https://api.ariaroute.com/provision/other/abc", false),
        ("https://api.ariaroute.com/x/provision/softphone/abc", false),
        ("ftp://api.ariaroute.com/provision/softphone/abc", false),
        ("file:///provision/softphone/abc", false),
        ("not a url", false),
    ] {
        assert_eq!(
            validate_redeem_url(raw, local).unwrap_err(),
            ProvisionError::InvalidLink,
            "{raw}"
        );
        assert_eq!(
            redeem_url(&link_for(raw), local).unwrap_err(),
            ProvisionError::InvalidLink,
            "{raw}"
        );
    }
}

#[test]
fn the_public_functions_never_allow_plain_http() {
    // Even to a stub that would answer: refused before any request.
    let stub = Stub::json(&preview_body(), &redeem_body());
    assert_eq!(
        provision_preview(stub.link()).unwrap_err(),
        ProvisionError::InvalidLink
    );
    assert_eq!(
        provision_redeem(stub.link()).unwrap_err(),
        ProvisionError::InvalidLink
    );
    assert!(stub.methods().is_empty());
}

#[test]
fn allows_local_http_only_when_asked() {
    let raw = "http://localhost:8787/provision/softphone/abc";
    assert!(validate_redeem_url(raw, true).is_ok());
    assert!(validate_redeem_url(raw, false).is_err());
}

#[test]
fn errors_never_carry_the_token() {
    let errors = [
        ProvisionError::InvalidLink,
        ProvisionError::Expired,
        ProvisionError::Network(unreachable_message()),
        ProvisionError::Mismatch,
        unreadable(),
    ];
    for e in errors {
        assert!(!e.to_string().contains("tok123"));
        assert!(!format!("{e:?}").contains("tok123"));
    }
    // Nor does a network failure's message.
    let link = link_for("http://127.0.0.1:1/provision/softphone/tok123");
    let e = preview_with(&link, opts()).unwrap_err();
    assert!(matches!(e, ProvisionError::Network(_)), "{e:?}");
    assert!(!e.to_string().contains("tok123"));
}

// ── Preview ────────────────────────────────────────────────────────────────

#[test]
fn preview_uses_get_and_does_not_redeem() {
    let stub = Stub::json(&preview_body(), &redeem_body());
    let preview = preview_with(&stub.link(), opts()).unwrap();
    assert_eq!(
        preview,
        ProvisionPreview {
            tenant_name: "Regular Test".into(),
            extension: "1001".into(),
            display_name: "Front Desk".into(),
            domain: "regular-test.ariaroute.com".into(),
            expires_at: Some("2026-11-05T12:00:00Z".into()),
            server_host: format!("127.0.0.1:{}", stub.port),
        }
    );
    assert_eq!(stub.methods(), ["GET"]);
}

#[test]
fn not_found_means_expired_or_used() {
    let stub = Stub::start(status("404 Not Found"), status("404 Not Found"));
    assert_eq!(
        preview_with(&stub.link(), opts()).unwrap_err(),
        ProvisionError::Expired
    );
    assert_eq!(
        redeem_with(&stub.link(), opts()).unwrap_err(),
        ProvisionError::Expired
    );
}

#[test]
fn other_statuses_are_server_errors() {
    let stub = Stub::start(status("500 Internal Server Error"), status("410 Gone"));
    let e = preview_with(&stub.link(), opts()).unwrap_err();
    assert!(e.to_string().contains("HTTP 500"), "{e}");
}

#[test]
fn redirects_are_not_followed() {
    let target = Stub::json(&preview_body(), &redeem_body());
    let location = format!("Location: {}\r\n", target.url());
    let stub = Stub::start(
        Reply::Raw(response("302 Found", &location, "")),
        Reply::Raw(response("307 Temporary Redirect", &location, "")),
    );
    let r = preview_with(&stub.link(), opts());
    assert!(is_server_error(&r), "{r:?}");
    assert!(target.methods().is_empty(), "the redirect was followed");
    assert_eq!(stub.methods(), ["GET"]);
}

#[test]
fn bad_json_and_wrong_version_fail() {
    let stub = Stub::start(
        Reply::Raw(response("200 OK", "", "<html>")),
        Reply::Raw(response("200 OK", "", "[1]")),
    );
    assert!(is_server_error(&preview_with(&stub.link(), opts())));

    let mut v2 = preview_body();
    v2["v"] = json!(2);
    let stub = Stub::json(&v2, &redeem_body());
    let e = preview_with(&stub.link(), opts()).unwrap_err();
    assert!(e.to_string().contains("newer version"), "{e}");
}

#[test]
fn missing_or_unusable_preview_fields_fail() {
    for (key, value) in [
        ("extension", json!(null)),
        ("extension", json!("10 01")),
        ("extension", json!("<sip:x>")),
        ("domain", json!(null)),
        ("domain", json!("evil.com\r\nX: y")),
        ("domain", json!(".example.com")),
    ] {
        let mut body = preview_body();
        body[key] = value;
        let stub = Stub::json(&body, &redeem_body());
        assert!(
            is_server_error(&preview_with(&stub.link(), opts())),
            "{key}"
        );
    }
}

#[test]
fn a_reply_over_16_kb_is_refused() {
    let mut body = preview_body();
    body["tenant_name"] = json!("x".repeat(MAX_BODY_BYTES));
    let stub = Stub::json(&body, &redeem_body());
    let r = preview_with(&stub.link(), opts());
    assert!(is_server_error(&r), "{r:?}");

    // Without a Content-Length too (read until close).
    let raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
    );
    let stub = Stub::start(Reply::Raw(raw), Reply::Hang);
    let r = preview_with(&stub.link(), opts());
    assert!(is_server_error(&r), "{r:?}");

    // Just under the cap is fine.
    let mut body = preview_body();
    let room = MAX_BODY_BYTES - body.to_string().len() - 100;
    body["padding"] = json!("x".repeat(room));
    let stub = Stub::json(&body, &redeem_body());
    assert!(preview_with(&stub.link(), opts()).is_ok());
}

#[test]
fn a_server_that_never_answers_is_a_network_error() {
    let stub = Stub::start(Reply::Hang, Reply::Hang);
    let started = std::time::Instant::now();
    let e = preview_with(
        &stub.link(),
        Options {
            allow_local_http: true,
            timeout: Duration::from_millis(300),
        },
    )
    .unwrap_err();
    assert!(matches!(e, ProvisionError::Network(_)), "{e:?}");
    assert!(e.to_string().contains("too long"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

// ── Redeem ─────────────────────────────────────────────────────────────────

#[test]
fn redeem_after_preview_posts_once_and_maps_the_reply() {
    let stub = Stub::json(&preview_body(), &redeem_body());
    preview_with(&stub.link(), opts()).unwrap();
    let account = redeem_with(&stub.link(), opts()).unwrap();
    assert_eq!(stub.methods(), ["GET", "POST"]);
    assert_eq!(
        account,
        ProvisionedAccount {
            username: "1001".into(),
            auth_username: Some("1001-auth".into()),
            password: "s3cret-pw".into(),
            domain: "regular-test.ariaroute.com".into(),
            transport: "tls".into(),
            port: 5061,
            outbound_proxy: Some("sip.ariaroute.com:5061".into()),
            voicemail: Some("*97".into()),
            srtp: None,
            tenant_name: "Regular Test".into(),
            display_name: "Front Desk".into(),
            server_host: format!("127.0.0.1:{}", stub.port),
        }
    );
    assert!(!format!("{account:?}").contains("s3cret"));
}

#[test]
fn redeem_without_a_preview_in_this_process_previews_first() {
    let stub = Stub::json(&preview_body(), &redeem_body());
    redeem_with(&stub.link(), opts()).unwrap();
    assert_eq!(stub.methods(), ["GET", "POST"]);
}

#[test]
fn a_redeem_for_a_different_line_than_previewed_is_a_mismatch() {
    for (key, value) in [
        ("username", "1002"),
        ("domain", "other-tenant.ariaroute.com"),
    ] {
        let mut body = redeem_body();
        body[key] = json!(value);
        let stub = Stub::json(&preview_body(), &body);
        preview_with(&stub.link(), opts()).unwrap();
        assert_eq!(
            redeem_with(&stub.link(), opts()).unwrap_err(),
            ProvisionError::Mismatch,
            "{key}"
        );
    }
    // The domain is compared without regard to case.
    let mut body = redeem_body();
    body["domain"] = json!("Regular-Test.AriaRoute.com");
    let stub = Stub::json(&preview_body(), &body);
    preview_with(&stub.link(), opts()).unwrap();
    assert!(redeem_with(&stub.link(), opts()).is_ok());
}

#[test]
fn a_redeem_that_previews_first_is_held_to_that_preview() {
    let mut body = redeem_body();
    body["username"] = json!("1002");
    let stub = Stub::json(&preview_body(), &body);
    assert_eq!(
        redeem_with(&stub.link(), opts()).unwrap_err(),
        ProvisionError::Mismatch
    );
}

#[test]
fn redeem_defaults_and_optional_fields() {
    let line = parse_redeem(
        &obj(json!({
            "v": 1, "username": "1001", "password": "pw", "domain": "Example.COM",
        })),
        "h".into(),
    )
    .unwrap();
    assert_eq!(line.transport, "tls");
    assert_eq!(line.port, 0);
    assert_eq!(line.domain, "example.com");
    assert_eq!(line.display_name, "1001");
    assert_eq!(line.auth_username, None);
    assert_eq!(line.outbound_proxy, None);
    assert_eq!(line.voicemail, None);
    assert_eq!(line.srtp, None);
    assert_eq!(line.tenant_name, "");
}

#[test]
fn proxy_and_port_forms() {
    let parse = |proxy: &str, port: serde_json::Value| {
        parse_redeem(
            &obj(json!({
                "v": 1, "username": "1001", "password": "pw", "domain": "example.com",
                "outbound_proxy": proxy, "port": port,
            })),
            "h".into(),
        )
        .map(|l| (l.outbound_proxy, l.port))
    };
    assert_eq!(
        parse("sip.example.com", json!(null)).unwrap(),
        (Some("sip.example.com".into()), 0)
    );
    assert_eq!(
        parse("sip.example.com", json!(0)).unwrap(),
        (Some("sip.example.com".into()), 0)
    );
    assert_eq!(
        parse("sip.example.com", json!(5080)).unwrap(),
        (Some("sip.example.com:5080".into()), 5080)
    );
    assert_eq!(
        parse("SIPS:Sip.Example.com:5061", json!(5080)).unwrap(),
        (Some("sip.example.com:5061".into()), 5080)
    );
    assert!(parse("sip.example.com:0", json!(null)).is_err());
    assert!(parse("sip.example.com:x", json!(null)).is_err());
    assert!(parse("sip.example.com", json!(70000)).is_err());
    assert!(parse("sip.example.com", json!("5060")).is_err());
}

#[test]
fn srtp_and_voicemail_are_read_only_when_well_formed() {
    let parse = |extra: serde_json::Value| {
        let mut body =
            json!({"v": 1, "username": "1001", "password": "pw", "domain": "example.com"});
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        parse_redeem(&obj(body), "h".into()).unwrap()
    };
    assert_eq!(parse(json!({"srtp": "SDES"})).srtp.as_deref(), Some("sdes"));
    assert_eq!(
        parse(json!({"srtp": "disabled"})).srtp.as_deref(),
        Some("disabled")
    );
    assert_eq!(parse(json!({"srtp": "dtls"})).srtp, None);
    assert_eq!(parse(json!({"srtp": 1})).srtp, None);
    assert_eq!(
        parse(json!({"voicemail": "*97#"})).voicemail.as_deref(),
        Some("*97#")
    );
    assert_eq!(parse(json!({"voicemail": "sip:vm"})).voicemail, None);
    assert_eq!(
        parse(json!({"transport": "AUTO"})).transport,
        "auto".to_string()
    );
}

#[test]
fn redeem_rejects_unusable_fields() {
    for (key, value) in [
        ("username", json!(null)),
        ("username", json!("a b")),
        ("auth_username", json!("a@b")),
        ("password", json!("")),
        ("password", json!("pw\r\n")),
        ("password", json!(null)),
        ("domain", json!("a_b.com")),
        ("transport", json!("ws")),
        ("port", json!(-1)),
    ] {
        let mut body = redeem_body();
        body[key] = value;
        assert!(
            parse_redeem(&obj(body), "h".into()).is_err(),
            "{key} accepted"
        );
    }
}

#[test]
fn display_text_cannot_break_a_quoted_string() {
    assert_eq!(clean_text("A \"B\" <c>\\d\r\n", 100), "A B cd");
    assert_eq!(clean_text("abcdef", 3), "abc");
}
