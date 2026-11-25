//! Reliability end to end: a network switch in the middle of a call, and a
//! gateway instance that goes away and comes back.
//!
//! Two pieces stand in for the far side:
//!
//! - [`Instance`]: one push-gateway instance over HTTP, which can be killed
//!   (its port refuses connections) and revived on the same port. Like the
//!   real gateway it places calls only for devices registered on it.
//! - [`Relay`]: the PBX media relay with the behaviour of aria-cloud-pbx's
//!   re-point on re-INVITE: it sends to, and accepts only from, the address
//!   signalling gave it; a media update (`POST /v1/calls/{t}/media`) moves
//!   it to the new address, and a packet from anywhere else is dropped.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;

// ── Fake media relay ──────────────────────────────────────────────────────

/// The PBX side of the call's media.
struct Relay {
    socket: Arc<UdpSocket>,
    /// Where it sends and the only source it accepts.
    signaled: Arc<Mutex<Option<SocketAddr>>>,
    /// Packets accepted, by source port.
    from_ports: Arc<Mutex<Vec<u16>>>,
    dropped: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Relay {
    fn start() -> Arc<Self> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let relay = Arc::new(Self {
            socket,
            signaled: Arc::default(),
            from_ports: Arc::default(),
            dropped: Arc::default(),
            stop: Arc::default(),
        });
        let r = Arc::clone(&relay);
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut seq: u16 = 1;
            let mut next_send = Instant::now();
            while !r.stop.load(Ordering::Relaxed) {
                if let Ok((n, from)) = r.socket.recv_from(&mut buf) {
                    if n >= 12 {
                        if *r.signaled.lock().unwrap() == Some(from) {
                            r.from_ports.lock().unwrap().push(from.port());
                        } else {
                            r.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if Instant::now() >= next_send {
                    next_send += Duration::from_millis(20);
                    let to = *r.signaled.lock().unwrap();
                    if let Some(to) = to {
                        let _ = r.socket.send_to(&pcmu_tone(seq), to);
                        seq = seq.wrapping_add(1);
                    }
                }
            }
        });
        relay
    }

    fn port(&self) -> u16 {
        self.socket.local_addr().unwrap().port()
    }

    /// Point at the address an SDP gives (all on loopback here).
    fn signal(&self, sdp: &str) {
        let port = sdp
            .lines()
            .find_map(|l| l.strip_prefix("m=audio "))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|p| p.parse::<u16>().ok())
            .expect("an m=audio port");
        *self.signaled.lock().unwrap() = Some(SocketAddr::from(([127, 0, 0, 1], port)));
    }

    fn answer_sdp(&self) -> String {
        format!(
            "v=0\r\no=pbx 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n",
            self.port()
        )
    }

    fn heard_from(&self, port: u16) -> usize {
        self.from_ports
            .lock()
            .unwrap()
            .iter()
            .filter(|p| **p == port)
            .count()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A PCMU packet carrying a loud tone (not silence).
fn pcmu_tone(seq: u16) -> Vec<u8> {
    let mut p = vec![0x80, 0x00];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    p.extend_from_slice(&0x5eed_u32.to_be_bytes());
    p.extend((0..160).map(|i| if i % 2 == 0 { 0x10 } else { 0x90 }));
    p
}

// ── Fake gateway instance ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    body: String,
}

struct InstanceState {
    name: String,
    port: u16,
    alive: AtomicBool,
    seen: Mutex<Vec<Seen>>,
    devices: Mutex<HashSet<String>>,
    next: AtomicUsize,
    relay: Mutex<Option<Arc<Relay>>>,
    /// Answer 401 to heartbeats (an expired token).
    reject_tokens: AtomicBool,
}

/// One gateway instance on loopback.
struct Instance(Arc<InstanceState>);

impl Instance {
    fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(InstanceState {
            name: name.into(),
            port,
            alive: AtomicBool::new(true),
            seen: Mutex::default(),
            devices: Mutex::default(),
            next: AtomicUsize::new(1),
            relay: Mutex::new(None),
            reject_tokens: AtomicBool::new(false),
        });
        Self::serve(Arc::clone(&state), listener);
        Self(state)
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.0.port)
    }

    fn authority(&self) -> String {
        format!("127.0.0.1:{}", self.0.port)
    }

    fn with_relay(&self, relay: &Arc<Relay>) {
        *self.0.relay.lock().unwrap() = Some(Arc::clone(relay));
    }

    /// Stop listening: connections are refused from now on.
    fn kill(&self) {
        self.0.alive.store(false, Ordering::SeqCst);
        // Wake the accept loop so it drops the listener now.
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.0.port));
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::net::TcpStream::connect(("127.0.0.1", self.0.port)).is_ok() {
            assert!(Instant::now() < deadline, "instance still listening");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Listen again on the same port (it has forgotten nothing).
    fn revive(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let listener = loop {
            match TcpListener::bind(("127.0.0.1", self.0.port)) {
                Ok(l) => break l,
                Err(e) => {
                    assert!(Instant::now() < deadline, "rebind: {e}");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        };
        self.0.alive.store(true, Ordering::SeqCst);
        Self::serve(Arc::clone(&self.0), listener);
    }

    fn count(&self, method: &str, prefix: &str) -> usize {
        self.0
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.method == method && s.path.starts_with(prefix))
            .count()
    }

    fn serve(state: Arc<InstanceState>, listener: TcpListener) {
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if !state.alive.load(Ordering::SeqCst) {
                    return; // drops the listener
                }
                let Ok(stream) = stream else { continue };
                let state = Arc::clone(&state);
                std::thread::spawn(move || handle(&state, stream));
            }
        });
    }
}

fn handle(state: &InstanceState, mut stream: std::net::TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return;
    };
    let (method, path) = (method.to_string(), path.to_string());
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).is_err() {
            return;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((n, v)) = h.split_once(':') {
            if n.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; len];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    state.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        body: body.clone(),
    });
    let (status, json) = respond(state, &method, &path, &body);
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{json}",
        json.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    // Let the client close first, so this port is free to listen on again.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut sink = [0u8; 64];
    let _ = stream.read(&mut sink);
}

fn respond(state: &InstanceState, method: &str, path: &str, body: &str) -> (u16, String) {
    let relay = state.relay.lock().unwrap().clone();
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (method, segs.as_slice()) {
        ("GET", ["health"]) => (200, "\"ok\"".into()),
        ("POST", ["v1", "devices"]) => {
            let n = state.next.fetch_add(1, Ordering::Relaxed);
            let id = format!("{}-dev{n}", state.name);
            state.devices.lock().unwrap().insert(id.clone());
            (
                200,
                format!(r#"{{"device_id":"{id}","status":"registering"}}"#),
            )
        }
        ("POST", ["v1", "devices", _, "heartbeat"])
            if state.reject_tokens.load(Ordering::SeqCst) =>
        {
            (401, String::new())
        }
        ("GET", ["v1", "calls", tok]) if tok.starts_with(&state.name) => (
            200,
            serde_json::json!({
                "call_token": tok,
                "caller_uri": "2000@pbx",
                "caller_name": null,
                "sdp_offer": "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 4000 RTP/AVP 0\r\n",
            })
            .to_string(),
        ),
        ("POST", ["v1", "devices", id, "heartbeat"]) => {
            if state.devices.lock().unwrap().contains(*id) {
                (204, String::new())
            } else {
                (404, String::new())
            }
        }
        ("DELETE", ["v1", "devices", id]) => {
            state.devices.lock().unwrap().remove(*id);
            (204, String::new())
        }
        ("POST", ["v1", "calls"]) => {
            // Like the gateway: only for a device registered here.
            if state.devices.lock().unwrap().is_empty() {
                return (404, String::new());
            }
            let Some(relay) = relay else {
                return (502, String::new());
            };
            let offer: serde_json::Value = serde_json::from_str(body).unwrap();
            relay.signal(offer["sdp_offer"].as_str().unwrap());
            let n = state.next.fetch_add(1, Ordering::Relaxed);
            let answer = serde_json::json!({
                "call_token": format!("{}-call{n}", state.name),
                "sdp_answer": relay.answer_sdp(),
            });
            (200, answer.to_string())
        }
        ("GET", ["v1", "calls", _, "status"]) => (200, r#"{"status":"active"}"#.into()),
        ("POST", ["v1", "calls", _, "media"]) => {
            let Some(relay) = relay else {
                return (404, String::new());
            };
            let req: serde_json::Value = serde_json::from_str(body).unwrap();
            // The PBX re-points the leg to the address in the re-INVITE.
            relay.signal(req["sdp"].as_str().unwrap());
            (
                200,
                serde_json::json!({ "sdp_answer": relay.answer_sdp() }).to_string(),
            )
        }
        ("POST", ["v1", "calls", _, "hangup"]) => (200, "{}".into()),
        _ => (404, String::new()),
    }
}

// ── The app ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct Speaker {
    /// Loud frames played, so silence (hold, nothing arriving) is not
    /// counted as audio.
    loud_frames: AtomicU64,
}

struct Bridge(Arc<Speaker>);

impl media::PlatformAudioBridge for Bridge {
    fn on_playback_audio(&self, samples: Vec<i16>, _sample_rate: u32) {
        if samples.iter().any(|s| s.unsigned_abs() > 1000) {
            self.0.loud_frames.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn on_capture_audio(&self, _sample_rate: u32, frame_size: u32) -> Vec<i16> {
        (0..frame_size)
            .map(|i| if i % 2 == 0 { 8000 } else { -8000 })
            .collect()
    }
}

/// (device_id, status, error) of one `on_registration_changed`.
type RegEvent = (String, String, Option<String>);

#[derive(Default, Clone)]
struct App {
    auth_required: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<CallInfo>>>,
    registration: Arc<Mutex<Vec<RegEvent>>>,
}

impl MobileEventHandler for App {
    fn on_registration_changed(&self, device_id: String, status: String, error: Option<String>) {
        self.registration
            .lock()
            .unwrap()
            .push((device_id, status, error));
    }
    fn on_incoming_call(&self, _offer: CallOffer) {}
    fn on_call_state_changed(&self, info: CallInfo) {
        self.calls.lock().unwrap().push(info);
    }
    fn on_media_stats(&self, _call_id: String, _stats: MediaStats) {}
    fn on_error(&self, _context: String, _message: String) {}
    fn on_auth_required(&self) {
        self.auth_required.fetch_add(1, Ordering::SeqCst);
    }
}

impl App {
    fn ended(&self, call_id: &str) -> Vec<CallInfo> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.call_id == call_id && c.state == CallState::Ended)
            .cloned()
            .collect()
    }

    fn statuses(&self) -> Vec<String> {
        self.registration
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.1.clone())
            .collect()
    }
}

fn registration() -> DeviceRegistration {
    DeviceRegistration {
        platform: "ios".into(),
        push_token: "push".into(),
        bundle_id: None,
        alert_token: None,
        sip: SipCredentials {
            username: "1001".into(),
            password: "pw".into(),
            domain: "sip.example.com".into(),
            registrar: None,
            transport: "tls".into(),
            port: 5061,
            auth_username: None,
            display_name: "Alice".into(),
        },
    }
}

fn engine(instances: &[&Instance]) -> (AriaMobileEngine, App, Arc<Speaker>) {
    init_runtime();
    let mut engine = AriaMobileEngine::new(GatewayConfig {
        base_url: instances[0].url(),
        api_key: "jwt".into(),
    });
    engine.poll_interval = Duration::from_millis(50);
    engine.rebind_stun_budget = Duration::from_millis(10);
    engine.advertise_override = Some("127.0.0.1".into());
    engine.instance_lost_after = (Duration::from_millis(300), Duration::from_secs(3));
    *engine.registrar.failback_timing.write().unwrap() = registration::FailbackTiming {
        first: Duration::from_millis(200),
        max: Duration::from_millis(400),
    };
    // Quiet unless a test speeds it up (`fast_supervisor`).
    *engine.registrar.supervisor_timing.write().unwrap() = slow_supervisor();
    let urls: Vec<String> = instances.iter().map(|i| i.url()).collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    engine.gateway.set_test_routes(&urls);
    let app = App::default();
    engine.set_event_handler(Box::new(app.clone()));
    let speaker = Arc::new(Speaker::default());
    engine.set_audio_bridge(Box::new(Bridge(Arc::clone(&speaker))));
    (engine, app, speaker)
}

fn slow_supervisor() -> registration::SupervisorTiming {
    registration::SupervisorTiming {
        keepalive: Duration::from_secs(3600),
        first: Duration::from_secs(3600),
        max: Duration::from_secs(3600),
    }
}

fn fast_supervisor(engine: &AriaMobileEngine, keepalive_ms: u64) {
    *engine.registrar.supervisor_timing.write().unwrap() = registration::SupervisorTiming {
        keepalive: Duration::from_millis(keepalive_ms),
        first: Duration::from_millis(50),
        max: Duration::from_millis(200),
    };
}

fn flush(engine: &AriaMobileEngine) {
    engine.events.flush();
}

fn wait_until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < limit, "{what}: not within {limit:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn call(engine: &AriaMobileEngine) -> String {
    let id = new_outgoing_call_id();
    engine
        .make_call_with_id(
            id.clone(),
            "1002".into(),
            registration().sip,
            vec![AudioCodec::Pcmu],
        )
        .expect("the call connects");
    id
}

fn local_port_of(engine: &AriaMobileEngine, call_id: &str) -> u16 {
    engine.calls.lock().unwrap()[call_id]
        .media
        .as_ref()
        .unwrap()
        .local_port()
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// The phone moves from Wi-Fi to cellular mid-call: a new local socket (new
/// address), a re-INVITE through the gateway, and the relay follows. Audio
/// keeps flowing both ways and the call never ends.
#[test]
fn a_network_switch_mid_call_keeps_audio_flowing_both_ways() {
    let gw = Instance::start("gw1");
    let relay = Relay::start();
    gw.with_relay(&relay);
    let (engine, app, speaker) = engine(&[&gw]);
    engine.register_device(registration()).unwrap();
    let call_id = call(&engine);

    let wifi_port = local_port_of(&engine, &call_id);
    wait_until("audio both ways on Wi-Fi", Duration::from_secs(3), || {
        relay.heard_from(wifi_port) >= 10 && speaker.loud_frames.load(Ordering::Relaxed) >= 10
    });

    // The network changes. The Wi-Fi socket is now on a dead path: what
    // the relay gets from it (stray in-flight packets) no longer counts.
    engine.notify_network_change();
    wait_until(
        "media moved to a new socket",
        Duration::from_secs(3),
        || local_port_of(&engine, &call_id) != wifi_port,
    );
    let cell_port = local_port_of(&engine, &call_id);
    wait_until(
        "the gateway re-INVITEd with the new address",
        Duration::from_secs(3),
        || {
            gw.0.seen.lock().unwrap().iter().any(|s| {
                s.path.ends_with("/media") && s.body.contains(&format!("m=audio {cell_port} "))
            })
        },
    );

    let heard_before = speaker.loud_frames.load(Ordering::Relaxed);
    wait_until(
        "audio both ways on cellular",
        Duration::from_secs(3),
        || {
            relay.heard_from(cell_port) >= 10
                && speaker.loud_frames.load(Ordering::Relaxed) >= heard_before + 10
        },
    );
    let old_after = relay.heard_from(wifi_port);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        relay.heard_from(wifi_port),
        old_after,
        "nothing is sent from the old socket any more"
    );

    flush(&engine);
    assert!(app.ended(&call_id).is_empty(), "the call must not end");
    assert_eq!(
        engine.get_active_call().unwrap().state,
        CallState::Connected
    );
    assert_eq!(
        engine.get_active_call().unwrap().codec.as_deref(),
        Some("PCMU")
    );
    assert!(
        app.statuses()
            .ends_with(&["recovering".into(), "registered".into()]),
        "{:?}",
        app.statuses()
    );
    engine.hangup(call_id).unwrap();
}

/// gw1 (preferred) goes away: a new call moves the registration to gw2 and
/// is placed there. gw1 comes back: nothing moves while the call is live,
/// and the device fails back once it has ended.
#[test]
fn registration_and_new_calls_move_to_the_other_instance_and_fail_back_later() {
    let gw1 = Instance::start("gw1");
    let gw2 = Instance::start("gw2");
    let relay = Relay::start();
    gw1.with_relay(&relay);
    gw2.with_relay(&relay);
    let (engine, app, _) = engine(&[&gw1, &gw2]);

    engine.register_device(registration()).unwrap();
    assert_eq!(engine.current_gateway(), Some(gw1.authority()));
    assert_eq!(gw2.count("POST", "/v1/devices"), 0, "gw2 is the backup");

    gw1.kill();
    let call_id = call(&engine);
    assert_eq!(engine.current_gateway(), Some(gw2.authority()));
    assert_eq!(
        gw2.count("POST", "/v1/devices"),
        1,
        "registered on gw2 first"
    );
    assert_eq!(
        gw2.count("POST", "/v1/calls"),
        1,
        "then the call is placed there"
    );

    // gw1 is back, but a live call never moves, and neither does the
    // registration while it is up.
    gw1.revive();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        gw1.count("POST", "/v1/devices"),
        1,
        "no failback during a call"
    );
    assert_eq!(engine.current_gateway(), Some(gw2.authority()));

    engine.hangup(call_id.clone()).unwrap();
    wait_until("failed back to gw1", Duration::from_secs(5), || {
        engine.current_gateway() == Some(gw1.authority())
    });
    assert_eq!(gw1.count("POST", "/v1/devices"), 2);
    wait_until("gw2's registration removed", Duration::from_secs(2), || {
        gw2.count("DELETE", "/v1/devices/gw2-dev") == 1
    });
    flush(&engine);
    let reg = app.registration.lock().unwrap().clone();
    let last = reg.last().unwrap();
    assert_eq!(last.1, "registered");
    assert!(last.0.starts_with("gw1-dev"), "the new device_id: {last:?}");
    assert_eq!(app.ended(&call_id).len(), 1);
}

/// A network change after the registered instance died moves the
/// registration, reporting `recovering` then `registered`.
#[test]
fn a_network_change_moves_the_registration_off_a_dead_instance() {
    let gw1 = Instance::start("gw1");
    let gw2 = Instance::start("gw2");
    let (engine, app, _) = engine(&[&gw1, &gw2]);
    engine.register_device(registration()).unwrap();
    gw1.kill();
    engine.notify_network_change();
    wait_until("moved to gw2", Duration::from_secs(3), || {
        engine.current_gateway() == Some(gw2.authority())
    });
    flush(&engine);
    let statuses = app.statuses();
    assert_eq!(
        statuses,
        ["registered", "recovering", "registered"],
        "{statuses:?}"
    );
}

/// A live call on an instance that dies ends once, `Failed`, when another
/// instance shows the gateway side is what went away.
#[test]
fn a_live_call_on_a_dead_instance_ends_cleanly_exactly_once() {
    let gw1 = Instance::start("gw1");
    let gw2 = Instance::start("gw2");
    let relay = Relay::start();
    gw1.with_relay(&relay);
    let (engine, app, _) = engine(&[&gw1, &gw2]);
    engine.register_device(registration()).unwrap();
    let call_id = call(&engine);
    assert_eq!(gw1.count("POST", "/v1/calls"), 1);

    gw1.kill();
    wait_until("the call ended", Duration::from_secs(5), || {
        flush(&engine);
        !app.ended(&call_id).is_empty()
    });
    std::thread::sleep(Duration::from_millis(500));
    flush(&engine);
    let ended = app.ended(&call_id);
    assert_eq!(ended.len(), 1, "exactly one Ended");
    assert_eq!(ended[0].end_reason, Some(EndReason::Failed));
    assert!(engine.get_active_call().is_none());
    // A hangup afterwards finds nothing and reports nothing more.
    let _ = engine.hangup(call_id.clone());
    flush(&engine);
    assert_eq!(app.ended(&call_id).len(), 1);
}

/// A failed heartbeat with no instance reachable reports `failed`.
#[test]
fn recovery_with_no_reachable_instance_reports_failed() {
    let gw1 = Instance::start("gw1");
    let (engine, app, _) = engine(&[&gw1]);
    engine.register_device(registration()).unwrap();
    gw1.kill();
    engine.notify_network_change();
    wait_until("failed reported", Duration::from_secs(3), || {
        flush(&engine);
        app.statuses().last().map(String::as_str) == Some("failed")
    });
    let reg = app.registration.lock().unwrap().clone();
    assert!(reg.last().unwrap().2.is_some(), "with a reason");
}

/// A 401 during recovery asks the app for a token (once) and reports
/// `auth_required`; the new token resumes recovery by itself.
#[test]
fn a_refused_token_during_recovery_resumes_after_set_gateway_token() {
    let gw1 = Instance::start("gw1");
    let (engine, app, _) = engine(&[&gw1]);
    engine.register_device(registration()).unwrap();
    gw1.0.reject_tokens.store(true, Ordering::SeqCst);
    engine.notify_network_change();
    wait_until("auth_required", Duration::from_secs(3), || {
        flush(&engine);
        app.statuses().last().map(String::as_str) == Some("auth_required")
    });
    assert_eq!(app.auth_required.load(Ordering::SeqCst), 1);

    gw1.0.reject_tokens.store(false, Ordering::SeqCst);
    engine.set_gateway_token("jwt-2".into());
    wait_until("registered again", Duration::from_secs(3), || {
        flush(&engine);
        app.statuses().last().map(String::as_str) == Some("registered")
    });
    assert_eq!(
        app.statuses(),
        [
            "registered",
            "recovering",
            "auth_required",
            "recovering",
            "registered"
        ]
    );
}

/// A push for a call offered by the other instance (the registration moved
/// after it was sent) still finds the call.
#[test]
fn an_offer_held_by_the_other_instance_is_found() {
    let gw1 = Instance::start("gw1");
    let gw2 = Instance::start("gw2");
    let (engine, _app, _) = engine(&[&gw1, &gw2]);
    engine.register_device(registration()).unwrap();
    let offer = engine
        .handle_push_notification(PushCallPayload {
            call_token: "gw2-call9".into(),
            caller_uri: "2000@pbx".into(),
            caller_name: None,
            gateway_url: String::new(),
        })
        .expect("the offer is found on gw2");
    assert_eq!(offer.call_token, "gw2-call9");
    assert_eq!(
        gw1.count("GET", "/v1/calls/gw2-call9"),
        1,
        "asked gw1 first"
    );
    assert_eq!(gw2.count("GET", "/v1/calls/gw2-call9"), 1);
    let _ = engine.reject_incoming_call("gw2-call9".into());
}

/// A recovery that fails (the gateway is down) is retried by itself, with
/// no further network change, until the gateway answers: the device ends
/// `registered`, having reported `failed` on the way.
#[test]
fn a_failed_recovery_is_retried_until_the_gateway_is_back() {
    let gw1 = Instance::start("gw1");
    let (engine, app, _) = engine(&[&gw1]);
    engine.register_device(registration()).unwrap();
    fast_supervisor(&engine, 3_600_000);
    gw1.kill();
    engine.notify_network_change();
    wait_until("failed reported", Duration::from_secs(3), || {
        flush(&engine);
        app.statuses().iter().any(|s| s == "failed")
    });
    let tries = gw1.count("POST", "/v1/devices/");
    gw1.revive();
    wait_until("registered again", Duration::from_secs(5), || {
        flush(&engine);
        app.statuses().last().map(String::as_str) == Some("registered")
    });
    assert!(gw1.count("POST", "/v1/devices/") > tries);
}

/// With nothing wrong, the core heartbeats on its own, silently.
#[test]
fn the_core_heartbeats_by_itself_without_noise() {
    let gw1 = Instance::start("gw1");
    let (engine, app, _) = engine(&[&gw1]);
    engine.register_device(registration()).unwrap();
    fast_supervisor(&engine, 80);
    // The supervisor sleeps the old (long) interval once; a failure wakes it.
    gw1.kill();
    engine.notify_network_change();
    gw1.revive();
    wait_until("several heartbeats", Duration::from_secs(5), || {
        gw1.count("POST", "/v1/devices/") >= 4
    });
    wait_until("settled registered", Duration::from_secs(3), || {
        flush(&engine);
        app.statuses().last().map(String::as_str) == Some("registered")
    });
    let n = app.statuses().len();
    std::thread::sleep(Duration::from_millis(400));
    flush(&engine);
    assert_eq!(app.statuses().len(), n, "keepalives report nothing");
}

/// The supervisor holds the registrar weakly: dropping the engine frees it.
#[test]
fn dropping_the_engine_ends_the_supervisor() {
    let gw1 = Instance::start("gw1");
    let (engine, _app, _) = engine(&[&gw1]);
    engine.register_device(registration()).unwrap();
    let weak = Arc::downgrade(&engine.registrar);
    drop(engine);
    wait_until("registrar freed", Duration::from_secs(3), || {
        weak.upgrade().is_none()
    });
}
