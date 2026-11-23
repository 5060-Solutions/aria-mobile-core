//! Mobile media session — RTP send/receive with codec processing.
//!
//! On mobile, the platform (iOS/Android) manages the audio hardware.
//! This module handles:
//! - SDP offer/answer generation and parsing
//! - RTP socket management with receive/send loops
//! - Codec encode/decode via rtp-engine
//! - DTMF generation (RFC 2833)
//! - Platform audio I/O via the PlatformAudioBridge callback

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

use crate::types::*;

// ── Platform Audio Bridge ──────────────────────────────────────────────────

/// Callback trait for platform audio I/O.
/// Implemented by the Android (Oboe/AudioTrack) or iOS (AudioUnit) layer.
pub trait PlatformAudioBridge: Send + Sync + 'static {
    /// Called when decoded PCM audio is ready for playback (speaker).
    /// Samples are mono i16 at 8000 Hz (or 48000 for Opus).
    fn on_playback_audio(&self, samples: Vec<i16>, sample_rate: u32);

    /// Called periodically to request microphone audio for sending.
    /// Should return mono i16 PCM at 8000 Hz, 20ms worth (160 samples).
    /// Return empty vec if no audio available.
    fn on_capture_audio(&self, sample_rate: u32, frame_size: u32) -> Vec<i16>;
}

// ── Media Session ──────────────────────────────────────────────────────────

/// Where decoded call audio is handed to the on-device AI, if it is running.
///
/// Both legs are tapped inside Rust, at the point where the PCM already exists,
/// so audio never crosses the FFI boundary. The tap is a ring-buffer write; the
/// expensive work (resampling, VAD, inference) happens on the AI core's own
/// drain thread, never on an RTP thread.
#[cfg(feature = "ai")]
pub type AiTap = std::sync::Arc<aria_ai_core::session::CallSession>;

/// A media session for mobile — processes RTP with platform audio bridge.
pub struct MobileMediaSession {
    /// The RTP socket. Replaced by [`Rebinder::rebind`] after a network
    /// change; both RTP threads read it per packet, so they move with it.
    rtp_socket: SocketSlot,
    /// Shared remote address — updated by update_remote() and symmetric RTP
    remote_addr: Arc<Mutex<SocketAddr>>,
    local_port: Arc<AtomicU16>,
    codec: AudioCodec,
    muted: Arc<AtomicBool>,
    on_hold: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    ssrc: u32,
    // Stats
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    // Audio levels (RMS * 1000, stored as u64 for atomic access)
    rx_level: Arc<AtomicU64>,
    tx_level: Arc<AtomicU64>,
    /// Optional on-device AI capture for this call. `None` until a host asks
    /// for it, so a call with no AI running costs one uncontended lock per
    /// frame and nothing else.
    #[cfg(feature = "ai")]
    ai_tap: Arc<Mutex<Option<AiTap>>>,
    /// SDES-SRTP contexts, once a crypto line has been agreed.
    ///
    /// Separate inbound and outbound contexts because each carries its own
    /// rollover counter and replay state; sharing one would corrupt both.
    /// `None` means the peer offered no crypto and media is plain RTP — the
    /// only configuration this crate supported before.
    srtp_out: Arc<Mutex<Option<rtp_engine::srtp::SrtpContext>>>,
    srtp_in: Arc<Mutex<Option<rtp_engine::srtp::SrtpContext>>>,
    /// The key material we advertised, held until the answer arrives.
    offered_srtp_key: Arc<Mutex<Option<String>>>,
    /// Our SRTP key once SRTP is on, offered again in a re-offer.
    local_srtp_key: Arc<Mutex<Option<String>>>,
    /// The local conference this call is mixed into, and its leg there.
    /// `None` outside a conference. Read per frame by both RTP threads.
    conference: ConferenceSlot,
    /// The WAV recorder for this call, if it is being recorded. Fed by both
    /// RTP threads; see [`CallRecorder`].
    recorder: RecorderSlot,
}

type RecorderSlot = Arc<Mutex<Option<Arc<CallRecorder>>>>;

/// The current RTP socket of a session.
type SocketSlot = Arc<std::sync::RwLock<Arc<UdpSocket>>>;

fn current_socket(slot: &SocketSlot) -> Arc<UdpSocket> {
    slot.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Moves a running session to a new local socket after a network change
/// (Wi-Fi to cellular, a new IP): see [`MobileMediaSession::rebinder`].
/// Holds only shared handles, so it is used without the call map locked.
#[derive(Clone)]
pub struct Rebinder {
    socket: SocketSlot,
    local_port: Arc<AtomicU16>,
    remote_addr: Arc<Mutex<SocketAddr>>,
    codec: AudioCodec,
    local_srtp_key: Arc<Mutex<Option<String>>>,
}

impl Rebinder {
    /// Bind a new RTP socket on whatever interface now routes, find its
    /// public address by STUN on that socket (within `stun_budget`; the
    /// interface address after that, or `advertise` when given), and swap
    /// it in. The RTP threads send their next frame from it and listen on it
    /// from then on. Returns the new port and the address to advertise.
    ///
    /// # Errors
    /// [`MobileError::MediaError`] if no socket can be bound.
    pub async fn rebind(
        &self,
        stun_budget: std::time::Duration,
        advertise: Option<String>,
    ) -> Result<(u16, String), MobileError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| MobileError::MediaError)?;
        let port = socket
            .local_addr()
            .map_err(|_| MobileError::MediaError)?
            .port();
        let ip = match advertise {
            Some(ip) => ip,
            None => {
                let peer = *self
                    .remote_addr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                advertised_ip(stun_on(&socket, "rebind"), stun_budget, Some(peer)).await
            }
        };
        let old = std::mem::replace(
            &mut *self
                .socket
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Arc::new(socket),
        );
        self.local_port.store(port, Ordering::Relaxed);
        log::info!(
            "RTP rebound from port {} to {port} (advertising {ip})",
            old.local_addr().map(|a| a.port()).unwrap_or(0)
        );
        Ok((port, ip))
    }

    /// An SDP offer for the session's current socket: its codec only (the
    /// call has one), and its SRTP key again if SRTP is on.
    pub fn reoffer_sdp(&self, ip: &str, port: u16) -> String {
        let key = self
            .local_srtp_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        build_sdp_offer(port, ip, &[self.codec], key.as_deref())
    }

    /// Apply the answer to a re-offer: send to the address it gives.
    pub fn apply_answer(&self, sdp: &str) {
        if let Some((addr, _)) = parse_sdp_remote(sdp) {
            if !addr.ip().is_unspecified() && addr.port() != 0 {
                *self
                    .remote_addr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = addr;
            }
        }
    }
}

/// A session's place in a local conference: the mixer and the leg index.
type ConferenceSlot = Arc<Mutex<Option<(Arc<Conference>, usize)>>>;

impl MobileMediaSession {
    /// Create a new media session bound to a local UDP port.
    pub async fn new(remote_addr: SocketAddr, codec: AudioCodec) -> Result<Self, MobileError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| MobileError::MediaError)?;

        let local_port = socket
            .local_addr()
            .map_err(|_| MobileError::MediaError)?
            .port();

        let ssrc: u32 = ::rand::random();

        Ok(Self {
            rtp_socket: Arc::new(std::sync::RwLock::new(Arc::new(socket))),
            remote_addr: Arc::new(Mutex::new(remote_addr)),
            local_port: Arc::new(AtomicU16::new(local_port)),
            codec,
            muted: Arc::new(AtomicBool::new(false)),
            on_hold: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(true)),
            ssrc,
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            rx_level: Arc::new(AtomicU64::new(0)),
            tx_level: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "ai")]
            ai_tap: Arc::new(Mutex::new(None)),
            srtp_out: Arc::new(Mutex::new(None)),
            srtp_in: Arc::new(Mutex::new(None)),
            offered_srtp_key: Arc::new(Mutex::new(None)),
            local_srtp_key: Arc::new(Mutex::new(None)),
            conference: Arc::new(Mutex::new(None)),
            recorder: Arc::new(Mutex::new(None)),
        })
    }

    /// Attach (or with `None`, detach) the on-device AI capture for this call.
    ///
    /// Safe to call at any point in the call: the RTP threads read the tap per
    /// frame, so audio starts flowing to the AI from the next packet and stops
    /// the moment it is cleared. Detaching does not end the AI session — the
    /// caller still owns it and decides when to transcribe.
    #[cfg(feature = "ai")]
    pub fn set_ai_tap(&self, tap: Option<AiTap>) {
        *self
            .ai_tap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tap;
    }

    /// Local RTP port for SDP.
    pub fn local_port(&self) -> u16 {
        self.local_port.load(Ordering::Relaxed)
    }

    /// The current RTP socket (for STUN discovery).
    pub fn rtp_socket(&self) -> Arc<UdpSocket> {
        current_socket(&self.rtp_socket)
    }

    /// A handle that moves this session to a new socket (see [`Rebinder`]).
    pub fn rebinder(&self) -> Rebinder {
        Rebinder {
            socket: Arc::clone(&self.rtp_socket),
            local_port: Arc::clone(&self.local_port),
            remote_addr: Arc::clone(&self.remote_addr),
            codec: self.codec,
            local_srtp_key: Arc::clone(&self.local_srtp_key),
        }
    }

    /// The negotiated codec, by its SDP name (`PCMU`, `PCMA`, `opus`, `G729`).
    pub fn codec_name(&self) -> String {
        self.codec.name().to_string()
    }

    /// Update the remote RTP address (e.g., after receiving SDP answer).
    pub fn update_remote(&self, addr: SocketAddr) {
        *self
            .remote_addr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = addr;
        log::info!("Remote RTP address updated to {}", addr);
    }

    /// Start the RTP receive and send loops with a platform audio bridge.
    pub fn start_with_bridge(&self, bridge: Arc<dyn PlatformAudioBridge>) {
        let codec_type = self.codec.to_rtp_codec();
        let sample_rate = self.codec.clock_rate();
        let frame_samples: u32 = match self.codec {
            AudioCodec::Opus => 960, // 20ms at 48kHz
            _ => 160,                // 20ms at 8kHz
        };

        // ── RX thread: receive RTP → decode → platform playback ──
        {
            let socket = self.rtp_socket.clone();
            let running = self.running.clone();
            let on_hold = self.on_hold.clone();
            let remote_addr = self.remote_addr.clone();
            let pkts_rx = self.packets_received.clone();
            let bytes_rx = self.bytes_received.clone();
            let rx_level = self.rx_level.clone();
            let bridge_rx = bridge.clone();
            #[cfg(feature = "ai")]
            let ai_tap_rx = self.ai_tap.clone();
            let srtp_in = self.srtp_in.clone();
            let conference_rx = self.conference.clone();
            let recorder_rx = self.recorder.clone();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async move {
                    let mut decoder = match rtp_engine::codec::create_decoder(codec_type) {
                        Ok(d) => d,
                        Err(e) => {
                            log::error!("Failed to create decoder: {}", e);
                            return;
                        }
                    };

                    let mut buf = vec![0u8; 2048];
                    log::info!("RTP RX thread started");

                    while running.load(Ordering::Relaxed) {
                        // The socket may have been replaced by a rebind; a
                        // receive on the old one ends within 100 ms.
                        let sock = current_socket(&socket);
                        let recv = tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            sock.recv_from(&mut buf),
                        )
                        .await;

                        let (len, src) = match recv {
                            Ok(Ok((len, src))) => (len, src),
                            Ok(Err(_)) => continue,
                            Err(_) => continue, // timeout
                        };

                        if len < 12 {
                            continue;
                        }

                        // Symmetric RTP: learn the remote address from the
                        // FIRST packet, then hold it.
                        //
                        // Despite the old comment this used to re-point on
                        // every packet from a new source, for the life of the
                        // call — and `remote_addr` is shared with the TX
                        // thread, which is where the microphone goes. One
                        // 12-byte datagram to this port redirected the user's
                        // audio to the sender and silenced the real peer. The
                        // port is published in our SDP and the NAT pinhole is
                        // already open, so no privileged position was needed.
                        //
                        // rtp-engine's own session latches correctly; this loop
                        // was reimplemented by hand and dropped it.
                        {
                            let mut addr = remote_addr
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if addr.port() == 0 {
                                log::info!("Learned remote RTP address: {src}");
                                *addr = src;
                            } else if *addr != src {
                                // Not our peer. Drop it rather than adopting it.
                                continue;
                            }
                        }

                        pkts_rx.fetch_add(1, Ordering::Relaxed);
                        bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

                        if on_hold.load(Ordering::Relaxed) {
                            continue;
                        }

                        // Decrypt before parsing, when SRTP was negotiated.
                        //
                        // A packet that fails to authenticate is dropped, not
                        // played: on an encrypted call, anything that does not
                        // carry a valid tag did not come from the peer.
                        let plain: Vec<u8>;
                        let payload_bytes: &[u8] = {
                            let mut ctx = srtp_in
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            match ctx.as_mut() {
                                Some(ctx) => match ctx.unprotect_rtp(&buf[..len]) {
                                    Ok(p) => {
                                        plain = p;
                                        &plain
                                    }
                                    Err(e) => {
                                        log::debug!("SRTP: dropping unauthenticated packet: {e}");
                                        continue;
                                    }
                                },
                                None => &buf[..len],
                            }
                        };

                        // Parse RTP header
                        let header = match rtp_engine::rtp::RtpHeader::parse(payload_bytes) {
                            Some(h) => h,
                            None => continue,
                        };

                        // Skip DTMF (PT 101)
                        if header.payload_type == 101 {
                            continue;
                        }

                        let payload = &buf[header.header_length()..len];
                        if payload.is_empty() {
                            continue;
                        }

                        // Decode to PCM
                        let mut pcm = Vec::with_capacity(frame_samples as usize);
                        decoder.decode(payload, &mut pcm);

                        if !pcm.is_empty() {
                            // Calculate RMS audio level
                            let sum: f64 = pcm.iter().map(|&s| (s as f64) * (s as f64)).sum();
                            let rms = (sum / pcm.len() as f64).sqrt();
                            rx_level.store((rms * 1000.0) as u64, Ordering::Relaxed);

                            // Tap the far end for the AI before the buffer is
                            // handed to the platform. This is a ring-buffer
                            // write; nothing expensive runs on the RTP thread.
                            #[cfg(feature = "ai")]
                            {
                                if let Some(tap) = ai_tap_rx
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .as_ref()
                                {
                                    if let Err(e) = tap.push_remote(&pcm, sample_rate) {
                                        // Never let an AI problem disturb the
                                        // call: log once per frame at debug and
                                        // keep the audio flowing.
                                        log::debug!("AI tap (remote) dropped a frame: {e}");
                                    }
                                }
                            }

                            if let Some(recorder) = recorder_rx
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .as_ref()
                            {
                                recorder.push_rx(&pcm);
                            }

                            // In a conference the mixer owns the speaker: it
                            // plays the sum of both far ends, once per frame.
                            let conference = conference_rx
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .clone();
                            match conference {
                                Some((conference, leg)) => conference.push_rx(leg, &pcm),
                                None => bridge_rx.on_playback_audio(pcm, sample_rate),
                            }
                        }
                    }

                    log::info!("RTP RX thread stopped");
                });
            });
        }

        // ── TX thread: platform capture → encode → send RTP ──
        {
            let socket = self.rtp_socket.clone();
            let running = self.running.clone();
            let muted = self.muted.clone();
            let on_hold = self.on_hold.clone();
            let remote_addr = self.remote_addr.clone(); // shared with RX for symmetric RTP
            let ssrc = self.ssrc;
            let pt = self.codec.payload_type();
            let pkts_tx = self.packets_sent.clone();
            let bytes_tx = self.bytes_sent.clone();
            let tx_level = self.tx_level.clone();
            #[cfg(feature = "ai")]
            let ai_tap_tx = self.ai_tap.clone();
            let srtp_out = self.srtp_out.clone();
            let conference_tx = self.conference.clone();
            let recorder_tx = self.recorder.clone();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async move {
                    let mut encoder = match rtp_engine::codec::create_encoder(codec_type) {
                        Ok(e) => e,
                        Err(e) => {
                            log::error!("Failed to create encoder: {}", e);
                            return;
                        }
                    };

                    let mut seq: u16 = rand::random();
                    let mut timestamp: u32 = rand::random();
                    let frame_duration = std::time::Duration::from_millis(20);

                    log::info!("RTP TX thread started, ssrc={}, pt={}", ssrc, pt);

                    while running.load(Ordering::Relaxed) {
                        tokio::time::sleep(frame_duration).await;

                        let remote = *remote_addr
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if remote.port() == 0 {
                            continue; // no remote yet
                        }

                        let conference = conference_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        // Get mic audio from platform
                        let pcm = if on_hold.load(Ordering::Relaxed) {
                            vec![0i16; frame_samples as usize]
                        } else if let Some((conference, leg @ 1..)) = &conference {
                            // A conference's second leg sends what the mixer
                            // made for it: the microphone and the first far
                            // end. Only the first leg reads the microphone.
                            conference.pop_tx(*leg, frame_samples as usize)
                        } else {
                            let mic = if muted.load(Ordering::Relaxed) {
                                vec![0i16; frame_samples as usize]
                            } else {
                                let captured = bridge.on_capture_audio(sample_rate, frame_samples);
                                if captured.is_empty() {
                                    vec![0i16; frame_samples as usize]
                                } else {
                                    // Calculate TX audio level
                                    let sum: f64 =
                                        captured.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                    let rms = (sum / captured.len() as f64).sqrt();
                                    tx_level.store((rms * 1000.0) as u64, Ordering::Relaxed);

                                    // Tap the near end. Taken after the mute/hold
                                    // check above, so held or muted audio is
                                    // silence to the AI exactly as it is to the far
                                    // end — the transcript cannot contain words the
                                    // other party never heard.
                                    #[cfg(feature = "ai")]
                                    {
                                        if let Some(tap) = ai_tap_tx
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                                            .as_ref()
                                        {
                                            if let Err(e) = tap.push_local(&captured, sample_rate) {
                                                log::debug!("AI tap (local) dropped a frame: {e}");
                                            }
                                        }
                                    }

                                    captured
                                }
                            };
                            match &conference {
                                // The first leg drives the conference: one
                                // microphone frame, mixed with both far ends.
                                Some((conference, _)) => {
                                    let mixed = conference.mix_frame(&mic);
                                    bridge.on_playback_audio(mixed.speaker, sample_rate);
                                    mixed.to_first
                                }
                                None => mic,
                            }
                        };

                        // The TX loop is the recording's clock: each frame
                        // sent is written, mixed with what the far end said.
                        if let Some(recorder) = recorder_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .as_ref()
                        {
                            recorder.write_frame(&pcm);
                        }

                        // Encode
                        let header = rtp_engine::rtp::RtpHeader::new(pt, seq, timestamp, ssrc);
                        let mut packet = header.to_bytes();
                        encoder.encode(&pcm, &mut packet);

                        // Encrypt, when SRTP was negotiated. A protect failure
                        // drops the frame rather than sending it in the clear —
                        // a silent downgrade mid-call is exactly what an
                        // attacker wants and the user cannot see.
                        {
                            let mut ctx = srtp_out
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if let Some(ctx) = ctx.as_mut() {
                                match ctx.protect_rtp(&packet) {
                                    Ok(sealed) => packet = sealed,
                                    Err(e) => {
                                        log::warn!(
                                            "SRTP: dropping frame we could not protect: {e}"
                                        );
                                        continue;
                                    }
                                }
                            }
                        }

                        // Send, from the current socket (a rebind takes
                        // effect from the next frame).
                        if let Err(e) = current_socket(&socket).send_to(&packet, remote).await {
                            log::warn!("RTP send error: {}", e);
                        } else {
                            pkts_tx.fetch_add(1, Ordering::Relaxed);
                            bytes_tx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                        }

                        seq = seq.wrapping_add(1);
                        timestamp = timestamp.wrapping_add(frame_samples);
                    }

                    log::info!("RTP TX thread stopped");
                });
            });
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Mix `first` and `second` into one local conference: each far end
    /// hears the microphone plus the other far end, and the speaker plays
    /// both far ends. `first` drives the mixer (it reads the microphone and
    /// plays the speaker once per 20 ms frame) at its own codec rate;
    /// `second`'s audio is resampled to and from that rate.
    ///
    /// Both sessions must be off hold for audio to flow; a held leg is
    /// silence both ways, as outside a conference.
    pub fn join_conference(first: &MobileMediaSession, second: &MobileMediaSession) {
        let conference = Arc::new(Conference::new(
            first.codec.clock_rate(),
            second.codec.clock_rate(),
        ));
        *second
            .conference
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((Arc::clone(&conference), 1));
        *first
            .conference
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((conference, 0));
    }

    /// The codec's sample rate: what the RTP loops decode to and encode from.
    pub fn sample_rate(&self) -> u32 {
        self.codec.clock_rate()
    }

    /// Attach (or with `None`, detach) a call recorder. Audio reaches it from
    /// the next frame.
    pub fn set_recorder(&self, recorder: Option<Arc<CallRecorder>>) {
        *self
            .recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = recorder;
    }

    /// Leave the local conference, if in one. From the next frame this
    /// session plays and captures on its own again.
    pub fn leave_conference(&self) {
        *self
            .conference
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn set_mute(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Hold or resume the call. While held, the RTP loops keep running (the
    /// stream stays up and the far end hears silence), but received audio is
    /// dropped before it is decoded, so it reaches neither the speaker nor
    /// the AI tap, and the TX loop does not ask the bridge for microphone
    /// audio. Call waiting relies on this: the bridge is shared, and only the
    /// active call may use it.
    pub fn set_hold(&self, on_hold: bool) {
        self.on_hold.store(on_hold, Ordering::Relaxed);
    }

    pub fn send_dtmf(&self, digit: &str) {
        // Send RFC 2833 DTMF via the RTP socket
        let event = match digit {
            "0" => 0u8,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            "4" => 4,
            "5" => 5,
            "6" => 6,
            "7" => 7,
            "8" => 8,
            "9" => 9,
            "*" => 10,
            "#" => 11,
            _ => {
                log::warn!("Unknown DTMF digit: {}", digit);
                return;
            }
        };

        let digit_owned = digit.to_string();
        let socket = current_socket(&self.rtp_socket);
        let remote_addr = self.remote_addr.clone();
        let ssrc = self.ssrc;

        // Spawn DTMF send on a background task
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let remote = *remote_addr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if remote.port() == 0 {
                    log::warn!("Cannot send DTMF: no remote address");
                    return;
                }

                let timestamp: u32 = rand::random();
                let seq_base: u16 = rand::random();

                // Send 3 DTMF packets with increasing duration
                let durations = [160u16, 320, 480];
                for (i, &duration) in durations.iter().enumerate() {
                    let is_end = i == durations.len() - 1;
                    let mut header = rtp_engine::rtp::RtpHeader::new(
                        101, // telephone-event PT
                        seq_base.wrapping_add(i as u16),
                        timestamp,
                        ssrc,
                    );
                    if i == 0 {
                        header.marker = true;
                    }

                    let mut packet = header.to_bytes();
                    // RFC 2833 payload: event, E bit + volume, duration
                    let end_flag: u8 = if is_end { 0x80 } else { 0 };
                    packet.push(event);
                    packet.push(end_flag | 10); // volume = 10
                    packet.push((duration >> 8) as u8);
                    packet.push(duration as u8);

                    let _ = socket.send_to(&packet, remote).await;

                    // Retransmit end packet
                    if is_end {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        let _ = socket.send_to(&packet, remote).await;
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        let _ = socket.send_to(&packet, remote).await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }

                log::info!("DTMF sent: {} (event={})", digit_owned, event);
            });
        });
    }

    pub fn stats(&self) -> MediaStats {
        MediaStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    /// Get current RX audio level (RMS * 1000).
    pub fn rx_audio_level(&self) -> f32 {
        self.rx_level.load(Ordering::Relaxed) as f32 / 1000.0
    }

    /// Get current TX audio level (RMS * 1000).
    pub fn tx_audio_level(&self) -> f32 {
        self.tx_level.load(Ordering::Relaxed) as f32 / 1000.0
    }

    /// Remember the key we offered, so the answer can be paired with it.
    pub fn set_offered_srtp_key(&self, key: Option<String>) {
        *self
            .offered_srtp_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = key;
    }

    /// Apply a peer's SDP answer: enable SRTP if it accepted our crypto line.
    ///
    /// # Errors
    /// [`MobileError::MediaError`] if the peer's key material is unusable.
    pub fn apply_remote_sdp(&self, remote_sdp: &str) -> Result<(), MobileError> {
        let Some(remote_key) = rtp_engine::srtp::parse_sdp_crypto(remote_sdp) else {
            log::info!("Peer answered without a crypto line; media is plain RTP");
            return Ok(());
        };
        let local_key = self
            .offered_srtp_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(local_key) = local_key else {
            // They sent crypto we never asked for; without our own key there
            // is nothing to protect the outbound direction with.
            log::warn!("Peer sent a crypto line for an offer that had none; ignoring");
            return Ok(());
        };
        self.set_srtp_keys(&local_key, &remote_key)
    }

    /// Install SDES-SRTP key material agreed in SDP.
    ///
    /// `local_key` is what we offered and protects what we send; `remote_key`
    /// came from the peer and opens what we receive. Both are the base64
    /// `inline:` values from the crypto lines.
    ///
    /// # Errors
    /// [`MobileError::MediaError`] if either key is not valid AES_CM_128 key
    /// material — SRTP is refused rather than silently downgraded to plain RTP,
    /// which would be the one outcome the user cannot detect.
    pub fn set_srtp_keys(&self, local_key: &str, remote_key: &str) -> Result<(), MobileError> {
        let out = rtp_engine::srtp::SrtpContext::from_base64(local_key).map_err(|e| {
            log::error!("SRTP: our own key material was rejected: {e}");
            MobileError::MediaError
        })?;
        let inbound = rtp_engine::srtp::SrtpContext::from_base64(remote_key).map_err(|e| {
            log::error!("SRTP: peer key material was rejected: {e}");
            MobileError::MediaError
        })?;
        *self
            .srtp_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(out);
        *self
            .srtp_in
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(inbound);
        *self
            .local_srtp_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(local_key.to_string());
        log::info!("SRTP enabled for this call");
        Ok(())
    }

    /// Whether media on this call is encrypted.
    ///
    /// Reports what was actually negotiated, not what was configured — a UI
    /// that shows a padlock from configuration lies whenever the peer declines
    /// the crypto line.
    #[must_use]
    pub fn srtp_active(&self) -> bool {
        self.srtp_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

// ── Local conference ────────────────────────────────────────────────────────

/// How much decoded audio a conference leg may queue for the mixer, in
/// 20 ms frames. The two legs' RTP threads run on separate clocks; a bound
/// keeps a leg that runs ahead from building up delay (the oldest audio is
/// dropped) instead of growing the queue without limit.
const CONFERENCE_MAX_QUEUED_FRAMES: usize = 4;

/// Add two samples without wrapping: clamp to the i16 range.
pub(crate) fn mix_add(a: i16, b: i16) -> i16 {
    (i32::from(a) + i32::from(b)).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

/// One mixed conference frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MixedFrame {
    /// Both far ends, for the speaker.
    pub speaker: Vec<i16>,
    /// The microphone and the second far end, sent to the first.
    pub to_first: Vec<i16>,
    /// The microphone and the first far end, sent to the second.
    pub to_second: Vec<i16>,
}

/// Mix one frame of a three-way call. All three inputs are at the same rate;
/// the frame is `mic.len()` samples, and a far end that delivered fewer
/// (a late or lost packet) counts as silence for the rest. No far end ever
/// hears itself, and every sum is clamped rather than wrapped.
pub(crate) fn mix_three_way(mic: &[i16], first: &[i16], second: &[i16]) -> MixedFrame {
    let n = mic.len();
    let at = |v: &[i16], i: usize| v.get(i).copied().unwrap_or(0);
    let mut frame = MixedFrame {
        speaker: Vec::with_capacity(n),
        to_first: Vec::with_capacity(n),
        to_second: Vec::with_capacity(n),
    };
    for (i, &m) in mic.iter().enumerate() {
        let (a, b) = (at(first, i), at(second, i));
        frame.speaker.push(mix_add(a, b));
        frame.to_first.push(mix_add(m, b));
        frame.to_second.push(mix_add(m, a));
    }
    frame
}

/// Linear-interpolation resampling between codec rates (8 kHz and 48 kHz in
/// practice). Good enough for speech crossing between two calls; the same
/// rate is passed through untouched.
pub(crate) fn resample(input: &[i16], from: u32, to: u32) -> Vec<i16> {
    if from == to || input.is_empty() || from == 0 || to == 0 {
        return input.to_vec();
    }
    let out_len = (input.len() as u64 * u64::from(to) / u64::from(from)) as usize;
    let step = f64::from(from) / f64::from(to);
    (0..out_len)
        .map(|i| {
            let pos = i as f64 * step;
            let idx = pos as usize;
            let frac = pos - idx as f64;
            let a = f64::from(input[idx.min(input.len() - 1)]);
            let b = f64::from(input[(idx + 1).min(input.len() - 1)]);
            (a + (b - a) * frac).round() as i16
        })
        .collect()
}

/// Append to a bounded sample queue, dropping the oldest samples past `cap`.
fn push_bounded(queue: &mut std::collections::VecDeque<i16>, samples: &[i16], cap: usize) {
    queue.extend(samples.iter().copied());
    let excess = queue.len().saturating_sub(cap);
    queue.drain(..excess);
}

/// Take `n` samples from a queue, padding with silence when it runs short.
fn pop_samples(queue: &mut std::collections::VecDeque<i16>, n: usize) -> Vec<i16> {
    let take = n.min(queue.len());
    let mut out: Vec<i16> = queue.drain(..take).collect();
    out.resize(n, 0);
    out
}

/// One call's audio in a conference.
struct ConferenceLeg {
    /// The leg's codec rate.
    rate: u32,
    /// Decoded far-end audio waiting for the mixer, at the mixer's rate.
    rx: Mutex<std::collections::VecDeque<i16>>,
    /// Mixed audio waiting to be sent on this leg, at the leg's rate. Only
    /// the second leg uses it; the first sends what the mixer returns.
    tx: Mutex<std::collections::VecDeque<i16>>,
}

/// The local mixer of a two-call conference. Leg 0 drives it.
pub(crate) struct Conference {
    /// The mixer's rate: leg 0's codec rate.
    rate: u32,
    legs: [ConferenceLeg; 2],
}

impl Conference {
    pub(crate) fn new(first_rate: u32, second_rate: u32) -> Self {
        let leg = |rate| ConferenceLeg {
            rate,
            rx: Mutex::new(std::collections::VecDeque::new()),
            tx: Mutex::new(std::collections::VecDeque::new()),
        };
        Self {
            rate: first_rate,
            legs: [leg(first_rate), leg(second_rate)],
        }
    }

    fn frame_len(rate: u32) -> usize {
        (rate / 50) as usize
    }

    /// Queue a leg's decoded far-end audio (at the leg's rate) for mixing.
    pub(crate) fn push_rx(&self, leg: usize, pcm: &[i16]) {
        let Some(l) = self.legs.get(leg) else { return };
        let pcm = resample(pcm, l.rate, self.rate);
        let cap = Self::frame_len(self.rate) * CONFERENCE_MAX_QUEUED_FRAMES;
        push_bounded(
            &mut l
                .rx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &pcm,
            cap,
        );
    }

    /// Mix one frame around `mic` (at the mixer's rate): take a frame of
    /// each far end, queue the second leg's share for its TX thread, and
    /// return the frame (the first leg's share and the speaker's).
    pub(crate) fn mix_frame(&self, mic: &[i16]) -> MixedFrame {
        let n = mic.len();
        let take = |l: &ConferenceLeg| {
            pop_samples(
                &mut l
                    .rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                n,
            )
        };
        let (first, second) = (take(&self.legs[0]), take(&self.legs[1]));
        let frame = mix_three_way(mic, &first, &second);
        let out = &self.legs[1];
        let to_second = resample(&frame.to_second, self.rate, out.rate);
        let cap = Self::frame_len(out.rate) * CONFERENCE_MAX_QUEUED_FRAMES;
        push_bounded(
            &mut out
                .tx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &to_second,
            cap,
        );
        frame
    }

    /// The next `n` samples to send on `leg` (silence if the mixer has not
    /// produced them yet).
    pub(crate) fn pop_tx(&self, leg: usize, n: usize) -> Vec<i16> {
        match self.legs.get(leg) {
            Some(l) => pop_samples(
                &mut l
                    .tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                n,
            ),
            None => vec![0; n],
        }
    }
}

// ── Call recording ──────────────────────────────────────────────────────────

/// How much far-end audio the recorder may hold for the next frame, in
/// 20 ms frames, so the RX and TX threads' clocks cannot drift into delay.
const RECORDER_MAX_QUEUED_FRAMES: usize = 4;

/// The 44-byte header of a 16-bit PCM mono WAV file with `data_bytes` of
/// samples.
pub(crate) fn wav_header(sample_rate: u32, data_bytes: u32) -> [u8; 44] {
    let mut h = [0_u8; 44];
    h[0..4].copy_from_slice(b"RIFF");
    h[4..8].copy_from_slice(&data_bytes.saturating_add(36).to_le_bytes());
    h[8..12].copy_from_slice(b"WAVE");
    h[12..16].copy_from_slice(b"fmt ");
    h[16..20].copy_from_slice(&16_u32.to_le_bytes());
    h[20..22].copy_from_slice(&1_u16.to_le_bytes()); // PCM
    h[22..24].copy_from_slice(&1_u16.to_le_bytes()); // mono
    h[24..28].copy_from_slice(&sample_rate.to_le_bytes());
    h[28..32].copy_from_slice(&(sample_rate * 2).to_le_bytes()); // byte rate
    h[32..34].copy_from_slice(&2_u16.to_le_bytes()); // block align
    h[34..36].copy_from_slice(&16_u16.to_le_bytes()); // bits per sample
    h[36..40].copy_from_slice(b"data");
    h[40..44].copy_from_slice(&data_bytes.to_le_bytes());
    h
}

struct RecorderState {
    /// `None` once finished.
    file: Option<std::io::BufWriter<std::fs::File>>,
    data_bytes: u32,
    /// Far-end audio waiting for the next frame.
    rx: std::collections::VecDeque<i16>,
    failed: bool,
}

/// Records one call to a WAV file: 16-bit PCM mono at the codec's rate.
///
/// The RX thread queues decoded far-end audio with [`CallRecorder::push_rx`];
/// the TX thread, once per 20 ms frame, mixes it with the frame it sends and
/// writes the result ([`CallRecorder::write_frame`]). What is sent already
/// carries the microphone and, in a conference, the other far end, so the
/// recording holds everyone the user hears or is heard by. Held or muted
/// time is silence, as it is on the wire.
pub struct CallRecorder {
    path: String,
    sample_rate: u32,
    state: Mutex<RecorderState>,
}

impl CallRecorder {
    /// Create (or replace) the file at `path` and write a header.
    pub fn create(path: &str, sample_rate: u32) -> std::io::Result<Self> {
        use std::io::Write;
        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        file.write_all(&wav_header(sample_rate, 0))?;
        Ok(Self {
            path: path.to_string(),
            sample_rate,
            state: Mutex::new(RecorderState {
                file: Some(file),
                data_bytes: 0,
                rx: std::collections::VecDeque::new(),
                failed: false,
            }),
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RecorderState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queue decoded far-end audio for the next frame.
    pub fn push_rx(&self, pcm: &[i16]) {
        let cap = (self.sample_rate / 50) as usize * RECORDER_MAX_QUEUED_FRAMES;
        let mut state = self.lock();
        if state.file.is_some() {
            push_bounded(&mut state.rx, pcm, cap);
        }
    }

    /// Mix one sent frame with the queued far-end audio and append it.
    /// A write error stops the recording (logged once); the call goes on.
    pub fn write_frame(&self, tx: &[i16]) {
        use std::io::Write;
        let mut state = self.lock();
        if state.file.is_none() || state.failed {
            return;
        }
        let rx = pop_samples(&mut state.rx, tx.len());
        let bytes: Vec<u8> = tx
            .iter()
            .zip(&rx)
            .flat_map(|(&t, &r)| mix_add(t, r).to_le_bytes())
            .collect();
        // A RIFF size is 32 bits: about 12 hours at 48 kHz. Past that the
        // file is complete as it stands.
        let Some(total) = u32::try_from(bytes.len())
            .ok()
            .and_then(|n| state.data_bytes.checked_add(n))
            .filter(|t| t.checked_add(36).is_some())
        else {
            return;
        };
        let result = state
            .file
            .as_mut()
            .expect("checked above")
            .write_all(&bytes);
        match result {
            Ok(()) => state.data_bytes = total,
            Err(e) => {
                log::warn!("Call recording stopped: write failed: {e}");
                state.failed = true;
            }
        }
    }

    /// Finish the file: flush it and write the final sizes into the header.
    /// Later frames are ignored. Idempotent; errors only the first time.
    pub fn finish(&self) -> std::io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut state = self.lock();
        let Some(writer) = state.file.take() else {
            return Ok(());
        };
        state.rx.clear();
        let mut file = writer.into_inner().map_err(|e| e.into_error())?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&wav_header(self.sample_rate, state.data_bytes))?;
        file.sync_all()?;
        if state.failed {
            return Err(std::io::Error::other("a write failed during the recording"));
        }
        Ok(())
    }
}

impl Drop for CallRecorder {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

// ── SDP Helpers ─────────────────────────────────────────────────────────────

/// Build an offer, optionally advertising SDES-SRTP.
///
/// `srtp_key` is the base64 key material we are offering. When present the
/// media line becomes RTP/SAVP and carries a crypto attribute; when absent the
/// offer is plain RTP, which is what this crate did unconditionally before —
/// mobile call media was never encrypted, while the Android network security
/// config claimed confidentiality came from "TLS transport + SRTP".
fn build_sdp_offer(
    local_port: u16,
    local_ip: &str,
    codecs: &[AudioCodec],
    srtp_key: Option<&str>,
) -> String {
    let profile = if srtp_key.is_some() {
        "RTP/SAVP"
    } else {
        "RTP/AVP"
    };
    let mut sdp = format!(
        "v=0\r\n\
         o=aria 0 0 IN IP4 {local_ip}\r\n\
         s=Aria Mobile\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {local_port} {profile}"
    );

    for codec in codecs {
        sdp.push_str(&format!(" {}", codec.payload_type()));
    }
    sdp.push_str(" 101\r\n");

    for codec in codecs {
        let pt = codec.payload_type();
        let name = codec.name();
        let rate = codec.clock_rate();
        if *codec == AudioCodec::Opus {
            sdp.push_str(&format!("a=rtpmap:{pt} {name}/{rate}/2\r\n"));
            sdp.push_str(&format!("a=fmtp:{pt} useinbandfec=1\r\n"));
        } else {
            sdp.push_str(&format!("a=rtpmap:{pt} {name}/{rate}\r\n"));
        }
    }

    sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
    sdp.push_str("a=fmtp:101 0-16\r\n");
    if let Some(key) = srtp_key {
        sdp.push_str(&rtp_engine::srtp::build_sdp_crypto_line(key));
        sdp.push_str("\r\n");
    }
    sdp.push_str("a=sendrecv\r\n");

    sdp
}

fn build_sdp_answer(local_port: u16, local_ip: &str, chosen_codec: AudioCodec) -> String {
    let pt = chosen_codec.payload_type();
    let name = chosen_codec.name();
    let rate = chosen_codec.clock_rate();

    let mut sdp = format!(
        "v=0\r\n\
         o=aria 0 0 IN IP4 {local_ip}\r\n\
         s=Aria Mobile\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {local_port} RTP/AVP {pt} 101\r\n"
    );

    if chosen_codec == AudioCodec::Opus {
        sdp.push_str(&format!("a=rtpmap:{pt} {name}/{rate}/2\r\n"));
        sdp.push_str(&format!("a=fmtp:{pt} useinbandfec=1\r\n"));
    } else {
        sdp.push_str(&format!("a=rtpmap:{pt} {name}/{rate}\r\n"));
    }

    sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
    sdp.push_str("a=fmtp:101 0-16\r\n");
    sdp.push_str("a=sendrecv\r\n");

    sdp
}

/// Parse the remote RTP address and preferred codec from an SDP.
fn parse_sdp_remote(sdp: &str) -> Option<(SocketAddr, AudioCodec)> {
    let mut remote_ip = None;
    let mut remote_port = None;
    let mut first_codec = None;

    for line in sdp.lines() {
        let line = line.trim();
        if let Some(ip) = line.strip_prefix("c=IN IP4 ") {
            remote_ip = Some(ip.trim().to_string());
        } else if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                remote_port = parts[1].parse::<u16>().ok();
                if let Some(pt_str) = parts.get(3) {
                    first_codec = match *pt_str {
                        "0" => Some(AudioCodec::Pcmu),
                        "8" => Some(AudioCodec::Pcma),
                        "18" => Some(AudioCodec::G729),
                        "111" => Some(AudioCodec::Opus),
                        _ => None,
                    };
                }
            }
        }
    }

    match (remote_ip, remote_port, first_codec) {
        (Some(ip), Some(port), Some(codec)) => {
            let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
            Some((addr, codec))
        }
        _ => None,
    }
}

/// Public wrapper for parse_sdp_remote.
pub fn parse_sdp_remote_pub(sdp: &str) -> Option<(SocketAddr, AudioCodec)> {
    parse_sdp_remote(sdp)
}

/// Negotiate codec — pick the first from our preferences that appears in the offer.
fn negotiate_codec(offer_sdp: &str, our_prefs: &[AudioCodec]) -> AudioCodec {
    let offered: Vec<u8> = offer_sdp
        .lines()
        .find(|l| l.trim().starts_with("m=audio"))
        .map(|l| {
            l.split_whitespace()
                .skip(3)
                .filter_map(|pt| pt.parse().ok())
                .collect()
        })
        .unwrap_or_default();

    for pref in our_prefs {
        if offered.contains(&pref.payload_type()) {
            return *pref;
        }
    }

    AudioCodec::Pcmu
}

/// Create a media session as the answerer (incoming call).
pub async fn create_answer_session(
    offer_sdp: &str,
    preferred_codecs: &[AudioCodec],
) -> Result<(MobileMediaSession, String), MobileError> {
    let (remote_addr, _offer_codec) = parse_sdp_remote(offer_sdp).ok_or(MobileError::MediaError)?;

    let chosen = negotiate_codec(offer_sdp, preferred_codecs);

    let session = MobileMediaSession::new(remote_addr, chosen).await?;

    // Use the actual RTP socket for STUN so NAT mapping matches
    let local_ip = advertised_ip(
        stun_on(&session.rtp_socket(), "answer"),
        STUN_BUDGET,
        Some(remote_addr),
    )
    .await;
    let answer_sdp = build_sdp_answer(session.local_port(), &local_ip, chosen);

    Ok((session, answer_sdp))
}

/// Create a media session as the offerer (outgoing call).
pub async fn create_offer_session(
    preferred_codecs: &[AudioCodec],
) -> Result<(MobileMediaSession, String), MobileError> {
    let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let codec = preferred_codecs
        .first()
        .copied()
        .unwrap_or(AudioCodec::Pcmu);

    let session = MobileMediaSession::new(placeholder, codec).await?;

    // Discover public IP using the ACTUAL RTP socket so the NAT mapping matches.
    // If we use a different socket, the NAT mapping won't match and RTP won't flow.
    let local_ip = advertised_ip(stun_on(&session.rtp_socket(), "offer"), STUN_BUDGET, None).await;

    let codecs = if preferred_codecs.is_empty() {
        vec![AudioCodec::Pcmu, AudioCodec::Pcma, AudioCodec::Opus]
    } else {
        preferred_codecs.to_vec()
    };

    // Offer SDES-SRTP. The key is generated per call and kept on the session
    // so the answer's crypto line can be paired with it once it arrives.
    //
    // Offered, not required: a PBX that answers without a crypto line still
    // gets a working plain-RTP call, which is what every deployment has today.
    // Refusing outright would break every existing installation on upgrade;
    // what matters is that the encrypted path now exists and that
    // `srtp_active()` reports the truth either way.
    let (offer_key, offer_sdp) = match rtp_engine::srtp::SrtpContext::generate() {
        Ok((_ctx, key)) => {
            let sdp = build_sdp_offer(session.local_port(), &local_ip, &codecs, Some(&key));
            (Some(key), sdp)
        }
        Err(e) => {
            log::warn!("SRTP: could not generate key material, offering plain RTP: {e}");
            (
                None,
                build_sdp_offer(session.local_port(), &local_ip, &codecs, None),
            )
        }
    };
    session.set_offered_srtp_key(offer_key);

    Ok((session, offer_sdp))
}

/// How long STUN discovery may take in all, for one SDP offer or answer.
///
/// rtp-engine's STUN resolves the server with no timeout and, on failure, a
/// second discovery runs; unbounded, that could hold up a call for 30 s or
/// more. Past this budget the SDP carries the local interface address.
pub(crate) const STUN_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// The public address of `socket` by STUN, so the NAT mapping matches the
/// RTP socket, then by a plain STUN query if that fails. `None` if neither
/// answers.
async fn stun_on(socket: &UdpSocket, label: &'static str) -> Option<String> {
    match rtp_engine::discover_public_address(socket).await {
        Ok(result) => {
            log::info!(
                "STUN on RTP socket ({label}): public {}:{}",
                result.public_ip,
                result.public_port
            );
            Some(result.public_ip.to_string())
        }
        Err(_) => rtp_engine::stun_discover(0)
            .await
            .ok()
            .map(|result| result.public_ip.to_string()),
    }
}

/// The address to advertise in SDP: what `discovery` finds within `budget`,
/// otherwise the local interface address.
pub(crate) async fn advertised_ip(
    discovery: impl std::future::Future<Output = Option<String>>,
    budget: std::time::Duration,
    towards: Option<SocketAddr>,
) -> String {
    match tokio::time::timeout(budget, discovery).await {
        Ok(Some(ip)) => ip,
        Ok(None) => {
            log::warn!("STUN failed; advertising the local interface address");
            local_interface_ip_towards(towards).await
        }
        Err(_) => {
            log::warn!("STUN took over {budget:?}; advertising the local interface address");
            local_interface_ip_towards(towards).await
        }
    }
}

/// The address of the interface that routes to `towards` (the media peer,
/// when known), else to the internet at large. Connecting a UDP socket only
/// consults the routing table; nothing is sent.
pub(crate) async fn local_interface_ip_towards(towards: Option<SocketAddr>) -> String {
    let target = towards
        .filter(|a| !a.ip().is_unspecified() && a.port() != 0)
        .unwrap_or_else(|| SocketAddr::from(([8, 8, 8, 8], 80)));
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
        if sock.connect(target).await.is_ok() {
            if let Ok(addr) = sock.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "0.0.0.0".to_string()
}

/// End-to-end proof that call audio reaches the on-device AI without crossing
/// the FFI boundary.
///
/// These drive the real path rather than calling the tap directly: a
/// `MobileMediaSession` is started, genuine RTP is sent at its socket, and the
/// AI session is checked for accumulated audio. A tap wired to the wrong leg,
/// dropped after mute, or left attached after detach would fail here.
#[cfg(all(test, feature = "ai"))]
mod ai_tap_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;

    use aria_ai_core::session::{CallSession, SessionConfig};

    /// Records what the platform layer was handed, so we can prove the tap does not
    /// steal or corrupt the audio the user actually hears.
    #[derive(Default)]
    struct RecordingBridge {
        played: Mutex<Vec<i16>>,
        /// Mic audio this bridge will hand to the TX thread each time it is asked.
        capture: Mutex<Vec<i16>>,
    }

    impl PlatformAudioBridge for RecordingBridge {
        fn on_playback_audio(&self, samples: Vec<i16>, _sample_rate: u32) {
            self.played
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(&samples);
        }

        fn on_capture_audio(&self, _sample_rate: u32, frame_size: u32) -> Vec<i16> {
            let src = self
                .capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if src.is_empty() {
                return vec![0_i16; frame_size as usize];
            }
            // Repeat the canned tone for as long as the session asks.
            src.iter()
                .cycle()
                .take(frame_size as usize)
                .copied()
                .collect()
        }
    }

    /// One 20 ms G.711 µ-law RTP packet of 440 Hz tone.
    fn ulaw_rtp_packet(seq: u16, timestamp: u32, ssrc: u32, phase: u32) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(12 + 160);
        pkt.push(0x80); // V=2
        pkt.push(0); // PT=0 (PCMU)
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&timestamp.to_be_bytes());
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        for i in 0..160_u32 {
            let t = f64::from(phase + i) / 8000.0;
            let sample = (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 12000.0) as i16;
            pkt.push(linear_to_ulaw(sample));
        }
        pkt
    }

    /// G.711 µ-law encoder, so the test feeds a decoder real audio rather than noise.
    fn linear_to_ulaw(sample: i16) -> u8 {
        const BIAS: i16 = 0x84;
        const CLIP: i16 = 32635;
        let (sign, mut mag) = if sample < 0 {
            (0x80_u8, -sample.max(-CLIP))
        } else {
            (0, sample.min(CLIP))
        };
        mag = mag.saturating_add(BIAS);
        let exponent = match mag {
            m if m <= 0x00FF => 0,
            m if m <= 0x01FF => 1,
            m if m <= 0x03FF => 2,
            m if m <= 0x07FF => 3,
            m if m <= 0x0FFF => 4,
            m if m <= 0x1FFF => 5,
            m if m <= 0x3FFF => 6,
            _ => 7,
        };
        let mantissa = (mag >> (exponent + 3)) & 0x0F;
        !(sign | ((exponent as u8) << 4) | mantissa as u8)
    }

    struct Fixture {
        session: MobileMediaSession,
        ai: Arc<CallSession>,
        bridge: Arc<RecordingBridge>,
        port: u16,
        /// The far end: the session's remote address, so the RX loop's
        /// source latch accepts what it sends, and where TX goes.
        peer: tokio::net::UdpSocket,
    }

    async fn fixture(call_id: &str) -> Fixture {
        // The tone must come from the session's remote address: RX drops
        // packets from any other source. TX goes back to the same socket,
        // which nothing reads.
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let remote = peer.local_addr().expect("peer addr");
        let session = MobileMediaSession::new(remote, AudioCodec::Pcmu)
            .await
            .expect("media session");
        let port = session.local_port();

        let ai = CallSession::start(SessionConfig::new(call_id)).expect("ai session");
        session.set_ai_tap(Some(ai.clone()));

        let bridge = Arc::new(RecordingBridge::default());
        session.start_with_bridge(bridge.clone());

        Fixture {
            session,
            ai,
            bridge,
            port,
            peer,
        }
    }

    /// Send `n` packets of tone from `tx` at the session's RTP port.
    async fn send_tone(tx: &tokio::net::UdpSocket, port: u16, n: u16) {
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        let ssrc = 0x1234_5678;
        for i in 0..n {
            let pkt = ulaw_rtp_packet(i, u32::from(i) * 160, ssrc, u32::from(i) * 160);
            let _ = tx.send_to(&pkt, target).await;
            // Real pacing: the RX path is a live socket loop, not a batch API.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Let the last packets drain through decode and into the tap.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn far_end_rtp_reaches_the_ai_and_still_reaches_the_speaker() {
        let f = fixture("call-tap-1").await;
        send_tone(&f.peer, f.port, 50).await;

        // push_* only fills the ring buffer; captured_ms counts what pump()
        // has drained and resampled. In production this is the AI core's own
        // drain thread; here it is explicit so the test is deterministic.
        f.ai.pump().expect("pump");
        let (_local, remote) = f.ai.tap().stats();
        assert!(
            remote.captured_ms > 0,
            "the AI received no far-end audio (captured_ms = 0)"
        );
        assert_eq!(
            remote.source_rate_hz, 8000,
            "far-end leg should report the RTP clock rate"
        );

        // The tap must not consume the audio the user is supposed to hear.
        let played = f
            .bridge
            .played
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert!(played > 0, "platform bridge got no playback audio");

        f.session.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn detaching_the_tap_stops_the_flow_without_ending_the_call() {
        let f = fixture("call-tap-2").await;
        send_tone(&f.peer, f.port, 25).await;
        f.ai.pump().expect("pump");
        let before = f.ai.tap().stats().1.captured_ms;
        assert!(before > 0, "expected audio before detaching");

        f.session.set_ai_tap(None);
        send_tone(&f.peer, f.port, 25).await;
        f.ai.pump().expect("pump");
        let after = f.ai.tap().stats().1.captured_ms;
        assert_eq!(after, before, "audio kept flowing to the AI after detach");

        // Audio to the user must be unaffected by detaching the AI.
        let played = f
            .bridge
            .played
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert!(played > 0, "detaching the tap broke playback");

        f.session.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn microphone_audio_reaches_the_ai_as_the_near_end() {
        // The positive control for the mute test below. Without this, "muted is
        // silent" would also hold if the near-end tap were never wired at all.
        let f = fixture("call-tap-4").await;
        *f.bridge
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = vec![8000_i16; 160];

        tokio::time::sleep(Duration::from_millis(400)).await;
        f.ai.pump().expect("pump");

        let local = f.ai.tap().stats().0;
        assert!(
            local.captured_ms > 0,
            "near-end microphone audio never reached the AI"
        );
        f.session.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_held_call_reaches_neither_the_ai_nor_the_speaker() {
        // With call waiting the held call's far end must not be transcribed
        // into the active call's insight, nor played over it.
        let f = fixture("call-tap-held").await;
        *f.bridge
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = vec![8000_i16; 160];
        f.session.set_hold(true);
        send_tone(&f.peer, f.port, 50).await;

        f.ai.pump().expect("pump");
        let (local, remote) = f.ai.tap().stats();
        assert_eq!(remote.captured_ms, 0, "held far-end audio reached the AI");
        assert_eq!(local.captured_ms, 0, "held microphone audio reached the AI");
        let played = f
            .bridge
            .played
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert_eq!(played, 0, "held call audio reached the speaker");
        f.session.stop();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_muted_microphone_is_silence_to_the_ai_as_well() {
        // The transcript must not contain words the far end never heard.
        let f = fixture("call-tap-3").await;
        *f.bridge
            .capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = vec![8000_i16; 160];

        f.session.set_mute(true);
        // TX only runs once a remote address is known; the fixture already has one.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Pump first, or this test passes simply because nothing was drained —
        // it has to be capable of failing.
        f.ai.pump().expect("pump");
        let local = f.ai.tap().stats().0;
        assert_eq!(
            local.captured_ms, 0,
            "muted microphone audio reached the AI"
        );

        f.session.stop();
    }
}

/// A held call keeps its RTP stream running but neither plays the far end
/// nor reads the microphone: with call waiting, the other call owns both.
#[cfg(test)]
mod hold_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Counts what the session hands the platform and asks it for.
    #[derive(Default)]
    struct CountingBridge {
        played: AtomicUsize,
        captures: AtomicUsize,
    }

    impl PlatformAudioBridge for CountingBridge {
        fn on_playback_audio(&self, samples: Vec<i16>, _sample_rate: u32) {
            self.played.fetch_add(samples.len(), Ordering::Relaxed);
        }

        fn on_capture_audio(&self, _sample_rate: u32, frame_size: u32) -> Vec<i16> {
            self.captures.fetch_add(1, Ordering::Relaxed);
            vec![1000_i16; frame_size as usize]
        }
    }

    /// One 20 ms PCMU packet (µ-law 0x00 is a loud sample, so it decodes to
    /// non-empty PCM).
    fn rtp_packet(seq: u16) -> Vec<u8> {
        let mut pkt = vec![0x80, 0];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        pkt.extend_from_slice(&0x1234_5678_u32.to_be_bytes());
        pkt.extend(std::iter::repeat_n(0_u8, 160));
        pkt
    }

    /// Send `n` packets from `peer` to the session on `port`, then let them
    /// drain through the RX loop.
    async fn send(peer: &UdpSocket, port: u16, from_seq: u16, n: u16) {
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        for seq in from_seq..from_seq + n {
            let _ = peer.send_to(&rtp_packet(seq), target).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_call_neither_plays_nor_reads_the_microphone() {
        // No remote yet: it is learned from the first packet, as on an
        // outgoing call, so TX goes back to the test's socket.
        let placeholder: SocketAddr = "0.0.0.0:0".parse().expect("addr");
        let session = MobileMediaSession::new(placeholder, AudioCodec::Pcmu)
            .await
            .expect("media session");
        let port = session.local_port();
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind");

        session.set_hold(true);
        let bridge = Arc::new(CountingBridge::default());
        session.start_with_bridge(bridge.clone());
        send(&peer, port, 0, 30).await;

        assert_eq!(
            bridge.played.load(Ordering::Relaxed),
            0,
            "held call audio reached the speaker"
        );
        assert_eq!(
            bridge.captures.load(Ordering::Relaxed),
            0,
            "a held call read the microphone"
        );
        let stats = session.stats();
        assert!(stats.packets_received > 0, "RX stopped while held");
        assert!(stats.packets_sent > 0, "RTP stopped while held");

        // The positive control: resumed, the same path plays and captures.
        session.set_hold(false);
        send(&peer, port, 30, 30).await;
        assert!(
            bridge.played.load(Ordering::Relaxed) > 0,
            "no playback once resumed"
        );
        assert!(
            bridge.captures.load(Ordering::Relaxed) > 0,
            "no capture once resumed"
        );
        session.stop();
    }
}

#[cfg(test)]
mod srtp_negotiation_tests {
    use super::{build_sdp_offer, AudioCodec};

    /// Mobile media was never encrypted: the offer was always RTP/AVP with no
    /// crypto attribute, while the Android network security config claimed
    /// confidentiality came from "TLS transport + SRTP".
    #[test]
    fn an_offer_with_a_key_advertises_savp_and_crypto() {
        let sdp = build_sdp_offer(
            10000,
            "203.0.113.5",
            &[AudioCodec::Pcmu],
            Some("dGVzdGtleQ=="),
        );
        assert!(sdp.contains("RTP/SAVP"), "{sdp}");
        assert!(sdp.contains("a=crypto:"), "{sdp}");
    }

    /// Plain RTP must still be offerable: refusing outright would break every
    /// deployment that does not answer with a crypto line.
    #[test]
    fn an_offer_without_a_key_stays_plain_rtp() {
        let sdp = build_sdp_offer(10000, "203.0.113.5", &[AudioCodec::Pcmu], None);
        assert!(sdp.contains("RTP/AVP"), "{sdp}");
        assert!(!sdp.contains("RTP/SAVP"), "{sdp}");
        assert!(!sdp.contains("a=crypto:"), "{sdp}");
    }

    /// The crypto attribute must sit inside the media section, after the
    /// rtpmap lines — a crypto line above m= is not part of the stream.
    #[test]
    fn the_crypto_line_is_inside_the_media_section() {
        let sdp = build_sdp_offer(
            10000,
            "203.0.113.5",
            &[AudioCodec::Pcmu],
            Some("dGVzdGtleQ=="),
        );
        let m = sdp.find("m=audio").expect("media line");
        let crypto = sdp.find("a=crypto:").expect("crypto line");
        assert!(crypto > m, "crypto must follow the m= line:\n{sdp}");
    }
}

#[cfg(test)]
mod conference_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn mix_add_clamps_instead_of_wrapping() {
        assert_eq!(mix_add(1000, 2000), 3000);
        assert_eq!(mix_add(30000, 30000), i16::MAX);
        assert_eq!(mix_add(-30000, -30000), i16::MIN);
        assert_eq!(mix_add(i16::MIN, i16::MAX), -1);
        assert_eq!(mix_add(-5, 5), 0);
    }

    #[test]
    fn nobody_hears_themselves_and_everyone_hears_the_rest() {
        let mic = [100_i16; 4];
        let first = [10_i16; 4];
        let second = [1_i16; 4];
        let f = mix_three_way(&mic, &first, &second);
        assert_eq!(f.speaker, [11; 4], "speaker: both far ends, not the mic");
        assert_eq!(f.to_first, [101; 4], "first: mic + second");
        assert_eq!(f.to_second, [110; 4], "second: mic + first");
    }

    #[test]
    fn a_short_far_end_frame_counts_as_silence_and_loud_sums_clip() {
        let mic = [20000_i16, 20000, -20000, 0];
        let first = [20000_i16, -20000];
        let second: [i16; 0] = [];
        let f = mix_three_way(&mic, &first, &second);
        assert_eq!(f.speaker, [20000, -20000, 0, 0]);
        assert_eq!(f.to_first, [20000, 20000, -20000, 0]);
        assert_eq!(f.to_second, [i16::MAX, 0, -20000, 0]);
        assert_eq!(f.to_second.len(), mic.len());
    }

    #[test]
    fn resampling_keeps_duration_and_level() {
        let narrow = vec![1000_i16; 160];
        let wide = resample(&narrow, 8000, 48000);
        assert_eq!(wide.len(), 960);
        assert!(wide.iter().all(|&s| s == 1000));
        let back = resample(&wide, 48000, 8000);
        assert_eq!(back.len(), 160);
        assert!(back.iter().all(|&s| s == 1000));
        assert_eq!(resample(&narrow, 8000, 8000), narrow);
        // A ramp stays monotonic through upsampling.
        let ramp: Vec<i16> = (0..160).map(|i| i * 10).collect();
        let up = resample(&ramp, 8000, 48000);
        assert!(up.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn the_mixer_routes_each_legs_audio_and_bounds_its_queues() {
        let conf = Conference::new(8000, 48000);
        conf.push_rx(0, &[300; 160]);
        conf.push_rx(1, &[20; 960]); // 48 kHz leg, resampled to 8 kHz
        let f = conf.mix_frame(&[1000; 160]);
        assert_eq!(f.speaker, vec![320; 160]);
        assert_eq!(f.to_first, vec![1020; 160]);
        // The second leg's share is queued at its own rate.
        assert_eq!(conf.pop_tx(1, 960), vec![1300; 960]);
        // Nothing queued: silence, not stale audio.
        assert_eq!(conf.pop_tx(1, 960), vec![0; 960]);
        let f = conf.mix_frame(&[0; 160]);
        assert_eq!(f.speaker, vec![0; 160]);

        // A leg that runs ahead is capped, oldest audio dropped.
        for i in 0..20 {
            conf.push_rx(0, &[i; 160]);
        }
        let queued = conf.legs[0].rx.lock().unwrap().len();
        assert_eq!(queued, 160 * CONFERENCE_MAX_QUEUED_FRAMES);
        assert_eq!(conf.legs[0].rx.lock().unwrap()[0], 16);
    }

    /// Mic at a fixed level; records what reaches the speaker.
    #[derive(Default)]
    struct MicBridge {
        played: Mutex<Vec<i16>>,
        captures: std::sync::atomic::AtomicUsize,
    }

    impl PlatformAudioBridge for MicBridge {
        fn on_playback_audio(&self, samples: Vec<i16>, _sample_rate: u32) {
            self.played.lock().unwrap().extend(samples);
        }

        fn on_capture_audio(&self, _sample_rate: u32, frame_size: u32) -> Vec<i16> {
            self.captures.fetch_add(1, Ordering::Relaxed);
            vec![2000; frame_size as usize]
        }
    }

    fn pcmu_packet(seq: u16, level: i16) -> Vec<u8> {
        let mut pkt =
            rtp_engine::rtp::RtpHeader::new(0, seq, u32::from(seq) * 160, 0x55).to_bytes();
        let mut enc = rtp_engine::codec::create_encoder(rtp_engine::CodecType::Pcmu).unwrap();
        enc.encode(&[level; 160], &mut pkt);
        pkt
    }

    /// Decode every PCMU packet a far end received, as average levels.
    async fn received_levels(peer: &UdpSocket) -> Vec<i32> {
        let mut dec = rtp_engine::codec::create_decoder(rtp_engine::CodecType::Pcmu).unwrap();
        let mut levels = Vec::new();
        let mut buf = [0_u8; 2048];
        while let Ok(Ok((len, _))) =
            tokio::time::timeout(Duration::from_millis(50), peer.recv_from(&mut buf)).await
        {
            let mut pcm = Vec::new();
            dec.decode(&buf[12..len], &mut pcm);
            if !pcm.is_empty() {
                levels.push(pcm.iter().map(|&s| i32::from(s)).sum::<i32>() / pcm.len() as i32);
            }
        }
        levels
    }

    fn near(level: i32, want: i32) -> bool {
        (level - want).abs() <= want / 20 + 40
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_live_sessions_are_mixed_both_ways_and_to_the_speaker() {
        let peer_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = MobileMediaSession::new(peer_a.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        let b = MobileMediaSession::new(peer_b.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        MobileMediaSession::join_conference(&a, &b);
        let bridge = Arc::new(MicBridge::default());
        a.start_with_bridge(bridge.clone());
        b.start_with_bridge(bridge.clone());

        let to_a: SocketAddr = format!("127.0.0.1:{}", a.local_port()).parse().unwrap();
        let to_b: SocketAddr = format!("127.0.0.1:{}", b.local_port()).parse().unwrap();
        for seq in 0..40 {
            peer_a.send_to(&pcmu_packet(seq, 1000), to_a).await.unwrap();
            peer_b.send_to(&pcmu_packet(seq, 4000), to_b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        a.stop();
        b.stop();
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Each far end hears the mic (2000) plus the other far end.
        let at_a = received_levels(&peer_a).await;
        let at_b = received_levels(&peer_b).await;
        assert!(at_a.iter().any(|&l| near(l, 6000)), "A heard {at_a:?}");
        assert!(at_b.iter().any(|&l| near(l, 3000)), "B heard {at_b:?}");
        // Never itself on top: A never hears 2000 + 1000 + ...
        assert!(!at_a.iter().any(|&l| l > 6500), "A heard itself: {at_a:?}");
        assert!(!at_b.iter().any(|&l| l > 3500), "B heard itself: {at_b:?}");

        // The speaker plays both far ends (1000 + 4000), and never the mic
        // or a far end on its own after the mixer filled.
        let played = bridge.played.lock().unwrap().clone();
        let frames: Vec<i32> = played
            .chunks(160)
            .map(|c| c.iter().map(|&s| i32::from(s)).sum::<i32>() / c.len() as i32)
            .collect();
        assert!(frames.iter().any(|&l| near(l, 5000)), "speaker {frames:?}");
        // One microphone reader: the second leg never asks the platform.
        let captures = bridge.captures.load(Ordering::Relaxed);
        assert!(captures > 0 && captures <= 45, "{captures} captures");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn after_leaving_a_session_plays_and_captures_on_its_own() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = MobileMediaSession::new(peer.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        let other = MobileMediaSession::new(peer.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        MobileMediaSession::join_conference(&other, &a);
        a.leave_conference();
        let bridge = Arc::new(MicBridge::default());
        a.start_with_bridge(bridge.clone());
        let to_a: SocketAddr = format!("127.0.0.1:{}", a.local_port()).parse().unwrap();
        for seq in 0..10 {
            peer.send_to(&pcmu_packet(seq, 1000), to_a).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        a.stop();
        assert!(bridge.captures.load(Ordering::Relaxed) > 0);
        let played = bridge.played.lock().unwrap().clone();
        assert!(!played.is_empty());
        let level = played.iter().map(|&s| i32::from(s)).sum::<i32>() / played.len() as i32;
        assert!(near(level, 1000), "{level}");
    }
}

#[cfg(test)]
pub(crate) mod recording_tests {
    use super::*;
    use std::time::Duration;

    pub(crate) fn temp_wav(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("aria-rec-{name}-{}.wav", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned()
    }

    /// Check a WAV file's header against its length and return
    /// (sample rate, samples).
    pub(crate) fn read_wav(path: &str) -> (u32, Vec<i16>) {
        let bytes = std::fs::read(path).expect("read wav");
        assert!(bytes.len() >= 44, "shorter than a header");
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let u16_at = |i: usize| u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
        assert_eq!(&bytes[0..4], b"RIFF");
        assert_eq!(u32_at(4) as usize, bytes.len() - 8, "RIFF size");
        assert_eq!(&bytes[8..16], b"WAVEfmt ");
        assert_eq!(u32_at(16), 16);
        assert_eq!(u16_at(20), 1, "PCM");
        assert_eq!(u16_at(22), 1, "mono");
        let rate = u32_at(24);
        assert_eq!(u32_at(28), rate * 2, "byte rate");
        assert_eq!(u16_at(32), 2, "block align");
        assert_eq!(u16_at(34), 16, "bits");
        assert_eq!(&bytes[36..40], b"data");
        assert_eq!(u32_at(40) as usize, bytes.len() - 44, "data size");
        let samples = bytes[44..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| i16::from_le_bytes(*c))
            .collect();
        (rate, samples)
    }

    #[test]
    fn the_header_describes_16_bit_mono_pcm() {
        let h = wav_header(48000, 1000);
        assert_eq!(&h[0..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(h[4..8].try_into().unwrap()), 1036);
        assert_eq!(u32::from_le_bytes(h[24..28].try_into().unwrap()), 48000);
        assert_eq!(u32::from_le_bytes(h[28..32].try_into().unwrap()), 96000);
        assert_eq!(u32::from_le_bytes(h[40..44].try_into().unwrap()), 1000);
    }

    #[test]
    fn frames_mix_the_far_end_with_what_is_sent() {
        let path = temp_wav("mix");
        let rec = CallRecorder::create(&path, 8000).unwrap();
        rec.push_rx(&[100; 160]);
        rec.write_frame(&[1000; 160]);
        // No far-end audio for this frame: what was sent alone.
        rec.write_frame(&[-30000; 160]);
        rec.push_rx(&[-30000; 160]);
        rec.write_frame(&[-30000; 160]); // clamps
        rec.finish().unwrap();
        // Finished: further audio is ignored and finishing again is fine.
        rec.write_frame(&[5; 160]);
        rec.finish().unwrap();

        let (rate, samples) = read_wav(&path);
        assert_eq!(rate, 8000);
        assert_eq!(samples.len(), 480);
        assert!(samples[..160].iter().all(|&s| s == 1100));
        assert!(samples[160..320].iter().all(|&s| s == -30000));
        assert!(samples[320..].iter().all(|&s| s == i16::MIN));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_empty_recording_is_still_a_valid_file() {
        let path = temp_wav("empty");
        CallRecorder::create(&path, 8000).unwrap().finish().unwrap();
        let (_, samples) = read_wav(&path);
        assert!(samples.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_recorder_dropped_unfinished_still_leaves_a_valid_file() {
        let path = temp_wav("drop");
        {
            let rec = CallRecorder::create(&path, 48000).unwrap();
            rec.write_frame(&[7; 960]);
        }
        let (rate, samples) = read_wav(&path);
        assert_eq!((rate, samples.len()), (48000, 960));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_path_that_cannot_be_created_is_an_error() {
        assert!(CallRecorder::create("/nonexistent-dir/x/y.wav", 8000).is_err());
    }

    struct Mic;
    impl PlatformAudioBridge for Mic {
        fn on_playback_audio(&self, _: Vec<i16>, _: u32) {}
        fn on_capture_audio(&self, _: u32, frame_size: u32) -> Vec<i16> {
            vec![2000; frame_size as usize]
        }
    }

    fn pcmu_packet(seq: u16, level: i16) -> Vec<u8> {
        let mut pkt =
            rtp_engine::rtp::RtpHeader::new(0, seq, u32::from(seq) * 160, 0x77).to_bytes();
        let mut enc = rtp_engine::codec::create_encoder(rtp_engine::CodecType::Pcmu).unwrap();
        enc.encode(&[level; 160], &mut pkt);
        pkt
    }

    fn frame_levels(samples: &[i16], n: usize) -> Vec<i32> {
        samples
            .chunks(n)
            .map(|c| c.iter().map(|&s| i32::from(s)).sum::<i32>() / c.len() as i32)
            .collect()
    }

    fn near(level: i32, want: i32) -> bool {
        (level - want).abs() <= want / 20 + 40
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_session_records_both_ends_mixed() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let session = MobileMediaSession::new(peer.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        let path = temp_wav("live");
        let rec = Arc::new(CallRecorder::create(&path, session.sample_rate()).unwrap());
        session.set_recorder(Some(Arc::clone(&rec)));
        session.start_with_bridge(Arc::new(Mic));
        let to: SocketAddr = format!("127.0.0.1:{}", session.local_port())
            .parse()
            .unwrap();
        for seq in 0..25 {
            peer.send_to(&pcmu_packet(seq, 1000), to).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        session.set_recorder(None);
        session.stop();
        rec.finish().unwrap();

        let (rate, samples) = read_wav(&path);
        assert_eq!(rate, 8000);
        assert!(samples.len() >= 160 * 10, "{} samples", samples.len());
        let levels = frame_levels(&samples, 160);
        assert!(levels.iter().any(|&l| near(l, 3000)), "{levels:?}");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recording_a_conferenced_call_includes_the_other_far_end() {
        let peer_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = MobileMediaSession::new(peer_a.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        let b = MobileMediaSession::new(peer_b.local_addr().unwrap(), AudioCodec::Pcmu)
            .await
            .unwrap();
        MobileMediaSession::join_conference(&a, &b);
        // Record each leg: both must hold mic + A + B.
        let (path_a, path_b) = (temp_wav("conf-a"), temp_wav("conf-b"));
        let rec_a = Arc::new(CallRecorder::create(&path_a, 8000).unwrap());
        let rec_b = Arc::new(CallRecorder::create(&path_b, 8000).unwrap());
        a.set_recorder(Some(Arc::clone(&rec_a)));
        b.set_recorder(Some(Arc::clone(&rec_b)));
        let mic = Arc::new(Mic);
        a.start_with_bridge(mic.clone());
        b.start_with_bridge(mic);
        let to_a: SocketAddr = format!("127.0.0.1:{}", a.local_port()).parse().unwrap();
        let to_b: SocketAddr = format!("127.0.0.1:{}", b.local_port()).parse().unwrap();
        for seq in 0..40 {
            peer_a.send_to(&pcmu_packet(seq, 1000), to_a).await.unwrap();
            peer_b.send_to(&pcmu_packet(seq, 4000), to_b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        a.stop();
        b.stop();
        rec_a.finish().unwrap();
        rec_b.finish().unwrap();
        for path in [path_a, path_b] {
            let (_, samples) = read_wav(&path);
            let levels = frame_levels(&samples, 160);
            assert!(levels.iter().any(|&l| near(l, 7000)), "{path}: {levels:?}");
            let _ = std::fs::remove_file(path);
        }
    }
}
