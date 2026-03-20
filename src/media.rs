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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// A media session for mobile — processes RTP with platform audio bridge.
pub struct MobileMediaSession {
    rtp_socket: Arc<UdpSocket>,
    /// Shared remote address — updated by update_remote() and symmetric RTP
    remote_addr: Arc<Mutex<SocketAddr>>,
    local_port: u16,
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
}

impl MobileMediaSession {
    /// Create a new media session bound to a local UDP port.
    pub async fn new(
        remote_addr: SocketAddr,
        codec: AudioCodec,
    ) -> Result<Self, MobileError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|_| MobileError::MediaError)?;

        let local_port = socket
            .local_addr()
            .map_err(|_| MobileError::MediaError)?
            .port();

        let ssrc: u32 = ::rand::random();

        Ok(Self {
            rtp_socket: Arc::new(socket),
            remote_addr: Arc::new(Mutex::new(remote_addr)),
            local_port,
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
        })
    }

    /// Local RTP port for SDP.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Get a reference to the RTP socket (for STUN discovery).
    pub fn rtp_socket_ref(&self) -> &UdpSocket {
        &self.rtp_socket
    }

    /// Update the remote RTP address (e.g., after receiving SDP answer).
    pub fn update_remote(&self, addr: SocketAddr) {
        *self.remote_addr.lock().unwrap() = addr;
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
                        let recv = tokio::time::timeout(
                            std::time::Duration::from_millis(100),
                            socket.recv_from(&mut buf),
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

                        // Symmetric RTP: learn remote address from first packet
                        {
                            let mut addr = remote_addr.lock().unwrap();
                            if addr.port() == 0 || *addr != src {
                                if addr.port() == 0 {
                                    log::info!("Learned remote RTP address: {}", src);
                                }
                                *addr = src;
                            }
                        }

                        pkts_rx.fetch_add(1, Ordering::Relaxed);
                        bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

                        if on_hold.load(Ordering::Relaxed) {
                            continue;
                        }

                        // Parse RTP header
                        let header = match rtp_engine::rtp::RtpHeader::parse(&buf[..len]) {
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

                            bridge_rx.on_playback_audio(pcm, sample_rate);
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

                        let remote = *remote_addr.lock().unwrap();
                        if remote.port() == 0 {
                            continue; // no remote yet
                        }

                        // Get mic audio from platform
                        let pcm = if muted.load(Ordering::Relaxed) || on_hold.load(Ordering::Relaxed) {
                            vec![0i16; frame_samples as usize]
                        } else {
                            let captured = bridge.on_capture_audio(sample_rate, frame_samples);
                            if captured.is_empty() {
                                vec![0i16; frame_samples as usize]
                            } else {
                                // Calculate TX audio level
                                let sum: f64 = captured.iter().map(|&s| (s as f64) * (s as f64)).sum();
                                let rms = (sum / captured.len() as f64).sqrt();
                                tx_level.store((rms * 1000.0) as u64, Ordering::Relaxed);
                                captured
                            }
                        };

                        // Encode
                        let header = rtp_engine::rtp::RtpHeader::new(pt, seq, timestamp, ssrc);
                        let mut packet = header.to_bytes();
                        encoder.encode(&pcm, &mut packet);

                        // Send
                        if let Err(e) = socket.send_to(&packet, remote).await {
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

    pub fn set_mute(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    pub fn set_hold(&self, on_hold: bool) {
        self.on_hold.store(on_hold, Ordering::Relaxed);
    }

    pub fn send_dtmf(&self, digit: &str) {
        // Send RFC 2833 DTMF via the RTP socket
        let event = match digit {
            "0" => 0u8, "1" => 1, "2" => 2, "3" => 3,
            "4" => 4, "5" => 5, "6" => 6, "7" => 7,
            "8" => 8, "9" => 9, "*" => 10, "#" => 11,
            _ => {
                log::warn!("Unknown DTMF digit: {}", digit);
                return;
            }
        };

        let digit_owned = digit.to_string();
        let socket = self.rtp_socket.clone();
        let remote_addr = self.remote_addr.clone();
        let ssrc = self.ssrc;

        // Spawn DTMF send on a background task
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move {
                let remote = *remote_addr.lock().unwrap();
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
}

// ── SDP Helpers ─────────────────────────────────────────────────────────────

fn build_sdp_offer(local_port: u16, local_ip: &str, codecs: &[AudioCodec]) -> String {
    let mut sdp = format!(
        "v=0\r\n\
         o=aria 0 0 IN IP4 {local_ip}\r\n\
         s=Aria Mobile\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {local_port} RTP/AVP"
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
    sdp.push_str("a=sendrecv\r\n");

    sdp
}

fn build_sdp_answer(
    local_port: u16,
    local_ip: &str,
    chosen_codec: AudioCodec,
) -> String {
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
        if line.starts_with("c=IN IP4 ") {
            remote_ip = Some(line[9..].trim().to_string());
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
    let (remote_addr, _offer_codec) =
        parse_sdp_remote(offer_sdp).ok_or(MobileError::MediaError)?;

    let chosen = negotiate_codec(offer_sdp, preferred_codecs);

    let session = MobileMediaSession::new(remote_addr, chosen).await?;

    // Use the actual RTP socket for STUN so NAT mapping matches
    let local_ip = match rtp_engine::discover_public_address(session.rtp_socket_ref()).await {
        Ok(result) => {
            log::info!("STUN on RTP socket (answer): public {}:{}", result.public_ip, result.public_port);
            result.public_ip.to_string()
        }
        Err(_) => discover_local_ip().await,
    };
    let answer_sdp = build_sdp_answer(session.local_port(), &local_ip, chosen);

    Ok((session, answer_sdp))
}

/// Create a media session as the offerer (outgoing call).
pub async fn create_offer_session(
    preferred_codecs: &[AudioCodec],
) -> Result<(MobileMediaSession, String), MobileError> {
    let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let codec = preferred_codecs.first().copied().unwrap_or(AudioCodec::Pcmu);

    let session = MobileMediaSession::new(placeholder, codec).await?;

    // Discover public IP using the ACTUAL RTP socket so the NAT mapping matches.
    // If we use a different socket, the NAT mapping won't match and RTP won't flow.
    let local_ip = match rtp_engine::discover_public_address(session.rtp_socket_ref()).await {
        Ok(result) => {
            log::info!("STUN on RTP socket: public {}:{}, local port {}",
                result.public_ip, result.public_port, session.local_port());
            result.public_ip.to_string()
        }
        Err(_) => discover_local_ip().await,
    };

    let codecs = if preferred_codecs.is_empty() {
        vec![AudioCodec::Pcmu, AudioCodec::Pcma, AudioCodec::Opus]
    } else {
        preferred_codecs.to_vec()
    };

    let offer_sdp = build_sdp_offer(session.local_port(), &local_ip, &codecs);

    Ok((session, offer_sdp))
}

/// Best-effort local IP discovery via STUN.
async fn discover_local_ip() -> String {
    match rtp_engine::stun_discover(0).await {
        Ok(result) => result.public_ip.to_string(),
        Err(_) => {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                if sock.connect("8.8.8.8:80").await.is_ok() {
                    if let Ok(addr) = sock.local_addr() {
                        return addr.ip().to_string();
                    }
                }
            }
            "0.0.0.0".to_string()
        }
    }
}
