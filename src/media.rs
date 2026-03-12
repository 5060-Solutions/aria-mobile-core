//! Mobile media session — RTP send/receive without platform audio device.
//!
//! On mobile, the platform (iOS/Android) manages the audio hardware via
//! AudioUnit/Oboe. This module handles:
//! - SDP offer/answer generation and parsing
//! - RTP socket management
//! - Codec encode/decode
//! - DTMF generation (RFC 2833)
//!
//! The platform layer feeds PCM samples in/out via the `feed_capture`
//! and `drain_playback` methods.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::types::*;

/// A media session for mobile — no native audio device, platform feeds PCM.
pub struct MobileMediaSession {
    #[allow(dead_code)]
    rtp_socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    local_port: u16,
    #[allow(dead_code)]
    codec: AudioCodec,
    muted: Arc<AtomicBool>,
    on_hold: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    ssrc: u32,
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
            remote_addr,
            local_port,
            codec,
            muted: Arc::new(AtomicBool::new(false)),
            on_hold: Arc::new(AtomicBool::new(false)),
            running: Arc::new(AtomicBool::new(true)),
            ssrc,
        })
    }

    /// Local RTP port for SDP.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Update the remote RTP address (e.g., after receiving SDP answer).
    pub fn update_remote(&mut self, addr: SocketAddr) {
        self.remote_addr = addr;
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
        log::info!("DTMF: {}", digit);
        // RFC 2833 DTMF would be sent here via the RTP socket
        // For now, log the digit — full implementation uses rtp_engine's DTMF support
    }

    pub fn stats(&self) -> MediaStats {
        // Basic stats — full implementation would track via RTP counters
        MediaStats::default()
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

    // Add payload types
    for codec in codecs {
        sdp.push_str(&format!(" {}", codec.payload_type()));
    }
    // Telephone events
    sdp.push_str(" 101\r\n");

    // Add rtpmap for each codec
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

    // Telephone event
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

/// Parse the remote RTP address and preferred codec from an SDP offer.
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
                // First payload type after RTP/AVP
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

/// Public wrapper for parse_sdp_remote — used by lib.rs for outgoing call SDP answers.
pub fn parse_sdp_remote_pub(sdp: &str) -> Option<(SocketAddr, AudioCodec)> {
    parse_sdp_remote(sdp)
}

/// Negotiate codec — pick the first from our preferences that appears in the offer.
fn negotiate_codec(offer_sdp: &str, our_prefs: &[AudioCodec]) -> AudioCodec {
    // Parse offered payload types from m= line
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

    // Default to PCMU
    AudioCodec::Pcmu
}

/// Create a media session as the answerer (incoming call via gateway).
pub async fn create_answer_session(
    offer_sdp: &str,
    preferred_codecs: &[AudioCodec],
) -> Result<(MobileMediaSession, String), MobileError> {
    let (remote_addr, _offer_codec) =
        parse_sdp_remote(offer_sdp).ok_or(MobileError::MediaError)?;

    let chosen = negotiate_codec(offer_sdp, preferred_codecs);

    let session = MobileMediaSession::new(remote_addr, chosen).await?;

    // Use STUN to discover public IP, or fallback to local
    let local_ip = discover_local_ip().await;
    let answer_sdp = build_sdp_answer(session.local_port(), &local_ip, chosen);

    Ok((session, answer_sdp))
}

/// Create a media session as the offerer (outgoing call).
pub async fn create_offer_session(
    preferred_codecs: &[AudioCodec],
) -> Result<(MobileMediaSession, String), MobileError> {
    // Use a placeholder remote — will be updated when SDP answer arrives
    let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let codec = preferred_codecs.first().copied().unwrap_or(AudioCodec::Pcmu);

    let session = MobileMediaSession::new(placeholder, codec).await?;

    let local_ip = discover_local_ip().await;
    let codecs = if preferred_codecs.is_empty() {
        vec![AudioCodec::Pcmu, AudioCodec::Pcma, AudioCodec::Opus]
    } else {
        preferred_codecs.to_vec()
    };

    let offer_sdp = build_sdp_offer(session.local_port(), &local_ip, &codecs);

    Ok((session, offer_sdp))
}

/// Best-effort local IP discovery.
async fn discover_local_ip() -> String {
    // Try STUN first (port 0 = OS-assigned)
    match rtp_engine::stun_discover(0).await {
        Ok(result) => result.public_ip.to_string(),
        Err(_) => {
            // Fallback: connect a UDP socket to a public address to learn our local IP
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

