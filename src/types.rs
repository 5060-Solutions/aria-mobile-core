//! Shared types for the mobile core, matching the UDL definitions.

/// Configuration for connecting to the push gateway.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub base_url: String,
    pub api_key: String,
}

/// SIP account credentials.
#[derive(Debug, Clone)]
pub struct SipCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub registrar: Option<String>,
    pub transport: String,
    pub port: u16,
    pub auth_username: Option<String>,
    pub display_name: String,
}

/// Device registration request.
#[derive(Debug, Clone)]
pub struct DeviceRegistration {
    pub platform: String,
    pub push_token: String,
    pub bundle_id: Option<String>,
    pub sip: SipCredentials,
}

/// Response from device registration.
#[derive(Debug, Clone)]
pub struct DeviceRegistrationResponse {
    pub device_id: String,
    pub auth_token: String,
}

/// Incoming call offer from the gateway.
#[derive(Debug, Clone)]
pub struct CallOffer {
    pub call_token: String,
    pub caller_uri: String,
    pub caller_name: Option<String>,
    pub sdp_offer: String,
}

/// Current call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Idle,
    Incoming,
    Ringing,
    Connecting,
    Connected,
    OnHold,
    Ended,
}

/// Call direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Inbound,
    Outbound,
}

/// Information about an active call.
#[derive(Debug, Clone)]
pub struct CallInfo {
    pub call_id: String,
    pub remote_uri: String,
    pub remote_name: Option<String>,
    pub state: CallState,
    pub direction: CallDirection,
    pub muted: bool,
    pub on_hold: bool,
    pub duration_secs: u64,
}

/// Audio codec selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    Pcmu,
    Pcma,
    Opus,
    G729,
}

impl AudioCodec {
    pub fn to_rtp_codec(self) -> rtp_engine::CodecType {
        match self {
            AudioCodec::Pcmu => rtp_engine::CodecType::Pcmu,
            AudioCodec::Pcma => rtp_engine::CodecType::Pcma,
            AudioCodec::Opus => rtp_engine::CodecType::Opus,
            AudioCodec::G729 => rtp_engine::CodecType::G729,
        }
    }

    pub fn payload_type(self) -> u8 {
        match self {
            AudioCodec::Pcmu => 0,
            AudioCodec::Pcma => 8,
            AudioCodec::Opus => 111,
            AudioCodec::G729 => 18,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AudioCodec::Pcmu => "PCMU",
            AudioCodec::Pcma => "PCMA",
            AudioCodec::Opus => "opus",
            AudioCodec::G729 => "G729",
        }
    }

    pub fn clock_rate(self) -> u32 {
        match self {
            AudioCodec::Pcmu | AudioCodec::Pcma | AudioCodec::G729 => 8000,
            AudioCodec::Opus => 48000,
        }
    }
}

/// RTP media statistics.
#[derive(Debug, Clone, Default)]
pub struct MediaStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub jitter_ms: f64,
    pub packet_loss: u32,
    pub rtt_ms: f64,
}

/// Push notification payload.
#[derive(Debug, Clone)]
pub struct PushCallPayload {
    pub call_token: String,
    pub caller_uri: String,
    pub caller_name: Option<String>,
    pub gateway_url: String,
}

/// Response from call status polling.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CallStatusResponse {
    pub status: String,
    /// Reason the call ended (if status == "ended")
    pub reason: Option<String>,
}

/// Errors from the mobile engine.
#[derive(Debug, thiserror::Error)]
pub enum MobileError {
    #[error("Network error")]
    NetworkError,
    #[error("Authentication error")]
    AuthenticationError,
    #[error("Registration failed")]
    RegistrationFailed,
    #[error("Call failed")]
    CallFailed,
    #[error("Media error")]
    MediaError,
    #[error("Invalid state")]
    InvalidState,
    #[error("Gateway error")]
    GatewayError,
    #[error("Timeout")]
    Timeout,
}

impl From<reqwest::Error> for MobileError {
    fn from(e: reqwest::Error) -> Self {
        log::error!("HTTP error: {}", e);
        if e.is_timeout() {
            MobileError::Timeout
        } else {
            MobileError::NetworkError
        }
    }
}
