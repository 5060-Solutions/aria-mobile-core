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

/// Why a call ended. Set only on the `Ended` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// This handset hung up.
    LocalHangup,
    /// The far end hung up (BYE).
    RemoteHangup,
    /// The caller hung up an incoming call before it was answered.
    CallerCancelled,
    /// An incoming call was answered on another device.
    AnsweredElsewhere,
    /// An incoming call was rejected.
    Rejected,
    /// The call was blind-transferred away from this handset.
    Transferred,
    /// The call could not be set up: an outgoing call failed, or an accept
    /// had an unknown outcome.
    Failed,
    /// An outgoing call was hung up before it was answered.
    Cancelled,
}

impl EndReason {
    /// Map the gateway's `/status` `reason` for an ended call, or `fallback`
    /// when it is absent or unrecognised.
    pub fn from_gateway(reason: Option<&str>, fallback: EndReason) -> EndReason {
        match reason {
            Some("transferred") => EndReason::Transferred,
            Some("bye_from_remote" | "bye") => EndReason::RemoteHangup,
            Some("cancelled") => EndReason::CallerCancelled,
            Some("rejected" | "declined") => EndReason::Rejected,
            Some("answered_elsewhere") => EndReason::AnsweredElsewhere,
            Some("no_ack") => EndReason::Failed,
            _ => fallback,
        }
    }
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
    /// Why the call ended; set only when `state` is `Ended`.
    pub end_reason: Option<EndReason>,
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
    /// On an active call after a blind transfer was accepted: "pending"
    /// while the PBX works on it, "failed" when its NOTIFY reported a
    /// failure. Absent on a gateway that does not report transfer outcomes.
    #[serde(default)]
    pub transfer: Option<String>,
    /// The SIP status of a failed transfer.
    #[serde(default)]
    pub transfer_code: Option<u16>,
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
    /// The message says why, for example the SIP status of a failed
    /// transfer. It reaches the app as the error's message.
    #[error("Call failed: {0}")]
    CallFailed(String),
    #[error("Media error")]
    MediaError,
    #[error("Invalid state")]
    InvalidState,
    #[error("Gateway error")]
    GatewayError,
    #[error("Timeout")]
    Timeout,
    #[error("Invalid target")]
    InvalidTarget,
    #[error("Cancelled")]
    Cancelled,
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

// ── On-device AI (mirrors the `Ai*` dictionaries in aria_mobile.udl) ─────────

/// One model the user can install.
#[derive(Debug, Clone)]
pub struct AiModel {
    pub id: String,
    pub display_name: String,
    pub kind: String,
    pub size_bytes: u64,
    pub available: bool,
    pub unavailable_reason: Option<String>,
    pub installed: bool,
}

/// Progress of a model download. Polled, not pushed.
#[derive(Debug, Clone)]
pub struct AiDownloadProgress {
    pub model_id: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub state: String,
    pub error: Option<String>,
}

/// One utterance in a transcript.
#[derive(Debug, Clone)]
pub struct AiTranscriptSegment {
    pub speaker: String,
    pub start_ms: u32,
    pub end_ms: u32,
    pub text: String,
}

/// The finished result for one call.
#[derive(Debug, Clone)]
pub struct AiCallInsight {
    pub call_id: String,
    pub created_at: i64,
    pub duration_secs: u32,
    pub segments: Vec<AiTranscriptSegment>,
    pub language: Option<String>,
    pub summary_headline: Option<String>,
    pub summary_points: Vec<String>,
    pub status: String,
}

/// A stored insight in list form: enough for a history row, without carrying
/// the transcript text until something actually opens it.
#[derive(Debug, Clone)]
pub struct AiInsightSummary {
    pub call_id: String,
    pub created_at: i64,
    pub duration_secs: u32,
    pub status: String,
}
