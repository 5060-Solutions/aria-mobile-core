//! On-device AI surface for the mobile apps.
//!
//! This is the only place `aria-ai-core` is exposed across the FFI boundary,
//! and it deliberately exposes *control* and *results* — never audio. Call
//! audio is tapped in [`crate::media`], where the RTP threads already hold the
//! decoded PCM, so samples never make the crossing. Routing 20 ms frames out to
//! Kotlin/Swift and back would be roughly a hundred crossings per second per
//! call.
//!
//! Everything here has a no-op counterpart compiled when the `ai` feature is
//! off, each returning `MobileError::InvalidState` with a message saying so.
//! That lets a host ship one binary and ask [`AriaMobileEngine::ai_available`]
//! at runtime rather than inferring support from its build flavour.

use crate::types::{AiCallInsight, AiDownloadProgress, AiModel, MobileError};
#[cfg(feature = "ai")]
use crate::types::AiTranscriptSegment;

#[cfg(feature = "ai")]
use std::collections::HashMap;
#[cfg(feature = "ai")]
use std::sync::{Arc, Mutex};

/// Holds the AI engine and the capture session for each call being recorded.
#[cfg(feature = "ai")]
pub struct AiState {
    engine: aria_ai_core::engine::AiEngine,
    /// Capture sessions keyed by call id, plus the drain handle keeping the
    /// resampler fed. Dropping the handle stops the thread.
    sessions: Mutex<HashMap<String, CaptureSession>>,
}

#[cfg(feature = "ai")]
struct CaptureSession {
    session: Arc<aria_ai_core::session::CallSession>,
    /// Held for its `Drop`: it stops the background drain thread.
    _drain: aria_ai_core::session::DrainHandle,
}

#[cfg(feature = "ai")]
impl AiState {
    /// How often the drain thread moves audio out of the ring buffers.
    ///
    /// The ring is sized in seconds, so this only has to be comfortably faster
    /// than it can fill; doing it per-frame would put resampling on the RTP
    /// thread, which is what the split exists to avoid.
    const DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

    /// Build the engine against a host-supplied storage directory.
    ///
    /// # Errors
    /// [`MobileError::InvalidState`] if the engine cannot be created, which in
    /// practice means the directory is unusable.
    pub fn new(storage_dir: &str) -> Result<Self, MobileError> {
        let capability = device_capability();
        let config = aria_ai_core::engine::AiConfig::new(storage_dir, capability);
        let engine = aria_ai_core::engine::AiEngine::new(config).map_err(|e| {
            log::error!("AI engine init failed: {e}");
            MobileError::InvalidState
        })?;
        Ok(Self {
            engine,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn models(&self) -> Vec<AiModel> {
        let installed: Vec<String> = self
            .engine
            .installed_models()
            .into_iter()
            .map(|m| m.id)
            .collect();
        self.engine
            .availability()
            .into_iter()
            .map(|a| AiModel {
                id: a.model.id.clone(),
                display_name: a.model.display_name.clone(),
                kind: match a.model.kind {
                    aria_ai_core::models::catalog::ModelKind::Stt => "stt",
                    aria_ai_core::models::catalog::ModelKind::Llm => "llm",
                    aria_ai_core::models::catalog::ModelKind::Vad => "vad",
                }
                .to_string(),
                size_bytes: a.model.size_bytes,
                available: a.available,
                unavailable_reason: a.reason,
                installed: installed.contains(&a.model.id),
            })
            .collect()
    }

    /// # Errors
    /// [`MobileError::InvalidState`] if the model is unknown or the download
    /// cannot start.
    pub fn start_download(&self, model_id: &str) -> Result<(), MobileError> {
        self.engine.start_download(model_id).map_err(|e| {
            log::error!("start_download({model_id}) failed: {e}");
            MobileError::InvalidState
        })
    }

    pub fn download_progress(&self, model_id: &str) -> Option<AiDownloadProgress> {
        self.engine.download_progress(model_id).map(|p| {
            let (state, error) = match &p.state {
                aria_ai_core::models::download::DownloadState::Queued => ("queued", None),
                aria_ai_core::models::download::DownloadState::Running => ("running", None),
                aria_ai_core::models::download::DownloadState::Verifying => ("verifying", None),
                aria_ai_core::models::download::DownloadState::Completed => ("completed", None),
                aria_ai_core::models::download::DownloadState::Cancelled => ("cancelled", None),
                aria_ai_core::models::download::DownloadState::Failed { reason } => {
                    ("failed", Some(reason.clone()))
                }
            };
            AiDownloadProgress {
                model_id: p.model_id.clone(),
                downloaded_bytes: p.downloaded_bytes,
                total_bytes: p.total_bytes,
                state: state.to_string(),
                error,
            }
        })
    }

    pub fn cancel_download(&self, model_id: &str) {
        self.engine.cancel_download(model_id);
    }

    /// # Errors
    /// [`MobileError::InvalidState`] if the model is unknown or cannot be
    /// removed.
    pub fn delete_model(&self, model_id: &str) -> Result<(), MobileError> {
        self.engine.delete_model(model_id).map(|_| ()).map_err(|e| {
            log::error!("delete_model({model_id}) failed: {e}");
            MobileError::InvalidState
        })
    }

    /// Start a capture session and return the tap the media layer should feed.
    ///
    /// # Errors
    /// [`MobileError::InvalidState`] if a session cannot be started.
    pub fn start_capture(
        &self,
        call_id: &str,
    ) -> Result<Arc<aria_ai_core::session::CallSession>, MobileError> {
        let config = aria_ai_core::session::SessionConfig::new(call_id);
        let session = aria_ai_core::session::CallSession::start(config).map_err(|e| {
            log::error!("AI capture start failed for {call_id}: {e}");
            MobileError::InvalidState
        })?;
        let drain = session.spawn_drain_thread(Self::DRAIN_INTERVAL);
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(
            call_id.to_string(),
            CaptureSession {
                session: session.clone(),
                _drain: drain,
            },
        );
        Ok(session)
    }

    /// Stop capturing but keep the audio, so it can still be transcribed.
    pub fn stop_capture(&self, call_id: &str) {
        if let Some(entry) = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(call_id) {
            let _ = entry.session.stop();
        }
    }

    /// Throw away a capture without transcribing it.
    pub fn discard(&self, call_id: &str) {
        if let Some(entry) = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(call_id) {
            entry.session.discard();
        }
    }

    /// Transcribe a finished capture, summarising it when an LLM is installed.
    ///
    /// # Errors
    /// [`MobileError::InvalidState`] when there is no capture for that call, no
    /// speech-to-text model is installed, or the model fails to run.
    pub fn transcribe(&self, call_id: &str) -> Result<AiCallInsight, MobileError> {
        let entry = self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(call_id)
            .ok_or_else(|| {
                log::warn!("transcribe: no capture for {call_id}");
                MobileError::InvalidState
            })?;
        let session = entry.session;
        let _ = session.stop();

        let stt_id = self
            .engine
            .recommended(aria_ai_core::models::catalog::ModelKind::Stt)
            .map(|m| m.id.clone())
            .ok_or_else(|| {
                log::warn!("transcribe: no speech-to-text model installed");
                MobileError::InvalidState
            })?;
        let transcriber = self.engine.transcriber(&stt_id).map_err(|e| {
            log::error!("transcribe: loading {stt_id} failed: {e}");
            MobileError::InvalidState
        })?;
        session.transcribe(transcriber.as_ref()).map_err(|e| {
            log::error!("transcribe({call_id}) failed: {e}");
            MobileError::InvalidState
        })?;

        // Summarisation is best effort: a transcript with no summary is a
        // first-class outcome, not a failure, and the LLM may simply not be
        // installed.
        self.summarize_if_possible(&session);

        Ok(to_insight(&session.insight()))
    }

    fn summarize_if_possible(&self, session: &Arc<aria_ai_core::session::CallSession>) {
        let Some(llm_id) = self
            .engine
            .recommended(aria_ai_core::models::catalog::ModelKind::Llm)
            .map(|m| m.id.clone())
        else {
            return;
        };
        let Ok(summarizer) = self.engine.summarizer(&llm_id) else {
            log::warn!("summary skipped: {llm_id} would not load");
            return;
        };
        let ctx = aria_ai_core::llm::prompt::CallContext {
            remote_label: String::new(),
            date_label: String::new(),
            duration_secs: session.insight().duration_secs,
        };
        let cfg = aria_ai_core::llm::pipeline::SummaryConfig::default();
        if let Err(e) = session.summarize(summarizer.as_ref(), &ctx, &cfg) {
            log::warn!("summary failed (transcript is still available): {e}");
        }
    }
}

/// Describe the handset so the catalogue can gate models it cannot run.
#[cfg(feature = "ai")]
fn device_capability() -> aria_ai_core::models::capability::DeviceCapability {
    use aria_ai_core::models::capability::{DeviceCapability, Platform};

    let platform = if cfg!(target_os = "ios") {
        Platform::Ios
    } else if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Other
    };

    // A conservative floor rather than a guess: the host knows its real memory
    // and can gate further, and over-reporting here would offer the user a
    // model their phone cannot load.
    let total_ram_mb = 4096;
    DeviceCapability {
        platform,
        total_ram_mb,
        available_ram_mb: total_ram_mb / 2,
        cpu_cores: u32::try_from(
            std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get),
        )
        .unwrap_or(4),
        is_64bit: cfg!(target_pointer_width = "64"),
        has_gpu_backend: cfg!(any(target_os = "ios", target_os = "macos")),
    }
}

#[cfg(feature = "ai")]
fn to_insight(i: &aria_ai_core::types::CallInsight) -> AiCallInsight {
    use aria_ai_core::types::{InsightStatus, Speaker};

    let (segments, language) = i.transcript.as_ref().map_or_else(
        || (Vec::new(), None),
        |t| {
            (
                t.segments
                    .iter()
                    .map(|s| AiTranscriptSegment {
                        speaker: match s.speaker {
                            Speaker::Local => "local",
                            Speaker::Remote => "remote",
                        }
                        .to_string(),
                        start_ms: s.start_ms,
                        end_ms: s.end_ms,
                        text: s.text.clone(),
                    })
                    .collect(),
                Some(t.language.clone()),
            )
        },
    );

    let (summary_headline, summary_points) = i.summary.as_ref().map_or_else(
        || (None, Vec::new()),
        |s| (Some(s.headline.clone()), s.key_points.clone()),
    );

    AiCallInsight {
        call_id: i.call_id.clone(),
        created_at: i.created_at,
        duration_secs: i.duration_secs,
        segments,
        language,
        summary_headline,
        summary_points,
        status: match &i.status {
            InsightStatus::Pending => "pending",
            InsightStatus::Transcribing => "transcribing",
            InsightStatus::Summarizing => "summarizing",
            InsightStatus::Complete => "complete",
            InsightStatus::TranscriptOnly { .. } => "transcript_only",
            InsightStatus::Failed { .. } => "failed",
        }
        .to_string(),
    }
}

// ── Builds without the `ai` feature ─────────────────────────────────────────

/// Stand-in so the engine can hold the same field either way.
#[cfg(not(feature = "ai"))]
pub struct AiState;

#[cfg(not(feature = "ai"))]
impl AiState {
    /// # Errors
    /// Always: this binary has no transcription support.
    pub fn new(_storage_dir: &str) -> Result<Self, MobileError> {
        log::warn!("ai_init called, but this build has no `ai` feature");
        Err(MobileError::InvalidState)
    }

    #[must_use]
    pub fn models(&self) -> Vec<AiModel> {
        Vec::new()
    }

    /// # Errors
    /// Always.
    pub fn start_download(&self, _model_id: &str) -> Result<(), MobileError> {
        Err(MobileError::InvalidState)
    }

    #[must_use]
    pub fn download_progress(&self, _model_id: &str) -> Option<AiDownloadProgress> {
        None
    }

    pub fn cancel_download(&self, _model_id: &str) {}

    /// # Errors
    /// Always.
    pub fn delete_model(&self, _model_id: &str) -> Result<(), MobileError> {
        Err(MobileError::InvalidState)
    }

    pub fn stop_capture(&self, _call_id: &str) {}

    pub fn discard(&self, _call_id: &str) {}

    /// # Errors
    /// Always.
    pub fn transcribe(&self, _call_id: &str) -> Result<AiCallInsight, MobileError> {
        Err(MobileError::InvalidState)
    }
}
