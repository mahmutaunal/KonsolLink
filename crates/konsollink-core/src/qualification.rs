//! Aggregate-only shadow evaluation and the fail-closed M2 selection gate.

use crate::classifier::FlowClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedClass {
    NonDiscord,
    DiscordControl,
    DiscordMedia,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualificationReport {
    pub non_discord_samples: u64,
    pub discord_control_samples: u64,
    pub discord_media_samples: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub class_mismatches: u64,
}

/// The evaluator receives independent ground-truth labels from a fixture or
/// human-operated test. It stores counts only, never flow tuples or names.
#[derive(Debug, Default)]
pub struct ShadowEvaluator {
    report: QualificationReport,
}

impl ShadowEvaluator {
    pub fn observe(&mut self, expected: ExpectedClass, observed: FlowClass) {
        match expected {
            ExpectedClass::NonDiscord => {
                self.report.non_discord_samples = self.report.non_discord_samples.saturating_add(1);
                if observed != FlowClass::Direct {
                    self.report.false_positives = self.report.false_positives.saturating_add(1);
                }
            }
            ExpectedClass::DiscordControl => {
                self.report.discord_control_samples =
                    self.report.discord_control_samples.saturating_add(1);
                match observed {
                    FlowClass::DiscordControlCandidate => {}
                    FlowClass::Direct => {
                        self.report.false_negatives = self.report.false_negatives.saturating_add(1)
                    }
                    FlowClass::DiscordMediaCandidate => {
                        self.report.class_mismatches =
                            self.report.class_mismatches.saturating_add(1)
                    }
                }
            }
            ExpectedClass::DiscordMedia => {
                self.report.discord_media_samples =
                    self.report.discord_media_samples.saturating_add(1);
                match observed {
                    FlowClass::DiscordMediaCandidate => {}
                    FlowClass::Direct => {
                        self.report.false_negatives = self.report.false_negatives.saturating_add(1)
                    }
                    FlowClass::DiscordControlCandidate => {
                        self.report.class_mismatches =
                            self.report.class_mismatches.saturating_add(1)
                    }
                }
            }
        }
    }

    pub fn report(&self) -> QualificationReport {
        self.report
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureHealth {
    pub observer_active: bool,
    pub captured_packets: u32,
    pub dropped_packets: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualificationRequirements {
    pub min_non_discord_samples: u64,
    pub min_control_samples: u64,
    pub min_media_samples: u64,
}

impl Default for QualificationRequirements {
    fn default() -> Self {
        Self {
            min_non_discord_samples: 2,
            min_control_samples: 1,
            min_media_samples: 1,
        }
    }
}

impl QualificationRequirements {
    /// M2's selected engine intercepts TCP control only. UDP media remains
    /// direct and is verified by the later end-to-end device acceptance test.
    pub fn tcp_control_m2() -> Self {
        Self {
            min_non_discord_samples: 2,
            min_control_samples: 1,
            min_media_samples: 0,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QualificationError {
    #[error("observer is not active")]
    ObserverInactive,
    #[error("capture has no packets")]
    EmptyCapture,
    #[error("capture dropped packets")]
    CaptureDrops,
    #[error("insufficient independently labelled samples")]
    InsufficientSamples,
    #[error("non-Discord flow was selected")]
    FalsePositive,
    #[error("Discord flow was missed")]
    FalseNegative,
    #[error("Discord control/media class mismatch")]
    ClassMismatch,
}

/// Opaque proof that a shadow run met the configured requirements. It can only
/// be constructed by `qualify`; callers cannot set a boolean feature flag.
pub struct QualifiedShadowRun {
    _private: (),
}

pub fn qualify(
    report: QualificationReport,
    capture: CaptureHealth,
    requirements: QualificationRequirements,
) -> Result<QualifiedShadowRun, QualificationError> {
    if !capture.observer_active {
        return Err(QualificationError::ObserverInactive);
    }
    if capture.captured_packets == 0 {
        return Err(QualificationError::EmptyCapture);
    }
    if capture.dropped_packets != 0 {
        return Err(QualificationError::CaptureDrops);
    }
    if report.non_discord_samples < requirements.min_non_discord_samples
        || report.discord_control_samples < requirements.min_control_samples
        || report.discord_media_samples < requirements.min_media_samples
    {
        return Err(QualificationError::InsufficientSamples);
    }
    if report.false_positives != 0 {
        return Err(QualificationError::FalsePositive);
    }
    if report.false_negatives != 0 {
        return Err(QualificationError::FalseNegative);
    }
    if report.class_mismatches != 0 {
        return Err(QualificationError::ClassMismatch);
    }
    Ok(QualifiedShadowRun { _private: () })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M2Path {
    Direct,
    TcpProxyCandidate,
}

/// The current macOS candidate is TCP-only. UDP media remains on the direct
/// kernel path even after shadow qualification.
pub fn m2_path(_: &QualifiedShadowRun, class: FlowClass, current_capture: CaptureHealth) -> M2Path {
    if !current_capture.observer_active
        || current_capture.captured_packets == 0
        || current_capture.dropped_packets != 0
    {
        return M2Path::Direct;
    }
    match class {
        FlowClass::DiscordControlCandidate => M2Path::TcpProxyCandidate,
        FlowClass::Direct | FlowClass::DiscordMediaCandidate => M2Path::Direct,
    }
}
