use crate::commands::publish_common::{NpmProvenanceAttachment, TarballFile, TarballHashes};
use crate::oidc;
use lpm_common::LpmError;
use lpm_registry::{PublicationHold, PublicationStatusResponse, SwiftReleaseState};
use lpm_runner::lpm_json;
/// Target registries for a publish operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishTarget {
    Lpm,
    Npm,
    GitHub,
    GitLab,
    Custom(String),
}

impl PublishTarget {
    /// Short display name for human output.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Lpm => "LPM",
            Self::Npm => "npm",
            Self::GitHub => "GitHub Packages",
            Self::GitLab => "GitLab Packages",
            Self::Custom(_) => "custom",
        }
    }

    /// Exact key used for internal target identity and lookup.
    pub fn key(&self) -> String {
        match self {
            Self::Lpm => "lpm".into(),
            Self::Npm => "npm".into(),
            Self::GitHub => "github".into(),
            Self::GitLab => "gitlab".into(),
            Self::Custom(url) => url.clone(),
        }
    }

    /// Registry identifier safe for human and JSON output.
    pub fn output_key(&self) -> String {
        match self {
            Self::Custom(url) => crate::install_ui::safe_url_origin(url),
            _ => self.key(),
        }
    }

    /// CLI flag to retry a failed publish for this target.
    pub fn retry_flag(&self) -> String {
        match self {
            Self::Lpm => "--lpm".into(),
            Self::Npm => "--npm".into(),
            Self::GitHub => "--github".into(),
            Self::GitLab => "--gitlab".into(),
            Self::Custom(_) => "--publish-registry REGISTRY_URL".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LpmPublicationStatus {
    Active,
    PendingReview,
    Processing,
    ManualReview,
    Rejected,
    Quarantined,
    Unpublished,
    Other(String),
}

impl LpmPublicationStatus {
    pub(super) fn from_registry_response(response: &serde_json::Value) -> Option<Self> {
        response
            .get("publicationStatus")
            .and_then(serde_json::Value::as_str)
            .map(Self::from_registry_value)
    }

    pub(super) fn from_registry_value(value: &str) -> Self {
        match value {
            "active" => Self::Active,
            "pending_review" => Self::PendingReview,
            "processing" => Self::Processing,
            "manual_review" => Self::ManualReview,
            "rejected" => Self::Rejected,
            "quarantined" => Self::Quarantined,
            "unpublished" => Self::Unpublished,
            other => Self::Other(other.to_string()),
        }
    }

    pub(super) fn as_str(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::PendingReview => "pending_review",
            Self::Processing => "processing",
            Self::ManualReview => "manual_review",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
            Self::Unpublished => "unpublished",
            Self::Other(value) => value,
        }
    }

    pub(super) fn is_terminal_rejection(&self) -> bool {
        matches!(self, Self::Rejected | Self::Quarantined | Self::Unpublished)
    }
}

/// What one publication-status poll observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PublicationSnapshot {
    pub(super) status: LpmPublicationStatus,
    pub(super) current_latest_version: Option<String>,
    pub(super) hold: Option<PublicationHold>,
    pub(super) swift: Option<SwiftReleaseState>,
}

impl From<PublicationStatusResponse> for PublicationSnapshot {
    fn from(response: PublicationStatusResponse) -> Self {
        Self {
            status: LpmPublicationStatus::from_registry_value(&response.status),
            current_latest_version: response.current_latest_version,
            hold: response.hold,
            swift: response.swift,
        }
    }
}

/// Text the Registry sent, unless it's missing or blank.
fn registry_text(text: Option<&str>) -> Option<&str> {
    text.map(str::trim).filter(|text| !text.is_empty())
}

const HOLD_FALLBACK: &str = "LPM.dev Registry is holding it.";

/// The Registry's account of a hold, or a stand-in where it gives none.
pub(super) fn hold_explanation(hold: &PublicationHold) -> &str {
    registry_text(hold.message.as_deref()).unwrap_or(HOLD_FALLBACK)
}

pub(super) const SWIFT_RELEASE_REJECTED: &str =
    "Upload succeeded, but LPM.dev Registry rejected the Swift release.";
pub(super) const SWIFT_REASON_FALLBACK: &str = "LPM.dev Registry gave no reason.";
pub(super) const SWIFT_REMEDY_FALLBACK: &str =
    "Publishing this version again replaces the rejected release.";

/// Why the Swift job rejected a release, as it put it, which can be Swift
/// compiler output over several lines; a stand-in where it gives none.
pub(super) fn swift_rejection_reason(rejection: &SwiftReleaseState) -> &str {
    registry_text(rejection.message.as_deref()).unwrap_or(SWIFT_REASON_FALLBACK)
}

/// What the publisher can do about a rejected Swift release, or a stand-in
/// where the Registry gives none.
pub(super) fn swift_rejection_remedy(rejection: &SwiftReleaseState) -> &str {
    registry_text(rejection.remedy.as_deref()).unwrap_or(SWIFT_REMEDY_FALLBACK)
}

/// Whether a wait that ended early last saw the Swift job still preparing
/// the release, whose outcome then decides whether its version can be
/// published again.
fn swift_still_preparing(last: Option<&PublicationSnapshot>) -> bool {
    last.and_then(|last| last.swift.as_ref())
        .is_some_and(SwiftReleaseState::is_pending)
}

/// What a wait that ended early says about publishing the version again.
fn republish_advice(swift_still_preparing: bool) -> &'static str {
    if swift_still_preparing {
        "The package page shows whether the Swift release was published or rejected. Only a rejected Swift release can be published again under this version."
    } else {
        "Do not publish this version again."
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationWaitResult {
    pub success: bool,
    pub status: Option<LpmPublicationStatus>,
    pub current_latest_version: Option<String>,
    pub hold: Option<PublicationHold>,
    pub swift: Option<SwiftReleaseState>,
    pub error: Option<String>,
    /// Why the wait failed, which says whether the version can be
    /// published again; `None` when it succeeded.
    pub(super) failure: Option<PublicationFailure>,
}

impl PublicationWaitResult {
    fn unsuccessful(failure: PublicationFailure, error: String) -> Self {
        Self {
            success: false,
            status: None,
            current_latest_version: None,
            hold: None,
            swift: None,
            error: Some(error),
            failure: Some(failure),
        }
    }

    pub(super) fn active() -> Self {
        Self {
            success: true,
            status: Some(LpmPublicationStatus::Active),
            current_latest_version: None,
            hold: None,
            swift: None,
            error: None,
            failure: None,
        }
    }

    /// The upload's own answer put the version in a state further polls
    /// can't change.
    pub(super) fn terminal(status: LpmPublicationStatus) -> Self {
        let error = terminal_error(&status);
        Self {
            status: Some(status),
            ..Self::unsuccessful(PublicationFailure::NotConfirmed, error)
        }
    }

    /// The wait ends on a state further polls can't change, keeping all the
    /// poll saw. A release the Swift job rejected says why and what to fix:
    /// publishing the same version again replaces it. A publication
    /// review's rejection has no Swift job rejection.
    pub(super) fn terminal_snapshot(snapshot: PublicationSnapshot) -> Self {
        let swift_rejection = snapshot.swift.as_ref().filter(|swift| {
            snapshot.status == LpmPublicationStatus::Rejected && swift.is_rejected()
        });
        let result = match swift_rejection {
            Some(rejection) => Self::unsuccessful(
                PublicationFailure::SwiftReleaseRejected,
                swift_rejection_error(rejection),
            ),
            None => Self::unsuccessful(
                PublicationFailure::NotConfirmed,
                terminal_error(&snapshot.status),
            ),
        };
        result.with_last_snapshot(Some(snapshot))
    }

    /// The Registry holds the version and only a new version gets past it,
    /// as the poll's hold says.
    pub(super) fn held(snapshot: PublicationSnapshot) -> Self {
        let error = format!(
            "Upload succeeded, but this version won't become available. {} Do not publish this version again.",
            snapshot
                .hold
                .as_ref()
                .map_or(HOLD_FALLBACK, hold_explanation)
        );
        Self::unsuccessful(PublicationFailure::NotConfirmed, error)
            .with_last_snapshot(Some(snapshot))
    }

    /// The wait ended first, keeping what the last poll saw, whose hold
    /// says why.
    pub(super) fn timed_out(last: Option<PublicationSnapshot>) -> Self {
        let held = last
            .as_ref()
            .and_then(|last| last.hold.as_ref())
            .map_or_else(String::new, |hold| {
                format!(
                    " The version isn't available yet. {}",
                    hold_explanation(hold)
                )
            });
        let preparing = swift_still_preparing(last.as_ref());
        Self::unsuccessful(
            PublicationFailure::for_early_end(preparing),
            format!(
                "Upload succeeded, but waiting for LPM.dev Registry publication timed out.{held} {}",
                republish_advice(preparing)
            ),
        )
        .with_last_snapshot(last)
    }

    /// A poll failed, keeping what the last one before it saw.
    pub(super) fn request_failed(error: &LpmError, last: Option<PublicationSnapshot>) -> Self {
        let preparing = swift_still_preparing(last.as_ref());
        let was_preparing = if preparing {
            " LPM.dev Registry was still preparing the Swift release."
        } else {
            ""
        };
        Self::unsuccessful(
            PublicationFailure::for_early_end(preparing),
            format!(
                "Upload succeeded, but LPM.dev Registry publication could not be checked: {error}.{was_preparing} {}",
                republish_advice(preparing)
            ),
        )
        .with_last_snapshot(last)
    }

    /// The Swift job's rejection the wait ended on, if it ended on one.
    pub(super) fn swift_rejection(&self) -> Option<&SwiftReleaseState> {
        self.swift
            .as_ref()
            .filter(|_| self.failure == Some(PublicationFailure::SwiftReleaseRejected))
    }

    /// Keeps all the last poll saw: its status, hold, latest version and
    /// the Swift job's state.
    pub(super) fn with_last_snapshot(mut self, last: Option<PublicationSnapshot>) -> Self {
        if let Some(PublicationSnapshot {
            status,
            current_latest_version,
            hold,
            swift,
        }) = last
        {
            self.status = Some(status);
            self.current_latest_version = current_latest_version;
            self.hold = hold;
            self.swift = swift;
        }
        self
    }

    pub(super) fn with_current_latest_version(
        mut self,
        current_latest_version: Option<String>,
    ) -> Self {
        self.current_latest_version = current_latest_version;
        self
    }
}

fn terminal_error(status: &LpmPublicationStatus) -> String {
    let message = match status {
        LpmPublicationStatus::ManualReview => "publication requires manual review",
        LpmPublicationStatus::Rejected => "publication review rejected the version",
        LpmPublicationStatus::Quarantined => "the uploaded version was quarantined",
        LpmPublicationStatus::Unpublished => "the uploaded version was unpublished",
        LpmPublicationStatus::Other(_) => "the Registry returned an unrecognized publication state",
        LpmPublicationStatus::Active
        | LpmPublicationStatus::PendingReview
        | LpmPublicationStatus::Processing => "publication did not become active",
    };
    format!("Upload succeeded, but {message}. Do not publish this version again.")
}

fn swift_rejection_error(rejection: &SwiftReleaseState) -> String {
    format!(
        "{SWIFT_RELEASE_REJECTED}\n{}\n{}",
        swift_rejection_reason(rejection),
        swift_rejection_remedy(rejection)
    )
}

/// Result of publishing to a single registry.
#[derive(Debug)]
pub struct PublishResult {
    pub warnings: Vec<String>,
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub auth: Option<&'static str>,
    pub publication_status: Option<LpmPublicationStatus>,
    pub current_latest_version: Option<String>,
    pub publication_wait: Option<PublicationWaitResult>,
    pub duration: std::time::Duration,
}

impl PublishResult {
    /// Why the target's upload succeeded but its publication didn't, if it
    /// didn't.
    pub(super) fn publication_failure(&self) -> Option<PublicationFailure> {
        if let Some(failure) = self.publication_wait.as_ref().and_then(|wait| wait.failure) {
            return Some(failure);
        }
        self.publication_status
            .as_ref()
            .is_some_and(LpmPublicationStatus::is_terminal_rejection)
            .then_some(PublicationFailure::NotConfirmed)
    }
}

/// Why a publish whose upload succeeded still failed, which says whether
/// the same version can be published again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationFailure {
    /// The Registry didn't make the version available, and it keeps the
    /// version number.
    NotConfirmed,
    /// The Registry's Swift job rejected the release, which publishing the
    /// same version again replaces.
    SwiftReleaseRejected,
    /// The wait ended while the Swift job was still preparing the release:
    /// only its rejection would free the version number.
    SwiftReleaseStillPreparing,
}

impl PublicationFailure {
    fn for_early_end(swift_still_preparing: bool) -> Self {
        if swift_still_preparing {
            Self::SwiftReleaseStillPreparing
        } else {
            Self::NotConfirmed
        }
    }

    pub(super) fn summary(self) -> &'static str {
        match self {
            Self::NotConfirmed => {
                "the upload succeeded, but LPM.dev Registry publication was not confirmed; do not publish the same version again"
            }
            Self::SwiftReleaseRejected => {
                "the upload succeeded, but LPM.dev Registry rejected the Swift release; fix it, then publish the same version again to replace it"
            }
            Self::SwiftReleaseStillPreparing => {
                "the upload succeeded, but LPM.dev Registry is still preparing the Swift release; the package page shows whether it was published or rejected, and only a rejected one can be published again under this version"
            }
        }
    }
}

/// Local package artifact prepared for publish-like uploads.
pub(crate) struct PublishProject {
    pub(crate) source_dir: std::sync::Arc<cap_std::fs::Dir>,
    pub(crate) publish_control: Option<PublishControl>,
    pub(crate) pkg_json: serde_json::Value,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publish_config: Option<lpm_json::PublishConfig>,
    pub(crate) readme: Option<String>,
    pub(crate) tarball_data: std::sync::Arc<Vec<u8>>,
    pub(crate) tarball_hashes: std::sync::Arc<TarballHashes>,
    pub(crate) tarball_files: Vec<TarballFile>,
    pub(crate) secret_scan: Option<lpm_security::behavioral::secrets::SecretScanResult>,
    pub(crate) tarball_size: usize,
    pub(crate) lpm_config: Option<serde_json::Value>,
    pub(crate) detected_ecosystem: String,
    pub(crate) swift_manifest: Option<serde_json::Value>,
}

pub(crate) struct PublishControl {
    pub(crate) source_dir: std::sync::Arc<cap_std::fs::Dir>,
    pub(crate) pkg_json: serde_json::Value,
}

#[derive(Clone)]
pub(crate) struct ProvenanceContext {
    pub(crate) ci: oidc::CiEnvironment,
    pub(crate) jwt: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedProvenanceFile {
    pub(crate) attachment: NpmProvenanceAttachment,
    pub(crate) statement: serde_json::Value,
}

#[derive(Clone)]
pub(crate) enum ResolvedProvenance {
    Generate(ProvenanceContext),
    File(LoadedProvenanceFile),
}

#[derive(Debug)]
pub(crate) struct NpmTargetArtifact {
    pub(crate) tarball_hashes: std::sync::Arc<TarballHashes>,
    pub(crate) version_data: serde_json::Value,
    pub(crate) provenance_attachment: Option<NpmProvenanceAttachment>,
}

pub(crate) struct PublishQualityGateInput<'a> {
    /// The gzipped tarball LPM.dev Registry receives.
    pub(crate) tarball: &'a [u8],
    pub(crate) detected_ecosystem: &'a str,
    pub(crate) swift_manifest: Option<&'a serde_json::Value>,
    pub(crate) min_score: Option<u32>,
    pub(crate) json_output: bool,
    /// `--check`, which lists every check instead of the ones that lost
    /// points.
    pub(crate) check_only: bool,
}

pub(crate) struct NpmTargetArtifactInput<'a> {
    pub(crate) npm_name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) base_version_data: &'a serde_json::Value,
    pub(crate) final_tarball_hashes: std::sync::Arc<TarballHashes>,
    pub(crate) provenance_context: Option<&'a ResolvedProvenance>,
    pub(crate) target_label: &'a str,
    pub(crate) json_output: bool,
}
