use crate::commands::publish_common::{NpmProvenanceAttachment, TarballFile};
use crate::oidc;
use lpm_common::LpmError;
use lpm_runner::lpm_json;
use std::path::Path;

/// Target registries for a publish operation.
#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationWaitResult {
    pub success: bool,
    pub status: Option<LpmPublicationStatus>,
    pub current_latest_version: Option<String>,
    pub error: Option<String>,
}

impl PublicationWaitResult {
    pub(super) fn active() -> Self {
        Self {
            success: true,
            status: Some(LpmPublicationStatus::Active),
            current_latest_version: None,
            error: None,
        }
    }

    pub(super) fn terminal(status: LpmPublicationStatus) -> Self {
        let message = match status {
            LpmPublicationStatus::ManualReview => "publication requires manual review",
            LpmPublicationStatus::Rejected => "publication review rejected the version",
            LpmPublicationStatus::Quarantined => "the uploaded version was quarantined",
            LpmPublicationStatus::Unpublished => "the uploaded version was unpublished",
            LpmPublicationStatus::Other(_) => {
                "the Registry returned an unrecognized publication state"
            }
            LpmPublicationStatus::Active
            | LpmPublicationStatus::PendingReview
            | LpmPublicationStatus::Processing => "publication did not become active",
        };
        Self {
            success: false,
            status: Some(status),
            current_latest_version: None,
            error: Some(format!(
                "Upload succeeded, but {message}. Do not publish this version again."
            )),
        }
    }

    pub(super) fn timed_out(status: Option<LpmPublicationStatus>) -> Self {
        Self {
            success: false,
            status,
            current_latest_version: None,
            error: Some(
                "Upload succeeded, but waiting for LPM.dev Registry publication timed out. Do not publish this version again."
                    .to_string(),
            ),
        }
    }

    pub(super) fn request_failed(error: &LpmError) -> Self {
        Self {
            success: false,
            status: None,
            current_latest_version: None,
            error: Some(format!(
                "Upload succeeded, but LPM.dev Registry publication could not be checked: {error}. Do not publish this version again."
            )),
        }
    }

    pub(super) fn with_current_latest_version(
        mut self,
        current_latest_version: Option<String>,
    ) -> Self {
        self.current_latest_version = current_latest_version;
        self
    }
}

/// Result of publishing to a single registry.
#[derive(Debug)]
pub struct PublishResult {
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub auth: Option<&'static str>,
    pub publication_status: Option<LpmPublicationStatus>,
    pub current_latest_version: Option<String>,
    pub publication_wait: Option<PublicationWaitResult>,
    pub duration: std::time::Duration,
}

/// Local package artifact prepared for publish-like uploads.
pub(crate) struct PublishProject {
    pub(crate) pkg_json: serde_json::Value,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publish_config: Option<lpm_json::PublishConfig>,
    pub(crate) readme: Option<String>,
    pub(crate) tarball_data: std::sync::Arc<Vec<u8>>,
    pub(crate) tarball_files: Vec<TarballFile>,
    pub(crate) secret_scan: Option<lpm_security::behavioral::secrets::SecretScanResult>,
    pub(crate) tarball_size: usize,
    pub(crate) detected_ecosystem: String,
    pub(crate) swift_manifest: Option<serde_json::Value>,
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
    pub(crate) tarball_data: std::sync::Arc<Vec<u8>>,
    pub(crate) version_data: serde_json::Value,
    pub(crate) provenance_attachment: Option<NpmProvenanceAttachment>,
}

pub(crate) struct PublishQualityGateInput<'a> {
    pub(crate) pkg_json: &'a serde_json::Value,
    pub(crate) readme: Option<&'a str>,
    pub(crate) project_dir: &'a Path,
    pub(crate) tarball_files: &'a [TarballFile],
    pub(crate) detected_ecosystem: &'a str,
    pub(crate) swift_manifest: Option<&'a serde_json::Value>,
    pub(crate) min_score: Option<u32>,
    pub(crate) json_output: bool,
}

pub(crate) struct NpmTargetArtifactInput<'a> {
    pub(crate) npm_name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) base_version_data: &'a serde_json::Value,
    pub(crate) final_tarball_data: std::sync::Arc<Vec<u8>>,
    pub(crate) provenance_context: Option<&'a ResolvedProvenance>,
    pub(crate) target_label: &'a str,
    pub(crate) json_output: bool,
}
