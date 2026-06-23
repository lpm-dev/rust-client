use crate::commands::publish_common::{NpmProvenanceAttachment, TarballFile};
use crate::oidc;
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

    /// Key for JSON output.
    pub fn key(&self) -> String {
        match self {
            Self::Lpm => "lpm".into(),
            Self::Npm => "npm".into(),
            Self::GitHub => "github".into(),
            Self::GitLab => "gitlab".into(),
            Self::Custom(url) => url.clone(),
        }
    }

    /// CLI flag to retry a failed publish for this target.
    pub fn retry_flag(&self) -> String {
        match self {
            Self::Lpm => "--lpm".into(),
            Self::Npm => "--npm".into(),
            Self::GitHub => "--github".into(),
            Self::GitLab => "--gitlab".into(),
            Self::Custom(url) => format!("--publish-registry {url}"),
        }
    }
}

/// Result of publishing to a single registry.
#[derive(Debug)]
pub struct PublishResult {
    pub target: String,
    pub success: bool,
    pub error: Option<String>,
    pub auth: Option<&'static str>,
    pub duration: std::time::Duration,
}

/// Local package artifact prepared for publish-like uploads.
pub(crate) struct PublishProject {
    pub(crate) package_json_path: std::path::PathBuf,
    pub(crate) pkg_json: serde_json::Value,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) publish_config: Option<lpm_json::PublishConfig>,
    pub(crate) readme: Option<String>,
    pub(crate) tarball_data: Vec<u8>,
    pub(crate) tarball_files: Vec<TarballFile>,
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
    pub(crate) tarball_data: Vec<u8>,
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
    pub(crate) package_json_name: &'a str,
    pub(crate) npm_name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) base_version_data: &'a serde_json::Value,
    pub(crate) base_tarball_data: &'a [u8],
    pub(crate) provenance_context: Option<&'a ResolvedProvenance>,
    pub(crate) target_label: &'a str,
    pub(crate) json_output: bool,
}
