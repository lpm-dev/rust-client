//! What LPM.dev review approved for each version of a package, as the
//! registry answered on this machine. Kept in LPM's cache, outside every
//! project, so files a repository commits under `.lpm/skills` can't pass
//! for reviewed skills: a materialized set counts as reviewed only where it
//! matches the record LPM wrote from the registry's answer. Records are
//! kept per registry, so one registry's approvals never vouch for skills
//! while LPM uses another.

use lpm_common::{LpmError, LpmRoot};
use lpm_registry::SkillReviewIssue;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Records written before they kept review warnings read as no record, so
/// a warned skill never passes for one review approved outright.
const RECORD_VERSION: u32 = 2;
/// Room for each approved skill's warning at its limits.
const MAX_RECORD_SIZE: u64 = 1024 * 1024;
/// How many of the risks review found in one skill a record keeps.
const MAX_WARNING_ISSUES: usize = 10;
/// How much of each risk's description a record keeps, in characters.
const MAX_WARNING_DESCRIPTION_CHARS: usize = 500;
/// How long a record that still leaves some of its package's skill
/// directories unapproved is trusted before an install asks again.
const PENDING_RECHECK_SECS: u64 = 24 * 60 * 60;

static ISSUING_REGISTRY: OnceLock<String> = OnceLock::new();

/// Names the LPM registry this process asks for package skills, the one
/// whose answers it records and reads.
pub(crate) fn use_registry(base_url: &str) {
    let _ = ISSUING_REGISTRY.set(base_url.trim_end_matches('/').to_string());
}

/// Names the registry a run asks when its command line names none:
/// `LPM_REGISTRY_URL`, else LPM.dev. The install fast lane, which answers
/// before the command line is parsed and only when it names no registry,
/// reads records under it.
pub(crate) fn use_registry_from_environment() {
    let named = std::env::var("LPM_REGISTRY_URL").ok();
    use_registry(
        named
            .as_deref()
            .filter(|url| !url.is_empty())
            .unwrap_or(lpm_common::DEFAULT_REGISTRY_URL),
    );
}

/// The registry whose answers LPM records and reads in this run.
pub(crate) fn issuing_registry() -> &'static str {
    ISSUING_REGISTRY
        .get()
        .map_or(lpm_common::DEFAULT_REGISTRY_URL, String::as_str)
}

/// The registry's answer for one version of one package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReviewRecord {
    pub(crate) schema_version: u32,
    /// The registry that answered, by base URL.
    pub(crate) registry: String,
    /// `owner.package`.
    pub(crate) package: String,
    pub(crate) version: String,
    /// Each approved flat skill, by name, with the digest of its document.
    pub(crate) skills: BTreeMap<String, String>,
    /// Each approved `skills/<name>/` directory, with the digest of its
    /// files.
    #[serde(default)]
    pub(crate) directories: BTreeMap<String, String>,
    /// The approved flat skills review served with a warning, by name, with
    /// the risks it found, which may be none it could describe.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) skill_warnings: BTreeMap<String, Vec<SkillReviewIssue>>,
    /// The approved directories review served with a warning, likewise.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) directory_warnings: BTreeMap<String, Vec<SkillReviewIssue>>,
    /// When the registry answered, in seconds since the Unix epoch.
    pub(crate) checked_at: u64,
    /// Whether the package ships a skill directory this answer didn't
    /// approve, so a later install asks again in case review approved it.
    #[serde(default)]
    pub(crate) pending: bool,
}

impl ReviewRecord {
    /// Whether an install should ask the registry again: a directory was
    /// waiting for review when this answer came, long enough ago.
    pub(crate) fn wants_recheck(&self) -> bool {
        self.pending && now_secs().saturating_sub(self.checked_at) >= PENDING_RECHECK_SECS
    }
}

/// What a registry's answer approved for one version of a package, and
/// which of those skills its review served with a warning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Approvals {
    /// Each approved flat skill, by name, with the digest of its document.
    pub(crate) skills: BTreeMap<String, String>,
    /// Each approved `skills/<name>/` directory, with the digest of its
    /// files.
    pub(crate) directories: BTreeMap<String, String>,
    /// The approved flat skills served with a warning, by name.
    pub(crate) skill_warnings: BTreeMap<String, Vec<SkillReviewIssue>>,
    /// The approved directories served with a warning, by name.
    pub(crate) directory_warnings: BTreeMap<String, Vec<SkillReviewIssue>>,
}

/// The risks review found in a skill it served with a warning, as a record
/// keeps them: at most [`MAX_WARNING_ISSUES`], each description on one line
/// with nothing a terminal acts on, and a severity or category that isn't a
/// short lowercase word left out.
pub(crate) fn recorded_warning(issues: &[SkillReviewIssue]) -> Vec<SkillReviewIssue> {
    let word = |text: &str| {
        (!text.is_empty()
            && text.len() <= 64
            && text.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            }))
        .then(|| text.to_string())
    };
    issues
        .iter()
        .filter_map(|issue| {
            let description =
                lpm_common::sanitize_server_text(&issue.description, MAX_WARNING_DESCRIPTION_CHARS);
            (!description.is_empty()).then(|| SkillReviewIssue {
                severity: word(&issue.severity).unwrap_or_else(|| "unknown".to_string()),
                category: issue.category.as_deref().and_then(word),
                description,
            })
        })
        .take(MAX_WARNING_ISSUES)
        .collect()
}

/// Where `registry`'s record of `package` (`owner.package`) at `version`
/// lives; `None` for a version that can't name a file.
fn record_path(root: &LpmRoot, registry: &str, package: &str, version: &str) -> Option<PathBuf> {
    let portable = |text: &str| {
        !text.is_empty()
            && text.len() <= 256
            && !text.starts_with('.')
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_+".contains(&byte))
    };
    if !portable(package) || !portable(version) {
        return None;
    }
    let mut path = root.cache_root();
    path.push("skill-reviews");
    path.push(hex::encode(&sha2::Sha256::digest(registry.as_bytes())[..8]));
    path.push(package);
    path.push(format!("{version}.json"));
    Some(path)
}

/// Runs `body` with the record at `path`, which it may replace, while no
/// other LPM process changes it.
fn with_record_locked<R>(
    path: &Path,
    body: impl FnOnce() -> Result<R, LpmError>,
) -> Result<R, LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    lpm_common::with_exclusive_lock(PathBuf::from(lock), body)
}

/// Records the registry's answer for `package` at `version`. A record that
/// was waiting on a directory stays waiting while the answer approves
/// nothing it didn't approve before, so a later install asks again.
pub(crate) fn write(package: &str, version: &str, approvals: Approvals) -> Result<(), LpmError> {
    write_for(issuing_registry(), package, version, approvals)
}

pub(crate) fn write_for(
    registry: &str,
    package: &str,
    version: &str,
    approvals: Approvals,
) -> Result<(), LpmError> {
    let Approvals {
        skills,
        directories,
        skill_warnings,
        directory_warnings,
    } = approvals;
    let root = LpmRoot::from_env()?;
    let Some(path) = record_path(&root, registry, package, version) else {
        return Ok(());
    };
    with_record_locked(&path, || {
        let pending = load(&path, registry, package, version).is_some_and(|previous| {
            previous.pending
                && directories
                    .iter()
                    .all(|(name, digest)| previous.directories.get(name) == Some(digest))
        });
        let record = ReviewRecord {
            schema_version: RECORD_VERSION,
            registry: registry.to_string(),
            package: package.to_string(),
            version: version.to_string(),
            skills,
            directories,
            skill_warnings,
            directory_warnings,
            checked_at: now_secs(),
            pending,
        };
        save(&path, &record)
    })
}

/// The active registry's record of `package` (`owner.package`) at
/// `version`, when LPM has one.
pub(crate) fn read(package: &str, version: &str) -> Option<ReviewRecord> {
    read_for(issuing_registry(), package, version)
}

pub(crate) fn read_for(registry: &str, package: &str, version: &str) -> Option<ReviewRecord> {
    let root = LpmRoot::from_env().ok()?;
    let path = record_path(&root, registry, package, version)?;
    load(&path, registry, package, version)
}

fn load(path: &Path, registry: &str, package: &str, version: &str) -> Option<ReviewRecord> {
    let content = lpm_common::read_text_file_capped(path, MAX_RECORD_SIZE).ok()?;
    let record: ReviewRecord = serde_json::from_str(&content).ok()?;
    (record.schema_version == RECORD_VERSION
        && record.registry == registry
        && record.package == package
        && record.version == version)
        .then_some(record)
}

/// Notes that `package` at `version` ships the skill directory `directory`
/// its record doesn't name, so a later install asks the registry again.
/// Only the record's `pending` flag changes, and only while the record
/// still doesn't name the directory.
pub(crate) fn mark_pending(package: &str, version: &str, directory: &str) -> Result<(), LpmError> {
    mark_pending_for(issuing_registry(), package, version, directory)
}

fn mark_pending_for(
    registry: &str,
    package: &str,
    version: &str,
    directory: &str,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let Some(path) = record_path(&root, registry, package, version) else {
        return Ok(());
    };
    if load(&path, registry, package, version)
        .is_none_or(|record| record.pending || record.directories.contains_key(directory))
    {
        return Ok(());
    }
    with_record_locked(&path, || {
        let Some(mut record) = load(&path, registry, package, version) else {
            return Ok(());
        };
        if record.pending || record.directories.contains_key(directory) {
            return Ok(());
        }
        record.pending = true;
        save(&path, &record)
    })
}

fn save(path: &Path, record: &ReviewRecord) -> Result<(), LpmError> {
    let mut content = serde_json::to_vec_pretty(record).map_err(|error| {
        LpmError::Registry(format!("failed to serialize a review record: {error}"))
    })?;
    content.push(b'\n');
    lpm_common::write_file_atomic(path, content)?;
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_lpm_home<T>(test: impl FnOnce() -> T) -> T {
        let _home = crate::test_env::isolated_lpm_home();
        test()
    }

    const REGISTRY: &str = "https://registry.example";

    fn approved(names: &[(&str, &str)]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|(name, digest)| ((*name).to_string(), format!("sha256:{digest}")))
            .collect()
    }

    fn write_directories(directories: &[(&str, &str)]) {
        write_for(
            REGISTRY,
            "acme.kit",
            "1.0.0",
            Approvals {
                directories: approved(directories),
                ..Approvals::default()
            },
        )
        .unwrap();
    }

    fn record() -> ReviewRecord {
        read_for(REGISTRY, "acme.kit", "1.0.0").unwrap()
    }

    #[test]
    fn a_refreshed_answer_stays_pending_until_it_approves_files_it_did_not_before() {
        with_lpm_home(|| {
            write_directories(&[("setup", "a")]);
            mark_pending_for(REGISTRY, "acme.kit", "1.0.0", "deploy").unwrap();

            write_directories(&[("setup", "a")]);
            assert!(record().pending);

            write_directories(&[("setup", "b")]);
            assert!(!record().pending);

            mark_pending_for(REGISTRY, "acme.kit", "1.0.0", "deploy").unwrap();
            write_directories(&[("setup", "b"), ("deploy", "c")]);
            assert!(!record().pending);
        });
    }

    fn issue(severity: &str, category: Option<&str>, description: &str) -> SkillReviewIssue {
        SkillReviewIssue {
            severity: severity.to_string(),
            category: category.map(str::to_string),
            description: description.to_string(),
        }
    }

    #[test]
    fn a_recorded_warning_is_bounded_and_fit_for_one_terminal_line() {
        let mut issues = vec![
            issue(
                "high",
                Some("insecure-patterns"),
                "Runs \u{1b}[2Jcurl\n| sh\ton request",
            ),
            issue("High; rm", Some("Not A Word"), "kept without its labels"),
            issue("low", None, " \n\t "),
            issue(
                "medium",
                None,
                &"x".repeat(2 * MAX_WARNING_DESCRIPTION_CHARS),
            ),
        ];
        issues.extend((0..MAX_WARNING_ISSUES).map(|_| issue("low", None, "more")));

        let recorded = recorded_warning(&issues);

        assert_eq!(recorded.len(), MAX_WARNING_ISSUES);
        assert_eq!(
            recorded[0],
            issue(
                "high",
                Some("insecure-patterns"),
                "Runs curl | sh on request"
            )
        );
        assert_eq!(
            recorded[1],
            issue("unknown", None, "kept without its labels")
        );
        assert_eq!(
            recorded[2].description.chars().count(),
            MAX_WARNING_DESCRIPTION_CHARS
        );
        assert!(recorded[2].description.ends_with('…'));
        assert_eq!(recorded[3].description, "more");
    }

    #[test]
    fn review_warnings_survive_a_written_record() {
        with_lpm_home(|| {
            let warned = vec![issue("high", Some("insecure-patterns"), "Runs curl | sh")];
            write_for(
                REGISTRY,
                "acme.kit",
                "1.0.0",
                Approvals {
                    skills: approved(&[("usage", "a")]),
                    directories: approved(&[("setup", "b")]),
                    skill_warnings: BTreeMap::from([("usage".to_string(), Vec::new())]),
                    directory_warnings: BTreeMap::from([("setup".to_string(), warned.clone())]),
                },
            )
            .unwrap();

            let record = record();
            assert_eq!(record.skill_warnings["usage"], Vec::new());
            assert_eq!(record.directory_warnings["setup"], warned);
        });
    }

    #[test]
    fn a_record_from_before_review_warnings_were_kept_reads_as_no_record() {
        with_lpm_home(|| {
            write_directories(&[("setup", "a")]);
            let root = LpmRoot::from_env().unwrap();
            let path = record_path(&root, REGISTRY, "acme.kit", "1.0.0").unwrap();
            let mut written: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            written["schema_version"] = serde_json::json!(1);
            std::fs::write(&path, serde_json::to_vec(&written).unwrap()).unwrap();

            assert!(read_for(REGISTRY, "acme.kit", "1.0.0").is_none());
        });
    }

    #[test]
    fn one_registrys_record_does_not_answer_for_another() {
        with_lpm_home(|| {
            write_directories(&[("setup", "a")]);

            assert!(read_for("https://other.example", "acme.kit", "1.0.0").is_none());
            assert_eq!(record().registry, REGISTRY);
        });
    }

    #[test]
    fn marking_pending_changes_only_the_flag_and_skips_a_directory_the_record_names() {
        with_lpm_home(|| {
            write_directories(&[("setup", "a")]);

            mark_pending_for(REGISTRY, "acme.kit", "1.0.0", "setup").unwrap();
            assert!(!record().pending);

            let before = record();
            mark_pending_for(REGISTRY, "acme.kit", "1.0.0", "deploy").unwrap();
            let after = record();
            assert!(after.pending);
            assert_eq!(
                ReviewRecord {
                    pending: false,
                    ..after
                },
                before
            );
        });
    }
}
