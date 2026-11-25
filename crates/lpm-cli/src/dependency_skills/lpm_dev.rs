//! LPM.dev package skills as agents see them. Installs materialize each
//! `@lpm.dev` dependency's reviewed flat skills, `lpm-skills/<name>.md`, in
//! `.lpm/skills/<owner.package>/`, with the digests of the `skills/<name>/`
//! directories review approved. Each flat skill links as an
//! `<owner>-<package>-<name>/SKILL.md` directory, so generic names such as
//! `usage` from two packages don't collide; names that still meet, such as
//! `acme.ui` + `kit-setup` and `acme.ui-kit` + `setup`, are held as a name
//! conflict like any other.

use lpm_registry::SkillReviewIssue;
use lpm_skill::{MAX_SKILL_NAME_LENGTH, is_skill_name};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One LPM.dev package's reviewed skills in one project.
#[derive(Debug, Clone)]
pub(crate) struct ReviewedSet {
    /// `@lpm.dev/owner.package`.
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) skills: Vec<ReviewedSkill>,
    /// The `skills/<name>/` directories review approved, with the digest of
    /// the approved files, as LPM recorded the registry's answer on this
    /// machine.
    pub(crate) directories: BTreeMap<String, String>,
    /// Those of `directories` review served with a warning, with the risks
    /// it found.
    pub(crate) directory_warnings: BTreeMap<String, Vec<SkillReviewIssue>>,
    /// Whether LPM holds a record of the registry's answer for this version.
    pub(crate) recorded: bool,
    /// The flat skills that record approved, under the names agents see:
    /// what the version ships as far as LPM can vouch, whatever files the
    /// set holds.
    pub(crate) approved: Vec<String>,
    /// Whether `lpm skills add` delivered it, so it links although the
    /// project doesn't install the package.
    pub(crate) added: bool,
}

impl ReviewedSet {
    /// Whether review served `skill`, under the name agents see, with a
    /// warning.
    pub(crate) fn review_warned(&self, skill: &str) -> bool {
        self.directory_warnings.contains_key(skill)
            || self
                .skills
                .iter()
                .any(|reviewed| reviewed.name == skill && reviewed.warning.is_some())
    }
}

/// A reviewed flat skill, under the name agents see.
#[derive(Debug, Clone)]
pub(crate) struct ReviewedSkill {
    pub(crate) name: String,
    /// The reviewed document with its frontmatter `name` set to `name`, or
    /// why it can't link under that name.
    pub(crate) document: Result<String, String>,
    /// Whether the document is the one the registry approved, as LPM
    /// recorded its answer on this machine. Files a checkout carries in
    /// `.lpm/skills` prove nothing by themselves.
    pub(crate) verified: bool,
    /// For a verified document review served with a warning, the risks it
    /// found.
    pub(crate) warning: Option<Vec<SkillReviewIssue>>,
}

fn sets_root(project_dir: &Path) -> PathBuf {
    let mut root = project_dir.join(lpm_common::PROJECT_STATE_DIR);
    root.push("skills");
    root
}

/// Whether `.lpm` and `.lpm/skills` in `project_dir` are plain directories,
/// not links or junctions to somewhere else.
fn sets_root_is_plain(project_dir: &Path) -> bool {
    matches!(
        crate::project_fs::open_directory(project_dir, Path::new(".lpm/skills")),
        Ok(Some(_))
    )
}

/// Whether an install materialized any LPM.dev package's skills in
/// `project_dir`; reads one directory.
pub(crate) fn has_reviewed_sets(project_dir: &Path) -> bool {
    std::fs::read_dir(sets_root(project_dir)).is_ok_and(|mut entries| {
        entries.any(|entry| {
            entry.is_ok_and(|entry| {
                !entry.file_name().to_string_lossy().starts_with('.')
                    && entry.file_type().is_ok_and(|kind| kind.is_dir())
            })
        })
    })
}

/// The reviewed sets materialized in `project_dir`, sorted by package. A
/// set with local changes or an invalid manifest is left out, as is a flat
/// skill whose name or frontmatter can't carry its package's name. What
/// counts as reviewed comes from the record LPM keeps of the registry's
/// answer, never from the set's own manifest. `.lpm/skills` is read only
/// through plain directories.
pub(crate) fn reviewed_sets(project_dir: &Path) -> Vec<ReviewedSet> {
    if !sets_root_is_plain(project_dir) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(sets_root(project_dir)) else {
        return Vec::new();
    };
    let mut sets: Vec<ReviewedSet> = entries
        .flatten()
        .filter(|entry| !entry.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|entry| crate::commands::skills::package::materialized_set(&entry.path()))
        .map(|set| {
            let version = set.version.unwrap_or_default();
            let record = crate::commands::skills::reviews::read(&set.package, &version);
            let mut skills: Vec<ReviewedSkill> = set
                .skills
                .iter()
                .filter_map(|(skill, document)| {
                    let name = linked_name(&set.package, skill)?;
                    let verified = record.as_ref().is_some_and(|record| {
                        record.skills.get(skill).is_some_and(|approved| {
                            *approved == crate::commands::skills::package::digest(document.as_bytes())
                        })
                    });
                    let warning = record
                        .as_ref()
                        .filter(|_| verified)
                        .and_then(|record| record.skill_warnings.get(skill).cloned());
                    let document = with_name(document, &name).ok_or_else(|| {
                        format!(
                            "`{skill}.md` has no top-level `name` in its frontmatter for LPM to set to `{name}`"
                        )
                    });
                    Some(ReviewedSkill {
                        name,
                        document,
                        verified,
                        warning,
                    })
                })
                .collect();
            let mut seen = BTreeMap::new();
            for skill in &skills {
                *seen.entry(skill.name.clone()).or_insert(0usize) += 1;
            }
            for skill in &mut skills {
                if seen[&skill.name] > 1 {
                    skill.document = Err(format!(
                        "more than one of the package's skills links as `{}`",
                        skill.name
                    ));
                }
            }
            let directories: BTreeMap<String, String> = set
                .directories
                .into_iter()
                .filter(|(name, digest)| {
                    record
                        .as_ref()
                        .is_some_and(|record| record.directories.get(name) == Some(digest))
                })
                .collect();
            let directory_warnings = record
                .as_ref()
                .map(|record| {
                    record
                        .directory_warnings
                        .iter()
                        .filter(|(name, _)| directories.contains_key(*name))
                        .map(|(name, issues)| (name.clone(), issues.clone()))
                        .collect()
                })
                .unwrap_or_default();
            let approved = record
                .as_ref()
                .map(|record| {
                    record
                        .skills
                        .keys()
                        .filter_map(|skill| linked_name(&set.package, skill))
                        .collect()
                })
                .unwrap_or_default();
            ReviewedSet {
                package: format!("@lpm.dev/{}", set.package),
                version,
                skills,
                directories,
                directory_warnings,
                recorded: record.is_some(),
                approved,
                added: set.origin == crate::commands::skills::package::SetOrigin::Added,
            }
        })
        .collect();
    sets.sort_by(|left, right| left.package.cmp(&right.package));
    sets
}

/// A digest of the reviewed-set manifests in each of `project_dirs`, so a
/// set an install refreshed without the lockfile changing, such as one
/// review approved since, links again; and, when there is a set, of the
/// registry whose review records count, so switching registries reconciles
/// the links of projects that have LPM.dev skills.
pub(crate) fn sets_fingerprint(project_dirs: &[PathBuf]) -> String {
    sets_fingerprint_under(
        crate::commands::skills::reviews::issuing_registry(),
        project_dirs,
    )
}

/// [`sets_fingerprint`] with `registry` the one whose review records count.
fn sets_fingerprint_under(registry: &str, project_dirs: &[PathBuf]) -> String {
    let mut hasher = Sha256::new();
    let mut names_registry = false;
    for (index, project_dir) in project_dirs.iter().enumerate() {
        let Ok(entries) = std::fs::read_dir(sets_root(project_dir)) else {
            continue;
        };
        let mut manifests: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| {
                entry
                    .path()
                    .join(crate::commands::skills::package::MANIFEST_FILE)
            })
            .collect();
        manifests.sort();
        for manifest in manifests {
            if let Ok(content) = lpm_common::read_file_capped(&manifest, 64 * 1024) {
                if !names_registry {
                    hasher.update(registry);
                    hasher.update([0]);
                    names_registry = true;
                }
                hasher.update((index as u64).to_be_bytes());
                hasher.update(manifest.as_os_str().as_encoded_bytes());
                hasher.update([0]);
                hasher.update(&content);
                hasher.update([0]);
                hasher.update(review_fingerprint(registry, &content));
            }
        }
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// What `registry`'s LPM.dev review approved for the set whose manifest
/// reads `manifest`, and what it warned about, as the record LPM keeps
/// says: a set waiting for its record links once another install writes
/// one, and a warning changes what links, so the record counts.
fn review_fingerprint(registry: &str, manifest: &[u8]) -> Vec<u8> {
    #[derive(serde::Deserialize)]
    struct Identity {
        package: String,
        #[serde(default)]
        version: Option<String>,
    }
    let Ok(identity) = serde_json::from_slice::<Identity>(manifest) else {
        return Vec::new();
    };
    identity
        .version
        .and_then(|version| {
            crate::commands::skills::reviews::read_for(registry, &identity.package, &version)
        })
        .and_then(|record| {
            serde_json::to_vec(&(
                record.skills,
                record.directories,
                record.skill_warnings,
                record.directory_warnings,
            ))
            .ok()
        })
        .unwrap_or_default()
}

/// What `registry`'s LPM.dev review warned about in the skill a version of
/// `package` (`@lpm.dev/owner.package`) links as `name` from the files
/// `digest` names, as LPM recorded its answer.
pub(crate) fn recorded_review_warning(
    registry: &str,
    package: &str,
    version: &str,
    name: &str,
    digest: &str,
) -> Option<Vec<SkillReviewIssue>> {
    let short = package.strip_prefix("@lpm.dev/")?;
    let record = crate::commands::skills::reviews::read_for(registry, short, version)?;
    if record.directories.get(name).map(String::as_str) == Some(digest) {
        return record.directory_warnings.get(name).cloned();
    }
    record
        .skill_warnings
        .iter()
        .find(|(skill, _)| linked_name(short, skill).as_deref() == Some(name))
        .map(|(_, issues)| issues.clone())
}

/// What LPM.dev review warned about in a skill, for one terminal row: at
/// most [`SHOWN_REVIEW_ISSUES`] of the risks it found, then how many more
/// `--json` lists.
pub(crate) fn review_warning_note(issues: &[SkillReviewIssue]) -> String {
    let mut note = String::from("LPM.dev review warned about it");
    for (index, issue) in issues.iter().take(SHOWN_REVIEW_ISSUES).enumerate() {
        note.push_str(if index == 0 { ": " } else { "; " });
        note.push_str(&issue.severity);
        if let Some(category) = &issue.category {
            note.push(' ');
            note.push_str(category);
        }
        note.push_str(", ");
        note.push_str(&issue.description);
    }
    if issues.len() > SHOWN_REVIEW_ISSUES {
        note.push_str("; and ");
        note.push_str(&(issues.len() - SHOWN_REVIEW_ISSUES).to_string());
        note.push_str(" more");
    }
    note
}

const SHOWN_REVIEW_ISSUES: usize = 3;

/// The name an LPM.dev package's flat skill links as: `owner.package` and
/// `usage` give `owner-package-usage`. A name past the Agent Skills limit
/// keeps its start and gains a hash of the whole, so it stays unique.
pub(crate) fn linked_name(short_package: &str, skill: &str) -> Option<String> {
    let mut name = String::with_capacity(short_package.len() + skill.len() + 1);
    for character in short_package
        .chars()
        .chain(std::iter::once('-'))
        .chain(skill.chars())
    {
        let character = match character {
            '.' | '_' => '-',
            character => character.to_ascii_lowercase(),
        };
        if character == '-' && name.ends_with('-') {
            continue;
        }
        name.push(character);
    }
    let name = name.trim_matches('-').to_string();
    if is_skill_name(&name) {
        return Some(name);
    }
    let digest = hex::encode(Sha256::digest(format!("{short_package}/{skill}")));
    let keep = MAX_SKILL_NAME_LENGTH - 9;
    let mut shortened: String = name.chars().take(keep).collect();
    while shortened.ends_with('-') {
        shortened.pop();
    }
    shortened.push('-');
    shortened.push_str(&digest[..8]);
    is_skill_name(&shortened).then_some(shortened)
}

/// `document` with the top-level `name` of its frontmatter set to `name`,
/// written however YAML allows (quoted, spaced before the colon, or as a
/// value running over several lines), or `None` when it has no frontmatter
/// or no such key. A leading byte order mark is dropped.
pub(crate) fn with_name(document: &str, name: &str) -> Option<String> {
    let document = document.strip_prefix('\u{feff}').unwrap_or(document);
    let body_start = if document.starts_with("---\r\n") {
        5
    } else if document.starts_with("---\n") {
        4
    } else {
        return None;
    };
    let mut output = String::with_capacity(document.len() + name.len());
    output.push_str(&document[..body_start]);
    let mut replaced = false;
    let mut in_frontmatter = true;
    let mut in_old_value = false;
    for line in document[body_start..].split_inclusive('\n') {
        let bare = line.trim_end_matches(['\n', '\r']);
        if in_frontmatter {
            if in_old_value {
                if bare.is_empty() || bare.starts_with([' ', '\t']) {
                    continue;
                }
                in_old_value = false;
            }
            if bare == "---" {
                in_frontmatter = false;
            } else if !replaced && is_name_key(bare) {
                output.push_str("name: ");
                output.push_str(name);
                output.push_str(&line[bare.len()..]);
                replaced = true;
                in_old_value = true;
                continue;
            }
        }
        output.push_str(line);
    }
    (replaced && !in_frontmatter).then_some(output)
}

/// Whether `line` starts the frontmatter's top-level `name` key.
fn is_name_key(line: &str) -> bool {
    ["name", "\"name\"", "'name'"]
        .iter()
        .filter_map(|key| line.strip_prefix(key))
        .any(|rest| rest.trim_start_matches([' ', '\t']).starts_with(':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::skills::reviews::Approvals;

    fn setup_approved() -> Approvals {
        Approvals {
            directories: BTreeMap::from([("setup".to_string(), "sha256:setup".to_string())]),
            ..Approvals::default()
        }
    }

    #[test]
    fn a_review_record_written_after_the_set_changes_the_sets_fingerprint() {
        let _home = crate::test_env::isolated_lpm_home();
        let project = tempfile::tempdir().unwrap();
        let set = sets_root(project.path()).join("acme.ui");
        std::fs::create_dir_all(&set).unwrap();
        std::fs::write(
            set.join(crate::commands::skills::package::MANIFEST_FILE),
            r#"{"schema_version":1,"package":"acme.ui","version":"1.0.0","skills":{}}"#,
        )
        .unwrap();
        let importers = [project.path().to_path_buf()];
        let before = sets_fingerprint(&importers);

        crate::commands::skills::reviews::write("acme.ui", "1.0.0", setup_approved()).unwrap();

        assert_ne!(sets_fingerprint(&importers), before);
    }

    /// A workspace whose root has no LPM.dev skills and whose member
    /// `packages/ui` has the set of `acme.ui@1.0.0`, as importers.
    fn workspace_with_a_member_set(root: &Path) -> [PathBuf; 2] {
        let member = root.join("packages/ui");
        let set = sets_root(&member).join("acme.ui");
        std::fs::create_dir_all(&set).unwrap();
        std::fs::write(
            set.join(crate::commands::skills::package::MANIFEST_FILE),
            r#"{"schema_version":1,"package":"acme.ui","version":"1.0.0","skills":{}}"#,
        )
        .unwrap();
        [root.to_path_buf(), member]
    }

    #[test]
    fn the_sets_fingerprint_changes_with_the_registry_whose_reviews_count_once_a_set_exists() {
        let _home = crate::test_env::isolated_lpm_home();
        let project = tempfile::tempdir().unwrap();
        let root_only = [project.path().to_path_buf()];
        assert_eq!(
            sets_fingerprint_under("https://one.example", &root_only),
            sets_fingerprint_under("https://other.example", &root_only),
            "a project without LPM.dev skills ignores the registry"
        );

        let importers = workspace_with_a_member_set(project.path());

        assert_ne!(
            sets_fingerprint_under("https://one.example", &importers),
            sets_fingerprint_under("https://other.example", &importers),
            "a member's set makes the registry count"
        );
    }

    #[test]
    fn a_review_record_counts_only_toward_its_own_registrys_fingerprint() {
        let _home = crate::test_env::isolated_lpm_home();
        let project = tempfile::tempdir().unwrap();
        let importers = workspace_with_a_member_set(project.path());
        let one = sets_fingerprint_under("https://one.example", &importers);
        let other = sets_fingerprint_under("https://other.example", &importers);

        crate::commands::skills::reviews::write_for(
            "https://one.example",
            "acme.ui",
            "1.0.0",
            setup_approved(),
        )
        .unwrap();

        assert_ne!(
            sets_fingerprint_under("https://one.example", &importers),
            one
        );
        assert_eq!(
            sets_fingerprint_under("https://other.example", &importers),
            other
        );
    }

    #[test]
    fn a_review_warning_recorded_later_changes_the_sets_fingerprint() {
        let _home = crate::test_env::isolated_lpm_home();
        let project = tempfile::tempdir().unwrap();
        let importers = workspace_with_a_member_set(project.path());
        crate::commands::skills::reviews::write("acme.ui", "1.0.0", setup_approved()).unwrap();
        let clean = sets_fingerprint(&importers);

        let mut warned = setup_approved();
        warned
            .directory_warnings
            .insert("setup".to_string(), Vec::new());
        crate::commands::skills::reviews::write("acme.ui", "1.0.0", warned).unwrap();

        assert_ne!(sets_fingerprint(&importers), clean);
    }

    #[test]
    fn linked_names_qualify_the_skill_with_its_package() {
        assert_eq!(
            linked_name("owner.package", "usage").as_deref(),
            Some("owner-package-usage")
        );
        assert_eq!(
            linked_name("acme.ui_kit", "getting-started").as_deref(),
            Some("acme-ui-kit-getting-started")
        );
    }

    #[test]
    fn long_linked_names_stay_within_the_limit_and_unique() {
        let long_package = format!("owner.{}", "p".repeat(80));
        let first = linked_name(&long_package, "usage").unwrap();
        let second = linked_name(&long_package, "guide").unwrap();
        assert!(first.len() <= MAX_SKILL_NAME_LENGTH);
        assert!(is_skill_name(&first));
        assert_ne!(first, second);
    }

    #[test]
    fn the_frontmatter_name_is_rewritten_and_nothing_else_changes() {
        let document = "---\nname: usage\ndescription: Use it.\n---\n\nname: not frontmatter\n";
        assert_eq!(
            with_name(document, "owner-package-usage").unwrap(),
            "---\nname: owner-package-usage\ndescription: Use it.\n---\n\nname: not frontmatter\n"
        );
        let crlf = "---\r\nname: usage\r\ndescription: Use it.\r\n---\r\nBody\r\n";
        assert_eq!(
            with_name(crlf, "x").unwrap(),
            "---\r\nname: x\r\ndescription: Use it.\r\n---\r\nBody\r\n"
        );
        assert!(with_name("no frontmatter", "x").is_none());
        assert!(with_name("---\ndescription: d\n---\n", "x").is_none());
        assert!(with_name("---\nname: usage\n", "x").is_none());
    }

    #[test]
    fn a_name_written_any_way_yaml_allows_is_replaced_whole() {
        assert_eq!(
            with_name("\u{feff}---\nname: usage\n---\nBody\n", "x").unwrap(),
            "---\nname: x\n---\nBody\n"
        );
        assert_eq!(
            with_name("---\n\"name\": usage\nnamespace: kept\n---\n", "x").unwrap(),
            "---\nname: x\nnamespace: kept\n---\n"
        );
        assert_eq!(
            with_name("---\nname : usage\n---\n", "x").unwrap(),
            "---\nname: x\n---\n"
        );
        assert_eq!(
            with_name("---\nname: >\n  usage\n  guide\ndescription: d\n---\n", "x").unwrap(),
            "---\nname: x\ndescription: d\n---\n"
        );
    }
}
