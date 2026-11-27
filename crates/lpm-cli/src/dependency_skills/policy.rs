use lpm_security::query::{PseudoClass, Selector, parse_selector};
use std::collections::BTreeSet;

/// The key under `package.json > lpm` that holds the project's policy.
pub(crate) const POLICY_KEY: &str = "skills";
/// The most entries `allow` or `deny` holds.
pub(crate) const MAX_POLICY_ENTRIES: usize = 256;
/// The longest selector an entry can hold, in bytes.
const MAX_SELECTOR_LENGTH: usize = 1024;
/// The most explicit target directories.
const MAX_TARGETS: usize = 16;
/// Path components a target directory may not pass through.
const RESERVED_TARGET_COMPONENTS: [&str; 3] = [".git", ".lpm", "node_modules"];

/// Which skills of installed dependencies a project lets agents see, from
/// `package.json > lpm > skills`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SkillsPolicy {
    pub(crate) allow: Vec<PolicyEntry>,
    pub(crate) deny: Vec<PolicyEntry>,
    pub(crate) targets: Targets,
    /// Whether a `deny` entry, or a key such as a misspelled `deny`,
    /// couldn't be read. What the policy denies is then unknown, so it
    /// links nothing.
    pub(crate) deny_unreadable: bool,
}

/// One selector, with the text the project wrote.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PolicyEntry {
    pub(crate) text: String,
    pub(crate) selector: Selector,
}

/// The project directories skills are linked into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Targets {
    /// `.agents/skills`, which most coding agents read, plus
    /// `.claude/skills` when the project has a `.claude` directory.
    Auto,
    /// Project-relative directories, `/`-separated.
    Explicit(Vec<String>),
}

/// The policy a manifest declares, and what was wrong with it.
#[derive(Debug, Default)]
pub(crate) struct ParsedPolicy {
    /// `None` when the manifest declares no policy, or one too malformed to
    /// apply.
    pub(crate) policy: Option<SkillsPolicy>,
    pub(crate) problems: Vec<String>,
}

impl SkillsPolicy {
    /// Whether the policy can link anything: it allows at least one
    /// selector, and every `deny` entry could be read.
    pub(crate) fn is_active(&self) -> bool {
        !self.allow.is_empty() && !self.deny_unreadable
    }

    /// A stable text form for fingerprints: canonical selectors in written
    /// order, then the targets.
    pub(crate) fn fingerprint_text(&self) -> String {
        let mut text = String::with_capacity(64);
        for (label, entries) in [("allow", &self.allow), ("deny", &self.deny)] {
            text.push_str(label);
            for entry in entries {
                text.push('\0');
                text.push_str(&entry.selector.to_string());
            }
            text.push('\n');
        }
        match &self.targets {
            Targets::Auto => text.push_str("targets\0auto"),
            Targets::Explicit(targets) => {
                text.push_str("targets");
                for target in targets {
                    text.push('\0');
                    text.push_str(target);
                }
            }
        }
        text
    }
}

/// Reads the policy from a parsed `package.json`.
pub(crate) fn read_policy(manifest: &serde_json::Value) -> ParsedPolicy {
    let Some(value) = manifest
        .get("lpm")
        .and_then(|lpm| lpm.get(POLICY_KEY))
        .filter(|value| !value.is_null())
    else {
        return ParsedPolicy::default();
    };
    let mut problems = Vec::new();
    let Some(object) = value.as_object() else {
        problems.push(format!(
            "`lpm.{POLICY_KEY}` must be an object with `allow`, `deny` and `targets`"
        ));
        return ParsedPolicy {
            policy: None,
            problems,
        };
    };
    let mut keys_known = true;
    for key in object.keys() {
        if !matches!(key.as_str(), "allow" | "deny" | "targets") {
            problems.push(format!(
                "`lpm.{POLICY_KEY}.{key}` is not a known key; use `allow`, `deny` or `targets`"
            ));
            keys_known = false;
        }
    }
    let (deny, deny_complete) = read_entries(object.get("deny"), "deny", &mut problems);
    let (allow, _) = read_entries(object.get("allow"), "allow", &mut problems);
    let targets = read_targets(object.get("targets"), &mut problems);
    if !deny_complete || !keys_known {
        problems.push(format!(
            "`lpm.{POLICY_KEY}` holds entries LPM can't read, so no dependency skills are linked until they are fixed"
        ));
    }
    ParsedPolicy {
        policy: Some(SkillsPolicy {
            allow,
            deny,
            targets,
            deny_unreadable: !deny_complete || !keys_known,
        }),
        problems,
    }
}

/// A digest of the policy's links-deciding content, `inactive` when it
/// links nothing.
pub(crate) fn policy_digest(policy: Option<&SkillsPolicy>) -> String {
    use sha2::{Digest as _, Sha256};
    match policy.filter(|policy| policy.is_active()) {
        Some(policy) => format!(
            "sha256:{}",
            hex::encode(Sha256::digest(policy.fingerprint_text()))
        ),
        None => "inactive".to_string(),
    }
}

/// The entries of one list, and whether every entry could be read.
fn read_entries(
    value: Option<&serde_json::Value>,
    field: &str,
    problems: &mut Vec<String>,
) -> (Vec<PolicyEntry>, bool) {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return (Vec::new(), true);
    };
    let Some(items) = value.as_array() else {
        problems.push(format!(
            "`lpm.{POLICY_KEY}.{field}` must be an array of selectors"
        ));
        return (Vec::new(), false);
    };
    let mut entries = Vec::with_capacity(items.len().min(MAX_POLICY_ENTRIES));
    let mut complete = true;
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let location = format!("`lpm.{POLICY_KEY}.{field}[{index}]`");
        if index == MAX_POLICY_ENTRIES {
            problems.push(format!(
                "`lpm.{POLICY_KEY}.{field}` holds more than {MAX_POLICY_ENTRIES} selectors; {location} and later entries are ignored"
            ));
            complete = false;
            break;
        }
        let Some(text) = item.as_str() else {
            problems.push(format!("{location} must be a selector string"));
            complete = false;
            continue;
        };
        if text.len() > MAX_SELECTOR_LENGTH {
            problems.push(format!(
                "{location} is longer than {MAX_SELECTOR_LENGTH} bytes"
            ));
            complete = false;
            continue;
        }
        match parse_selector(text) {
            Ok(selector) => {
                if let Some(class) = standalone_root(&selector) {
                    problems.push(format!(
                        "{location} uses `{}` on its own, which no installed package is; it works before `>`, as in `{} > #pkg`",
                        class.display_name(),
                        class.display_name()
                    ));
                    complete = false;
                    continue;
                }
                if let Some(class) = unsupported_class(&selector) {
                    problems.push(format!(
                        "{location} uses `{}`, which skill selectors can't decide; use package names, `:skills`, `:skill()`, `:malware`, `:lpm`, `:npm`, `:root`, `>` and behavioral tags",
                        class.display_name()
                    ));
                    complete = false;
                    continue;
                }
                if seen.insert(selector.to_string()) {
                    entries.push(PolicyEntry {
                        text: text.trim().to_string(),
                        selector,
                    });
                }
            }
            Err(error) => {
                problems.push(format!(
                    "{location} is not a valid selector: {}",
                    error.message
                ));
                complete = false;
            }
        }
    }
    (entries, complete)
}

fn read_targets(value: Option<&serde_json::Value>, problems: &mut Vec<String>) -> Targets {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Targets::Auto;
    };
    if value.as_str() == Some("auto") {
        return Targets::Auto;
    }
    let Some(items) = value.as_array() else {
        problems.push(format!(
            "`lpm.{POLICY_KEY}.targets` must be \"auto\" or an array of project directories"
        ));
        return Targets::Explicit(Vec::new());
    };
    let mut targets: Vec<String> = Vec::with_capacity(items.len().min(MAX_TARGETS));
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let location = format!("`lpm.{POLICY_KEY}.targets[{index}]`");
        if targets.len() == MAX_TARGETS {
            problems.push(format!(
                "`lpm.{POLICY_KEY}.targets` holds more than {MAX_TARGETS} directories; {location} and later entries are ignored"
            ));
            break;
        }
        let Some(text) = item.as_str() else {
            problems.push(format!("{location} must be a directory path"));
            continue;
        };
        match normalize_target(text) {
            Ok(target) => {
                if seen.insert(target.to_ascii_lowercase()) {
                    targets.push(target);
                }
            }
            Err(reason) => problems.push(format!("{location} `{text}` {reason}")),
        }
    }
    Targets::Explicit(targets)
}

/// A `:root` or `:workspace-root` in `selector` other than as the parent of
/// `>`: on its own it names the project, never a package, so it decides
/// nothing.
fn standalone_root(selector: &Selector) -> Option<PseudoClass> {
    match selector {
        Selector::PseudoClass(class @ (PseudoClass::Root | PseudoClass::WorkspaceRoot)) => {
            Some(*class)
        }
        Selector::PseudoClass(_) | Selector::Id(_) | Selector::Skill(_) => None,
        Selector::And(parts) | Selector::Or(parts) => parts.iter().find_map(standalone_root),
        Selector::Not(inner) => standalone_root(inner),
        Selector::DirectChild { parent, child } => match parent.as_ref() {
            Selector::PseudoClass(PseudoClass::Root | PseudoClass::WorkspaceRoot) => {
                standalone_root(child)
            }
            parent => standalone_root(parent).or_else(|| standalone_root(child)),
        },
    }
}

/// Parses `text` as a skill-policy selector, refusing what [`read_policy`]
/// would drop, and returns it in canonical form.
pub(crate) fn validate_selector(text: &str) -> Result<String, String> {
    if text.len() > MAX_SELECTOR_LENGTH {
        return Err(format!(
            "`{text}` is longer than {MAX_SELECTOR_LENGTH} bytes"
        ));
    }
    let selector = parse_selector(text)
        .map_err(|error| format!("`{text}` is not a valid selector: {}", error.message))?;
    if let Some(class) = standalone_root(&selector) {
        return Err(format!(
            "`{text}` uses `{}` on its own, which no installed package is; it works before `>`",
            class.display_name()
        ));
    }
    if let Some(class) = unsupported_class(&selector) {
        return Err(format!(
            "`{text}` uses `{}`, which skill selectors can't decide",
            class.display_name()
        ));
    }
    let canonical = selector.to_string();
    if canonical.len() > MAX_SELECTOR_LENGTH {
        return Err(format!(
            "`{text}` is longer than {MAX_SELECTOR_LENGTH} bytes as LPM writes it"
        ));
    }
    Ok(canonical)
}

/// The first pseudo-class in `selector` that skill selection has no data
/// for: script and build state, vulnerability and deprecation data, and
/// `:high`, which includes them. Accepting one would make `:not()` over it
/// hold for every package.
fn unsupported_class(selector: &Selector) -> Option<PseudoClass> {
    match selector {
        Selector::PseudoClass(
            class @ (PseudoClass::Scripts
            | PseudoClass::Built
            | PseudoClass::Vulnerable
            | PseudoClass::Deprecated
            | PseudoClass::High),
        ) => Some(*class),
        Selector::PseudoClass(_) | Selector::Id(_) | Selector::Skill(_) => None,
        Selector::And(parts) | Selector::Or(parts) => parts.iter().find_map(unsupported_class),
        Selector::Not(inner) => unsupported_class(inner),
        Selector::DirectChild { parent, child } => {
            unsupported_class(parent).or_else(|| unsupported_class(child))
        }
    }
}

/// A target directory as the project wrote it, `/`-separated, or why it
/// can't be one: it must stay inside the project, end in `skills`, and not
/// pass through Git, LPM or package directories.
pub(crate) fn normalize_target(text: &str) -> Result<String, &'static str> {
    let normalized = normalize_relative_dir(text)?;
    if normalized.rsplit('/').next() != Some("skills") {
        return Err("must end in a `skills` directory");
    }
    Ok(normalized)
}

/// A project-relative directory, `/`-separated, whose components are
/// portable names (a leading dot allowed) and none of `.git`, `.lpm` or
/// `node_modules`.
pub(crate) fn normalize_relative_dir(text: &str) -> Result<String, &'static str> {
    let trimmed = text.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.contains('\\') {
        return Err("must be a relative path inside the project, written with `/`");
    }
    let components: Vec<&str> = trimmed.split('/').collect();
    for component in &components {
        if component.is_empty() || *component == "." || *component == ".." {
            return Err("must not contain empty, `.` or `..` components");
        }
        if RESERVED_TARGET_COMPONENTS
            .iter()
            .any(|reserved| component.eq_ignore_ascii_case(reserved))
        {
            return Err("must not pass through `.git`, `.lpm` or `node_modules`");
        }
        let visible = component.strip_prefix('.').unwrap_or(component);
        if !lpm_skill::is_portable_path_component(visible) {
            return Err("must use portable directory names");
        }
    }
    Ok(components.join("/"))
}

/// Checks a recorded target entry: a target directory, then one skill name.
pub(crate) fn normalize_target_entry(path: &str) -> Result<(), &'static str> {
    let (target, name) = path
        .rsplit_once('/')
        .ok_or("must be a target directory and a skill name")?;
    normalize_target(target)?;
    if !lpm_skill::is_skill_name(name) {
        return Err("must end in a skill name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> ParsedPolicy {
        read_policy(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn a_manifest_without_a_policy_declares_none() {
        let parsed = parse(r#"{"name":"app","lpm":{"trustedDependencies":{}}}"#);
        assert!(parsed.policy.is_none());
        assert!(parsed.problems.is_empty());
    }

    #[test]
    fn allow_and_deny_entries_are_parsed_and_deduplicated_by_canonical_form() {
        let parsed = parse(
            r##"{"lpm":{"skills":{"allow":["#agent-browser","#agent-browser ", "#a:skill(x,y)"],"deny":["#noisy"]}}}"##,
        );
        let policy = parsed.policy.unwrap();
        assert!(parsed.problems.is_empty(), "{:?}", parsed.problems);
        let allowed: Vec<&str> = policy
            .allow
            .iter()
            .map(|entry| entry.text.as_str())
            .collect();
        assert_eq!(allowed, ["#agent-browser", "#a:skill(x,y)"]);
        assert_eq!(policy.deny.len(), 1);
        assert_eq!(policy.targets, Targets::Auto);
        assert!(policy.is_active());
    }

    #[test]
    fn an_invalid_selector_is_reported_and_never_treated_as_a_wildcard() {
        let parsed = parse(r##"{"lpm":{"skills":{"allow":["#ok", ":unknown", 42, ""]}}}"##);
        let policy = parsed.policy.unwrap();
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(parsed.problems.len(), 3, "{:?}", parsed.problems);
        assert!(parsed.problems[0].contains("allow[1]"));
    }

    #[test]
    fn selectors_over_data_skill_selection_lacks_are_refused() {
        let parsed = parse(
            r##"{"lpm":{"skills":{"allow":[":skills:not(:vulnerable)", "#a:not(:high)", ":scripts > #b", "#ok:not(:eval)"]}}}"##,
        );
        let policy = parsed.policy.unwrap();
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].text, "#ok:not(:eval)");
        assert_eq!(parsed.problems.len(), 3, "{:?}", parsed.problems);
        assert!(parsed.problems[0].contains("`:vulnerable`"));
    }

    #[test]
    fn a_selector_whose_canonical_form_outgrows_the_limit_is_refused() {
        let text = (0..160)
            .map(|index| format!("#p{index:03}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(text.len() <= MAX_SELECTOR_LENGTH);

        let refused = validate_selector(&text).unwrap_err();
        assert!(refused.contains("as LPM writes it"), "{refused}");
        let shorter = (0..140)
            .map(|index| format!("#p{index:03}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(validate_selector(&shorter).is_ok());
    }

    #[test]
    fn root_selectors_count_only_before_a_child_combinator() {
        let parsed = parse(
            r##"{"lpm":{"skills":{"allow":[":root", ":root > #a"], "deny":[":workspace-root"]}}}"##,
        );
        let policy = parsed.policy.unwrap();
        assert_eq!(policy.allow.len(), 1);
        assert_eq!(policy.allow[0].text, ":root > #a");
        assert!(
            policy.deny_unreadable,
            "an unusable deny entry must fail closed"
        );
        assert!(
            parsed
                .problems
                .iter()
                .any(|problem| problem.contains("`:root`")),
            "{:?}",
            parsed.problems
        );
        assert!(
            parsed
                .problems
                .iter()
                .any(|problem| problem.contains("`:workspace-root`")),
            "{:?}",
            parsed.problems
        );
    }

    #[test]
    fn a_policy_that_is_not_an_object_links_nothing() {
        let parsed = parse(r##"{"lpm":{"skills":["#agent-browser"]}}"##);
        assert!(parsed.policy.is_none());
        assert_eq!(parsed.problems.len(), 1);
    }

    #[test]
    fn unknown_keys_are_reported_so_typos_surface() {
        let parsed = parse(r##"{"lpm":{"skills":{"allows":["#a"]}}}"##);
        assert!(!parsed.policy.unwrap().is_active());
        assert!(parsed.problems[0].contains("`lpm.skills.allows`"));
    }

    #[test]
    fn explicit_targets_must_stay_inside_the_project_and_end_in_skills() {
        let parsed = parse(
            r##"{"lpm":{"skills":{"allow":["#a"],"targets":[".agents/skills","./.claude/skills/",".agents/skills","/abs/skills","../out/skills","docs","node_modules/x/skills",".git/skills","a\\skills"]}}}"##,
        );
        let policy = parsed.policy.unwrap();
        assert_eq!(
            policy.targets,
            Targets::Explicit(vec![".agents/skills".into(), ".claude/skills".into()])
        );
        assert_eq!(parsed.problems.len(), 6, "{:?}", parsed.problems);
    }

    #[test]
    fn an_unreadable_deny_entry_keeps_the_policy_from_linking_anything() {
        for deny in [
            r#"[":unknown"]"#,
            r##"["#ok", 42]"##,
            r##""#noisy""##,
            r#"[":scripts"]"#,
        ] {
            let parsed = parse(&format!(
                r##"{{"lpm":{{"skills":{{"allow":["#a"],"deny":{deny}}}}}}}"##
            ));
            assert!(
                !parsed.policy.unwrap().is_active(),
                "deny {deny} must fail closed"
            );
            assert!(
                parsed
                    .problems
                    .iter()
                    .any(|problem| problem.contains("no dependency skills")),
                "{:?}",
                parsed.problems
            );
        }
    }

    #[test]
    fn deny_entries_are_never_crowded_out_by_allow_entries() {
        let allow: Vec<String> = (0..MAX_POLICY_ENTRIES)
            .map(|index| format!("#a{index}"))
            .collect();
        let parsed = parse(
            &serde_json::json!({ "lpm": { "skills": { "allow": allow, "deny": ["#b"] } } })
                .to_string(),
        );
        let policy = parsed.policy.unwrap();
        assert_eq!(policy.deny.len(), 1, "{:?}", parsed.problems);
        assert!(policy.is_active());
    }

    #[test]
    fn a_misspelled_key_keeps_the_policy_from_linking_anything() {
        let parsed = parse(r##"{"lpm":{"skills":{"allow":["#a"],"Deny":["#a"]}}}"##);
        assert!(!parsed.policy.unwrap().is_active());
        assert!(
            parsed.problems[0].contains("`lpm.skills.Deny`"),
            "{:?}",
            parsed.problems
        );
    }

    #[test]
    fn the_fingerprint_follows_canonical_selectors_and_targets() {
        let first = parse(r##"{"lpm":{"skills":{"allow":["#a , #b"]}}}"##)
            .policy
            .unwrap();
        let same = parse(r##"{"lpm":{"skills":{"allow":["#a,#b"],"targets":"auto"}}}"##)
            .policy
            .unwrap();
        let other =
            parse(r##"{"lpm":{"skills":{"allow":["#a,#b"],"targets":[".agents/skills"]}}}"##)
                .policy
                .unwrap();
        assert_eq!(first.fingerprint_text(), same.fingerprint_text());
        assert_ne!(first.fingerprint_text(), other.fingerprint_text());
    }
}
