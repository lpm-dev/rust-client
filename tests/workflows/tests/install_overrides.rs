//! Workflow tests for `lpm.overrides` resolution + offline-mode safety.
//!
//! Override-fail-closed acceptance criteria, end-to-end through the binary:
//!
//! 1. **Fail-closed parsing** — invalid overrides in `package.json` are
//!    a hard error at install entry, not a silent no-op. The error
//!    names the offending key.
//! 2. **`.lpm/overrides-state.json` lifecycle** — the state file is
//!    created on first install with overrides, deleted when overrides
//!    are removed, and the fingerprint changes when the override set
//!    changes.
//! 3. **Offline safety** — `--offline` cannot re-resolve, so any
//!    drift between the persisted overrides-state and the current
//!    `lpm.overrides` is a hard error rather than a silent stale-link.
//!
//! In its own file (not appended to `install.rs`) because the helpers
//! — `override_state_fingerprint` mirror, `seed_store_package`, lockfile/state
//! synthesis — are scoped to this gate. install.rs is also already
//! past the file-size review trigger.
//!
//! `lpm graph --why` + overrides-trace coverage lives in `graph.rs`.

mod support;

use support::{TempProject, lpm_with_registry};

// ─── Helpers ────────────────────────────────────────────────────────────

/// Strip ANSI escapes from captured streams for stable substring assertions.
/// UTF-8 safe: iterates `chars()` and skips CSI sequences without
/// re-encoding bytes individually.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for cc in chars.by_ref() {
                let cb = cc as u32;
                if (0x40..=0x7e).contains(&cb) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Synthetic `lpm.lock` containing the given `(name, version, deps)` entries.
fn write_lockfile(project: &TempProject, entries: &[(&str, &str, &[&str])]) {
    let pkgs: Vec<String> = entries
        .iter()
        .map(|(name, version, deps)| {
            let deps_block = if deps.is_empty() {
                String::new()
            } else {
                let inner = deps
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("\ndependencies = [{inner}]")
            };
            format!("[[packages]]\nname = \"{name}\"\nversion = \"{version}\"{deps_block}\n")
        })
        .collect();
    let toml = format!(
        "[metadata]\nlockfile-version = {}\nresolved-with = \"pubgrub\"\n\n{}\n",
        lpm_lockfile::LOCKFILE_VERSION,
        pkgs.join("\n")
    );
    project.write_file("lpm.lock", &toml);
}

/// Seed a fake but well-formed entry in `<HOME>/.lpm/store/v1/<safe>@<v>/`.
/// `lpm install --offline` checks `PackageStore::has_package` for every
/// locked package; the offline branch demands a `package.json` +
/// `.integrity` file inside the version directory.
fn seed_store_package(project: &TempProject, name: &str, version: &str) {
    let safe_name = name.replace(['/', '\\'], "+");
    let dir = project
        .store_dir()
        .join("v1")
        .join(format!("{safe_name}@{version}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
    std::fs::write(dir.join(".integrity"), "sha512-fixture").unwrap();
}

/// Write a synthetic `.lpm/overrides-state.json`. `parsed` is the
/// `(raw_key, target)` set; `applied` is the `(pkg, from, to, via_parent)`
/// trace.
fn write_overrides_state(
    project: &TempProject,
    fingerprint: &str,
    parsed: &[(&str, &str)],
    applied: &[(&str, &str, &str, Option<&str>)],
) {
    let parsed_json: Vec<serde_json::Value> = parsed
        .iter()
        .map(|(key, target)| {
            serde_json::json!({
                "raw_key": key,
                "source": "lpm.overrides",
                "selector": { "kind": "name", "name": key },
                "target": target,
            })
        })
        .collect();
    let applied_json: Vec<serde_json::Value> = applied
        .iter()
        .map(|(pkg, from, to, via)| {
            serde_json::json!({
                "raw_key": pkg,
                "source": "lpm.overrides",
                "package": pkg,
                "from_version": from,
                "to_version": to,
                "via_parent": via,
            })
        })
        .collect();
    let state = serde_json::json!({
        "state_version": 1,
        "fingerprint": fingerprint,
        "captured_at": "2026-04-11T00:00:00Z",
        "parsed": parsed_json,
        "applied": applied_json,
    });
    project.write_file(
        ".lpm/overrides-state.json",
        &serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Mirror of `lpm_resolver::overrides::compute_fingerprint`. The
/// canonical encoding is one line per entry, sorted ASCII, fed through
/// SHA-256 with `\n` after each line. Each line is
/// `{source}|{raw_key}|{selector}|{target}`.
///
/// **MUST stay in sync** with the resolver's `compute_fingerprint`. If
/// the resolver changes, this helper diverges and the matching-fingerprint
/// test will fail loudly.
fn override_state_fingerprint(entries: &[(&str, &str, &str)]) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical: Vec<String> = entries
        .iter()
        .map(|(source, key, target)| format!("{source}|{key}|name:{key}|{target}"))
        .collect();
    canonical.sort();
    let mut hasher = Sha256::new();
    for line in &canonical {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256-{:x}", hasher.finalize())
}

// ─── Fail-closed parsing ────────────────────────────────────────────────

/// Multi-segment path selectors (`a>b>c`) must hard-error at install
/// entry — not silently no-op or warn. Error names the offending key.
#[test]
fn install_overrides_rejects_multi_segment_path_selector() {
    let project = TempProject::empty(
        r#"{
  "name": "multi-segment-path",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "a>b>c": "1.0.0" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "multi-segment path must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("a>b>c"),
        "error must name the offending key; got:\n{combined}"
    );
}

/// Invalid target version must hard-error and name the offending override key.
#[test]
fn install_overrides_rejects_invalid_target_version() {
    let project = TempProject::empty(
        r#"{
  "name": "invalid-target",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "lodash": "not-a-version-or-range" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "invalid target must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("lodash"),
        "error must name the offending key; got:\n{combined}"
    );
}

/// Invalid range in the selector half must hard-error and surface the
/// validation failure.
#[test]
fn install_overrides_rejects_invalid_range_in_selector() {
    let project = TempProject::empty(
        r#"{
  "name": "invalid-range",
  "version": "0.0.0",
  "dependencies": {},
  "lpm": { "overrides": { "lodash@???": "1.0.0" } }
}"#,
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "invalid range must error; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("???") || combined.contains("invalid"),
        "error must surface the validation failure; got:\n{combined}"
    );
}

// ─── Offline safety: state vs current overrides ─────────────────────────

/// Stale state with applied overrides + non-empty deps + EMPTY current
/// overrides → offline must hard-error. We can't re-resolve offline, so
/// silently completing the install would link against the (now-stale)
/// override-shifted lockfile and leave a ghost state file on disk.
#[test]
fn offline_install_hard_errors_when_overrides_removed_with_prior_state() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-overrides-removed",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    write_overrides_state(
        &project,
        "sha256-stale-fp",
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install must hard error when overrides are removed but state lingers; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
    assert!(
        combined.contains("online") || combined.contains("re-resolve"),
        "error must point at the recovery path (run online); got:\n{combined}"
    );
}

/// Stale state fingerprint X + non-empty deps + CURRENT overrides whose
/// fingerprint is Y (different) → offline must hard-error rather than
/// silently ignoring the user's override edits.
#[test]
fn offline_install_hard_errors_on_overrides_fingerprint_mismatch() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-fingerprint-mismatch",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "5.0.0" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    write_overrides_state(
        &project,
        "sha256-totally-different-fp-from-current",
        &[("lodash", "4.17.20")],
        &[],
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install with fingerprint mismatch must hard error; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
}

/// Non-empty deps + CURRENT overrides + NO persisted state file →
/// offline must hard-error. Without a fingerprint to verify against,
/// we can't prove the lockfile was generated under the current
/// override set, so the safe behavior is to refuse.
#[test]
fn offline_install_hard_errors_when_overrides_exist_but_no_state_file() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-no-prior-state",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "4.17.20" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    // Intentionally no overrides-state.json.

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        !out.status.success(),
        "offline install with overrides but no state file must hard error; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ));
    assert!(
        combined.contains("override") || combined.contains("fingerprint"),
        "error must mention overrides/fingerprint; got:\n{combined}"
    );
}

/// Positive case: matching fingerprint + non-empty deps + matching
/// overrides → offline install succeeds AND preserves the existing
/// state file on disk. Mirrors the resolver's canonical fingerprint
/// hash; if the resolver's hash function changes, this test fails
/// loudly.
#[test]
fn offline_install_succeeds_when_overrides_fingerprint_matches() {
    let project = TempProject::empty(
        r#"{
  "name": "offline-fp-match",
  "version": "0.0.0",
  "dependencies": { "lodash": "^4.17.0" },
  "lpm": { "overrides": { "lodash": "4.17.20" } }
}"#,
    );
    write_lockfile(&project, &[("lodash", "4.17.20", &[])]);
    seed_store_package(&project, "lodash", "4.17.20");
    let fingerprint = override_state_fingerprint(&[("lpm.overrides", "lodash", "4.17.20")]);
    write_overrides_state(
        &project,
        &fingerprint,
        &[("lodash", "4.17.20")],
        &[("lodash", "4.17.21", "4.17.20", None)],
    );

    let state_path = project.path().join(".lpm").join("overrides-state.json");
    assert!(
        state_path.exists(),
        "fixture must produce overrides-state.json"
    );

    let out = lpm_with_registry(&project, "http://127.0.0.1:1")
        .args(["install", "--offline"])
        .output()
        .expect("spawn lpm install");
    assert!(
        out.status.success(),
        "offline install with matching fingerprint must succeed; \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        state_path.exists(),
        "state file must be preserved when fingerprints match"
    );
}
