use super::prelude::*;

/// Find a blocked package matching either `name` or `name@version`.
/// Used by the `<pkg>` argument path.
#[cfg(test)]
pub(super) fn find_blocked_by_arg<'a>(
    blocked: &'a [BlockedPackage],
    arg: &str,
) -> Option<&'a BlockedPackage> {
    match lookup_blocked_by_arg(blocked, arg) {
        BlockedLookup::Match(blocked) => Some(blocked),
        BlockedLookup::NotFound | BlockedLookup::Ambiguous { .. } => None,
    }
}

#[derive(Debug)]
pub(super) enum BlockedLookup<'a> {
    Match(&'a BlockedPackage),
    NotFound,
    Ambiguous { candidates: Vec<&'a BlockedPackage> },
}

pub(super) fn blocked_identity_selector(blocked: &BlockedPackage) -> String {
    let base = format!("{}@{}", blocked.name, blocked.version);
    match TrustedDependencies::rich_identity_token(
        blocked.source.as_deref(),
        blocked.integrity.as_deref(),
        blocked.script_hash.as_deref(),
    ) {
        Some(identity) => format!("{base}#{identity}"),
        None => base,
    }
}

pub(super) fn lookup_blocked_by_arg<'a>(
    blocked: &'a [BlockedPackage],
    arg: &str,
) -> BlockedLookup<'a> {
    if let Some(at) = arg.rfind('@') {
        // arg COULD be `name@version` OR a scoped name `@scope/pkg`.
        // Distinguish: if the `@` is at position 0, it's the scope marker.
        if at > 0 {
            let (name, version_and_identity) = (&arg[..at], &arg[at + 1..]);
            let (version, identity) = version_and_identity
                .split_once('#')
                .map_or((version_and_identity, None), |(version, identity)| {
                    (version, Some(identity))
                });
            let matches: Vec<&BlockedPackage> = blocked
                .iter()
                .filter(|b| {
                    b.name == name
                        && b.version == version
                        && identity.is_none_or(|expected| {
                            TrustedDependencies::rich_identity_token(
                                b.source.as_deref(),
                                b.integrity.as_deref(),
                                b.script_hash.as_deref(),
                            )
                            .as_deref()
                                == Some(expected)
                        })
                })
                .collect();
            return match matches.as_slice() {
                [] => BlockedLookup::NotFound,
                [single] => BlockedLookup::Match(single),
                _ => BlockedLookup::Ambiguous {
                    candidates: matches,
                },
            };
        }
    }
    let matches: Vec<&BlockedPackage> = blocked.iter().filter(|b| b.name == arg).collect();
    match matches.as_slice() {
        [] => BlockedLookup::NotFound,
        [single] => BlockedLookup::Match(single),
        _ => BlockedLookup::Ambiguous {
            candidates: matches,
        },
    }
}

/// Extract `lpm.trustedDependencies` from a parsed manifest into a typed
/// [`TrustedDependencies`] enum. Returns the default (empty Legacy) if the
/// field is missing or fails to parse.
pub(super) fn extract_trusted_dependencies(manifest: &serde_json::Value) -> TrustedDependencies {
    let Some(td_value) = manifest
        .get("lpm")
        .and_then(|l| l.get("trustedDependencies"))
    else {
        return TrustedDependencies::default();
    };
    serde_json::from_value(td_value.clone()).unwrap_or_default()
}

/// Write the updated `trustedDependencies` back to `package.json`.
///
/// Atomic via temp-file rename. Preserves the rest of the manifest
/// untouched (we mutate only the `lpm.trustedDependencies` subtree).
pub(super) fn write_back(
    pkg_json_path: &Path,
    manifest: &mut serde_json::Value,
    trusted: &TrustedDependencies,
) -> Result<(), LpmError> {
    // Ensure `lpm` exists as a JSON object
    if manifest.get("lpm").is_none() {
        manifest["lpm"] = serde_json::json!({});
    }
    if !manifest["lpm"].is_object() {
        return Err(LpmError::Registry(
            "package.json `lpm` field is not a JSON object — refusing to write".into(),
        ));
    }

    let td_value = serde_json::to_value(trusted)
        .map_err(|e| LpmError::Registry(format!("failed to serialize trustedDependencies: {e}")))?;
    manifest["lpm"]["trustedDependencies"] = td_value;

    let updated = serde_json::to_string_pretty(manifest)
        .map_err(|e| LpmError::Registry(format!("failed to serialize package.json: {e}")))?;

    // Atomic write: temp file + rename. Mirrors build_state::write_build_state.
    let parent = pkg_json_path.parent().unwrap_or(Path::new("."));
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let tmp = parent.join(format!(".package.json.{pid}.{nanos}.tmp"));
    std::fs::write(&tmp, format!("{updated}\n")).map_err(LpmError::Io)?;
    std::fs::rename(&tmp, pkg_json_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to rename package.json tempfile into place: {e}"),
        ))
    })?;

    Ok(())
}
