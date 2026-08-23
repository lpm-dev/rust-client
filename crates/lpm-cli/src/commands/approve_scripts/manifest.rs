use super::prelude::*;

/// Find a blocked package matching `name`, `name@version`, or an
/// artifact-qualified `name@version#artifact-id` selector.
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

pub(super) fn lookup_blocked_by_arg<'a>(
    blocked: &'a [BlockedPackage],
    arg: &str,
) -> BlockedLookup<'a> {
    let (coordinate_arg, artifact_qualifier) = arg
        .rsplit_once('#')
        .map_or((arg, None), |(coordinate, qualifier)| {
            (coordinate, (!qualifier.is_empty()).then_some(qualifier))
        });
    if let Some(at) = coordinate_arg.rfind('@') {
        // arg COULD be `name@version` OR a scoped name `@scope/pkg`.
        // Distinguish: if the `@` is at position 0, it's the scope marker.
        if at > 0 {
            let (name, version) = (&coordinate_arg[..at], &coordinate_arg[at + 1..]);
            let matches: Vec<&BlockedPackage> = blocked
                .iter()
                .filter(|b| {
                    b.name == name
                        && b.version == version
                        && artifact_qualifier.is_none_or(|qualifier| {
                            blocked_artifact_matches_qualifier(b, qualifier)
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
    if artifact_qualifier.is_some() {
        return BlockedLookup::NotFound;
    }
    let matches: Vec<&BlockedPackage> = blocked
        .iter()
        .filter(|b| b.name == coordinate_arg)
        .collect();
    match matches.as_slice() {
        [] => BlockedLookup::NotFound,
        [single] => BlockedLookup::Match(single),
        _ => BlockedLookup::Ambiguous {
            candidates: matches,
        },
    }
}

fn blocked_artifact_matches_qualifier(blocked: &BlockedPackage, qualifier: &str) -> bool {
    blocked.integrity.as_deref() == Some(qualifier)
        || blocked.script_hash.as_deref() == Some(qualifier)
        || lpm_common::artifact_binding_id(
            blocked.integrity.as_deref(),
            blocked.script_hash.as_deref(),
        ) == qualifier
}

pub(super) fn blocked_artifact_selector(blocked: &BlockedPackage) -> String {
    format!(
        "{}@{}#{}",
        blocked.name,
        blocked.version,
        lpm_common::artifact_binding_id(
            blocked.integrity.as_deref(),
            blocked.script_hash.as_deref(),
        ),
    )
}

/// Extract `lpm.trustedDependencies` from a parsed manifest into a typed
/// [`TrustedDependencies`] enum. A missing field is an empty legacy list;
/// malformed present data fails closed so an approval cannot overwrite it.
pub(super) fn extract_trusted_dependencies(
    manifest: &serde_json::Value,
) -> Result<TrustedDependencies, LpmError> {
    let Some(td_value) = manifest
        .get("lpm")
        .and_then(|l| l.get("trustedDependencies"))
    else {
        return Ok(TrustedDependencies::default());
    };
    serde_json::from_value(td_value.clone()).map_err(|error| {
        LpmError::Registry(format!(
            "package.json `lpm.trustedDependencies` is malformed: {error}; refusing to overwrite it"
        ))
    })
}

/// Write the updated `trustedDependencies` back to `package.json`.
///
/// Refuses the write if the manifest bytes changed after review, including
/// formatting-only edits. Otherwise preserves the manifest data outside the
/// `lpm.trustedDependencies` subtree.
pub(super) fn write_back(
    pkg_json_path: &Path,
    reviewed_manifest_text: &str,
    manifest: &mut serde_json::Value,
    trusted: &TrustedDependencies,
) -> Result<(), LpmError> {
    ensure_manifest_unchanged(pkg_json_path, reviewed_manifest_text)?;

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

    lpm_common::write_file_atomic(pkg_json_path, format!("{updated}\n")).map_err(|e| {
        LpmError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to atomically write package.json: {e}"),
        ))
    })
}

pub(super) fn ensure_manifest_unchanged(
    pkg_json_path: &Path,
    reviewed_manifest_text: &str,
) -> Result<(), LpmError> {
    let current_text =
        lpm_common::read_text_file_capped(pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
    if current_text != reviewed_manifest_text {
        return Err(LpmError::Script(
            "package.json changed while approve-scripts was reviewing it; no approvals were written. Review the current manifest and retry."
                .into(),
        ));
    }
    Ok(())
}
