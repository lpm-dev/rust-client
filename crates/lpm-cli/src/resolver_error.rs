use lpm_common::{LpmError, ResolutionErrorContext, ResolutionFailureKind};

pub(crate) fn resolver_error_to_lpm(error: lpm_resolver::ResolveError) -> LpmError {
    match error {
        lpm_resolver::ResolveError::Resolution(context) => LpmError::Resolution(context),
        lpm_resolver::ResolveError::PeerConflict {
            canonical,
            requirements,
        } => LpmError::Resolution(Box::new(peer_conflict_context(canonical, requirements))),
        other => LpmError::Registry(format!("resolution failed: {other}")),
    }
}

fn peer_conflict_context(
    canonical: String,
    mut requirements: Vec<(String, String, bool)>,
) -> ResolutionErrorContext {
    requirements.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    let mut ranges: Vec<&str> = requirements
        .iter()
        .map(|(_, range, _)| range.as_str())
        .collect();
    ranges.sort_unstable();
    ranges.dedup();
    let requested = if ranges.is_empty() {
        "*".to_string()
    } else {
        ranges.join(", ")
    };
    let required_by = if requirements.len() == 1 {
        Some(requirements[0].0.clone())
    } else {
        None
    };
    let derivation = if requirements.is_empty() {
        None
    } else {
        Some(
            requirements
                .iter()
                .map(|(consumer, range, optional)| {
                    if *optional {
                        format!("{consumer} wants {range} (optional peer)")
                    } else {
                        format!("{consumer} wants {range}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };

    ResolutionErrorContext {
        package: canonical.clone(),
        requested,
        dependency: canonical,
        required_by,
        kind: ResolutionFailureKind::PeerConflict,
        reason: "no published peer version satisfies the required range".to_string(),
        available_versions: None,
        newest_version: None,
        derivation,
    }
}
