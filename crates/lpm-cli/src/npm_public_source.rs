/// Returns `true` only when the lockfile entry for `name` exists and
/// records a public npm registry source. Commands that inspect or
/// upgrade bare npm dependencies use this gate to avoid leaking private
/// package names to registry.npmjs.org.
pub(crate) fn lockfile_source_is_npm_public(
    lockfile: Option<&lpm_lockfile::Lockfile>,
    name: &str,
) -> bool {
    let Some(lf) = lockfile else {
        return false;
    };
    let Some(pkg) = lf.find_package(name) else {
        return false;
    };
    match pkg.source_kind() {
        Some(Ok(lpm_lockfile::Source::Registry { url })) => is_public_npm_origin(&url),
        _ => false,
    }
}

fn is_public_npm_origin(url: &str) -> bool {
    let lower = url.trim_end_matches('/').to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "https://registry.npmjs.org" | "https://registry.npmjs.com"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_npm_origin_recognises_canonical_shapes() {
        assert!(is_public_npm_origin("https://registry.npmjs.org"));
        assert!(is_public_npm_origin("https://registry.npmjs.org/"));
        assert!(is_public_npm_origin("https://registry.npmjs.com"));
        assert!(is_public_npm_origin("https://REGISTRY.NPMJS.ORG"));
    }

    #[test]
    fn public_npm_origin_rejects_private_mirrors() {
        assert!(!is_public_npm_origin("https://npm.internal.example.com"));
        assert!(!is_public_npm_origin("https://npm.pkg.github.com"));
        assert!(!is_public_npm_origin("https://verdaccio.local"));
        assert!(!is_public_npm_origin("http://localhost:4873"));
        assert!(!is_public_npm_origin(""));
    }
}