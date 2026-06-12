use lpm_common::{LpmError, PackageName};
use std::collections::HashMap;

/// What `lpm add` resolved the user's input to.
///
/// The `Lpm` variant flows through the lpm.dev metadata API and
/// `PackageName`'s strict `owner.name` validation. The `Npm` variant
/// flows through the npm metadata API (or `.npmrc`-declared registry per
/// `RouteTable`) and carries the original input string verbatim: bare
/// names, scoped names, and anything else npm accepts.
///
/// Encoding identity as an enum (rather than `Option<PackageName>` or a
/// runtime `is_lpm` check) means anywhere we hand `&PackageName` off to
/// a lpm.dev-only API (skills extraction, rich-config flow), the type
/// system proves we have one — and anywhere we render output for a non-
/// LPM target, the lpm.dev-prefixed `PackageName::scoped()` is statically
/// out of reach.
#[derive(Debug, Clone)]
pub(super) enum AddTarget {
    /// `@lpm.dev/owner.name` — the only form that means lpm.dev.
    Lpm(PackageName),
    /// Anything else npm accepts: bare names (`react`, `lodash.merge`),
    /// scoped names (`@juggle/resize-observer`, `@private/internal-pkg`).
    /// Stored verbatim so output renders the user's spec, not a
    /// reconstruction.
    Npm { spec: String },
}

impl AddTarget {
    /// Human-readable identity for `output::info` / `println!`.
    pub(super) fn display(&self) -> String {
        match self {
            Self::Lpm(pkg) => pkg.scoped(),
            Self::Npm { spec } => spec.clone(),
        }
    }

    /// Identity for the `package.name` field in `--json` output.
    /// Same shape as `display()` today; kept as a separate method so
    /// JSON consumers can be evolved independently of human output.
    pub(super) fn json_name(&self) -> String {
        self.display()
    }

    /// Identity passed to routing helpers (`route_for_package`,
    /// `download_tarball_routed`). For `Lpm`, the scoped form is what
    /// `RouteTable` matches on (`@lpm.dev/*` → forces `LpmWorker`); for
    /// `Npm`, the original spec is what npm/`.npmrc` route on.
    pub(super) fn route_name(&self) -> String {
        self.display()
    }
}

/// Output of `resolve_add_target`: the parsed target identity, an
/// optional explicit version spec (everything after the trailing `@`),
/// and any inline `?key=val&key=val` config picked up from the input.
pub(super) type ResolvedAddInput = (AddTarget, Option<String>, HashMap<String, String>);

/// Resolve a user-supplied `lpm add <spec>` argument to an `AddTarget`,
/// stripping any `@version` suffix and `?key=val` query params.
///
/// Bare, dotted, and non-`@lpm.dev/` inputs flow to `AddTarget::Npm`
/// verbatim. Dotted-name auto-prepending would silently rewrite real npm
/// packages like `lodash.merge`, `lodash.debounce`, and
/// `lodash.throttle` into the `@lpm.dev/` namespace where they do not
/// exist. Only `@lpm.dev/owner.name` identifies an lpm.dev-hosted
/// package, so the resolver does no rewriting outside that scope.
pub(super) fn resolve_add_target(spec: &str) -> Result<ResolvedAddInput, LpmError> {
    let mut inline_config = HashMap::new();

    // Split on `?` for query params (e.g., `pkg?component=dialog`).
    let rest = if let Some(pos) = spec.find('?') {
        let q = &spec[pos + 1..];
        for param in q.split('&') {
            if let Some(eq) = param.find('=') {
                inline_config.insert(param[..eq].to_string(), param[eq + 1..].to_string());
            }
        }
        &spec[..pos]
    } else {
        spec
    };

    // Split on `@` for version, handling scoped packages whose first
    // char is also `@`.
    let (name, version) = if let Some(stripped) = rest.strip_prefix('@') {
        // `@scope/name@version` — find the `@` that follows the scope.
        if let Some(at_pos) = stripped.find('@') {
            let at_pos = at_pos + 1; // +1 to account for the stripped '@'
            (
                rest[..at_pos].to_string(),
                Some(rest[at_pos + 1..].to_string()),
            )
        } else {
            (rest.to_string(), None)
        }
    } else if let Some(at_pos) = rest.find('@') {
        (
            rest[..at_pos].to_string(),
            Some(rest[at_pos + 1..].to_string()),
        )
    } else {
        (rest.to_string(), None)
    };

    if name.is_empty() {
        return Err(LpmError::InvalidPackageName(format!(
            "could not parse package name from '{spec}'"
        )));
    }

    // Identity rule: only `@lpm.dev/` inputs route through `PackageName`.
    // Everything else stays verbatim and flows through npm/`.npmrc`.
    let target = if name.starts_with("@lpm.dev/") {
        AddTarget::Lpm(PackageName::parse(&name)?)
    } else {
        AddTarget::Npm { spec: name }
    };

    Ok((target, version, inline_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_add_target_lpm_full_scoped() {
        let (target, version, _config) =
            resolve_add_target("@lpm.dev/tolga.sample-source-code1").unwrap();
        match target {
            AddTarget::Lpm(pkg) => {
                assert_eq!(pkg.scoped(), "@lpm.dev/tolga.sample-source-code1");
            }
            AddTarget::Npm { spec } => panic!("expected Lpm variant, got Npm({spec})"),
        }
        assert!(version.is_none());
    }

    #[test]
    fn resolve_add_target_lpm_with_version_and_inline_config() {
        let (target, version, config) =
            resolve_add_target("@lpm.dev/acme.design@2.1.0?component=dialog&styling=panda")
                .unwrap();
        match &target {
            AddTarget::Lpm(pkg) => assert_eq!(pkg.scoped(), "@lpm.dev/acme.design"),
            AddTarget::Npm { .. } => panic!("expected Lpm variant"),
        }
        assert_eq!(version.as_deref(), Some("2.1.0"));
        assert_eq!(config.get("component").map(String::as_str), Some("dialog"));
        assert_eq!(config.get("styling").map(String::as_str), Some("panda"));
    }

    #[test]
    fn resolve_add_target_npm_bare() {
        let (target, version, _config) = resolve_add_target("react").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(pkg) => panic!("expected Npm, got Lpm({})", pkg.scoped()),
        }
        assert!(version.is_none());
    }

    #[test]
    fn resolve_add_target_npm_scoped() {
        let (target, _, _) = resolve_add_target("@juggle/resize-observer").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "@juggle/resize-observer"),
            AddTarget::Lpm(pkg) => panic!("expected Npm, got Lpm({})", pkg.scoped()),
        }
    }

    #[test]
    fn resolve_add_target_npm_with_version() {
        let (target, version, _) = resolve_add_target("react@18.3.1").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(version.as_deref(), Some("18.3.1"));
    }

    #[test]
    fn resolve_add_target_npm_with_dist_tag() {
        let (target, version, _) = resolve_add_target("react@beta").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(version.as_deref(), Some("beta"));
    }

    #[test]
    fn resolve_add_target_dotted_npm_name_is_npm_not_lpm_shorthand() {
        for spec in [
            "lodash.merge",
            "lodash.debounce",
            "lodash.throttle",
            "tolga.foo",
        ] {
            let (target, _, _) = resolve_add_target(spec).unwrap();
            match target {
                AddTarget::Npm { spec: s } => assert_eq!(s, spec),
                AddTarget::Lpm(pkg) => panic!(
                    "'{spec}' must resolve to Npm, not Lpm({}) — auto-prepend regression",
                    pkg.scoped()
                ),
            }
        }
    }

    #[test]
    fn resolve_add_target_npm_with_inline_config() {
        let (target, _, config) = resolve_add_target("react?theme=dark&variant=primary").unwrap();
        match target {
            AddTarget::Npm { spec } => assert_eq!(spec, "react"),
            AddTarget::Lpm(_) => panic!("expected Npm"),
        }
        assert_eq!(config.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(config.get("variant").map(String::as_str), Some("primary"));
    }

    #[test]
    fn resolve_add_target_empty_input_errors() {
        let err = resolve_add_target("").unwrap_err();
        match err {
            LpmError::InvalidPackageName(_) => {}
            other => panic!("expected InvalidPackageName, got {other:?}"),
        }
    }

    #[test]
    fn add_target_display_renders_lpm_scoped() {
        let (target, _, _) = resolve_add_target("@lpm.dev/owner.pkg").unwrap();
        assert_eq!(target.display(), "@lpm.dev/owner.pkg");
    }

    #[test]
    fn add_target_display_renders_npm_verbatim() {
        let (target, _, _) = resolve_add_target("@juggle/resize-observer").unwrap();
        assert_eq!(target.display(), "@juggle/resize-observer");

        let (target, _, _) = resolve_add_target("lodash.merge").unwrap();
        assert_eq!(target.display(), "lodash.merge");
    }
}
