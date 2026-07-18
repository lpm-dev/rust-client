use super::prelude::*;

/// Intersect a consumer's declared `peerDependencies` against the
/// install set's resolved-versions lookup. Returns
/// `(peer_name, resolved_version)` pairs sorted by peer_name (stable
/// for GraphKey hashing).
///
/// **What "resolved" means here.** The pubgrub / greedy arms have
/// already finished resolution by the time we reach this helper, so
/// the install set is fixed. Peer resolution at this stage is just a
/// lookup: for each declared peer, does the install set contain a
/// version of that package? If yes, that version IS the resolved
/// peer (peer-dep ranges don't multi-select — a peer is whatever
/// version of the named package is in scope).
///
/// **What's NOT here.** Split-aware peer resolution (consumer in
/// context X picks peer in context X first, falling back to
/// unsplit). The upstream `check_unmet_peers` does this for warning
/// generation. For the v2 GraphKey we use the simpler lookup because
/// the audit-fixture scope doesn't exercise splits, and a
/// pessimistic (slightly over-binding) GraphKey is acceptable —
/// worst case is fewer cross-project sharing hits, never an
/// incorrect share. When split-aware resolution becomes load-bearing
/// (once cross-project benchmarks make it load-bearing), this helper grows the
/// `unsplit_versions` parameter the same way `resolve_peer_version`
/// already does.
pub(super) fn compute_resolved_peers(
    consumer: &ResolverPackage,
    consumer_version: &str,
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    resolved_versions: &HashMap<String, Vec<(Option<String>, String)>>,
) -> Vec<(String, String)> {
    let key = CanonicalKey::from(consumer);
    let Some(peer_deps) = cache
        .get(&key)
        .and_then(|info| info.peer_deps.get(consumer_version))
    else {
        return Vec::new();
    };
    let mut peers: Vec<(String, String)> = peer_deps
        .iter()
        .filter_map(|(peer_name, peer_range)| {
            let specifier = crate::PeerSpecifier::parse(peer_name, peer_range).ok()?;
            resolve_peer_binding_version(
                consumer,
                specifier.target(),
                Some(specifier.comparable_range()),
                resolved_versions,
            )
            .map(|(version, _)| (peer_name.clone(), version.clone()))
        })
        .collect();
    peers.sort_by(|a, b| a.0.cmp(&b.0));
    peers
}

pub(crate) fn resolve_peer_binding_version<'a>(
    consumer: &ResolverPackage,
    peer_name: &str,
    peer_range: Option<&NpmRange>,
    resolved_versions: &'a HashMap<String, Vec<(Option<String>, String)>>,
) -> Option<(&'a String, bool)> {
    let candidates = resolved_versions.get(peer_name)?;

    if let Some(context) = consumer.context() {
        let same_context: Vec<&(Option<String>, String)> = candidates
            .iter()
            .filter(|(candidate_context, _)| candidate_context.as_deref() == Some(context))
            .collect();
        if let Some(selected) = select_peer_candidate(&same_context, peer_range) {
            return Some(selected);
        }
    }

    let unsplit: Vec<&(Option<String>, String)> = candidates
        .iter()
        .filter(|(candidate_context, _)| candidate_context.is_none())
        .collect();
    if let Some(selected) = select_peer_candidate(&unsplit, peer_range) {
        return Some(selected);
    }

    let all_candidates: Vec<&(Option<String>, String)> = candidates.iter().collect();
    select_peer_candidate(&all_candidates, peer_range)
}

pub(super) fn select_peer_candidate<'a>(
    candidates: &[&'a (Option<String>, String)],
    peer_range: Option<&NpmRange>,
) -> Option<(&'a String, bool)> {
    let mut first_candidate: Option<&'a String> = None;
    let mut first_satisfying: Option<&'a String> = None;
    let mut newest_candidate: Option<(&'a String, NpmVersion)> = None;
    let mut newest_satisfying: Option<(&'a String, NpmVersion)> = None;

    for candidate in candidates.iter().copied() {
        let version = &candidate.1;
        first_candidate.get_or_insert(version);

        let parsed = NpmVersion::parse(version).ok();
        if let Some(parsed) = parsed.as_ref()
            && newest_candidate
                .as_ref()
                .is_none_or(|(_, newest)| parsed > newest)
        {
            newest_candidate = Some((version, parsed.clone()));
        }

        if peer_version_satisfies(version, peer_range) {
            first_satisfying.get_or_insert(version);
            if let Some(parsed) = parsed
                && newest_satisfying
                    .as_ref()
                    .is_none_or(|(_, newest)| &parsed > newest)
            {
                newest_satisfying = Some((version, parsed));
            }
        }
    }

    if let Some((version, _)) = newest_satisfying {
        return Some((version, true));
    }
    if let Some(version) = first_satisfying {
        return Some((version, true));
    }
    if let Some((version, _)) = newest_candidate {
        return Some((version, false));
    }
    first_candidate.map(|version| (version, false))
}

pub(super) fn peer_version_satisfies(version: &str, peer_range: Option<&NpmRange>) -> bool {
    peer_range.is_none_or(|range| {
        NpmVersion::parse(version)
            .ok()
            .is_some_and(|parsed| range.satisfies(&parsed))
    })
}

/// A warning about an unmet peer dependency.
///
/// Peer deps are checked post-resolution against the actual resolved tree,
/// not during resolution. This avoids over-constraining (union-across-all-versions)
/// and matches npm/pnpm behavior.
#[derive(Debug, Clone)]
pub struct PeerWarning {
    /// The package that declares the peer dependency.
    pub package: String,
    /// The version of the package that declares the peer.
    pub version: String,
    /// The peer dependency name.
    pub peer: String,
    /// The required peer version range.
    pub required_range: String,
    /// The version actually resolved in the tree (None if peer is completely missing).
    pub resolved_version: Option<String>,
}

impl std::fmt::Display for PeerWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.resolved_version {
            Some(v) => write!(
                f,
                "{}@{} requires peer {} ({}), but {}@{} was resolved",
                self.package, self.version, self.peer, self.required_range, self.peer, v
            ),
            None => write!(
                f,
                "{}@{} requires peer {} ({}), but it is not installed",
                self.package, self.version, self.peer, self.required_range
            ),
        }
    }
}

/// Pre-compiled peer-dependency rules consumed by [`check_unmet_peers`].
///
/// Mirrors the on-disk shape of `package.json > lpm.peerDependencyRules`
/// (and pnpm's identical `pnpm.peerDependencyRules`) but with patterns
/// pre-split, selector keys parsed, and version ranges pre-parsed so
/// the post-resolution peer-warning loop never re-parses on the hot
/// path.
///
/// Build with [`CompiledPeerRules::compile`] from raw string inputs.
/// Compile is **fail-closed**: any unparseable selector key or version
/// range in `allowed_versions` returns an `Err`. The install path
/// propagates this as `LpmError::Script`, matching the
/// [`crate::OverrideSet`] fail-closed posture for `lpm.overrides` —
/// silent typos in hand-authored manifest config are more dangerous
/// than a hard install error. Pass [`CompiledPeerRules::default`]
/// when no rules apply.
///
/// The three sub-fields are independent and combined per pnpm's
/// documented semantics:
///
/// - `ignore_missing` suppresses missing-peer warnings (peer is not in
///   the tree at all).
/// - `allowed_versions` widens the accepted range when the peer is in
///   the tree but at a non-satisfying version.
/// - `allow_any` suppresses version-mismatch warnings entirely when
///   the peer is in the tree (any version goes).
///
/// **Selector grammar (mirrors `lpm.overrides`)** for
/// `allowed_versions` keys:
///
/// - `"react"` — any peer named `react`, regardless of consumer
/// - `"@scope/foo"` — scoped peer, any consumer
/// - `"foo>react"` — `react` peer of `foo` (any version of foo)
/// - `"foo@^2>react"` — `react` peer of `foo` whose version
///   satisfies `^2`
/// - `"@scope/foo@^2>react"` — same shape with scoped parent
///
/// Multi-segment paths (`a>b>c`) and standalone version qualifiers
/// on a bare peer name (`"foo@2"` without `>`) are rejected at
/// compile time — same fail-closed posture as `lpm.overrides`.
///
/// Glob patterns (`*`, `@scope/*`, `*-suffix`, etc.) are supported by
/// `ignore_missing` and `allow_any`; `allowed_versions` uses the
/// structured selector grammar above instead.
#[derive(Debug, Clone, Default)]
pub struct CompiledPeerRules {
    ignore_missing: Vec<GlobPattern>,
    allowed_versions: Vec<AllowedVersionsRule>,
    allow_any: Vec<GlobPattern>,
}

/// One pre-parsed `lpm.peerDependencyRules.allowedVersions` entry.
///
/// `selector` decides which (consumer, peer) pairs the rule applies
/// to; `widened_range` is the user's accepted range for the peer's
/// resolved version. Multiple rules may match a given (consumer, peer)
/// — `check_unmet_peers` accepts the resolved version if **any**
/// matching rule's range is satisfied (union semantics).
#[derive(Debug, Clone)]
struct AllowedVersionsRule {
    selector: AllowedVersionsSelector,
    widened_range: crate::ranges::NpmRange,
}

/// Parsed selector key for an `allowedVersions` rule. Mirrors the
/// `lpm.overrides` selector grammar — bare peer name, or
/// `parent>peer` with optional `@range` on the parent half.
#[derive(Debug, Clone)]
pub(super) struct AllowedVersionsSelector {
    /// Optional consumer constraint. `None` matches any consumer.
    pub(super) parent: Option<ParentSelector>,
    /// Exact peer name. No version qualifier permitted on this side
    /// (the rule's value is the widened range).
    pub(super) peer: String,
}

/// Parent half of an `allowedVersions` selector.
#[derive(Debug, Clone)]
pub(super) struct ParentSelector {
    pub(super) name: String,
    /// Optional version range on the consumer. `None` matches any
    /// version of `name`.
    pub(super) range: Option<crate::ranges::NpmRange>,
}

impl AllowedVersionsSelector {
    /// Parse a raw `allowedVersions` key. Fails closed on:
    /// - empty input
    /// - multi-segment paths (`a>b>c`)
    /// - empty parent or peer halves (`"foo>"`, `">react"`, `">"`)
    /// - bare keys carrying a version qualifier (`"foo@2"` without `>`)
    /// - peer half carrying a version qualifier (`"foo>react@2"`)
    /// - invalid npm names on either side
    /// - unparseable parent version range
    pub(super) fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty allowedVersions selector".into());
        }
        let parts: Vec<&str> = trimmed.split('>').collect();
        match parts.len() {
            1 => {
                // Bare peer name. Reject `foo@version` forms — too
                // ambiguous (could mean "scope by peer required range"
                // or "scope by peer resolved version"). pnpm's own
                // examples don't use this shape.
                let name = parts[0];
                if has_version_qualifier(name) {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: peer name cannot \
                         carry a version qualifier; use `<consumer>{}<peer>` to \
                         scope the rule by consumer",
                        '>'
                    ));
                }
                validate_selector_name(name, "peer name")?;
                Ok(AllowedVersionsSelector {
                    parent: None,
                    peer: name.to_string(),
                })
            }
            2 => {
                let parent_raw = parts[0];
                let peer = parts[1];
                if peer.is_empty() {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: empty peer name \
                         after `>`"
                    ));
                }
                if has_version_qualifier(peer) {
                    return Err(format!(
                        "invalid allowedVersions selector {raw:?}: peer half cannot \
                         carry a version qualifier (the rule's value is the \
                         widened range)"
                    ));
                }
                validate_selector_name(peer, "peer name")?;
                let parent = parse_parent_selector(parent_raw)?;
                Ok(AllowedVersionsSelector {
                    parent: Some(parent),
                    peer: peer.to_string(),
                })
            }
            _ => Err(format!(
                "invalid allowedVersions selector {raw:?}: multi-segment paths \
                 (`a>b>c`) are not supported"
            )),
        }
    }

    /// Match against a (consumer, consumer_version, peer) triple from
    /// the resolved tree. Returns true iff every component of the
    /// selector matches.
    pub(super) fn matches(
        &self,
        consumer: &str,
        consumer_version: &NpmVersion,
        peer: &str,
    ) -> bool {
        if self.peer != peer {
            return false;
        }
        let Some(parent) = &self.parent else {
            return true;
        };
        if parent.name != consumer {
            return false;
        }
        if let Some(range) = &parent.range
            && !range.satisfies(consumer_version)
        {
            return false;
        }
        true
    }
}

/// Parse the parent half of `parent>peer`. Accepts:
/// - `"foo"` — bare name
/// - `"@scope/foo"` — scoped name
/// - `"foo@^2"` — name + version range
/// - `"@scope/foo@^2"` — scoped name + version range
fn parse_parent_selector(raw: &str) -> Result<ParentSelector, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty parent name in allowedVersions selector".into());
    }
    // For `@scope/foo@^2`, the version-separating `@` is the rightmost
    // one at position > 0 (the leading `@` is part of the scope).
    let at_idx = trimmed
        .rmatch_indices('@')
        .find(|(i, _)| *i > 0)
        .map(|(i, _)| i);
    match at_idx {
        Some(i) => {
            let name = &trimmed[..i];
            let range_str = &trimmed[i + 1..];
            if range_str.is_empty() {
                return Err(format!(
                    "empty version range after `@` in allowedVersions parent selector \
                     {trimmed:?}"
                ));
            }
            validate_selector_name(name, "parent name")?;
            let range = crate::ranges::NpmRange::parse(range_str)
                .map_err(|e| format!("unparseable parent version range in {trimmed:?}: {e}"))?;
            Ok(ParentSelector {
                name: name.to_string(),
                range: Some(range),
            })
        }
        None => {
            validate_selector_name(trimmed, "parent name")?;
            Ok(ParentSelector {
                name: trimmed.to_string(),
                range: None,
            })
        }
    }
}

/// `true` iff `name` appears to carry a version qualifier (a `@`
/// past the optional leading scope `@`).
fn has_version_qualifier(name: &str) -> bool {
    if let Some(stripped) = name.strip_prefix('@') {
        stripped.contains('@')
    } else {
        name.contains('@')
    }
}

/// Validate a name appearing in an `allowedVersions` selector.
///
/// Returns `Ok(())` for a valid npm package name; `Err(msg)` with a
/// position-aware error message otherwise. `position` is interpolated
/// into the error (e.g. `"peer name"`, `"parent name"`) so the user
/// sees which half of the selector is malformed.
///
/// **Why not just use [`crate::provider::is_valid_dep_name`]?** That
/// helper is a registry-data hygiene check — its job is to catch
/// path traversal and null bytes in tarball metadata, not to enforce
/// npm's full naming spec. It accepts `"foo bar"` (spaces),
/// `"FooBar"` (uppercase), `".hidden"` / `"_private"` (npm-forbidden
/// leading chars), and `"*"` (glob wildcards) as "valid names" —
/// any of which would silently no-op at runtime against a resolved
/// tree that uses real npm names.
///
/// This validator enforces the actual npm naming contract:
/// 1–214 ASCII characters, lowercase letters / digits /
/// `- _ . ~`, cannot start with `.` or `_`, scoped form
/// `@scope/name` with both halves following the same rules.
/// Glob wildcards (`*`) are explicitly classified separately so the
/// error message can point at `ignoreMissing` / `allowAny`.
///
/// `ignoreMissing` and `allowAny` keep using the unrestricted
/// `GlobPattern` parser — wildcards (and other relaxed shapes) are
/// first-class there.
fn validate_selector_name(name: &str, position: &str) -> Result<(), String> {
    if name.contains('*') {
        return Err(format!(
            "invalid {position} {name:?} in allowedVersions selector \
             (glob wildcards like `*` are not accepted here — use \
             `ignoreMissing` or `allowAny` for pattern-based rules)"
        ));
    }
    if !is_real_npm_package_name(name) {
        return Err(format!(
            "invalid {position} {name:?} in allowedVersions selector \
             (must be a valid npm package name: lowercase letters, digits, \
             `- _ . ~`, cannot start with `.` or `_`; scoped form is \
             `@scope/name`)"
        ));
    }
    Ok(())
}

/// Real npm package-name validator (the contract `npm publish`
/// enforces, not the permissive registry-hygiene fallback).
///
/// Accepts:
/// - 1..=214 ASCII characters
/// - Unscoped: starts with a lowercase letter, digit, `-`, or `~`;
///   body may also include `_`, `.`
/// - Scoped: `@scope/name` where the **scope** follows the unscoped
///   leading-char rules, and the **package half** is a body-only
///   match (leading `.` or `_` is permitted there — npm's
///   `validate-npm-package-name` enforces the leading-char check
///   against the WHOLE name string, which for a scoped name starts
///   with `@`, so `@scope/_internal` and `@scope/.config` are valid
///   per the npm spec).
///
/// Rejects:
/// - Empty / over-length names
/// - Uppercase letters anywhere
/// - Leading `.` or `_` on the unscoped form (or on the scope half
///   of a scoped form)
/// - Any character outside the allowed set (spaces, punctuation, etc.)
fn is_real_npm_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    if let Some(rest) = name.strip_prefix('@') {
        let Some(slash_pos) = rest.find('/') else {
            return false;
        };
        let scope = &rest[..slash_pos];
        let pkg = &rest[slash_pos + 1..];
        // Scope: full unscoped rules — including the leading-`.`/`_`
        // restriction. Package half: body-only — leading `.`/`_` is
        // allowed because npm's leading-char check fires against the
        // whole name (which starts with `@`), not the package half.
        return is_valid_unscoped_npm_name(scope) && is_valid_npm_name_body(pkg);
    }
    is_valid_unscoped_npm_name(name)
}

/// Full unscoped npm-name validator. Used for the unscoped form and
/// for the scope half of a scoped form. Enforces both the leading-
/// char rule and the body charset.
fn is_valid_unscoped_npm_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let first = bytes[0];
    // Cannot start with `.` or `_` per npm's own validator (when
    // applied to the WHOLE name; for scoped names this rule is
    // satisfied by the leading `@` and the scope half running
    // through here, not by the package half — see
    // [`is_valid_npm_name_body`]).
    if !(first.is_ascii_lowercase() || first.is_ascii_digit() || first == b'-' || first == b'~') {
        return false;
    }
    is_valid_npm_name_body(s)
}

/// Body-only npm-name validator: charset matches
/// [`is_valid_unscoped_npm_name`] but the leading-char restriction
/// is dropped. Used for the package half of a scoped name —
/// `@scope/_internal` and `@scope/.config` are valid per npm because
/// the leading-`.`/`_` check fires against the whole `name` string,
/// which starts with `@`.
fn is_valid_npm_name_body(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.as_bytes().iter().all(|&b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || b == b'_'
            || b == b'.'
            || b == b'~'
    })
}

/// Validate an `lpm.peerDependencyRules.allowedVersions` selector key
/// without compiling the full ruleset. Used by the migrate planner to
/// surface bad pnpm-side selector keys up-front before any disk
/// mutation. The migrate planner wraps the error message into its
/// structured `allowed_versions_parse_errors` list so the user sees
/// every bad entry at once.
pub fn validate_allowed_versions_selector(raw_key: &str) -> Result<(), String> {
    AllowedVersionsSelector::parse(raw_key).map(|_| ())
}

/// Validate the widened-range value of an
/// `lpm.peerDependencyRules.allowedVersions` entry against the same
/// parser the resolver uses at install time
/// ([`crate::ranges::NpmRange`]). Exposed so the migrate planner can
/// validate pnpm-side ranges with the exact parser the resolver
/// runs against `lpm.peerDependencyRules` — no parser drift between
/// the two surfaces.
///
/// This explicitly does NOT use `lpm_semver::VersionReq::parse`,
/// which is a stricter strict-semver parser; `NpmRange` accepts the
/// fuller npm-compat range grammar (unions via `||`, `>=1 <2`, etc.)
/// that the install path honors. A range that migrates clean must
/// also compile clean.
pub fn validate_allowed_versions_range(raw_range: &str) -> Result<(), String> {
    crate::ranges::NpmRange::parse(raw_range).map(|_| ())
}

impl CompiledPeerRules {
    /// Compile raw peer-rule inputs from `package.json`.
    ///
    /// **Fail-closed.** Any unparseable selector key or version range
    /// in `allowed_versions` returns an `Err` carrying a human-readable
    /// message naming the offending entry. The install path propagates
    /// this as `LpmError::Script`, matching the [`crate::OverrideSet`]
    /// fail-closed posture for `lpm.overrides`. A silent typo in
    /// hand-authored manifest config is more dangerous than a hard
    /// install error.
    ///
    /// `ignore_missing` and `allow_any` patterns never fail to compile
    /// (they're plain glob fragments — any string is a valid pattern).
    pub fn compile(
        ignore_missing: &[String],
        allowed_versions: &HashMap<String, String>,
        allow_any: &[String],
    ) -> Result<Self, String> {
        let ignore_missing = ignore_missing
            .iter()
            .map(|s| GlobPattern::compile(s))
            .collect();

        let mut allowed_versions_compiled: Vec<AllowedVersionsRule> =
            Vec::with_capacity(allowed_versions.len());
        for (raw_key, raw_range) in allowed_versions {
            let selector = AllowedVersionsSelector::parse(raw_key).map_err(|e| {
                format!("`lpm.peerDependencyRules.allowedVersions[{raw_key:?}]`: {e}")
            })?;
            let widened_range = crate::ranges::NpmRange::parse(raw_range).map_err(|e| {
                format!(
                    "`lpm.peerDependencyRules.allowedVersions[{raw_key:?}] = \
                     {raw_range:?}`: unparseable version range: {e}"
                )
            })?;
            allowed_versions_compiled.push(AllowedVersionsRule {
                selector,
                widened_range,
            });
        }

        let allow_any = allow_any.iter().map(|s| GlobPattern::compile(s)).collect();

        Ok(Self {
            ignore_missing,
            allowed_versions: allowed_versions_compiled,
            allow_any,
        })
    }

    /// `true` iff every list/map is empty — the no-op rule set.
    /// `check_unmet_peers` short-circuits on this for the common case.
    pub fn is_empty(&self) -> bool {
        self.ignore_missing.is_empty()
            && self.allowed_versions.is_empty()
            && self.allow_any.is_empty()
    }

    /// `true` iff a missing-peer warning for `name` should be
    /// suppressed. Tested on every peer-not-in-tree case.
    pub fn ignore_missing_matches(&self, name: &str) -> bool {
        self.ignore_missing.iter().any(|p| p.matches(name))
    }

    /// `true` iff at least one `allowedVersions` rule applies to the
    /// given (consumer, consumer_version, peer) triple AND the
    /// resolved peer version satisfies that rule's widened range.
    /// Multiple matching rules combine with union semantics — any
    /// match suppresses the warning.
    ///
    /// `consumer` is the canonical name of the package declaring the
    /// peer; `consumer_version` is its actual resolved version.
    /// Together they let `parent>peer` and `parent@range>peer`
    /// selectors filter precisely.
    pub fn allowed_versions_satisfies(
        &self,
        consumer: &str,
        consumer_version: &NpmVersion,
        peer: &str,
        resolved_peer_version: &NpmVersion,
    ) -> bool {
        self.allowed_versions.iter().any(|rule| {
            rule.selector.matches(consumer, consumer_version, peer)
                && rule.widened_range.satisfies(resolved_peer_version)
        })
    }

    /// `true` iff a version-mismatch warning for `name` should be
    /// suppressed. Only consulted when the peer IS in the tree.
    pub fn allow_any_matches(&self, name: &str) -> bool {
        self.allow_any.iter().any(|p| p.matches(name))
    }
}

/// Pre-compiled glob pattern.
///
/// Supports the pnpm-compatible subset: literal names, `*` as a
/// wildcard standing in for zero-or-more characters, anywhere in the
/// pattern. Exactly the surface the migrate path translates verbatim.
///
/// Implementation: split on `*`, then walk segments. Empty leading /
/// trailing segments mean "no anchor on that side." Compiled once;
/// matched many times.
#[derive(Debug, Clone)]
pub(super) struct GlobPattern {
    segments: Vec<String>,
    has_wildcard: bool,
}

impl GlobPattern {
    pub(super) fn compile(pattern: &str) -> Self {
        let has_wildcard = pattern.contains('*');
        let segments: Vec<String> = if has_wildcard {
            pattern.split('*').map(str::to_string).collect()
        } else {
            vec![pattern.to_string()]
        };
        Self {
            segments,
            has_wildcard,
        }
    }

    pub(super) fn matches(&self, name: &str) -> bool {
        if !self.has_wildcard {
            return self.segments.first().map(String::as_str) == Some(name);
        }
        let mut idx: usize = 0;
        let last = self.segments.len().saturating_sub(1);
        for (i, seg) in self.segments.iter().enumerate() {
            if seg.is_empty() {
                // Empty segment = wildcard adjacent to a `*`. Leading
                // empty unanchors the prefix, trailing empty unanchors
                // the suffix; an empty middle is impossible to produce
                // via `split('*')` unless there's a `**` (rare; treated
                // as another unanchored gap, harmless).
                continue;
            }
            if i == 0 {
                // First non-empty segment must anchor the prefix.
                if !name[idx..].starts_with(seg.as_str()) {
                    return false;
                }
                idx += seg.len();
            } else if i == last {
                // Last non-empty segment must anchor the suffix at
                // or after the current `idx`.
                let tail = &name[idx..];
                if tail.len() < seg.len() || !tail.ends_with(seg.as_str()) {
                    return false;
                }
                // No idx update — done after the last segment.
            } else {
                // Middle segment: find anywhere in the remainder.
                let tail = &name[idx..];
                match tail.find(seg.as_str()) {
                    Some(p) => idx += p + seg.len(),
                    None => return false,
                }
            }
        }
        true
    }
}

/// Check the resolved tree for unmet peer dependencies.
///
/// For each resolved package, looks up its *actual selected version's* peer deps
/// from the cached metadata, then checks whether the resolved tree satisfies them.
///
/// `peer_rules` is the user-declared peer-dependency rule set from
/// `package.json > lpm.peerDependencyRules` (mirrored from
/// `pnpm.peerDependencyRules` by `lpm migrate`). Three filters apply:
/// `ignore_missing` suppresses missing-peer warnings; `allow_any`
/// suppresses version-mismatch warnings when the peer is present;
/// `allowed_versions` widens the accepted range for matched names.
/// Pass [`CompiledPeerRules::default`] when no rules apply — the
/// helper short-circuits the empty case.
///
/// Returns a list of warnings for unmet peers. This is intentionally warnings-only
/// (not errors) to match npm's default peer behavior. Strict mode enforcement
/// is the caller's responsibility.
pub fn check_unmet_peers(
    resolved: &[ResolvedPackage],
    cache: &HashMap<CanonicalKey, std::sync::Arc<CachedPackageInfo>>,
    peer_rules: &CompiledPeerRules,
) -> Vec<PeerWarning> {
    // Build lookup: canonical_name → all resolved instances for that package.
    // Split packages may legitimately appear multiple times with different contexts.
    let resolved_versions: HashMap<String, Vec<(Option<String>, String)>> =
        resolved.iter().fold(HashMap::new(), |mut acc, package| {
            acc.entry(package.package.canonical_name())
                .or_default()
                .push((
                    package.package.context().map(str::to_string),
                    package.version.to_string(),
                ));
            acc
        });

    let mut warnings = Vec::new();

    for resolved_pkg in resolved {
        let ver_str = resolved_pkg.version.to_string();
        let canonical = resolved_pkg.package.canonical_name();

        // Look up this package's peer deps for its actual resolved
        // version. Canonicalize — split-retry variants share a single
        // cache entry under the canonical key.
        let key = CanonicalKey::from(&resolved_pkg.package);
        let info = cache.get(&key);
        let peer_deps = info.and_then(|i| i.peer_deps.get(&ver_str));

        let Some(peer_deps) = peer_deps else {
            continue;
        };

        // Set of peer names this version marked optional via
        // `peerDependenciesMeta.optional`. Empty for the common case.
        // Used below to suppress the missing-peer warning ONLY — an
        // optional peer that's present but at the wrong version still
        // warrants a warning (the user opted into having a peer, just
        // at an incompatible version).
        let optional_peers = info.and_then(|i| i.optional_peer_names.get(&ver_str));

        for (peer_name, peer_range_str) in peer_deps {
            let Ok(specifier) = crate::PeerSpecifier::parse(peer_name, peer_range_str) else {
                warnings.push(PeerWarning {
                    package: canonical.clone(),
                    version: ver_str.clone(),
                    peer: peer_name.clone(),
                    required_range: peer_range_str.clone(),
                    resolved_version: None,
                });
                continue;
            };
            let required_range = specifier.comparable_range().raw().to_string();
            let resolved_peer_ver = resolve_peer_binding_version(
                &resolved_pkg.package,
                specifier.target(),
                Some(specifier.comparable_range()),
                &resolved_versions,
            );

            match resolved_peer_ver {
                Some((resolved_ver, satisfies)) => {
                    // Peer is in the tree — check if the resolved version satisfies the range
                    let parsed_resolved = NpmVersion::parse(resolved_ver).ok();

                    if !satisfies {
                        // peerDependencyRules filter: allow_any
                        // suppresses every version-mismatch warning
                        // for matched names. allowed_versions tries
                        // a user-widened range as a fallback, with
                        // selector-aware matching against the consumer
                        // (the package declaring the peer) so
                        // `foo@^2>react` only fires for foo@^2.
                        if peer_rules.allow_any_matches(peer_name) {
                            continue;
                        }
                        if let Some(v) = parsed_resolved.as_ref()
                            && peer_rules.allowed_versions_satisfies(
                                &canonical,
                                &resolved_pkg.version,
                                peer_name,
                                v,
                            )
                        {
                            continue;
                        }
                        warnings.push(PeerWarning {
                            package: canonical.clone(),
                            version: ver_str.clone(),
                            peer: peer_name.clone(),
                            required_range: required_range.clone(),
                            resolved_version: Some(resolved_ver.clone()),
                        });
                    }
                }
                None => {
                    // Peer is completely missing from the resolved
                    // tree. peerDependencyRules.ignoreMissing can
                    // suppress the warning entirely.
                    if peer_rules.ignore_missing_matches(peer_name) {
                        continue;
                    }
                    // `peerDependenciesMeta.optional: true` is the
                    // manifest author's explicit "this peer is
                    // optional; no warning if it's missing." pnpm,
                    // yarn, and npm v7+ all honor this. Gates ONLY
                    // the missing-peer branch — version-mismatch
                    // above still warrants a warning.
                    if optional_peers.is_some_and(|set| set.contains(peer_name)) {
                        continue;
                    }
                    warnings.push(PeerWarning {
                        package: canonical.clone(),
                        version: ver_str.clone(),
                        peer: peer_name.clone(),
                        required_range,
                        resolved_version: None,
                    });
                }
            }
        }
    }

    // Sort for deterministic output
    warnings.sort_by(|a, b| a.package.cmp(&b.package).then(a.peer.cmp(&b.peer)));
    warnings
}
