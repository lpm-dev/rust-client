use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `package.json :: lpm.trustedDependencies` — accepts BOTH the legacy
/// bare-name array form and the rich version-bound map form.
///
/// ## Forms
///
/// **Legacy** (bare-name array):
///
/// ```json
/// "trustedDependencies": ["esbuild", "sharp"]
/// ```
///
/// **Rich** (version- and artifact-bound map):
///
/// ```json
/// "trustedDependencies": {
///   "esbuild@0.25.1": {
///     "integrity": "sha512-...",
///     "scriptHash": "sha256-..."
///   }
/// }
/// ```
///
/// The first artifact at a coordinate uses `name@version`. If distinct
/// artifacts share that coordinate, later entries use
/// `name@version#artifact-id` so neither approval replaces the other.
///
/// ## Migration semantics (read-permissive, write-strict)
///
/// - **Read:** both forms deserialize cleanly via `serde(untagged)`. Order
///   matters — the array form is tried first because it's strictly more
///   restrictive (an array can never be confused for a map).
/// - **Write:** `lpm approve-scripts` upgrades any Legacy variant to Rich on
///   the first new approval. The `lpm rebuild` strict gate accepts both forms;
///   legacy bare-name entries match by name only and produce a deprecation warning.
/// - **Coexistence:** a manifest stays in the Legacy form until the first
///   approval is made through `lpm approve-scripts`, at which point it
///   migrates to the Rich form and stays there. There is no downgrade path.
///   Existing entries in a Legacy array are preserved during the upgrade —
///   they become Rich entries with `binding: None` (name only, no integrity,
///   no script hash).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TrustedDependencies {
    /// Legacy form: `["esbuild", "sharp"]`. Bare package names with no
    /// version, integrity, or script hash binding. The strict gate accepts
    /// these as `LegacyNameOnly` matches with a deprecation warning.
    Legacy(Vec<String>),
    /// Rich form: `{"esbuild@0.25.1": {integrity, scriptHash}}`. Keys are
    /// `name@version` or `name@version#artifact-id`; values contain the
    /// integrity and script-hash binding metadata.
    Rich(HashMap<String, TrustedDependencyBinding>),
}

// `ProvenanceSnapshot` lives in `lpm-common` so `lpm-global` (which
// deliberately does not depend on `lpm-workspace`) can share the canonical
// serde shape with project-level `TrustedDependencyBinding`. Callers that
// already import from `lpm_workspace` continue to work via this re-export.
pub use lpm_common::{ProvenanceSnapshot, ProvenanceStatus};

/// Binding metadata for one entry in a Rich `trustedDependencies` map.
///
/// Both fields are `Option<String>` because approvals from the legacy upgrade
/// path carry no integrity or script hash (the user approved by name only).
/// When `lpm approve-scripts` writes a new approval, both fields are populated
/// from the install-time blocked-set in `<project_dir>/.lpm/build-state.json`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct TrustedDependencyBinding {
    /// SRI integrity hash from the lockfile (e.g., `"sha512-..."`).
    /// Mirrors `LockedPackage::integrity`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    /// Deterministic script hash computed by
    /// `lpm_security::script_hash::compute_script_hash`. Format: `"sha256-<hex>"`.
    #[serde(
        default,
        rename = "scriptHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub script_hash: Option<String>,
    /// Snapshot of the publisher identity tuple captured at approval time.
    /// Used by the install-time drift check to detect publisher-identity
    /// drift between the approved version and a candidate version.
    ///
    /// `None` means the binding predates provenance capture (legacy upgrade
    /// path) OR the approved version had no provenance attestation. Both
    /// cases degrade to "cannot detect drift" — the script-hash and
    /// integrity checks still fire independently.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]` keeps
    /// older `trustedDependencies` entries round-tripping unchanged.
    #[serde(
        default,
        rename = "provenanceAtApproval",
        skip_serializing_if = "Option::is_none"
    )]
    pub provenance_at_approval: Option<ProvenanceSnapshot>,
    /// SHA-256 over the sorted canonical names of the active behavioral
    /// tags (per `lpm_security::triage::hash_behavioral_tag_set`) at
    /// approval time. Stored alongside the candidate-side hash on
    /// `BlockedPackage` so the version-diff UI can detect behavioral-tag
    /// drift with a single equality check, without re-fetching metadata.
    ///
    /// `None` for approvals without behavioral analysis (offline, registry
    /// fetch error, or the registry carried no analysis). Two `None`s are
    /// treated as "no signal, don't claim drift" by `compute_version_diff`.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]`.
    #[serde(
        default,
        rename = "behavioralTagsHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavioral_tags_hash: Option<String>,
    /// Sorted canonical names of the active behavioral tags whose hash is
    /// `behavioral_tags_hash`. Persisted so the version-diff UI can render
    /// the delta ("gained network, eval") rather than just "tags changed".
    ///
    /// Both fields are populated from one `active_tag_names()` call so the
    /// hash and the names cannot drift apart. `None` whenever
    /// `behavioral_tags_hash` is `None`; `Some(vec![])` when the version
    /// had analysis but every tag was false.
    ///
    /// Non-breaking: `#[serde(default, skip_serializing_if)]`.
    #[serde(
        default,
        rename = "behavioralTags",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavioral_tags: Option<Vec<String>>,
    /// SHA-256 (`sha256-<hex>` SRI form) over the canonical serialization
    /// of the per-package capability set the user granted at approval time.
    /// Canonicalization is owned by `lpm_cli::capability::CapabilitySet::
    /// canonical_hash`; this field only stores the result.
    ///
    /// # Semantic when `None`
    ///
    /// `None` means a legacy approval — the user never reviewed a specific
    /// capability request. Such approvals grant the baseline capability set
    /// only: empty `passEnv`, `readProject = Narrow`, no `sandboxLimits`
    /// bumps. A request that loosens any of those MUST NOT be satisfied by
    /// a legacy approval.
    ///
    /// The match decision lives in
    /// [`lpm_cli::capability::CapabilitySet::is_approved_by`]
    /// (this crate intentionally does not import the capability types to keep
    /// the dep graph acyclic). Callers must route through that method; do NOT
    /// compare this field directly against a hash string in enforcement code.
    ///
    /// # Semantic when `Some(hash)`
    ///
    /// Binds the approval to the **exact** capability set whose
    /// `canonical_hash()` equals `hash`. Any drift produces a different hash
    /// and invalidates the approval — forcing a re-review before the widened
    /// request takes effect.
    ///
    /// Non-breaking via `#[serde(default, skip_serializing_if)]`: old records
    /// deserialize with `None` and never silently widen.
    #[serde(
        default,
        rename = "capabilityHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_hash: Option<String>,
}

impl Default for TrustedDependencies {
    fn default() -> Self {
        // Default to the LEGACY form so a missing field deserializes as an
        // empty approval list. Existing manifests with no `trustedDependencies`
        // key round-trip as `Vec::new()` and are never accidentally migrated
        // to the Rich form on a no-op read.
        TrustedDependencies::Legacy(Vec::new())
    }
}

/// Bundle of install-time-captured metadata that `lpm approve-scripts`
/// persists onto a [`TrustedDependencyBinding`] via
/// [`TrustedDependencies::approve_with_metadata`].
///
/// All fields are `Option` because each degrades independently to "not
/// captured" under offline or fetch-error conditions; downstream gates
/// treat `None` as "no signal, don't claim drift."
///
/// All fields are sourced from the matching candidate `BlockedPackage`.
#[derive(Debug, Clone, Default)]
pub struct ApprovalMetadata {
    /// SRI integrity hash from the lockfile.
    pub integrity: Option<String>,
    /// Deterministic script hash from
    /// `lpm_security::script_hash::compute_script_hash`.
    pub script_hash: Option<String>,
    /// Publisher-identity snapshot from the registry's Sigstore attestation.
    pub provenance_at_approval: Option<ProvenanceSnapshot>,
    /// SHA-256 over the sorted active behavioral-tag names.
    pub behavioral_tags_hash: Option<String>,
    /// Sorted active behavioral-tag names — the rendering input for the
    /// version-diff "gained / lost" delta.
    pub behavioral_tags: Option<Vec<String>>,
    /// Canonical hash of the per-package `CapabilitySet` the user granted
    /// at approval time. Persists into [`TrustedDependencyBinding::capability_hash`];
    /// enforcement consults it via `CapabilitySet::is_approved_by`.
    ///
    /// `None` means the package requested no extras (baseline) OR the approval
    /// was written by a legacy path. Both degrade to "approved with no extra
    /// capabilities" — they cannot silently widen.
    ///
    /// The hash MUST come from the same `CapabilitySet` object the runtime
    /// will later enforce against. Callers must parse the capability set once
    /// per `approve-scripts` invocation and thread the same object through to
    /// both the prompt renderer and this field.
    pub capability_hash: Option<String>,
}

/// The result of looking up a package in `trustedDependencies`.
/// See [`TrustedDependencies::matches_strict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMatch {
    /// Rich entry with all four fields equal to the queried values.
    /// `lpm rebuild` runs the script.
    Strict,
    /// Name appears in a Legacy `Vec<String>` entry. `lpm rebuild` runs the
    /// script with a deprecation warning suggesting `lpm approve-scripts` to
    /// upgrade to a strict binding.
    LegacyNameOnly,
    /// Rich entry exists for this `name@version` but at least one of
    /// `integrity` / `script_hash` differs from the queried values.
    /// `lpm rebuild` SKIPS the script and surfaces the drift to the user.
    BindingDrift {
        /// The binding currently stored in `package.json` (so callers
        /// can show a diff). Boxed because `TrustedDependencyBinding` grew
        /// past clippy's `large_enum_variant` threshold; boxing the drift
        /// variant keeps the no-data sibling variants cheap.
        stored: Box<TrustedDependencyBinding>,
    },
    /// No matching entry in either form.
    NotTrusted,
}

impl TrustedDependencies {
    /// Base trust-store key for a package coordinate: `"name@version"`.
    /// Artifact-qualified siblings append `#artifact-id` when multiple
    /// artifacts share the coordinate.
    pub fn rich_key(name: &str, version: &str) -> String {
        format!("{name}@{version}")
    }

    fn artifact_key(
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> String {
        format!(
            "{}#{}",
            Self::rich_key(name, version),
            lpm_common::artifact_binding_id(integrity, script_hash),
        )
    }

    /// Strict trust query — the default gate for `lpm rebuild`.
    ///
    /// Returns:
    /// - [`TrustMatch::Strict`] if the Rich variant has a coordinate-matching
    ///   base or artifact-qualified entry whose stored `integrity` and
    ///   `script_hash` BOTH equal the
    ///   queried values. `None` on either side counts as "no constraint" —
    ///   intentional for the legacy-upgrade path where a Rich entry was
    ///   inserted before the binding fields were known.
    /// - [`TrustMatch::BindingDrift`] if a Rich entry exists for the
    ///   `name@version` key but at least one binding field is set on BOTH
    ///   sides and they differ.
    /// - [`TrustMatch::LegacyNameOnly`] if and only if the Legacy
    ///   `Vec<String>` variant contains the bare `name` string. Caller
    ///   should warn about deprecation.
    /// - [`TrustMatch::NotTrusted`] otherwise.
    ///
    /// **`<name>@*` Rich-form sentinels are NOT honored by this strict
    /// gate.** A `name@*` entry is the migration marker [`Self::upgrade_to_rich`]
    /// writes when transferring a legacy `Vec<String>` approval into the
    /// Rich form — at that point no concrete `(integrity, script_hash)`
    /// binding exists yet. Honoring `@*` as `LegacyNameOnly` here would
    /// auto-trust every future version of the package under the
    /// inherited name-only approval, which is a cross-version trust
    /// laundering surface: an attacker who compromises a previously-
    /// approved maintainer's publish flow ships a malicious v1.0.1
    /// that inherits v1.0.0's approval token without integrity or
    /// script_hash checks. The user is forced through `lpm approve-scripts`
    /// on each new version, which writes a concrete `name@version`
    /// entry that closes the loop. `Vec<String>` legacy form is
    /// preserved as `LegacyNameOnly` because that shape is an explicit
    /// user-authored decision in the manifest, distinct from the
    /// auto-generated `@*` sentinel.
    ///
    /// **Lookup precedence:** concrete base and artifact-qualified Rich keys
    /// are the only Rich-form keys that participate in the strict decision.
    /// `name@*` sentinels are still walked by [`Self::contains_name_lenient`]
    /// for non-trust-decision use cases (e.g., the deprecation warning).
    pub fn matches_strict(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustMatch {
        match self {
            TrustedDependencies::Legacy(names) => {
                if names.iter().any(|n| n == name) {
                    TrustMatch::LegacyNameOnly
                } else {
                    TrustMatch::NotTrusted
                }
            }
            TrustedDependencies::Rich(map) => {
                // Concrete coordinate keys are the only Rich-form keys that
                // participate in the strict trust decision. A `name@*`
                // sentinel is an auto-generated migration marker; honoring
                // it here would auto-trust every future version of the
                // package under the inherited name-only approval. See the
                // method docstring for the cross-version trust laundering
                // rationale.
                let mut candidates: Vec<_> = map
                    .iter()
                    .filter(|(key, _)| rich_key_matches_coordinate(key, name, version))
                    .collect();
                candidates.sort_by(|(left, _), (right, _)| left.cmp(right));
                for (_, stored) in &candidates {
                    if binding_matches_query(stored, integrity, script_hash) {
                        return TrustMatch::Strict;
                    }
                }
                candidates
                    .first()
                    .map_or(TrustMatch::NotTrusted, |(_, stored)| {
                        TrustMatch::BindingDrift {
                            stored: Box::new((*stored).clone()),
                        }
                    })
            }
        }
    }

    /// Lenient name-only check. Used by the existing `lpm rebuild` code
    /// path before `matches_strict` was introduced, and by logic that
    /// just wants to know "does this name appear at all?" (e.g., the
    /// stale-trustedDependencies warning).
    pub fn contains_name_lenient(&self, name: &str) -> bool {
        match self {
            TrustedDependencies::Legacy(names) => names.iter().any(|n| n == name),
            TrustedDependencies::Rich(map) => map.keys().any(|k| {
                // Match the part before `@version`, handling scoped
                // packages (`@scope/name@version`) by finding the LAST `@`.
                k.rfind('@')
                    .map_or_else(|| k == name, |at| &k[..at] == name)
            }),
        }
    }

    /// Look up the unambiguous rich binding for a specific coordinate.
    ///
    /// Used by the capability-hash enforcement path to obtain the
    /// [`TrustedDependencyBinding`] whose
    /// [`TrustedDependencyBinding::capability_hash`] the caller feeds to
    /// `lpm_cli::capability::CapabilitySet::is_approved_by`.
    ///
    /// Lookup precedence mirrors [`Self::matches_strict`]:
    /// - Rich entries: base and artifact-qualified keys for the concrete
    ///   coordinate participate. Conflicting artifacts return `None`.
    ///   `name@*` migration sentinels are not a binding source.
    /// - Legacy entries: returns `None` — the legacy form has no binding.
    ///   Callers treat `None` as "legacy approval, no capability hash stored,"
    ///   which collapses via `is_approved_by` to the baseline-only semantic.
    pub fn get_binding(&self, name: &str, version: &str) -> Option<&TrustedDependencyBinding> {
        self.binding_for_exact_version(name, version)
    }

    /// Iterate over (name, optional binding). Legacy entries yield `None`
    /// for the binding. Used by introspection paths like
    /// `lpm approve-scripts --list`.
    pub fn iter(
        &self,
    ) -> Box<dyn Iterator<Item = (String, Option<&TrustedDependencyBinding>)> + '_> {
        match self {
            TrustedDependencies::Legacy(names) => Box::new(names.iter().map(|n| (n.clone(), None))),
            TrustedDependencies::Rich(map) => Box::new(map.iter().map(|(k, v)| {
                // For Rich entries, the user-facing "name" is the part
                // BEFORE the `@version` so callers can group by package.
                let name =
                    parse_rich_key(k).map_or_else(|| k.clone(), |(name, _)| name.to_string());
                (name, Some(v))
            })),
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        match self {
            TrustedDependencies::Legacy(names) => names.len(),
            TrustedDependencies::Rich(map) => map.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Convert any Legacy variant into a Rich variant. Idempotent on Rich.
    /// Used by `lpm approve-scripts` BEFORE inserting any new approval so
    /// that the manifest write path is uniform.
    ///
    /// Existing legacy entries are preserved as Rich entries with no
    /// version pin (key = `<name>@*`) and no binding metadata. These
    /// sentinels are visible to [`Self::contains_name_lenient`] so the
    /// "still approved by name" deprecation warning continues to fire,
    /// but they DO NOT participate in the strict trust gate
    /// ([`Self::matches_strict`]) — see that method's doc for the
    /// cross-version trust laundering rationale. The next install of
    /// any concrete version forces the user through `lpm approve-scripts`,
    /// which writes a full `name@version` Rich entry that REPLACES the
    /// sentinel-only trust with content-bound trust.
    pub fn upgrade_to_rich(&mut self) {
        if matches!(self, TrustedDependencies::Rich(_)) {
            return;
        }
        let TrustedDependencies::Legacy(names) = self else {
            unreachable!("matched Rich above")
        };
        let mut map = HashMap::new();
        for name in names.drain(..) {
            // Use `<name>@*` as the legacy-preserve key. The `*` is a
            // sentinel — `matches_strict` won't match it (because the
            // queried version is always concrete) but `contains_name_lenient`
            // walks the keys and strips the `@*` correctly.
            let key = format!("{name}@*");
            map.insert(
                key,
                TrustedDependencyBinding {
                    integrity: None,
                    script_hash: None,
                    provenance_at_approval: None,
                    behavioral_tags_hash: None,
                    behavioral_tags: None,
                    // The `<name>@*` migration sentinel carries no capability
                    // grant: None = "legacy approval, baseline only".
                    capability_hash: None,
                },
            );
        }
        *self = TrustedDependencies::Rich(map);
    }

    /// Insert a new approval entry, upgrading the variant to Rich if
    /// needed. The first artifact uses `name@version`; a distinct artifact
    /// at the same coordinate uses `name@version#artifact-id`. Re-approving
    /// the same artifact overwrites its prior binding. Returns whether an
    /// entry for that artifact previously existed.
    ///
    /// Metadata-agnostic variant — persists `provenance_at_approval`,
    /// `behavioral_tags_hash`, and `behavioral_tags` as `None`. Production
    /// callers (the `lpm approve-scripts` flow) use
    /// [`Self::approve_with_metadata`] so the drift-check and version-
    /// diff references are populated from the install-time capture.
    pub fn approve(
        &mut self,
        name: &str,
        version: &str,
        integrity: Option<String>,
        script_hash: Option<String>,
    ) -> bool {
        self.approve_with_metadata(
            name,
            version,
            ApprovalMetadata {
                integrity,
                script_hash,
                provenance_at_approval: None,
                behavioral_tags_hash: None,
                behavioral_tags: None,
                capability_hash: None,
            },
        )
    }

    /// Insert or overwrite one artifact approval with the install-time-captured
    /// metadata bundle. Equivalent to [`Self::approve`] but carries provenance,
    /// behavioral-tag hash, and capability-hash fields through to the binding so
    /// subsequent installs can compare against them.
    ///
    /// The caller (`lpm approve-scripts`) reads the metadata from the
    /// install-time `BlockedPackage`. This closes the round-trip: capture →
    /// `BlockedPackage` → binding → next install's drift / version-diff check.
    ///
    /// Passing all-`None` metadata is identical to [`Self::approve`].
    pub fn approve_with_metadata(
        &mut self,
        name: &str,
        version: &str,
        meta: ApprovalMetadata,
    ) -> bool {
        self.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = self else {
            unreachable!("upgrade_to_rich left us in Rich state")
        };
        let binding = TrustedDependencyBinding {
            integrity: meta.integrity,
            script_hash: meta.script_hash,
            provenance_at_approval: meta.provenance_at_approval,
            behavioral_tags_hash: meta.behavioral_tags_hash,
            behavioral_tags: meta.behavioral_tags,
            capability_hash: meta.capability_hash,
        };
        let existing_key = map.iter().find_map(|(key, existing)| {
            (rich_key_matches_coordinate(key, name, version)
                && same_artifact_binding(existing, &binding))
            .then(|| key.clone())
        });
        let replaced = existing_key.is_some();
        let key = existing_key.unwrap_or_else(|| {
            let base = Self::rich_key(name, version);
            if map.contains_key(&base) {
                Self::artifact_key(
                    name,
                    version,
                    binding.integrity.as_deref(),
                    binding.script_hash.as_deref(),
                )
            } else {
                base
            }
        });
        map.insert(key, binding);
        replaced
    }

    /// Find the provenance-bearing approval entry for this package name whose
    /// version sorts highest. Returns `(version, binding)` as the reference
    /// point for the install-time drift check.
    ///
    /// Filtering to provenance-bearing entries only is the safer default:
    /// if `axios@1.14.0` was approved WITH provenance and `axios@1.13.5`
    /// WITHOUT, comparing a candidate against the 1.13.5 binding would
    /// short-circuit to `NoDrift` and mask the signal.
    ///
    /// The returned version string is the part after the LAST `@` in the
    /// rich-map key, so scoped names like `@scope/pkg@1.0.0` correctly
    /// split into `@scope/pkg` + `1.0.0`.
    ///
    /// ## Determinism
    ///
    /// `HashMap` iteration order is non-deterministic. Selecting "the first
    /// match" would make the drift verdict flip across runs when multiple
    /// provenance-bearing approvals for the same package carry different
    /// identities. Instead, this selects the semver-highest entry when both
    /// versions parse, with lexical ordering as a deterministic fallback for
    /// unusual version strings.
    pub fn provenance_reference_for_name(
        &self,
        name: &str,
    ) -> Option<(&str, &TrustedDependencyBinding)> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        let version = map
            .iter()
            .filter_map(|(key, binding)| {
                let (n, v) = parse_rich_key(key)?;
                if n == name && binding.provenance_at_approval.is_some() {
                    Some((v, binding))
                } else {
                    None
                }
            })
            .max_by(|(v1, _), (v2, _)| compare_version_strings(v1, v2))
            .map(|(version, _)| version)?;
        let binding = unambiguous_binding_for_coordinate(map, name, version)?;
        binding
            .provenance_at_approval
            .is_some()
            .then_some((version, binding))
    }

    /// Find the provenance snapshot that should be used to evaluate
    /// drift for a concrete candidate version.
    ///
    /// An exact rich binding for the candidate artifact wins. If multiple
    /// artifacts share a name and version, the most specific unambiguous
    /// integrity and script-hash match is the only eligible reference.
    /// This prevents one artifact from inheriting another artifact's
    /// publisher identity.
    /// When no exact binding exists, use the greatest approved version
    /// lower than the candidate so upgrades still compare against the
    /// most recent prior approval.
    pub fn provenance_reference_for_candidate(
        &self,
        name: &str,
        candidate_version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> Option<(&str, &TrustedDependencyBinding)> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };

        let exact: Vec<_> = map
            .iter()
            .filter_map(|(key, binding)| {
                let (candidate_name, version) = parse_rich_key(key)?;
                (candidate_name == name && version == candidate_version)
                    .then_some((key, version, binding))
            })
            .collect();
        if !exact.is_empty() {
            let mut matching: Vec<_> = exact
                .into_iter()
                .filter_map(|(key, version, binding)| {
                    artifact_match_specificity(binding, integrity, script_hash)
                        .map(|specificity| (specificity, key, version, binding))
                })
                .collect();
            matching.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
            let best = matching.first()?;
            if matching
                .get(1)
                .is_some_and(|next| next.0 == best.0 && next.3 != best.3)
            {
                return None;
            }
            return best
                .3
                .provenance_at_approval
                .is_some()
                .then_some((best.2, best.3));
        }

        let version = map
            .iter()
            .filter_map(|(key, binding)| {
                let (n, v) = parse_rich_key(key)?;
                if n == name
                    && v != "*"
                    && version_string_precedes(v, candidate_version)
                    && binding.provenance_at_approval.is_some()
                {
                    Some((v, binding))
                } else {
                    None
                }
            })
            .max_by(|(v1, _), (v2, _)| compare_version_strings(v1, v2))
            .map(|(version, _)| version)?;
        let binding = unambiguous_binding_for_coordinate(map, name, version)?;
        binding
            .provenance_at_approval
            .is_some()
            .then_some((version, binding))
    }

    /// Find the approved binding for this package name whose version is the
    /// highest known version STRICTLY LESS THAN the given candidate version.
    /// Returns `(version, binding)` as the reference point for the version-diff UI.
    ///
    /// Differences from [`Self::provenance_reference_for_name`]:
    /// - Not filtered by provenance presence — script-hash and behavioral-tag
    ///   drift can be rendered even without a provenance capture.
    /// - Strictly less than `candidate_version`: on re-install of the same
    ///   version there is nothing to diff, so returns `None`.
    /// - Skips `@*` legacy preserve-key entries — they're migration sentinels,
    ///   not concrete prior approvals with binding metadata to diff.
    ///
    /// Semver-aware selection keeps the diff UI and the drift gate in sync
    /// on which version is the "prior approval." Non-semver strings fall
    /// back to lexical ordering so unusual package versions still get a
    /// deterministic result.
    pub fn latest_binding_for_name(
        &self,
        name: &str,
        candidate_version: &str,
    ) -> Option<(&str, &TrustedDependencyBinding)> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        let version = map
            .iter()
            .filter_map(|(key, binding)| {
                let (n, v) = parse_rich_key(key)?;
                // Skip the `@*` legacy preserve key: it's a migration
                // sentinel, not a real approval, and `*` would out-sort
                // every concrete version under lex-max (`*` > any
                // digit). Pre-filter so the preserve key can't poison
                // the reduction.
                if n == name && v != "*" && version_string_precedes(v, candidate_version) {
                    Some((v, binding))
                } else {
                    None
                }
            })
            .max_by(|(v1, _), (v2, _)| compare_version_strings(v1, v2))
            .map(|(version, _)| version)?;
        unambiguous_binding_for_coordinate(map, name, version).map(|binding| (version, binding))
    }

    /// Look up the unambiguous rich-form binding for an exact coordinate.
    /// Base and artifact-qualified keys participate. Returns `None` for
    /// legacy state, no match, or conflicting artifacts at the coordinate.
    pub fn binding_for_exact_version(
        &self,
        name: &str,
        version: &str,
    ) -> Option<&TrustedDependencyBinding> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        unambiguous_binding_for_coordinate(map, name, version)
    }

    /// Look up the binding that authorizes one exact artifact tuple.
    pub fn binding_for_artifact(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> Option<&TrustedDependencyBinding> {
        let TrustedDependencies::Rich(map) = self else {
            return None;
        };
        let mut candidates: Vec<_> = map
            .iter()
            .filter_map(|(key, binding)| {
                if !rich_key_matches_coordinate(key, name, version) {
                    return None;
                }
                artifact_match_specificity(binding, integrity, script_hash)
                    .map(|specificity| (specificity, key, binding))
            })
            .collect();
        candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
        let best = candidates.first()?;
        if candidates
            .get(1)
            .is_some_and(|next| next.0 == best.0 && next.2 != best.2)
        {
            return None;
        }
        Some(best.2)
    }

    /// Remove every base or artifact-qualified approval at an exact
    /// coordinate. Returns `true` if at least one entry was removed.
    ///
    /// Does NOT touch Legacy entries — revoking from a Legacy `Vec<String>`
    /// is a separate concern that callers should handle by upgrading
    /// first if they want strict semantics.
    pub fn revoke(&mut self, name: &str, version: &str) -> bool {
        match self {
            TrustedDependencies::Legacy(_) => false,
            TrustedDependencies::Rich(map) => {
                let previous_len = map.len();
                map.retain(|key, _| !rich_key_matches_coordinate(key, name, version));
                map.len() != previous_len
            }
        }
    }
}

fn parse_rich_key(key: &str) -> Option<(&str, &str)> {
    let coordinate = key
        .split_once('#')
        .map_or(key, |(coordinate, _)| coordinate);
    coordinate.rsplit_once('@')
}

fn rich_key_matches_coordinate(key: &str, name: &str, version: &str) -> bool {
    matches!(parse_rich_key(key), Some((candidate_name, candidate_version)) if candidate_name == name && candidate_version == version)
}

fn binding_matches_query(
    binding: &TrustedDependencyBinding,
    integrity: Option<&str>,
    script_hash: Option<&str>,
) -> bool {
    !matches!(
        (binding.integrity.as_deref(), integrity),
        (Some(stored), Some(queried)) if stored != queried
    ) && !matches!(
        (binding.script_hash.as_deref(), script_hash),
        (Some(stored), Some(queried)) if stored != queried
    )
}

fn artifact_match_specificity(
    binding: &TrustedDependencyBinding,
    integrity: Option<&str>,
    script_hash: Option<&str>,
) -> Option<u8> {
    if !binding_matches_query(binding, integrity, script_hash) {
        return None;
    }
    let integrity_match =
        u8::from(binding.integrity.is_some() && binding.integrity.as_deref() == integrity);
    let script_hash_match =
        u8::from(binding.script_hash.is_some() && binding.script_hash.as_deref() == script_hash);
    Some(integrity_match + script_hash_match)
}

fn same_artifact_binding(
    left: &TrustedDependencyBinding,
    right: &TrustedDependencyBinding,
) -> bool {
    left.integrity == right.integrity && left.script_hash == right.script_hash
}

fn unambiguous_binding_for_coordinate<'a>(
    map: &'a HashMap<String, TrustedDependencyBinding>,
    name: &str,
    version: &str,
) -> Option<&'a TrustedDependencyBinding> {
    let mut selected: Option<&TrustedDependencyBinding> = None;
    for (key, binding) in map {
        if !rich_key_matches_coordinate(key, name, version) {
            continue;
        }
        if selected.is_some_and(|existing| existing != binding) {
            return None;
        }
        selected = Some(binding);
    }
    selected
}

fn parse_version_for_order(version: &str) -> Option<lpm_semver::Version> {
    lpm_semver::Version::parse(version).ok()
}

fn compare_version_strings(left: &str, right: &str) -> std::cmp::Ordering {
    match (
        parse_version_for_order(left),
        parse_version_for_order(right),
    ) {
        (Some(left), Some(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn version_string_precedes(left: &str, right: &str) -> bool {
    compare_version_strings(left, right).is_lt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn legacy_array_form_deserializes_to_legacy_variant() {
        let json = r#"["esbuild", "sharp"]"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        match td {
            TrustedDependencies::Legacy(names) => {
                assert_eq!(names, vec!["esbuild".to_string(), "sharp".to_string()])
            }
            other => panic!("expected Legacy, got {other:?}"),
        }
    }

    #[test]
    fn rich_map_form_deserializes_to_rich_variant() {
        let json = r#"{
            "esbuild@0.25.1": {
                "integrity": "sha512-foo",
                "scriptHash": "sha256-bar"
            }
        }"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        match td {
            TrustedDependencies::Rich(map) => {
                assert_eq!(map.len(), 1);
                let entry = map.get("esbuild@0.25.1").expect("entry must exist");
                assert_eq!(entry.integrity.as_deref(), Some("sha512-foo"));
                assert_eq!(entry.script_hash.as_deref(), Some("sha256-bar"));
            }
            other => panic!("expected Rich, got {other:?}"),
        }
    }

    #[test]
    fn rich_map_form_with_missing_optional_fields_deserializes() {
        // Both integrity and scriptHash are #[serde(default)] Option<String>
        // so an entry with neither should still parse successfully — this
        // is the legacy-upgrade path where binding metadata is unknown.
        let json = r#"{ "esbuild@0.25.1": {} }"#;
        let td: TrustedDependencies = serde_json::from_str(json).unwrap();
        let TrustedDependencies::Rich(map) = td else {
            panic!("expected Rich");
        };
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert!(binding.integrity.is_none());
        assert!(binding.script_hash.is_none());
    }

    #[test]
    fn empty_array_deserializes_as_legacy_empty() {
        let td: TrustedDependencies = serde_json::from_str("[]").unwrap();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Legacy(_)));
    }

    #[test]
    fn empty_map_deserializes_as_rich_empty() {
        let td: TrustedDependencies = serde_json::from_str("{}").unwrap();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Rich(_)));
    }

    #[test]
    fn default_value_is_empty_legacy() {
        let td = TrustedDependencies::default();
        assert!(td.is_empty());
        assert!(matches!(td, TrustedDependencies::Legacy(_)));
    }

    fn rich_with(
        key: &str,
        integrity: Option<&str>,
        script_hash: Option<&str>,
    ) -> TrustedDependencies {
        let mut map = HashMap::new();
        map.insert(
            key.to_string(),
            TrustedDependencyBinding {
                integrity: integrity.map(String::from),
                script_hash: script_hash.map(String::from),
                ..Default::default()
            },
        );
        TrustedDependencies::Rich(map)
    }

    #[test]
    fn matches_strict_returns_strict_for_full_match() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
    }

    #[test]
    fn matches_strict_returns_legacy_name_only_for_legacy_entry() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".to_string()]);
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::LegacyNameOnly
        );
    }

    #[test]
    fn matches_strict_returns_binding_drift_when_script_hash_differs() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-old"));
        let result = td.matches_strict(
            "esbuild",
            "0.25.1",
            Some("sha512-x"),
            Some("sha256-new"), // drifted
        );
        match result {
            TrustMatch::BindingDrift { stored } => {
                assert_eq!(stored.script_hash.as_deref(), Some("sha256-old"));
            }
            other => panic!("expected BindingDrift, got {other:?}"),
        }
    }

    #[test]
    fn matches_strict_returns_binding_drift_when_integrity_differs() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-old"), Some("sha256-y"));
        let result = td.matches_strict("esbuild", "0.25.1", Some("sha512-new"), Some("sha256-y"));
        assert!(matches!(result, TrustMatch::BindingDrift { .. }));
    }

    #[test]
    fn matches_strict_returns_not_trusted_for_unknown_package() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("unknown", "1.0.0", None, None),
            TrustMatch::NotTrusted
        );
    }

    #[test]
    fn matches_strict_returns_not_trusted_for_known_name_different_version() {
        // Rich keys are name@version — a different version key is a
        // different entry. The package must be re-approved at the new version.
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.2", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::NotTrusted
        );
    }

    #[test]
    fn matches_strict_none_query_field_is_wildcard_against_set_stored_field() {
        // If the caller doesn't know the query value (None), and the stored
        // value is set, that's NOT drift — it's "no constraint on the
        // caller side". This is the legacy-upgrade-friendly contract.
        // The stored value continues to constrain SET caller queries.
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", None, Some("sha256-y")),
            TrustMatch::Strict,
            "None query integrity should not produce drift against a set stored integrity"
        );
    }

    #[test]
    fn matches_strict_none_stored_field_is_wildcard_against_set_query_field() {
        // Mirror image: stored binding has no integrity (legacy-upgrade
        // case), caller queries with a concrete integrity. This should
        // be Strict, not Drift, because there's no stored value to drift
        // FROM.
        let td = rich_with("esbuild@0.25.1", None, Some("sha256-y"));
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
    }

    // ── contains_name_lenient ───────────────────────────────────────

    #[test]
    fn contains_name_lenient_finds_legacy_entry() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".to_string()]);
        assert!(td.contains_name_lenient("esbuild"));
        assert!(!td.contains_name_lenient("sharp"));
    }

    #[test]
    fn contains_name_lenient_finds_rich_entry_strips_at_version() {
        let td = rich_with("esbuild@0.25.1", None, None);
        assert!(td.contains_name_lenient("esbuild"));
        assert!(!td.contains_name_lenient("sharp"));
    }

    #[test]
    fn contains_name_lenient_handles_scoped_packages_in_rich_keys() {
        // Scoped name `@scope/pkg` plus version `1.0.0` → key `@scope/pkg@1.0.0`.
        // The lenient matcher must split on the LAST `@`, not the first,
        // so the leading `@` of the scope is preserved.
        let td = rich_with("@scope/pkg@1.0.0", None, None);
        assert!(td.contains_name_lenient("@scope/pkg"));
        assert!(!td.contains_name_lenient("scope/pkg"));
    }

    // ── upgrade_to_rich ─────────────────────────────────────────────

    #[test]
    fn upgrade_to_rich_converts_legacy_entries_with_no_binding() {
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into(), "sharp".into()]);
        td.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich after upgrade");
        };
        assert_eq!(map.len(), 2);
        // The legacy preserve key is `<name>@*`
        assert!(map.contains_key("esbuild@*"));
        assert!(map.contains_key("sharp@*"));
        // Bindings are None because the legacy form had no binding metadata
        for binding in map.values() {
            assert!(binding.integrity.is_none());
            assert!(binding.script_hash.is_none());
        }
    }

    #[test]
    fn upgrade_to_rich_is_idempotent_on_rich_variant() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        td.upgrade_to_rich();
        td.upgrade_to_rich();
        td.upgrade_to_rich();
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich");
        };
        assert_eq!(map.len(), 1);
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.integrity.as_deref(), Some("sha512-x"));
        assert_eq!(binding.script_hash.as_deref(), Some("sha256-y"));
    }

    #[test]
    fn upgrade_to_rich_then_lenient_lookup_still_finds_legacy_names() {
        // After upgrade, contains_name_lenient must still find pre-upgrade
        // entries because their preserve key is `<name>@*` and the lenient
        // matcher strips on the last `@`.
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        td.upgrade_to_rich();
        assert!(td.contains_name_lenient("esbuild"));
    }

    // ── approve / revoke ────────────────────────────────────────────

    #[test]
    fn approve_inserts_new_entry_and_upgrades_to_rich() {
        let mut td = TrustedDependencies::Legacy(vec![]);
        let was_present = td.approve(
            "esbuild",
            "0.25.1",
            Some("sha512-x".to_string()),
            Some("sha256-y".to_string()),
        );
        assert!(!was_present);
        let TrustedDependencies::Rich(map) = &td else {
            panic!("approve must upgrade to Rich");
        };
        assert_eq!(map.len(), 1);
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.integrity.as_deref(), Some("sha512-x"));
        assert_eq!(binding.script_hash.as_deref(), Some("sha256-y"));
    }

    #[test]
    fn approve_with_metadata_updates_an_existing_artifact_binding() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-e"), Some("sha256-s"));
        let was_present = td.approve_with_metadata(
            "esbuild",
            "0.25.1",
            ApprovalMetadata {
                integrity: Some("sha512-e".into()),
                script_hash: Some("sha256-s".into()),
                behavioral_tags_hash: Some("sha256-tags".into()),
                ..ApprovalMetadata::default()
            },
        );
        assert!(was_present);
        let TrustedDependencies::Rich(map) = &td else {
            panic!("expected Rich");
        };
        let binding = map.get("esbuild@0.25.1").unwrap();
        assert_eq!(binding.behavioral_tags_hash.as_deref(), Some("sha256-tags"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn approvals_retain_distinct_artifacts_with_the_same_name_and_version() {
        let mut trusted = TrustedDependencies::default();
        trusted.approve(
            "native-addon",
            "1.0.0",
            Some("sha512-artifact-a".into()),
            Some("sha256-script-a".into()),
        );
        trusted.approve(
            "native-addon",
            "1.0.0",
            Some("sha512-artifact-b".into()),
            Some("sha256-script-b".into()),
        );
        let serialized = serde_json::to_vec(&trusted).unwrap();
        let trusted: TrustedDependencies = serde_json::from_slice(&serialized).unwrap();

        assert_eq!(trusted.len(), 2);
        assert_eq!(
            trusted.matches_strict(
                "native-addon",
                "1.0.0",
                Some("sha512-artifact-a"),
                Some("sha256-script-a"),
            ),
            TrustMatch::Strict,
        );
        assert_eq!(
            trusted.matches_strict(
                "native-addon",
                "1.0.0",
                Some("sha512-artifact-b"),
                Some("sha256-script-b"),
            ),
            TrustMatch::Strict,
        );
    }

    #[test]
    fn binding_for_artifact_prefers_specific_binding_over_wildcard_binding() {
        let wildcard = TrustedDependencyBinding {
            capability_hash: Some("sha256-wildcard-capabilities".into()),
            ..TrustedDependencyBinding::default()
        };
        let specific = TrustedDependencyBinding {
            integrity: Some("sha512-artifact-b".into()),
            script_hash: Some("sha256-script-b".into()),
            capability_hash: Some("sha256-specific-capabilities".into()),
            ..TrustedDependencyBinding::default()
        };
        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), wildcard);
        map.insert("native-addon@1.0.0#artifact-b".into(), specific);
        let trusted = TrustedDependencies::Rich(map);

        let binding = trusted
            .binding_for_artifact(
                "native-addon",
                "1.0.0",
                Some("sha512-artifact-b"),
                Some("sha256-script-b"),
            )
            .expect("the specific artifact binding must be selected");

        assert_eq!(
            binding.capability_hash.as_deref(),
            Some("sha256-specific-capabilities"),
        );
    }

    #[test]
    fn binding_for_artifact_rejects_conflicting_duplicate_artifact_bindings() {
        let first = TrustedDependencyBinding {
            integrity: Some("sha512-artifact".into()),
            script_hash: Some("sha256-script".into()),
            capability_hash: Some("sha256-capabilities-a".into()),
            ..TrustedDependencyBinding::default()
        };
        let second = TrustedDependencyBinding {
            integrity: Some("sha512-artifact".into()),
            script_hash: Some("sha256-script".into()),
            capability_hash: Some("sha256-capabilities-b".into()),
            ..TrustedDependencyBinding::default()
        };
        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), first);
        map.insert("native-addon@1.0.0#duplicate".into(), second);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .binding_for_artifact(
                    "native-addon",
                    "1.0.0",
                    Some("sha512-artifact"),
                    Some("sha256-script"),
                )
                .is_none(),
            "conflicting equal-specificity bindings must fail closed",
        );
    }

    #[test]
    fn binding_for_exact_version_returns_a_single_qualified_artifact_binding() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-artifact".into()),
            script_hash: Some("sha256-script".into()),
            ..TrustedDependencyBinding::default()
        };
        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0#artifact".into(), binding);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .binding_for_exact_version("native-addon", "1.0.0")
                .is_some(),
            "a sole qualified artifact is the unambiguous exact-version binding",
        );
    }

    #[test]
    fn binding_for_exact_version_rejects_distinct_artifacts_at_one_coordinate() {
        let first = TrustedDependencyBinding {
            integrity: Some("sha512-artifact-a".into()),
            ..TrustedDependencyBinding::default()
        };
        let second = TrustedDependencyBinding {
            integrity: Some("sha512-artifact-b".into()),
            ..TrustedDependencyBinding::default()
        };
        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), first);
        map.insert("native-addon@1.0.0#artifact-b".into(), second);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .binding_for_exact_version("native-addon", "1.0.0")
                .is_none(),
            "coordinate-only lookup must fail closed when artifacts differ",
        );
    }

    #[test]
    fn get_binding_returns_a_single_qualified_artifact_binding() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-artifact".into()),
            ..TrustedDependencyBinding::default()
        };
        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0#artifact".into(), binding);
        let trusted = TrustedDependencies::Rich(map);

        assert!(trusted.get_binding("native-addon", "1.0.0").is_some());
    }

    /// Legacy `@*` preserve keys remain visible to lenient lookup but do
    /// not satisfy the strict gate. A concrete approval inserted during
    /// the same upgrade still works normally.
    #[test]
    fn approve_legacy_then_approve_new_preserves_legacy_for_lenient_lookup() {
        let mut td = TrustedDependencies::Legacy(vec!["sharp".to_string()]);
        td.approve(
            "esbuild",
            "0.25.1",
            Some("sha512-x".into()),
            Some("sha256-y".into()),
        );

        // Both entries reachable via lenient lookup
        assert!(td.contains_name_lenient("sharp"));
        assert!(td.contains_name_lenient("esbuild"));

        // Strict lookup finds esbuild as Strict (full binding)
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
        // Strict lookup of sharp returns NotTrusted: the `@*` migration
        // sentinel does NOT participate in the strict trust gate. The user
        // must re-approve sharp via `lpm approve-scripts` on the next
        // install, which writes a concrete `sharp@0.33.0` Rich entry that
        // binds the trust to the specific (integrity, script_hash) tuple.
        // Honoring the sentinel here would auto-trust every future version
        // of sharp under the inherited name-only approval (cross-version
        // trust laundering).
        assert_eq!(
            td.matches_strict("sharp", "0.33.0", Some("sha512-z"), Some("sha256-z")),
            TrustMatch::NotTrusted,
            "`name@*` migration sentinels MUST NOT auto-trust unknown \
             versions. `contains_name_lenient` still walks the sentinel \
             so the deprecation warning fires."
        );
        // The sentinel IS still visible to lenient lookups (used by the
        // deprecation warning and the stale-trustedDependencies surface).
        assert!(td.contains_name_lenient("sharp"));
    }

    /// A `<name>@*` Rich-form sentinel MUST NOT auto-trust any concrete
    /// version. The user is forced through `lpm approve-scripts` on
    /// each new version of the package, which writes a content-bound
    /// `name@version` Rich entry that REPLACES the sentinel-only trust.
    #[test]
    fn matches_strict_at_star_sentinel_does_not_auto_trust_any_version() {
        let mut map = HashMap::new();
        map.insert(
            "esbuild@*".to_string(),
            TrustedDependencyBinding {
                integrity: None,
                script_hash: None,
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        for version in &["0.25.1", "0.25.2", "1.0.0", "0.0.0-beta.1"] {
            assert_eq!(
                td.matches_strict("esbuild", version, None, None),
                TrustMatch::NotTrusted,
                "version {version}: `@*` sentinel must not auto-trust"
            );
        }

        // contains_name_lenient still walks the sentinel — used by
        // non-trust-decision surfaces like the deprecation warning.
        assert!(td.contains_name_lenient("esbuild"));
    }

    /// A scoped package whose only Rich entry is the `@scope/pkg@*`
    /// sentinel must also return NotTrusted for concrete versions —
    /// scoped names follow the same rule as bare names.
    #[test]
    fn matches_strict_at_star_sentinel_does_not_auto_trust_scoped_package() {
        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@*".to_string(),
            TrustedDependencyBinding::default(),
        );
        let td = TrustedDependencies::Rich(map);
        assert_eq!(
            td.matches_strict("@scope/pkg", "1.2.3", None, None),
            TrustMatch::NotTrusted
        );
        assert!(td.contains_name_lenient("@scope/pkg"));
    }

    /// A concrete `name@version` Rich entry is still honored when the
    /// `name@*` sentinel exists alongside it. The sentinel doesn't grant
    /// trust, but it doesn't break trust that the concrete entry grants.
    #[test]
    fn matches_strict_concrete_entry_works_alongside_at_star_sentinel() {
        let mut map = HashMap::new();
        map.insert("esbuild@*".to_string(), TrustedDependencyBinding::default());
        map.insert(
            "esbuild@0.25.1".to_string(),
            TrustedDependencyBinding {
                integrity: Some("sha512-x".into()),
                script_hash: Some("sha256-y".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        // Concrete version + matching binding → Strict (unchanged).
        assert_eq!(
            td.matches_strict("esbuild", "0.25.1", Some("sha512-x"), Some("sha256-y")),
            TrustMatch::Strict
        );
        // Different version → NotTrusted. The `@*` sentinel does NOT
        // grant trust to versions the user has not concretely approved.
        assert_eq!(
            td.matches_strict("esbuild", "0.25.2", None, None),
            TrustMatch::NotTrusted,
            "the @* sentinel does NOT auto-trust unknown versions, even \
             when a sibling concrete version is approved"
        );
        // Concrete version + DRIFTED binding → still BindingDrift on the
        // concrete entry (the @* key does NOT silently mask drift on the
        // entry the user explicitly approved).
        assert!(matches!(
            td.matches_strict(
                "esbuild",
                "0.25.1",
                Some("sha512-x"),
                Some("sha256-DRIFTED")
            ),
            TrustMatch::BindingDrift { .. }
        ));
    }

    #[test]
    fn revoke_removes_entry_and_returns_true() {
        let mut td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        assert!(td.revoke("esbuild", "0.25.1"));
        assert!(td.is_empty());
    }

    #[test]
    fn revoke_returns_false_for_missing_entry() {
        let mut td = rich_with("esbuild@0.25.1", None, None);
        assert!(!td.revoke("sharp", "0.33.0"));
        assert!(!td.is_empty()); // unchanged
    }

    #[test]
    fn revoke_on_legacy_variant_is_a_noop() {
        // Documented contract: revoke does NOT touch Legacy entries.
        // Callers must upgrade first if they want strict semantics.
        let mut td = TrustedDependencies::Legacy(vec!["esbuild".into()]);
        assert!(!td.revoke("esbuild", "0.25.1"));
        assert!(td.contains_name_lenient("esbuild"));
    }

    // ── iter ────────────────────────────────────────────────────────

    #[test]
    fn iter_yields_names_with_none_for_legacy_entries() {
        let td = TrustedDependencies::Legacy(vec!["esbuild".into(), "sharp".into()]);
        let mut entries: Vec<(String, bool)> = td.iter().map(|(n, b)| (n, b.is_some())).collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![("esbuild".to_string(), false), ("sharp".to_string(), false)]
        );
    }

    #[test]
    fn iter_yields_names_with_some_binding_for_rich_entries() {
        let td = rich_with("esbuild@0.25.1", Some("sha512-x"), Some("sha256-y"));
        let entries: Vec<(String, bool)> = td.iter().map(|(n, b)| (n, b.is_some())).collect();
        assert_eq!(entries, vec![("esbuild".to_string(), true)]);
    }

    #[test]
    fn iter_yields_scoped_names_correctly() {
        let td = rich_with("@scope/pkg@1.0.0", None, None);
        let names: Vec<String> = td.iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["@scope/pkg".to_string()]);
    }

    // ── rich_key format ─────────────────────────────────────────────

    #[test]
    fn rich_key_format_uses_at_separator() {
        assert_eq!(
            TrustedDependencies::rich_key("esbuild", "0.25.1"),
            "esbuild@0.25.1"
        );
    }

    #[test]
    fn rich_key_format_handles_scoped_names() {
        assert_eq!(
            TrustedDependencies::rich_key("@scope/pkg", "1.0.0"),
            "@scope/pkg@1.0.0"
        );
    }

    // ── ProvenanceSnapshot tests live in crates/lpm-common/src/provenance.rs;
    //    see the re-export above.

    // ── TrustedDependencyBinding.provenance_at_approval ─────────────

    /// Older `trustedDependencies` entries — with only `integrity`
    /// and `scriptHash` — must keep round-tripping through serde
    /// without the new `provenanceAtApproval` field surfacing as a
    /// `null` key. A live manifest should never grow a `null` key on
    /// read/write cycles.
    #[test]
    fn trusted_binding_without_provenance_roundtrips_cleanly() {
        let pre_p4 = r#"{
            "integrity": "sha512-abc",
            "scriptHash": "sha256-deadbeef"
        }"#;
        let parsed: TrustedDependencyBinding = serde_json::from_str(pre_p4).unwrap();
        assert_eq!(parsed.integrity.as_deref(), Some("sha512-abc"));
        assert_eq!(parsed.script_hash.as_deref(), Some("sha256-deadbeef"));
        assert!(parsed.provenance_at_approval.is_none());

        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("provenanceAtApproval"),
            "older binding must NOT emit a provenanceAtApproval key when None; \
             got {reserialized}"
        );
    }

    /// Provenance-aware happy path: an entry approved in a provenance-aware install
    /// captures the `ProvenanceSnapshot` and round-trips through
    /// serde without field drift. The `provenanceAtApproval` JSON
    /// key name matches the wire spec.
    #[test]
    fn trusted_binding_with_provenance_roundtrips() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-deadbeef".into()),
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some("github:axios/axios".into()),
                workflow_path: Some(".github/workflows/publish.yml".into()),
                workflow_ref: Some("refs/tags/v1.14.0".into()),
                attestation_cert_sha256: Some("sha256-aaa".into()),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains(r#""provenanceAtApproval":"#),
            "wire key must be camelCase `provenanceAtApproval`, got {json}"
        );

        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
    }

    // ── provenance_reference_for_name ─────────────────────────────
    //
    // The selector must be deterministic: HashMap iteration order isn't,
    // so `map.iter().find(...)` would pick different entries across runs
    // when multiple matches exist. Policy: semver-highest version, with
    // lexical fallback for versions outside npm semver.

    fn trusted_dep_binding_with_provenance(publisher: &str) -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: true,
                publisher: Some(publisher.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn trusted_dep_binding_no_provenance() -> TrustedDependencyBinding {
        TrustedDependencyBinding {
            integrity: Some("sha512-x".into()),
            script_hash: Some("sha256-y".into()),
            ..Default::default()
        }
    }

    #[test]
    fn provenance_reference_returns_none_for_legacy_variant() {
        let trusted = TrustedDependencies::Legacy(vec!["axios".into()]);
        assert!(trusted.provenance_reference_for_name("axios").is_none());
    }

    #[test]
    fn provenance_reference_returns_none_for_absent_name() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        assert!(trusted.provenance_reference_for_name("express").is_none());
    }

    #[test]
    fn provenance_reference_returns_none_when_no_entries_have_provenance() {
        // Name matches, but every entry's provenance_at_approval is
        // None — must NOT mask subsequent provenance-bearing
        // approvals by returning a legacy binding. See the
        // drift selector policy.
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        let trusted = TrustedDependencies::Rich(map);
        assert!(trusted.provenance_reference_for_name("axios").is_none());
    }

    #[test]
    fn provenance_reference_returns_single_provenance_bearing_entry() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, binding) = trusted
            .provenance_reference_for_name("axios")
            .expect("entry exists");
        assert_eq!(version, "1.14.0");
        assert_eq!(
            binding
                .provenance_at_approval
                .as_ref()
                .unwrap()
                .publisher
                .as_deref(),
            Some("github:axios/axios"),
        );
    }

    #[test]
    fn provenance_reference_filters_out_legacy_entries_in_mixed_map() {
        // Mix of provenance-bearing and legacy entries for the same
        // name. The selector must pick the provenance-bearing one
        // regardless of insertion order — a legacy v1.13.5 must
        // never be chosen over a provenance-bearing v1.14.0.
        let mut map = HashMap::new();
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_no_provenance(),
        );
        map.insert(
            "axios@1.14.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, _) = trusted
            .provenance_reference_for_name("axios")
            .expect("provenance-bearing entry exists");
        assert_eq!(version, "1.14.0");
    }

    #[test]
    fn provenance_reference_picks_semver_highest_version_deterministically() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.9.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        map.insert(
            "axios@1.10.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios-next"),
        );
        map.insert(
            "axios@1.13.5".to_string(),
            trusted_dep_binding_with_provenance("github:axios/axios"),
        );
        let trusted = TrustedDependencies::Rich(map);

        // Run the selector multiple times — must always pick the same
        // semver-highest entry regardless of HashMap iteration order.
        for _ in 0..8 {
            let (version, binding) = trusted
                .provenance_reference_for_name("axios")
                .expect("at least one match");
            assert_eq!(
                version, "1.13.5",
                "selector must always pick semver-highest; got {version}",
            );
            assert_eq!(
                binding
                    .provenance_at_approval
                    .as_ref()
                    .unwrap()
                    .publisher
                    .as_deref(),
                Some("github:axios/axios"),
                "binding returned must correspond to the semver-highest key",
            );
        }
    }

    #[test]
    fn provenance_reference_for_candidate_prefers_exact_approval_over_higher_version() {
        let mut map = HashMap::new();
        map.insert(
            "esbuild@0.25.12".to_string(),
            TrustedDependencyBinding {
                provenance_at_approval: Some(ProvenanceSnapshot {
                    present: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        map.insert(
            "esbuild@0.28.0".to_string(),
            trusted_dep_binding_with_provenance("github:evanw/esbuild"),
        );
        let trusted = TrustedDependencies::Rich(map);

        let (version, binding) = trusted
            .provenance_reference_for_candidate("esbuild", "0.25.12", None, None)
            .expect("exact approval is the drift reference");

        assert_eq!(version, "0.25.12");
        assert_eq!(
            binding
                .provenance_at_approval
                .as_ref()
                .map(|snapshot| snapshot.present),
            Some(false),
        );
    }

    #[test]
    fn provenance_reference_for_candidate_does_not_cross_same_coordinate_artifacts() {
        let mut primary = trusted_dep_binding_no_provenance();
        primary.integrity = Some("sha512-artifact-b".into());
        primary.script_hash = Some("sha256-script-b".into());
        let mut other = trusted_dep_binding_with_provenance("github:attacker/fork");
        other.integrity = Some("sha512-artifact-a".into());
        other.script_hash = Some("sha256-script-a".into());

        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), primary);
        map.insert("native-addon@1.0.0#artifact-a".into(), other);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .provenance_reference_for_candidate(
                    "native-addon",
                    "1.0.0",
                    Some("sha512-artifact-b"),
                    Some("sha256-script-b"),
                )
                .is_none(),
            "the primary artifact without provenance must not inherit another artifact's publisher identity",
        );
    }

    #[test]
    fn provenance_reference_for_candidate_rejects_ambiguous_prior_artifacts() {
        let mut first = trusted_dep_binding_with_provenance("github:example/first");
        first.integrity = Some("sha512-artifact-a".into());
        first.script_hash = Some("sha256-script-a".into());
        let mut second = trusted_dep_binding_with_provenance("github:example/second");
        second.integrity = Some("sha512-artifact-b".into());
        second.script_hash = Some("sha256-script-b".into());

        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), first);
        map.insert("native-addon@1.0.0#artifact-b".into(), second);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .provenance_reference_for_candidate("native-addon", "2.0.0", None, None)
                .is_none(),
            "an upgrade must not inherit an arbitrary publisher from ambiguous prior artifacts",
        );
    }

    #[test]
    fn latest_binding_for_name_rejects_ambiguous_prior_artifacts() {
        let mut first = trusted_dep_binding_no_provenance();
        first.integrity = Some("sha512-artifact-a".into());
        let mut second = trusted_dep_binding_no_provenance();
        second.integrity = Some("sha512-artifact-b".into());

        let mut map = HashMap::new();
        map.insert("native-addon@1.0.0".into(), first);
        map.insert("native-addon@1.0.0#artifact-b".into(), second);
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .latest_binding_for_name("native-addon", "2.0.0")
                .is_none(),
            "version-diff output must not describe an arbitrary prior artifact",
        );
    }

    #[test]
    fn provenance_reference_for_candidate_does_not_use_higher_version_as_reference() {
        let mut map = HashMap::new();
        map.insert(
            "esbuild@0.28.0".to_string(),
            trusted_dep_binding_with_provenance("github:evanw/esbuild"),
        );
        let trusted = TrustedDependencies::Rich(map);

        assert!(
            trusted
                .provenance_reference_for_candidate("esbuild", "0.25.12", None, None)
                .is_none(),
            "a future approved version must not be used as the drift reference for an older candidate",
        );
    }

    #[test]
    fn provenance_reference_for_candidate_uses_prior_approval_for_upgrade() {
        let mut map = HashMap::new();
        map.insert(
            "axios@1.9.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/old"),
        );
        map.insert(
            "axios@1.10.0".to_string(),
            trusted_dep_binding_with_provenance("github:axios/current"),
        );
        let trusted = TrustedDependencies::Rich(map);

        let (version, binding) = trusted
            .provenance_reference_for_candidate("axios", "1.11.0", None, None)
            .expect("prior approval is the drift reference");

        assert_eq!(version, "1.10.0");
        assert_eq!(
            binding
                .provenance_at_approval
                .as_ref()
                .unwrap()
                .publisher
                .as_deref(),
            Some("github:axios/current"),
        );
    }

    /// Scoped package names (`@scope/pkg`) must split cleanly at the
    /// LAST `@` — the leading `@` in the scope must not be confused
    /// with the version delimiter.
    #[test]
    fn provenance_reference_handles_scoped_name_correctly() {
        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@1.0.0".to_string(),
            trusted_dep_binding_with_provenance("github:scope/pkg"),
        );
        let trusted = TrustedDependencies::Rich(map);
        let (version, _) = trusted
            .provenance_reference_for_name("@scope/pkg")
            .expect("scoped entry resolves");
        assert_eq!(version, "1.0.0");
    }

    /// An approval flow that captures "no provenance present" (the
    /// approved version had no attestation in the first place) must
    /// still serialize the `present: false` snapshot. This matters
    /// for the drift rule's `(None, Some(_)) → block` branch,
    /// which distinguishes "approved version had provenance, this
    /// one doesn't" (block) from "neither side had provenance"
    /// (layers 1/2/4 decide).
    #[test]
    fn trusted_binding_preserves_absent_provenance_marker() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-deadbeef".into()),
            provenance_at_approval: Some(ProvenanceSnapshot {
                present: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
        assert!(!back.provenance_at_approval.as_ref().unwrap().present);
    }

    // ── capabilityHash serde ─────────────────────────────────────

    /// Old binding records (without `capabilityHash`) deserialize with
    /// `capability_hash = None`. Every existing approval in every user's
    /// `package.json > trustedDependencies` must round-trip unchanged.
    #[test]
    fn binding_without_capability_hash_loads_as_legacy_approval() {
        // Three plausible forms: bare legacy (only integrity/scriptHash),
        // full binding (plus provenance + behavioral tags), and empty-object.
        let cases = [
            r#"{}"#,
            r#"{"integrity":"sha512-xyz","scriptHash":"sha256-abc"}"#,
            r#"{
                "integrity":"sha512-xyz",
                "scriptHash":"sha256-abc",
                "provenanceAtApproval":{"present":true},
                "behavioralTagsHash":"sha256-def",
                "behavioralTags":["eval","network"]
            }"#,
        ];
        for raw in cases {
            let binding: TrustedDependencyBinding = serde_json::from_str(raw).unwrap();
            assert_eq!(
                binding.capability_hash, None,
                "older record {raw:?} must load with capability_hash = None; \
                 any other value would silently widen legacy approvals to \
                 cover capabilities they never approved"
            );
        }
    }

    /// Record WITH `capabilityHash` round-trips cleanly: serialize
    /// emits the key, deserialize restores the value.
    #[test]
    fn binding_with_capability_hash_round_trips() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            script_hash: Some("sha256-def".into()),
            capability_hash: Some("sha256-capset-v1-deadbeef".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            json.contains("\"capabilityHash\":\"sha256-capset-v1-deadbeef\""),
            "serialized form includes the camelCase key: {json}"
        );
        let back: TrustedDependencyBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(binding, back);
        assert_eq!(
            back.capability_hash.as_deref(),
            Some("sha256-capset-v1-deadbeef")
        );
    }

    /// `None` in the struct serializes to ABSENT key in JSON —
    /// matches the sibling Option fields (provenanceAtApproval,
    /// behavioralTagsHash, etc.). Absent key ≡ legacy approval,
    /// and the serialized form should reflect that clearly rather
    /// than emitting `"capabilityHash":null` (which would be
    /// semantically equivalent but inconsistent with the rest of
    /// the struct).
    #[test]
    fn binding_with_none_capability_hash_omits_key_in_json() {
        let binding = TrustedDependencyBinding {
            integrity: Some("sha512-abc".into()),
            capability_hash: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(
            !json.contains("capabilityHash"),
            "None should serialize as absent key, not null: {json}"
        );
    }

    /// Old record → new record: a binding with no capabilityHash
    /// that serializes, then deserializes on the new code, then
    /// re-serializes MUST NOT gain a capabilityHash. This protects
    /// the invariant "we never silently upgrade a legacy approval
    /// to bind a specific capability set."
    #[test]
    fn legacy_binding_stays_legacy_after_round_trip_on_new_code() {
        let raw = r#"{"integrity":"sha512-abc","scriptHash":"sha256-def"}"#;
        let binding: TrustedDependencyBinding = serde_json::from_str(raw).unwrap();
        assert_eq!(binding.capability_hash, None);
        let reserialized = serde_json::to_string(&binding).unwrap();
        assert!(
            !reserialized.contains("capabilityHash"),
            "re-serialization of a legacy binding must not introduce \
             a capabilityHash key (doing so would change the semantic \
             from 'legacy approval, baseline only' to 'approval bound \
             to a specific hash' — silent widening if that hash \
             doesn't match what the package now requests). Got: {reserialized}"
        );
    }

    /// Default impl produces `capability_hash = None` — same as the
    /// older default. Pinning this from the Default side so a
    /// future "let's default to some sentinel" refactor fails
    /// loudly.
    #[test]
    fn default_binding_has_no_capability_hash() {
        let b = TrustedDependencyBinding::default();
        assert_eq!(b.capability_hash, None);
    }
}
