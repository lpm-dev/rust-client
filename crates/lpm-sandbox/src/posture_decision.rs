//! Phase 46.1: pure posture-decision helper for the Linux backend.
//!
//! Given a kernel version string (as produced by
//! `/proc/sys/kernel/osrelease` or `uname -r`) and the user's
//! `[sandbox] allow-degraded` opt-in, decide which sandbox posture
//! the backend should construct:
//!
//! - [`PostureDecision::Strict`] — kernel ≥ 6.7. The backend probes
//!   landlock at ABI V4 and installs both filesystem and network
//!   rules.
//! - [`PostureDecision::Degraded`] — kernel < 6.7 AND the user has
//!   set `allow-degraded = true`. The backend probes landlock at
//!   ABI V1 and installs filesystem rules only; the install layer
//!   emits the structured per-install warning.
//! - [`PostureDecision::Refuse`] — kernel < 6.7 AND
//!   `allow-degraded = false` (the default). The factory surfaces
//!   [`crate::SandboxError::KernelTooOld`] with `required: "6.7"`
//!   and the lifecycle script does not run.
//!
//! The decision is a pure function of (kernel version string,
//! `allow_degraded` bool) so the unit tests in this module can
//! exercise the full table on the macOS developer host without
//! spinning up a Linux VM, per the Q3 locked methodology in
//! [the Phase 46.1 design note].
//!
//! [the Phase 46.1 design note]: ../../../../../../../a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase46.1-sandbox-network-denial.md

/// Effective posture the Linux backend should construct, per the
/// kernel-version probe + user opt-in. See module doc for the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PostureDecision {
    /// Strict V4: filesystem + network containment.
    Strict,
    /// Degraded V1: filesystem-only fallback. Field carries the
    /// detected kernel string so the structured warning + doctor
    /// surface can name it verbatim.
    Degraded {
        /// `/proc/sys/kernel/osrelease` output, trimmed.
        detected_kernel: String,
    },
    /// Refuse to construct a sandbox; surface `KernelTooOld`.
    Refuse {
        /// Detected kernel version string for the error message.
        detected_kernel: String,
        /// Minimum kernel version the Phase 46.1 contract requires.
        required_kernel: &'static str,
    },
}

/// Phase 46.1 kernel-version floor. Bumped from 5.13 (V1) to 6.7 (V4)
/// because V4 is the first landlock ABI that adds network access
/// rules — without it, the backend has no way to deny outbound
/// network at the kernel level.
pub(crate) const REQUIRED_KERNEL_FOR_STRICT: &str = "6.7";

/// Decide the posture from a kernel version string + the user's
/// `allow-degraded` opt-in. Pure function — the only inputs are
/// the two arguments.
pub(crate) fn decide_posture(kernel: &str, allow_degraded: bool) -> PostureDecision {
    if meets_v4_floor(kernel) {
        PostureDecision::Strict
    } else if allow_degraded {
        PostureDecision::Degraded {
            detected_kernel: kernel.to_string(),
        }
    } else {
        PostureDecision::Refuse {
            detected_kernel: kernel.to_string(),
            required_kernel: REQUIRED_KERNEL_FOR_STRICT,
        }
    }
}

/// Parse the leading `major.minor` from a Linux kernel version
/// string and return `true` iff it meets the landlock-V4 floor
/// (≥ 6.7). Tolerates trailing distro / suffix tokens —
/// `"5.15.0-1063-aws"`, `"6.7.0-rc1"`, `"6.7"`, `"7.0"` all parse.
///
/// Strings that don't start with `<digits>.<digits>` are treated as
/// "below the floor" — the safe interpretation, since a kernel that
/// reports an unparseable version string is one we can't promise
/// the contract for. The strict default then refuses (the right
/// answer for the floor case), and the explicit `allow-degraded`
/// opt-in still works.
fn meets_v4_floor(s: &str) -> bool {
    let (major, minor) = match parse_major_minor(s) {
        Some(pair) => pair,
        None => return false,
    };
    major > 6 || (major == 6 && minor >= 7)
}

/// Parse the leading two dot-separated integer tokens from a kernel
/// version string. Stops at the first non-digit inside either token.
/// Returns `None` if either token is absent or empty.
fn parse_major_minor(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next().and_then(parse_leading_uint)?;
    let minor = parts.next().and_then(parse_leading_uint)?;
    Some((major, minor))
}

/// Parse the leading consecutive ASCII-digit run as a `u32`. The
/// `5.15.0-1063-aws` form has `5`, `15`, `0-1063-aws` as its
/// dot-split tokens; we want `0` from the third, so this helper
/// stops at the first non-digit.
fn parse_leading_uint(s: &str) -> Option<u32> {
    let end = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    if end == 0 {
        return None;
    }
    s[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Floor parsing ──

    #[test]
    fn parse_major_minor_handles_plain_two_token_form() {
        assert_eq!(parse_major_minor("6.7"), Some((6, 7)));
        assert_eq!(parse_major_minor("5.15"), Some((5, 15)));
        assert_eq!(parse_major_minor("7.0"), Some((7, 0)));
    }

    #[test]
    fn parse_major_minor_handles_three_token_form() {
        assert_eq!(parse_major_minor("6.7.0"), Some((6, 7)));
        assert_eq!(parse_major_minor("5.15.123"), Some((5, 15)));
    }

    #[test]
    fn parse_major_minor_handles_distro_suffix_after_patch() {
        // Real Ubuntu/Amazon Linux strings of the shape
        // `5.15.0-1063-aws` — the third token contains a non-digit
        // suffix; we don't care about it for the floor check.
        assert_eq!(parse_major_minor("5.15.0-1063-aws"), Some((5, 15)));
        assert_eq!(
            parse_major_minor("6.1.91-99.172.amzn2023.x86_64"),
            Some((6, 1))
        );
    }

    #[test]
    fn parse_major_minor_handles_rc_suffix_inside_minor() {
        // `6.7.0-rc1` has the suffix in the patch token; major.minor
        // remains parseable. `6.7-rc1` (no patch, suffix inside minor)
        // also parses — the minor token's leading-digit run is `7`.
        assert_eq!(parse_major_minor("6.7.0-rc1"), Some((6, 7)));
        assert_eq!(parse_major_minor("6.7-rc1"), Some((6, 7)));
    }

    #[test]
    fn parse_major_minor_returns_none_for_unparseable() {
        assert_eq!(parse_major_minor(""), None);
        assert_eq!(parse_major_minor("unknown"), None);
        assert_eq!(parse_major_minor("6"), None); // missing minor
        assert_eq!(parse_major_minor("v6.7"), None); // leading non-digit
    }

    #[test]
    fn meets_v4_floor_strictly_above_and_at_the_floor() {
        assert!(meets_v4_floor("6.7"));
        assert!(meets_v4_floor("6.7.0"));
        assert!(meets_v4_floor("6.8"));
        assert!(meets_v4_floor("6.12.1"));
        assert!(meets_v4_floor("7.0"));
        assert!(meets_v4_floor("10.0"));
    }

    #[test]
    fn meets_v4_floor_below_the_floor() {
        assert!(!meets_v4_floor("6.6"));
        assert!(!meets_v4_floor("6.6.99"));
        assert!(!meets_v4_floor("6.1.91-99.172.amzn2023.x86_64"));
        assert!(!meets_v4_floor("5.15.0-1063-aws")); // Ubuntu 22.04
        assert!(!meets_v4_floor("5.10.0")); // RHEL 9
        assert!(!meets_v4_floor("4.19.0"));
    }

    #[test]
    fn meets_v4_floor_treats_unparseable_as_below_floor() {
        // Defensive: if the kernel reports a version we can't parse,
        // we don't know whether V4 is supported, so we say "no". The
        // strict default then refuses with KernelTooOld — exactly the
        // right escalation surface for "I have no idea what this
        // kernel can do."
        assert!(!meets_v4_floor("unknown"));
        assert!(!meets_v4_floor(""));
    }

    // ── decide_posture: the locked Q2 table ──

    #[test]
    fn decide_posture_kernel_at_floor_with_allow_degraded_false_is_strict() {
        // 6.7 is the floor; allow_degraded irrelevant when the
        // floor is met.
        assert_eq!(
            decide_posture("6.7", false),
            PostureDecision::Strict,
            "kernel == floor + allow_degraded=false must be Strict"
        );
    }

    #[test]
    fn decide_posture_kernel_at_floor_with_allow_degraded_true_is_strict() {
        // The opt-in does NOT downgrade a strict-capable kernel —
        // it's the floor-fallback escape hatch, not a global
        // weakener. A user who set `allow-degraded = true` for
        // compatibility on one machine but rolls onto a 6.7+ kernel
        // gets full strict containment.
        assert_eq!(
            decide_posture("6.7", true),
            PostureDecision::Strict,
            "kernel == floor + allow_degraded=true must still be Strict — the opt-in \
             only fires when the kernel cannot deliver V4"
        );
    }

    #[test]
    fn decide_posture_kernel_above_floor_is_strict_regardless_of_opt_in() {
        for v in &["6.8", "6.12.1", "7.0", "10.0.0-rc1"] {
            for opt in &[false, true] {
                assert_eq!(
                    decide_posture(v, *opt),
                    PostureDecision::Strict,
                    "kernel {v} > floor + allow_degraded={opt} must be Strict",
                );
            }
        }
    }

    #[test]
    fn decide_posture_below_floor_without_opt_in_refuses() {
        let d = decide_posture("5.15.0-1063-aws", false);
        match d {
            PostureDecision::Refuse {
                detected_kernel,
                required_kernel,
            } => {
                assert_eq!(detected_kernel, "5.15.0-1063-aws");
                assert_eq!(required_kernel, "6.7");
            }
            other => panic!("expected Refuse, got {other:?}"),
        }
    }

    #[test]
    fn decide_posture_below_floor_with_opt_in_degrades() {
        let d = decide_posture("5.15.0-1063-aws", true);
        match d {
            PostureDecision::Degraded { detected_kernel } => {
                assert_eq!(detected_kernel, "5.15.0-1063-aws");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    #[test]
    fn decide_posture_unparseable_kernel_falls_through_floor_branch() {
        // Unparseable kernel reports are treated as "below floor" —
        // strict default refuses, opt-in degrades. This is the safest
        // behavior: we don't pretend to deliver a contract on a
        // kernel whose feature set we can't determine.
        assert!(matches!(
            decide_posture("unknown", false),
            PostureDecision::Refuse { .. }
        ));
        assert!(matches!(
            decide_posture("unknown", true),
            PostureDecision::Degraded { .. }
        ));
    }

    #[test]
    fn decide_posture_distro_lts_kernels_below_floor_get_refused() {
        // The four LTS kernels named in the design note all sit
        // below the 6.7 floor. Strict default must refuse all four.
        // (The note: "RHEL 9, Ubuntu 22.04, Debian 12, Amazon Linux
        // 2023 all sit below the 6.7 floor.")
        let cases = &[
            ("5.14.0-362.8.1.el9_3.x86_64", "RHEL 9.3"),
            ("5.15.0-94-generic", "Ubuntu 22.04"),
            ("6.1.0-13-amd64", "Debian 12 (bookworm)"),
            ("6.1.91-99.172.amzn2023.x86_64", "Amazon Linux 2023"),
        ];
        for (kernel, label) in cases {
            assert!(
                matches!(
                    decide_posture(kernel, false),
                    PostureDecision::Refuse { .. }
                ),
                "{label} ({kernel}) must Refuse under strict default",
            );
            // And degrade cleanly when the user opts in.
            assert!(
                matches!(
                    decide_posture(kernel, true),
                    PostureDecision::Degraded { .. }
                ),
                "{label} ({kernel}) must Degrade with allow_degraded=true",
            );
        }
    }
}
