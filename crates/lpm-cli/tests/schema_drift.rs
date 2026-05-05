//! **Tier placement: cli-binary** (per CLAUDE.md `# Testing Tier
//! Discipline`). Justification class: **parser/schema corpus**. This
//! file walks up the workspace tree from `CARGO_MANIFEST_DIR` to find
//! the `a-package-manager/public/schemas/` directory and diffs it
//! against the binary's current schema output. Cross-repo path
//! resolution + direct schema-source comparison both anchor on
//! `lpm-cli`'s manifest dir; the workflow tier's project-isolated
//! `TempProject` would obscure the cross-repo location instead of
//! using it.
//!
//! Drift guard between the rust-client schema source-of-truth and the
//! static copies served by `a-package-manager` at
//! `https://lpm.dev/schemas/<name>.json`.
//!
//! When this test fails, regenerate the public copies via:
//!
//! ```bash
//! cd a-package-manager
//! lpm schema lpm.json        -o public/schemas/lpm.json
//! lpm schema lpm.config.json -o public/schemas/lpm.config.json
//! ```
//!
//! and commit the diff alongside the rust-client change. Done in
//! lockstep so the CDN copy never lags the binary.
//!
//! ## How the test finds the public schemas dir
//!
//! Cross-repo concern: the gate is best-effort by design. Standalone
//! `rust-client` CI doesn't check out `a-package-manager`, so the gate
//! must not block that workflow.
//!
//! Resolution order:
//!
//! 1. `LPM_SCHEMAS_PUBLIC_DIR=<path>` — explicit path. **Hard-fails**
//!    when the path doesn't exist. Use this in any CI that wants the
//!    drift check enforced (cross-repo workflow, release pipeline).
//! 2. `LPM_SCHEMAS_PUBLIC_DIR=skip` — explicit opt-out, with a stderr
//!    note.
//! 3. Otherwise: walk up from `CARGO_MANIFEST_DIR` looking for a
//!    descendant `a-package-manager/public/schemas/` under any
//!    intermediate ancestor. Handles both the sibling-under-one-parent
//!    layout (`Projects/{rust-client,a-package-manager}/`) and the
//!    cross-subtree layout (`Projects/{lpm-dev,tolgaergin}/...`).
//! 4. When none of the above resolves: **silent skip with stderr
//!    note**. Standalone CI without the docs repo just sees the test
//!    pass. Local dev with the docs repo present sees the gate enforce.
//!
//! The primary value of this gate is preventing local hand-edits of
//! the public copy from drifting. CI that needs to enforce the cross-
//! repo invariant must opt in via the env var.

use std::path::PathBuf;
use std::process::Command;

const SKIP_SENTINEL: &str = "skip";

/// Search strategy for the synced schemas dir.
enum Located {
    /// Path resolved — gate enforces against this dir.
    Found(PathBuf),
    /// Skip with a stderr note. Test passes.
    Skipped(String),
    /// Path was set explicitly but doesn't exist on disk.
    /// Hard fail; the user asked for enforcement and we can't deliver.
    ExplicitMissing(PathBuf),
}

fn locate_public_schemas_dir() -> Located {
    if let Ok(explicit) = std::env::var("LPM_SCHEMAS_PUBLIC_DIR") {
        if explicit == SKIP_SENTINEL {
            return Located::Skipped(format!(
                "LPM_SCHEMAS_PUBLIC_DIR={SKIP_SENTINEL} (explicit opt-out)"
            ));
        }
        let path = PathBuf::from(explicit);
        return if path.is_dir() {
            Located::Found(path)
        } else {
            Located::ExplicitMissing(path)
        };
    }
    // Walk up from CARGO_MANIFEST_DIR. At each ancestor, breadth-first
    // search up to two levels deep for `a-package-manager/public/schemas/`
    // — covers both `Projects/<sibling>/a-package-manager/...` and
    // `Projects/<parent>/<repo>/...` layouts without scanning the world.
    let mut cursor = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        for candidate in candidate_dirs_under(&cursor) {
            if candidate.is_dir() {
                return Located::Found(candidate);
            }
        }
        if !cursor.pop() {
            // Implicit walk-up exhausted without finding the dir. This
            // is the standalone-CI case — `a-package-manager` isn't
            // checked out next to `rust-client`. Skip rather than block
            // the workflow; CI that wants enforcement sets the env var.
            return Located::Skipped(
                "no a-package-manager/public/schemas/ found under any ancestor of \
                 CARGO_MANIFEST_DIR. Set LPM_SCHEMAS_PUBLIC_DIR=<path> to enforce."
                    .into(),
            );
        }
    }
}

/// Generate plausible `a-package-manager/public/schemas/` paths under
/// `root`: direct child, plus any subdirectory that itself contains an
/// `a-package-manager` directory. Bounded so we never read more than
/// the immediate children of `root`.
fn candidate_dirs_under(root: &std::path::Path) -> Vec<PathBuf> {
    let target = std::path::Path::new("a-package-manager")
        .join("public")
        .join("schemas");
    let mut out = vec![root.join(&target)];
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.push(path.join(&target));
            }
        }
    }
    out
}

fn render_canonical(kind: &str) -> String {
    // Build the binary on demand (assert_cmd's pattern). Cheap when the
    // workspace is already built; correct when it isn't.
    let bin = env!("CARGO_BIN_EXE_lpm-rs");
    let output = Command::new(bin)
        .args(["schema", kind])
        .output()
        .unwrap_or_else(|e| panic!("could not invoke `lpm schema {kind}`: {e}"));
    assert!(
        output.status.success(),
        "`lpm schema {kind}` exited non-zero: stderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap_or_else(|e| panic!("`lpm schema {kind}` produced non-UTF8 stdout: {e}"))
}

fn assert_in_sync(kind: &str) {
    let dir = match locate_public_schemas_dir() {
        Located::Found(d) => d,
        Located::Skipped(reason) => {
            eprintln!("[schema_drift] {kind}: skipped — {reason}");
            return;
        }
        Located::ExplicitMissing(path) => panic!(
            "LPM_SCHEMAS_PUBLIC_DIR points at {} which is not a directory. \
             Either fix the path, unset the variable to fall back to the \
             implicit walk-up + silent-skip behavior, or set \
             LPM_SCHEMAS_PUBLIC_DIR=skip to opt out explicitly.",
            path.display()
        ),
    };
    let public_path = dir.join(kind);
    let public = std::fs::read_to_string(&public_path).unwrap_or_else(|e| {
        panic!(
            "could not read {}: {e}\nExpected the synced copy to live next to the \
             a-package-manager repo. Run `lpm schema {kind} -o {}` to regenerate.",
            public_path.display(),
            public_path.display(),
        )
    });
    let canonical = render_canonical(kind);
    // Trim trailing whitespace on both sides — `lpm schema` writes a
    // single trailing newline via `std::fs::write`, while the file is
    // committed without a final newline depending on editor.
    if canonical.trim_end() != public.trim_end() {
        let public_first_diff = public
            .lines()
            .zip(canonical.lines())
            .position(|(a, b)| a != b)
            .map(|i| i + 1)
            .unwrap_or_else(|| public.lines().count().max(canonical.lines().count()));
        panic!(
            "schema drift: {} differs from `lpm schema {kind}` output.\n\
             First diverging line: ~{public_first_diff}\n\
             Regenerate with: lpm schema {kind} -o {}",
            public_path.display(),
            public_path.display(),
        );
    }
}

#[test]
fn lpm_json_schema_in_sync_with_public_copy() {
    assert_in_sync("lpm.json");
}

#[test]
fn lpm_config_schema_in_sync_with_public_copy() {
    assert_in_sync("lpm.config.json");
}
