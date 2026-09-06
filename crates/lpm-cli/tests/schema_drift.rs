//! **Tier placement: cli-binary.** Justification class:
//! **parser/schema corpus**. This file walks up the workspace tree from
//! `CARGO_MANIFEST_DIR` to find public schema directories and diffs them
//! against the binary's current schema output. Direct schema-source
//! comparison anchors on `lpm-cli`'s manifest dir; the workflow tier's
//! project-isolated `TempProject` would obscure the schema location instead
//! of using it.
//!
//! Drift guard between the rust-client schema source-of-truth and the
//! static copies served from public schema URLs.
//!
//! When this test fails, regenerate the public copies via:
//!
//! ```bash
//! lpm schema lpm.json        -o public/schemas/lpm.json
//! lpm schema lpm.config.json -o public/schemas/lpm.config.json
//! ```
//!
//! and commit the diff alongside the rust-client change. Done in lockstep so
//! the public copy never lags the binary.
//!
//! ## How the test finds the public schemas dir
//!
//! The gate is best-effort by design. Standalone CI might not check out the
//! public schema host, so the gate must not block that workflow.
//!
//! Resolution order:
//!
//! 1. `LPM_SCHEMAS_PUBLIC_DIR=<path>` — explicit path. **Hard-fails**
//!    when the path doesn't exist. Use this in any CI that wants the
//!    drift check enforced against one specific public schema directory.
//! 2. `LPM_SCHEMAS_PUBLIC_DIR=skip` — explicit opt-out, with a stderr
//!    note.
//! 3. Otherwise: walk up from `CARGO_MANIFEST_DIR` looking for known public
//!    schema directories under any intermediate ancestor. Handles both the
//!    sibling-under-one-parent and cross-subtree local layouts.
//! 4. When none of the above resolves: **silent skip with stderr
//!    note**. Standalone CI without the docs repo just sees the test
//!    pass. Local dev with the docs repo present sees the gate enforce.
//!
//! The primary value of this gate is preventing local hand-edits of
//! the public copy from drifting. CI that needs to enforce the cross-
//! repo invariant must opt in via the env var.

use std::path::PathBuf;
use std::process::Command;

use jsonschema::Validator;

const SKIP_SENTINEL: &str = "skip";

/// Search strategy for the synced schemas dir.
enum Located {
    /// Paths resolved — gate enforces against each dir.
    Found(Vec<PathBuf>),
    /// Skip with a stderr note. Test passes.
    Skipped(String),
    /// Path was set explicitly but doesn't exist on disk.
    /// Hard fail; the user asked for enforcement and we can't deliver.
    ExplicitMissing(PathBuf),
}

fn locate_public_schemas_dirs() -> Located {
    if let Ok(explicit) = std::env::var("LPM_SCHEMAS_PUBLIC_DIR") {
        if explicit == SKIP_SENTINEL {
            return Located::Skipped(format!(
                "LPM_SCHEMAS_PUBLIC_DIR={SKIP_SENTINEL} (explicit opt-out)"
            ));
        }
        let path = PathBuf::from(explicit);
        return if path.is_dir() {
            Located::Found(vec![path])
        } else {
            Located::ExplicitMissing(path)
        };
    }
    // Walk up from CARGO_MANIFEST_DIR. At each ancestor, breadth-first
    // search up to two levels deep for known public schema directories.
    // This covers sibling and cross-subtree local layouts without
    // scanning the world.
    let mut cursor = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    loop {
        for candidate in candidate_dirs_under(&cursor) {
            if candidate.is_dir() && !found.iter().any(|known| known == &candidate) {
                found.push(candidate);
            }
        }
        if !cursor.pop() {
            if !found.is_empty() {
                return Located::Found(found);
            }
            // Implicit walk-up exhausted without finding the dir. This
            // is the standalone-CI case — the public schema repos are
            // not checked out next to `rust-client`. Skip rather than
            // block the workflow; CI that wants enforcement sets the
            // env var.
            return Located::Skipped(
                "no public schema directory found under any ancestor of CARGO_MANIFEST_DIR. \
                 Set LPM_SCHEMAS_PUBLIC_DIR=<path> to enforce."
                    .into(),
            );
        }
    }
}

/// Generate plausible public schema paths under `root`: direct child,
/// plus any subdirectory that itself contains an expected schema host
/// directory. Bounded so we never read more than the immediate children
/// of `root`.
fn candidate_dirs_under(root: &std::path::Path) -> Vec<PathBuf> {
    let targets = [
        std::path::Path::new("rust-client-docs")
            .join("public")
            .join("schemas"),
        std::path::Path::new("a-package-manager")
            .join("public")
            .join("schemas"),
    ];
    let mut out = Vec::with_capacity(targets.len() * 2);
    for target in &targets {
        out.push(root.join(target));
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                for target in &targets {
                    out.push(path.join(target));
                }
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
    let dirs = match locate_public_schemas_dirs() {
        Located::Found(dirs) => dirs,
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
    let canonical = render_canonical(kind);
    for dir in dirs {
        let public_path = dir.join(kind);
        let public = std::fs::read_to_string(&public_path).unwrap_or_else(|e| {
            panic!(
                "could not read {}: {e}\nExpected the synced copy to live next to a public schema repo. \
                 Run `lpm schema {kind} -o {}` to regenerate.",
                public_path.display(),
                public_path.display(),
            )
        });
        // Trim trailing whitespace on both sides — `lpm schema` writes
        // a single trailing newline via `std::fs::write`, while the
        // file is committed without a final newline depending on editor.
        if canonical.trim_end() != public.trim_end() {
            let public_first_diff = public
                .lines()
                .zip(canonical.lines())
                .position(|(a, b)| a != b)
                .map_or_else(
                    || public.lines().count().max(canonical.lines().count()),
                    |i| i + 1,
                );
            panic!(
                "schema drift: {} differs from `lpm schema {kind}` output.\n\
                 First diverging line: ~{public_first_diff}\n\
                 Regenerate with: lpm schema {kind} -o {}",
                public_path.display(),
                public_path.display(),
            );
        }
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

fn lpm_json_validator() -> Validator {
    Validator::new(&lpm_runner::lpm_json::generate_schema())
        .expect("generated lpm.json schema must compile")
}

#[test]
fn lpm_json_schema_does_not_advertise_an_invalid_checkpoint_default() {
    let schema = lpm_runner::lpm_json::generate_schema();
    let synced_at = &schema["$defs"]["VaultSyncAuthorityCheckpoint"]["properties"]["syncedAt"];

    assert!(
        synced_at.get("default").is_none(),
        "optional syncedAt must not advertise a default rejected by its own string type: {synced_at}",
    );
}

#[test]
fn lpm_json_schema_accepts_checkpoint_without_synced_at() {
    let validator = lpm_json_validator();
    let document = serde_json::json!({
        "vaultSync": {
            "authorityCheckpoints": {
                "personal": {
                    "https://lpm.dev": {
                        "account-1": {"version": 1},
                    },
                },
            },
        },
    });

    assert!(
        validator.is_valid(&document),
        "published schema must accept an optional omitted syncedAt field",
    );
}

#[test]
fn lpm_json_schema_rejects_malformed_sync_authority_metadata() {
    let validator = lpm_json_validator();
    for document in [
        serde_json::json!({
            "vaultSync": {
                "personalBinding": {
                    "registryUrl": "https://lpm.dev",
                    "principalId": "account-1",
                },
            },
        }),
        serde_json::json!({
            "vaultSync": {
                "orgBindings": {
                    "acme": {
                        "registryUrl": "https://lpm.dev",
                        "principalId": "11111111-1111-4111-8111-111111111111",
                    },
                },
            },
        }),
        serde_json::json!({"vaultSync": {"personalBinding": 17}}),
        serde_json::json!({"vaultSync": {"personalPlatformBindings": {"https://lpm.dev": 17}}}),
        serde_json::json!({"vaultSync": {"orgBindings": {"acme": "account-1"}}}),
        serde_json::json!({"vaultSync": {"authorityCheckpoints": {"personal": 5}}}),
        serde_json::json!({
            "vaultSync": {
                "authorityCheckpoints": {
                    "personal": {
                        "https://lpm.dev": {
                            "account-1": {"version": 0},
                        },
                    },
                },
            },
        }),
        serde_json::json!({
            "vaultSync": {
                "authorityCheckpoints": {
                    "personal": {
                        "https://lpm.dev": {
                            "account-1": {"version": 1, "syncedAt": null},
                        },
                    },
                },
            },
        }),
        serde_json::json!({
            "vaultSync": {
                "personalBinding": {
                    "registryUrl": "https://lpm.dev",
                    "principalId": "account-1\u{0000}substitute",
                },
            },
        }),
        serde_json::json!({
            "vaultSync": {
                "authorityCheckpoints": {
                    "organizations": {
                        "acme\u{0085}substitute": {},
                    },
                },
            },
        }),
    ] {
        assert!(
            !validator.is_valid(&document),
            "published schema accepted malformed sync authority metadata: {document}",
        );
    }
}

#[test]
fn lpm_json_schema_documents_runtime_only_sync_authority_constraints() {
    let validator = lpm_json_validator();
    let noncanonical_registry = serde_json::json!({
        "vaultSync": {
            "authorityCheckpoints": {
                "personal": {
                    "https://LPM.dev/": {
                        "account-1": {"version": 1},
                    },
                },
            },
        },
    });
    assert!(validator.is_valid(&noncanonical_registry));
    let manifest =
        lpm_vault::vault_id::VaultManifestSnapshot::parse(&noncanonical_registry.to_string())
            .expect("schema-valid metadata should deserialize");
    assert!(
        manifest
            .personal_sync_principal_for_registry("https://lpm.dev")
            .is_err(),
        "runtime must enforce canonical Registry property names",
    );

    let multibyte_principal = "é".repeat(65);
    let oversized_principal = serde_json::json!({
        "vaultSync": {
            "authorityCheckpoints": {
                "personal": {
                    "https://lpm.dev": {
                        multibyte_principal: {"version": 1},
                    },
                },
            },
        },
    });
    assert!(validator.is_valid(&oversized_principal));
    let manifest =
        lpm_vault::vault_id::VaultManifestSnapshot::parse(&oversized_principal.to_string())
            .expect("schema-valid metadata should deserialize");
    assert!(
        manifest
            .personal_sync_principal_for_registry("https://lpm.dev")
            .is_err(),
        "runtime must enforce the principal ID UTF-8 byte limit",
    );

    let multibyte_organization = "é".repeat(65);
    let oversized_organization = serde_json::json!({
        "vaultSync": {
            "authorityCheckpoints": {
                "organizations": {
                    (&multibyte_organization): {},
                },
            },
        },
    });
    assert!(validator.is_valid(&oversized_organization));
    let manifest =
        lpm_vault::vault_id::VaultManifestSnapshot::parse(&oversized_organization.to_string())
            .expect("schema-valid metadata should deserialize");
    assert!(
        manifest
            .org_sync_principal_for_registry(&multibyte_organization, "https://lpm.dev",)
            .is_err(),
        "runtime must enforce the organization slug UTF-8 byte limit",
    );

    let principals = (0..33)
        .map(|index| {
            (
                format!("account-{index}"),
                serde_json::json!({"version": 1}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let global_capacity = serde_json::json!({
        "vaultSync": {
            "authorityCheckpoints": {
                "personal": {
                    "https://one.example": principals,
                    "https://two.example": principals,
                },
            },
        },
    });
    assert!(validator.is_valid(&global_capacity));
    let manifest = lpm_vault::vault_id::VaultManifestSnapshot::parse(&global_capacity.to_string())
        .expect("schema-valid metadata should deserialize");
    assert!(
        manifest
            .personal_sync_principal_for_registry("https://one.example")
            .is_err(),
        "runtime must enforce the global authority-checkpoint leaf limit",
    );
}

#[test]
fn lpm_json_schema_accepts_valid_sync_authority_metadata() {
    let validator = lpm_json_validator();
    let document = serde_json::json!({
        "vaultSync": {
            "personalVersion": 7,
            "personalPlatformBindings": {
                "https://lpm.dev": {
                    "registryUrl": "https://lpm.dev",
                    "principalId": "account-1",
                },
            },
            "authorityCheckpoints": {
                "personal": {
                    "https://lpm.dev": {
                        "account-1": {
                            "version": 7,
                            "syncedAt": "2026-09-04T00:00:00Z",
                        },
                    },
                },
                "organizations": {
                    "acme": {
                        "https://lpm.dev": {
                            "11111111-1111-4111-8111-111111111111": {
                                "version": 3,
                                "syncedAt": "2026-09-04T00:00:00Z",
                            },
                        },
                    },
                },
            },
        },
    });

    assert!(
        validator.is_valid(&document),
        "published schema rejected valid sync authority metadata",
    );
}
