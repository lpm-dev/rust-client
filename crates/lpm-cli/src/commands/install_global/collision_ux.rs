use super::super::global_util::short_name;
use super::prepare::PrepResult;
use crate::{install_ui, output};
use lpm_common::{LpmError, LpmRoot, sanitize_for_terminal};
use lpm_global::{
    CommandCollision, InstallRootStatus, find_command_collisions, read_for, validate_install_root,
};
use std::collections::{BTreeMap, HashSet};

/// user-supplied resolutions for command-name collisions.
///
/// Built from the `--replace-bin` and `--alias` Install flags at the
/// CLI dispatch site ([`CollisionResolution::parse_from_flags`]).
/// Passed through to the install pipeline; semantic application + the
/// "does this command actually exist in the package" check happen under
/// the commit-time lock, where `marker_commands` is authoritative.
///
/// Wraps a `HashSet<String>` for `--replace-bin` (set semantics — listing
/// the same command twice is legal, just redundant) and a `BTreeMap`
/// for `--alias` (deterministic iteration order for diagnostics,
/// serde output, and test assertions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollisionResolution {
    /// Commands the user has opted to forcibly take ownership of from
    /// whatever package (or alias) currently owns them.
    pub replace: HashSet<String>,
    /// Alias mappings: key is the declared bin name (`<orig>`), value
    /// is the PATH name to expose it as (`<alias>`). At commit time
    /// the original name is NOT emitted as a shim; only the alias is.
    pub alias: BTreeMap<String, String>,
}

impl CollisionResolution {
    /// True when the user supplied no flags — the "abort on collision"
    /// path is still the right behaviour for this case.
    /// consumes this to decide between flag-driven resolution
    /// and the TTY-prompt / error paths.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.replace.is_empty() && self.alias.is_empty()
    }

    /// Parse and locally-validate the CLI flag vectors. Returns an
    /// `Err(String)` with a user-facing message on any syntactic /
    /// local-consistency failure:
    ///
    /// - `--alias` mapping that doesn't match `<orig>=<alias>` shape.
    /// - Empty `<orig>` or `<alias>` after splitting on `=`.
    /// - Self-map (`--alias a=a`) — nothing to resolve.
    /// - Duplicate `--alias` keys (`a=b,a=c`) — ambiguous intent.
    /// - Alias target that fails [`lpm_linker::validate_bin_name`] —
    ///   null bytes, path separators, traversal.
    /// - Same command appearing in both `--replace-bin` and `--alias`
    ///   keys — mutually exclusive intents for the same collision.
    ///
    /// Explicitly does NOT check "is this a real command of the
    /// package" — that requires marker discovery and happens under
    /// the commit lock. The `package_name` parameter is only
    /// used to produce useful validator warnings via
    /// `validate_bin_name` (it logs shadowing warnings with the pkg
    /// name attached).
    pub fn parse_from_flags(replace_bin: &[String], alias: &[String]) -> Result<Self, String> {
        let replace: HashSet<String> = replace_bin.iter().cloned().collect();

        let mut alias_map: BTreeMap<String, String> = BTreeMap::new();
        // `--alias a=b,c=d` and `--alias a=b --alias c=d` are both valid;
        // flatten on comma first, then parse each `orig=alias` pair.
        for raw in alias {
            for piece in raw.split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                let (orig, mapped) = piece.split_once('=').ok_or_else(|| {
                    format!(
                        "`--alias {piece}`: expected `<orig>=<alias>` shape (e.g. \
                         `--alias serve=foo-serve`)"
                    )
                })?;
                let orig = orig.trim();
                let mapped = mapped.trim();
                if orig.is_empty() {
                    return Err(format!("`--alias {piece}`: `<orig>` side is empty"));
                }
                if mapped.is_empty() {
                    return Err(format!("`--alias {piece}`: `<alias>` side is empty"));
                }
                if orig == mapped {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: alias target is the same as the \
                         original — nothing to resolve"
                    ));
                }
                // Validate the alias target against the same safety bar
                // package-declared bin names meet. The linker's
                // `validate_bin_name` is the single source of truth so
                // the PATH surface is uniformly safe regardless of
                // whether names come from `package.json` or CLI flags.
                if let Err(reason) = lpm_linker::validate_bin_name(mapped, "<cli-alias>") {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: alias target rejected: {reason}"
                    ));
                }
                if alias_map.contains_key(orig) {
                    return Err(format!(
                        "`--alias {orig}={mapped}`: `{orig}` already has another \
                         alias mapping — specify each `<orig>` at most once"
                    ));
                }
                alias_map.insert(orig.to_string(), mapped.to_string());
            }
        }

        // A single command can't be simultaneously replaced AND aliased;
        // the two resolutions express contradictory intents for the
        // same collision. Catch it early — commit-time would detect it
        // too, but a CLI-shape error is the clearer place.
        for (orig, mapped) in &alias_map {
            if replace.contains(orig) {
                return Err(format!(
                    "`{orig}` is listed in both `--replace-bin` and `--alias {orig}={mapped}` \
                     — these are mutually exclusive resolutions"
                ));
            }
        }

        Ok(Self {
            replace,
            alias: alias_map,
        })
    }
}

/// Render a list of collisions as a multi-line error message. Reused
/// by both the user-facing collision error and the WAL Abort reason
/// recovery would later see.
pub(super) fn format_collisions(collisions: &[CommandCollision]) -> String {
    collisions
        .iter()
        .map(|c| {
            let owner_safe = sanitize_for_terminal(&c.current_owner);
            let command_safe = sanitize_for_terminal(&c.command);
            let owner = if c.via_alias {
                format!("alias \u{2192} {owner_safe}")
            } else {
                owner_safe
            };
            format!("  {command_safe} (owned by {owner})")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Unresolved-collision error with a copy-pasteable remediation. Output
/// shape:
///
///   'foo' would expose command(s) already taken on this host:
///     serve (owned by http-server)
///     lint  (owned by alias → eslint-config)
///
///   To resolve, re-run with one of the following per colliding
///   command:
///
///     lpm install -g foo --replace-bin serve --replace-bin lint
///     lpm install -g foo --alias serve=foo-serve,lint=foo-lint
///
///   --replace-bin transfers ownership; --alias installs the declared
///   bin under a different PATH name. Mix both as needed.
///
/// The concrete example uses the actual colliding command names so the
/// user can paste without substitution. The alias-target names use a
/// `<package>-<command>` pattern as a safe default (real command names
/// that won't collide with the existing owners, even on a repeat run).
pub(super) fn collision_error(installing_pkg: &str, collisions: &[CommandCollision]) -> LpmError {
    let plural_s = if collisions.len() == 1 { "" } else { "s" };
    let plural_verb = if collisions.len() == 1 { "is" } else { "are" };

    // Build concrete example invocations using the real collisions.
    // `--replace-bin <cmd>` per collision; `--alias <cmd>=<pkg>-<cmd>`
    // per collision. The alias prefix is deterministic from the
    // package being installed, so the user gets a reasonable default
    // they can tweak.
    let installing_pkg_safe = sanitize_for_terminal(installing_pkg);
    let short_pkg = sanitize_for_terminal(short_name(installing_pkg));
    let replace_flags = collisions
        .iter()
        .map(|c| format!("--replace-bin {}", sanitize_for_terminal(&c.command)))
        .collect::<Vec<_>>()
        .join(" ");
    let alias_flags = {
        let mappings = collisions
            .iter()
            .map(|c| {
                let cmd_safe = sanitize_for_terminal(&c.command);
                format!("{cmd_safe}={short_pkg}-{cmd_safe}")
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("--alias {mappings}")
    };

    LpmError::Script(format!(
        "'{installing_pkg_safe}' would expose command{plural_s} that {plural_verb} already \
         taken on this host:\n{}\n\nTo resolve, re-run with one of the following per \
         colliding command:\n\n    lpm install -g {installing_pkg_safe} {replace_flags}\n    \
         lpm install -g {installing_pkg_safe} {alias_flags}\n\n--replace-bin transfers ownership to \
         '{installing_pkg_safe}'; --alias installs the declared bin under a different PATH name. \
         Mix both as needed.",
        format_collisions(collisions),
    ))
}

// ─── TTY interactive prompt ────────────────────────────────────

/// Per-collision choice from the TTY prompt. Folds into a
/// `CollisionResolution` by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CollisionChoice {
    Replace,
    Alias(String),
    Cancel,
}

/// Pre-commit pass that prompts the user to resolve collisions when:
///   - Collisions exist on the current (unlocked) manifest view
///   - The user supplied no `--replace-bin`/`--alias` flags
///   - `json_output` is false (JSON mode falls through to the commit-
///     time error so agents get a deterministic structured response)
///   - `stdin` is a TTY
///
/// Otherwise passes the resolution through unchanged — `commit_locked`
/// will either find no collisions (fine), find collisions with flags
/// (planner takes over), or find collisions with no flags (emits the
/// error).
///
/// The manifest read here is UNLOCKED. Drift between this read and
/// commit_locked's lock acquisition is acceptable: the planner inside
/// commit_locked re-validates against a freshly-read manifest under the
/// tx lock, and any new residual collision becomes a
/// `PlanError::ResidualCollision` error. The user sees "collision set
/// changed, re-run" via the standard error path.
pub(super) fn maybe_prompt_for_collisions(
    root: &LpmRoot,
    prep: &PrepResult,
    resolution: CollisionResolution,
    json_output: bool,
) -> Result<CollisionResolution, LpmError> {
    // Early exits.
    if !resolution.is_empty() {
        return Ok(resolution);
    }
    if json_output {
        return Ok(resolution);
    }
    // Require both stdin and stdout to be TTYs. Checking only stdin
    // would let `lpm install -g foo | cat` enter the cliclack prompt
    // with no visible UI, stranding the user with an unresponsive
    // terminal.
    // Matches the pattern used by `approve_scripts/display.rs` and
    // `upgrade.rs` for every other interactive command.
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(resolution);
    }

    // Unlocked read of the current manifest + install root validation.
    // Same shape as the very first step of commit_locked so the
    // collision set we prompt about matches what commit_locked will
    // re-check under the lock (modulo drift).
    let manifest = read_for(root)?;
    let status = validate_install_root(&prep.install_root, None)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        // If the marker isn't ready yet we can't enumerate the
        // commands to prompt about. Fall through; commit_locked will
        // surface the validate error.
        _ => return Ok(resolution),
    };
    let collisions = find_command_collisions(&manifest, &prep.name, &marker_commands);
    if collisions.is_empty() {
        return Ok(resolution);
    }

    // Run the prompt.
    prompt_collisions(&prep.name, &collisions)
}

/// The interactive prompt itself. One cliclack `select` per colliding
/// command (replace / alias / cancel). Alias choice follows up with
/// an `input` for the alias name; invalid inputs re-prompt. Cancel on
/// any colliding command aborts the whole install.
fn prompt_collisions(
    installing_pkg: &str,
    collisions: &[CommandCollision],
) -> Result<CollisionResolution, LpmError> {
    use crate::prompt::prompt_err;

    eprintln!();
    let installing_pkg_safe = sanitize_for_terminal(installing_pkg);
    output::warn_line(crate::install_ui::terminal_line!(
        "'{}' would expose {} command{} that {} already taken on this host.",
        install_ui::bold(&installing_pkg_safe),
        collisions.len(),
        if collisions.len() == 1 { "" } else { "s" },
        if collisions.len() == 1 { "is" } else { "are" },
    ));
    eprintln!();

    // Collect one choice per collision, then fold. Separating the
    // I/O loop from the fold lets `fold_choices_into_resolution` be
    // unit-tested without a PTY.
    let mut choices: Vec<(CommandCollision, CollisionChoice)> =
        Vec::with_capacity(collisions.len());
    for c in collisions {
        let choice = prompt_one_collision(installing_pkg, c).map_err(prompt_err)?;
        choices.push((c.clone(), choice));
    }
    fold_choices_into_resolution(&choices)
}

/// Pure fold: one `(CommandCollision, CollisionChoice)` pair per
/// colliding command in order. Returns `Err` if any choice is
/// `Cancel` (the whole install aborts on first cancel). Otherwise
/// builds a `CollisionResolution` with the per-collision choices.
///
/// Separated from `prompt_collisions` so the fold logic is testable
/// without a PTY. The I/O shell (`prompt_one_collision` + cliclack)
/// stays thin around this pure core.
fn fold_choices_into_resolution(
    choices: &[(CommandCollision, CollisionChoice)],
) -> Result<CollisionResolution, LpmError> {
    let mut replace: HashSet<String> = HashSet::new();
    let mut alias: BTreeMap<String, String> = BTreeMap::new();
    for (collision, choice) in choices {
        match choice {
            CollisionChoice::Replace => {
                replace.insert(collision.command.clone());
            }
            CollisionChoice::Alias(alias_name) => {
                alias.insert(collision.command.clone(), alias_name.clone());
            }
            CollisionChoice::Cancel => {
                return Err(LpmError::Script(format!(
                    "install cancelled: user declined to resolve collision on '{}'",
                    sanitize_for_terminal(&collision.command)
                )));
            }
        }
    }
    Ok(CollisionResolution { replace, alias })
}

/// Prompt for one collision. Returns the user's choice.
fn prompt_one_collision(
    installing_pkg: &str,
    collision: &CommandCollision,
) -> Result<CollisionChoice, std::io::Error> {
    let installing_pkg_safe = sanitize_for_terminal(installing_pkg);
    let command_safe = sanitize_for_terminal(&collision.command);
    let owner_safe = sanitize_for_terminal(&collision.current_owner);
    let owner_label = if collision.via_alias {
        format!("alias \u{2192} {owner_safe}")
    } else {
        owner_safe
    };
    let label =
        format!("Command '{command_safe}' is currently owned by '{owner_label}'. How to resolve?");

    let short_pkg = sanitize_for_terminal(short_name(installing_pkg));
    let default_alias = format!("{short_pkg}-{command_safe}");

    loop {
        let choice: &str = cliclack::select(&label)
            .item(
                "replace",
                format!("Replace — transfer '{command_safe}' to '{installing_pkg_safe}'"),
                "",
            )
            .item(
                "alias",
                format!("Alias — install '{command_safe}' under a different PATH name"),
                "",
            )
            .item("cancel", "Cancel — abort the install", "")
            .initial_value("alias")
            .interact()?;

        match choice {
            "replace" => return Ok(CollisionChoice::Replace),
            "cancel" => return Ok(CollisionChoice::Cancel),
            "alias" => {
                let alias_input: String =
                    cliclack::input(format!("Alias name for '{command_safe}' (PATH command)"))
                        .default_input(&default_alias)
                        .validate(|v: &String| {
                            let trimmed = v.trim();
                            if trimmed.is_empty() {
                                return Err("alias name cannot be empty".to_string());
                            }
                            lpm_linker::validate_bin_name(trimmed, "<cli-alias>")
                        })
                        .interact()?;
                let alias_name = alias_input.trim().to_string();
                if alias_name == collision.command {
                    let alias_safe = sanitize_for_terminal(&alias_name);
                    output::warn(&format!(
                        "alias target '{alias_safe}' is the same as the original name — \
                         nothing to resolve. Try again."
                    ));
                    continue;
                }
                return Ok(CollisionChoice::Alias(alias_name));
            }
            _ => unreachable!("cliclack::select returns one of the declared keys"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_collisions_renders_alias_path_distinctly() {
        let collisions = vec![
            CommandCollision {
                command: "serve".into(),
                current_owner: "pkg-a".into(),
                via_alias: false,
            },
            CommandCollision {
                command: "srv".into(),
                current_owner: "pkg-b".into(),
                via_alias: true,
            },
        ];
        let rendered = format_collisions(&collisions);
        assert!(rendered.contains("serve (owned by pkg-a)"));
        assert!(rendered.contains("srv (owned by alias \u{2192} pkg-b)"));
    }

    #[test]
    fn collision_error_message_includes_workaround_hint() {
        // The collision error now uses concrete --replace-bin / --alias
        // examples rather than a generic workaround hint. This test
        // pins the baseline shape (owner naming + remediation present);
        // the sections below pin the exact flag forms.
        let collisions = vec![CommandCollision {
            command: "eslint".into(),
            current_owner: "eslint".into(),
            via_alias: false,
        }];
        let err = collision_error("alt-eslint", &collisions);
        let msg = format!("{err}");
        assert!(msg.contains("eslint (owned by eslint)"));
        assert!(msg.contains("lpm install -g alt-eslint"));
    }

    #[test]
    fn collision_error_pluralizes_correctly() {
        let one = vec![CommandCollision {
            command: "foo".into(),
            current_owner: "a".into(),
            via_alias: false,
        }];
        assert!(format!("{}", collision_error("c", &one)).contains("command that is"));
        let two = vec![
            CommandCollision {
                command: "foo".into(),
                current_owner: "a".into(),
                via_alias: false,
            },
            CommandCollision {
                command: "bar".into(),
                current_owner: "b".into(),
                via_alias: false,
            },
        ];
        assert!(format!("{}", collision_error("c", &two)).contains("commands that are"));
    }

    // ─── CollisionResolution flag parsing ──────────────────────

    fn parse(replace: &[&str], alias: &[&str]) -> Result<CollisionResolution, String> {
        let r: Vec<String> = replace.iter().map(|s| (*s).to_string()).collect();
        let a: Vec<String> = alias.iter().map(|s| (*s).to_string()).collect();
        CollisionResolution::parse_from_flags(&r, &a)
    }

    #[test]
    fn collision_resolution_empty_flags_is_empty() {
        let r = parse(&[], &[]).unwrap();
        assert!(r.is_empty());
        assert!(r.replace.is_empty());
        assert!(r.alias.is_empty());
    }

    #[test]
    fn collision_resolution_replace_bin_collects_to_set() {
        let r = parse(&["serve", "lint"], &[]).unwrap();
        assert_eq!(r.replace.len(), 2);
        assert!(r.replace.contains("serve"));
        assert!(r.replace.contains("lint"));
        assert!(r.alias.is_empty());
    }

    #[test]
    fn collision_resolution_duplicate_replace_bin_is_idempotent() {
        // Same command listed twice is redundant, not an error — set
        // semantics handle it cleanly and the user's intent is clear.
        let r = parse(&["serve", "serve"], &[]).unwrap();
        assert_eq!(r.replace.len(), 1);
        assert!(r.replace.contains("serve"));
    }

    #[test]
    fn collision_resolution_alias_single_flag_parses() {
        let r = parse(&[], &["serve=foo-serve"]).unwrap();
        assert_eq!(r.alias.len(), 1);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    #[test]
    fn collision_resolution_alias_comma_separated_and_repeated_flags_both_work() {
        let r = parse(&[], &["serve=foo-serve,lint=foo-lint", "test=foo-test"]).unwrap();
        assert_eq!(r.alias.len(), 3);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
        assert_eq!(r.alias.get("test"), Some(&"foo-test".to_string()));
    }

    #[test]
    fn collision_resolution_alias_trims_whitespace_around_pieces() {
        // A user copying from a doc with extra spaces shouldn't fail.
        let r = parse(&[], &["  serve=foo-serve , lint=foo-lint  "]).unwrap();
        assert_eq!(r.alias.len(), 2);
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
    }

    #[test]
    fn collision_resolution_alias_empty_pieces_are_ignored() {
        // Trailing / leading / doubled commas shouldn't fail.
        let r = parse(&[], &[",serve=foo-serve,,lint=foo-lint,"]).unwrap();
        assert_eq!(r.alias.len(), 2);
    }

    #[test]
    fn collision_resolution_alias_missing_equals_rejected() {
        let err = parse(&[], &["foo-serve"]).unwrap_err();
        assert!(
            err.contains("expected `<orig>=<alias>` shape"),
            "error must name the expected shape: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_empty_orig_rejected() {
        let err = parse(&[], &["=foo-serve"]).unwrap_err();
        assert!(err.contains("`<orig>` side is empty"));
    }

    #[test]
    fn collision_resolution_alias_empty_alias_rejected() {
        let err = parse(&[], &["serve="]).unwrap_err();
        assert!(err.contains("`<alias>` side is empty"));
    }

    #[test]
    fn collision_resolution_alias_self_map_rejected() {
        let err = parse(&[], &["serve=serve"]).unwrap_err();
        assert!(
            err.contains("nothing to resolve"),
            "self-map must be rejected with clear message: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_duplicate_orig_key_rejected() {
        // Two mappings for the same `<orig>` is ambiguous user intent.
        let err = parse(&[], &["serve=foo-serve,serve=bar-serve"]).unwrap_err();
        assert!(err.contains("already has another alias mapping"));
    }

    #[test]
    fn collision_resolution_alias_target_with_path_separator_rejected() {
        // validate_bin_name rejects '/' / '\\' / '..' / null bytes.
        let err = parse(&[], &["serve=../evil"]).unwrap_err();
        assert!(
            err.contains("alias target rejected"),
            "path traversal in alias target must be rejected: {err}"
        );
    }

    #[test]
    fn collision_resolution_alias_target_with_null_byte_rejected() {
        let err = parse(&[], &["serve=foo\0bar"]).unwrap_err();
        assert!(err.contains("alias target rejected"));
    }

    #[test]
    fn collision_resolution_command_in_both_replace_and_alias_rejected() {
        // Mutually exclusive intents for the same collision.
        let err = parse(&["serve"], &["serve=foo-serve"]).unwrap_err();
        assert!(
            err.contains("mutually exclusive resolutions"),
            "same command in both sets must be rejected: {err}"
        );
    }

    #[test]
    fn collision_resolution_mixed_replace_and_alias_on_different_commands_is_valid() {
        // Different commands in each set is the normal multi-collision case.
        let r = parse(&["lint"], &["serve=foo-serve"]).unwrap();
        assert!(r.replace.contains("lint"));
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    /// explicitly does NOT know about the package's actual command
    /// set — marker discovery runs later in the pipeline. Commands
    /// named in flags that don't exist on the package are accepted
    /// here and will be rejected in the commit-time semantic check.
    /// Pins the boundary so a future refactor doesn't accidentally pull
    /// that check upstream without wiring marker_commands access.
    #[test]
    fn collision_resolution_does_not_validate_against_package_commands_yet() {
        // "nonexistent" looks like any other command name at flag-parse time.
        let r = parse(&["nonexistent"], &["another=x"]).unwrap();
        assert!(r.replace.contains("nonexistent"));
        assert!(r.alias.contains_key("another"));
    }

    fn single_collision(cmd: &str, owner: &str) -> CommandCollision {
        CommandCollision {
            command: cmd.into(),
            current_owner: owner.into(),
            via_alias: false,
        }
    }

    /// Error must name both flag forms so a user with no prior LPM
    /// context can recover. Pins the remediation contract.
    #[test]
    fn collision_error_mentions_both_override_flags() {
        let e = collision_error("foo", &[single_collision("serve", "http-server")]);
        let msg = e.to_string();
        assert!(
            msg.contains("--replace-bin"),
            "error must mention --replace-bin: {msg}"
        );
        assert!(msg.contains("--alias"), "error must mention --alias: {msg}");
    }

    /// Concrete examples must use the actual collision names so the
    /// user can paste without substitution.
    #[test]
    fn collision_error_emits_copy_pasteable_example_with_real_command_names() {
        let e = collision_error("foo", &[single_collision("serve", "http-server")]);
        let msg = e.to_string();
        assert!(
            msg.contains("lpm install -g foo --replace-bin serve"),
            "error must include the tailored --replace-bin example: {msg}"
        );
        assert!(
            msg.contains("--alias serve=foo-serve"),
            "error must include the tailored --alias example with the short package name: {msg}"
        );
    }

    /// Multi-collision: the example flags must cover every colliding
    /// command, not just the first.
    #[test]
    fn collision_error_multi_collision_covers_every_command() {
        let e = collision_error(
            "foo",
            &[
                single_collision("serve", "http-server"),
                single_collision("lint", "eslint"),
            ],
        );
        let msg = e.to_string();
        // Both replace-bin flags present
        assert!(msg.contains("--replace-bin serve"));
        assert!(msg.contains("--replace-bin lint"));
        // Both alias mappings in one --alias comma list
        assert!(
            msg.contains("--alias serve=foo-serve,lint=foo-lint"),
            "multi-collision --alias must be comma-separated: {msg}"
        );
    }

    /// Scoped package names (`@scope/pkg.tool`) should use the short
    /// name (after the scope) in alias-target defaults so the suggestion
    /// is a valid shell token.
    #[test]
    fn collision_error_alias_default_uses_short_name_for_scoped_pkg() {
        let e = collision_error("@lpm.dev/owner.tool", &[single_collision("run", "other")]);
        let msg = e.to_string();
        assert!(
            msg.contains("--alias run=owner.tool-run"),
            "scoped-package alias target must strip the scope: {msg}"
        );
    }

    /// Error must not reference stale placeholder wording.
    #[test]
    fn collision_error_does_not_reference_old_placeholder_wording() {
        let e = collision_error("foo", &[single_collision("serve", "x")]);
        let msg = e.to_string();
        assert!(!msg.to_lowercase().contains("wait for"));
        assert!(
            !msg.to_lowercase().contains("until then"),
            "placeholder 'Until then' wording must be gone: {msg}"
        );
    }

    // ─── TTY prompt fold logic ─────────────────────────────────
    //
    // The actual cliclack interaction can't be unit-tested without a
    // PTY. The fold function `fold_choices_into_resolution` is the
    // pure core — given a per-collision `CollisionChoice`, produce a
    // `CollisionResolution` identical in shape to what the flag-parsing
    // path would produce. These tests pin the pure-logic contract.

    fn col(cmd: &str, owner: &str) -> CommandCollision {
        CommandCollision {
            command: cmd.into(),
            current_owner: owner.into(),
            via_alias: false,
        }
    }

    #[test]
    fn fold_replace_choice_populates_replace_set() {
        let r =
            fold_choices_into_resolution(&[(col("serve", "x"), CollisionChoice::Replace)]).unwrap();
        assert_eq!(r.replace.len(), 1);
        assert!(r.replace.contains("serve"));
        assert!(r.alias.is_empty());
    }

    #[test]
    fn fold_alias_choice_populates_alias_map() {
        let r = fold_choices_into_resolution(&[(
            col("serve", "x"),
            CollisionChoice::Alias("foo-serve".into()),
        )])
        .unwrap();
        assert!(r.replace.is_empty());
        assert_eq!(r.alias.get("serve"), Some(&"foo-serve".to_string()));
    }

    #[test]
    fn fold_mixed_choices_populate_both_sides() {
        let r = fold_choices_into_resolution(&[
            (col("serve", "a"), CollisionChoice::Replace),
            (col("lint", "b"), CollisionChoice::Alias("foo-lint".into())),
        ])
        .unwrap();
        assert!(r.replace.contains("serve"));
        assert_eq!(r.alias.get("lint"), Some(&"foo-lint".to_string()));
    }

    #[test]
    fn fold_cancel_on_first_collision_aborts_entire_install() {
        let err = fold_choices_into_resolution(&[
            (col("serve", "x"), CollisionChoice::Cancel),
            (col("lint", "y"), CollisionChoice::Replace),
        ])
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("install cancelled"),
            "cancel must abort the install with a clear message: {msg}"
        );
        // Must name the specific command the user cancelled on.
        assert!(msg.contains("serve"));
    }

    #[test]
    fn fold_cancel_after_valid_choices_still_aborts_everything() {
        // Cancel on the SECOND collision (first was resolved) must still
        // abort — partial-resolution installs violate the invariant.
        let err = fold_choices_into_resolution(&[
            (col("serve", "x"), CollisionChoice::Replace),
            (col("lint", "y"), CollisionChoice::Cancel),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("install cancelled"));
        assert!(err.to_string().contains("lint"));
    }

    #[test]
    fn fold_empty_choices_yields_empty_resolution() {
        // Defensive: if no collisions were prompted (shouldn't happen
        // — caller only calls us when there IS a collision — but the
        // invariant should hold).
        let r = fold_choices_into_resolution(&[]).unwrap();
        assert!(r.is_empty());
    }
}
