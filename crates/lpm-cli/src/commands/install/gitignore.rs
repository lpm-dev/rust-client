use super::*;

/// Wipe whichever legacy linker-state subtree the project still has under
/// `node_modules/`.
///
/// Two legacy layouts exist:
///
/// - Pre-61.1 isolated wrapper root at `node_modules/.lpm/<seg>/`
///   (moved this to `<project>/.lpm/wrappers/`).
/// - Pre-symmetry hoisted state at `node_modules/.lpm-metadata.json`
///   plus `node_modules/.lpm/nested/` (hoisted-symmetry follow-up
///   moves these to `<project>/.lpm/hoisted/metadata.json` and
///   `<project>/.lpm/hoisted/nested/` respectively).
///
/// The freshness gate in [`crate::install_state::check_install_state`]
/// (and its mtime fast path in [`crate::install_state::try_mtime_fast_path`])
/// already forced the install pipeline to run when
/// [`lpm_linker::LayoutPaths::needs_layout_migration`] reports `true`
/// (which unions the per-mode predicates); this helper is the
/// corresponding wipe-and-rebuild side. Re-running the install at the
/// new locations rematerializes every package from the global store
/// — bounded by exactly one slow warm install per project (a
/// one-time cost the user incurs the first time they install on the
/// new binary).
///
/// **No rename-first attempt.** Cross-FS rename hazards (Linux
/// containers, network FS, EXDEV) outweigh the saved relink cost.
///
/// ** — migration notice modes.** Human-pretty mode prints one
/// line on stderr per legacy layout that needed migrating; JSON /
/// `--quiet` / non-TTY remain silent. Successful installs do not
/// start writing to stderr by default.
///
/// Idempotent: calling on a project without populated legacy state
/// is a no-op.
pub(super) fn migrate_legacy_wrapper_layout(project_dir: &Path, json_output: bool) {
    let layout = lpm_linker::LayoutPaths::for_project(project_dir);

    // Single union gate, mirroring the freshness check upstream.
    // When false (no legacy state, OR both legacy AND new state
    // populated mid-migration), this helper is a no-op so a normal
    // `lpm install` re-run can converge mid-migration projects
    // without an aggressive wipe.
    if !layout.needs_layout_migration() {
        return;
    }

    // Per-subtree probe and notice so a project that's only on one
    // of the two legacy layouts doesn't see the other layout's
    // message.
    //
    // The isolated branch gates on
    // `legacy_isolated_root_has_wrapper_segments()` (NOT on
    // `legacy_root.exists()`), because a hoisted-only legacy project
    // with transitive conflicts leaves a `node_modules/.lpm/nested/`
    // dir behind which makes the parent `.lpm/` exist. That's hoisted
    // state, not isolated, and gets cleaned up by the hoisted branch
    // of this helper. Without the wrapper-segment gate, the user
    // would see a spurious "migrating wrapper layout" notice for a
    // hoisted-only project. The corresponding wipe of the otherwise
    // empty `.lpm/` parent is left to the hoisted branch's
    // `remove_dir_all` of `hoisted_legacy_nested_root()`, which
    // collapses the empty parent on most platforms.

    let legacy_isolated_root = layout.isolated_legacy_wrapper_root();
    if layout.legacy_isolated_root_has_wrapper_segments() {
        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "migrating wrapper layout: {} → {}",
                install_ui::dim(&legacy_isolated_root.display().to_string()),
                install_ui::dim(&layout.isolated_wrapper_root().display().to_string()),
            ));
        }
        // Best-effort wipe — a permission error or partial wipe shows
        // up as a noisier-than-usual install (the new linker
        // materializes wrappers at the new location regardless of
        // what's in the legacy tree), but we don't want to abort the
        // install on legacy-state quirks.
        let _ = std::fs::remove_dir_all(&legacy_isolated_root);
    }

    let legacy_hoisted_metadata = layout.hoisted_legacy_metadata_path();
    if legacy_hoisted_metadata.exists() {
        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "migrating hoisted layout: {} → {}",
                install_ui::dim(&legacy_hoisted_metadata.display().to_string()),
                install_ui::dim(&layout.hoisted_metadata_path().display().to_string()),
            ));
        }
        // Wipe the metadata sidecar AND the nested fallback root.
        // The nested root is only populated when at least one
        // transitive conflict landed under a non-hoisted parent —
        // most projects don't have it, in which case the
        // `remove_dir_all` is a cheap no-op.
        let _ = std::fs::remove_file(&legacy_hoisted_metadata);
        let _ = std::fs::remove_dir_all(layout.hoisted_legacy_nested_root());
    }
}

pub(super) fn maintain_project_linker_layout(project_dir: &Path, json_output: bool) {
    migrate_legacy_wrapper_layout(project_dir, json_output);
    ensure_lpm_wrappers_gitignore(project_dir);
    ensure_lpm_hoisted_gitignore(project_dir);
}

/// — ensure `.gitignore` contains an entry for
/// `.lpm/wrappers/`.
///
/// Mirrors [`ensure_skills_gitignore`] (and its siblings in
/// `lpm-vault::ensure_lpm_dir_gitignore` and
/// `commands::npmrc::ensure_lpm_dir_gitignore`) — runtime "ensure
/// once" pattern, idempotent, OpenOptions-append to minimize the
/// read-then-write TOCTOU window.
///
/// Why runtime instead of template emission: existing projects also
/// need the entry, and the repo has a precedent for runtime
/// `.gitignore` maintenance for sibling `.lpm/*` paths. Template-only
/// would silently miss every project that already has a `.gitignore`
/// at install time.
pub fn ensure_lpm_wrappers_gitignore(project_dir: &Path) {
    let gitignore_path = project_dir.join(".gitignore");
    let marker = ".lpm/wrappers/";

    if let Some(content) = read_gitignore(&gitignore_path) {
        if content.lines().any(|l| l.trim() == marker) {
            return; // Already present
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitignore_path)
        {
            if !content.ends_with('\n') {
                let _ = writeln!(file);
            }
            let _ = writeln!(file);
            let _ = writeln!(file, "# LPM wrapper tree (auto-generated)");
            let _ = writeln!(file, "{marker}");
        }
    } else {
        let _ = std::fs::write(&gitignore_path, format!("# LPM wrapper tree\n{marker}\n"));
    }
}

/// Hoisted-symmetry follow-up — ensure `.gitignore` contains an entry
/// for `.lpm/hoisted/`.
///
/// Mirrors [`ensure_lpm_wrappers_gitignore`] structurally (idempotent
/// append, OpenOptions append-mode) but writes a separate marker so
/// each linker mode owns its own `.gitignore` entry. This matters for
/// projects that opted into hoisted-mode AFTER an isolated install
/// landed the `.lpm/wrappers/` marker — without this helper, hoisted
/// state would silently land in commits even though wrapper state
/// was correctly ignored.
pub fn ensure_lpm_hoisted_gitignore(project_dir: &Path) {
    let gitignore_path = project_dir.join(".gitignore");
    let marker = ".lpm/hoisted/";

    if let Some(content) = read_gitignore(&gitignore_path) {
        if content.lines().any(|l| l.trim() == marker) {
            return; // Already present
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitignore_path)
        {
            if !content.ends_with('\n') {
                let _ = writeln!(file);
            }
            let _ = writeln!(file);
            let _ = writeln!(file, "# LPM hoisted state (auto-generated)");
            let _ = writeln!(file, "{marker}");
        }
    } else {
        let _ = std::fs::write(&gitignore_path, format!("# LPM hoisted state\n{marker}\n"));
    }
}

/// Ensure `.gitignore` contains an entry for `.lpm/skills/`.
pub fn ensure_skills_gitignore(project_dir: &Path) {
    let gitignore_path = project_dir.join(".gitignore");
    let marker = ".lpm/skills/";

    if let Some(content) = read_gitignore(&gitignore_path) {
        if content.lines().any(|l| l.trim() == marker) {
            return; // Already present
        }
        // Append using OpenOptions to reduce TOCTOU window vs read-then-write
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitignore_path)
        {
            if !content.ends_with('\n') {
                let _ = writeln!(file);
            }
            let _ = writeln!(file);
            let _ = writeln!(file, "# LPM Agent Skills (auto-generated)");
            let _ = writeln!(file, "{marker}");
        }
    } else {
        let _ = std::fs::write(&gitignore_path, format!("# LPM Agent Skills\n{marker}\n"));
    }
}

fn read_gitignore(path: &Path) -> Option<String> {
    match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
        Ok(content) => Some(content),
        Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to inspect .gitignore");
            Some(String::new())
        }
    }
}

//: `read_auto_build_config` was removed as part of
// consolidating script-config reads into
// `crate::script_policy_config::ScriptPolicyConfig`. Callers now
// access `.auto_build` on the loader's return value. Equivalent test
// coverage lives in `script_policy_config::tests`.
