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
    remove_legacy_gitignore_entries(project_dir, json_output);
}

/// The comment and entry pairs `lpm install` and `lpm add` appended to the
/// project's `.gitignore` before `.lpm` kept itself out of git
/// ([`lpm_common::project_state`]), as they wrote them: with the comment
/// they used when appending, or the shorter one when they created the file.
const LEGACY_GITIGNORE_BLOCKS: [(&[u8], &[u8]); 6] = [
    (b"# LPM wrapper tree (auto-generated)", b".lpm/wrappers/"),
    (b"# LPM wrapper tree", b".lpm/wrappers/"),
    (b"# LPM hoisted state (auto-generated)", b".lpm/hoisted/"),
    (b"# LPM hoisted state", b".lpm/hoisted/"),
    (b"# LPM Agent Skills (auto-generated)", b".lpm/skills/"),
    (b"# LPM Agent Skills", b".lpm/skills/"),
];

/// Removes the blocks in [`LEGACY_GITIGNORE_BLOCKS`] from the project's
/// `.gitignore`, with the blank line an append put before each, and the
/// file itself when nothing else is left in it. Anything else in the file,
/// including the same entries written another way, stays. A `.gitignore`
/// that is a link or not a regular file is left alone.
pub(super) fn remove_legacy_gitignore_entries(project_dir: &Path, json_output: bool) {
    let path = project_dir.join(".gitignore");
    match lpm_common::project_secret::rewrite_ignore_file(&path, without_legacy_gitignore_blocks) {
        Ok(lpm_common::project_secret::IgnoreRewrite::Unchanged) => {}
        Ok(_) if !json_output => output::info_line(crate::install_ui::terminal_line!(
            "removed LPM's old entries from {} — .lpm/ now keeps itself out of git",
            install_ui::dim(&path.display().to_string()),
        )),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            path = %path.display(),
            %error,
            "failed to remove LPM's old .gitignore entries"
        ),
    }
}

/// The `.gitignore` bytes without [`LEGACY_GITIGNORE_BLOCKS`], or `None`
/// when it holds none of them.
pub(super) fn without_legacy_gitignore_blocks(content: &[u8]) -> Option<Vec<u8>> {
    let lines: Vec<&[u8]> = content.split_inclusive(|byte| *byte == b'\n').collect();
    let text = |line: &[u8]| -> Vec<u8> {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        line.strip_suffix(b"\r").unwrap_or(line).to_vec()
    };
    let mut kept: Vec<&[u8]> = Vec::with_capacity(lines.len());
    let mut removed = false;
    let mut index = 0;
    while index < lines.len() {
        let comment = text(lines[index]);
        let entry = lines.get(index + 1).map(|line| text(line));
        let is_block = LEGACY_GITIGNORE_BLOCKS
            .iter()
            .any(|(block_comment, block_entry)| {
                comment == *block_comment && entry.as_deref() == Some(*block_entry)
            });
        if is_block {
            if kept.last().is_some_and(|line| text(line).is_empty()) {
                kept.pop();
            }
            removed = true;
            index += 2;
        } else {
            kept.push(lines[index]);
            index += 1;
        }
    }
    removed.then(|| kept.concat())
}

//: `read_auto_build_config` was removed as part of
// consolidating script-config reads into
// `crate::script_policy_config::ScriptPolicyConfig`. Callers now
// access `.auto_build` on the loader's return value. Equivalent test
// coverage lives in `script_policy_config::tests`.
