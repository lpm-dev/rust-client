use std::collections::HashSet;
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};

use lpm_common::LpmError;
use lpm_store::v2::Store;

use super::V2Target;
use super::compat_island::{CompatibilityLinks, manifest_needs_bin_compatibility};
use super::keymap::KeyMap;
use super::reconcile::{ensure_real_dir, is_direct, remove_node_modules_entry};
use crate::validate_bin_name;
use crate::validation::validate_bin_target;

struct BinLinkSpec {
    cmd_name: String,
    target: PathBuf,
    needs_project_node_path: bool,
    #[cfg(unix)]
    unix_invocation: UnixBinInvocation,
}

#[cfg(unix)]
struct UnixShebangInvocation {
    interpreter: String,
    arg: Option<String>,
}

#[cfg(unix)]
enum UnixBinInvocation {
    Direct,
    Shebang(UnixShebangInvocation),
}

fn clear_bin_dir(project_dir: &Path) -> Result<(), LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    if bin_dir.symlink_metadata().is_err() {
        return Ok(());
    }
    remove_node_modules_entry(&bin_dir, "stale bin directory")
}

fn ensure_bin_dir(bin_dir: &Path) -> Result<(), LpmError> {
    match bin_dir.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            return Ok(());
        }
        Ok(_) => {
            remove_node_modules_entry(bin_dir, "stale bin directory")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(LpmError::Store(format!(
                "v2 linker: failed to inspect .bin directory at {}: {error}",
                bin_dir.display()
            )));
        }
    }

    std::fs::create_dir_all(bin_dir).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to create .bin/ at {}: {e}",
            bin_dir.display()
        ))
    })?;
    ensure_real_dir(bin_dir, "project .bin directory")
}

fn reconcile_bin_dir(bin_dir: &Path, desired: &HashSet<String>) -> Result<(), LpmError> {
    let entries = match std::fs::read_dir(bin_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(LpmError::Store(format!(
                "v2 linker: failed to read .bin directory at {}: {error}",
                bin_dir.display()
            )));
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !desired.contains(&name) {
            remove_node_modules_entry(&entry.path(), "stale bin shim")?;
        }
    }
    Ok(())
}

/// `.bin/` shim creation for the v2 layout. Walks each direct dep's
/// `package.json` from inside the link entry's package dir
/// (`<store>/links/<graph-key>/node_modules/<name>/package.json`)
/// and emits a project `.bin/<cmd>` shim pointing at the bin script in
/// the link entry. Unix uses symlinks for already-executable targets
/// and wrapper scripts for non-executable shebang targets.
///
/// Only DIRECT deps get bin shims (matches npm/v1 semantics). Bin
/// shims for transitive deps are unreachable from project scripts
/// without an explicit `npx`/`require.resolve` round-trip, and
/// hoisted-mode v1 only emits direct-dep shims either.
pub(super) fn create_bin_links_v2(
    project_dir: &Path,
    targets: &[V2Target],
    store: &Store,
    key_map: &KeyMap,
    compatibility_links: &CompatibilityLinks,
) -> Result<usize, LpmError> {
    let bin_dir = project_dir.join("node_modules").join(".bin");
    let project_node_modules = project_dir.join("node_modules");

    // Scratch `PathBuf`s reused across iterations: the per-iteration
    // paths build into reusable buffers rather than allocating fresh
    // each loop turn (~4×N PathBuf allocations saved for an install
    // with N direct deps × ~2 bin entries each).
    let mut pkg_json_path = PathBuf::with_capacity(256);
    let mut bin_target = PathBuf::with_capacity(256);
    let mut specs = Vec::with_capacity(targets.len());

    for v2t in targets {
        if !is_direct(&v2t.target) {
            continue;
        }
        let key = match key_map.get_for(&v2t.target) {
            Some(k) => k,
            None => continue,
        };
        let compatibility_pkg_dir = compatibility_links.package_dir_for_key(key);
        let pkg_dir = compatibility_pkg_dir
            .map_or_else(|| store.paths().link_package_dir(key), Path::to_path_buf);
        pkg_json_path.clear();
        pkg_json_path.push(&pkg_dir);
        pkg_json_path.push("package.json");

        // Read once; treat I/O failure as "no bin" (equivalent to the old
        // exists() check but saves one stat(2) syscall per direct dep).
        let content = match lpm_common::read_file_capped(
            &pkg_json_path,
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        ) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Fast byte pre-scan to skip serde_json parse entirely for
        // direct deps that declare no `bin`. The quoted key `"bin"`
        // reliably identifies the JSON field; any false positive (a
        // value containing the 5-byte sequence) is harmless — we just
        // parse and get back None.
        const BIN_KEY: &[u8] = b"\"bin\"";
        if !content.windows(BIN_KEY.len()).any(|w| w == BIN_KEY) {
            continue;
        }

        let bin_config = match lpm_workspace::parse_bin_field(&content) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                tracing::debug!(
                    "v2 linker: skipping bin links for {}: failed to parse package.json: {e}",
                    v2t.target.name
                );
                continue;
            }
        };
        let entries = bin_config.entries(&v2t.target.name);
        if entries.is_empty() {
            continue;
        }
        let needs_project_node_path =
            compatibility_pkg_dir.is_none() && manifest_needs_bin_compatibility(&content);

        for (cmd_name, bin_rel_path) in entries {
            // Reject bin entries whose key would write outside `.bin/`
            // or shadow path components — same bar as v1's hoisted
            // emitter (lib.rs). Warn-and-skip rather than fail-install
            // so one malformed entry doesn't abort the whole link.
            if let Err(reason) = validate_bin_name(&cmd_name, &v2t.target.name) {
                tracing::warn!(
                    "v2 linker: rejecting bin \"{cmd_name}\" from {}: {reason}",
                    v2t.target.name
                );
                continue;
            }

            // Use validate_bin_target as a *guard only* — the canonical
            // return value is discarded. Downstream `pathdiff::diff_paths`
            // expects bin_target and bin_dir in the same canonical
            // (or same non-canonical) form, and v2's bin_dir is built
            // from the raw project_dir. Mixing forms (canonical target,
            // raw bin_dir) produces malformed symlinks on macOS, where
            // `/var/folders/...` and `/private/var/folders/...` share no
            // prefix until both are canonicalised.
            //
            // The guard call still enforces:
            // - rejection of `..` components in script_path
            // - rejection of bin_rel_path whose canonical resolve
            //   escapes the package dir (e.g. via an in-package symlink
            //   pointing outside)
            // - rejection of missing files (canonicalize fails)
            if let Err(reason) = validate_bin_target(&pkg_dir, &bin_rel_path) {
                tracing::warn!(
                    "v2 linker: rejecting bin {cmd_name} from {}: {reason}",
                    v2t.target.name
                );
                continue;
            }
            bin_target.clear();
            bin_target.push(&pkg_dir);
            bin_target.push(&bin_rel_path);
            #[cfg(unix)]
            let unix_invocation = match unix_bin_invocation(&bin_target) {
                Ok(invocation) => invocation,
                Err(error) => {
                    tracing::warn!(
                        "v2 linker: skipping bin {cmd_name} from {}: {error}",
                        v2t.target.name
                    );
                    continue;
                }
            };
            specs.push(BinLinkSpec {
                cmd_name,
                target: bin_target.clone(),
                needs_project_node_path,
                #[cfg(unix)]
                unix_invocation,
            });
        }
    }

    if specs.is_empty() {
        clear_bin_dir(project_dir)?;
        return Ok(0);
    }

    ensure_bin_dir(&bin_dir)?;
    let desired: HashSet<String> = specs
        .iter()
        .map(|spec| {
            #[cfg(unix)]
            {
                spec.cmd_name.clone()
            }
            #[cfg(windows)]
            {
                format!("{}.cmd", spec.cmd_name)
            }
        })
        .collect();
    reconcile_bin_dir(&bin_dir, &desired)?;

    let mut link_path = PathBuf::with_capacity(bin_dir.as_os_str().len() + 64);
    let mut count = 0usize;
    for spec in specs {
        link_path.clear();
        link_path.push(&bin_dir);
        link_path.push(&spec.cmd_name);

        #[cfg(unix)]
        {
            if spec.needs_project_node_path
                || !matches!(spec.unix_invocation, UnixBinInvocation::Direct)
            {
                let project_node_modules = spec
                    .needs_project_node_path
                    .then_some(project_node_modules.as_path());
                write_unix_bin_wrapper(
                    &link_path,
                    &spec.target,
                    project_node_modules,
                    &spec.unix_invocation,
                )?;
            } else {
                let relative = pathdiff::diff_paths(&spec.target, &bin_dir)
                    .unwrap_or_else(|| spec.target.clone());
                if std::fs::read_link(&link_path).is_ok_and(|existing| existing == relative) {
                    count += 1;
                    continue;
                }
                if link_path.symlink_metadata().is_ok() {
                    remove_node_modules_entry(&link_path, "stale bin shim")?;
                }
                std::os::unix::fs::symlink(&relative, &link_path).map_err(|e| {
                    LpmError::Store(format!(
                        "v2 linker: failed to create bin shim {} → {}: {e}",
                        link_path.display(),
                        relative.display()
                    ))
                })?;
            }
        }

        #[cfg(windows)]
        {
            // Windows: emit a `.cmd` shim that invokes node.exe
            // on the script. Mirrors v1's hoisted/.bin emission.
            // (Junction-style symlinks to script files don't run
            // under cmd.exe; `.cmd` shim is the cross-version
            // path that works on every Windows lpm has shipped
            // on.)
            let target_str = spec.target.to_string_lossy();
            if let Err(reason) = lpm_common::symlink::validate_cmd_path(&target_str) {
                tracing::warn!(
                    "v2 linker: skipping .cmd shim for {}: {reason}",
                    spec.cmd_name
                );
                continue;
            }
            let node_path_prefix = if spec.needs_project_node_path {
                let node_path_str = project_node_modules.to_string_lossy();
                if let Err(reason) = lpm_common::symlink::validate_cmd_path(&node_path_str) {
                    tracing::warn!(
                        "v2 linker: skipping .cmd shim for {}: {reason}",
                        spec.cmd_name
                    );
                    continue;
                }
                format!("@SET \"NODE_PATH={node_path_str};%NODE_PATH%\"\n")
            } else {
                String::new()
            };
            let cmd_content = format!(
                "{node_path_prefix}@IF EXIST \"%~dp0\\node.exe\" (\n  \"%~dp0\\node.exe\" \"{target_str}\" %*\n) ELSE (\n  node \"{target_str}\" %*\n)",
            );
            let cmd_path = bin_dir.join(format!("{}.cmd", spec.cmd_name));
            if lpm_common::read_file_capped(&cmd_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
                .is_ok_and(|existing| existing == cmd_content.as_bytes())
            {
                count += 1;
                continue;
            }
            if cmd_path.symlink_metadata().is_ok() {
                remove_node_modules_entry(&cmd_path, "stale .cmd shim")?;
            }
            std::fs::write(&cmd_path, cmd_content).map_err(|e| {
                LpmError::Store(format!(
                    "v2 linker: failed to write .cmd shim at {}: {e}",
                    cmd_path.display()
                ))
            })?;
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(unix)]
fn unix_bin_invocation(target: &Path) -> Result<UnixBinInvocation, LpmError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(target).map_err(|e| {
        LpmError::Store(format!(
            "failed to inspect bin target at {}: {e}",
            target.display()
        ))
    })?;
    if metadata.permissions().mode() & 0o111 != 0 {
        return Ok(UnixBinInvocation::Direct);
    }
    Ok(UnixBinInvocation::Shebang(read_unix_shebang(target)?))
}

#[cfg(unix)]
fn read_unix_shebang(target: &Path) -> Result<UnixShebangInvocation, LpmError> {
    let mut file = std::fs::File::open(target).map_err(|e| {
        LpmError::Store(format!(
            "failed to open non-executable bin target at {} for shebang inspection: {e}",
            target.display()
        ))
    })?;
    let mut buf = [0_u8; 512];
    let read = file.read(&mut buf).map_err(|e| {
        LpmError::Store(format!(
            "failed to read non-executable bin target at {} for shebang inspection: {e}",
            target.display()
        ))
    })?;
    let bytes = &buf[..read];
    if !bytes.starts_with(b"#!") {
        return Err(LpmError::Store(format!(
            "bin target {} is not executable and has no shebang",
            target.display()
        )));
    }
    let line_end = bytes.iter().position(|byte| *byte == b'\n').unwrap_or(read);
    let shebang = std::str::from_utf8(&bytes[2..line_end])
        .map_err(|e| {
            LpmError::Store(format!(
                "bin target {} has a non-UTF-8 shebang: {e}",
                target.display()
            ))
        })?
        .trim_end_matches('\r')
        .trim();
    let mut parts = shebang.splitn(2, char::is_whitespace);
    let interpreter = parts.next().ok_or_else(|| {
        LpmError::Store(format!(
            "bin target {} has an empty shebang",
            target.display()
        ))
    })?;
    let arg = parts
        .next()
        .map(str::trim)
        .filter(|arg| !arg.is_empty())
        .map(str::to_string);
    Ok(UnixShebangInvocation {
        interpreter: interpreter.to_string(),
        arg,
    })
}

#[cfg(unix)]
fn write_unix_bin_wrapper(
    link_path: &Path,
    target: &Path,
    project_node_modules: Option<&Path>,
    invocation: &UnixBinInvocation,
) -> Result<(), LpmError> {
    let content = unix_bin_wrapper_content(target, project_node_modules, invocation);
    let metadata = match link_path.symlink_metadata() {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(LpmError::Store(format!(
                "v2 linker: failed to inspect bin shim at {}: {error}",
                link_path.display()
            )));
        }
    };
    if metadata.as_ref().is_some_and(|metadata| {
        metadata.file_type().is_file() && !metadata.file_type().is_symlink()
    }) && lpm_common::read_file_capped(link_path, lpm_common::STATE_FILE_SIZE_CAP_BYTES)
        .is_ok_and(|existing| existing == content.as_bytes())
    {
        return set_unix_bin_shim_executable(link_path);
    }
    if metadata.is_some() {
        remove_node_modules_entry(link_path, "stale bin shim")?;
    }
    std::fs::write(link_path, content).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to write bin shim at {}: {e}",
            link_path.display()
        ))
    })?;
    set_unix_bin_shim_executable(link_path)
}

#[cfg(unix)]
fn set_unix_bin_shim_executable(link_path: &Path) -> Result<(), LpmError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(link_path)
        .map_err(|e| {
            LpmError::Store(format!(
                "v2 linker: failed to inspect bin shim at {}: {e}",
                link_path.display()
            ))
        })?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(link_path, permissions).map_err(|e| {
        LpmError::Store(format!(
            "v2 linker: failed to mark bin shim executable at {}: {e}",
            link_path.display()
        ))
    })
}

#[cfg(unix)]
fn unix_bin_wrapper_content(
    target: &Path,
    project_node_modules: Option<&Path>,
    invocation: &UnixBinInvocation,
) -> String {
    let mut content = String::with_capacity(target.as_os_str().len() + 96);
    content.push_str("#!/bin/sh\n");
    if let Some(project_node_modules) = project_node_modules {
        content.push_str("NODE_PATH=");
        content.push_str(&shell_quote_path(project_node_modules));
        content.push_str("${NODE_PATH:+:$NODE_PATH}\nexport NODE_PATH\n");
    }
    content.push_str("exec ");
    match invocation {
        UnixBinInvocation::Direct => content.push_str(&shell_quote_path(target)),
        UnixBinInvocation::Shebang(shebang) => {
            content.push_str(&shell_quote(&shebang.interpreter));
            if let Some(arg) = &shebang.arg {
                content.push(' ');
                content.push_str(&shell_quote(arg));
            }
            content.push(' ');
            content.push_str(&shell_quote_path(target));
        }
    }
    content.push_str(" \"$@\"\n");
    content
}

#[cfg(unix)]
fn shell_quote_path(path: &Path) -> String {
    shell_quote(path.to_string_lossy().as_ref())
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}
