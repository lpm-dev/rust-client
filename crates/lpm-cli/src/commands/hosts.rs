use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use std::io::IsTerminal;
use std::path::Path;

pub fn run(action: &str, json_output: bool, yes: bool) -> Result<(), LpmError> {
    match action {
        "clean" => run_clean(json_output, yes),
        _ => Err(LpmError::Script(format!(
            "unknown hosts action '{action}'. Available: clean"
        ))),
    }
}

pub fn run_internal_hosts_file(
    action: &str,
    block_id: Option<&str>,
    hosts: &[String],
) -> Result<(), LpmError> {
    crate::privilege::require_effective_root("hosts-file")?;
    let path = lpm_runner::local_domains::system_hosts_file_path();
    match action {
        "upsert" => {
            let block_id = validated_block_id(block_id)?;
            validate_hosts(hosts)?;
            let plan = lpm_runner::local_domains::HostsFilePlan {
                path,
                backup_path: std::path::PathBuf::new(),
                block_id: block_id.to_string(),
                hosts: hosts.to_vec(),
            };
            lpm_runner::local_domains::apply_hosts_file_plan_without_backup(&plan)
                .map_err(LpmError::Script)?;
        }
        "remove" => {
            let block_id = validated_block_id(block_id)?;
            lpm_runner::local_domains::remove_hosts_file_block_without_backup(&path, block_id)
                .map_err(LpmError::Script)?;
        }
        "clean" => {
            lpm_runner::local_domains::clean_hosts_file_without_backup(&path)
                .map_err(LpmError::Script)?;
        }
        _ => {
            return Err(LpmError::Script(format!(
                "unknown internal hosts-file action '{action}'"
            )));
        }
    }
    Ok(())
}

pub fn apply_hosts_file_plan_with_permission(
    plan: &lpm_runner::local_domains::HostsFilePlan,
) -> Result<lpm_runner::local_domains::ManagedHostsFile, String> {
    match lpm_runner::local_domains::apply_hosts_file_plan(plan) {
        Ok(lease) => Ok(lease),
        Err(_) if should_try_privileged_hosts_helper(&plan.path) => {
            lpm_runner::local_domains::ensure_hosts_file_backup(&plan.path, &plan.backup_path)?;
            run_privileged_hosts_helper("upsert", Some(&plan.block_id), &plan.hosts)?;
            Ok(lpm_runner::local_domains::ManagedHostsFile::from_plan(
                plan, true,
            ))
        }
        Err(err) => Err(err),
    }
}

pub fn release_hosts_file_with_permission(
    hosts_file: lpm_runner::local_domains::ManagedHostsFile,
) -> Result<(), String> {
    let elevated_release = hosts_file.clone();
    match hosts_file.release() {
        Ok(_) => Ok(()),
        Err(_) if should_try_privileged_hosts_helper(elevated_release.path()) => {
            run_privileged_hosts_helper("remove", Some(elevated_release.block_id()), &[])
        }
        Err(err) => Err(err),
    }
}

fn run_clean(json_output: bool, yes: bool) -> Result<(), LpmError> {
    let plan = lpm_runner::local_domains::plan_hosts_file_clean().map_err(|err| {
        LpmError::Script(format!("local hosts file cleanup planning failed: {err}"))
    })?;
    if plan.block_count == 0 {
        if json_output {
            print_clean_json(&plan.path, &plan.backup_path, 0, false);
        } else {
            install_ui::done("hosts file has no LPM-managed entries");
        }
        return Ok(());
    }

    confirm_hosts_file_clean(&plan, yes)?;
    let outcome = apply_hosts_file_clean_plan_with_permission(&plan).map_err(|err| {
        LpmError::Script(format!(
            "local hosts file cleanup failed for {}: {err}. Run `lpm hosts clean` with permission to edit the hosts file (sudo on Unix, Administrator on Windows).",
            plan.path.display()
        ))
    })?;

    if json_output {
        print_clean_json(
            &outcome.path,
            &outcome.backup_path,
            outcome.removed_blocks,
            outcome.changed,
        );
    } else if outcome.changed {
        install_ui::done_untrusted(&format!(
            "removed {} LPM-managed hosts file {}",
            outcome.removed_blocks,
            if outcome.removed_blocks == 1 {
                "block"
            } else {
                "blocks"
            }
        ));
    } else {
        install_ui::done("hosts file has no LPM-managed entries");
    }
    Ok(())
}

fn apply_hosts_file_clean_plan_with_permission(
    plan: &lpm_runner::local_domains::HostsFileCleanPlan,
) -> Result<lpm_runner::local_domains::HostsFileCleanOutcome, String> {
    match lpm_runner::local_domains::apply_hosts_file_clean_plan(plan) {
        Ok(outcome) => Ok(outcome),
        Err(_) if should_try_privileged_hosts_helper(&plan.path) => {
            lpm_runner::local_domains::ensure_hosts_file_backup(&plan.path, &plan.backup_path)?;
            run_privileged_hosts_helper("clean", None, &[])?;
            Ok(lpm_runner::local_domains::HostsFileCleanOutcome {
                path: plan.path.clone(),
                backup_path: plan.backup_path.clone(),
                removed_blocks: plan.block_count,
                changed: plan.block_count > 0,
            })
        }
        Err(err) => Err(err),
    }
}

fn should_try_privileged_hosts_helper(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::env::var_os("LPM_HOSTS_FILE").is_none()
            && path == lpm_runner::local_domains::system_hosts_file_path()
            && std::io::stdin().is_terminal()
    }
    #[cfg(windows)]
    {
        std::env::var_os("LPM_HOSTS_FILE").is_none()
            && path == lpm_runner::local_domains::system_hosts_file_path()
            && std::io::stdin().is_terminal()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

fn run_privileged_hosts_helper(
    action: &str,
    block_id: Option<&str>,
    hosts: &[String],
) -> Result<(), String> {
    let args = internal_hosts_file_args(action, block_id, hosts);
    crate::elevation::run_current_exe_helper(
        &args,
        "Password for LPM hosts-file update: ",
        "hosts-file",
    )
    .map_err(|error| error.to_string())
}

fn internal_hosts_file_args(action: &str, block_id: Option<&str>, hosts: &[String]) -> Vec<String> {
    let mut args = Vec::with_capacity(2 + usize::from(block_id.is_some()) * 2 + hosts.len() * 2);
    args.push("internal-hosts-file".to_string());
    args.push(action.to_string());
    if let Some(block_id) = block_id {
        args.push("--block-id".to_string());
        args.push(block_id.to_string());
    }
    for host in hosts {
        args.push("--host".to_string());
        args.push(host.clone());
    }
    args
}

fn validated_block_id(block_id: Option<&str>) -> Result<&str, LpmError> {
    let Some(block_id) = block_id else {
        return Err(LpmError::Script(
            "internal hosts-file helper requires --block-id".into(),
        ));
    };
    if block_id.is_empty()
        || !block_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LpmError::Script(
            "internal hosts-file helper received an invalid block id".into(),
        ));
    }
    Ok(block_id)
}

fn validate_hosts(hosts: &[String]) -> Result<(), LpmError> {
    if hosts.is_empty() {
        return Err(LpmError::Script(
            "internal hosts-file helper requires at least one --host".into(),
        ));
    }
    for host in hosts {
        let normalized = host.to_ascii_lowercase();
        if host.is_empty()
            || host
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '#')
            || !normalized.contains('.')
            || normalized.contains('*')
            || normalized.starts_with('.')
            || normalized.ends_with('.')
            || normalized.starts_with('-')
            || normalized.ends_with('-')
            || normalized.contains("..")
            || !normalized
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(LpmError::Script(
                "internal hosts-file helper received an invalid host".into(),
            ));
        }
    }
    Ok(())
}

fn confirm_hosts_file_clean(
    plan: &lpm_runner::local_domains::HostsFileCleanPlan,
    yes: bool,
) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(format!(
            "non-interactive shell: pass `--yes` to consent to removing {} LPM-managed hosts file {} from {}",
            plan.block_count,
            if plan.block_count == 1 {
                "block"
            } else {
                "blocks"
            },
            plan.path.display()
        )));
    }

    println!();
    println!(
        "  {}",
        "LPM will remove its managed entries from your hosts file.".bold()
    );
    println!();
    print_field("Hosts file:", plan.path.display().to_string());
    print_field("Backup:", plan.backup_path.display().to_string());
    print_field("Blocks:", plan.block_count.to_string());
    println!();
    let answer = cliclack::confirm("Clean LPM hosts entries now?")
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if !answer {
        return Err(LpmError::Script(
            "hosts file cleanup declined; no entries were removed.".into(),
        ));
    }
    Ok(())
}

fn print_field<T: install_ui::TerminalValue>(label: &'static str, value: T) {
    println!(
        "{}",
        crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{label:<12}")),
            value
        )
    );
}

fn print_clean_json(
    path: &std::path::Path,
    backup_path: &std::path::Path,
    removed_blocks: usize,
    changed: bool,
) {
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "cleaned": changed,
            "removedBlocks": removed_blocks,
            "hostsFile": path,
            "backupPath": backup_path,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_hosts_file_helper_rejects_block_id_with_line_syntax() {
        let err = validated_block_id(Some("project-a\n127.0.0.1 bad")).unwrap_err();

        assert!(err.to_string().contains("invalid block id"), "got {err}");
    }

    #[test]
    fn internal_hosts_file_helper_rejects_host_with_whitespace() {
        let err = validate_hosts(&["bad host.test".to_string()]).unwrap_err();

        assert!(err.to_string().contains("invalid host"), "got {err}");
    }

    #[test]
    fn internal_hosts_file_helper_rejects_host_with_path_separator() {
        let err = validate_hosts(&["bad/host.test".to_string()]).unwrap_err();

        assert!(err.to_string().contains("invalid host"), "got {err}");
    }

    #[test]
    fn privileged_hosts_helper_args_preserve_reexec_contract() {
        let args = internal_hosts_file_args(
            "upsert",
            Some("project.local"),
            &["app.localhost".to_string(), "api.localhost".to_string()],
        );

        assert_eq!(
            args,
            vec![
                "internal-hosts-file",
                "upsert",
                "--block-id",
                "project.local",
                "--host",
                "app.localhost",
                "--host",
                "api.localhost",
            ]
        );
    }
}
