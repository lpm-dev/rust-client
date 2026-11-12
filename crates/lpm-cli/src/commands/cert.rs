use crate::install_ui;
use lpm_common::LpmError;
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct ExtraArgs {
    pub extra_projects: Vec<PathBuf>,
    pub keep_old_trusted_days: Option<u32>,
    pub fail_on_missing: bool,
    pub dry_run: bool,
}

/// Run the `lpm cert` subcommand.
pub async fn run(
    action: &str,
    project_dir: &Path,
    extra_hosts: &[String],
    json_output: bool,
    extras: ExtraArgs,
) -> Result<(), LpmError> {
    for (present, flag, required_action) in [
        (!extra_hosts.is_empty(), "--host", "generate"),
        (!extras.extra_projects.is_empty(), "--project", "rotate"),
        (
            extras.keep_old_trusted_days.is_some(),
            "--keep-old-trusted",
            "rotate",
        ),
        (extras.fail_on_missing, "--fail-on-missing", "rotate"),
        (extras.dry_run, "--dry-run", "reconcile"),
    ] {
        if present && action != required_action {
            return Err(LpmError::Cert(format!(
                "{flag} is only valid for `lpm cert {required_action}`"
            )));
        }
    }
    match action {
        "status" => run_status(project_dir, json_output),
        "trust" => run_trust(json_output),
        "uninstall" => run_uninstall(json_output),
        "generate" => run_generate(project_dir, extra_hosts, json_output),
        "rotate" => run_rotate(extras, json_output).await,
        "reconcile" => run_reconcile(extras, json_output).await,
        _ => Err(LpmError::Cert(format!(
            "unknown action '{action}'. Available: status, trust, uninstall, generate, rotate, reconcile"
        ))),
    }
}

fn run_status(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let status = lpm_cert::status(project_dir)?;
    let ca_cert_path = lpm_cert::paths::ca_cert_path()?;
    let days_remaining = if ca_cert_path.exists() {
        lpm_cert::ca_days_until_expiry(&ca_cert_path)
    } else {
        None
    };
    let drifts = lpm_cert::audit_cert_permissions().unwrap_or_default();

    if json_output {
        let drift_json: Vec<_> = drifts
            .iter()
            .map(|d| {
                serde_json::json!({
                    "path": d.path.to_string_lossy(),
                    "role": d.role,
                    "actual_mode": format!("{:o}", d.actual_mode),
                    "expected_mode": format!("{:o}", d.expected_mode),
                    "fix": d.chmod_hint(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "ca": {
                    "exists": status.ca_exists,
                    "trusted": status.ca_trusted,
                    "expires": status.ca_expires,
                    "subject": status.ca_subject,
                    "days_until_expiry": days_remaining,
                },
                "project": {
                    "exists": status.project_cert_exists,
                    "expires": status.project_cert_expires,
                    "hostnames": status.project_cert_hostnames,
                    "needs_renewal": status.project_cert_needs_renewal,
                    "valid": status.project_cert_valid,
                    "error": status.project_cert_error,
                },
                "permission_drifts": drift_json,
            })
        );
        return Ok(());
    }

    println!("{}", install_ui::section("Root CA"));
    if status.ca_exists {
        let trust_status = if status.ca_trusted {
            install_ui::status_ok("trusted")
        } else {
            install_ui::red("not trusted")
        };
        print_field("status", &trust_status);

        if let Some(subject) = &status.ca_subject {
            print_field("subject", subject);
        }
        if let Some(expires) = &status.ca_expires {
            print_field("expires", expires);
        }
        if let Some(days) = days_remaining {
            let txt = format!("{days} days");
            let colored = if days < 30 {
                install_ui::red(&txt)
            } else if days < 60 {
                install_ui::section(&txt)
            } else {
                install_ui::status_ok(&txt)
            };
            print_field("remaining", &colored);
            if days < 60 {
                println!(
                    "  {}",
                    install_ui::dim("Run `lpm cert rotate` to roll the CA before it expires.")
                );
            }
        }
    } else {
        print_field("status", install_ui::red("not installed"));
        println!(
            "  {}",
            install_ui::dim("Run `lpm cert trust` to generate and install the CA")
        );
    }

    if !drifts.is_empty() {
        println!();
        println!("{}", install_ui::section("Permission drift"));
        for d in &drifts {
            print_field(d.role, install_ui::red(&d.summary()));
            println!("  {}", install_ui::dim(&format!("fix: {}", d.chmod_hint())));
        }
    }

    println!();
    println!("{}", install_ui::section("Project cert"));
    if status.project_cert_exists {
        if status.project_cert_needs_renewal {
            print_field("status", install_ui::section("needs renewal"));
        } else if !status.project_cert_valid {
            print_field("status", install_ui::red("invalid"));
        } else {
            print_field("status", install_ui::status_ok("valid"));
        }
        if let Some(error) = &status.project_cert_error {
            print_field("error", error);
            println!(
                "  {}",
                install_ui::dim("Run `lpm cert generate` to repair the project certificate.")
            );
        }
        if !status.project_cert_hostnames.is_empty() {
            print_field("hosts", status.project_cert_hostnames.join(", "));
        }
        if let Some(expires) = &status.project_cert_expires {
            print_field("expires", expires);
        }
    } else {
        print_field("status", install_ui::dim("not generated"));
        println!(
            "  {}",
            install_ui::dim("Run `lpm dev --https` or `lpm cert generate` to create")
        );
    }

    println!();
    if status.ca_exists
        && status.ca_trusted
        && status.project_cert_valid
        && !status.project_cert_needs_renewal
    {
        install_ui::done("HTTPS certificates are ready");
    } else {
        install_ui::warn("HTTPS certificates need setup");
    }

    Ok(())
}

fn run_trust(json_output: bool) -> Result<(), LpmError> {
    let result = lpm_cert::trust_ca()?;
    if result.generated && !json_output {
        install_ui::done("root CA generated");
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "ca_installed": true })
        );
    } else {
        install_ui::done("CA installed to system trust store");
        let info = lpm_cert::cert::read_cert_info(&result.cert_path)?;
        print_field("subject", &info.subject);
        print_field("expires", &info.not_after);
        print_field("path", result.cert_path.to_string_lossy());
    }

    Ok(())
}

fn run_uninstall(json_output: bool) -> Result<(), LpmError> {
    let _result = lpm_cert::uninstall_active_ca()?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "ca_uninstalled": true })
        );
    } else {
        install_ui::done("CA removed from system trust store");
    }

    Ok(())
}

/// What the elevated certificate-trust helper does to the Windows Root
/// store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum CertStoreAction {
    Add,
    Remove,
}

/// The elevated helper that changes the Windows Root store for `lpm cert`
/// and the commands that set up HTTPS: adds the certificate in `file`, which
/// must have the SHA-256 fingerprint `sha256`, or removes the one with the
/// SHA-1 thumbprint `sha1`.
pub(crate) fn run_internal_cert_store(
    action: CertStoreAction,
    file: Option<&Path>,
    sha256: Option<&str>,
    sha1: Option<&str>,
) -> Result<(), LpmError> {
    crate::privilege::require_effective_root("certificate-trust")?;
    #[cfg(windows)]
    {
        lpm_cert::trust::apply_windows_root_store_change(&cert_store_change(
            action, file, sha256, sha1,
        )?)
    }
    #[cfg(not(windows))]
    {
        let _ = (action, file, sha256, sha1);
        Err(LpmError::Cert(
            "the certificate-trust helper changes the Windows Root store only".into(),
        ))
    }
}

/// The change `internal-cert-store`'s arguments ask for.
#[cfg(windows)]
fn cert_store_change(
    action: CertStoreAction,
    file: Option<&Path>,
    sha256: Option<&str>,
    sha1: Option<&str>,
) -> Result<lpm_cert::trust::WindowsRootStoreChange, LpmError> {
    use lpm_cert::trust::WindowsRootStoreChange;

    let missing = |flag: &str| LpmError::Cert(format!("internal-cert-store needs {flag}"));
    Ok(match action {
        CertStoreAction::Add => WindowsRootStoreChange::Add {
            path: file.ok_or_else(|| missing("--file"))?.to_path_buf(),
            sha256: sha256.ok_or_else(|| missing("--sha256"))?.to_string(),
        },
        CertStoreAction::Remove => WindowsRootStoreChange::Remove {
            sha1: sha1.ok_or_else(|| missing("--sha1"))?.to_string(),
        },
    })
}

/// Makes a Root-store change through [`run_internal_cert_store`], elevated
/// with UAC, whose prompt then names LPM's publisher; or directly where LPM
/// already runs elevated.
///
/// The elevated helper is this executable, so it is used only where just
/// administrators can change it and the folders above it, as in Program
/// Files. An npm install sits where the user's own processes, an install
/// script among them, could replace it or plant a DLL beside it for the
/// elevated run to load; there LPM elevates certutil, as before.
#[cfg(windows)]
pub(crate) fn change_windows_root_store_through_helper(
    change: &lpm_cert::trust::WindowsRootStoreChange,
) -> Result<(), LpmError> {
    if crate::privilege::is_elevated() {
        return lpm_cert::trust::apply_windows_root_store_change(change);
    }
    let helper_is_protected = std::env::current_exe()
        .is_ok_and(|exe| crate::commands::self_update::path_is_administrators_only(&exe));
    if !helper_is_protected {
        return lpm_cert::trust::change_windows_root_store_with_certutil(change);
    }
    crate::elevation::run_current_exe_helper(
        &internal_cert_store_args(change),
        "Password for LPM certificate trust: ",
        "certificate-trust",
    )
    .map_err(|error| match error {
        LpmError::Registry(message) => LpmError::Cert(message),
        other => other,
    })
}

/// The `lpm internal-cert-store` arguments that make `change`.
#[cfg(windows)]
fn internal_cert_store_args(change: &lpm_cert::trust::WindowsRootStoreChange) -> Vec<String> {
    use lpm_cert::trust::WindowsRootStoreChange;

    match change {
        WindowsRootStoreChange::Add { path, sha256 } => vec![
            "internal-cert-store".to_string(),
            "add".to_string(),
            "--file".to_string(),
            path.display().to_string(),
            "--sha256".to_string(),
            sha256.clone(),
        ],
        WindowsRootStoreChange::Remove { sha1 } => vec![
            "internal-cert-store".to_string(),
            "remove".to_string(),
            "--sha1".to_string(),
            sha1.clone(),
        ],
    }
}

fn run_generate(
    project_dir: &Path,
    extra_hosts: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let extra_permitted_dns = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .map_err(LpmError::Script)?
        .map(|config| {
            lpm_runner::lpm_json::validated_cert_extra_permitted_dns(&config)
                .map(|entries| lpm_cert::name_constraints::dns_subtrees_from_entries(&entries))
        })
        .transpose()
        .map_err(LpmError::Script)?
        .unwrap_or_default();

    let setup = lpm_cert::ensure_https_with_consent_and_permitted_dns(
        project_dir,
        extra_hosts,
        &extra_permitted_dns,
        lpm_cert::TrustStoreConsent::Decline,
    )?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "cert_path": setup.cert_path,
                "key_path": setup.key_path,
                "ca_freshly_installed": setup.ca_freshly_installed,
                "cert_freshly_generated": setup.cert_freshly_generated,
            })
        );
    } else {
        if setup.ca_freshly_installed {
            install_ui::done("root CA generated and installed to trust store");
        }
        if setup.cert_freshly_generated {
            install_ui::done("project certificate generated");
        } else {
            install_ui::done("project certificate already exists and is valid");
        }
        print_field("cert", &setup.cert_path);
        print_field("key", &setup.key_path);
    }

    Ok(())
}

async fn run_rotate(extras: ExtraArgs, json_output: bool) -> Result<(), LpmError> {
    let active_tls_consumers = active_tls_consumers().await?;
    validate_rotation_runtime_safety(extras.keep_old_trusted_days, &active_tls_consumers)?;
    let opts = lpm_cert::rotate::RotateOptions {
        extra_projects: extras.extra_projects,
        skip_missing: !extras.fail_on_missing,
        keep_old_trusted_days: extras.keep_old_trusted_days,
    };
    let result = lpm_cert::rotate::rotate(opts)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return Ok(());
    }

    install_ui::done("CA rotated");
    print_field("mode", result.mode);
    print_field("old_fingerprint", &result.old_fingerprint);
    print_field("new_fingerprint", &result.new_fingerprint);
    print_field("reissued", result.reissued_leaves.len().to_string());
    if !result.skipped_missing.is_empty() {
        print_field("skipped_missing", result.skipped_missing.len().to_string());
    }
    if let Some(when) = &result.old_ca_removal_scheduled {
        print_field("old_ca_removes_at", when);
    } else if result.old_ca_uninstalled {
        print_field("old_ca_uninstalled", "true");
    }
    Ok(())
}

async fn run_reconcile(extras: ExtraArgs, json_output: bool) -> Result<(), LpmError> {
    if !extras.dry_run {
        let active_tls_consumers = active_tls_consumers().await?;
        if !active_tls_consumers.is_empty() {
            return Err(LpmError::Cert(format!(
                "refusing CA reconciliation while local TLS is active ({}). Stop these `lpm dev` or proxy sessions, restart them so they load the current certificate chain, then retry `lpm cert reconcile`",
                active_tls_consumers.join(", ")
            )));
        }
    }
    let result = lpm_cert::reconcile::reconcile(lpm_cert::reconcile::ReconcileOptions {
        dry_run: extras.dry_run,
    })?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return Ok(());
    }

    if extras.dry_run {
        install_ui::phase("dry-run: no mutations performed");
    } else {
        install_ui::done("reconcile complete");
    }
    if result.pending_recovery {
        install_ui::warn(
            "interrupted certificate operation needs recovery; run `lpm cert reconcile` without `--dry-run`, then preview again",
        );
    }
    print_field("grace_removed", result.grace_removed.len().to_string());
    print_field("grace_pending", result.grace_pending.len().to_string());
    print_field("stale_removed", result.stale_removed.len().to_string());
    if result.reconcile_required_cleared {
        print_field("reconcile_required_cleared", "true");
    }
    Ok(())
}

async fn active_tls_consumers() -> Result<Vec<String>, LpmError> {
    let mut consumers = std::collections::BTreeSet::new();
    let proxy_status = lpm_proxy::status()
        .await
        .map_err(|error| LpmError::Cert(format!("inspect local proxy TLS state: {error}")))?;
    if proxy_status.running && proxy_status.tls_addr.is_some() && !proxy_status.routes.is_empty() {
        consumers.insert("local proxy daemon".to_string());
    }
    for session in lpm_runner::dev_session::discover_active_https_sessions()? {
        consumers.insert(format!("lpm dev at {}", session.project_dir.display()));
    }
    Ok(consumers.into_iter().collect())
}

fn validate_rotation_runtime_safety(
    keep_old_trusted_days: Option<u32>,
    active_tls_consumers: &[String],
) -> Result<(), LpmError> {
    if keep_old_trusted_days.is_some() || active_tls_consumers.is_empty() {
        return Ok(());
    }
    Err(LpmError::Cert(format!(
        "refusing hard CA rotation while local TLS is active ({}). Existing processes would keep serving certificates signed by the old CA after it is removed. Stop these `lpm dev` or proxy sessions and retry, or use `--keep-old-trusted 1`; restart them before `lpm cert reconcile` removes the old CA",
        active_tls_consumers.join(", ")
    )))
}

fn print_field<T: install_ui::TerminalValue>(label: &'static str, value: T) {
    println!(
        "{}",
        crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim(&format!("{label:<10}")),
            value
        )
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The elevated helper gets back the change it was asked to make,
    /// through ShellExecute's command line and LPM's own parsing.
    #[cfg(windows)]
    #[test]
    fn the_cert_store_helper_gets_the_change_it_was_asked_for() {
        use clap::Parser as _;
        use lpm_cert::trust::WindowsRootStoreChange;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

        let split = |line: &str| -> Vec<String> {
            let wide: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
            let mut count = 0;
            // SAFETY: `wide` is NUL-terminated; the returned array is freed below.
            let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
            assert!(!argv.is_null());
            let args = (0..count as usize)
                .map(|index| {
                    // SAFETY: CommandLineToArgvW returned `count` NUL-terminated strings.
                    let arg = unsafe { *argv.add(index) };
                    let length = (0..).take_while(|&at| unsafe { *arg.add(at) } != 0).count();
                    String::from_utf16(unsafe { std::slice::from_raw_parts(arg, length) }).unwrap()
                })
                .collect();
            // SAFETY: the array came from CommandLineToArgvW and is freed once.
            unsafe { LocalFree(argv.cast()) };
            args
        };
        for change in [
            WindowsRootStoreChange::Add {
                path: r"C:\Users\O'Brien & Co\.lpm\certs\.lpm-verified ca 1".into(),
                sha256: "AB".repeat(32),
            },
            WindowsRootStoreChange::Remove {
                sha1: "cd".repeat(20),
            },
        ] {
            let line = format!(
                r#""C:\Program Files\LPM\lpm.exe" {}"#,
                crate::elevation::quote_windows_args(&internal_cert_store_args(&change))
            );
            let cli = crate::cli::Cli::try_parse_from(split(&line)).unwrap();
            let Some(crate::cli::Commands::InternalCertStore(args)) = cli.command else {
                panic!("{line} is not internal-cert-store");
            };
            let parsed = cert_store_change(
                args.action,
                args.file.as_deref(),
                args.sha256.as_deref(),
                args.sha1.as_deref(),
            )
            .unwrap();
            assert_eq!(parsed, change, "{line}");
        }
    }

    #[test]
    fn hard_ca_rotation_rejects_active_tls_consumers() {
        let error =
            validate_rotation_runtime_safety(None, &["lpm dev at /tmp/project".to_string()])
                .unwrap_err();

        assert!(error.to_string().contains("refusing hard CA rotation"));
        assert!(error.to_string().contains("`--keep-old-trusted 1`"));
        assert!(error.to_string().contains("restart"));
    }

    #[test]
    fn grace_window_ca_rotation_allows_active_tls_consumers() {
        validate_rotation_runtime_safety(Some(1), &["local proxy daemon".to_string()]).unwrap();
    }
}
