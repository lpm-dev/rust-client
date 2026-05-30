use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
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
    match action {
        "status" => run_status(project_dir, json_output),
        "trust" => run_trust(json_output),
        "uninstall" => run_uninstall(json_output),
        "generate" => run_generate(project_dir, extra_hosts, json_output),
        "rotate" => run_rotate(extras, json_output),
        "reconcile" => run_reconcile(extras, json_output),
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
                },
                "permission_drifts": drift_json,
            })
        );
        return Ok(());
    }

    println!("Root CA");
    if status.ca_exists {
        let trust_status = if status.ca_trusted {
            "trusted".green()
        } else {
            "not trusted".red()
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
                txt.red()
            } else if days < 60 {
                txt.yellow()
            } else {
                txt.green()
            };
            print_field("remaining", &colored);
            if days < 60 {
                println!(
                    "  {}",
                    "Run `lpm cert rotate` to roll the CA before it expires.".dimmed()
                );
            }
        }
    } else {
        print_field("status", &"not installed".red());
        println!(
            "  {}",
            "Run `lpm cert trust` to generate and install the CA".dimmed()
        );
    }

    if !drifts.is_empty() {
        println!();
        println!("Permission drift");
        for d in &drifts {
            print_field(d.role, &d.summary().red().to_string());
            println!("  {}", format!("fix: {}", d.chmod_hint()).dimmed());
        }
    }

    println!();
    println!("Project cert");
    if status.project_cert_exists {
        if status.project_cert_needs_renewal {
            print_field("status", &"needs renewal".yellow());
        } else {
            print_field("status", &"valid".green());
        }
        if !status.project_cert_hostnames.is_empty() {
            print_field("hosts", &status.project_cert_hostnames.join(", "));
        }
        if let Some(expires) = &status.project_cert_expires {
            print_field("expires", expires);
        }
    } else {
        print_field("status", &"not generated".dimmed());
        println!(
            "  {}",
            "Run `lpm dev --https` or `lpm cert generate` to create".dimmed()
        );
    }

    println!();
    if status.ca_exists
        && status.ca_trusted
        && status.project_cert_exists
        && !status.project_cert_needs_renewal
    {
        install_ui::done("HTTPS certificates are ready");
    } else {
        install_ui::warn("HTTPS certificates need setup");
    }

    Ok(())
}

fn run_trust(json_output: bool) -> Result<(), LpmError> {
    let ca_cert_path = lpm_cert::paths::ca_cert_path()?;

    let ca_dir = lpm_cert::paths::ca_dir()?;
    lpm_cert::create_dir_secure(&ca_dir)
        .map_err(|e| LpmError::Cert(format!("failed to secure cert dir: {e}")))?;

    if !ca_cert_path.exists() {
        let (ca_cert_pem, ca_key_pem) = lpm_cert::ca::generate_ca()
            .map_err(|e| LpmError::Cert(format!("failed to generate CA: {e}")))?;

        std::fs::write(&ca_cert_path, &ca_cert_pem)
            .map_err(|e| LpmError::Cert(format!("failed to write CA cert: {e}")))?;

        let key_path = lpm_cert::paths::ca_key_path()?;
        lpm_cert::write_key_file(&key_path, ca_key_pem.as_bytes())
            .map_err(|e| LpmError::Cert(format!("failed to write CA key: {e}")))?;

        let fp = lpm_cert::cert::fingerprint_sha256(&ca_cert_path)?;
        lpm_cert::audit::append_best_effort(lpm_cert::audit::AuditAction::CaGenerate {
            fingerprint: lpm_cert::cert::fingerprint_hex(&fp),
            validity_days: lpm_cert::ca::CA_VALIDITY_DAYS,
            name_constraints: lpm_cert::ca::wants_name_constraints(),
        });

        if !json_output {
            install_ui::done("root CA generated");
        }
    }

    let fp = lpm_cert::cert::fingerprint_sha256(&ca_cert_path)?;
    let fp_hex = lpm_cert::cert::fingerprint_hex(&fp);
    match lpm_cert::trust::install_ca(&ca_cert_path) {
        Ok(()) => {
            lpm_cert::audit::append_best_effort(lpm_cert::audit::AuditAction::CaTrustInstall {
                fingerprint: fp_hex,
                store: lpm_cert::trust_store_label(),
                status: lpm_cert::audit::AuditStatus::Ok,
                error: None,
            });
        }
        Err(e) => {
            lpm_cert::audit::append_best_effort(lpm_cert::audit::AuditAction::CaTrustInstall {
                fingerprint: fp_hex,
                store: lpm_cert::trust_store_label(),
                status: lpm_cert::audit::AuditStatus::Error,
                error: Some(e.to_string()),
            });
            return Err(e);
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "ca_installed": true })
        );
    } else {
        install_ui::done("CA installed to system trust store");
        let info = lpm_cert::cert::read_cert_info(&ca_cert_path)?;
        print_field("subject", &info.subject);
        print_field("expires", &info.not_after);
        print_field("path", &ca_cert_path.to_string_lossy());
    }

    Ok(())
}

fn run_uninstall(json_output: bool) -> Result<(), LpmError> {
    let ca_cert_path = lpm_cert::paths::ca_cert_path()?;
    if !ca_cert_path.exists() {
        return Err(LpmError::Cert(format!(
            "no on-disk CA at {}; nothing to uninstall (the fingerprint of the cert to remove is read from this file)",
            ca_cert_path.display()
        )));
    }
    let fp = lpm_cert::cert::fingerprint_sha256(&ca_cert_path)?;
    let fp_hex = lpm_cert::cert::fingerprint_hex(&fp);
    match lpm_cert::trust::uninstall_ca(&ca_cert_path) {
        Ok(()) => {
            lpm_cert::audit::append_best_effort(lpm_cert::audit::AuditAction::CaTrustUninstall {
                fingerprint: fp_hex,
                store: lpm_cert::trust_store_label(),
                status: lpm_cert::audit::AuditStatus::Ok,
                error: None,
            });
        }
        Err(e) => {
            lpm_cert::audit::append_best_effort(lpm_cert::audit::AuditAction::CaTrustUninstall {
                fingerprint: fp_hex,
                store: lpm_cert::trust_store_label(),
                status: lpm_cert::audit::AuditStatus::Error,
                error: Some(e.to_string()),
            });
            return Err(e);
        }
    }

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

fn run_generate(
    project_dir: &Path,
    extra_hosts: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    let setup = lpm_cert::ensure_https_with_consent(
        project_dir,
        extra_hosts,
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

fn run_rotate(extras: ExtraArgs, json_output: bool) -> Result<(), LpmError> {
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
    print_field("reissued", &result.reissued_leaves.len().to_string());
    if !result.skipped_missing.is_empty() {
        print_field("skipped_missing", &result.skipped_missing.len().to_string());
    }
    if let Some(when) = &result.old_ca_removal_scheduled {
        print_field("old_ca_removes_at", when);
    } else if result.old_ca_uninstalled {
        print_field("old_ca_uninstalled", "true");
    }
    Ok(())
}

fn run_reconcile(extras: ExtraArgs, json_output: bool) -> Result<(), LpmError> {
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
    print_field("grace_removed", &result.grace_removed.len().to_string());
    print_field("grace_pending", &result.grace_pending.len().to_string());
    print_field("stale_removed", &result.stale_removed.len().to_string());
    if result.reconcile_required_cleared {
        print_field("reconcile_required_cleared", "true");
    }
    Ok(())
}

fn print_field(label: &str, value: &str) {
    println!("  {label:<10} {value}");
}
