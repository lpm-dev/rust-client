use std::collections::HashSet;
use std::io::IsTerminal as _;
use std::path::Path;

use lpm_common::{LpmError, LpmRoot};
use lpm_registry::RegistryClient;

use crate::doctor_catalog::{DoctorFix, Severity};
use crate::install_ui;

use super::check::{Check, FixTarget};
use super::install_fix::run_doctor_install;
use super::lockfile::{fix_binary_lockfile, fix_gitattributes};

#[derive(Default)]
pub(super) struct FixReport {
    pub(super) applied: Vec<String>,
    pub(super) failed: Vec<FixFailure>,
}

#[derive(serde::Serialize)]
pub(super) struct FixFailure {
    action: &'static str,
    error: String,
}

#[derive(Default)]
struct RuntimeInstallContext {
    http_client: Option<reqwest::Client>,
    platform: Option<lpm_runtime::platform::Platform>,
}

impl RuntimeInstallContext {
    fn http_client(&mut self) -> Result<reqwest::Client, LpmError> {
        if self.http_client.is_none() {
            self.http_client = Some(
                lpm_http::client_builder()
                    .timeout(std::time::Duration::from_secs(60))
                    .build()
                    .map_err(|error| LpmError::Network(error.to_string()))?,
            );
        }
        self.http_client
            .clone()
            .ok_or_else(|| LpmError::Network("runtime HTTP client was not initialized".into()))
    }

    fn platform(&mut self) -> Result<lpm_runtime::platform::Platform, LpmError> {
        if self.platform.is_none() {
            self.platform = Some(lpm_runtime::platform::Platform::current()?);
        }
        self.platform
            .clone()
            .ok_or_else(|| LpmError::Script("runtime platform was not initialized".into()))
    }
}

pub(super) fn confirm_before_apply(
    checks: &[Check],
    json_output: bool,
    yes: bool,
) -> Result<bool, LpmError> {
    let actions = planned_actions(checks)?;
    if actions.is_empty() {
        return Ok(false);
    }
    if yes {
        return Ok(true);
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Script(
            "Automatic fixes require confirmation. Pass `--yes` in a non-interactive session."
                .into(),
        ));
    }

    install_ui::phase("Planned auto-fix actions");
    for action in &actions {
        install_ui::detail_untrusted(&format!("    {action}"));
    }
    install_ui::detail("");

    let confirmed = cliclack::confirm("Apply these automatic fixes?")
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if confirmed {
        Ok(true)
    } else {
        Err(LpmError::Script(
            "Automatic fixes were declined. No changes were made.".into(),
        ))
    }
}

fn planned_actions(checks: &[Check]) -> Result<Vec<String>, LpmError> {
    let mut seen = HashSet::with_capacity(checks.len());
    let mut actions = Vec::with_capacity(checks.len());

    for check in checks {
        if matches!(check.severity, Severity::Pass) {
            continue;
        }
        if let Some(action) = check.entry.auto_fix {
            let target = if action.requires_target() {
                check.fix_target.as_ref()
            } else {
                None
            };
            if seen.insert((action, target)) {
                actions.push(planned_action_label(action, check)?);
            }
        }
    }

    Ok(actions)
}

fn planned_action_label(action: DoctorFix, check: &Check) -> Result<String, LpmError> {
    match action {
        DoctorFix::ReplaceNodeModulesLink => Ok("replace the project node_modules link".into()),
        DoctorFix::InstallNodeSpec | DoctorFix::InstallNode22 => {
            Ok(format!("lpm use node@{}", target_node_spec(check)?))
        }
        DoctorFix::InstallBunSpec => Ok(format!("lpm use bun@{}", target_bun_spec(check)?)),
        DoctorFix::ClaimTunnel => Ok(format!("lpm tunnel claim {}", target_tunnel_domain(check)?)),
        DoctorFix::UpdatePlugin => Ok(format!("lpm plugin update {}", target_plugin_name(check)?)),
        _ => Ok(action.label().into()),
    }
}

pub(super) async fn apply(
    checks: &[Check],
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
) -> FixReport {
    if !json_output {
        install_ui::phase("Running auto-fix");
    }

    let mut report = FixReport::default();
    let mut attempted = HashSet::with_capacity(checks.len());
    let mut runtime_context = RuntimeInstallContext::default();

    for check in checks {
        if matches!(check.severity, Severity::Pass) {
            continue;
        }
        let Some(action) = check.entry.auto_fix else {
            continue;
        };
        let target = action
            .requires_target()
            .then_some(check.fix_target.as_ref());
        if !attempted.insert((action, target)) {
            continue;
        }

        let result = apply_one(
            action,
            check,
            client,
            project_dir,
            json_output,
            &mut runtime_context,
        )
        .await;

        match result {
            Ok(Some(summary)) => report.applied.push(summary),
            Ok(None) => {}
            Err(error) => {
                super::render_autofix_failed(action.label(), &error);
                report.failed.push(FixFailure {
                    action: action.label(),
                    error: error.to_string(),
                });
            }
        }
    }

    if !json_output {
        render_summary(&report.applied);
    }
    report
}

async fn apply_one(
    action: DoctorFix,
    check: &Check,
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    runtime_context: &mut RuntimeInstallContext,
) -> Result<Option<String>, LpmError> {
    match action {
        DoctorFix::ReplaceNodeModulesLink => {
            phase(
                json_output,
                "fixing: replacing the project node_modules link",
            );
            super::replace_project_node_modules_link(project_dir)
                .map(|()| Some("replaced project node_modules link with a real directory".into()))
        }
        DoctorFix::PruneStore => {
            phase(json_output, "fixing: lpm cache prune --apply");
            prune_store().map(Some)
        }
        DoctorFix::InstallProject => {
            phase(json_output, "fixing: lpm install");
            run_doctor_install(client, project_dir).await?;
            Ok(Some("lpm install".into()))
        }
        DoctorFix::ReconcileBinaryLockfile => {
            phase(json_output, "fixing: reconciling lpm.lockb with lpm.lock");
            fix_binary_lockfile(project_dir)
                .map(|()| Some("reconciled lpm.lockb".into()))
                .map_err(LpmError::Script)
        }
        DoctorFix::UpdateGitAttributes => {
            phase(
                json_output,
                "fixing: ensuring .gitattributes marks lpm.lockb as binary",
            );
            fix_gitattributes(project_dir)
                .map(|()| Some("updated .gitattributes".into()))
                .map_err(LpmError::Script)
        }
        DoctorFix::InstallNodeSpec | DoctorFix::InstallNode22 => {
            let spec = target_node_spec(check)?;
            phase_untrusted(json_output, &format!("fixing: lpm use node@{spec}"));
            install_node(runtime_context, spec)
                .await
                .map(|version| Some(format!("installed node {version}")))
        }
        DoctorFix::InstallBunSpec => {
            let spec = target_bun_spec(check)?;
            phase_untrusted(json_output, &format!("fixing: lpm use bun@{spec}"));
            install_bun(runtime_context, spec)
                .await
                .map(|version| Some(format!("installed bun {version}")))
        }
        DoctorFix::FormatProject => {
            phase(json_output, "fixing: lpm fmt");
            crate::commands::tools::fmt_for_doctor(project_dir)
                .await
                .map(|()| Some("lpm fmt".into()))
        }
        DoctorFix::ClaimTunnel => {
            let domain = target_tunnel_domain(check)?;
            phase_untrusted(json_output, &format!("fixing: lpm tunnel claim {domain}"));
            client
                .tunnel_claim(domain, None)
                .await
                .map(|_| Some(format!("claimed tunnel domain {domain}")))
        }
        DoctorFix::UpdatePlugin => {
            let name = target_plugin_name(check)?;
            phase_untrusted(json_output, &format!("fixing: lpm plugin update {name}"));
            lpm_plugin::update_plugin(name)
                .await
                .map(|version| Some(format!("updated plugin {name} to {version}")))
        }
    }
}

fn phase(json_output: bool, message: &'static str) {
    if !json_output {
        install_ui::phase(message);
    }
}

fn phase_untrusted(json_output: bool, message: &str) {
    if !json_output {
        install_ui::phase_untrusted(message);
    }
}

fn render_summary(fixes_applied: &[String]) {
    if fixes_applied.is_empty() {
        install_ui::phase("no auto-fixable issues found");
        return;
    }
    install_ui::done_untrusted(&format!(
        "applied {} fix(es): {}",
        fixes_applied.len(),
        fixes_applied.join(", ")
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {} Run {} to verify fixes.",
        install_ui::dim("hint"),
        install_ui::yellow("lpm doctor")
    ));
}

fn prune_store() -> Result<String, LpmError> {
    let root = LpmRoot::from_env()?;
    let summary = crate::commands::cache_prune::apply_for_doctor(&root)?;
    Ok(format!(
        "pruned {} store link entries and {} objects",
        summary.link_entries_orphaned.len(),
        summary.object_entries_orphaned.len()
    ))
}

async fn install_node(context: &mut RuntimeInstallContext, spec: &str) -> Result<String, LpmError> {
    lpm_runtime::node::validate_version_spec(spec)?;
    let client = context.http_client()?;
    let platform = context.platform()?;
    let releases = lpm_runtime::node::fetch_index(&client).await?;
    let release = lpm_runtime::node::resolve_version(&releases, spec)
        .ok_or_else(|| LpmError::Script(format!("no Node.js release found matching '{spec}'")))?;
    lpm_runtime::download::install_node(&client, &release, &platform).await
}

async fn install_bun(context: &mut RuntimeInstallContext, spec: &str) -> Result<String, LpmError> {
    lpm_runtime::bun::validate_version_spec(spec)?;
    let client = context.http_client()?;
    let platform = context.platform()?;
    let releases = lpm_runtime::bun::fetch_releases(&client).await?;
    let release = lpm_runtime::bun::resolve_version(&releases, spec)?
        .ok_or_else(|| LpmError::Script(format!("no Bun release found matching '{spec}'")))?;
    let asset = release.asset_for_platform(&platform).ok_or_else(|| {
        LpmError::Script(format!(
            "no Bun asset found for platform {platform} in {}",
            release.tag_name
        ))
    })?;
    lpm_runtime::download::install_bun(&client, &release, &asset).await
}

fn target_node_spec(check: &Check) -> Result<&str, LpmError> {
    match check.fix_target.as_ref() {
        Some(FixTarget::NodeSpec(spec)) => Ok(spec),
        _ => Err(missing_target(check, "Node version")),
    }
}

fn target_bun_spec(check: &Check) -> Result<&str, LpmError> {
    match check.fix_target.as_ref() {
        Some(FixTarget::BunSpec(spec)) => Ok(spec),
        _ => Err(missing_target(check, "Bun version")),
    }
}

fn target_tunnel_domain(check: &Check) -> Result<&str, LpmError> {
    match check.fix_target.as_ref() {
        Some(FixTarget::TunnelDomain(domain)) => Ok(domain),
        _ => Err(missing_target(check, "tunnel domain")),
    }
}

fn target_plugin_name(check: &Check) -> Result<&str, LpmError> {
    match check.fix_target.as_ref() {
        Some(FixTarget::PluginName(name)) => Ok(name),
        _ => Err(missing_target(check, "plugin name")),
    }
}

fn missing_target(check: &Check, target: &str) -> LpmError {
    LpmError::Script(format!(
        "doctor catalog invariant failed: `{}` has no structured {target}",
        check.code()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog;

    #[test]
    fn node_fix_target_is_read_without_parsing_human_detail() {
        let check = Check::fail_with_fix_target(
            &doctor_catalog::NODE_MISSING_PINNED,
            "wording can change freely",
            FixTarget::NodeSpec("22.5".into()),
        );

        assert_eq!(target_node_spec(&check).unwrap(), "22.5");
    }

    #[test]
    fn plugin_fix_target_is_read_without_parsing_human_detail() {
        let check = Check::warn_with_fix_target(
            &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
            "wording can change freely",
            FixTarget::PluginName("biome".into()),
        );

        assert_eq!(target_plugin_name(&check).unwrap(), "biome");
    }

    #[test]
    fn planned_actions_deduplicate_actions_in_check_order() {
        let checks = vec![
            Check::warn(&doctor_catalog::LOCKFILE_BINARY_MISSING, "missing"),
            Check::warn(&doctor_catalog::LOCKFILE_BINARY_STALE, "stale"),
            Check::warn(&doctor_catalog::GITATTRIBUTES_MISSING, "missing"),
        ];

        assert_eq!(
            planned_actions(&checks).unwrap(),
            vec![
                "reconcile lpm.lockb".to_string(),
                "update .gitattributes".to_string(),
            ]
        );
    }

    #[test]
    fn planned_actions_keep_distinct_targets_for_one_action() {
        let checks = vec![
            Check::warn_with_fix_target(
                &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
                "biome update",
                FixTarget::PluginName("biome".into()),
            ),
            Check::warn_with_fix_target(
                &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
                "oxlint update",
                FixTarget::PluginName("oxlint".into()),
            ),
        ];

        assert_eq!(
            planned_actions(&checks).unwrap(),
            vec![
                "lpm plugin update biome".to_string(),
                "lpm plugin update oxlint".to_string(),
            ]
        );
    }

    #[test]
    fn confirmation_is_not_required_when_no_fixable_actions_exist() {
        let checks = [Check::fail(
            &doctor_catalog::REGISTRY_UNREACHABLE,
            "offline",
        )];

        assert!(!confirm_before_apply(&checks, true, false).unwrap());
    }

    #[test]
    fn yes_bypasses_confirmation_for_noninteractive_fixes() {
        let checks = [Check::warn(
            &doctor_catalog::LOCKFILE_BINARY_MISSING,
            "missing",
        )];

        assert!(confirm_before_apply(&checks, true, true).unwrap());
    }

    #[tokio::test]
    async fn one_failed_project_install_is_not_retried_for_duplicate_findings() {
        let project = tempfile::tempdir().unwrap();
        let checks = [
            Check::fail(&doctor_catalog::NODE_MODULES_MISSING, "missing"),
            Check::warn(&doctor_catalog::LOCKFILE_MISSING, "missing"),
        ];

        let report = apply(&checks, &RegistryClient::new(), project.path(), true).await;

        assert_eq!(
            report.failed.len(),
            1,
            "one planned install action must produce at most one failure"
        );
    }
}
