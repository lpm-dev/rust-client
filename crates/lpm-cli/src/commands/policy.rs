use crate::commands::config::GlobalConfig;
use crate::commands::install::policy_extensions::{
    POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE, PolicyExtensionAction, PolicyExtensionConfig,
    PolicyExtensionMode, load_policy_extension_configs, resolve_policy_extension_program,
    run_policy_extension_test,
};
use clap::Subcommand;
use lpm_common::{LpmError, sanitize_for_terminal};
use std::path::Path;

pub(crate) const POLICY_EXTENSIONS_NOT_CONFIGURED_CODE: &str = "policy_extensions_not_configured";
pub(crate) const POLICY_EXTENSIONS_CONFIGURED_CODE: &str = "policy_extensions_configured";
pub(crate) const POLICY_EXTENSION_REPORT_MODE_CODE: &str = "policy_extension_report_mode";
pub(crate) const POLICY_EXTENSION_COMMAND_UNAVAILABLE_CODE: &str =
    "policy_extension_command_unavailable";
pub(crate) const POLICY_EXTENSION_CONFIG_INVALID_CODE: &str = "policy_extension_config_invalid";

#[derive(Debug, Subcommand)]
pub enum PolicyCmd {
    /// List active policy extensions from ~/.lpm/config.toml.
    List,
    /// Summarize active policy extension posture.
    Status,
    /// Diagnose policy extension config and executable availability.
    Doctor {
        /// Optional extension name to diagnose.
        extension: Option<String>,
    },
    /// Send one package candidate to a configured extension.
    Test {
        /// Extension name from [policy.extensions.<name>].
        extension: String,
        /// Exact package candidate, e.g. react@19.0.0 or @scope/pkg@1.2.3.
        #[arg(long)]
        package: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyDiagnosticSeverity {
    Pass,
    Warn,
    Fail,
}

impl PolicyDiagnosticSeverity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyDiagnostic {
    pub(crate) code: &'static str,
    pub(crate) severity: PolicyDiagnosticSeverity,
    pub(crate) extension: Option<String>,
    pub(crate) detail: String,
}

impl PolicyDiagnostic {
    pub(crate) fn fail(
        code: &'static str,
        extension: Option<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity: PolicyDiagnosticSeverity::Fail,
            extension,
            detail: detail.into(),
        }
    }

    fn pass(code: &'static str, extension: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            severity: PolicyDiagnosticSeverity::Pass,
            extension,
            detail: detail.into(),
        }
    }

    fn warn(code: &'static str, extension: Option<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            severity: PolicyDiagnosticSeverity::Warn,
            extension,
            detail: detail.into(),
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "code": self.code,
            "severity": self.severity.as_str(),
            "detail": self.detail,
        });
        if let Some(extension) = &self.extension {
            json["extension"] = serde_json::Value::String(extension.clone());
        }
        json
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyInspection {
    pub(crate) enabled_count: usize,
    pub(crate) enforce_count: usize,
    pub(crate) report_count: usize,
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
}

impl PolicyInspection {
    pub(crate) fn has_failures(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == PolicyDiagnosticSeverity::Fail)
    }

    fn has_warnings(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == PolicyDiagnosticSeverity::Warn)
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled_count > 0,
            "enabled_count": self.enabled_count,
            "enforce_count": self.enforce_count,
            "report_count": self.report_count,
            "no_failures": !self.has_failures(),
            "has_warnings": self.has_warnings(),
            "diagnostics": self.diagnostics.iter().map(PolicyDiagnostic::to_json).collect::<Vec<_>>(),
        })
    }
}

pub(crate) async fn run(
    action: PolicyCmd,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        PolicyCmd::List => run_list(json_output),
        PolicyCmd::Status => run_status(json_output),
        PolicyCmd::Doctor { extension } => run_doctor(extension.as_deref(), json_output),
        PolicyCmd::Test { extension, package } => {
            run_test(project_dir, &extension, &package, json_output).await
        }
    }
}

pub(crate) fn load_policy_extension_configs_checked() -> Result<Vec<PolicyExtensionConfig>, LpmError>
{
    let global = GlobalConfig::load_checked()?;
    load_policy_extension_configs(&global)
}

pub(crate) fn inspect_policy_extensions(configs: &[PolicyExtensionConfig]) -> PolicyInspection {
    let enforce_count = configs
        .iter()
        .filter(|config| config.mode() == PolicyExtensionMode::Enforce)
        .count();
    let report_count = configs.len().saturating_sub(enforce_count);
    let mut diagnostics = Vec::new();
    if configs.is_empty() {
        diagnostics.push(PolicyDiagnostic::pass(
            POLICY_EXTENSIONS_NOT_CONFIGURED_CODE,
            None,
            "no policy extensions configured",
        ));
    } else {
        diagnostics.push(PolicyDiagnostic::pass(
            POLICY_EXTENSIONS_CONFIGURED_CODE,
            None,
            format!(
                "{} enabled ({} enforce, {} report)",
                configs.len(),
                enforce_count,
                report_count
            ),
        ));
    }

    for config in configs {
        if config.mode() == PolicyExtensionMode::Report {
            diagnostics.push(PolicyDiagnostic::warn(
                POLICY_EXTENSION_REPORT_MODE_CODE,
                Some(config.name().to_string()),
                format!(
                    "`{}` is report-only; block decisions will be reported but will not stop installs",
                    config.name()
                ),
            ));
        }
        if let Err(error) = validate_policy_extension_command_available(config) {
            diagnostics.push(PolicyDiagnostic::fail(
                POLICY_EXTENSION_COMMAND_UNAVAILABLE_CODE,
                Some(config.name().to_string()),
                error,
            ));
        }
    }

    PolicyInspection {
        enabled_count: configs.len(),
        enforce_count,
        report_count,
        diagnostics,
    }
}

fn run_list(json_output: bool) -> Result<(), LpmError> {
    let configs = load_policy_extension_configs_checked()?;
    if json_output {
        print_json(&serde_json::json!({
            "success": true,
            "enabled_count": configs.len(),
            "extensions": configs.iter().map(PolicyExtensionConfig::to_config_json).collect::<Vec<_>>(),
        }))?;
        return Ok(());
    }

    if configs.is_empty() {
        println!("No policy extensions configured");
        return Ok(());
    }

    println!("Policy extensions");
    for config in &configs {
        println!(
            "  {:<24} {:<7} on-error={:<5} timeout={}ms  {}",
            sanitize_for_terminal(config.name()),
            config.mode().as_str(),
            config.on_error().as_str(),
            config.timeout_ms(),
            sanitize_for_terminal(&config.command().join(" "))
        );
    }
    Ok(())
}

fn run_status(json_output: bool) -> Result<(), LpmError> {
    let configs = load_policy_extension_configs_checked()?;
    let inspection = inspect_policy_extensions(&configs);
    if json_output {
        let mut json = inspection.to_json();
        json["success"] = serde_json::Value::Bool(true);
        print_json(&json)?;
        return Ok(());
    }

    print_policy_inspection(&inspection);
    Ok(())
}

fn run_doctor(extension: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let configs = match load_policy_extension_configs_checked() {
        Ok(configs) => configs,
        Err(error) => {
            let inspection = PolicyInspection {
                enabled_count: 0,
                enforce_count: 0,
                report_count: 0,
                diagnostics: vec![PolicyDiagnostic::fail(
                    POLICY_EXTENSION_CONFIG_INVALID_CODE,
                    None,
                    format!("could not load policy extension config: {error}"),
                )],
            };
            print_policy_doctor_result(&inspection, json_output)?;
            return Err(LpmError::ExitCode(1));
        }
    };
    let scoped_configs;
    let configs = if let Some(extension) = extension {
        let config = configs
            .iter()
            .find(|config| config.name() == extension)
            .ok_or_else(|| {
                LpmError::Script(format!("policy extension `{extension}` is not configured"))
            })?;
        scoped_configs = vec![config.clone()];
        scoped_configs.as_slice()
    } else {
        configs.as_slice()
    };
    let inspection = inspect_policy_extensions(configs);
    print_policy_doctor_result(&inspection, json_output)?;
    if inspection.has_failures() {
        return Err(LpmError::ExitCode(1));
    }
    Ok(())
}

async fn run_test(
    project_dir: &Path,
    extension: &str,
    package: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let configs = load_policy_extension_configs_checked()?;
    let config = configs
        .iter()
        .find(|config| config.name() == extension)
        .ok_or_else(|| {
            LpmError::Script(format!("policy extension `{extension}` is not configured"))
        })?;
    let (name, version) = parse_exact_package_candidate(package)?;
    let outcome = run_policy_extension_test(config, project_dir, &name, &version).await?;

    if json_output {
        print_json(&policy_test_json(config, &name, &version, &outcome))?;
        return Ok(());
    }

    println!(
        "Policy extension `{}` test",
        sanitize_for_terminal(extension)
    );
    println!(
        "  package     {}@{}",
        sanitize_for_terminal(&name),
        sanitize_for_terminal(&version)
    );
    println!("  event       {POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE}");
    println!("  duration    {}ms", outcome.duration_ms);
    if outcome.decisions.is_empty() {
        println!("  decisions   none");
    } else {
        println!("  decisions");
        for decision in &outcome.decisions {
            let code = decision.code.as_deref().map_or_else(String::new, |code| {
                format!(" [{}]", sanitize_for_terminal(code))
            });
            let reason = decision
                .reason
                .as_deref()
                .map_or_else(|| "no reason provided".to_string(), sanitize_for_terminal);
            println!(
                "    {}@{} - {}{}: {}",
                sanitize_for_terminal(&decision.name),
                sanitize_for_terminal(&decision.version),
                decision.action.as_str(),
                code,
                reason
            );
        }
    }
    Ok(())
}

fn print_policy_doctor_result(
    inspection: &PolicyInspection,
    json_output: bool,
) -> Result<(), LpmError> {
    if json_output {
        let mut json = inspection.to_json();
        json["success"] = serde_json::Value::Bool(true);
        print_json(&json)?;
    } else {
        print_policy_inspection(inspection);
    }
    Ok(())
}

fn print_policy_inspection(inspection: &PolicyInspection) {
    if inspection.enabled_count == 0 {
        println!("Policy extensions: none configured");
    } else {
        println!(
            "Policy extensions: {} enabled ({} enforce, {} report)",
            inspection.enabled_count, inspection.enforce_count, inspection.report_count
        );
    }
    for diagnostic in &inspection.diagnostics {
        let prefix = match diagnostic.severity {
            PolicyDiagnosticSeverity::Pass => "ok",
            PolicyDiagnosticSeverity::Warn => "warn",
            PolicyDiagnosticSeverity::Fail => "fail",
        };
        if diagnostic.code == POLICY_EXTENSIONS_CONFIGURED_CODE
            || diagnostic.code == POLICY_EXTENSIONS_NOT_CONFIGURED_CODE
        {
            continue;
        }
        if let Some(extension) = &diagnostic.extension {
            println!(
                "  {prefix:<4} {:<24} {}",
                sanitize_for_terminal(extension),
                sanitize_for_terminal(&diagnostic.detail)
            );
        } else {
            println!(
                "  {prefix:<4} {}",
                sanitize_for_terminal(&diagnostic.detail)
            );
        }
    }
}

fn policy_test_json(
    config: &PolicyExtensionConfig,
    name: &str,
    version: &str,
    outcome: &crate::commands::install::policy_extensions::PolicyExtensionTestOutcome,
) -> serde_json::Value {
    let (allow_count, warn_count, block_count) = policy_decision_counts(&outcome.decisions);
    serde_json::json!({
        "success": true,
        "extension": config.name(),
        "event": POLICY_EXTENSION_EVENT_PACKAGE_CANDIDATE,
        "package": {
            "name": name,
            "version": version,
        },
        "duration_ms": outcome.duration_ms,
        "allow_count": allow_count,
        "warn_count": warn_count,
        "block_count": block_count,
        "decisions": outcome.decisions.iter().map(crate::commands::install::policy_extensions::PolicyExtensionDecision::to_json).collect::<Vec<_>>(),
    })
}

fn policy_decision_counts(
    decisions: &[crate::commands::install::policy_extensions::PolicyExtensionDecision],
) -> (usize, usize, usize) {
    let mut allow_count = 0usize;
    let mut warn_count = 0usize;
    let mut block_count = 0usize;
    for decision in decisions {
        match decision.action {
            PolicyExtensionAction::Allow => allow_count += 1,
            PolicyExtensionAction::Warn => warn_count += 1,
            PolicyExtensionAction::Block => block_count += 1,
        }
    }
    (allow_count, warn_count, block_count)
}

fn parse_exact_package_candidate(spec: &str) -> Result<(String, String), LpmError> {
    let split = spec.rfind('@').filter(|index| *index > 0).ok_or_else(|| {
        LpmError::Script(
            "`lpm policy test --package` requires an exact package candidate like react@19.0.0"
                .to_string(),
        )
    })?;
    let (name, version_with_at) = spec.split_at(split);
    let version = &version_with_at[1..];
    if name.is_empty() || version.is_empty() {
        return Err(LpmError::Script(
            "`lpm policy test --package` requires non-empty package name and version".to_string(),
        ));
    }
    Ok((name.to_string(), version.to_string()))
}

fn validate_policy_extension_command_available(
    config: &PolicyExtensionConfig,
) -> Result<(), String> {
    let program = config
        .command()
        .first()
        .ok_or_else(|| format!("`{}` has an empty command", config.name()))?;
    resolve_policy_extension_program(program)
        .map(|_| ())
        .map_err(|error| format!("`{}` command unavailable: {error}", config.name()))
}

fn print_json(value: &serde_json::Value) -> Result<(), LpmError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|error| LpmError::Script(format!("failed to serialize policy output: {error}")))?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exact_package_candidate_accepts_unscoped_package() {
        let (name, version) = parse_exact_package_candidate("react@19.0.0").unwrap();

        assert_eq!(name, "react");
        assert_eq!(version, "19.0.0");
    }

    #[test]
    fn parse_exact_package_candidate_accepts_scoped_package() {
        let (name, version) = parse_exact_package_candidate("@scope/pkg@1.2.3").unwrap();

        assert_eq!(name, "@scope/pkg");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn parse_exact_package_candidate_rejects_missing_version() {
        let err = parse_exact_package_candidate("@scope/pkg").unwrap_err();

        assert!(err.to_string().contains("requires an exact package"));
    }
}
