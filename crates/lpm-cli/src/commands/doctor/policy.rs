use crate::commands::doctor::check::Check;
use crate::commands::policy::{self, PolicyDiagnosticSeverity};
use crate::doctor_catalog;

pub(super) fn check_policy_extensions(
    global: &crate::commands::config::GlobalConfig,
    config_error: Option<&str>,
) -> Vec<Check> {
    if let Some(error) = config_error {
        return vec![Check::fail(
            &doctor_catalog::POLICY_EXTENSION_CONFIG_INVALID,
            &format!("could not load policy extension config: {error}"),
        )];
    }
    let configs = match policy::load_policy_extension_configs_from_global(global) {
        Ok(configs) => configs,
        Err(error) => {
            return vec![Check::fail(
                &doctor_catalog::POLICY_EXTENSION_CONFIG_INVALID,
                &format!("could not load policy extension config: {error}"),
            )];
        }
    };
    let inspection = policy::inspect_policy_extensions(&configs);
    inspection
        .diagnostics
        .iter()
        .filter_map(policy_diagnostic_to_check)
        .collect()
}

fn policy_diagnostic_to_check(diagnostic: &policy::PolicyDiagnostic) -> Option<Check> {
    let entry = match diagnostic.code {
        policy::POLICY_EXTENSIONS_NOT_CONFIGURED_CODE => {
            &doctor_catalog::POLICY_EXTENSIONS_NOT_CONFIGURED
        }
        policy::POLICY_EXTENSIONS_CONFIGURED_CODE => &doctor_catalog::POLICY_EXTENSIONS_CONFIGURED,
        policy::POLICY_EXTENSION_REPORT_MODE_CODE => &doctor_catalog::POLICY_EXTENSION_REPORT_MODE,
        policy::POLICY_EXTENSION_COMMAND_UNAVAILABLE_CODE => {
            &doctor_catalog::POLICY_EXTENSION_COMMAND_UNAVAILABLE
        }
        policy::POLICY_EXTENSION_CONFIG_INVALID_CODE => {
            &doctor_catalog::POLICY_EXTENSION_CONFIG_INVALID
        }
        _ => return None,
    };
    Some(match diagnostic.severity {
        PolicyDiagnosticSeverity::Pass => Check::pass(entry, &diagnostic.detail),
        PolicyDiagnosticSeverity::Warn => Check::warn(entry, &diagnostic.detail),
        PolicyDiagnosticSeverity::Fail => Check::fail(entry, &diagnostic.detail),
    })
}
