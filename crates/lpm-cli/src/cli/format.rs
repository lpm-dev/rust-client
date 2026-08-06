use clap::Parser;
use miette::Diagnostic as _;

use crate::{auth, install_ui};

use super::args::Cli;
use super::helpers::{args_for_cli_parse, argv_requests_json, clap_help_hint_from_argv};

pub(super) fn parse_cli_or_exit() -> Cli {
    let args = args_for_cli_parse(std::env::args_os());
    let json_output = argv_requests_json(&args);
    let help_hint = clap_help_hint_from_argv(&args);
    match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => exit_with_clap_error(error, json_output, help_hint),
    }
}

pub(super) fn argv_has_global_registry_flag<I>(args: I) -> bool
where
    I: IntoIterator,
    I::Item: Into<std::ffi::OsString>,
{
    args.into_iter().skip(1).any(|arg| {
        let arg = arg.into();
        arg == "--registry"
            || arg
                .to_str()
                .is_some_and(|value| value.starts_with("--registry="))
    })
}

pub(super) fn argv_has_setup_ci_registry_flag<I>(args: I) -> bool
where
    I: IntoIterator,
    I::Item: Into<std::ffi::OsString>,
{
    args.into_iter().skip(1).any(|arg| {
        let arg = arg.into();
        arg == "--registry"
            || arg
                .to_str()
                .is_some_and(|value| value.starts_with("--registry=") || value.starts_with("-r"))
    })
}

#[derive(Debug, Eq, PartialEq)]
enum SlimErrorLine {
    Failed(install_ui::TerminalLine),
    Detail(install_ui::TerminalLine),
}

fn exit_with_clap_error(error: clap::Error, json_output: bool, help_hint: Option<String>) -> ! {
    match error.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            error.exit();
        }
        _ => {
            let exit_code = error.exit_code();
            if json_output {
                print_json_clap_error(&error, help_hint.as_deref());
            } else {
                render_slim_clap_error(&error, help_hint.as_deref());
            }
            std::process::exit(exit_code);
        }
    }
}

pub(super) fn exit_with_lpm_error(
    error: &lpm_common::LpmError,
    json_output: bool,
    registry_url: &str,
) -> ! {
    if json_output && !matches!(error, lpm_common::LpmError::ExitCode(_)) {
        print_json_error(error);
    } else if !json_output && !matches!(error, lpm_common::LpmError::ExitCode(_)) {
        render_slim_error(error);
    }

    if matches!(error, lpm_common::LpmError::AuthRequired) {
        let _ = auth::clear_token(registry_url);
    }

    match error {
        lpm_common::LpmError::ExitCode(code) => std::process::exit(*code),
        _ => std::process::exit(1),
    }
}

fn print_json_clap_error(error: &clap::Error, help_hint: Option<&str>) {
    let mut object = serde_json::Map::with_capacity(9);
    object.insert(
        "schema_version".to_owned(),
        serde_json::json!(crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION),
    );
    object.insert("success".to_owned(), serde_json::json!(false));
    object.insert("error_code".to_owned(), serde_json::json!("usage"));
    object.insert(
        "kind".to_owned(),
        serde_json::json!(clap_error_kind_code(error.kind())),
    );
    object.insert(
        "error".to_owned(),
        serde_json::json!(clap_error_reason(error)),
    );

    if let Some(argument) = clap_context_first(error, clap::error::ContextKind::InvalidArg) {
        object.insert("argument".to_owned(), serde_json::json!(argument));
    }
    if let Some(command) = clap_context_first(error, clap::error::ContextKind::InvalidSubcommand) {
        object.insert("command".to_owned(), serde_json::json!(command));
    }
    if let Some(value) = clap_context_first(error, clap::error::ContextKind::InvalidValue) {
        object.insert("value".to_owned(), serde_json::json!(value));
    }

    let valid_values = clap_context_values(error, clap::error::ContextKind::ValidValue);
    if !valid_values.is_empty() {
        object.insert("valid_values".to_owned(), serde_json::json!(valid_values));
    }

    if let Some(usage) = clap_usage(error) {
        object.insert("usage".to_owned(), serde_json::json!(usage));
    }
    object.insert(
        "hint".to_owned(),
        serde_json::json!(clap_help_hint(error, help_hint)),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(object)).unwrap()
    );
}

fn print_json_error(error: &lpm_common::LpmError) {
    println!(
        "{}",
        serde_json::to_string_pretty(&json_error_value(error)).unwrap()
    );
}

fn json_error_value(error: &lpm_common::LpmError) -> serde_json::Value {
    let mut json = match error {
        lpm_common::LpmError::Resolution(context) => {
            let mut detail = serde_json::Map::with_capacity(12);
            detail.insert("code".to_owned(), serde_json::json!("RESOLUTION_FAILED"));
            detail.insert("message".to_owned(), serde_json::json!(context.to_string()));
            detail.insert(
                "package".to_owned(),
                serde_json::json!(context.package.as_str()),
            );
            detail.insert(
                "requested".to_owned(),
                serde_json::json!(context.requested.as_str()),
            );
            detail.insert(
                "dependency".to_owned(),
                serde_json::json!(context.dependency.as_str()),
            );
            detail.insert("kind".to_owned(), serde_json::json!(context.kind.as_str()));
            detail.insert(
                "reason".to_owned(),
                serde_json::json!(context.reason.as_str()),
            );
            if let Some(required_by) = &context.required_by {
                detail.insert("required_by".to_owned(), serde_json::json!(required_by));
            }
            if let Some(available_versions) = context.available_versions {
                detail.insert(
                    "available_versions".to_owned(),
                    serde_json::json!(available_versions),
                );
            }
            if let Some(newest_version) = &context.newest_version {
                detail.insert(
                    "newest_version".to_owned(),
                    serde_json::json!(newest_version),
                );
            }
            if let Some(derivation) = &context.derivation {
                detail.insert("derivation".to_owned(), serde_json::json!(derivation));
            }
            serde_json::json!({
                "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
                "success": false,
                "error_code": error.error_code(),
                "error": serde_json::Value::Object(detail),
            })
        }
        lpm_common::LpmError::ArtifactUnavailable(context) => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "error_code": error.error_code(),
            "error": {
                "code": error.error_code().to_ascii_uppercase(),
                "message": context.to_string(),
                "package": context.package,
                "version": context.version,
                "source": context.source,
                "kind": context.kind,
                "lockfiles_preserved": context.lockfiles_preserved,
                "suggested_command": context.suggested_command,
            }
        }),
        lpm_common::LpmError::UnsupportedAuthSource {
            command,
            auth_source,
        } => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "error_code": error.error_code(),
            "error": {
                "code": "UNSUPPORTED_AUTH_SOURCE",
                "message": error.to_string(),
                "command": command,
                "source": auth_source,
            }
        }),
        lpm_common::LpmError::TyposquatSuspected(context) => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "error_code": "typosquat_suspected",
            "error": {
                "code": "TYPOSQUAT_SUSPECTED",
                "message": context.to_string(),
                "findings": context.findings,
                "config_path": context.config_path,
                "allow_example": context.allow_example,
                "suggested_command": context.suggested_command,
            }
        }),
        lpm_common::LpmError::SecurityApprovalRequired {
            message,
            requested_scopes,
            project_root,
            suggested_command,
        } => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "error_code": "security_approval_required",
            "error": {
                "code": "SECURITY_APPROVAL_REQUIRED",
                "message": message,
                "requested_scopes": requested_scopes,
                "project_root": project_root,
                "suggested_command": suggested_command,
            }
        }),
        lpm_common::LpmError::PoolAttributionUnconfirmed { reason } => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "installed": true,
            "pool_attribution_confirmed": false,
            "error_code": "pool_attribution_unconfirmed",
            "error": {
                "code": "POOL_ATTRIBUTION_UNCONFIRMED",
                "message": error.to_string(),
                "reason": reason,
                "retry_safe": true,
                "suggested_action": "Run the same lpm install command again.",
            }
        }),
        _ => serde_json::json!({
            "schema_version": crate::json_contract::ERROR_ENVELOPE_SCHEMA_VERSION,
            "success": false,
            "error": format!("{error}"),
            "error_code": error.error_code(),
        }),
    };
    if let Some(next_steps) = next_steps_for_error(error) {
        json["next_steps"] = next_steps;
    }
    json
}

fn next_steps_for_error(error: &lpm_common::LpmError) -> Option<serde_json::Value> {
    match error {
        lpm_common::LpmError::AuthRequired => Some(crate::json_contract::command_next_steps(
            "Authenticate with LPM",
            "lpm login",
        )),
        lpm_common::LpmError::SessionExpired => Some(crate::json_contract::command_next_steps(
            "Re-authenticate with LPM",
            "lpm login",
        )),
        lpm_common::LpmError::ArtifactUnavailable(context) => {
            context.suggested_command.as_deref().map(|command| {
                crate::json_contract::command_next_steps(
                    "Update the pin in a mutable development environment",
                    command,
                )
            })
        }
        lpm_common::LpmError::TyposquatSuspected(context) => {
            context.suggested_command.as_deref().map(|command| {
                crate::json_contract::command_next_steps("Install the suggested package", command)
            })
        }
        lpm_common::LpmError::SecurityApprovalRequired {
            suggested_command: Some(command),
            ..
        } => Some(crate::json_contract::command_next_steps(
            "Approve the requested security change",
            command,
        )),
        _ => None,
    }
}

fn render_slim_clap_error(error: &clap::Error, help_hint: Option<&str>) {
    for line in slim_clap_error_lines(error, help_hint) {
        match line {
            SlimErrorLine::Failed(message) => install_ui::failed_line(message),
            SlimErrorLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

fn render_slim_error(error: &lpm_common::LpmError) {
    for line in slim_error_lines(error) {
        match line {
            SlimErrorLine::Failed(message) => install_ui::failed_line(message),
            SlimErrorLine::Detail(message) => install_ui::detail_line(message),
        }
    }
}

fn slim_clap_error_lines(error: &clap::Error, help_hint: Option<&str>) -> Vec<SlimErrorLine> {
    let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
        "Invalid command line",
    ))];
    push_multiline_detail(&mut lines, "reason", &clap_error_reason(error));
    push_clap_context_detail(
        &mut lines,
        "argument",
        error,
        clap::error::ContextKind::InvalidArg,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "command",
        error,
        clap::error::ContextKind::InvalidSubcommand,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "value",
        error,
        clap::error::ContextKind::InvalidValue,
        ClapDetailStyle::Value,
    );
    push_clap_context_detail(
        &mut lines,
        "values",
        error,
        clap::error::ContextKind::ValidValue,
        ClapDetailStyle::Value,
    );
    push_clap_context_detail(
        &mut lines,
        "conflicts",
        error,
        clap::error::ContextKind::PriorArg,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "suggestion",
        error,
        clap::error::ContextKind::SuggestedCommand,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "suggestion",
        error,
        clap::error::ContextKind::SuggestedSubcommand,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "suggestion",
        error,
        clap::error::ContextKind::SuggestedArg,
        ClapDetailStyle::Command,
    );
    push_clap_context_detail(
        &mut lines,
        "suggestion",
        error,
        clap::error::ContextKind::SuggestedValue,
        ClapDetailStyle::Value,
    );

    if let Some(usage) = clap_usage(error) {
        push_detail(&mut lines, "usage", install_ui::yellow(&usage));
    }

    push_detail(
        &mut lines,
        "hint",
        install_ui::dim(&clap_help_hint(error, help_hint)),
    );
    lines
}

fn slim_error_lines(error: &lpm_common::LpmError) -> Vec<SlimErrorLine> {
    match error {
        lpm_common::LpmError::InvalidPackageName(reason) => {
            diagnostic_lines("Invalid package name", Some(reason), error)
        }
        lpm_common::LpmError::InvalidIntegrity(reason) => {
            diagnostic_lines("Invalid integrity hash", Some(reason), error)
        }
        lpm_common::LpmError::IntegrityMismatch { expected, actual } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Integrity mismatch",
            ))];
            push_detail(&mut lines, "expected", install_ui::cyan(expected));
            push_detail(&mut lines, "actual", install_ui::cyan(actual));
            push_diagnostic_help(&mut lines, error);
            lines
        }
        lpm_common::LpmError::InvalidVersion(reason) => {
            diagnostic_lines("Invalid version", Some(reason), error)
        }
        lpm_common::LpmError::InvalidVersionRange(reason) => {
            diagnostic_lines("Invalid version range", Some(reason), error)
        }
        lpm_common::LpmError::Registry(reason) => {
            diagnostic_lines("Registry error", Some(reason), error)
        }
        lpm_common::LpmError::PoolAttributionUnconfirmed { reason } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Installed, but Pool attribution is unconfirmed",
            ))];
            push_untrusted_detail(&mut lines, "reason", reason);
            push_detail(
                &mut lines,
                "retry",
                install_ui::yellow("run the same lpm install command again"),
            );
            lines
        }
        lpm_common::LpmError::Resolution(context) => resolution_error_lines(context, error),
        lpm_common::LpmError::TyposquatSuspected(context) => {
            let headline = if context.cancelled {
                "Install cancelled"
            } else {
                "Suspicious package name"
            };
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                headline,
            ))];
            for finding in &context.findings {
                push_detail(&mut lines, "package", install_ui::yellow(&finding.package));
                push_detail_line(
                    &mut lines,
                    "resembles",
                    install_ui::terminal_line!(
                        "{} {}",
                        install_ui::yellow(&finding.similar_to),
                        install_ui::dim(&format!("({})", finding.technique)),
                    ),
                );
            }
            if let Some(command) = &context.suggested_command {
                push_detail(&mut lines, "try", install_ui::yellow(command));
            }
            lines
        }
        lpm_common::LpmError::PeerDependency(reason) => {
            diagnostic_lines("Peer dependency check failed", Some(reason), error)
        }
        lpm_common::LpmError::Network(reason) => {
            diagnostic_lines("Network error", Some(reason), error)
        }
        lpm_common::LpmError::Http { status, message } => {
            let status = if *status >= 400 {
                install_ui::red(&status.to_string())
            } else {
                install_ui::yellow(&status.to_string())
            };
            let mut lines = vec![SlimErrorLine::Failed(install_ui::terminal_line!(
                "HTTP {}", status
            ))];
            push_untrusted_detail(&mut lines, "message", message);
            lines
        }
        lpm_common::LpmError::AuthRequired => {
            diagnostic_lines("Authentication required", None, error)
        }
        lpm_common::LpmError::SessionExpired => {
            diagnostic_lines("Session expired or revoked", None, error)
        }
        lpm_common::LpmError::UnsupportedAuthSource {
            command,
            auth_source,
        } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Unsupported authentication source",
            ))];
            push_detail(&mut lines, "command", install_ui::yellow(command));
            push_detail(&mut lines, "source", install_ui::yellow(auth_source));
            push_diagnostic_help(&mut lines, error);
            lines
        }
        lpm_common::LpmError::Forbidden(reason) => {
            diagnostic_lines("Forbidden", Some(reason), error)
        }
        lpm_common::LpmError::NpmFirewallBlocked {
            package,
            verdict,
            reason,
            decision_id,
            match_source,
        } => {
            let mut lines = vec![
                SlimErrorLine::Failed(install_ui::terminal_line!(
                    "Firewall blocked {}",
                    install_ui::yellow(package),
                )),
                SlimErrorLine::Detail(install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("verdict"),
                    install_ui::yellow(verdict),
                )),
                SlimErrorLine::Detail(install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("reason"),
                    reason,
                )),
            ];
            if let Some(decision_id) = decision_id {
                lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("decision"),
                    install_ui::cyan(decision_id),
                )));
            }
            if let Some(match_source) = match_source {
                lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("match"),
                    install_ui::cyan(match_source),
                )));
            }
            lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
                "  {} {}",
                install_ui::dim("hint"),
                install_ui::dim("The package was not downloaded."),
            )));
            lines
        }
        lpm_common::LpmError::NpmFirewallEntitlementRequired {
            message,
            reason,
            entitlement_source,
        } => entitlement_error_lines(
            "NPM firewall access denied",
            message,
            reason.as_deref(),
            entitlement_source.as_deref(),
            "Use a Pro/org token for npm firewall checks, or set [firewall].mode = \"off\".",
        ),
        lpm_common::LpmError::UpstreamProxyEntitlementRequired {
            message,
            reason,
            entitlement_source,
        } => entitlement_error_lines(
            "Upstream npm proxy access denied",
            message,
            reason.as_deref(),
            entitlement_source.as_deref(),
            "Use a Pro/org token, or route standalone npm packages directly to npm.",
        ),
        lpm_common::LpmError::NotFound(reason) => {
            diagnostic_lines("Not found", Some(reason), error)
        }
        lpm_common::LpmError::ArtifactUnavailable(context) => {
            let headline = match context.kind {
                lpm_common::ArtifactUnavailableKind::Pinned => "Pinned artifact unavailable",
                lpm_common::ArtifactUnavailableKind::Selected => "Selected artifact unavailable",
            };
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                headline,
            ))];
            push_detail(
                &mut lines,
                "package",
                install_ui::yellow(&context.package_request()),
            );
            push_detail(&mut lines, "source", install_ui::cyan(&context.source));
            push_detail(&mut lines, "lockfiles", install_ui::status_ok("preserved"));
            if let Some(command) = &context.suggested_command {
                push_detail(&mut lines, "command", install_ui::yellow(command));
                lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
                    "  {} {}",
                    install_ui::dim("CI"),
                    install_ui::dim(
                        "update in a mutable development environment and commit the lockfiles",
                    ),
                )));
            } else if context.kind == lpm_common::ArtifactUnavailableKind::Pinned {
                push_detail(
                    &mut lines,
                    "recovery",
                    install_ui::dim(
                        "restore the artifact, or update its owning direct dependency or override",
                    ),
                );
            }
            lines
        }
        lpm_common::LpmError::RateLimited { retry_after_secs } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Rate limited",
            ))];
            push_detail(
                &mut lines,
                "retry after",
                install_ui::status_ok(&format!("{retry_after_secs}s")),
            );
            push_diagnostic_help(&mut lines, error);
            lines
        }
        lpm_common::LpmError::Script(reason) => {
            diagnostic_lines("Script error", Some(reason), error)
        }
        lpm_common::LpmError::Cert(reason) => {
            diagnostic_lines("Certificate error", Some(reason), error)
        }
        lpm_common::LpmError::Tunnel(reason) => {
            diagnostic_lines("Tunnel error", Some(reason), error)
        }
        lpm_common::LpmError::Store(reason) => diagnostic_lines("Store error", Some(reason), error),
        lpm_common::LpmError::ProjectLayout(reason) => {
            diagnostic_lines("Project layout error", Some(reason), error)
        }
        lpm_common::LpmError::ScriptWithOutput {
            code,
            stdout,
            stderr,
        } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::terminal_line!(
                "Script exited with code {}",
                install_ui::red(&code.to_string()),
            ))];
            push_captured_output(&mut lines, "stdout", stdout);
            push_captured_output(&mut lines, "stderr", stderr);
            lines
        }
        lpm_common::LpmError::ExitCode(code) => {
            vec![SlimErrorLine::Failed(install_ui::terminal_line!(
                "Process exited with code {}",
                install_ui::red(&code.to_string()),
            ))]
        }
        lpm_common::LpmError::Io(reason) => {
            diagnostic_lines("I/O error", Some(&reason.to_string()), error)
        }
        lpm_common::LpmError::Json(reason) => {
            diagnostic_lines("JSON error", Some(&reason.to_string()), error)
        }
        lpm_common::LpmError::Task(reason) => diagnostic_lines("Task error", Some(reason), error),
        lpm_common::LpmError::Plugin(reason) => {
            diagnostic_lines("Plugin error", Some(reason), error)
        }
        lpm_common::LpmError::Engine(reason) => {
            diagnostic_lines("Engine error", Some(reason), error)
        }
        lpm_common::LpmError::Workspace(reason) => {
            diagnostic_lines("Workspace error", Some(reason), error)
        }
        lpm_common::LpmError::CatalogEntryInvalidRecursiveDefinition {
            dependency,
            catalog,
            specifier,
        } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Invalid recursive catalog entry",
            ))];
            push_detail(&mut lines, "dependency", install_ui::yellow(dependency));
            push_detail(&mut lines, "catalog", install_ui::cyan(catalog));
            push_detail(&mut lines, "specifier", install_ui::cyan(specifier));
            push_diagnostic_help(&mut lines, error);
            lines
        }
        lpm_common::LpmError::EnvValidation(reason) => {
            diagnostic_lines("Environment validation failed", Some(reason), error)
        }
        lpm_common::LpmError::EngineMismatch {
            engine,
            required,
            actual,
            from,
        }
        | lpm_common::LpmError::RunEngineMismatch {
            engine,
            required,
            actual,
            from,
        } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Engine version mismatch",
            ))];
            push_detail(&mut lines, "engine", install_ui::yellow(engine));
            push_detail(&mut lines, "required", install_ui::cyan(required));
            push_detail(&mut lines, "actual", install_ui::cyan(actual));
            push_detail(&mut lines, "from", install_ui::dim(from));
            push_diagnostic_help(&mut lines, error);
            lines
        }
        lpm_common::LpmError::SelfUpdatePaused(reason) => {
            diagnostic_lines("Update check paused", Some(reason), error)
        }
        lpm_common::LpmError::SelfUpdateRateLimited(reason) => {
            diagnostic_lines("Update check rate-limited", Some(reason), error)
        }
        lpm_common::LpmError::ProvenanceVerification(reason) => {
            diagnostic_lines("Provenance verification failed", Some(reason), error)
        }
        lpm_common::LpmError::SelfUpdate(reason) => {
            diagnostic_lines("Self-update refused", Some(reason), error)
        }
        lpm_common::LpmError::SecurityFloor(reason) => {
            diagnostic_lines("Security floor refused", Some(reason), error)
        }
        lpm_common::LpmError::SecurityApprovalStore(reason) => {
            diagnostic_lines("Security approval store refused", Some(reason), error)
        }
        lpm_common::LpmError::SecurityApprovalRequired {
            message,
            requested_scopes,
            project_root,
            suggested_command,
        } => {
            let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
                "Security approval required",
            ))];
            push_multiline_detail(&mut lines, "reason", message);
            if !requested_scopes.is_empty() {
                push_detail(
                    &mut lines,
                    "scopes",
                    install_ui::cyan(&requested_scopes.join(", ")),
                );
            }
            if let Some(project_root) = project_root {
                push_detail(&mut lines, "project", install_ui::cyan(project_root));
            }
            if let Some(suggested_command) = suggested_command {
                push_detail(&mut lines, "command", install_ui::yellow(suggested_command));
            }
            push_diagnostic_help(&mut lines, error);
            lines
        }
    }
}

fn resolution_error_lines(
    context: &lpm_common::ResolutionErrorContext,
    error: &lpm_common::LpmError,
) -> Vec<SlimErrorLine> {
    let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
        "Could not resolve dependencies",
    ))];
    push_detail(
        &mut lines,
        "package",
        install_ui::yellow(&context.package_request()),
    );
    if context.dependency != context.package {
        push_detail(
            &mut lines,
            "dependency",
            install_ui::cyan(&context.dependency),
        );
    }
    if let Some(required_by) = &context.required_by {
        push_detail(&mut lines, "required by", install_ui::yellow(required_by));
    }
    push_untrusted_detail(&mut lines, "reason", &context.reason);
    if let Some(available) = resolution_available_detail(context) {
        push_detail_line(&mut lines, "available", available);
    }
    if let Some(derivation) = &context.derivation {
        push_dimmed_multiline_detail(&mut lines, "because", derivation);
    }
    push_diagnostic_help(&mut lines, error);
    lines
}

fn resolution_available_detail(
    context: &lpm_common::ResolutionErrorContext,
) -> Option<install_ui::TerminalLine> {
    let count = context.available_versions?;
    let noun = if count == 1 { "version" } else { "versions" };
    let count = install_ui::status_ok(&count.to_string());
    match context.newest_version.as_deref() {
        Some(newest) => Some(install_ui::terminal_line!(
            "{} {}, newest {}",
            count,
            noun,
            install_ui::yellow(newest),
        )),
        None => Some(install_ui::terminal_line!("{} {}", count, noun)),
    }
}

fn diagnostic_lines(
    headline: &'static str,
    reason: Option<&str>,
    error: &lpm_common::LpmError,
) -> Vec<SlimErrorLine> {
    let mut lines = vec![SlimErrorLine::Failed(install_ui::TerminalLine::new(
        headline,
    ))];
    if let Some(reason) = reason {
        push_multiline_detail(&mut lines, "reason", reason);
    }
    push_diagnostic_help(&mut lines, error);
    lines
}

fn entitlement_error_lines(
    title: &'static str,
    message: &str,
    reason: Option<&str>,
    entitlement_source: Option<&str>,
    hint: &'static str,
) -> Vec<SlimErrorLine> {
    let mut lines = vec![
        SlimErrorLine::Failed(install_ui::TerminalLine::new(title)),
        SlimErrorLine::Detail(install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("reason"),
            message,
        )),
    ];
    if let Some(reason) = reason {
        lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("policy"),
            install_ui::cyan(reason),
        )));
    }
    if let Some(entitlement_source) = entitlement_source {
        lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("entitlement"),
            install_ui::cyan(entitlement_source),
        )));
    }
    lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim("hint"),
        install_ui::dim(hint),
    )));
    lines
}

fn push_detail(
    lines: &mut Vec<SlimErrorLine>,
    label: &'static str,
    value: install_ui::TerminalFragment,
) {
    lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim(label),
        value,
    )));
}

fn push_detail_line(
    lines: &mut Vec<SlimErrorLine>,
    label: &'static str,
    value: install_ui::TerminalLine,
) {
    lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
        "  {} {}",
        install_ui::dim(label),
        value,
    )));
}

fn push_untrusted_detail(lines: &mut Vec<SlimErrorLine>, label: &'static str, value: &str) {
    push_detail(lines, label, install_ui::field(value));
}

fn push_multiline_detail(lines: &mut Vec<SlimErrorLine>, label: &'static str, value: &str) {
    let mut non_empty = value.lines().filter(|line| !line.trim().is_empty());
    if let Some(first) = non_empty.next() {
        push_untrusted_detail(lines, label, first);
    }
    for line in non_empty {
        lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
            "    {}", line,
        )));
    }
}

fn push_diagnostic_help(lines: &mut Vec<SlimErrorLine>, error: &lpm_common::LpmError) {
    if let Some(help) = error.help() {
        push_dimmed_multiline_detail(lines, "hint", &help.to_string());
    }
}

fn push_captured_output(lines: &mut Vec<SlimErrorLine>, label: &'static str, output: &str) {
    if output.trim().is_empty() {
        return;
    }
    push_dimmed_multiline_detail(lines, label, output.trim_end());
}

fn push_dimmed_multiline_detail(lines: &mut Vec<SlimErrorLine>, label: &'static str, value: &str) {
    let mut non_empty = value.lines().filter(|line| !line.trim().is_empty());
    if let Some(first) = non_empty.next() {
        push_detail(lines, label, install_ui::dim(first));
    }
    for line in non_empty {
        lines.push(SlimErrorLine::Detail(install_ui::terminal_line!(
            "    {}",
            install_ui::dim(line),
        )));
    }
}

#[derive(Clone, Copy)]
enum ClapDetailStyle {
    Command,
    Value,
}

fn push_clap_context_detail(
    lines: &mut Vec<SlimErrorLine>,
    label: &'static str,
    error: &clap::Error,
    kind: clap::error::ContextKind,
    style: ClapDetailStyle,
) {
    let values = clap_context_values(error, kind);
    if values.is_empty() {
        return;
    }

    let joined = values.join(", ");
    let styled = match style {
        ClapDetailStyle::Command => install_ui::yellow(&joined),
        ClapDetailStyle::Value => install_ui::cyan(&joined),
    };
    push_detail(lines, label, styled);
}

fn clap_context_first(error: &clap::Error, kind: clap::error::ContextKind) -> Option<String> {
    clap_context_values(error, kind).into_iter().next()
}

fn clap_context_values(error: &clap::Error, kind: clap::error::ContextKind) -> Vec<String> {
    let Some(value) = error.get(kind) else {
        return Vec::new();
    };

    match value {
        clap::error::ContextValue::None => Vec::new(),
        clap::error::ContextValue::Bool(value) => vec![value.to_string()],
        clap::error::ContextValue::String(value) => one_non_empty(value),
        clap::error::ContextValue::Strings(values) => values
            .iter()
            .filter_map(|value| non_empty_plain(value))
            .collect(),
        clap::error::ContextValue::StyledStr(value) => one_non_empty(&value.to_string()),
        clap::error::ContextValue::StyledStrs(values) => values
            .iter()
            .filter_map(|value| non_empty_plain(&value.to_string()))
            .collect(),
        clap::error::ContextValue::Number(value) => vec![value.to_string()],
        _ => one_non_empty(&value.to_string()),
    }
}

fn one_non_empty(value: &str) -> Vec<String> {
    non_empty_plain(value).into_iter().collect()
}

fn non_empty_plain(value: &str) -> Option<String> {
    let plain = console::strip_ansi_codes(value).trim().to_owned();
    (!plain.is_empty()).then_some(plain)
}

fn clap_usage(error: &clap::Error) -> Option<String> {
    clap_context_first(error, clap::error::ContextKind::Usage).map(|usage| {
        let usage = usage
            .strip_prefix("Usage:")
            .unwrap_or(&usage)
            .trim()
            .to_owned();
        normalize_clap_program_name(&usage)
    })
}

fn normalize_clap_program_name(usage: &str) -> String {
    if let Some(rest) = usage.strip_prefix("lpm-rs ") {
        format!("lpm {rest}")
    } else if usage == "lpm-rs" {
        "lpm".to_owned()
    } else {
        usage.to_owned()
    }
}

fn clap_error_reason(error: &clap::Error) -> String {
    let rendered = console::strip_ansi_codes(&error.render().to_string()).into_owned();
    for line in rendered.lines() {
        let trimmed = line.trim();
        if let Some(reason) = trimmed.strip_prefix("error: ") {
            return reason.to_owned();
        }
    }

    for line in rendered.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Usage:")
            || trimmed.starts_with("For more information, try")
        {
            continue;
        }
        return trimmed.to_owned();
    }

    clap_error_kind_fallback(error.kind()).to_owned()
}

fn clap_error_kind_fallback(kind: clap::error::ErrorKind) -> &'static str {
    match kind {
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "required command line input was missing"
        }
        clap::error::ErrorKind::Io => "command line parser I/O failed",
        clap::error::ErrorKind::Format => "command line parser formatting failed",
        _ => kind.as_str().unwrap_or("invalid command line"),
    }
}

fn clap_error_kind_code(kind: clap::error::ErrorKind) -> &'static str {
    match kind {
        clap::error::ErrorKind::InvalidValue => "invalid_value",
        clap::error::ErrorKind::UnknownArgument => "unknown_argument",
        clap::error::ErrorKind::InvalidSubcommand => "invalid_subcommand",
        clap::error::ErrorKind::NoEquals => "missing_equals",
        clap::error::ErrorKind::ValueValidation => "value_validation",
        clap::error::ErrorKind::TooManyValues => "too_many_values",
        clap::error::ErrorKind::TooFewValues => "too_few_values",
        clap::error::ErrorKind::WrongNumberOfValues => "wrong_number_of_values",
        clap::error::ErrorKind::ArgumentConflict => "argument_conflict",
        clap::error::ErrorKind::MissingRequiredArgument => "missing_required_argument",
        clap::error::ErrorKind::MissingSubcommand => "missing_subcommand",
        clap::error::ErrorKind::InvalidUtf8 => "invalid_utf8",
        clap::error::ErrorKind::DisplayHelp => "display_help",
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "display_help_on_missing_argument_or_subcommand"
        }
        clap::error::ErrorKind::DisplayVersion => "display_version",
        clap::error::ErrorKind::Io => "io",
        clap::error::ErrorKind::Format => "format",
        _ => "unknown",
    }
}

fn clap_help_hint(error: &clap::Error, fallback: Option<&str>) -> String {
    let Some(usage) = clap_usage(error) else {
        return fallback.unwrap_or("Run `lpm --help` for usage.").to_owned();
    };

    let mut parts = usage.split_whitespace();
    let _program = parts.next();
    let mut command_path = Vec::new();
    for part in parts {
        if part.starts_with('-') || part.starts_with('[') || part.starts_with('<') {
            break;
        }
        command_path.push(part);
    }

    if command_path.is_empty() {
        fallback.unwrap_or("Run `lpm --help` for usage.").to_owned()
    } else {
        format!(
            "Run `lpm {} --help` for command usage.",
            command_path.join(" ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_ci_registry_flag_scan_detects_every_explicit_form() {
        for args in [
            vec!["lpm", "--registry", "https://registry.example"],
            vec!["lpm", "--registry=https://registry.example"],
            vec![
                "lpm",
                "setup",
                "ci",
                "npmrc",
                "-r",
                "https://registry.example",
            ],
            vec!["lpm", "setup", "ci", "npmrc", "-rhttps://registry.example"],
        ] {
            assert!(argv_has_setup_ci_registry_flag(args));
        }
    }

    #[test]
    fn setup_ci_registry_flag_scan_ignores_argv_without_registry_flags() {
        assert!(!argv_has_setup_ci_registry_flag([
            "lpm",
            "setup",
            "ci",
            "github-actions"
        ]));
    }

    fn plain_slim_line(line: &SlimErrorLine) -> String {
        let raw = match line {
            SlimErrorLine::Failed(message) | SlimErrorLine::Detail(message) => message,
        };
        console::strip_ansi_codes(raw).into_owned()
    }

    #[test]
    fn slim_error_lines_render_firewall_block_as_contract_rows() {
        let error = lpm_common::LpmError::NpmFirewallBlocked {
            package: "is-number@7.0.0".into(),
            verdict: "malicious".into(),
            reason: "product_default policy maps malicious to block".into(),
            decision_id: Some("decision-1".into()),
            match_source: Some("package".into()),
        };

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "Firewall blocked is-number@7.0.0");
        assert_eq!(plain[1], "  verdict malicious");
        assert_eq!(
            plain[2],
            "  reason product_default policy maps malicious to block"
        );
        assert_eq!(plain[3], "  decision decision-1");
        assert_eq!(plain[4], "  match package");
        assert_eq!(plain[5], "  hint The package was not downloaded.");
    }

    #[test]
    fn slim_error_lines_render_entitlement_denial_as_contract_rows() {
        let error = lpm_common::LpmError::UpstreamProxyEntitlementRequired {
            message: "A Pro account or active org membership is required.".into(),
            reason: Some("personal_plan_not_eligible".into()),
            entitlement_source: None,
        };

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "Upstream npm proxy access denied");
        assert_eq!(
            plain[1],
            "  reason A Pro account or active org membership is required."
        );
        assert_eq!(plain[2], "  policy personal_plan_not_eligible");
        assert_eq!(
            plain[3],
            "  hint Use a Pro/org token, or route standalone npm packages directly to npm."
        );
    }

    #[test]
    fn slim_error_lines_render_firewall_entitlement_denial_as_contract_rows() {
        let error = lpm_common::LpmError::NpmFirewallEntitlementRequired {
            message: "A Pro account or active org membership is required.".into(),
            reason: Some("personal_plan_not_eligible".into()),
            entitlement_source: Some("personal".into()),
        };

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "NPM firewall access denied");
        assert_eq!(
            plain[1],
            "  reason A Pro account or active org membership is required."
        );
        assert_eq!(plain[2], "  policy personal_plan_not_eligible");
        assert_eq!(plain[3], "  entitlement personal");
        assert_eq!(
            plain[4],
            "  hint Use a Pro/org token for npm firewall checks, or set [firewall].mode = \"off\"."
        );
    }

    #[test]
    fn slim_error_lines_render_script_errors_without_miette_frame() {
        let error = lpm_common::LpmError::Script(
            "--workspace-concurrency requires --all, --filter, --filter-prod, or --affected".into(),
        );

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "Script error");
        assert_eq!(
            plain[1],
            "  reason --workspace-concurrency requires --all, --filter, --filter-prod, or --affected"
        );
        assert!(
            plain.iter().all(|line| !line.contains("Error:")),
            "slim error rows must not include miette framing: {plain:?}"
        );
    }

    #[test]
    fn slim_error_lines_render_project_layout_without_store_repair_guidance() {
        let error = lpm_common::LpmError::ProjectLayout(
            "project node_modules must be a real directory, but /repo/node_modules is a symlink"
                .into(),
        );

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "Project layout error");
        assert_eq!(
            plain[1],
            "  reason project node_modules must be a real directory, but /repo/node_modules is a symlink"
        );
        assert!(
            plain[2].contains("lpm doctor --fix"),
            "project layout hint must explain the local repair: {plain:?}"
        );
        assert!(
            plain
                .iter()
                .all(|line| !line.contains("store clean") && !line.contains("cache prune")),
            "project layout output must not recommend global store repair: {plain:?}"
        );
    }

    #[test]
    fn project_layout_json_error_uses_a_dedicated_code() {
        let error = lpm_common::LpmError::ProjectLayout("project node_modules is a symlink".into());

        let envelope = json_error_value(&error);

        assert_eq!(envelope["success"], serde_json::json!(false));
        assert_eq!(envelope["error_code"], serde_json::json!("project_layout"));
        assert_eq!(
            envelope["error"],
            serde_json::json!("project layout error: project node_modules is a symlink")
        );
    }

    #[test]
    fn pool_attribution_failure_json_is_truthful_about_installed_state() {
        let error = lpm_common::LpmError::PoolAttributionUnconfirmed {
            reason: "HTTP 503: temporary outage".into(),
        };

        let envelope = json_error_value(&error);

        assert_eq!(envelope["success"], serde_json::json!(false));
        assert_eq!(envelope["installed"], serde_json::json!(true));
        assert_eq!(
            envelope["pool_attribution_confirmed"],
            serde_json::json!(false)
        );
        assert_eq!(
            envelope["error_code"],
            serde_json::json!("pool_attribution_unconfirmed")
        );
        assert_eq!(envelope["error"]["retry_safe"], serde_json::json!(true));
        insta::assert_json_snapshot!(envelope, @r###"
        {
          "schema_version": 1,
          "success": false,
          "installed": true,
          "pool_attribution_confirmed": false,
          "error_code": "pool_attribution_unconfirmed",
          "error": {
            "code": "POOL_ATTRIBUTION_UNCONFIRMED",
            "message": "packages were installed, but Pool attribution could not be confirmed: HTTP 503: temporary outage",
            "reason": "HTTP 503: temporary outage",
            "retry_safe": true,
            "suggested_action": "Run the same lpm install command again."
          }
        }
        "###);
    }

    #[test]
    fn pool_attribution_failure_human_output_reports_partial_success() {
        let error = lpm_common::LpmError::PoolAttributionUnconfirmed {
            reason: "HTTP 503: temporary outage".into(),
        };

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(
            plain,
            vec![
                "Installed, but Pool attribution is unconfirmed",
                "  reason HTTP 503: temporary outage",
                "  retry run the same lpm install command again",
            ]
        );
    }

    #[test]
    fn slim_error_lines_render_security_approval_context_rows() {
        let error = lpm_common::LpmError::SecurityApprovalRequired {
            message: "strict sandbox weakening needs approval".into(),
            requested_scopes: vec!["sandbox.strict".into(), "network.host".into()],
            project_root: Some("/repo/app".into()),
            suggested_command: Some("lpm security unlock sandbox.strict".into()),
        };

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(plain[0], "Security approval required");
        assert_eq!(plain[1], "  reason strict sandbox weakening needs approval");
        assert_eq!(plain[2], "  scopes sandbox.strict, network.host");
        assert_eq!(plain[3], "  project /repo/app");
        assert_eq!(plain[4], "  command lpm security unlock sandbox.strict");
    }

    #[test]
    fn slim_error_lines_render_typosquat_cancel_as_compact_contract_rows() {
        let error =
            lpm_common::LpmError::TyposquatSuspected(Box::new(lpm_common::TyposquatErrorContext {
                findings: vec![lpm_common::TyposquatErrorFinding {
                    package: "axois".into(),
                    similar_to: "axios".into(),
                    technique: "edit_distance".into(),
                    source: "cli".into(),
                }],
                config_path: "/repo/app/lpm.toml".into(),
                allow_example: concat!(
                    "[[policy.typosquat.allow]]\n",
                    "package = \"axois\"\n",
                    "similar-to = \"axios\"\n",
                    "reason = \"Intentional package\""
                )
                .into(),
                suggested_command: Some("lpm install axios".into()),
                cancelled: true,
            }));

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(
            plain,
            vec![
                "Install cancelled",
                "  package axois",
                "  resembles axios (edit_distance)",
                "  try lpm install axios",
            ]
        );
    }

    #[test]
    fn slim_error_lines_render_pinned_artifact_without_command_as_recovery_guidance() {
        let error = lpm_common::LpmError::ArtifactUnavailable(Box::new(
            lpm_common::ArtifactUnavailableErrorContext {
                package: "transitive-package".into(),
                version: "1.0.0".into(),
                source: "registry+https://registry.npmjs.org".into(),
                kind: lpm_common::ArtifactUnavailableKind::Pinned,
                lockfiles_preserved: true,
                suggested_command: None,
            },
        ));

        let lines = slim_error_lines(&error);
        let plain: Vec<_> = lines.iter().map(plain_slim_line).collect();

        assert_eq!(
            plain,
            vec![
                "Pinned artifact unavailable",
                "  package transitive-package@1.0.0",
                "  source registry+https://registry.npmjs.org",
                "  lockfiles preserved",
                "  recovery restore the artifact, or update its owning direct dependency or override",
            ]
        );
    }
}
