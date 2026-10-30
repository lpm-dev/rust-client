use crate::commands::registry_change::{OtpCode, RegistryChange, send_with_second_factor};
use crate::commands::release_target::ReleaseTarget;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// The longest deprecation message the registry keeps, in UTF-16 code
/// units, as JavaScript counts a string's length.
const MAX_MESSAGE_UNITS: usize = 500;

/// Checks a deprecation message as the registry does, trimmed, so a message
/// it would refuse is refused before any request, and before an approval is
/// spent on it.
pub(crate) fn parse_message(value: &str) -> Result<String, String> {
    let message = value.trim();
    if message.is_empty() {
        return Err(
            "the message can't be empty; to remove a deprecation, run `lpm undeprecate`".into(),
        );
    }
    let units = message.encode_utf16().count();
    if units > MAX_MESSAGE_UNITS {
        return Err(format!(
            "the message is {units} characters long, and can be at most {MAX_MESSAGE_UNITS}"
        ));
    }
    Ok(message.to_owned())
}

/// Deprecate one version of an lpm.dev package, or every version it has that
/// isn't deprecated or unpublished, with `message`: installs still work, and
/// show it.
pub async fn run_deprecate(
    client: &RegistryClient,
    registry_url: &str,
    target: &str,
    message: &str,
    otp: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    run(
        client,
        registry_url,
        Change::Deprecate { message },
        target,
        otp,
        json_output,
    )
    .await
}

/// Remove the deprecation of one version of an lpm.dev package, or of every
/// version.
pub async fn run_undeprecate(
    client: &RegistryClient,
    registry_url: &str,
    target: &str,
    otp: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    run(
        client,
        registry_url,
        Change::Undeprecate,
        target,
        otp,
        json_output,
    )
    .await
}

#[derive(Clone, Copy)]
enum Change<'a> {
    Deprecate { message: &'a str },
    Undeprecate,
}

impl<'a> Change<'a> {
    fn command(self) -> &'static str {
        match self {
            Self::Deprecate { .. } => "lpm deprecate",
            Self::Undeprecate => "lpm undeprecate",
        }
    }

    /// How the registry's refusals and errors name the change.
    fn operation(self) -> &'static str {
        match self {
            Self::Deprecate { .. } => "deprecation",
            Self::Undeprecate => "deprecation removal",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Deprecate { .. } => "deprecate",
            Self::Undeprecate => "undeprecate",
        }
    }

    fn message(self) -> Option<&'a str> {
        match self {
            Self::Deprecate { message } => Some(message),
            Self::Undeprecate => None,
        }
    }
}

async fn run(
    client: &RegistryClient,
    registry_url: &str,
    change: Change<'_>,
    target: &str,
    otp: Option<String>,
    json_output: bool,
) -> Result<(), LpmError> {
    let command = change.command();
    let target = ReleaseTarget::parse(target, command)?;
    let otp = otp.map(|code| OtpCode::parse(code, command)).transpose()?;
    let message = change.message();

    let subject = match &target.version {
        Some(_) => target.to_string(),
        None => format!("every version of {}", target.package),
    };
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "{} {}",
            match change {
                Change::Deprecate { .. } => "Deprecating",
                Change::Undeprecate => "Removing the deprecation of",
            },
            install_ui::yellow(&subject)
        ));
    }

    let url = format!("{registry_url}/api/registry/-/package/deprecate");
    let mut body = serde_json::json!({
        "package": target.package.scoped(),
        "message": message,
    });
    if let Some(version) = &target.version {
        body["version"] = serde_json::Value::from(version.as_str());
    }
    let approval = format!("{} {subject}", change.verb());
    let registry_change = RegistryChange {
        command,
        approval: &approval,
    };
    let (response, _) = send_with_second_factor(
        &registry_change,
        registry_url,
        otp.as_ref(),
        json_output,
        async |proof| {
            client
                .post_json_with_second_factor_and_bearer(
                    &url,
                    &body,
                    proof,
                    command,
                    change.operation(),
                )
                .await
        },
    )
    .await?;
    let changed = changed_versions(&response, change)?;

    if json_output {
        let mut json = serde_json::json!({
            "success": true,
            "deprecated": message.is_some(),
            "package": target.package.scoped(),
            "version": target.version_or_all(),
            "changed": changed,
        });
        if let Some(message) = message {
            json["message"] = serde_json::Value::from(message);
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let package = target.package.to_string();
    match (&target.version, message, changed) {
        (Some(_), Some(_), _) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · deprecated {}",
            install_ui::yellow(&subject)
        )),
        (Some(_), None, _) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · removed the deprecation of {}",
            install_ui::yellow(&subject)
        )),
        (None, Some(_), 0) => install_ui::skipped_line(crate::install_ui::terminal_line!(
            "Every version of {} was already deprecated or unpublished",
            install_ui::yellow(&package)
        )),
        (None, None, 0) => install_ui::skipped_line(crate::install_ui::terminal_line!(
            "No version of {} was deprecated",
            install_ui::yellow(&package)
        )),
        (None, Some(_), count) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · deprecated {} of {}",
            versions(count),
            install_ui::yellow(&package)
        )),
        (None, None, count) => install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · removed the deprecation of {} of {}",
            versions(count),
            install_ui::yellow(&package)
        )),
    }
    if let Some(message) = message {
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::dim("Message:"),
            install_ui::dim(&lpm_common::sanitize_terminal_inline(message))
        ));
    }
    Ok(())
}

/// How many versions the registry changed, checking that it made the change
/// it was asked for.
fn changed_versions(response: &serde_json::Value, change: Change<'_>) -> Result<u64, LpmError> {
    let expected = match change {
        Change::Deprecate { .. } => "deprecated",
        Change::Undeprecate => "undeprecated",
    };
    let action = response.get("action").and_then(serde_json::Value::as_str);
    let changed = response.get("changed").and_then(serde_json::Value::as_u64);
    match (
        response.get("ok").and_then(serde_json::Value::as_bool),
        action,
        changed,
    ) {
        (Some(true), Some(action), Some(changed)) if action == expected => Ok(changed),
        _ => Err(LpmError::Registry(format!(
            "invalid {} response: expected `ok: true`, `action: \"{expected}\"` and a `changed` count",
            change.operation()
        ))),
    }
}

fn versions(count: u64) -> String {
    if count == 1 {
        "1 version".to_owned()
    } else {
        format!("{count} versions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_is_trimmed_as_the_registry_keeps_it() {
        assert_eq!(parse_message("  Use 2.0.0 \n").unwrap(), "Use 2.0.0");
    }

    #[test]
    fn an_empty_message_points_to_undeprecate() {
        for value in ["", "   ", "\n\t"] {
            let error = parse_message(value).unwrap_err();
            assert!(error.contains("lpm undeprecate"), "{value:?}: {error}");
        }
    }

    #[test]
    fn a_message_is_measured_in_utf16_units_as_the_registry_measures_it() {
        let emoji = "🦀";
        assert_eq!(emoji.encode_utf16().count(), 2);
        assert!(parse_message(&emoji.repeat(250)).is_ok());
        let error = parse_message(&emoji.repeat(251)).unwrap_err();
        assert!(error.contains("502 characters"), "{error}");
        assert!(parse_message(&"x".repeat(500)).is_ok());
    }
}
