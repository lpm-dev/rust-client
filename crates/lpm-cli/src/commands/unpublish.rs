use crate::commands::registry_change::{OtpCode, RegistryChange, send_with_second_factor};
use crate::commands::release_target::ReleaseTarget;
use crate::install_ui;
use crate::prompt::PromptResultExt as _;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

const COMMAND: &str = "lpm unpublish";

/// Unpublish one version of an lpm.dev package. The registry decides whether
/// the version can still be unpublished, and refuses one that can't before
/// it asks for the second factor.
pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    target: &str,
    otp: Option<String>,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let target = ReleaseTarget::parse(target, COMMAND)?;
    let Some(version) = target.version.as_deref() else {
        return Err(LpmError::InvalidVersion(format!(
            "{COMMAND} removes one version: name it, as in {}@1.2.3",
            target.package
        )));
    };
    let otp = otp.map(|code| OtpCode::parse(code, COMMAND)).transpose()?;
    if !confirmed(&target, yes, json_output)? {
        install_ui::skipped("Unpublish cancelled");
        return Ok(());
    }

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Unpublishing {}",
            install_ui::yellow(&target.to_string())
        ));
    }
    let url = format!("{registry_url}/api/registry/-/package/unpublish");
    let body = serde_json::json!({
        "package": target.package.scoped(),
        "version": version,
    });
    let approval = format!("unpublish {target}");
    let change = RegistryChange {
        command: COMMAND,
        approval: &approval,
    };
    let (response, _) = send_with_second_factor(
        &change,
        registry_url,
        otp.as_ref(),
        json_output,
        async |proof| {
            client
                .post_json_with_second_factor_and_bearer(&url, &body, proof, COMMAND, "unpublish")
                .await
        },
    )
    .await?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(LpmError::Registry(
            "invalid unpublish response: expected `ok: true`".into(),
        ));
    }

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "unpublished": true,
            "package": target.package.scoped(),
            "version": version,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · unpublished {}",
            install_ui::yellow(&target.to_string())
        ));
    }
    Ok(())
}

/// Whether to go ahead: `--yes`, or the user's answer in a terminal.
/// Without a terminal to ask in, or with `--json`, `--yes` is required,
/// since an unpublished version can't be restored.
fn confirmed(target: &ReleaseTarget, yes: bool, json_output: bool) -> Result<bool, LpmError> {
    if yes {
        return Ok(true);
    }
    if json_output || !crate::commands::web_auth::terminal_is_interactive() {
        return Err(LpmError::ConfirmationRequired { command: COMMAND });
    }
    cliclack::confirm(crate::prompt::untrusted(format!(
        "Unpublish {target}? This can't be undone."
    )))
    .initial_value(false)
    .interact()
    .map_prompt_err(|error| LpmError::Registry(format!("confirmation prompt failed: {error}")))
}
