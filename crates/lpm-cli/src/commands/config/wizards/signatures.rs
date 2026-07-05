use super::prelude::*;

pub(in crate::commands::config) async fn run_signatures_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let enabled = if let Some(value) = set {
        parse_config_bool(value)
            .map_err(|message| LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}")))?
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Registry(
                "lpm config signatures requires a TTY; use `--set true|false` instead".to_string(),
            ));
        }

        let current = read_bool_value(config_path, SIGNATURES_KEY)?.unwrap_or(false);
        println!();
        println!("  current: {}", format_bool_enabled(current).cyan());
        let new_value: &str =
            cliclack::select("Verify npm registry package signatures during install?")
                .item(
                    "true",
                    "enabled",
                    "fail install when registry signatures cannot verify",
                )
                .item(
                    "false",
                    "disabled",
                    "default; use `lpm audit signatures` on demand",
                )
                .initial_value(if current { "true" } else { "false" })
                .interact()
                .map_err(prompt_err)?;
        parse_config_bool(new_value)
            .map_err(|message| LpmError::Registry(format!("`{SIGNATURES_KEY}` {message}")))?
    };

    persist_bool(config_path, SIGNATURES_KEY, enabled)?;
    announce_bool_set(SIGNATURES_KEY, enabled, json_output);
    Ok(())
}
