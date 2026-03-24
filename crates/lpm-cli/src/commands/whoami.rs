use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    let user = client.whoami().await?;

    if json_output {
        let json = serde_json::to_string_pretty(&user)?;
        println!("{json}");
        return Ok(());
    }

    let username = user
        .profile_username
        .as_deref()
        .or(user.username.as_deref())
        .unwrap_or("unknown");

    println!();
    output::success(&format!("Logged in as {}", username.bold()));

    if let Some(tier) = &user.plan_tier {
        output::field("plan", tier);
    }

    if let Some(mfa) = user.mfa_enabled {
        let status = if mfa {
            "enabled".green().to_string()
        } else {
            "disabled".yellow().to_string()
        };
        output::field("2FA", &status);
    }

    if user.has_pool_access == Some(true) {
        output::field("pool", &"active".green().to_string());
    }

    if !user.organizations.is_empty() {
        output::header("organizations");
        for org in &user.organizations {
            let role = org.role.as_deref().unwrap_or("member");
            println!("    @{} {}", org.slug.bold(), format!("({role})").dimmed());
        }
    }

    println!();
    Ok(())
}
