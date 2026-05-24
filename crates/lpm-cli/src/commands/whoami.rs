use super::whoami_ui;
use crate::auth;
use lpm_common::color::Painted;
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError};
use lpm_registry::RegistryClient;

pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    if !json_output && !has_local_whoami_auth(client.base_url()) {
        whoami_ui::phase(&format!("Not logged in to {}.", client.base_url().bold()));
        whoami_ui::phase(&format!(
            "Run {} to authenticate.",
            login_command_for_registry(client.base_url()).dimmed()
        ));
        return Ok(());
    }

    let user = client.whoami().await?;

    // API returns email in `username` (npm compat) and display name in `profile_username`.
    // Normalize for both JSON and human output.
    let display_name = user
        .profile_username
        .as_deref()
        .or(user.username.as_deref())
        .unwrap_or("unknown");
    let email = user
        .email
        .as_deref()
        .or(user.username.as_deref().filter(|u| u.contains('@')));

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "username": display_name,
            "email": email,
            "plan": user.plan_tier,
            "mfa_enabled": user.mfa_enabled,
            "has_pool_access": user.has_pool_access,
            "usage": user.usage.as_ref().map(|u| serde_json::json!({
                "storage_bytes": u.storage_bytes,
                "private_packages": u.private_packages,
            })),
            "limits": user.limits.as_ref().map(|l| serde_json::json!({
                "storage_bytes": l.storage_bytes,
                "private_packages": l.private_packages,
            })),
            "orgs": user.organizations.iter().map(|o| serde_json::json!({
                "slug": o.slug,
                "name": o.name,
                "role": o.role,
            })).collect::<Vec<_>>(),
            "registries": build_registries_json(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    if let Some(email_str) = email {
        whoami_ui::done(&format!(
            "Logged in as {} — {}",
            display_name.bold(),
            email_str.dimmed()
        ));
    } else {
        whoami_ui::done(&format!("Logged in as {}", display_name.bold()));
    }

    // Plan & Pool
    if let Some(tier) = &user.plan_tier {
        whoami_ui::detail("Plan", &tier.to_uppercase());

        if user.has_pool_access == Some(true) {
            whoami_ui::detail("Pool", "Active");
        } else {
            whoami_ui::detail("Pool", "Not subscribed");
        }
    }

    // 2FA
    if let Some(mfa) = user.mfa_enabled {
        let status = if mfa {
            "enabled".green()
        } else {
            "disabled".yellow()
        };
        whoami_ui::detail("2FA", &status);
    }

    // Usage & Limits
    if let Some(usage) = &user.usage {
        let storage_mb = usage.storage_bytes as f64 / (1024.0 * 1024.0);

        if let Some(limits) = &user.limits {
            // Storage
            if let Some(limit_bytes) = limits.storage_bytes {
                let limit_mb = limit_bytes as f64 / (1024.0 * 1024.0);
                let storage_msg = format!("{:.2}MB / {:.0}MB", storage_mb, limit_mb);
                if usage.storage_bytes > limit_bytes {
                    whoami_ui::warn(&format!("Storage: {} (OVER LIMIT)", storage_msg));
                } else {
                    whoami_ui::detail("Storage", &storage_msg);
                }
            } else {
                whoami_ui::detail("Storage", &format!("{:.2}MB", storage_mb));
            }

            // Package count
            if let Some(limit_pkgs) = limits.private_packages {
                if limit_pkgs == 0 || limit_pkgs == u32::MAX {
                    whoami_ui::detail(
                        "Private Packages",
                        &format!("{} (Unlimited)", usage.private_packages),
                    );
                } else {
                    let pkg_msg = format!("{} / {}", usage.private_packages, limit_pkgs);
                    if usage.private_packages > limit_pkgs {
                        whoami_ui::warn(&format!("Private Packages: {} (OVER LIMIT)", pkg_msg));
                    } else {
                        whoami_ui::detail("Private Packages", &pkg_msg);
                    }
                }
            } else {
                whoami_ui::detail("Private Packages", &format!("{}", usage.private_packages));
            }

            // Over-limit warning
            let over_storage = limits
                .storage_bytes
                .is_some_and(|l| usage.storage_bytes > l);
            let over_packages = limits
                .private_packages
                .is_some_and(|l| l > 0 && l != u32::MAX && usage.private_packages > l);

            if over_storage || over_packages {
                whoami_ui::warn("Your account is over its plan limits.");
                whoami_ui::warn("Write access (publishing, inviting members) is restricted.");
                whoami_ui::warn("Upgrade your plan: https://lpm.dev/dashboard/settings/billing");
            }
        } else {
            whoami_ui::detail("Storage", &format!("{:.2}MB", storage_mb));
            whoami_ui::detail("Private Packages", &format!("{}", usage.private_packages));
        }
    }

    // Available Scopes
    whoami_ui::blank_line();
    whoami_ui::phase("Available Scopes");
    if let Some(profile) = &user.profile_username {
        whoami_ui::list_item(&format!(
            "Personal: {}",
            format!("@lpm.dev/{profile}.*").cyan()
        ));
    } else {
        whoami_ui::warn("Personal: Not set (https://lpm.dev/dashboard/settings)");
    }

    if !user.organizations.is_empty() {
        whoami_ui::list_item("Organizations:");
        for org in &user.organizations {
            let role = org.role.as_deref().unwrap_or("member");
            whoami_ui::list_item(&format!(
                "  {} {}",
                format!("@lpm.dev/{}.*", org.slug).cyan(),
                format!("({role})").dimmed()
            ));
        }
    }

    // B4: Show external registries with stored tokens
    let external_registries = auth::list_stored_registries();
    if !external_registries.is_empty() {
        whoami_ui::blank_line();
        whoami_ui::phase("External Registries");
        for (name, status) in &external_registries {
            whoami_ui::list_item(&format!("{name} {}", status.dimmed()));
        }
    }

    // Show token expiry warnings
    let expiry_warnings = auth::check_token_expiry_warnings();
    for warning in &expiry_warnings {
        whoami_ui::warn(warning);
    }
    Ok(())
}

/// Build the registries array for JSON output.
fn build_registries_json() -> Vec<serde_json::Value> {
    let mut regs = vec![serde_json::json!({"name": "lpm.dev", "status": "authenticated"})];
    for (name, status) in auth::list_stored_registries() {
        regs.push(serde_json::json!({"name": name, "status": status}));
    }
    regs
}

fn has_local_whoami_auth(registry_url: &str) -> bool {
    auth::get_token(registry_url).is_some() || auth::has_refresh_token(registry_url)
}

fn login_command_for_registry(registry_url: &str) -> String {
    if registry_url.trim_end_matches('/') == DEFAULT_REGISTRY_URL.trim_end_matches('/') {
        "`lpm login`".to_string()
    } else {
        format!("`lpm login --registry {registry_url}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn scoped_home_dir() -> (tempfile::TempDir, crate::test_env::ScopedEnv) {
        let dir = tempfile::tempdir().unwrap();
        let env = crate::test_env::ScopedEnv::update([
            ("HOME", Some(dir.path().as_os_str().to_owned())),
            ("LPM_FORCE_FILE_AUTH", Some(OsString::from("1"))),
            ("LPM_TEST_FAST_SCRYPT", Some(OsString::from("1"))),
            ("LPM_TOKEN", None),
        ]);
        (dir, env)
    }

    #[test]
    fn whoami_local_auth_state_counts_refresh_token() {
        let (_home, _env) = scoped_home_dir();
        let registry = "https://whoami-refresh.test";

        auth::set_refresh_token(registry, "refresh-token");

        assert!(has_local_whoami_auth(registry));
    }

    #[test]
    fn login_command_for_default_registry_uses_short_form() {
        assert_eq!(
            login_command_for_registry(DEFAULT_REGISTRY_URL),
            "`lpm login`"
        );
        assert_eq!(
            login_command_for_registry("https://lpm.dev/"),
            "`lpm login`"
        );
    }

    #[test]
    fn login_command_for_custom_registry_keeps_registry_flag() {
        assert_eq!(
            login_command_for_registry("https://registry.example.com"),
            "`lpm login --registry https://registry.example.com`"
        );
    }

    #[tokio::test]
    async fn whoami_human_mode_returns_ok_when_no_local_auth_exists() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (_home, _env) = scoped_home_dir();
        let server = MockServer::start().await;
        let client = RegistryClient::new().with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let result = run(&client, false).await;

        assert!(
            result.is_ok(),
            "expected friendly logged-out info, got {result:?}"
        );
    }

    #[tokio::test]
    async fn whoami_json_mode_preserves_auth_required_when_no_local_auth_exists() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (_home, _env) = scoped_home_dir();
        let server = MockServer::start().await;
        let client = RegistryClient::new().with_base_url(server.uri());

        Mock::given(method("GET"))
            .and(path("/api/registry/-/whoami"))
            .respond_with(ResponseTemplate::new(401).set_body_string("expired"))
            .expect(1)
            .mount(&server)
            .await;

        let result = run(&client, true).await;

        assert!(matches!(result, Err(LpmError::AuthRequired)));
    }
}
