use super::whoami_ui;
use crate::{auth, install_ui};
use lpm_common::{DEFAULT_REGISTRY_URL, LpmError};
use lpm_registry::{RegistryClient, client::AuthPosture};

pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    if !json_output && !client.has_bearer_for_posture(AuthPosture::AuthRequired)? {
        whoami_ui::phase_line(crate::install_ui::terminal_line!(
            "Not logged in to {}.",
            install_ui::url(client.base_url())
        ));
        whoami_ui::phase_line(crate::install_ui::terminal_line!(
            "Run {} to authenticate.",
            install_ui::dim(&login_command_for_registry(client.base_url()))
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
    let storage_status = active_auth_storage_status(client)?;

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
                "counted_storage_bytes": u.counted_storage_bytes,
                "private_packages": u.private_packages,
            })),
            "limits": user.limits.as_ref().map(|l| serde_json::json!({
                "storage_bytes": l.storage_bytes,
                "private_packages": l.private_packages,
            })),
            "storage_overage": user.storage_overage,
            "storage_excess_billed": user.storage_excess_billed,
            "orgs": user.organizations.iter().map(|o| serde_json::json!({
                "slug": o.slug,
                "name": o.name,
                "role": o.role,
            })).collect::<Vec<_>>(),
            "registries": build_registries_json(storage_status),
            "storage_backend": storage_status.backend_json_value(),
            "storage_degraded": storage_status.degraded,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
        return Ok(());
    }

    whoami_ui::detail("username", install_ui::yellow(display_name));
    if let Some(email_str) = email {
        let masked_email = mask_email_for_display(email_str);
        whoami_ui::detail("email", install_ui::dim(&masked_email));
    }

    // Plan & Pool
    if let Some(tier) = &user.plan_tier {
        whoami_ui::detail("plan", install_ui::yellow(&format_plan_tier(tier)));

        if user.has_pool_access == Some(true) {
            whoami_ui::detail("pool access", install_ui::status_ok("yes"));
        } else {
            whoami_ui::detail("pool access", "no");
        }
    }

    // 2FA
    if let Some(mfa) = user.mfa_enabled {
        let status = if mfa {
            install_ui::status_ok("yes")
        } else {
            install_ui::section("no")
        };
        whoami_ui::detail("mfa", &status);
    }

    if let Some(label) = storage_status.human_label() {
        whoami_ui::detail("secure storage backend:", label);
    }
    if storage_status.degraded {
        whoami_ui::warn(
            "Encrypted file fallback is active; unlock or repair the OS keychain, run `lpm logout`, then run `lpm login` again to use keychain storage.",
        );
    }

    // Usage & Limits
    if let Some(usage) = &user.usage {
        whoami_ui::blank_line();
        whoami_ui::section("usage");
        let storage = lpm_common::format_bytes(usage.storage_bytes);
        // What publishing does past the limit, as the Registry's publish
        // gate decides it. A Registry that doesn't say still refuses the
        // free plan's storage past its limit, but without saying how much
        // of it counts: packages whose sales exempt them don't, so only
        // that the refusal comes at the limit is claimed. Nothing is claimed
        // of other plans.
        let free_plan_unstated = user.storage_overage.is_none()
            && user
                .plan_tier
                .as_deref()
                .is_some_and(|tier| tier.eq_ignore_ascii_case("free"));
        let storage_overage = user.storage_overage.as_deref();
        let on_pro = user
            .plan_tier
            .as_deref()
            .is_some_and(|tier| tier.eq_ignore_ascii_case("pro"));
        // The storage limit's figure where storage is at or past it, so any
        // publish goes past it, and whether it's past.
        let mut full_storage = None;
        let mut over_storage = false;

        if let Some(limits) = &user.limits {
            // Storage
            if let Some(limit_bytes) = limits.storage_bytes {
                // The free plan's limit leaves out the storage of packages
                // whose sales exempt them, as publishing does; a Registry
                // that doesn't say how much counts is shown all of it.
                let counted = usage
                    .counted_storage_bytes
                    .unwrap_or(usage.storage_bytes)
                    .min(usage.storage_bytes);
                let (used, limit) = lpm_common::format_quota(counted, limit_bytes);
                let storage_msg = with_usage_bar(format!("{used} / {limit}"), counted, limit_bytes);
                if counted >= limit_bytes {
                    full_storage = Some(limit.clone());
                }
                if counted <= limit_bytes {
                    whoami_ui::detail("storage", storage_msg);
                } else {
                    over_storage = true;
                    match storage_overage {
                        Some("billed") => {
                            whoami_ui::detail("storage", storage_msg);
                        }
                        Some("paused" | "blocked") => {
                            whoami_ui::warn_line(crate::install_ui::terminal_line!(
                                "Storage: {} (OVER LIMIT)",
                                storage_msg
                            ));
                        }
                        _ => {
                            whoami_ui::detail("storage", storage_msg);
                            whoami_ui::detail("limit", format!("past the {limit} limit"));
                        }
                    }
                }
                // At the limit too, so the publish that starts the overage
                // isn't its first notice.
                if counted >= limit_bytes && storage_overage == Some("billed") {
                    whoami_ui::detail(
                        "overage",
                        format!("storage past {limit} is billed per GiB a month, rounded up"),
                    );
                }
                if counted < usage.storage_bytes {
                    whoami_ui::detail(
                        "exempt",
                        format!(
                            "{} more, the tarballs of packages whose sales exempt them",
                            lpm_common::format_bytes(usage.storage_bytes - counted)
                        ),
                    );
                }
            } else {
                whoami_ui::detail("storage", storage);
            }

            // Package count
            if let Some(limit_pkgs) = limits.private_packages {
                if limit_pkgs == 0 || limit_pkgs == u32::MAX {
                    whoami_ui::detail(
                        "private pkgs",
                        format!("{} (Unlimited)", usage.private_packages),
                    );
                } else {
                    let pkg_msg = with_usage_bar(
                        format!("{} / {}", usage.private_packages, limit_pkgs),
                        usage.private_packages.into(),
                        limit_pkgs.into(),
                    );
                    if usage.private_packages > limit_pkgs {
                        whoami_ui::warn_line(crate::install_ui::terminal_line!(
                            "Private Packages: {} (OVER LIMIT)",
                            pkg_msg
                        ));
                    } else {
                        whoami_ui::detail("private pkgs", pkg_msg);
                    }
                }
            } else {
                whoami_ui::detail("private pkgs", format!("{}", usage.private_packages));
            }

            // The Registry refuses a new private package once the scope
            // holds its limit, and a publish once storage is at its own.
            let package_limit = limits
                .private_packages
                .filter(|&limit| limit > 0 && limit != u32::MAX);
            let packages_full = package_limit.is_some_and(|limit| usage.private_packages >= limit);
            let over_packages = package_limit.is_some_and(|limit| usage.private_packages > limit);
            // A Pro plan without a subscription, as staff grant one, has
            // nothing to bill storage on, and no subscription to take out.
            let unbilled_pro = on_pro && storage_overage == Some("blocked");
            let storage_refused =
                full_storage.is_some() && storage_overage == Some("blocked") && !unbilled_pro;

            match (&full_storage, storage_overage) {
                (Some(limit), Some("paused")) => {
                    whoami_ui::warn_line(crate::install_ui::terminal_line!(
                        "Publishing past {} is refused until billing is active again.",
                        limit.as_str()
                    ));
                    match (over_storage, user.storage_excess_billed) {
                        (true, Some(true)) => whoami_ui::warn(
                            "Storage already past it is still billed while the payment is retried.",
                        ),
                        (true, Some(false)) => {
                            whoami_ui::warn("Storage already past it isn't billed meanwhile.")
                        }
                        _ => {}
                    }
                    whoami_ui::warn("Manage billing: https://lpm.dev/dashboard/settings/billing");
                }
                (Some(limit), Some("blocked")) if unbilled_pro => {
                    whoami_ui::warn_line(crate::install_ui::terminal_line!(
                        "Storage past {} isn't billed on this plan, so publishing to your personal scope past it is refused.",
                        limit.as_str()
                    ));
                }
                _ => {}
            }
            if (over_storage && storage_refused) || over_packages {
                whoami_ui::warn("Your account is over its plan limits.");
            }
            if let (Some(limit), true) = (&full_storage, storage_refused) {
                whoami_ui::warn_line(crate::install_ui::terminal_line!(
                    "Publishing to your personal scope is refused while its storage is at or past {}.",
                    limit.as_str()
                ));
            }
            if let (Some(limit), true) = (package_limit, packages_full) {
                whoami_ui::warn_line(crate::install_ui::terminal_line!(
                    "New private packages in your personal scope are refused once it holds {}.",
                    limit
                ));
            }
            let storage_may_be_refused = free_plan_unstated && full_storage.is_some();
            if let (Some(limit), true) = (&full_storage, storage_may_be_refused) {
                whoami_ui::warn_line(crate::install_ui::terminal_line!(
                    "Publishing to your personal scope is refused while its storage is at or past {}, apart from packages whose sales exempt them.",
                    limit.as_str()
                ));
            }
            if storage_refused || storage_may_be_refused || packages_full {
                whoami_ui::warn("Upgrade your plan: https://lpm.dev/dashboard/settings/billing");
            }
        } else {
            whoami_ui::detail("storage", storage);
            whoami_ui::detail("private pkgs", format!("{}", usage.private_packages));
        }
    }

    // Available Scopes
    whoami_ui::blank_line();
    whoami_ui::section("scopes");
    if let Some(profile) = &user.profile_username {
        whoami_ui::list_item(crate::install_ui::terminal_line!(
            "personal {}",
            install_ui::cyan(&format!("@lpm.dev/{profile}.*"))
        ));
    } else {
        whoami_ui::warn("personal scope not set (https://lpm.dev/dashboard/settings)");
    }

    if !user.organizations.is_empty() {
        whoami_ui::list_item(install_ui::TerminalLine::new("organizations"));
        for org in &user.organizations {
            let role = org.role.as_deref().unwrap_or("member");
            let role_label = if role.eq_ignore_ascii_case("admin") {
                install_ui::yellow_badge(role)
            } else {
                install_ui::dim(role)
            };
            whoami_ui::list_item(crate::install_ui::terminal_line!(
                "  {} {}",
                install_ui::cyan(&format!("@lpm.dev/{}.*", org.slug)),
                role_label
            ));
        }
    }

    // B4: Show external registries with stored tokens
    whoami_ui::blank_line();
    whoami_ui::section("registries");
    whoami_ui::registry("lpm.dev", "authenticated", true);
    let external_registries = auth::list_registry_auth_statuses();
    for registry in &external_registries {
        whoami_ui::registry(&registry.name, &registry.status, true);
    }

    // Show token expiry warnings
    let expiry_warnings = auth::check_token_expiry_warnings();
    for warning in &expiry_warnings {
        whoami_ui::warn_untrusted(warning);
    }
    whoami_ui::done("Identity loaded");
    Ok(())
}

/// Build the registries array for JSON output.
fn build_registries_json(lpm_storage: auth::AuthStorageStatus) -> Vec<serde_json::Value> {
    let mut regs = vec![serde_json::json!({
        "name": "lpm.dev",
        "status": "authenticated",
        "storage_backend": lpm_storage.backend_json_value(),
        "storage_degraded": lpm_storage.degraded,
    })];
    for registry in auth::list_registry_auth_statuses() {
        regs.push(serde_json::json!({
            "name": registry.name,
            "status": registry.status,
            "storage_backend": registry.storage.backend_json_value(),
            "storage_degraded": registry.storage.degraded,
        }));
    }
    regs
}

fn active_auth_storage_status(
    client: &RegistryClient,
) -> Result<auth::AuthStorageStatus, LpmError> {
    let Some(session) = client.session() else {
        return Ok(auth::AuthStorageStatus::none());
    };

    Ok(match session.current_source()? {
        Some(auth::TokenSource::StoredSession) => auth::auth_storage_status(session.registry_url()),
        _ => auth::AuthStorageStatus::none(),
    })
}

fn login_command_for_registry(registry_url: &str) -> String {
    if registry_url.trim_end_matches('/') == DEFAULT_REGISTRY_URL.trim_end_matches('/') {
        "`lpm login`".to_string()
    } else {
        format!("`lpm login --registry {registry_url}`")
    }
}

/// The plan's name as lpm.dev shows it: the free plan is Hobby.
fn format_plan_tier(tier: &str) -> String {
    match tier.to_ascii_lowercase().as_str() {
        "free" => "Hobby".to_string(),
        "org" => "Organization".to_string(),
        _ => {
            let mut chars = tier.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect(),
                None => String::new(),
            }
        }
    }
}

fn mask_email_for_display(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return email.to_string();
    };
    if local.is_empty() || domain.is_empty() {
        return email.to_string();
    }

    let mut chars = local.chars();
    let Some(first) = chars.next() else {
        return email.to_string();
    };
    match chars.next_back() {
        Some(last) => format!("{first}...{last}@{domain}"),
        None => format!("{first}...@{domain}"),
    }
}

fn with_usage_bar(message: String, used: u64, limit: u64) -> install_ui::TerminalLine {
    let bar = install_ui::usage_bar(used, limit, 10);
    if bar.is_empty() {
        crate::install_ui::terminal_line!("{}", message)
    } else {
        crate::install_ui::terminal_line!("{}  {}", message, bar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn names_each_plan_as_lpm_dev_does() {
        assert_eq!(format_plan_tier("free"), "Hobby");
        assert_eq!(format_plan_tier("FREE"), "Hobby");
        assert_eq!(format_plan_tier("pro"), "Pro");
        assert_eq!(format_plan_tier("org"), "Organization");
        assert_eq!(format_plan_tier(""), "");
    }

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
    fn whoami_client_auth_state_counts_refresh_token() {
        let (_home, _env) = scoped_home_dir();
        let registry = "https://whoami-refresh.test";

        auth::set_refresh_token(registry, "refresh-token").unwrap();
        let session = std::sync::Arc::new(lpm_auth::SessionManager::new(registry, None));
        let client = RegistryClient::new().with_session(session);

        assert!(
            client
                .has_bearer_for_posture(AuthPosture::AuthRequired)
                .unwrap()
        );
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

    #[test]
    fn mask_email_for_display_keeps_domain_and_edges_of_local_part() {
        assert_eq!(
            mask_email_for_display("tolgaergin@gmail.com"),
            "t...n@gmail.com"
        );
    }

    #[test]
    fn mask_email_for_display_handles_single_character_local_part() {
        assert_eq!(mask_email_for_display("t@gmail.com"), "t...@gmail.com");
    }

    #[test]
    fn mask_email_for_display_leaves_non_email_values_unchanged() {
        assert_eq!(mask_email_for_display("tolga"), "tolga");
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
