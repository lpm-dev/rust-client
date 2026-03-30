use crate::{auth, output};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
	let user = client.whoami().await?;

	// API returns email in `username` (npm compat) and display name in `profile_username`.
	// Normalize for both JSON and human output.
	let display_name = user.profile_username.as_deref()
		.or(user.username.as_deref())
		.unwrap_or("unknown");
	let email = user.email.as_deref()
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

	println!();
	if let Some(email_str) = email {
		output::success(&format!("Logged in as {} — {}", display_name.bold(), email_str.dimmed()));
	} else {
		output::success(&format!("Logged in as {}", display_name.bold()));
	}

	// Plan & Pool
	if let Some(tier) = &user.plan_tier {
		println!();
		output::field("Plan", &tier.to_uppercase());

		if user.has_pool_access == Some(true) {
			output::success_inline("Pool", "Active");
		} else {
			output::field("Pool", "Not subscribed");
		}
	}

	// 2FA
	if let Some(mfa) = user.mfa_enabled {
		let status = if mfa {
			"enabled".green().to_string()
		} else {
			"disabled".yellow().to_string()
		};
		output::field("2FA", &status);
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
					output::warn(&format!("Storage: {} (OVER LIMIT)", storage_msg));
				} else {
					output::field("Storage", &storage_msg);
				}
			} else {
				output::field("Storage", &format!("{:.2}MB", storage_mb));
			}

			// Package count
			if let Some(limit_pkgs) = limits.private_packages {
				if limit_pkgs == 0 || limit_pkgs == u32::MAX {
					output::field(
						"Private Packages",
						&format!("{} (Unlimited)", usage.private_packages),
					);
				} else {
					let pkg_msg = format!("{} / {}", usage.private_packages, limit_pkgs);
					if usage.private_packages > limit_pkgs {
						output::warn(&format!("Private Packages: {} (OVER LIMIT)", pkg_msg));
					} else {
						output::field("Private Packages", &pkg_msg);
					}
				}
			} else {
				output::field(
					"Private Packages",
					&format!("{}", usage.private_packages),
				);
			}

			// Over-limit warning
			let over_storage = limits
				.storage_bytes
				.map(|l| usage.storage_bytes > l)
				.unwrap_or(false);
			let over_packages = limits
				.private_packages
				.map(|l| l > 0 && l != u32::MAX && usage.private_packages > l)
				.unwrap_or(false);

			if over_storage || over_packages {
				println!();
				output::warn("Your account is over its plan limits.");
				output::warn("Write access (publishing, inviting members) is restricted.");
				output::warn("Upgrade your plan: https://lpm.dev/dashboard/settings/billing");
			}
		} else {
			output::field("Storage", &format!("{:.2}MB", storage_mb));
			output::field(
				"Private Packages",
				&format!("{}", usage.private_packages),
			);
		}
	}

	// Available Scopes
	println!();
	output::header("Available Scopes");
	if let Some(profile) = &user.profile_username {
		println!("    Personal: {}", format!("@lpm.dev/{profile}.*").cyan());
	} else {
		output::warn("  Personal: Not set (https://lpm.dev/dashboard/settings)");
	}

	if !user.organizations.is_empty() {
		println!("    Organizations:");
		for org in &user.organizations {
			let role = org.role.as_deref().unwrap_or("member");
			println!(
				"      {} {}",
				format!("@lpm.dev/{}.*", org.slug).cyan(),
				format!("({role})").dimmed()
			);
		}
	}

	// B4: Show external registries with stored tokens
	let external_registries = auth::list_stored_registries();
	if !external_registries.is_empty() {
		println!();
		output::header("External Registries");
		for (name, status) in &external_registries {
			println!("    {} {}", format!("● {name}").cyan(), status.dimmed());
		}
	}

	// Show token expiry warnings
	let expiry_warnings = auth::check_token_expiry_warnings();
	for warning in &expiry_warnings {
		output::warn(warning);
	}

	println!();
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
