use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

/// Run the `lpm tunnel` command.
///
/// Actions:
///   (default) — start a tunnel to expose a local port
///   claim     — claim a domain (e.g., acme-api.lpm.llc)
///   unclaim   — release a claimed domain
///   list      — list claimed domains
///   domains   — list available base domains
pub async fn run(
	client: &RegistryClient,
	action: &str,
	token: Option<&str>,
	port: u16,
	subdomain: Option<&str>,
	org: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	match action {
		"claim" => run_claim(client, subdomain, org, json_output).await,
		"unclaim" | "release" => run_unclaim(client, subdomain, org, json_output).await,
		"list" | "ls" => run_list(client, org, json_output).await,
		"domains" => run_domains(client, json_output).await,
		"start" | "" => run_start(token, port, subdomain, json_output).await,
		_ => {
			// If action looks like a port number, treat as start
			if let Ok(p) = action.parse::<u16>() {
				return run_start(token, p, subdomain, json_output).await;
			}
			Err(LpmError::Tunnel(format!(
				"unknown action '{action}'. Available: claim, unclaim, list, domains, or a port number"
			)))
		}
	}
}

/// Start a tunnel to expose a local port.
async fn run_start(
	token: Option<&str>,
	port: u16,
	domain: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	let token = token.ok_or_else(|| {
		LpmError::Tunnel("authentication required. Run `lpm login` first.".into())
	})?;

	let options = lpm_tunnel::client::TunnelOptions {
		relay_url: lpm_tunnel::DEFAULT_RELAY_URL.to_string(),
		token: token.to_string(),
		local_port: port,
		domain: domain.map(|s| s.to_string()),
		tunnel_auth: None,
	};

	if !json_output {
		output::info(&format!("connecting tunnel for localhost:{port}..."));
	}

	lpm_tunnel::client::connect(
		&options,
		|session| {
			if json_output {
				println!(
					"{}",
					serde_json::json!({
						"tunnel_url": session.tunnel_url,
						"domain": session.domain,
						"local_port": session.local_port,
						"session_id": session.session_id,
					})
				);
			} else {
				println!();
				println!(
					"  {} {}",
					"●".green(),
					format!(
						"Tunnel: {} → localhost:{}",
						session.tunnel_url.bold(),
						session.local_port
					)
					.green()
				);
				println!();
				output::field("domain", &session.domain);
				output::field("session", &session.session_id);
				println!("  {}", "Press Ctrl+C to stop the tunnel".dimmed());
				println!();
			}
		},
		|msg| {
			if !json_output {
				output::warn(msg);
			}
		},
	)
	.await?;

	Ok(())
}

/// Claim a tunnel domain (e.g., acme-api.lpm.llc).
async fn run_claim(
	client: &RegistryClient,
	domain: Option<&str>,
	org: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	let domain = domain.ok_or_else(|| {
		LpmError::Tunnel(
			"missing domain. Usage: lpm tunnel claim <domain>\n  Example: lpm tunnel claim acme-api.lpm.llc".into(),
		)
	})?;

	// Validate: must contain a dot (full domain required)
	if !domain.contains('.') {
		return Err(LpmError::Tunnel(format!(
			"'{domain}' is not a full domain. Use: {domain}.lpm.fyi or {domain}.lpm.llc\n  Run `lpm tunnel domains` to see available base domains"
		)));
	}

	let result = client.tunnel_claim(domain, org).await?;

	if json_output {
		println!("{result}");
	} else {
		let url = result["url"].as_str().unwrap_or("");
		output::success(&format!("claimed {}", url.bold()));
		if let Some(org_name) = org {
			output::field("org", org_name);
		}
	}

	Ok(())
}

/// Release a claimed tunnel domain.
async fn run_unclaim(
	client: &RegistryClient,
	domain: Option<&str>,
	org: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	let domain = domain.ok_or_else(|| {
		LpmError::Tunnel("missing domain. Usage: lpm tunnel unclaim <domain>".into())
	})?;

	client.tunnel_unclaim(domain, org).await?;

	if json_output {
		println!("{}", serde_json::json!({ "released": true, "domain": domain }));
	} else {
		output::success(&format!("released {}", domain.bold()));
	}

	Ok(())
}

/// List claimed tunnel domains.
async fn run_list(
	client: &RegistryClient,
	org: Option<&str>,
	json_output: bool,
) -> Result<(), LpmError> {
	let result = client.tunnel_list(org).await?;

	if json_output {
		println!("{result}");
		return Ok(());
	}

	let domains = result["domains"].as_array();
	let limit = result["limit"].as_u64().unwrap_or(0);
	let used = result["used"].as_u64().unwrap_or(0);

	if let Some(org_name) = org {
		output::header(&format!("Tunnel Domains — {org_name}"));
	} else {
		output::header("Tunnel Domains");
	}

	println!("  {} of {} used", used.to_string().bold(), limit);
	println!();

	match domains {
		Some(doms) if !doms.is_empty() => {
			for d in doms {
				let domain = d["domain"].as_str().unwrap_or("?");
				let url = d["url"].as_str().unwrap_or("?");
				let base = d["baseDomain"].as_str().unwrap_or("?");
				println!(
					"  {} {} {}",
					"●".cyan(),
					url.bold(),
					format!("({base})").dimmed()
				);
			}
		}
		_ => {
			println!("  {}", "No domains claimed".dimmed());
			println!(
				"  {}",
				"Claim one with: lpm tunnel claim <name>.lpm.llc".dimmed()
			);
		}
	}

	println!();
	Ok(())
}

/// List available base domains.
async fn run_domains(
	client: &RegistryClient,
	json_output: bool,
) -> Result<(), LpmError> {
	let result = client.tunnel_available_domains().await?;

	if json_output {
		println!("{result}");
		return Ok(());
	}

	output::header("Available Tunnel Domains");
	println!();

	if let Some(domains) = result["domains"].as_array() {
		for d in domains {
			let domain = d["domain"].as_str().unwrap_or("?");
			let plan = d["planRequired"].as_str().unwrap_or("?");
			let plan_badge = if plan == "free" {
				"free".green().to_string()
			} else {
				"pro".cyan().to_string()
			};
			println!("  {} {:<15} {}", "●".green(), domain, plan_badge);
		}
	}

	println!();
	Ok(())
}
