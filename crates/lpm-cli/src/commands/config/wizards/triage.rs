use super::prelude::*;
use super::scripts::persist_script_policy;

const PRIVACY_LINE: &str = "Choosing a cloud advisor sends the package's lifecycle script text for review;      local advisors keep review on this machine.";

pub(in crate::commands::config) async fn run_triage_wizard(
    config_path: &std::path::Path,
    set: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    if let Some(v) = set {
        if !TRIAGE_ADVISOR_VALUES.contains(&v) {
            return Err(LpmError::Registry(format!(
                "invalid triage-advisor '{v}'; must be one of: {}",
                TRIAGE_ADVISOR_VALUES.join(" | ")
            )));
        }
        persist_string(config_path, TRIAGE_ADVISOR_KEY, v)?;
        announce_set(TRIAGE_ADVISOR_KEY, v, json_output);
        print_triage_advisor_followup(json_output);
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "lpm config triage requires a TTY; use `--set none|claude-cli|codex|ollama` instead"
                .to_string(),
        ));
    }

    // Cross-prompt: triage-advisor is inert unless script-policy = triage.
    let current_policy =
        read_string_value(config_path, SCRIPT_POLICY_KEY)?.unwrap_or_else(|| "deny".to_string());
    if current_policy != "triage" {
        println!();
        println!(
            "  {}: triage advisor only applies when script-policy = \"triage\". \
             Current policy: {}.",
            "note".cyan(),
            current_policy.yellow()
        );
        let switch = cliclack::confirm(r#"Switch script-policy to "triage" now?"#)
            .initial_value(false)
            .interact()
            .map_err(prompt_err)?;
        if switch {
            persist_script_policy(config_path, "triage", json_output)?;
            install_ui::done(&format!(
                "Done · {SCRIPT_POLICY_KEY} = {}",
                install_ui::section("\"triage\"")
            ));
        } else {
            println!(
                "  Leaving script-policy at {}. The triage-advisor value will be saved \
                 but stay inert until you switch policy.",
                current_policy.yellow()
            );
        }
    }

    // Detect available providers in parallel. Strict for Ollama
    // (binary + HTTP probe); `which`-style for the CLI providers.
    let reports = lpm_triage_advisor::probe_all().await;
    let detected: Vec<&lpm_triage_advisor::ProbeReport> =
        reports.iter().filter(|r| r.is_available()).collect();

    println!();
    println!("  {PRIVACY_LINE}");
    if detected.is_empty() {
        println!();
        println!(
            "  {}: no advisors detected on this machine (`claude` / `codex` / `ollama` \
             not on PATH or ollama daemon not running). You can still pick \"none\".",
            "note".cyan()
        );
    }

    // Build menu: detected first, then "none". Unavailable providers
    // are deliberately not listed (t3code's pattern — don't show
    // options the user can't pick).
    let mut sel = cliclack::select("Pick a triage advisor for amber-tier scripts:");
    for r in &detected {
        let (label, hint) = match r.provider {
            lpm_triage_advisor::Provider::Ollama => ("ollama", "local, no cloud egress"),
            lpm_triage_advisor::Provider::ClaudeCli => ("claude-cli", "cloud"),
            lpm_triage_advisor::Provider::Codex => ("codex", "cloud"),
        };
        sel = sel.item(r.provider.slug(), label, hint);
    }
    sel = sel.item("none", "none", "Layers 1-3 only (portable triage)");
    // Default to the first detected provider when available, else "none".
    let initial = detected.first().map_or("none", |r| r.provider.slug());
    let chosen_slug: &str = sel.initial_value(initial).interact().map_err(prompt_err)?;

    // Test-invoke when a real provider is chosen. Distinguish
    // EnvironmentNotReady (recoverable → save anyway) from
    // IntegrationFailure (block save per the locked contract).
    if let Some(provider) = lpm_triage_advisor::Provider::from_slug(chosen_slug) {
        match test_invoke_provider(provider).await {
            Ok(_) => println!("  {} test invoke OK", provider.slug().green()),
            Err(lpm_triage_advisor::AdvisorFailure::EnvironmentNotReady(msg)) => {
                println!(
                    "  {}: the advisor binary is present but didn't return a verdict ({msg})",
                    "environment not ready".yellow(),
                );
                let save = cliclack::confirm(
                    "Save this choice anyway? `lpm install` will degrade to no-advisor \
                     for any run where this provider isn't ready and print one warning; \
                     install never fails because the advisor failed.",
                )
                .initial_value(false)
                .interact()
                .map_err(prompt_err)?;
                if !save {
                    println!("  Aborted. No config change.");
                    return Ok(());
                }
            }
            Err(lpm_triage_advisor::AdvisorFailure::IntegrationFailure(msg)) => {
                return Err(LpmError::Registry(format!(
                    "advisor integration failure (no save): {msg}"
                )));
            }
        }
    }

    persist_string(config_path, TRIAGE_ADVISOR_KEY, chosen_slug)?;
    announce_set(TRIAGE_ADVISOR_KEY, chosen_slug, json_output);
    print_triage_advisor_followup(json_output);
    Ok(())
}

async fn test_invoke_provider(
    provider: lpm_triage_advisor::Provider,
) -> Result<lpm_triage_advisor::AdvisorVerdict, lpm_triage_advisor::AdvisorFailure> {
    use lpm_triage_advisor::{Advisor, ClaudeCliAdapter, CodexAdapter, OllamaAdapter};
    let adapter: Box<dyn Advisor> = match provider {
        lpm_triage_advisor::Provider::ClaudeCli => Box::new(ClaudeCliAdapter),
        lpm_triage_advisor::Provider::Codex => Box::new(CodexAdapter),
        lpm_triage_advisor::Provider::Ollama => Box::new(OllamaAdapter::default()),
    };
    adapter.test_invoke().await
}

pub(in crate::commands::config) fn print_triage_advisor_followup(json_output: bool) {
    if json_output {
        return;
    }
    println!(
        "  {}: `lpm install` preflights the advisor once per run. If it's \
         unavailable, the install degrades to no-advisor with one warning \
         and never fails on the advisor. The advisor only promotes amber \
         packages it returns Approve for, and the approval is ephemeral \
         (no persistent trust entry).",
        "note".cyan()
    );
}
