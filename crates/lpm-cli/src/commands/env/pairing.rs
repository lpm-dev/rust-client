use super::prelude::*;

/// Parsed positional + flag form of `lpm env pair`. Two fields:
/// the validated `code` (uppercase, 6 ASCII alphanumeric) and a `yes`
/// flag that bypasses the interactive verification prompt.
#[derive(Debug)]
struct PairArgs {
    code: String,
    yes: bool,
}

fn parse_pair_args(args: &[&str]) -> Result<PairArgs, LpmError> {
    let mut yes = false;
    let mut code: Option<String> = None;
    for arg in args {
        match *arg {
            "--yes" | "-y" => yes = true,
            other if other.starts_with('-') => {
                return Err(LpmError::Script(format!(
                    "unknown flag '{other}' for `lpm env pair`. Supported flags: --yes/-y."
                )));
            }
            other => {
                if code.is_some() {
                    return Err(LpmError::Script(
                        "usage: lpm env pair <CODE> [--yes]\n  Only one pairing code may be passed."
                            .into(),
                    ));
                }
                code = Some(other.to_string());
            }
        }
    }
    let code = code.ok_or_else(|| {
        LpmError::Script(
            "usage: lpm env pair <CODE> [--yes]\n  The 6-character pairing code shown in the dashboard."
                .into(),
        )
    })?;
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(LpmError::Script(
            "invalid pairing code. Expected 6 alphanumeric characters (e.g., ABC123).".into(),
        ));
    }
    Ok(PairArgs {
        code: code.to_ascii_uppercase(),
        yes,
    })
}

/// View-model for the binding-confirmation block printed before every
/// pair approval — interactive or `--yes`. Captures the four values the
/// user needs to glance-compare against the dashboard, plus the three
/// server-side facts that help spot a stranger's session.
struct PairConfirmationView {
    code: String,
    fingerprint: Option<String>,
    match_number: String,
    device_label: Option<String>,
    created_at: Option<String>,
    created_from_ip: Option<String>,
}

impl PairConfirmationView {
    fn new(
        code: &str,
        browser_pub_b64: &str,
        match_number: String,
        session: &lpm_vault::sync::PairingSession,
    ) -> Self {
        Self {
            code: code.to_string(),
            fingerprint: lpm_vault::crypto::browser_key_fingerprint(browser_pub_b64),
            match_number,
            device_label: session
                .device_label
                .as_deref()
                .map(|s| bounded_server_field(s, 80)),
            created_at: session
                .created_at
                .as_deref()
                .map(|s| bounded_server_field(s, 64)),
            created_from_ip: session
                .created_from_ip
                .as_deref()
                .map(|s| bounded_server_field(s, 64)),
        }
    }
}

fn bounded_server_field(value: &str, max_len: usize) -> String {
    let safe = lpm_common::sanitize_terminal_inline(value);
    if safe.chars().count() <= max_len {
        safe.into_owned()
    } else {
        let mut bounded = String::with_capacity(safe.len().min(max_len) + '…'.len_utf8());
        bounded.extend(safe.chars().take(max_len));
        bounded.push('…');
        bounded
    }
}

fn print_pair_confirmation(view: &PairConfirmationView) {
    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  {}",
            install_ui::bold("Pair this browser for env access?")
        )
    );
    println!();
    println!(
        "{}",
        install_ui::terminal_line!("    {}: {}", install_ui::dim("Code"), &view.code)
    );
    match &view.fingerprint {
        Some(fp) => println!(
            "{}",
            install_ui::terminal_line!(
                "    {}: {}",
                install_ui::dim("Browser key fingerprint"),
                fp
            )
        ),
        None => println!(
            "{}",
            install_ui::terminal_line!(
                "    {}: {}",
                install_ui::dim("Browser key fingerprint"),
                install_ui::red("unavailable (server returned an invalid key)")
            )
        ),
    }
    if let Some(label) = &view.device_label
        && !label.is_empty()
    {
        println!(
            "{}",
            install_ui::terminal_line!("    {}: {}", install_ui::dim("Device"), label)
        );
    }
    if let Some(created_at) = &view.created_at {
        println!(
            "{}",
            install_ui::terminal_line!("    {}: {}", install_ui::dim("Created"), created_at)
        );
    }
    if let Some(ip) = &view.created_from_ip {
        println!(
            "{}",
            install_ui::terminal_line!("    {}: {}", install_ui::dim("From IP"), ip)
        );
    }
    println!();
    println!(
        "{}",
        install_ui::terminal_line!(
            "  {} {}",
            install_ui::bold("Verify the dashboard shows the same number:"),
            install_ui::section(&view.match_number)
        )
    );
    println!();
}

/// Three-state decision parsed from a single line of stdin. `None` signals
/// "neither yes nor no" — the caller re-prompts so a single keystroke can't
/// accidentally approve a security-critical action.
#[derive(Debug, PartialEq, Eq)]
enum PairDecision {
    Approve,
    Decline,
}

fn parse_pair_decision(input: &str) -> Option<PairDecision> {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(PairDecision::Approve),
        "n" | "no" | "" => Some(PairDecision::Decline),
        _ => None,
    }
}

fn prompt_pair_confirmation() -> Result<(), LpmError> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut handle = stdin.lock();
    let mut line = String::new();
    loop {
        print!(
            "  {} {} ",
            "Type 'y' to approve, 'n' (or Enter) to abort:".bold(),
            "[y/N]".dimmed()
        );
        stdout
            .flush()
            .map_err(|e| LpmError::Script(format!("stdout flush failed: {e}")))?;
        line.clear();
        let bytes = handle
            .read_line(&mut line)
            .map_err(|e| LpmError::Script(format!("read from stdin failed: {e}")))?;
        if bytes == 0 {
            // EOF — treat as decline rather than approve.
            return Err(LpmError::Script(
                "pair aborted: no input received (stdin closed before a decision was made)".into(),
            ));
        }
        match parse_pair_decision(&line) {
            Some(PairDecision::Approve) => return Ok(()),
            Some(PairDecision::Decline) => {
                return Err(LpmError::Script(
                    "pair aborted by user. No wrapping key was sent.".into(),
                ));
            }
            None => {
                println!("  {}", "Please answer 'y' or 'n'.".yellow());
            }
        }
    }
}

pub(super) async fn env_pair(
    client: &lpm_registry::RegistryClient,
    args: &[&str],
    json_output: bool,
) -> Result<(), LpmError> {
    let parsed = parse_pair_args(args)?;

    super::auth::resolve_session_bearer(client).await?;

    // Refuse a non-interactive pair without --yes before sending the
    // social-engineered pairing code to the registry.
    if !parsed.yes {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return Err(LpmError::Script(
                "`lpm env pair` requires an interactive terminal so you can verify the \
                 browser identity. Re-run from a terminal directly (not from a pipe, \
                 heredoc, or CI), or pass `--yes` to skip the prompt (NOT recommended)."
                    .into(),
            ));
        }
    }

    output::info("fetching pairing session...");

    let session =
        super::auth::execute_sync_with_bearer(
            client,
            lpm_auth::AuthRequirement::SessionRequired,
            |registry_url, auth_token| {
                let code = parsed.code.clone();
                async move {
                    lpm_vault::sync::get_pairing_session(&registry_url, &auth_token, &code).await
                }
            },
        )
        .await?;

    if session.status != "pending" {
        return Err(LpmError::Script(format!(
            "pairing session is '{}' (expected 'pending'). The code may have expired or already been used.",
            session.status
        )));
    }

    let browser_pub_b64 = session
        .browser_public_key
        .clone()
        .ok_or_else(|| LpmError::Script("server did not return browser public key".into()))?;

    let protocol_version = session.protocol_version.unwrap_or(1);
    match protocol_version {
        1 => {
            let view = PairConfirmationView::new(
                &parsed.code,
                &browser_pub_b64,
                lpm_vault::crypto::legacy_pairing_match_number(&parsed.code, &browser_pub_b64),
                &session,
            );
            print_pair_confirmation(&view);
            confirm_pairing(&parsed)?;

            let wrapping_key =
                lpm_vault::crypto::get_or_create_wrapping_key().map_err(LpmError::Script)?;
            let (encrypted, ephemeral) =
                lpm_vault::crypto::p256_pair_wrap_key(&wrapping_key, &browser_pub_b64)
                    .map_err(LpmError::Script)?;
            super::auth::execute_sync_with_bearer(
                client,
                lpm_auth::AuthRequirement::SessionRequired,
                |registry_url, auth_token| {
                    let code = parsed.code.clone();
                    let encrypted = encrypted.clone();
                    let ephemeral = ephemeral.clone();
                    async move {
                        lpm_vault::sync::approve_pairing_legacy(
                            &registry_url,
                            &auth_token,
                            &code,
                            &encrypted,
                            &ephemeral,
                        )
                        .await
                    }
                },
            )
            .await?;
        }
        2 => {
            let exchange = lpm_vault::crypto::P256PairingKeyExchange::new(&browser_pub_b64)
                .map_err(LpmError::Script)?;
            let ephemeral = exchange.ephemeral_public_key_b64().to_string();
            super::auth::execute_sync_with_bearer(
                client,
                lpm_auth::AuthRequirement::SessionRequired,
                |registry_url, auth_token| {
                    let code = parsed.code.clone();
                    let ephemeral = ephemeral.clone();
                    async move {
                        lpm_vault::sync::stage_pairing(
                            &registry_url,
                            &auth_token,
                            &code,
                            &ephemeral,
                        )
                        .await
                    }
                },
            )
            .await?;

            let view = PairConfirmationView::new(
                &parsed.code,
                &browser_pub_b64,
                exchange.short_authentication_string(&parsed.code),
                &session,
            );
            print_pair_confirmation(&view);
            confirm_pairing(&parsed)?;

            let wrapping_key =
                lpm_vault::crypto::get_or_create_wrapping_key().map_err(LpmError::Script)?;
            let encrypted = exchange.wrap_key(&wrapping_key).map_err(LpmError::Script)?;
            super::auth::execute_sync_with_bearer(
                client,
                lpm_auth::AuthRequirement::SessionRequired,
                |registry_url, auth_token| {
                    let code = parsed.code.clone();
                    let encrypted = encrypted.clone();
                    let ephemeral = ephemeral.clone();
                    async move {
                        lpm_vault::sync::approve_pairing(
                            &registry_url,
                            &auth_token,
                            &code,
                            &encrypted,
                            &ephemeral,
                        )
                        .await
                    }
                },
            )
            .await?;
        }
        version => {
            return Err(LpmError::Script(format!(
                "pairing protocol {version} is not supported by this CLI. Upgrade LPM and try again."
            )));
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "status": "paired" })
        );
    } else {
        println!();
        output::success("browser paired successfully");
        println!(
            "  {}",
            "The dashboard can now decrypt your env secrets.".dimmed()
        );
        println!();
    }
    Ok(())
}

fn confirm_pairing(parsed: &PairArgs) -> Result<(), LpmError> {
    if parsed.yes {
        output::warn(
            "--yes: skipped browser-identity verification. \
             Only safe when you typed this command yourself from a trusted dashboard.",
        );
        Ok(())
    } else {
        prompt_pair_confirmation()
    }
}

pub(super) async fn env_unpair(
    client: &lpm_registry::RegistryClient,
    json_output: bool,
) -> Result<(), LpmError> {
    output::info("revoking all browser pairings...");

    super::auth::execute_sync_with_bearer(
        client,
        lpm_auth::AuthRequirement::SessionRequired,
        |registry_url, auth_token| async move {
            lpm_vault::sync::unpair_all(&registry_url, &auth_token).await
        },
    )
    .await?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({ "success": true, "status": "revoked" })
        );
    } else {
        println!();
        output::success("all browser pairings revoked");
        println!(
            "  {}",
            "Paired browsers will need to re-pair to access secrets.".dimmed()
        );
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── env pair: argument parsing + decision + sanitization ─────────────

    #[test]
    fn parse_pair_args_accepts_lowercase_code_and_uppercases_it() {
        let parsed = parse_pair_args(&["abc123"]).expect("valid code must parse");
        assert_eq!(parsed.code, "ABC123");
        assert!(!parsed.yes);
    }

    #[test]
    fn parse_pair_args_recognizes_yes_flag_before_or_after_code() {
        let before = parse_pair_args(&["--yes", "ABC123"]).unwrap();
        let after = parse_pair_args(&["ABC123", "--yes"]).unwrap();
        let short = parse_pair_args(&["-y", "ABC123"]).unwrap();
        for parsed in [before, after, short] {
            assert_eq!(parsed.code, "ABC123");
            assert!(parsed.yes);
        }
    }

    #[test]
    fn parse_pair_args_rejects_missing_code() {
        assert!(parse_pair_args(&[]).is_err());
        assert!(parse_pair_args(&["--yes"]).is_err());
    }

    #[test]
    fn parse_pair_args_rejects_wrong_length_or_non_alnum_code() {
        assert!(parse_pair_args(&["ABC12"]).is_err()); // 5 chars
        assert!(parse_pair_args(&["ABC1234"]).is_err()); // 7 chars
        assert!(parse_pair_args(&["ABC!23"]).is_err()); // punctuation
        assert!(parse_pair_args(&["ABC 23"]).is_err()); // whitespace
    }

    #[test]
    fn parse_pair_args_rejects_duplicate_positional_args() {
        let err = parse_pair_args(&["ABC123", "DEF456"]).unwrap_err();
        let LpmError::Script(msg) = err else {
            panic!("expected Script error");
        };
        assert!(msg.contains("Only one pairing code"));
    }

    #[test]
    fn parse_pair_args_rejects_unknown_flags() {
        let err = parse_pair_args(&["--force", "ABC123"]).unwrap_err();
        let LpmError::Script(msg) = err else {
            panic!("expected Script error");
        };
        assert!(msg.contains("unknown flag '--force'"));
    }

    #[test]
    fn parse_pair_decision_treats_y_yes_case_insensitive_as_approve() {
        for input in ["y", "Y", "yes", "YES", "Yes", "y\n", "  y  "] {
            assert_eq!(
                parse_pair_decision(input),
                Some(PairDecision::Approve),
                "input {input:?} must be Approve"
            );
        }
    }

    #[test]
    fn parse_pair_decision_treats_n_no_and_empty_as_decline() {
        for input in ["n", "N", "no", "NO", "", "\n", "   "] {
            assert_eq!(
                parse_pair_decision(input),
                Some(PairDecision::Decline),
                "input {input:?} must be Decline"
            );
        }
    }

    #[test]
    fn parse_pair_decision_returns_none_for_ambiguous_input_so_caller_re_prompts() {
        for input in ["maybe", "ya", "approve", "abort", "1", "true"] {
            assert_eq!(
                parse_pair_decision(input),
                None,
                "input {input:?} must trigger re-prompt rather than decide"
            );
        }
    }

    #[test]
    fn bounded_server_field_neutralizes_terminal_controls() {
        // An attacker-controlled UA could embed \x1b[2J (clear screen) or
        // \x07 (BEL) to repaint the prompt — neither may remain executable.
        let dirty = "Chrome\x1b[2Jon macOS\x07";
        let clean = bounded_server_field(dirty, 80);
        assert_eq!(clean, "Chromeon macOS?");
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x07'));
    }

    #[test]
    fn bounded_server_field_truncates_with_ellipsis_at_char_boundary() {
        let label = "a".repeat(200);
        let clean = bounded_server_field(&label, 10);
        // 10 ASCII chars + "…" marker.
        assert_eq!(clean.chars().count(), 11);
        assert!(clean.ends_with('…'));
    }

    #[test]
    fn bounded_server_field_preserves_legitimate_user_agents() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15";
        let clean = bounded_server_field(ua, 80);
        assert_eq!(clean, ua);
    }

    #[test]
    fn pair_confirmation_view_uses_derived_sas_and_fingerprints_browser_key() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let pub_b64 = BASE64.encode([0xAAu8; 65]);
        let session = lpm_vault::sync::PairingSession {
            status: "pending".into(),
            protocol_version: Some(2),
            browser_public_key: Some(pub_b64.clone()),
            device_label: Some("Safari on iOS".into()),
            created_at: Some("2026-05-20T12:34:56Z".into()),
            created_from_ip: Some("203.0.113.0/24".into()),
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, "1234 5678".into(), &session);
        assert_eq!(view.code, "ABC123");
        assert_eq!(view.match_number, "1234 5678");
        assert!(view.fingerprint.is_some());
        assert_eq!(view.device_label.as_deref(), Some("Safari on iOS"));
        assert_eq!(view.created_at.as_deref(), Some("2026-05-20T12:34:56Z"));
        assert_eq!(view.created_from_ip.as_deref(), Some("203.0.113.0/24"));
    }

    #[test]
    fn pair_confirmation_view_sanitizes_attacker_controlled_device_label() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let pub_b64 = BASE64.encode([0u8; 65]);
        let session = lpm_vault::sync::PairingSession {
            status: "pending".into(),
            protocol_version: Some(2),
            browser_public_key: Some(pub_b64.clone()),
            device_label: Some("Chrome\x1b[2J\x07".into()),
            created_at: None,
            created_from_ip: None,
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, "1234 5678".into(), &session);
        let label = view.device_label.as_deref().unwrap_or_default();
        assert!(!label.contains('\x1b'));
        assert!(!label.contains('\x07'));
    }

    #[test]
    fn pair_confirmation_view_sanitizes_created_at_and_created_from_ip() {
        // Both fields ride the same `PairingSession` JSON response as
        // `device_label`, which the view already sanitizes. Without the
        // same defense on these two, a malicious or MITM-routed server
        // can embed cursor-manipulation escapes (`ESC [2A ESC [2K …`)
        // that erase the genuine fingerprint or match-number line above
        // and repaint a spoofed one — bypassing the visual confirmation
        // that is this command's headline defense.
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let pub_b64 = BASE64.encode([0u8; 65]);
        let session = lpm_vault::sync::PairingSession {
            status: "pending".into(),
            protocol_version: Some(2),
            browser_public_key: Some(pub_b64.clone()),
            device_label: None,
            created_at: Some("2026-05-20T12:34:56Z\x1b[2A\x1b[2K".into()),
            created_from_ip: Some("203.0.113.0/24\x07\x1b[1B".into()),
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, "1234 5678".into(), &session);
        let created_at = view.created_at.as_deref().unwrap_or_default();
        let ip = view.created_from_ip.as_deref().unwrap_or_default();
        for field in [created_at, ip] {
            assert!(
                !field.contains('\x1b'),
                "ESC must be stripped from {field:?}"
            );
            assert!(
                !field.contains('\x07'),
                "BEL must be stripped from {field:?}"
            );
            for c in field.chars() {
                assert!(
                    !c.is_control(),
                    "{field:?} retained control char {c:?} — server-supplied \
                     fields rendered to the terminal must all flow through \
                     the same sanitizer as device_label"
                );
            }
        }
    }
}
