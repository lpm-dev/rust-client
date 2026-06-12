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
    fn new(code: &str, browser_pub_b64: &str, session: &lpm_vault::sync::PairingSession) -> Self {
        Self {
            code: code.to_string(),
            fingerprint: lpm_vault::crypto::browser_key_fingerprint(browser_pub_b64),
            match_number: lpm_vault::crypto::pairing_match_number(code, browser_pub_b64),
            // Every server-supplied string that reaches the terminal must
            // go through the same sanitizer — partial coverage (e.g.
            // `device_label` only) lets a MITM'd or compromised server
            // embed cursor-manipulation escapes in a sibling field and
            // repaint the fingerprint / match-number lines.
            device_label: session
                .device_label
                .as_deref()
                .map(|s| sanitize_server_string(s, 80)),
            created_at: session
                .created_at
                .as_deref()
                .map(|s| sanitize_server_string(s, 64)),
            created_from_ip: session
                .created_from_ip
                .as_deref()
                .map(|s| sanitize_server_string(s, 64)),
        }
    }
}

/// Strip ASCII control bytes (including ANSI CSI escape introducers) and
/// truncate to `max_len` characters before rendering an attacker-influenced
/// server string to the terminal. Used for every field on `PairingSession`
/// that reaches `print_pair_confirmation` — `device_label` originates from
/// `navigator.userAgent.slice(0, 200)` on the dashboard side (attacker can
/// set it via a malicious browser extension or XSS on lpm.dev), and
/// `created_at` / `created_from_ip` are echoed verbatim from the server
/// response, which the pair-flow threat model explicitly treats as
/// potentially adversarial. Without this guard the prompt could be made to
/// scroll itself off-screen, repaint the fingerprint or match-number line,
/// or fake an "OK" confirmation glyph.
fn sanitize_server_string(value: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_len));
    let mut chars = 0usize;
    for c in value.chars() {
        if c.is_control() {
            continue;
        }
        if chars >= max_len {
            out.push('…');
            break;
        }
        out.push(c);
        chars += 1;
    }
    out
}

fn print_pair_confirmation(view: &PairConfirmationView) {
    println!();
    println!("  {}", "Pair this browser to your vault?".bold());
    println!();
    println!("    {}: {}", "Code".dimmed(), view.code);
    match &view.fingerprint {
        Some(fp) => println!("    {}: {}", "Browser key fingerprint".dimmed(), fp),
        None => println!(
            "    {}: {}",
            "Browser key fingerprint".dimmed(),
            "unavailable (server returned an invalid key)".red()
        ),
    }
    if let Some(label) = &view.device_label
        && !label.is_empty()
    {
        println!("    {}: {label}", "Device".dimmed());
    }
    if let Some(created_at) = &view.created_at {
        println!("    {}: {created_at}", "Created".dimmed());
    }
    if let Some(ip) = &view.created_from_ip {
        println!("    {}: {ip}", "From IP".dimmed());
    }
    println!();
    println!(
        "  {} {}",
        "Verify the dashboard shows the same number:".bold(),
        view.match_number.yellow().bold()
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

pub(super) async fn env_pair(args: &[&str], json_output: bool) -> Result<(), LpmError> {
    let parsed = parse_pair_args(&args[1..])?;

    let registry_url = lpm_common::resolve_lpm_registry_url();
    // Vault pairing requires a refresh-backed session. The
    // `SessionRequired` posture rejects `LPM_TOKEN`/`--token`/
    // CI/legacy tokens with the same message the old
    // `has_refresh_token` check produced.
    let auth_token = super::auth::resolve_session_bearer(&registry_url, json_output).await?;

    // Refuse a non-interactive pair without --yes BEFORE touching
    // the registry — a curl-piped-to-sh phishing payload should not
    // even leak the social-engineered code into server access logs.
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

    let session = lpm_vault::sync::get_pairing_session(&registry_url, &auth_token, &parsed.code)
        .await
        .map_err(LpmError::Script)?;

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

    let view = PairConfirmationView::new(&parsed.code, &browser_pub_b64, &session);

    // Render the binding info before any decision branch — both the
    // interactive prompt and the --yes audit trail get the same
    // attribution lines in the same shape.
    print_pair_confirmation(&view);

    if parsed.yes {
        output::warn(
            "--yes: skipped browser-identity verification. \
             Only safe when you typed this command yourself from a trusted dashboard.",
        );
    } else {
        prompt_pair_confirmation()?;
    }

    let wrapping_key = lpm_vault::crypto::get_or_create_wrapping_key().map_err(LpmError::Script)?;

    let (encrypted_wrapping_key, ephemeral_public_key) =
        lpm_vault::crypto::p256_pair_wrap_key(&wrapping_key, &browser_pub_b64)
            .map_err(LpmError::Script)?;

    lpm_vault::sync::approve_pairing(
        &registry_url,
        &auth_token,
        &parsed.code,
        &encrypted_wrapping_key,
        &ephemeral_public_key,
    )
    .await
    .map_err(LpmError::Script)?;

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
            "The dashboard can now decrypt your vault secrets.".dimmed()
        );
        println!();
    }
    Ok(())
}

pub(super) async fn env_unpair(json_output: bool) -> Result<(), LpmError> {
    let registry_url = lpm_common::resolve_lpm_registry_url();
    // Unpair revokes browser pairings — same session-backed
    // requirement as `pair`.
    let auth_token = super::auth::resolve_session_bearer(&registry_url, json_output).await?;

    output::info("revoking all browser pairings...");

    lpm_vault::sync::unpair_all(&registry_url, &auth_token)
        .await
        .map_err(LpmError::Script)?;

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
    fn sanitize_server_string_strips_ansi_csi_escape_introducers() {
        // An attacker-controlled UA could embed \x1b[2J (clear screen) or
        // \x07 (BEL) to repaint the prompt — must be stripped, not rendered.
        let dirty = "Chrome\x1b[2Jon macOS\x07";
        let clean = sanitize_server_string(dirty, 80);
        assert_eq!(clean, "Chrome[2Jon macOS");
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x07'));
    }

    #[test]
    fn sanitize_server_string_truncates_with_ellipsis_at_char_boundary() {
        let label = "a".repeat(200);
        let clean = sanitize_server_string(&label, 10);
        // 10 ASCII chars + "…" marker.
        assert_eq!(clean.chars().count(), 11);
        assert!(clean.ends_with('…'));
    }

    #[test]
    fn sanitize_server_string_preserves_legitimate_user_agents() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15";
        let clean = sanitize_server_string(ua, 80);
        assert_eq!(clean, ua);
    }

    #[test]
    fn pair_confirmation_view_derives_fingerprint_and_match_number_from_pubkey() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let pub_b64 = BASE64.encode([0xAAu8; 65]);
        let session = lpm_vault::sync::PairingSession {
            status: "pending".into(),
            browser_public_key: Some(pub_b64.clone()),
            device_label: Some("Safari on iOS".into()),
            created_at: Some("2026-05-20T12:34:56Z".into()),
            created_from_ip: Some("203.0.113.0/24".into()),
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, &session);
        assert_eq!(view.code, "ABC123");
        assert_eq!(view.match_number.len(), 2);
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
            browser_public_key: Some(pub_b64.clone()),
            device_label: Some("Chrome\x1b[2J\x07".into()),
            created_at: None,
            created_from_ip: None,
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, &session);
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
            browser_public_key: Some(pub_b64.clone()),
            device_label: None,
            created_at: Some("2026-05-20T12:34:56Z\x1b[2A\x1b[2K".into()),
            created_from_ip: Some("203.0.113.0/24\x07\x1b[1B".into()),
        };
        let view = PairConfirmationView::new("ABC123", &pub_b64, &session);
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
