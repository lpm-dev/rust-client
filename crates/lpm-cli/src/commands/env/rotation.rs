use super::prelude::*;

pub(super) async fn env_rotate_key(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args
        .iter()
        .any(|arg| *arg == "--org" || arg.starts_with("--org="))
    {
        return Err(LpmError::Script(
            "`lpm env rotate-key` supports personal vaults only; organization key rotation is not available"
                .into(),
        ));
    }
    if let Some(argument) = args.first() {
        return Err(LpmError::Script(format!(
            "unknown rotate-key argument: {argument}"
        )));
    }

    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;

    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    let (raw_json, current_version) =
        lpm_vault::sync::pull_raw_for_rotation(&registry_url, &auth_token, &vault_id)
            .await
            .map_err(LpmError::Script)?;
    let environment_names = validate_rotation_payload(&raw_json).map_err(LpmError::Script)?;

    if !json_output {
        output::info("rotating vault encryption key...");
    }

    let result = lpm_vault::sync::push_raw(
        &registry_url,
        &auth_token,
        &vault_id,
        &raw_json,
        Some(current_version),
        false,
        None,
    )
    .await
    .map_err(LpmError::Script)?;

    let version = result
        .version
        .ok_or_else(|| LpmError::Script("rotation response omitted the new version".into()))?;
    lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
        .map_err(LpmError::Script)?;

    if json_output {
        super::response::print_json_value(&serde_json::json!({
            "success": true,
            "status": "rotated",
            "version": version,
            "environment_count": environment_names.len(),
            "environments": environment_names,
        }));
    } else {
        output::success_line(crate::install_ui::terminal_line!(
            "encryption key rotated (version {}, preserved {} environment{})",
            install_ui::bold(&version.to_string()),
            environment_names.len(),
            if environment_names.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        if !environment_names.is_empty() {
            output::info(&format!("preserved: {}", environment_names.join(", ")));
        }
    }
    Ok(())
}

fn validate_rotation_payload(raw_json: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|error| format!("remote vault payload is not valid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "remote vault payload must be a JSON object".to_string())?;

    if let Some(environments) = object.get("environments") {
        let environments = environments
            .as_object()
            .ok_or_else(|| "remote environments payload must be an object".to_string())?;
        let mut names = Vec::with_capacity(environments.len());
        for (name, values) in environments {
            if name.trim().is_empty() {
                return Err("remote environment names cannot be empty".to_string());
            }
            let values = values
                .as_object()
                .ok_or_else(|| format!("environment {name:?} must contain a key/value object"))?;
            if values.values().any(|value| value.as_str().is_none()) {
                return Err(format!(
                    "environment {name:?} contains a non-string secret value"
                ));
            }
            names.push(name.clone());
        }
        names.sort_unstable();
        return Ok(names);
    }

    if object.values().any(|value| value.as_str().is_none()) {
        return Err(
            "legacy flat remote vault payload contains a non-string secret value".to_string(),
        );
    }
    Ok(vec!["default".to_string()])
}

/// Shared classify-then-act helper for every org-vault flow that needs
/// the user's X25519 sharing keypair on the server (org `share`, org
/// `pull`). Closes the silent-overwrite vector the previous
/// `ensure_public_key` path enabled: that helper would happily upload
/// the local key over any server-stored key on first mismatch, so a
/// new device reading the user's auth token could rotate the user's
/// sharing key without re-authentication and without notification.
///
/// Three outcomes, mirroring the classifier enum:
///
///   - `Matches`: local key is already registered; return its private
///     half and let the caller proceed with the wrap operation.
///   - `NeedsInitialSet`: server has no key yet. Acquire a
///     `vault:public-key:set` step-up proof via the reauth flow
///     and upload the local public key. The user gets an out-of-band
///     security email confirming the registration. Return the private
///     half for the caller's wrap operation.
///   - `RotationRequired`: server has a DIFFERENT key. Refuse to
///     proceed and point the user at `lpm env rotate-sharing-key` —
///     the explicit, interactive, reauthed flow that handles the
///     blast-radius confirmation + email fan-out. The CLI MUST NOT
///     silently overwrite here; the server gate relies on the client
///     side to hold this contract.
pub(super) async fn ensure_sharing_key_ready_for_org_op(
    registry_url: &str,
    auth_token: &str,
    op_label: &str,
) -> Result<[u8; 32], LpmError> {
    use lpm_vault::sync::PublicKeyRegistrationState;
    let state = lpm_vault::sync::classify_public_key_state(registry_url, auth_token)
        .await
        .map_err(LpmError::Script)?;

    match state {
        PublicKeyRegistrationState::Matches(local) => Ok(local.private_key),
        PublicKeyRegistrationState::NeedsInitialSet(local) => {
            output::info(&format!(
                "no sharing key on file for this account; registering this device's key \
                 before continuing with `{op_label}`. You'll be prompted to confirm your \
                 password (and authenticator code, if enrolled) to authorize the write."
            ));
            let proof = crate::step_up::request_cli_step_up_proof(
                registry_url,
                auth_token,
                "vault:public-key:set",
            )
            .await
            .map_err(LpmError::Script)?;
            lpm_vault::sync::upload_public_key(
                registry_url,
                auth_token,
                &local.public_key_b64,
                Some(&proof),
            )
            .await
            .map_err(LpmError::Script)?;
            Ok(local.private_key)
        }
        PublicKeyRegistrationState::RotationRequired { .. } => Err(LpmError::Script(format!(
            "refusing to {op_label}: this device's sharing key does NOT match the key on \
                 the server. Silently overwriting the server-side key would invalidate every \
                 org teammate's wrapped access without your knowledge — exactly the attack \
                 surface the explicit rotation flow exists to close.\n\nIf you intentionally \
                 want to rotate your sharing key (e.g. you lost the previous device's key), \
                 run `lpm env rotate-sharing-key` here. That command prompts for step-up \
                 reauth, shows the blast radius, and sends an out-of-band security email \
                 before invalidating wrapped-key rows.",
        ))),
    }
}

/// Rotate the user's X25519 sharing keypair, with crash recovery and
/// explicit reauth before the server-side public key is replaced.
pub(super) async fn env_rotate_sharing_key(
    args: &[&str],
    json_output: bool,
) -> Result<(), LpmError> {
    use std::io::IsTerminal;

    // Non-interactive refusal — the prompt for typed confirmation +
    // password / TOTP cannot work without a TTY, and silently advancing
    // through stdin would either block forever or accept hostile input
    // piped from an unattended runner.
    let yes_skip = args.contains(&"--yes");
    if !std::io::stdin().is_terminal() || yes_skip {
        return Err(LpmError::Script(
            "`lpm env rotate-sharing-key` is an interactive recovery surface and \
             refuses to run without a TTY. Run it manually from your terminal."
                .into(),
        ));
    }

    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = super::auth::resolve_lpm_bearer(&registry_url, json_output).await?;

    // Crash recovery — if a pending key exists and matches the server,
    // the previous run committed the server side but didn't promote
    // locally. Promote and return; no second rotation needed.
    if let Some(pending) =
        lpm_vault::sync::read_pending_x25519_keypair().map_err(LpmError::Script)?
    {
        let server_key = lpm_vault::sync::get_my_public_key(&registry_url, &auth_token)
            .await
            .map_err(LpmError::Script)?;
        if server_key.as_deref() == Some(&pending.public_key_b64) {
            lpm_vault::sync::promote_pending_x25519_keypair().map_err(LpmError::Script)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "resumed",
                    })
                );
            } else {
                output::success(
                    "resumed pending sharing-key rotation: server already had the new key, \
                     promoted the local slot.",
                );
            }
            return Ok(());
        }
        // Pending exists but doesn't match server — last attempt failed
        // before the server committed. Discard the orphan so the next
        // step can re-generate.
        output::warn(
            "found a stale pending sharing-key from a prior failed rotation. Discarding it \
             and starting fresh.",
        );
        lpm_vault::sync::discard_pending_x25519_keypair().map_err(LpmError::Script)?;
    }

    // Show blast radius. We can't precompute it locally (we don't know
    // which orgs the user belongs to without a server roundtrip we'd
    // duplicate post-rotation), so the message names the EFFECT
    // honestly: every org vault wrapped to this user gets invalidated;
    // owners/admins of each affected org must re-share before pulls
    // resume.
    output::warn(
        "Rotating your sharing key invalidates EVERY org-vault wrapped-key entry stored \
         for you. Until an owner or admin of each affected org runs \
         `lpm env share --org <slug>` to re-wrap, you will not be able to pull those \
         vaults. The dashboard's Member Access view will show those rows as \"Needs share\".",
    );
    output::info(
        "An out-of-band security email will be sent to your account, and a separate \
         impact email to every affected org's owners + admins.",
    );

    let typed: String =
        cliclack::input("Type ROTATE (uppercase) to confirm. Any other input cancels.")
            .interact()
            .map_err(|e| LpmError::Script(format!("confirmation prompt failed: {e}")))?;
    if typed != "ROTATE" {
        return Err(LpmError::Script(
            "rotation cancelled — no server-side or local state changed.".into(),
        ));
    }

    // Acquire the step-up proof BEFORE generating the pending
    // key — a credential refusal must not leave a stale pending file
    // on disk.
    let proof = crate::step_up::request_cli_step_up_proof(
        &registry_url,
        &auth_token,
        "vault:public-key:rotate",
    )
    .await
    .map_err(LpmError::Script)?;

    let pending = lpm_vault::sync::create_pending_x25519_keypair().map_err(LpmError::Script)?;

    output::info("uploading new sharing key...");
    let response = lpm_vault::sync::upload_public_key(
        &registry_url,
        &auth_token,
        &pending.public_key_b64,
        Some(&proof),
    )
    .await;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            // Server-side write failed — discard the pending so the
            // next attempt starts from a clean slate.
            let _ = lpm_vault::sync::discard_pending_x25519_keypair();
            return Err(LpmError::Script(e));
        }
    };

    // Promote pending → live. A crash here leaves the pending slot
    // and the server-side new key, which the crash-recovery branch
    // at the top of this function will finish on the next run.
    lpm_vault::sync::promote_pending_x25519_keypair().map_err(LpmError::Script)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "status": response.status,
                "fingerprintPrefix": response.fingerprint_prefix,
                "previousFingerprintPrefix": response.previous_fingerprint_prefix,
                "invalidatedWrappedKeys": response.invalidated_wrapped_keys,
                "affectedOrgs": response.affected_orgs,
            })
        );
    } else {
        let fp = response
            .fingerprint_prefix
            .as_deref()
            .unwrap_or("(unknown)");
        let invalidated = response.invalidated_wrapped_keys.unwrap_or(0);
        let orgs = response.affected_orgs.unwrap_or(0);
        output::success_line(crate::install_ui::terminal_line!(
            "sharing key rotated. New fingerprint: {}.",
            install_ui::bold(fp)
        ));
        if invalidated > 0 || orgs > 0 {
            output::info(&format!(
                "Invalidated {invalidated} wrapped-key entries across {orgs} org(s). \
                 Ask an owner/admin of each affected org to re-share before pulling again."
            ));
        } else {
            output::info(
                "No org-vault wrapped keys were affected (you weren't sharing into any orgs \
                 yet).",
            );
        }
    }

    Ok(())
}
