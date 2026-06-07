use crate::{auth_storage_notice, install_ui, output};
use futures::StreamExt;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use std::collections::HashMap;

/// Hard cap on platform-API response bodies (env / vault / OIDC
/// endpoints called from this module). Real payloads are kilobytes;
/// 10 MB leaves several orders of magnitude of headroom and prevents
/// a malicious / compromised platform endpoint from OOM-ing the CLI
/// on the `.json()` path.
const MAX_PLATFORM_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Drain a response body with a two-stage cap. Stage 1 refuses
/// pre-stream when `Content-Length` exceeds the cap; stage 2 aborts
/// mid-stream the moment another chunk would cross it.
async fn read_capped_platform_body(response: reqwest::Response) -> Result<Vec<u8>, LpmError> {
    if let Some(declared) = response.content_length()
        && declared as usize > MAX_PLATFORM_RESPONSE_BYTES
    {
        return Err(LpmError::Script(format!(
            "platform response too large: declared length {declared} exceeds cap {MAX_PLATFORM_RESPONSE_BYTES}"
        )));
    }
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| LpmError::Script(format!("response read error: {e}")))?;
        if buf.len().saturating_add(chunk.len()) > MAX_PLATFORM_RESPONSE_BYTES {
            return Err(LpmError::Script(format!(
                "platform response too large: streamed body exceeded cap {MAX_PLATFORM_RESPONSE_BYTES}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Parse a capped platform response as JSON. Used in success-path
/// reads where the caller wants typed parse errors back.
async fn parse_capped_platform_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, LpmError> {
    let buf = read_capped_platform_body(response).await?;
    serde_json::from_slice(&buf).map_err(|e| LpmError::Script(format!("parse error: {e}")))
}

/// Parse a capped platform response as JSON, falling back to a stub
/// `{"error": "unknown error"}` value on read / cap / parse failure.
/// Used on error-path reads where the caller only needs an `error`
/// field to display.
async fn parse_capped_platform_json_or_unknown(response: reqwest::Response) -> serde_json::Value {
    match read_capped_platform_body(response).await {
        Ok(buf) => serde_json::from_slice::<serde_json::Value>(&buf)
            .unwrap_or_else(|_| serde_json::json!({"error": "unknown error"})),
        Err(_) => serde_json::json!({"error": "unknown error"}),
    }
}

fn build_sync_environments(
    all_envs: &HashMap<String, HashMap<String, String>>,
    env_map: &HashMap<String, String>,
    environments: Option<&lpm_env::EnvironmentsConfig>,
) -> HashMap<String, HashMap<String, String>> {
    let mut ordered_envs: Vec<_> = all_envs
        .iter()
        .filter(|(_, secrets)| !secrets.is_empty())
        .map(|(storage_key, secrets)| {
            let resolved = lpm_env::resolver::resolve(storage_key, env_map, environments);
            let is_canonical_storage = resolved.canonical == *storage_key;
            (
                resolved.canonical,
                is_canonical_storage,
                storage_key.as_str(),
                secrets,
            )
        })
        .collect();

    ordered_envs.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(right.2))
    });

    let mut canonical_envs = HashMap::new();
    for (canonical, _is_canonical_storage, _storage_key, secrets) in ordered_envs {
        canonical_envs
            .entry(canonical)
            .or_insert_with(HashMap::new)
            .extend(secrets.clone());
    }

    canonical_envs
}

fn parse_remote_pull_payload_for_overwrite(
    raw_json: &str,
) -> Result<HashMap<String, HashMap<String, String>>, String> {
    if let Ok(wrapper) =
        serde_json::from_str::<HashMap<String, HashMap<String, HashMap<String, String>>>>(raw_json)
    {
        return Ok(wrapper.get("environments").cloned().unwrap_or_default());
    }

    if let Ok(remote_secrets) = serde_json::from_str::<HashMap<String, String>>(raw_json) {
        return Ok(HashMap::from([("default".to_string(), remote_secrets)]));
    }

    Err("failed to parse pulled vault data".to_string())
}

/// Read `lpm.json` for an `lpm env push` surface (personal or org).
///
/// Returns `Some(config)` on a clean parse and `None` when the file is
/// absent. When the file is present but malformed, emits a stderr warning
/// (and a tracing entry) then returns `None` rather than failing the push.
/// Push is the user's mainline action and a metadata read should never
/// block it; the stderr warning surfaces the silent-stale-schema failure
/// mode (push succeeds, server keeps last-known-good schema).
fn read_lpm_json_for_push(
    project_dir: &std::path::Path,
) -> Option<lpm_runner::lpm_json::LpmJsonConfig> {
    match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(opt) => opt,
        Err(e) => {
            output::warn(&format!(
                "lpm.json could not be parsed: {e}. Pushing without schema metadata; server keeps the last-known-good schema."
            ));
            tracing::warn!("lpm.json parse error during env push: {e}");
            None
        }
    }
}

/// Build the `schema` JSON value sent alongside a vault push.
///
/// Shape: `{ version: 2, envSchema?, envConfig?, environments? }`. The
/// dashboard renders these read-only so a teammate sees which keys are
/// required, secret, etc. Wire shape is identical for personal and org
/// vaults — the calling layer decides whether to send it. Returns `None`
/// when the project has no `lpm.json` (or it failed to parse — see
/// [`read_lpm_json_for_push`]).
fn build_push_schema_value(
    config: Option<&lpm_runner::lpm_json::LpmJsonConfig>,
) -> Option<serde_json::Value> {
    let c = config?;
    let mut obj = serde_json::Map::new();
    obj.insert("version".into(), serde_json::json!(2));

    // envSchema: flat var map (serialize .vars directly, not the EnvSchema wrapper)
    if let Some(env_schema) = &c.env_schema
        && let Ok(v) = serde_json::to_value(&env_schema.vars)
    {
        obj.insert("envSchema".into(), v);
    }

    // envConfig: alias → canonical mapping from lpm.json "env" field
    if !c.env.is_empty() {
        let env_config: serde_json::Map<_, _> = c
            .env
            .iter()
            .filter_map(|(alias, file_path)| {
                let mode = lpm_env::resolver::extract_mode_from_env_path(file_path)?;
                Some((
                    alias.clone(),
                    serde_json::json!({
                        "canonical": mode,
                        "file": file_path,
                    }),
                ))
            })
            .collect();
        obj.insert("envConfig".into(), serde_json::Value::Object(env_config));
    }

    // environments: inheritance config (extends, file, sensitive)
    if let Some(envs) = &c.environments
        && let Ok(v) = serde_json::to_value(envs)
    {
        obj.insert("environments".into(), v);
    }

    Some(serde_json::Value::Object(obj))
}

/// Resolve an LPM session bearer for env vault sync sites.
///
/// `lpm env` subcommands build their own reqwest client (long timeouts,
/// custom routing) so they don't get `RegistryClient::execute_with_recovery`
/// for free. This helper builds a local `SessionManager` (cheap,
/// local-only — no network) and asks it for a usable bearer.
///
/// `bearer_string_for` handles the refresh-only-state path internally:
/// if the cached access token is missing but a refresh token is on disk,
/// the silent refresh runs here. Subsequent calls within the same process
/// see the persisted rotated token, so constructing per-call instead of
/// threading a shared session is behaviorally equivalent for env's
/// single-shot usage pattern.
async fn resolve_lpm_bearer(registry_url: &str, json_output: bool) -> Result<String, LpmError> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
    session
        .bearer_string_for(lpm_auth::AuthRequirement::TokenRequired)
        .await
        .map_err(|_| LpmError::Script("not logged in. Run `lpm login` first".into()))
}

/// Vault-pairing variant that requires a real interactive login (not
/// `LPM_TOKEN`/`--token`/CI/legacy tokens). `SessionRequired` posture
/// maps directly to "source is `StoredSession`".
///
/// Distinguishes two failure modes so the user gets actionable text:
/// - **No session at all** (post-logout, never-logged-in): "not
///   logged in. Run `lpm login` first" — same message as
///   `resolve_lpm_bearer`.
/// - **Has a non-session token** (`LPM_TOKEN` / `--token` / CI /
///   legacy stored): the upgrade-to-session message.
async fn resolve_session_bearer(registry_url: &str, json_output: bool) -> Result<String, LpmError> {
    let session = auth_storage_notice::attach(
        lpm_auth::SessionManager::new(registry_url, None),
        json_output,
    );
    let has_any_source = session.current_source().is_some();
    session
        .bearer_string_for(lpm_auth::AuthRequirement::SessionRequired)
        .await
        .map_err(|_| {
            if has_any_source {
                LpmError::Script(
                    "your current login uses a legacy token that doesn't support vault pairing.\n  \
                     Run `lpm logout` then `lpm login` to upgrade to a session-based login."
                        .into(),
                )
            } else {
                LpmError::Script("not logged in. Run `lpm login` first".into())
            }
        })
}

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

/// Handle `lpm env` subcommands.
///
/// Local-file management (`set`, `get`, `list`, `delete`, `import`,
/// `export`, `print`, `copy`, `check`, `init`), cloud sync (`pull`,
/// `push`, `share`, `pair`, `diff`, `validate`), platform integrations
/// (`push --to <platform>`, `pull --from <platform>`, `connect`,
/// `status`), and OIDC policies (`oidc allow`, `oidc list`, `oidc pull`).
///
/// The `Env` clap variant captures everything after `lpm env` as `extra`
/// (trailing_var_arg), so this function re-parses raw argv to dispatch
/// on the subcommand.
pub async fn run(
    _client: &RegistryClient,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    // Re-parse args after `lpm env`
    let raw_args: Vec<String> = std::env::args().collect();
    let cmd_pos = raw_args.iter().position(|a| a == "env");
    let args: Vec<&str> = match cmd_pos {
        Some(pos) => raw_args[pos + 1..].iter().map(|s| s.as_str()).collect(),
        None => vec![],
    };

    if args.is_empty() {
        // Default: list keys
        vars_list(project_dir, None, false, json_output)?;
        return Ok(());
    }

    match args[0] {
        "set" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let pairs: Vec<(&str, &str)> = remaining
                .iter()
                .filter_map(|arg| arg.split_once('='))
                .collect();

            if pairs.is_empty() {
                return Err(LpmError::Script(
                    "usage: lpm env set [--env=<name>] KEY=VALUE [KEY2=VALUE2 ...]".into(),
                ));
            }

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            match &resolved_env {
                Some(env) => {
                    lpm_vault::set_env(project_dir, env, &pairs).map_err(LpmError::Script)?;
                }
                None => {
                    lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
                }
            }

            if json_output {
                let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
                println!(
                    "{}",
                    serde_json::json!({"success": true, "stored": keys, "env": env_label})
                );
            } else {
                for (key, _) in &pairs {
                    output::success(&format!("stored {} ({})", key.bold(), env_label));
                }
            }
        }

        "get" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let key = remaining
                .iter()
                .find(|a| **a != "--reveal")
                .ok_or_else(|| {
                    LpmError::Script("usage: lpm env get [--env=<name>] KEY [--reveal]".into())
                })?;
            let reveal = remaining.contains(&"--reveal");

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;

            let value = match &resolved_env {
                Some(env) => lpm_vault::try_get_env(project_dir, env, key),
                None => lpm_vault::try_get(project_dir, key),
            };
            let value = value.map_err(LpmError::Script)?;

            match value {
                Some(value) => {
                    if json_output {
                        if reveal {
                            println!("{}", serde_json::json!({"success": true, *key: value}));
                        } else {
                            println!("{}", serde_json::json!({"success": true, *key: "••••••••"}));
                        }
                    } else if reveal {
                        println!("{value}");
                    } else {
                        println!("{} = {}", key.bold(), "••••••••".dimmed());
                    }
                }
                None => {
                    return Err(LpmError::Script(format!("secret '{key}' not found")));
                }
            }
        }

        "list" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let reveal = remaining.contains(&"--reveal");
            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            vars_list(project_dir, resolved_env.as_deref(), reveal, json_output)?;
        }

        "delete" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let keys: Vec<&str> = remaining.to_vec();

            if keys.is_empty() {
                return Err(LpmError::Script(
                    "usage: lpm env delete [--env=<name>] KEY [KEY2 ...]".into(),
                ));
            }

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            match &resolved_env {
                Some(env) => {
                    lpm_vault::delete_env(project_dir, env, &keys).map_err(LpmError::Script)?;
                }
                None => {
                    lpm_vault::delete(project_dir, &keys).map_err(LpmError::Script)?;
                }
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "deleted": keys, "env": env_label})
                );
            } else {
                for key in &keys {
                    output::success(&format!("deleted {} ({})", key.bold(), env_label));
                }
            }
        }

        "import" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let file = remaining
                .iter()
                .find(|a| **a != "--overwrite")
                .ok_or_else(|| {
                    LpmError::Script(
                        "usage: lpm env import [--env=<name>] <file> [--overwrite]".into(),
                    )
                })?;
            let overwrite = remaining.contains(&"--overwrite");
            let path = project_dir.join(file);

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            let count = match &resolved_env {
                Some(env) => lpm_vault::import_env_file_to_env(project_dir, env, &path, overwrite)
                    .map_err(LpmError::Script)?,
                None => lpm_vault::import_env_file(project_dir, &path, overwrite)
                    .map_err(LpmError::Script)?,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "imported": count, "from": *file, "env": env_label})
                );
            } else {
                output::success(&format!(
                    "imported {} secret{} from {} ({})",
                    count.to_string().bold(),
                    if count == 1 { "" } else { "s" },
                    file.cyan(),
                    env_label
                ));
            }
        }

        "export" => {
            let (env_input, remaining) = parse_env_flag(&args[1..])?;
            let file = remaining.first().ok_or_else(|| {
                LpmError::Script("usage: lpm env export [--env=<name>] <file>".into())
            })?;
            let path = project_dir.join(file);

            let (resolved_env, _config) = resolve_env_from_flag(env_input, project_dir)?;
            let env_label = resolved_env.as_deref().unwrap_or("default");

            let count = match &resolved_env {
                Some(env) => lpm_vault::export_env_file_from_env(project_dir, env, &path)
                    .map_err(LpmError::Script)?,
                None => lpm_vault::export_env_file(project_dir, &path).map_err(LpmError::Script)?,
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "exported": count, "to": *file, "env": env_label})
                );
            } else {
                output::success(&format!(
                    "exported {} secret{} to {} ({})",
                    count.to_string().bold(),
                    if count == 1 { "" } else { "s" },
                    file.cyan(),
                    env_label
                ));
            }
        }

        "push" => {
            // Route to platform push if --to flag is present
            if args.iter().any(|a| a.starts_with("--to")) {
                return vars_platform_push(&args[1..], project_dir, json_output).await;
            }

            let force = args.contains(&"--force");
            let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
                LpmError::Script("no vault configured. Run `lpm env set` first".into())
            })?;

            let all_envs =
                lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
            let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
            if total_keys == 0 {
                return Err(LpmError::Script("vault is empty, nothing to push".into()));
            }

            let config = read_lpm_json_for_push(project_dir);
            let empty_env_map = HashMap::new();
            let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let non_empty_envs = build_sync_environments(&all_envs, env_map, environments);

            let secrets_for_sync: HashMap<String, HashMap<String, HashMap<String, String>>> = {
                let mut wrapper = HashMap::new();
                wrapper.insert("environments".to_string(), non_empty_envs.clone());
                wrapper
            };

            let project_name = lpm_vault::vault_id::read_project_name(project_dir);

            // Confirmation prompt
            if !yes && !json_output {
                output::warn("this will overwrite the cloud vault with your local secrets");
                output::field("project", &project_name);
                output::field("environments", &format!("{}", all_envs.len()));
                output::field("total keys", &format!("{}", total_keys));
                if force {
                    output::field("mode", "force (overwrite regardless of version)");
                }
                let confirm = cliclack::confirm("Continue?")
                    .initial_value(false)
                    .interact()
                    .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
                if !confirm {
                    output::info("cancelled");
                    return Ok(());
                }
            }

            let registry_url = lpm_common::resolve_lpm_registry_url();
            let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

            output::info("pushing vault to cloud...");

            let secrets_json = serde_json::to_string(&secrets_for_sync)
                .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

            let schema_value = build_push_schema_value(config.as_ref());

            let push_metadata = lpm_vault::sync::PushMetadata {
                name: Some(&project_name),
                schema: schema_value.as_ref(),
            };
            let expected_version = expected_personal_sync_version(project_dir, force);

            let result = lpm_vault::sync::push_raw(
                &registry_url,
                &auth_token,
                &vault_id,
                &secrets_json,
                expected_version,
                force,
                Some(&push_metadata),
            )
            .await
            .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": result.status,
                        "version": result.version,
                    })
                );
            } else {
                output::success(&format!(
                    "vault synced (version {})",
                    result.version.unwrap_or(0).to_string().bold()
                ));
            }
        }

        "pull" => {
            // Route to platform pull if --from flag is present
            if args.iter().any(|a| a.starts_with("--from")) {
                return vars_platform_pull(&args[1..], project_dir, json_output).await;
            }

            // Route to OIDC pull if --oidc flag is present
            if args.contains(&"--oidc") {
                return vars_oidc_pull(&args[1..], project_dir, json_output).await;
            }

            let yes = args.iter().any(|a| *a == "--yes" || *a == "-y");
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());

            let vault_id = lpm_vault::vault_id::get_or_create_vault_id(project_dir)
                .map_err(LpmError::Script)?;

            // Org pull: different flow with X25519 decryption
            if let Some(org_slug) = org_flag {
                let registry_url = lpm_common::resolve_lpm_registry_url();
                let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

                // Classify the sharing-key state before fetching the
                // wrapped vault. RotationRequired refuses silent
                // overwrite and routes the user to
                // `lpm env rotate-sharing-key`; NeedsInitialSet prompts
                // for step-up reauth and registers the local key.
                let private_key =
                    ensure_sharing_key_ready_for_org_op(&registry_url, &auth_token, "pull").await?;

                output::info(&format!("pulling vault from org {}...", org_slug.bold()));

                let (raw_json, version) = lpm_vault::sync::pull_org(
                    &registry_url,
                    &auth_token,
                    org_slug,
                    &vault_id,
                    &private_key,
                )
                .await
                .map_err(LpmError::Script)?;

                // Same merge logic as personal pull
                let total_keys;
                if let Ok(wrapper) = serde_json::from_str::<
                    std::collections::HashMap<
                        String,
                        std::collections::HashMap<
                            String,
                            std::collections::HashMap<String, String>,
                        >,
                    >,
                >(&raw_json)
                {
                    if let Some(remote_envs) = wrapper.get("environments") {
                        let mut total = 0;
                        for (env_name, remote_secrets) in remote_envs {
                            let mut env = lpm_vault::try_get_all_env(project_dir, env_name)
                                .map_err(LpmError::Script)?;
                            env.extend(remote_secrets.clone());
                            total += env.len();
                            let pairs: Vec<(&str, &str)> =
                                env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                            lpm_vault::set_env(project_dir, env_name, &pairs)
                                .map_err(LpmError::Script)?;
                        }
                        total_keys = total;
                    } else {
                        total_keys = 0;
                    }
                } else if let Ok(remote_secrets) =
                    serde_json::from_str::<std::collections::HashMap<String, String>>(&raw_json)
                {
                    let mut merged =
                        lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;
                    merged.extend(remote_secrets);
                    total_keys = merged.len();
                    let pairs: Vec<(&str, &str)> = merged
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
                } else {
                    return Err(LpmError::Script("failed to parse pulled vault data".into()));
                }

                lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
                    .map_err(LpmError::Script)?;

                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({"success": true, "status": "pulled", "org": org_slug, "version": version, "count": total_keys})
                    );
                } else {
                    output::success(&format!(
                        "pulled {} key{} from org {} (version {})",
                        total_keys.to_string().bold(),
                        if total_keys == 1 { "" } else { "s" },
                        org_slug.bold(),
                        version.to_string().bold()
                    ));
                }
                return Ok(());
            }

            let project_name = lpm_vault::vault_id::read_project_name(project_dir);
            let local_secrets = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

            // Confirmation prompt
            if !yes && !json_output {
                output::warn("this will overwrite your local secrets with the cloud vault");
                output::field("project", &project_name);
                output::field("local keys", &format!("{}", local_secrets.len()));
                let confirm = cliclack::confirm("Continue?")
                    .initial_value(false)
                    .interact()
                    .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
                if !confirm {
                    output::info("cancelled");
                    return Ok(());
                }
            }

            let registry_url = lpm_common::resolve_lpm_registry_url();
            let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

            output::info("pulling vault from cloud...");

            let (raw_json, version) =
                lpm_vault::sync::pull_raw(&registry_url, &auth_token, &vault_id)
                    .await
                    .map_err(LpmError::Script)?;

            let remote_envs =
                parse_remote_pull_payload_for_overwrite(&raw_json).map_err(LpmError::Script)?;
            let total_keys: usize = remote_envs.values().map(|env| env.len()).sum();
            lpm_vault::replace_all_environments(project_dir, &remote_envs)
                .map_err(LpmError::Script)?;

            lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                .map_err(LpmError::Script)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "pulled",
                        "version": version,
                        "count": total_keys,
                    })
                );
            } else {
                output::success(&format!(
                    "pulled {} key{} (version {})",
                    total_keys.to_string().bold(),
                    if total_keys == 1 { "" } else { "s" },
                    version.to_string().bold()
                ));
            }
        }

        "log" => {
            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
                .ok_or_else(|| LpmError::Script("no vault configured".into()))?;

            let registry_url = lpm_common::resolve_lpm_registry_url();
            let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

            let result =
                lpm_vault::sync::get_audit_log(&registry_url, &auth_token, &vault_id, None)
                    .await
                    .map_err(LpmError::Script)?;

            let entries = result.entries.unwrap_or_default();

            if json_output {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"success": true, "entries": entries.iter().map(|e| serde_json::json!({
					"action": e.action,
					"created_at": e.created_at,
				})).collect::<Vec<_>>()})).unwrap());
            } else if entries.is_empty() {
                output::info("No audit log entries");
            } else {
                output::info(&format!("Vault audit log ({} entries)", entries.len()));
                for entry in &entries {
                    println!(
                        "  {} {} {}",
                        entry.created_at.dimmed(),
                        entry.action.bold(),
                        entry.user_id.as_deref().unwrap_or("").dimmed()
                    );
                }
            }
        }

        "share" => {
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());
            let org_slug = org_flag
                .ok_or_else(|| LpmError::Script("usage: lpm env share --org <org-slug>".into()))?;

            // `--force` is not implemented on the share command. Before this
            // commit the flag was silently dropped, so a user resolving a
            // version conflict thought they were overwriting when they were
            // sending the same request again. Reject explicitly. An explicit
            // force surface for share is tracked as a separate change with
            // its own reauth-proof gate; the paired server PR's org 409
            // hints no longer mention --force.
            if args.contains(&"--force") {
                return Err(LpmError::Script(
                    "`lpm env share --force` is not supported. To resolve a version conflict run `lpm env pull --org <slug>` first, then retry the share.".into(),
                ));
            }

            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
                LpmError::Script("no vault configured. Run `lpm env set` first".into())
            })?;

            let all_envs =
                lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
            let total_keys: usize = all_envs.values().map(|e| e.len()).sum();
            if total_keys == 0 {
                return Err(LpmError::Script("vault is empty, nothing to share".into()));
            }

            let registry_url = lpm_common::resolve_lpm_registry_url();
            let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

            // Classify the sharing-key state before any wrap work. This
            // refuses the silent-overwrite path on RotationRequired and
            // prompts for step-up reauth on NeedsInitialSet, instead of
            // letting `push_org_with_keys`'s internal `ensure_public_key`
            // silently upload over whatever was on the server.
            ensure_sharing_key_ready_for_org_op(&registry_url, &auth_token, "share").await?;

            let config = read_lpm_json_for_push(project_dir);
            let empty_env_map = HashMap::new();
            let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let non_empty_envs = build_sync_environments(&all_envs, env_map, environments);
            let mut wrapper = std::collections::HashMap::new();
            wrapper.insert("environments".to_string(), non_empty_envs);
            let secrets_json = serde_json::to_string(&wrapper)
                .map_err(|e| LpmError::Script(format!("failed to serialize: {e}")))?;

            let project_name = lpm_vault::vault_id::read_project_name(project_dir);
            let schema_value = build_push_schema_value(config.as_ref());
            let push_metadata = lpm_vault::sync::PushMetadata {
                name: Some(&project_name),
                schema: schema_value.as_ref(),
            };

            output::info(&format!(
                "sharing vault with org {} ({} keys across {} environments)...",
                org_slug.bold(),
                total_keys,
                all_envs.len()
            ));

            let result = lpm_vault::sync::push_org_with_keys(
                &registry_url,
                &auth_token,
                org_slug,
                &vault_id,
                &secrets_json,
                expected_org_sync_version(project_dir, org_slug),
                Some(&push_metadata),
            )
            .await
            .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_org_sync_version(project_dir, org_slug, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": result.status,
                        "org": org_slug,
                        "version": result.version,
                    })
                );
            } else {
                output::success(&format!(
                    "vault shared with org {} (version {})",
                    org_slug.bold(),
                    result.version.unwrap_or(0).to_string().bold()
                ));
            }
        }

        "rotate-key" => {
            let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
                .ok_or_else(|| LpmError::Script("no vault configured".into()))?;

            let registry_url = lpm_common::resolve_lpm_registry_url();
            let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

            let secrets = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;
            if secrets.is_empty() {
                return Err(LpmError::Script("vault is empty, nothing to rotate".into()));
            }

            output::info("rotating vault encryption key...");

            // Re-encrypt with new key and push
            let result =
                lpm_vault::sync::push(&registry_url, &auth_token, &vault_id, &secrets, None, true)
                    .await
                    .map_err(LpmError::Script)?;

            if let Some(version) = result.version {
                lpm_vault::vault_id::write_personal_sync_version(project_dir, version)
                    .map_err(LpmError::Script)?;
            }

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "status": "rotated",
                        "version": result.version,
                    })
                );
            } else {
                output::success(&format!(
                    "encryption key rotated (version {})",
                    result.version.unwrap_or(0).to_string().bold()
                ));
            }
        }

        // Rotate the user's X25519 sharing keypair — the per-account key
        // that org members use to encrypt vault AES keys to this user.
        // DISTINCT from `rotate-key` (above), which rotates the
        // wrapping-key the personal-vault blob is encrypted under.
        //
        // Flow:
        //   1. Refuse if non-interactive (no TTY).
        //   2. Crash recovery: if a pending key exists and matches the
        //      server's current public key, the prior run committed the
        //      server-side rotation but didn't promote locally —
        //      finish the promotion and return.
        //   3. Generate a fresh keypair into the pending slot WITHOUT
        //      touching the live slot.
        //   4. Show blast radius + require typed `ROTATE` confirmation.
        //   5. Acquire a CLI step-up proof for
        //      `vault:public-key:rotate`.
        //   6. POST the new public key with the proof header.
        //   7. On 200, atomically promote the pending slot into the
        //      live slot. The server's response carries the counts of
        //      invalidated wrapped keys + affected orgs so the user
        //      knows which orgs will need to re-share before pulls
        //      resume.
        //
        // A failure between steps 5 and 6 leaves the pending slot but
        // no server-side change — the next `rotate-sharing-key`
        // invocation discards the stale pending and starts over.
        "rotate-sharing-key" => {
            return env_rotate_sharing_key(args, json_output).await;
        }

        "list-remote" | "ls-remote" => {
            let org_flag = args
                .iter()
                .position(|a| *a == "--org")
                .and_then(|i| args.get(i + 1).copied());
            return vars_list_remote(org_flag, json_output).await;
        }

        "diff" => {
            return vars_diff(&args[1..], project_dir, json_output).await;
        }

        "validate" => {
            let strict = args.contains(&"--strict");
            return vars_validate(project_dir, strict, json_output);
        }

        "example" => {
            let (env_input, _remaining) = parse_env_flag(&args[1..])?;
            return vars_example(project_dir, env_input, json_output);
        }

        "print" => {
            return vars_print(&args[1..], project_dir);
        }

        "check" => {
            return vars_check(project_dir, json_output);
        }

        "connect" => {
            return vars_connect(&args[1..], project_dir, json_output).await;
        }

        "oidc" => {
            return vars_oidc(&args[1..], project_dir, json_output).await;
        }

        "status" => {
            return vars_platform_status(project_dir, json_output).await;
        }

        "pair" => {
            let parsed = parse_pair_args(&args[1..])?;

            let registry_url = lpm_common::resolve_lpm_registry_url();
            // Vault pairing requires a refresh-backed session. The
            // `SessionRequired` posture rejects `LPM_TOKEN`/`--token`/
            // CI/legacy tokens with the same message the old
            // `has_refresh_token` check produced.
            let auth_token = resolve_session_bearer(&registry_url, json_output).await?;

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

            let session =
                lpm_vault::sync::get_pairing_session(&registry_url, &auth_token, &parsed.code)
                    .await
                    .map_err(LpmError::Script)?;

            if session.status != "pending" {
                return Err(LpmError::Script(format!(
                    "pairing session is '{}' (expected 'pending'). The code may have expired or already been used.",
                    session.status
                )));
            }

            let browser_pub_b64 = session.browser_public_key.clone().ok_or_else(|| {
                LpmError::Script("server did not return browser public key".into())
            })?;

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

            let wrapping_key =
                lpm_vault::crypto::get_or_create_wrapping_key().map_err(LpmError::Script)?;

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
        }

        "unpair" => {
            let registry_url = lpm_common::resolve_lpm_registry_url();
            // Unpair revokes browser pairings — same session-backed
            // requirement as `pair`.
            let auth_token = resolve_session_bearer(&registry_url, json_output).await?;

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
        }

        "init" => {
            let force = args.contains(&"--force");
            return vars_init(project_dir, force, json_output);
        }

        "ls" => {
            return vars_ls(project_dir, json_output);
        }

        "copy" | "cp" => {
            let remaining = &args[1..];
            if remaining.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm env copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            let overwrite = remaining.contains(&"--overwrite");
            let envs: Vec<&&str> = remaining.iter().filter(|a| **a != "--overwrite").collect();
            if envs.len() < 2 {
                return Err(LpmError::Script(
                    "usage: lpm env copy <source-env> <target-env> [--overwrite]".into(),
                ));
            }
            return vars_copy(project_dir, envs[0], envs[1], overwrite, json_output);
        }

        unknown => {
            return Err(LpmError::Script(format!(
                "unknown env action: '{unknown}'. Available: set, get, list, delete, import, export, push, pull, diff, validate, example, print, check, connect, status, log, share, rotate-key, rotate-sharing-key, pair, unpair, init, ls, copy"
            )));
        }
    }

    Ok(())
}

fn vars_example(
    project_dir: &std::path::Path,
    env_input: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

    let schema = config
        .as_ref()
        .and_then(|c| c.env_schema.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LpmError::Script(
                "no envSchema defined in lpm.json. Add an envSchema section first.".into(),
            )
        })?;

    // Resolve env name for the output filename — write path, use resolve_checked
    let (resolved_env, env_label, example_filename) = match env_input {
        Some(input) => {
            let empty = HashMap::new();
            let env_map = config.as_ref().map_or(&empty, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
                .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
            let filename = format!(".env.{}.example", resolved.canonical);
            let label = resolved.canonical.clone();
            (Some(resolved), label, filename)
        }
        None => (None, "default".to_string(), ".env.example".to_string()),
    };

    // Generate the example content
    let mut content = lpm_env::generate_env_example(schema);

    // If --env is specified, add a header comment noting the environment
    if let Some(ref env) = resolved_env {
        let header = format!(
            "# Environment: {}{}\n#\n",
            env.canonical,
            env.alias
                .as_ref()
                .map(|a| format!(" (lpm run {a})"))
                .unwrap_or_default()
        );
        content = header + &content;
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "variables": schema.len(),
                "environment": env_label,
                "filename": example_filename,
                "content": content,
            })
        );
        return Ok(());
    }

    let example_path = project_dir.join(&example_filename);
    std::fs::write(&example_path, &content)
        .map_err(|e| LpmError::Script(format!("failed to write {example_filename}: {e}")))?;

    output::success(&format!(
        "generated {} ({} variables)",
        example_filename.bold(),
        schema.len()
    ));

    Ok(())
}

/// `lpm env init` — interactive environment setup.
///
/// Detects lpm.json config, scans for .env files, imports each into
/// the correct vault environment, and creates empty envs for configured
/// environments without files.
fn vars_init(
    project_dir: &std::path::Path,
    force: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;

    // Build the list of environments to process
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    // Collect actions to perform
    struct InitAction {
        canonical: String,
        alias: Option<String>,
        file_path: Option<String>,
        file_exists: bool,
        file_var_count: usize,
        vault_exists: bool,
        vault_var_count: usize,
    }

    let mut actions: Vec<InitAction> = Vec::new();

    for env in &all_envs {
        let vault_vars = vault_envs.get(&env.canonical);
        let vault_exists = vault_vars.is_some_and(|v| !v.is_empty());
        let vault_var_count = vault_vars.map_or(0, |v| v.len());

        // Determine the .env file to check
        let file_path = env.file_path.clone().or_else(|| {
            if env.canonical == "default" {
                Some(".env".to_string())
            } else {
                Some(format!(".env.{}", env.canonical))
            }
        });

        let (file_exists, file_var_count) = if let Some(ref fp) = file_path {
            let abs = project_dir.join(fp);
            if abs.exists() {
                let content = std::fs::read_to_string(&abs).unwrap_or_default();
                let count = lpm_vault::parse_env_content(&content).len();
                (true, count)
            } else {
                (false, 0)
            }
        } else {
            (false, 0)
        };

        actions.push(InitAction {
            canonical: env.canonical.clone(),
            alias: env.alias.clone(),
            file_path,
            file_exists,
            file_var_count,
            vault_exists,
            vault_var_count,
        });
    }

    if json_output {
        let json_actions: Vec<serde_json::Value> = actions
            .iter()
            .map(|a| {
                serde_json::json!({
                    "environment": a.canonical,
                    "alias": a.alias,
                    "filePath": a.file_path,
                    "fileExists": a.file_exists,
                    "fileVarCount": a.file_var_count,
                    "vaultExists": a.vault_exists,
                    "vaultVarCount": a.vault_var_count,
                })
            })
            .collect();

        // Perform imports
        let mut results = Vec::new();
        for action in &actions {
            if action.file_exists && (!action.vault_exists || force) {
                let fp = action.file_path.as_deref().unwrap();
                let path = project_dir.join(fp);
                let count = if action.canonical == "default" {
                    lpm_vault::import_env_file(project_dir, &path, force)
                } else {
                    lpm_vault::import_env_file_to_env(project_dir, &action.canonical, &path, force)
                }
                .map_err(LpmError::Script)?;
                results.push(serde_json::json!({
                    "environment": action.canonical,
                    "action": "imported",
                    "count": count,
                }));
            } else if !action.vault_exists && !action.file_exists {
                // Create empty env by writing an empty set
                if action.canonical != "default" {
                    lpm_vault::set_env(project_dir, &action.canonical, &[])
                        .map_err(LpmError::Script)?;
                }
                results.push(serde_json::json!({
                    "environment": action.canonical,
                    "action": "created_empty",
                }));
            }
        }

        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "environments": json_actions,
                "actions": results,
            })
        );
        return Ok(());
    }

    // Display detected config
    if !env_map.is_empty() {
        println!();
        output::info("detected lpm.json env config:");
        for env in &all_envs {
            if let Some(alias) = &env.alias {
                println!(
                    "    {}  {}  {}",
                    alias.bold(),
                    "->".dimmed(),
                    env.file_path
                        .as_deref()
                        .unwrap_or(&format!(".env.{}", env.canonical))
                        .dimmed(),
                );
            }
        }
        println!();
    }

    // Show file scan results
    output::info("scanning .env files:");
    for action in &actions {
        let fallback = format!(".env.{}", action.canonical);
        let fp = action.file_path.as_deref().unwrap_or(&fallback);
        if action.file_exists {
            println!(
                "    {} {} ({} variable{})",
                "found".green(),
                fp.bold(),
                action.file_var_count,
                if action.file_var_count == 1 { "" } else { "s" }
            );
        } else {
            println!("    {}  {}", "missing".dimmed(), fp.dimmed());
        }
    }
    println!();

    // Perform actions
    let mut imported_count = 0;
    let mut created_count = 0;
    let mut skipped_count = 0;

    for action in &actions {
        if action.file_exists && (!action.vault_exists || force) {
            let fp = action.file_path.as_deref().unwrap();
            let path = project_dir.join(fp);
            let count = if action.canonical == "default" {
                lpm_vault::import_env_file(project_dir, &path, force)
            } else {
                lpm_vault::import_env_file_to_env(project_dir, &action.canonical, &path, force)
            }
            .map_err(LpmError::Script)?;
            output::success(&format!(
                "imported {} variable{} from {} into \"{}\"",
                count,
                if count == 1 { "" } else { "s" },
                fp.cyan(),
                action.canonical
            ));
            imported_count += 1;
        } else if action.file_exists && action.vault_exists {
            println!(
                "  {} \"{}\" already has {} secret{} (use {} to overwrite)",
                "skip".yellow(),
                action.canonical,
                action.vault_var_count,
                if action.vault_var_count == 1 { "" } else { "s" },
                "--force".bold()
            );
            skipped_count += 1;
        } else if !action.vault_exists && !action.file_exists && action.canonical != "default" {
            // Create empty env
            lpm_vault::set_env(project_dir, &action.canonical, &[]).map_err(LpmError::Script)?;
            output::success(&format!("created empty \"{}\"", action.canonical));
            created_count += 1;
        }
    }

    println!();
    let total = imported_count + created_count;
    if total > 0 || skipped_count > 0 {
        output::success(&format!(
            "vault initialized with {} environment{}{}",
            all_envs.len(),
            if all_envs.len() == 1 { "" } else { "s" },
            if skipped_count > 0 {
                format!(" ({skipped_count} skipped)")
            } else {
                String::new()
            }
        ));
        println!("  Run {} to sync to cloud", "lpm env push".cyan());
    } else {
        output::info("vault already initialized — nothing to do");
    }
    println!();

    Ok(())
}

/// `lpm env ls` — environment overview table.
///
/// Shows all environments with variable counts, schema status, and aliases.
fn vars_ls(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    if all_envs.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({"success": true, "environments": []})
            );
        } else {
            output::info("no environments found");
            println!("  Run {} to set up", "lpm env init".cyan());
        }
        return Ok(());
    }

    // Build rows
    struct EnvRow {
        canonical: String,
        var_count: usize,
        schema_status: Option<(usize, usize)>, // (valid, total)
        alias: Option<String>,
        source: lpm_env::EnvSource,
    }

    let mut rows: Vec<EnvRow> = Vec::new();
    let sync_summary = lpm_vault::vault_id::read_sync_summary(project_dir);

    for env in &all_envs {
        // Replicate the actual loader fallback behavior from dotenv.rs:79-88:
        // If the env-specific vault is completely empty, fall back to default.
        // If it has any secrets, use ONLY it (no per-key fallback to default).
        let env_specific = vault_envs.get(&env.canonical);
        let effective_vars = if env.canonical == "default" {
            env_specific.cloned().unwrap_or_default()
        } else {
            match env_specific {
                Some(v) if !v.is_empty() => v.clone(),
                _ => vault_envs.get("default").cloned().unwrap_or_default(),
            }
        };
        let var_count = env_specific.map_or(0, |v| v.len());

        let schema_status = schema.map(|s| {
            let total = s.vars.iter().filter(|(_, r)| r.required).count();
            let valid = s
                .vars
                .iter()
                .filter(|(_, r)| r.required)
                .filter(|(k, _)| effective_vars.contains_key(k.as_str()))
                .count();
            (valid, total)
        });

        rows.push(EnvRow {
            canonical: env.canonical.clone(),
            var_count,
            schema_status,
            alias: env.alias.clone(),
            source: env.source.clone(),
        });
    }

    if json_output {
        let json_rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                let mut obj = serde_json::json!({
                    "environment": r.canonical,
                    "variables": r.var_count,
                    "alias": r.alias,
                    "source": format!("{:?}", r.source),
                });
                if let Some((valid, total)) = r.schema_status {
                    obj["schemaValid"] = serde_json::json!(valid);
                    obj["schemaTotal"] = serde_json::json!(total);
                }
                obj
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({"success": true, "environments": json_rows})
        );
        return Ok(());
    }

    // Calculate column widths
    let name_width = rows
        .iter()
        .map(|r| r.canonical.len())
        .max()
        .unwrap_or(11)
        .max(11);
    let updated_width = rows
        .iter()
        .filter(|r| sync_summary.synced && r.var_count > 0)
        .filter_map(|_| sync_summary.synced_at.as_ref().map(|t| t.len()))
        .max()
        .unwrap_or(7)
        .max(7);

    println!();
    println!(
        "  {:<name_width$}  {:>9}  {:>6}  {:<updated_width$}",
        "Environment", "Variables", "Synced", "Updated",
    );

    for row in &rows {
        let schema_suffix = match row.schema_status {
            Some((valid, total)) if total > 0 => {
                if valid == total {
                    format!(" {}", install_ui::status_ok(&format!("{valid}/{total} ok")))
                } else {
                    format!(" {}", install_ui::red(&format!("{valid}/{total} !!")))
                }
            }
            _ => String::new(),
        };

        let row_synced = sync_summary.synced && row.var_count > 0;
        let synced_raw = if row_synced { "yes" } else { "no" };
        let synced_padded = format!("{synced_raw:>6}");
        let synced_str = if row_synced {
            install_ui::status_ok(&synced_padded)
        } else {
            install_ui::dim(&synced_padded)
        };

        let updated_raw = if row_synced {
            sync_summary.synced_at.as_deref().unwrap_or("-")
        } else {
            "-"
        };
        let updated_str = install_ui::dim(&format!("{updated_raw:<updated_width$}"));

        let source_indicator = match row.source {
            lpm_env::EnvSource::Legacy => format!(" {}", install_ui::yellow("legacy")),
            _ => String::new(),
        };

        let var_count = install_ui::dim(&format!("{:>9}", row.var_count));

        println!(
            "  {:<name_width$}  {}  {}  {}{}{}",
            row.canonical, var_count, synced_str, updated_str, schema_suffix, source_indicator,
        );
    }
    println!();
    println!(
        "  {} {}",
        install_ui::dim("Active environment:"),
        install_ui::status_ok("default")
    );
    println!(
        "  {}",
        install_ui::dim("Use lpm env list --env <name> to inspect secrets.")
    );
    println!();
    Ok(())
}

/// `lpm env copy <src> <dst>` — copy all secrets from one environment to another.
fn vars_copy(
    project_dir: &std::path::Path,
    src: &str,
    dst: &str,
    overwrite: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty = HashMap::new();
    let env_map = config.as_ref().map_or(&empty, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    // Resolve both env names (src = read path, dst = write path)
    let resolved_src = lpm_env::resolver::resolve(src, env_map, environments);
    let resolved_dst = lpm_env::resolver::resolve_checked(dst, env_map, environments)
        .map_err(|e| LpmError::Script(format!("invalid target environment: {e}")))?;

    if resolved_src.canonical == resolved_dst.canonical {
        return Err(LpmError::Script(
            "source and target environments are the same".into(),
        ));
    }

    let src_secrets = lpm_vault::try_get_all_env(project_dir, &resolved_src.storage_key)
        .map_err(LpmError::Script)?;
    if src_secrets.is_empty() {
        return Err(LpmError::Script(format!(
            "no secrets in source environment \"{}\"",
            resolved_src.canonical
        )));
    }

    let dst_secrets = lpm_vault::try_get_all_env(project_dir, &resolved_dst.storage_key)
        .map_err(LpmError::Script)?;

    // Compute what will be copied
    let mut to_copy = Vec::new();
    let mut to_skip = Vec::new();
    for (key, value) in &src_secrets {
        if dst_secrets.contains_key(key) && !overwrite {
            to_skip.push(key.as_str());
        } else {
            to_copy.push((key.as_str(), value.as_str()));
        }
    }

    if to_copy.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "success": true,
                    "copied": 0,
                    "skipped": to_skip.len(),
                    "source": resolved_src.canonical,
                    "target": resolved_dst.canonical,
                })
            );
        } else {
            output::info(&format!(
                "nothing to copy — all {} key{} already exist in \"{}\" (use {} to overwrite)",
                to_skip.len(),
                if to_skip.len() == 1 { "" } else { "s" },
                resolved_dst.canonical,
                "--overwrite".bold()
            ));
        }
        return Ok(());
    }

    // Perform the copy
    lpm_vault::set_env(project_dir, &resolved_dst.canonical, &to_copy).map_err(LpmError::Script)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "copied": to_copy.len(),
                "skipped": to_skip.len(),
                "source": resolved_src.canonical,
                "target": resolved_dst.canonical,
            })
        );
    } else {
        output::success(&format!(
            "copied {} secret{} from \"{}\" to \"{}\"{}",
            to_copy.len(),
            if to_copy.len() == 1 { "" } else { "s" },
            resolved_src.canonical,
            resolved_dst.canonical,
            if to_skip.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} existing skipped, use {} to overwrite)",
                    to_skip.len(),
                    "--overwrite".bold()
                )
            }
        ));
    }

    Ok(())
}

fn vars_print(args: &[&str], project_dir: &std::path::Path) -> Result<(), LpmError> {
    // Parse --format=<fmt> and --env=<mode> and --schema-only
    let mut format_str = "dotenv";
    let mut env_mode: Option<&str> = None;
    let mut schema_only = false;

    let mut i = 0;
    while i < args.len() {
        if let Some(fmt) = args[i].strip_prefix("--format=") {
            format_str = fmt;
        } else if args[i] == "--format" {
            if let Some(next) = args.get(i + 1) {
                format_str = next;
                i += 1;
            }
        } else if let Some(mode) = args[i].strip_prefix("--env=") {
            env_mode = Some(mode);
        } else if args[i] == "--env" {
            if let Some(next) = args.get(i + 1) {
                env_mode = Some(next);
                i += 1;
            }
        } else if args[i] == "--schema-only" {
            schema_only = true;
        }
        i += 1;
    }

    let format = lpm_env::PrintFormat::parse(format_str).ok_or_else(|| {
        LpmError::Script(format!(
            "unknown format: '{format_str}'. Available: {}",
            lpm_env::PrintFormat::all_names()
        ))
    })?;

    // Read config first so we can resolve env aliases
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    // Resolve the env mode through the canonical resolver (e.g., "dev" → "development")
    let empty_env_map = std::collections::HashMap::new();
    let resolved_mode = env_mode.map(|m| {
        let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        lpm_env::resolver::resolve(m, env_map, environments).canonical
    });

    // Use the unified loader (handles inheritance, vault, schema validation + defaults)
    let mut env_vars = lpm_runner::dotenv::load_project_env(project_dir, resolved_mode.as_deref())?;
    let schema = config.as_ref().and_then(|c| c.env_schema.as_ref());

    // Collect secret keys for masking
    let secret_keys: std::collections::HashSet<String> = schema
        .map(|s| {
            s.vars
                .iter()
                .filter(|(_, rule)| rule.secret)
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();

    // Filter to schema-only if requested
    if schema_only && let Some(schema) = schema {
        let schema_keys: std::collections::HashSet<&str> =
            schema.vars.keys().map(|k| k.as_str()).collect();
        env_vars.retain(|k, _| schema_keys.contains(k.as_str()));
    }

    let output = lpm_env::format_env(&env_vars, format, &secret_keys);
    println!("{output}");

    Ok(())
}

fn vars_check(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir).map_err(LpmError::Script)?;

    let schema = config
        .and_then(|c| c.env_schema)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            LpmError::Script(
                "no envSchema defined in lpm.json. Add an envSchema section first.".into(),
            )
        })?;

    // Get all environment names from lpm.json env mapping
    let lpm_config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();

    // Discover all environments via the canonical resolver.
    // This produces a consistent, deduplicated list from config + vault,
    // with legacy vault keys surfaced separately (never collapsed).
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let empty_env_map = std::collections::HashMap::new();
    let all_envs = lpm_env::resolver::list_all(
        lpm_config.as_ref().map_or(&empty_env_map, |c| &c.env),
        lpm_config.as_ref().and_then(|c| c.environments.as_ref()),
        &vault_envs,
    );
    let env_names: Vec<String> = all_envs.iter().map(|e| e.canonical.clone()).collect();

    let mut results: Vec<(String, usize, Vec<lpm_env::ValidationError>)> = Vec::new();
    let mut all_valid = true;

    // Temporarily skip validation in load_project_env — we run it manually per-env for reporting
    lpm_runner::script::set_skip_env_validation(true);

    for env_name in &env_names {
        let mode = if env_name == "default" {
            None
        } else {
            Some(env_name.as_str())
        };

        // Use unified loader (handles inheritance + vault) — hard errors on cycle/missing
        let mut env_vars = lpm_runner::dotenv::load_project_env(project_dir, mode)?;

        // Run schema validation manually to collect per-env errors
        let errors = lpm_env::validate(&schema, &mut env_vars);
        if !errors.is_empty() {
            all_valid = false;
        }
        results.push((env_name.clone(), schema.len(), errors));
    }

    // Restore validation flag
    lpm_runner::script::set_skip_env_validation(false);

    if json_output {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, total, errors)| {
                serde_json::json!({
                    "environment": name,
                    "total": total,
                    "valid": total - errors.len(),
                    "errors": errors.iter().map(|e| {
                        serde_json::json!({
                            "key": e.key,
                            "error": e.to_string(),
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "success": all_valid,
                "environments": json_results,
            })
        );
        return Ok(());
    }

    println!();
    for (name, total, errors) in &results {
        let valid = total - errors.len();
        if errors.is_empty() {
            println!(
                "  {}  {}  {}/{} valid",
                name.bold(),
                "✓".green(),
                valid,
                total
            );
        } else {
            let missing: Vec<&str> = errors.iter().map(|e| e.key.as_str()).collect();
            println!(
                "  {}  {}  {}/{} — missing: {}",
                name.bold(),
                "✗".red(),
                valid,
                total,
                missing.join(", ").red()
            );
        }
    }
    println!();

    if all_valid {
        output::success("all environments valid");
    } else {
        return Err(LpmError::EnvValidation(
            "one or more environments have missing or invalid variables".into(),
        ));
    }

    Ok(())
}

// ─── Platform Sync (Tier 4B) ──────────────────────────────────────

/// Get the LPM auth token and registry URL for API calls.
async fn get_platform_auth(json_output: bool) -> Result<(String, String), LpmError> {
    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;
    Ok((registry_url, auth_token))
}

/// `lpm env connect <platform> --project=<id> [--token=<token>] [--team=<id>] [--label=<name>]`
async fn vars_connect(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env connect <platform> --project=<id> [--token=<token>]".into(),
        ));
    }

    let platform = args[0];
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    // Parse flags
    let mut project_id: Option<&str> = None;
    let mut team_id: Option<&str> = None;
    let mut platform_token: Option<&str> = None;
    let mut label: Option<&str> = None;
    let mut linked_env: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        if let Some(v) = args[i].strip_prefix("--project=") {
            project_id = Some(v);
        } else if args[i] == "--project" {
            if let Some(next) = args.get(i + 1) {
                project_id = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--token=") {
            platform_token = Some(v);
        } else if args[i] == "--token" {
            if let Some(next) = args.get(i + 1) {
                platform_token = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--team=") {
            team_id = Some(v);
        } else if args[i] == "--team" {
            if let Some(next) = args.get(i + 1) {
                team_id = Some(next);
                i += 1;
            }
        } else if let Some(v) = args[i].strip_prefix("--label=") {
            label = Some(v);
        } else if args[i] == "--label"
            && let Some(next) = args.get(i + 1)
        {
            label = Some(next);
            i += 1;
        } else if let Some(v) = args[i].strip_prefix("--linked-env=") {
            linked_env = Some(v);
        } else if args[i] == "--linked-env"
            && let Some(next) = args.get(i + 1)
        {
            linked_env = Some(next);
            i += 1;
        } else if args[i].starts_with("--") {
            output::warn(&format!("unknown flag '{}' — ignored", args[i]));
        }
        i += 1;
    }

    let project_id = project_id.ok_or_else(|| {
        LpmError::Script(format!(
            "missing --project flag. Usage: lpm env connect {platform} --project=<id>"
        ))
    })?;

    // Prompt for token if not provided via flag
    let token_owned;
    let platform_token = if let Some(t) = platform_token {
        t
    } else {
        token_owned = cliclack::password(format!("Paste {platform} API token"))
            .interact()
            .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;
        token_owned.as_str()
    };

    // Build connection config
    let mut connection_config = serde_json::json!({
        "projectId": project_id,
    });
    if let Some(team) = team_id {
        connection_config["teamId"] = serde_json::Value::String(team.to_string());
    }
    // Resolve linked env through canonical resolver if provided
    if let Some(env_input) = linked_env {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        let resolved = lpm_env::resolver::resolve_checked(env_input, env_map, environments)
            .map_err(|e| LpmError::Script(format!("invalid --linked-env value: {e}")))?;
        connection_config["linkedEnv"] = serde_json::Value::String(resolved.canonical);
    }

    output::info(&format!("connecting to {platform}..."));

    // Send to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/connect"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "token": platform_token,
            "connectionConfig": connection_config,
            "label": label,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to connect: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("connection failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(response).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let status = result["status"].as_str().unwrap_or("connected");
        output::success(&format!(
            "{platform} {} (project: {project_id})",
            status.bold()
        ));
    }

    Ok(())
}

/// `lpm env push --to <platform> [--env=<mode>] [--clean] [--yes]`
async fn vars_platform_push(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    // Parse flags
    let mut platform: Option<&str> = None;
    let mut env_mode: Option<&str> = None;
    let mut clean = false;
    let mut yes = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--to=") {
            platform = Some(v);
        } else if *arg == "--to" {
            // Next arg handled by positional scan below
        } else if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if *arg == "--clean" {
            clean = true;
        } else if *arg == "--yes" || *arg == "-y" {
            yes = true;
        }
    }

    // Handle --to <value> (space-separated)
    if platform.is_none() {
        for (i, arg) in args.iter().enumerate() {
            if *arg == "--to"
                && let Some(next) = args.get(i + 1)
            {
                platform = Some(next);
            }
        }
    }

    let platform = platform.ok_or_else(|| {
        LpmError::Script("missing --to flag. Usage: lpm env push --to <platform>".into())
    })?;

    // Resolve env mode through canonical resolver — write path, use resolve_checked
    // (push sends secrets to a remote platform, invalid names should fail fast)
    let resolved_env_mode = if let Some(input) = env_mode {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());
        let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
            .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
        Some(resolved.canonical)
    } else {
        None
    };

    // Load resolved env vars (same as what lpm run sees)
    let env_vars = lpm_runner::dotenv::load_project_env(project_dir, resolved_env_mode.as_deref())?;

    // Convert to string-string map for JSON serialization
    let vars: std::collections::HashMap<String, String> = env_vars;

    output::info(&format!("comparing with {platform}..."));

    // Step 1: Dry-run to get diff
    let client = reqwest::Client::new();
    let dry_run_response = client
        .post(format!(
            "{registry_url}/api/vault/platforms/push?dryRun=true"
        ))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "env": resolved_env_mode.as_deref().unwrap_or("default"),
            "vars": vars,
            "clean": clean,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !dry_run_response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(dry_run_response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let diff: serde_json::Value = parse_capped_platform_json(dry_run_response).await?;

    let added = diff["added"].as_array().map_or(0, |a| a.len());
    let changed = diff["changed"].as_array().map_or(0, |a| a.len());
    let removed = diff["removed"].as_array().map_or(0, |a| a.len());
    let unchanged = diff["unchanged"].as_u64().unwrap_or(0);
    let orphans = diff["orphans"].as_array().map_or(0, |a| a.len());

    if added == 0 && changed == 0 && removed == 0 {
        if json_output {
            println!(
                "{}",
                serde_json::json!({"status": "no_changes", "platform": platform})
            );
        } else {
            output::success(&format!("{platform} is already in sync"));
            if orphans > 0 {
                output::warn(&format!(
                    "{orphans} orphan var(s) on {platform} not in vault. Use --clean to remove."
                ));
            }
        }
        return Ok(());
    }

    // Show diff
    if !json_output {
        println!();
        println!(
            "  {} — {}",
            platform.bold(),
            resolved_env_mode.as_deref().unwrap_or("default")
        );
        println!();

        if let Some(keys) = diff["added"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "+".green(),
                    key.as_str().unwrap_or("").bold(),
                    "(new)".dimmed()
                );
            }
        }
        if let Some(keys) = diff["changed"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "~".yellow(),
                    key.as_str().unwrap_or("").bold(),
                    "(changed)".dimmed()
                );
            }
        }
        if let Some(keys) = diff["removed"].as_array() {
            for key in keys {
                println!(
                    "  {} {} {}",
                    "-".red(),
                    key.as_str().unwrap_or("").bold(),
                    "(will be removed)".dimmed()
                );
            }
        }
        if unchanged > 0 {
            println!("  {} {unchanged} unchanged", "=".dimmed());
        }
        if orphans > 0 && !clean {
            println!(
                "  {} {orphans} orphan(s) on {platform} {}",
                "!".yellow(),
                "(use --clean to remove)".dimmed()
            );
        }
        println!();
    }

    // Confirm
    if !yes && !json_output {
        let confirm = cliclack::confirm(format!(
            "Push {added} added, {changed} changed, {removed} removed to {platform}?"
        ))
        .initial_value(false)
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;

        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    // Step 2: Apply
    output::info(&format!("pushing to {platform}..."));

    let push_response = client
        .post(format!("{registry_url}/api/vault/platforms/push"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
            "env": resolved_env_mode.as_deref().unwrap_or("default"),
            "vars": vars,
            "clean": clean,
        }))
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("push failed: {e}")))?;

    if !push_response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(push_response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("push failed").to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(push_response).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        let added_count = result["added"].as_u64().unwrap_or(0);
        let updated_count = result["updated"].as_u64().unwrap_or(0);
        let removed_count = result["removed"].as_u64().unwrap_or(0);

        output::success(&format!(
            "{platform} synced — {added_count} added, {updated_count} updated, {removed_count} removed"
        ));
    }

    Ok(())
}

/// `lpm env status`
async fn vars_platform_status(
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured. Run `lpm env set` first".into()))?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    // Load default env vars (backward compat)
    let default_vars = lpm_runner::dotenv::load_project_env(project_dir, None)?;

    // Build per-environment vars map for env-bound connections.
    // The server picks the right env per connection based on connectionConfig.linkedEnv.
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty_env_map = HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());
    let vault_envs = lpm_vault::try_get_all_environments(project_dir).map_err(LpmError::Script)?;
    let all_envs = lpm_env::resolver::list_all(env_map, environments, &vault_envs);

    // Collect all known environment names from config + vault
    let mut env_names: std::collections::HashSet<String> =
        all_envs.iter().map(|e| e.canonical.clone()).collect();

    // Also discover environments from .env.* files on disk.
    // A connection might be linked to e.g. "preview" which exists only as
    // .env.preview — not in lpm.json or vault. Without scanning disk,
    // envVars would miss it and the server would fall back to default vars.
    if let Ok(entries) = std::fs::read_dir(project_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(mode) = name.strip_prefix(".env.") {
                // Skip .local variants and .example files
                if !mode.contains(".local") && !mode.ends_with(".example") && !mode.is_empty() {
                    env_names.insert(mode.to_string());
                }
            }
        }
    }

    let mut env_vars_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for env_name in &env_names {
        let mode = if env_name == "default" {
            None
        } else {
            Some(env_name.as_str())
        };
        if let Ok(vars) = lpm_runner::dotenv::load_project_env(project_dir, mode) {
            env_vars_map.insert(
                env_name.clone(),
                serde_json::to_value(&vars).unwrap_or_default(),
            );
        }
    }

    output::info("checking platform status...");

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/status"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "vars": default_vars,
            "envVars": env_vars_map,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"]
                .as_str()
                .unwrap_or("status check failed")
                .to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(response).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    let platforms = result["platforms"].as_array();
    if platforms.is_none() || platforms.unwrap().is_empty() {
        output::warn("no platform connections. Run 'lpm env connect <platform>' to add one.");
        return Ok(());
    }

    println!();
    for platform in platforms.unwrap() {
        let name = platform["platform"].as_str().unwrap_or("?");
        let label = platform["label"].as_str().unwrap_or("");
        let env = platform["env"].as_str().unwrap_or("default");
        let status = platform["status"].as_str().unwrap_or("?");
        let last_push = platform["lastPushAt"].as_str();

        let env_suffix = if env != "default" {
            format!(" [{}]", env)
        } else {
            String::new()
        };
        let display_name = if label.is_empty() {
            format!("{name}{env_suffix}")
        } else {
            format!("{name} ({label}){env_suffix}")
        };

        let push_info = last_push.map_or_else(
            || "  never pushed".to_string(),
            |t| format!("  last push: {t}"),
        );

        match status {
            "synced" => {
                println!(
                    "  {} {}  {}",
                    "✓".green(),
                    display_name.bold(),
                    "synced".green()
                );
            }
            "drifted" => {
                let added = platform["added"].as_u64().unwrap_or(0);
                let changed = platform["changed"].as_u64().unwrap_or(0);
                let removed = platform["removed"].as_u64().unwrap_or(0);
                let drift_keys_arr = platform["driftKeys"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();

                let total_drift = added + changed + removed;

                println!(
                    "  {} {}  {} — +{added} ~{changed} -{removed}",
                    "!".yellow(),
                    display_name.bold(),
                    "drifted".yellow()
                );
                if !drift_keys_arr.is_empty() {
                    let display = drift_keys_arr.join(", ");
                    let extra = total_drift.saturating_sub(drift_keys_arr.len() as u64);
                    if extra > 0 {
                        println!(
                            "    {} {}",
                            display.dimmed(),
                            format!("and {extra} more").dimmed()
                        );
                    } else {
                        println!("    {}", display.dimmed());
                    }
                }
            }
            "write_only" => {
                println!(
                    "  {} {}  {}{}",
                    "?".dimmed(),
                    display_name.bold(),
                    "write-only".dimmed(),
                    push_info.dimmed()
                );
            }
            "error" => {
                let err = platform["error"].as_str().unwrap_or("unknown error");
                println!("  {} {}  {}", "✗".red(), display_name.bold(), err.red());
            }
            _ => {
                println!("  {} {}  {status}", "?".dimmed(), display_name.bold());
            }
        }
    }
    println!();

    Ok(())
}

// ─── OIDC (Tier 5) ────────────────────────────────────────────────

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production [--events=push,workflow_dispatch] [--allow-forks]`
async fn vars_oidc(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.is_empty() {
        return Err(LpmError::Script(
            "usage: lpm env oidc allow --provider=github --repo=<owner/repo> \
             --workflow=.github/workflows/<file>.yml --branch=<branch> --env=<env> \
             [--events=push,workflow_dispatch] [--allow-forks]"
                .into(),
        ));
    }

    match args[0] {
        "allow" => vars_oidc_allow(&args[1..], project_dir, json_output).await,
        "list" => vars_oidc_list(project_dir, json_output).await,
        unknown => Err(LpmError::Script(format!(
            "unknown oidc action: '{unknown}'. Available: allow, list"
        ))),
    }
}

/// `lpm env oidc allow --provider=github --repo=owner/repo --workflow=.github/workflows/deploy.yml --branch=main --env=production`
async fn vars_oidc_allow(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    let mut provider = "github";
    let mut repo: Option<&str> = None;
    let mut branches: Vec<String> = vec!["main".to_string()];
    let mut envs: Vec<String> = Vec::new();
    // of plan-security-findings-c3.md — `allowedWorkflows`.
    // No default: the server schema is `.min(1)`, and the safe default
    // ".github/workflows/deploy.yml" guesses the user's workflow name
    // (which is almost always wrong). Forcing the user to supply it
    // surfaces the security model.
    let mut workflows: Vec<String> = Vec::new();
    // `allowedEvents`. Defaults to push-only — the safest
    // event for fork-PR exposure. Adding `pull_request_target` to
    // this list also requires `--allow-forks` (cross-field check
    // enforced server-side, gated on JWT fixtures).
    let mut events: Vec<String> = vec!["push".to_string()];
    let mut allow_forks = false;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--provider=") {
            provider = v;
        } else if let Some(v) = arg.strip_prefix("--repo=") {
            repo = Some(v);
        } else if let Some(v) = arg.strip_prefix("--branch=") {
            branches = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--env=") {
            envs = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--workflow=") {
            workflows = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if let Some(v) = arg.strip_prefix("--events=") {
            events = v.split(',').map(|s| s.trim().to_string()).collect();
        } else if *arg == "--allow-forks" {
            allow_forks = true;
        }
    }

    let repo = repo.ok_or_else(|| {
        LpmError::Script(
            "missing --repo flag. Usage: lpm env oidc allow --repo=owner/repo \
             --workflow=.github/workflows/deploy.yml --branch=main --env=production"
                .into(),
        )
    })?;

    if workflows.is_empty() {
        return Err(LpmError::Script(
            "missing --workflow flag. Usage: lpm env oidc allow --repo=owner/repo \
             --workflow=.github/workflows/deploy.yml [--workflow=path2,path3]"
                .into(),
        ));
    }

    // Validate workflow paths client-side so the user gets a fast
    // failure instead of waiting for the server round-trip. The shape
    // matches the server's Zod regex
    // (`lib/validations/vault.js::GITHUB_WORKFLOW_PATH_RE`).
    for wf in &workflows {
        let valid = wf.starts_with(".github/workflows/")
            && !wf[".github/workflows/".len()..].contains('/')
            && (wf.ends_with(".yml") || wf.ends_with(".yaml"));
        if !valid {
            return Err(LpmError::Script(format!(
                "workflow path '{wf}' must be of the form `.github/workflows/<file>.yml` \
                 (subdirectories under .github/workflows/ are not supported by GitHub Actions)"
            )));
        }
    }

    // Canonicalize env names through resolver — OIDC policies store canonical names
    if !envs.is_empty() {
        let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
            .ok()
            .flatten();
        let empty = std::collections::HashMap::new();
        let env_map = config.as_ref().map_or(&empty, |c| &c.env);
        let environments = config.as_ref().and_then(|c| c.environments.as_ref());

        let mut canonical_envs = Vec::with_capacity(envs.len());
        for input in &envs {
            match lpm_env::resolver::resolve_checked(input, env_map, environments) {
                Ok(resolved) => {
                    if resolved.canonical != *input && !json_output {
                        output::info(&format!(
                            "resolved \"{}\" → canonical \"{}\"",
                            input, resolved.canonical
                        ));
                    }
                    canonical_envs.push(resolved.canonical);
                }
                Err(e) => {
                    // Warn on unknown names, don't block — matches spec
                    if !json_output {
                        output::warn(&format!(
                            "\"{}\" is not a known environment name: {}. Storing as-is.",
                            input, e
                        ));
                    }
                    canonical_envs.push(input.clone());
                }
            }
        }
        envs = canonical_envs;
    }

    let subject = format!("repo:{repo}");

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/oidc/policies"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "provider": provider,
            "subject": subject,
            "allowedBranches": branches,
            "allowedEnvironments": envs,
            "allowedWorkflows": workflows,
            "allowedEvents": events,
            "allowForks": allow_forks,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(response).await?;

    if !json_output {
        output::success(&format!(
            "OIDC policy set: {provider} {} on branches [{}] for envs [{}] via workflows [{}] events [{}]",
            repo.bold(),
            branches.join(", "),
            if envs.is_empty() {
                "all".to_string()
            } else {
                envs.join(", ")
            },
            workflows.join(", "),
            events.join(", "),
        ));
    }

    // Escrow the wrapping key so the server can decrypt for CI pulls.
    // Best-effort: don't fail if escrow upload fails (the policy was already created).
    match lpm_vault::crypto::get_or_create_wrapping_key() {
        Ok(wrapping_key) => {
            let wrapping_key_hex = hex::encode(wrapping_key);
            match lpm_vault::sync::upload_escrow_key(
                &registry_url,
                &auth_token,
                &vault_id,
                &wrapping_key_hex,
            )
            .await
            {
                Ok(()) => {
                    if !json_output {
                        output::info(
                            "CI escrow enabled — secrets will be decrypted server-side for OIDC pulls",
                        );
                    }
                }
                Err(e) => {
                    if !json_output {
                        output::warn(&format!(
                            "Failed to escrow wrapping key (CI pull may not work): {}",
                            e.dimmed()
                        ));
                    }
                }
            }
        }
        Err(e) => {
            if !json_output {
                output::warn(&format!(
                    "Could not read wrapping key for CI escrow: {}",
                    e.dimmed()
                ));
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    }

    Ok(())
}

/// `lpm env oidc list`
async fn vars_oidc_list(project_dir: &std::path::Path, json_output: bool) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
        .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "{registry_url}/api/vault/oidc/policies?vaultId={vault_id}"
        ))
        .bearer_auth(&auth_token)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("failed").to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(response).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    let policies = result["policies"].as_array();
    if policies.is_none() || policies.unwrap().is_empty() {
        output::warn("no OIDC policies configured. Run 'lpm env oidc allow' to add one.");
        return Ok(());
    }

    println!();
    // Render a JSON array field as a comma-joined string. Empty array
    // or missing field collapses to an empty string; the display logic
    // below replaces empty with `"-"` rather than `"all"` so a policy
    // that's missing required fields doesn't read as "wide-open."
    fn render_strings(field: &serde_json::Value) -> String {
        field
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    }
    for policy in policies.unwrap() {
        let provider = policy["provider"].as_str().unwrap_or("?");
        let subject = policy["subject"].as_str().unwrap_or("?");
        let branches = render_strings(&policy["allowedBranches"]);
        let envs = render_strings(&policy["allowedEnvironments"]);
        let workflows = render_strings(&policy["allowedWorkflows"]);
        let events = render_strings(&policy["allowedEvents"]);
        let forks = policy["allowForks"].as_bool().unwrap_or(false);

        let bb = if branches.is_empty() { "-" } else { &branches };
        let ee = if envs.is_empty() { "-" } else { &envs };
        let ww = if workflows.is_empty() {
            "-"
        } else {
            &workflows
        };
        let ev = if events.is_empty() { "-" } else { &events };
        println!(
            "  {} {}\n      branches:  [{bb}]\n      envs:      [{ee}]\n      workflows: [{ww}]\n      events:    [{ev}]{}",
            provider.bold(),
            subject,
            if forks {
                "\n      forks:     allowed"
            } else {
                ""
            },
        );
    }
    println!();

    Ok(())
}

/// `lpm env pull --oidc [--env=<mode>] [--output=<file>]`
///
/// Exchange CI OIDC token for a short-lived LPM token, then pull vault secrets.
async fn vars_oidc_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id = lpm_vault::vault_id::read_vault_id(project_dir).ok_or_else(|| {
        LpmError::Script("no vault configured. Set LPM_VAULT_ID or run 'lpm env set' first".into())
    })?;

    // Also check env var override for vault ID (useful in CI where lpm.json may not exist)
    let vault_id = std::env::var("LPM_VAULT_ID").unwrap_or(vault_id);

    let registry_url = lpm_common::resolve_lpm_registry_url();

    let mut env_mode: Option<&str> = None;
    let mut output_file: Option<&str> = None;

    for arg in args {
        if let Some(v) = arg.strip_prefix("--env=") {
            env_mode = Some(v);
        } else if let Some(v) = arg.strip_prefix("--output=") {
            output_file = Some(v);
        }
    }

    // Get OIDC token from CI environment
    let oidc_token = get_ci_oidc_token().await?;

    // Exchange OIDC token for short-lived LPM token
    let client = reqwest::Client::new();
    let exchange_response = client
        .post(format!("{registry_url}/api/vault/oidc"))
        .json(&serde_json::json!({
            "oidcToken": oidc_token,
            "vaultId": vault_id,
            "env": env_mode,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("OIDC exchange failed: {e}")))?;

    if !exchange_response.status().is_success() {
        let body: serde_json::Value =
            parse_capped_platform_json_or_unknown(exchange_response).await;
        let error = body["error"].as_str().unwrap_or("OIDC exchange failed");
        let hint = body["hint"].as_str().unwrap_or("");
        let code = body["code"].as_str().unwrap_or("");
        return Err(LpmError::Script(build_oidc_pull_error_message(
            error, hint, code,
        )));
    }

    let exchange_result: serde_json::Value = parse_capped_platform_json(exchange_response).await?;

    let lpm_token = exchange_result["token"]
        .as_str()
        .ok_or_else(|| LpmError::Script("missing token in OIDC response".into()))?;

    // Pull via CI escrow — server decrypts and returns plaintext secrets
    let (vars, env_name) = lpm_vault::sync::ci_pull(&registry_url, lpm_token, &vault_id, env_mode)
        .await
        .map_err(LpmError::Script)?;

    if let Some(file) = output_file {
        // Write .env file with KEY=VALUE pairs
        let mut content =
            format!("# LPM vault secrets (env: {env_name})\n# Pulled via OIDC CI escrow\n");
        let mut keys: Vec<&String> = vars.keys().collect();
        keys.sort();
        for key in &keys {
            let value = &vars[*key];
            // Quote values that contain spaces, newlines, or special chars
            if value.contains(' ')
                || value.contains('\n')
                || value.contains('#')
                || value.contains('"')
            {
                let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
                content.push_str(&format!("{key}=\"{escaped}\"\n"));
            } else {
                content.push_str(&format!("{key}={value}\n"));
            }
        }

        std::fs::write(file, &content)
            .map_err(|e| LpmError::Script(format!("failed to write {file}: {e}")))?;

        // Restrict to owner-only on Unix. The default umask leaves
        // dotenv files at 0o644 on most distros, which means any
        // concurrent CI build step running as a different uid
        // (sidecar containers, sibling daemons, shared runners) can
        // read the plaintext secrets escrowed here. Best-effort: on
        // filesystems without POSIX modes the chmod is a no-op, but
        // the call is still cheap and the failure path is just a
        // tracing::warn — never blocks the user's pipeline.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(file, perms) {
                tracing::warn!(
                    path = %file,
                    error = %e,
                    "failed to set 0o600 on env-pull dotenv file; secret may be readable by other local uids",
                );
            }
        }

        if !json_output {
            output::success(&format!(
                "wrote {} secret{} to {} (env: {})",
                keys.len().to_string().bold(),
                if keys.len() == 1 { "" } else { "s" },
                file,
                env_name,
            ));
        }
    } else if json_output {
        println!(
            "{}",
            serde_json::json!({ "env": env_name, "vars": vars, "count": vars.len() })
        );
    } else {
        output::success(&format!(
            "pulled {} secret{} via OIDC (env: {})",
            vars.len().to_string().bold(),
            if vars.len() == 1 { "" } else { "s" },
            env_name,
        ));
    }

    Ok(())
}

/// Get the OIDC token from the CI environment for the env-vault flow.
///
/// Audience is `https://lpm.dev` (the vault verifier rejects anything else),
/// so this routes through the shared registry-exchange resolver. Honors
/// `LPM_OIDC_TOKEN` (canonical), GitHub Actions runtime, and the legacy
/// `LPM_GITLAB_OIDC_TOKEN` alias.
async fn get_ci_oidc_token() -> Result<String, LpmError> {
    crate::oidc::resolve_registry_exchange_jwt()
        .await
        .map_err(|e| LpmError::Script(format!("{e}")))
}

/// Map a server-side error response from `POST /api/vault/oidc` to a
/// user-facing message with a code-specific remediation hint appended.
///
/// of plan-security-findings-c3.md stamps a stable
/// machine-readable `code` field on every 403/429 from the mint endpoint;
/// (this CLI side) maps each code to an actionable next step so
/// CI logs surface "what to do" rather than just "what failed."
///
/// Precedence:
///   1. If the server sent a `hint` field, use it verbatim.
///   2. Else if the code matches a known taxonomy entry, use the
///      CLI-side mapping.
///   3. Else emit just the server's `error` string.
fn build_oidc_pull_error_message(error: &str, hint: &str, code: &str) -> String {
    let code_hint = match code {
        "policy_not_found" => Some(
            "No OIDC policy exists for this repo+vault. Create one with: \
             lpm env oidc allow --repo=<owner/repo> --workflow=.github/workflows/<file>.yml \
             --branch=<name> --env=<name>",
        ),
        "policy_misconfigured" => Some(
            "The OIDC policy exists but is missing required fields (likely a pre-migration \
             row). Open the dashboard at <registry>/dashboard/vaults to update it.",
        ),
        "branch_not_allowed" => Some(
            "The branch claim from your CI's OIDC token isn't in the policy's allowedBranches. \
             Update the policy: lpm env oidc allow --repo=<owner/repo> --branch=<list> --workflow=...",
        ),
        "env_not_allowed" => Some(
            "The requested env isn't in the policy's allowedEnvironments. Update the policy: \
             lpm env oidc allow --repo=<owner/repo> --env=<list> --workflow=...",
        ),
        "workflow_not_allowed" => Some(
            "The workflow file that minted this token isn't in the policy's allowedWorkflows. \
             Add it: lpm env oidc allow --repo=<owner/repo> --workflow=<path>",
        ),
        "event_not_allowed" => Some(
            "The CI event_name that triggered this run isn't in the policy's allowedEvents. \
             Add it: lpm env oidc allow --repo=<owner/repo> --events=push,workflow_dispatch",
        ),
        "fork_not_allowed" => Some(
            "The OIDC token was minted by a fork PR but the policy has allowForks=false. \
             Add --allow-forks to lpm env oidc allow if this is intentional (note: only \
             enable for public repos with trusted reviewers — pull_request_target events \
             from forks run with BASE secrets).",
        ),
        "missing_branch_claim" => Some(
            "The OIDC token from your CI provider has no branch claim. Confirm your provider \
             sets the ref/branch claim correctly (GitHub Actions does by default; some \
             self-hosted runners may not).",
        ),
        "rate_limited" => Some(
            "Rate limit exceeded on /api/vault/oidc. Retry after the Retry-After interval. \
             If this is a sustained issue, check whether multiple CI jobs share a runner IP.",
        ),
        _ => None,
    };
    match (hint.is_empty(), code_hint) {
        (false, _) => format!("{error}\n  Hint: {hint}"),
        (true, Some(h)) => format!("{error}\n  Hint: {h}"),
        (true, None) => error.to_string(),
    }
}

#[cfg(test)]
mod oidc_error_hint_tests {
    use super::build_oidc_pull_error_message;

    #[test]
    fn server_hint_takes_precedence_over_code_mapping() {
        let msg = build_oidc_pull_error_message(
            "Env not authorized",
            "Run: lpm env oidc allow --env=production",
            "env_not_allowed",
        );
        // Server-supplied `hint` wins; CLI-side mapping is not appended on top.
        assert!(msg.contains("Run: lpm env oidc allow --env=production"));
        // The branch_not_allowed string from the CLI mapping must not leak in.
        assert!(!msg.contains("allowedBranches"));
    }

    #[test]
    fn policy_misconfigured_code_maps_to_dashboard_hint() {
        let msg = build_oidc_pull_error_message(
            "OIDC policy is misconfigured (no allowed branches set).",
            "",
            "policy_misconfigured",
        );
        assert!(msg.contains("OIDC policy is misconfigured"));
        assert!(msg.contains("dashboard"));
        assert!(msg.contains("Hint:"));
    }

    #[test]
    fn workflow_not_allowed_names_the_remediation_flag() {
        let msg =
            build_oidc_pull_error_message("Workflow not authorized", "", "workflow_not_allowed");
        assert!(msg.contains("--workflow"));
        assert!(msg.contains("allowedWorkflows"));
    }

    #[test]
    fn fork_not_allowed_warns_about_pull_request_target() {
        let msg = build_oidc_pull_error_message("Forks not allowed", "", "fork_not_allowed");
        assert!(msg.contains("--allow-forks"));
        assert!(msg.contains("pull_request_target"));
    }

    #[test]
    fn rate_limited_mentions_retry_after() {
        let msg = build_oidc_pull_error_message("rate limited", "", "rate_limited");
        assert!(msg.contains("Retry-After"));
    }

    #[test]
    fn unknown_code_falls_through_to_raw_error() {
        let msg = build_oidc_pull_error_message("Something failed", "", "totally_unknown");
        // No "Hint:" prefix because neither server-hint nor known-code matched.
        assert_eq!(msg, "Something failed");
    }

    #[test]
    fn no_code_no_hint_yields_raw_error() {
        let msg = build_oidc_pull_error_message("Boom", "", "");
        assert_eq!(msg, "Boom");
    }
}

/// `lpm env pull --from <platform> [--env=<mode>] [--yes]`
async fn vars_platform_pull(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let vault_id =
        lpm_vault::vault_id::get_or_create_vault_id(project_dir).map_err(LpmError::Script)?;
    let (registry_url, auth_token) = get_platform_auth(json_output).await?;

    // Parse flags
    let mut platform: Option<&str> = None;
    let mut env_name: Option<&str> = None;
    let mut yes = false;

    for (i, arg) in args.iter().enumerate() {
        if let Some(v) = arg.strip_prefix("--from=") {
            platform = Some(v);
        } else if *arg == "--from"
            && let Some(next) = args.get(i + 1)
        {
            platform = Some(next);
        } else if let Some(v) = arg.strip_prefix("--env=") {
            env_name = Some(v);
        } else if *arg == "--yes" || *arg == "-y" {
            yes = true;
        }
    }

    let platform = platform.ok_or_else(|| {
        LpmError::Script("missing --from flag. Usage: lpm env pull --from <platform>".into())
    })?;

    output::info(&format!("pulling from {platform}..."));

    // Request vars from server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{registry_url}/api/vault/platforms/pull"))
        .bearer_auth(&auth_token)
        .json(&serde_json::json!({
            "vaultId": vault_id,
            "platform": platform,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| LpmError::Network(format!("failed to reach server: {e}")))?;

    if !response.status().is_success() {
        let body: serde_json::Value = parse_capped_platform_json_or_unknown(response).await;
        return Err(LpmError::Script(
            body["error"].as_str().unwrap_or("pull failed").to_string(),
        ));
    }

    let result: serde_json::Value = parse_capped_platform_json(response).await?;

    let vars = result["vars"]
        .as_object()
        .ok_or_else(|| LpmError::Script("invalid response: missing vars".into()))?;

    let count = vars.len();

    if count == 0 {
        output::warn(&format!("no env vars found on {platform}"));
        return Ok(());
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
    } else {
        println!();
        println!("  Found {count} variable(s) on {platform}:");
        println!();
        for key in vars.keys() {
            println!("    {}", key.bold());
        }
        println!();
    }

    // Confirm before importing
    if !yes && !json_output {
        let confirm = cliclack::confirm(format!(
            "Import {count} variable(s) from {platform} into vault?"
        ))
        .initial_value(true)
        .interact()
        .map_err(|e| LpmError::Script(format!("prompt failed: {e}")))?;

        if !confirm {
            output::info("cancelled");
            return Ok(());
        }
    }

    // Store in vault
    let pairs: Vec<(&str, &str)> = vars
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|val| (k.as_str(), val)))
        .collect();

    if let Some(env) = env_name {
        lpm_vault::set_env(project_dir, env, &pairs).map_err(LpmError::Script)?;
    } else {
        lpm_vault::set(project_dir, &pairs).map_err(LpmError::Script)?;
    }

    if !json_output {
        output::success(&format!(
            "imported {count} variable(s) from {platform} into vault{}",
            env_name.map(|e| format!(" ({e})")).unwrap_or_default()
        ));
    }

    Ok(())
}

/// Parse `--env=<name>` or `--env <name>` from args, returning the env value
/// and the remaining args with the flag stripped.
///
/// Returns `Err` if `--env` is present but has no value (bare trailing `--env`).
fn parse_env_flag<'a>(args: &'a [&'a str]) -> Result<(Option<&'a str>, Vec<&'a str>), LpmError> {
    let mut env_mode = None;
    let mut remaining = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(val) = args[i].strip_prefix("--env=") {
            env_mode = Some(val);
        } else if args[i] == "--env" {
            match args.get(i + 1) {
                Some(next) if !next.starts_with('-') => {
                    env_mode = Some(*next);
                    i += 1;
                }
                _ => {
                    return Err(LpmError::Script(
                        "--env requires a value (e.g., --env=production or --env production)"
                            .into(),
                    ));
                }
            }
        } else {
            remaining.push(args[i]);
        }
        i += 1;
    }
    Ok((env_mode, remaining))
}

/// Load lpm.json config and resolve an --env flag value to a canonical env name.
/// Returns (canonical_env_name_or_none, lpm_config_or_none).
/// Resolve an `--env` flag value to a canonical env name.
///
/// Returns `Err` if the flag was provided but the value is invalid.
/// Returns `Ok(None)` if no `--env` flag was provided (use default).
fn resolve_env_from_flag(
    env_input: Option<&str>,
    project_dir: &std::path::Path,
) -> Result<(Option<String>, Option<lpm_runner::lpm_json::LpmJsonConfig>), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty = std::collections::HashMap::new();
    match env_input {
        Some(input) => {
            let env_map = config.as_ref().map_or(&empty, |c| &c.env);
            let environments = config.as_ref().and_then(|c| c.environments.as_ref());
            let resolved = lpm_env::resolver::resolve_checked(input, env_map, environments)
                .map_err(|e| LpmError::Script(format!("invalid environment name: {e}")))?;
            Ok((Some(resolved.canonical), config))
        }
        None => Ok((None, config)),
    }
}

fn vars_list(
    project_dir: &std::path::Path,
    env_name: Option<&str>,
    reveal: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let secrets = match env_name {
        Some(env) => lpm_vault::try_get_all_env(project_dir, env),
        None => lpm_vault::try_get_all(project_dir),
    };
    let secrets = secrets.map_err(LpmError::Script)?;
    let env_label = env_name.unwrap_or("default");

    if json_output {
        if reveal {
            println!("{}", serde_json::to_string_pretty(&secrets).unwrap());
        } else {
            let masked: std::collections::HashMap<&str, &str> =
                secrets.keys().map(|k| (k.as_str(), "••••••••")).collect();
            println!("{}", serde_json::to_string_pretty(&masked).unwrap());
        }
    } else if secrets.is_empty() {
        output::info(&format!("No secrets in vault ({env_label})"));
        println!("  Run {} to add one", "lpm env set KEY=VALUE".cyan());
    } else {
        let mut keys: Vec<&String> = secrets.keys().collect();
        keys.sort();
        output::info(&format!("Vault secrets — {} ({})", env_label, keys.len()));
        for key in keys {
            if reveal {
                println!("  {} = {}", key.bold(), &secrets[key]);
            } else {
                println!("  {} = {}", key.bold(), "••••••••".dimmed());
            }
        }
    }
    Ok(())
}

/// List cloud vaults — personal or org.
async fn vars_list_remote(org_slug: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let registry_url = lpm_common::resolve_lpm_registry_url();
    let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

    if let Some(slug) = org_slug {
        // List org vaults
        let vaults = lpm_vault::sync::list_org_vaults(&registry_url, &auth_token, slug)
            .await
            .map_err(LpmError::Script)?;

        if json_output {
            let json: Vec<serde_json::Value> = vaults
				.iter()
				.map(|v| serde_json::json!({"vault_id": v.vault_id, "version": v.version, "updated_at": v.updated_at, "org": slug}))
				.collect();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"success": true, "org": slug, "vaults": json})
                )
                .unwrap()
            );
            return Ok(());
        }

        if vaults.is_empty() {
            output::info(&format!("no shared vaults in org {}", slug.bold()));
            println!(
                "  Share a vault: {}",
                format!("lpm env share --org {slug}").cyan()
            );
            return Ok(());
        }

        output::info(&format!("Org {} vaults ({})", slug.bold(), vaults.len()));
        for v in &vaults {
            let version = v.version.map_or_else(|| "v?".into(), |v| format!("v{v}"));
            let updated = v.updated_at.as_deref().unwrap_or("?");
            println!(
                "  {} {} {} {}",
                "·".cyan(),
                v.vault_id.bold(),
                version.dimmed(),
                format!("(updated {updated})").dimmed()
            );
        }
        println!();
        println!(
            "  Pull: {}",
            format!("cd <project-dir> && lpm env pull --org {slug}").cyan()
        );
        return Ok(());
    }

    // Personal vaults
    let vaults = lpm_vault::sync::list_remote(&registry_url, &auth_token)
        .await
        .map_err(LpmError::Script)?;

    if json_output {
        let json: Vec<serde_json::Value> = vaults
            .iter()
            .map(|v| {
                serde_json::json!({
                    "vault_id": v.vault_id,
                    "version": v.version,
                    "updated_at": v.updated_at,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"success": true, "vaults": json}))
                .unwrap()
        );
        return Ok(());
    }

    if vaults.is_empty() {
        output::info("no cloud vaults found");
        println!("  Push a vault with: {}", "lpm env push".cyan());
        return Ok(());
    }

    output::info(&format!("Cloud vaults ({})", vaults.len()));
    for v in &vaults {
        let version = v.version.map_or_else(|| "v?".into(), |v| format!("v{v}"));
        let updated = v.updated_at.as_deref().unwrap_or("?");
        println!(
            "  {} {} {} {}",
            "·".cyan(),
            v.vault_id.bold(),
            version.dimmed(),
            format!("(updated {updated})").dimmed()
        );
    }
    println!();
    println!(
        "  Pull a vault: {}",
        "cd <project-dir> && lpm env pull".cyan()
    );

    Ok(())
}

/// Compare vault environments or local vs cloud.
///
/// Usage:
///   lpm env diff                     — local default vs cloud
///   lpm env diff staging             — local staging vs cloud staging
///   lpm env diff staging production  — two local environments
async fn vars_diff(
    args: &[&str],
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let config = lpm_runner::lpm_json::read_lpm_json(project_dir)
        .ok()
        .flatten();
    let empty_env_map = std::collections::HashMap::new();
    let env_map = config.as_ref().map_or(&empty_env_map, |c| &c.env);
    let environments = config.as_ref().and_then(|c| c.environments.as_ref());

    let (left_label, left_secrets, right_label, right_secrets) = if args.len() >= 2 {
        // Compare two local environments — resolve aliases to canonical names
        let resolved_a = lpm_env::resolver::resolve(args[0], env_map, environments);
        let resolved_b = lpm_env::resolver::resolve(args[1], env_map, environments);
        let a = lpm_vault::try_get_all_env(project_dir, &resolved_a.storage_key)
            .map_err(LpmError::Script)?;
        let b = lpm_vault::try_get_all_env(project_dir, &resolved_b.storage_key)
            .map_err(LpmError::Script)?;
        (
            format!("{} (local)", resolved_a.canonical),
            a,
            format!("{} (local)", resolved_b.canonical),
            b,
        )
    } else if args.len() == 1 {
        // Compare specific env local vs cloud — fetch the same env from cloud, not "default"
        let resolved = lpm_env::resolver::resolve(args[0], env_map, environments);
        let local = lpm_vault::try_get_all_env(project_dir, &resolved.storage_key)
            .map_err(LpmError::Script)?;

        let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let registry_url = lpm_common::resolve_lpm_registry_url();
        let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

        let (remote, _version) =
            lpm_vault::sync::pull_env(&registry_url, &auth_token, &vault_id, &resolved.canonical)
                .await
                .map_err(LpmError::Script)?;

        (
            format!("{} (local)", resolved.canonical),
            local,
            format!("{} (cloud)", resolved.canonical),
            remote,
        )
    } else {
        // Default: local default vs cloud
        let local = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

        let vault_id = lpm_vault::vault_id::read_vault_id(project_dir)
            .ok_or_else(|| LpmError::Script("no vault configured".into()))?;
        let registry_url = lpm_common::resolve_lpm_registry_url();
        let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

        let (remote, _version) = lpm_vault::sync::pull(&registry_url, &auth_token, &vault_id)
            .await
            .map_err(LpmError::Script)?;

        (
            "default (local)".into(),
            local,
            "default (cloud)".into(),
            remote,
        )
    };

    // Compute diff
    let mut all_keys: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for key in left_secrets.keys() {
        all_keys.insert(key.as_str());
    }
    for key in right_secrets.keys() {
        all_keys.insert(key.as_str());
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut same = 0u32;

    for key in &all_keys {
        let in_left = left_secrets.get(*key);
        let in_right = right_secrets.get(*key);
        match (in_left, in_right) {
            (Some(_), None) => added.push(*key),
            (None, Some(_)) => removed.push(*key),
            (Some(l), Some(r)) if l != r => changed.push(*key),
            (Some(_), Some(_)) => same += 1,
            _ => {}
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "left": left_label,
                "right": right_label,
                "added": added,
                "removed": removed,
                "changed": changed,
                "unchanged": same,
            })
        );
        return Ok(());
    }

    println!();
    println!(
        "  Comparing {} vs {}",
        left_label.bold(),
        right_label.bold()
    );
    println!();

    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        output::success("no differences");
        return Ok(());
    }

    for key in &added {
        println!(
            "  {} {} {}",
            "+".green(),
            key.bold(),
            "(only in left)".dimmed()
        );
    }
    for key in &removed {
        println!(
            "  {} {} {}",
            "-".red(),
            key.bold(),
            "(only in right)".dimmed()
        );
    }
    for key in &changed {
        println!("  {} {} {}", "~".yellow(), key.bold(), "(changed)".dimmed());
    }
    if same > 0 {
        println!("  {} {same} unchanged", "=".dimmed());
    }

    println!();
    println!(
        "  Summary: {} added, {} removed, {} changed, {} unchanged",
        added.len().to_string().green(),
        removed.len().to_string().red(),
        changed.len().to_string().yellow(),
        same.to_string().dimmed()
    );

    Ok(())
}

fn expected_personal_sync_version(project_dir: &std::path::Path, force: bool) -> Option<i32> {
    if force {
        return None;
    }

    lpm_vault::vault_id::read_personal_sync_version(project_dir)
}

fn expected_org_sync_version(project_dir: &std::path::Path, org_slug: &str) -> Option<i32> {
    lpm_vault::vault_id::read_org_sync_version(project_dir, org_slug)
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
///     `vault:public-key:set` step-up proof via the WS2 reauth flow
///     and upload the local public key. The user gets an out-of-band
///     security email confirming the registration. Return the private
///     half for the caller's wrap operation.
///   - `RotationRequired`: server has a DIFFERENT key. Refuse to
///     proceed and point the user at `lpm env rotate-sharing-key` —
///     the explicit, interactive, reauthed flow that handles the
///     blast-radius confirmation + email fan-out. The CLI MUST NOT
///     silently overwrite here; that's the headline H16 vulnerability
///     the WS3 server gate exists to close, and the client side has
///     to hold its side of the contract.
async fn ensure_sharing_key_ready_for_org_op(
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

/// Implementation of the `lpm env rotate-sharing-key` command branch.
/// Extracted so the dispatcher arm stays small and the rotation flow
/// can be unit-tested independently in the future. See the dispatcher
/// docstring for the step-by-step flow.
async fn env_rotate_sharing_key(args: Vec<&str>, json_output: bool) -> Result<(), LpmError> {
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
    let auth_token = resolve_lpm_bearer(&registry_url, json_output).await?;

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

    // Acquire the WS2 step-up proof BEFORE generating the pending
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
        output::success(&format!(
            "sharing key rotated. New fingerprint: {}.",
            fp.bold()
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

/// Validate vault secrets against .env.example.
fn vars_validate(
    project_dir: &std::path::Path,
    strict: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let example_path = project_dir.join(".env.example");
    if !example_path.exists() {
        return Err(LpmError::Script(
            "no .env.example found. Create one with the required variable names.".into(),
        ));
    }

    let content = std::fs::read_to_string(&example_path)?;

    // Parse .env.example — extract key names (values are ignored)
    let required_keys: Vec<String> = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .filter_map(|line| {
            let trimmed = line.trim().strip_prefix("export ").unwrap_or(line.trim());
            trimmed.split_once('=').map(|(k, _)| k.trim().to_string())
        })
        .collect();

    let secrets = lpm_vault::try_get_all(project_dir).map_err(LpmError::Script)?;

    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut extra = Vec::new();

    for key in &required_keys {
        if secrets.contains_key(key) {
            present.push(key.as_str());
        } else {
            missing.push(key.as_str());
        }
    }

    if strict {
        let required_set: std::collections::HashSet<&str> =
            required_keys.iter().map(|s| s.as_str()).collect();
        for key in secrets.keys() {
            if !required_set.contains(key.as_str()) {
                extra.push(key.as_str());
            }
        }
    }

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "required": required_keys.len(),
                "present": present,
                "missing": missing,
                "extra": extra,
                "valid": missing.is_empty(),
            })
        );
        return Ok(());
    }

    println!();
    println!("  Validating against {}", ".env.example".bold());
    println!();

    for key in &present {
        println!("  {} {} {}", "✓".green(), key.bold(), "set".green());
    }
    for key in &missing {
        println!("  {} {} {}", "✗".red(), key.bold(), "missing".red());
    }
    for key in &extra {
        println!(
            "  {} {} {}",
            "!".yellow(),
            key.bold(),
            "not in .env.example (extra)".yellow()
        );
    }

    println!();
    if missing.is_empty() {
        output::success(&format!(
            "all {} required variables are set",
            required_keys.len()
        ));
    } else {
        let missing_list = missing.join(" ");
        println!(
            "  {} of {} required variables are missing",
            missing.len().to_string().red().bold(),
            required_keys.len()
        );
        println!(
            "  Fix: {}",
            format!("lpm env set {missing_list}=...").cyan()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── env push schema metadata helpers ────────────────────────────

    #[test]
    fn build_push_schema_value_returns_none_when_config_is_missing() {
        // No lpm.json → push sends no schema → server keeps last-known-good schema.
        assert!(build_push_schema_value(None).is_none());
    }

    #[test]
    fn build_push_schema_value_always_emits_version_marker() {
        // Even an empty config carries the version marker so the server can
        // distinguish "CLI-fresh, but author cleared the schema" from
        // "CLI never sent metadata" (None).
        let cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        let value =
            build_push_schema_value(Some(&cfg)).expect("empty config still emits an object");
        let obj = value.as_object().expect("schema must be a JSON object");
        assert_eq!(obj.get("version"), Some(&serde_json::json!(2)));
        assert!(!obj.contains_key("envSchema"));
        assert!(!obj.contains_key("envConfig"));
        assert!(!obj.contains_key("environments"));
    }

    #[test]
    fn build_push_schema_value_includes_env_schema_vars() {
        let mut cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        let mut vars = std::collections::HashMap::new();
        vars.insert(
            "DATABASE_URL".to_string(),
            lpm_env::EnvVarRule {
                required: true,
                ..Default::default()
            },
        );
        cfg.env_schema = Some(lpm_env::EnvSchema { vars });

        let value =
            build_push_schema_value(Some(&cfg)).expect("config with envSchema emits a value");
        let env_schema = value
            .get("envSchema")
            .expect("envSchema field must round-trip on push");
        assert!(
            env_schema.get("DATABASE_URL").is_some(),
            "var entries must be flat, not wrapped in EnvSchema"
        );
    }

    #[test]
    fn build_push_schema_value_includes_env_config_when_aliases_defined() {
        let mut cfg = lpm_runner::lpm_json::LpmJsonConfig::default();
        cfg.env.insert("dev".into(), ".env.development".into());

        let value = build_push_schema_value(Some(&cfg)).expect("config with env emits a value");
        let env_config = value
            .get("envConfig")
            .and_then(|v| v.as_object())
            .expect("envConfig must serialize as an object");
        let dev = env_config
            .get("dev")
            .and_then(|v| v.as_object())
            .expect("alias entry must serialize as an object");
        assert_eq!(
            dev.get("canonical"),
            Some(&serde_json::json!("development"))
        );
        assert_eq!(
            dev.get("file"),
            Some(&serde_json::json!(".env.development"))
        );
    }

    #[test]
    fn read_lpm_json_for_push_returns_none_when_file_missing() {
        // Absent lpm.json is not a warning condition — push just doesn't send schema.
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_lpm_json_for_push(dir.path()).is_none());
    }

    #[test]
    fn read_lpm_json_for_push_returns_none_on_malformed_lpm_json() {
        // Malformed lpm.json must not abort the push — return None and (in practice)
        // emit a stderr warning so the silent-stale-schema state is observable.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lpm.json"), "{ this is not json")
            .expect("seed broken lpm.json");
        let parsed = read_lpm_json_for_push(dir.path());
        assert!(
            parsed.is_none(),
            "malformed lpm.json must yield None so the push proceeds without metadata"
        );
    }

    #[test]
    fn read_lpm_json_for_push_returns_some_on_valid_lpm_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{"envSchema":{"vars":{"FOO":{"required":true}}}}"#,
        )
        .expect("seed valid lpm.json");
        let parsed = read_lpm_json_for_push(dir.path()).expect("valid lpm.json must parse");
        assert!(
            parsed.env_schema.is_some(),
            "envSchema field must round-trip through the parser helper"
        );
    }

    #[test]
    fn build_sync_environments_canonicalizes_legacy_alias_keys() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([(String::from("API_KEY"), String::from("legacy-secret"))]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);

        assert_eq!(
            sync_envs.len(),
            1,
            "sync payload should contain exactly one environment"
        );
        assert!(
            sync_envs.contains_key("development"),
            "legacy alias keys should be canonicalized before sync"
        );
        assert!(
            !sync_envs.contains_key("dev"),
            "legacy alias storage keys should not leak into cloud sync payloads"
        );
    }

    #[test]
    fn build_sync_environments_prefers_canonical_values_when_legacy_alias_collides() {
        let mut env_map = HashMap::new();
        env_map.insert("dev".into(), ".env.development".into());

        let mut all_envs = HashMap::new();
        all_envs.insert(
            "dev".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("legacy")),
                (String::from("ONLY_LEGACY"), String::from("present")),
            ]),
        );
        all_envs.insert(
            "development".into(),
            HashMap::from([
                (String::from("SHARED"), String::from("canonical")),
                (String::from("ONLY_CANONICAL"), String::from("present")),
            ]),
        );

        let sync_envs = build_sync_environments(&all_envs, &env_map, None);
        let development = sync_envs
            .get("development")
            .expect("canonical environment should be present in sync payload");

        assert_eq!(
            sync_envs.len(),
            1,
            "legacy alias and canonical env should collapse into one sync payload entry"
        );
        assert_eq!(
            development.get("SHARED").map(String::as_str),
            Some("canonical")
        );
        assert_eq!(
            development.get("ONLY_LEGACY").map(String::as_str),
            Some("present")
        );
        assert_eq!(
            development.get("ONLY_CANONICAL").map(String::as_str),
            Some("present")
        );
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_uses_remote_environments_exactly() {
        let raw_json = serde_json::json!({
            "environments": {
                "default": {
                    "KEEP": "remote",
                    "REMOTE_ONLY": "fresh"
                },
                "production": {
                    "PROD_ONLY": "remote"
                }
            }
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("KEEP"))
                .map(String::as_str),
            Some("remote")
        );
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("REMOTE_ONLY"))
                .map(String::as_str),
            Some("fresh")
        );
        assert!(
            parsed
                .get("default")
                .and_then(|env| env.get("DROP_ME"))
                .is_none()
        );
        assert!(!parsed.contains_key("preview"));
        assert_eq!(
            parsed
                .get("production")
                .and_then(|env| env.get("PROD_ONLY"))
                .map(String::as_str),
            Some("remote")
        );
    }

    #[test]
    fn parse_remote_pull_payload_for_overwrite_wraps_flat_payload_as_default() {
        let raw_json = serde_json::json!({
            "KEEP": "remote",
            "REMOTE_ONLY": "fresh"
        })
        .to_string();

        let parsed = parse_remote_pull_payload_for_overwrite(&raw_json).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("KEEP"))
                .map(String::as_str),
            Some("remote")
        );
        assert_eq!(
            parsed
                .get("default")
                .and_then(|env| env.get("REMOTE_ONLY"))
                .map(String::as_str),
            Some("fresh")
        );
    }

    // ── No legacy `lpm use vars` strings in production ─────────────
    // The command was renamed top-level to `lpm env`; this regression
    // test ensures no production string still references the old form.

    #[test]
    fn no_old_command_name_in_source() {
        let source = include_str!("env.rs");
        // Build the forbidden pattern dynamically so the test itself doesn't contain it
        let forbidden = format!("lpm use {}", "vars");
        let production_code = source.split("#[cfg(test)]").next().unwrap_or(source);
        let count = production_code.matches(&forbidden).count();
        assert_eq!(
            count, 0,
            "found {count} occurrence(s) of the old `lpm use vars` command surface in production code — all user-facing strings should reference `lpm env`"
        );
    }

    #[test]
    fn expected_personal_sync_version_uses_stored_version_when_not_forced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), false), Some(6));
    }

    #[test]
    fn expected_personal_sync_version_skips_cas_in_force_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_personal_sync_version(dir.path(), 6).unwrap();

        assert_eq!(expected_personal_sync_version(dir.path(), true), None);
    }

    #[test]
    fn expected_org_sync_version_reads_org_scoped_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{"vault":"vault-123"}"#).unwrap();
        lpm_vault::vault_id::write_org_sync_version(dir.path(), "acme", 9).unwrap();

        assert_eq!(expected_org_sync_version(dir.path(), "acme"), Some(9));
        assert_eq!(expected_org_sync_version(dir.path(), "umbrella"), None);
    }

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
