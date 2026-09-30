use super::{
    exchange_client, finish_session, generate_pkce_pair, parse_cli_exchange_session,
    read_capped_exchange_body,
};
use crate::install_ui;
use lpm_common::{AtomicWriteOptions, LpmError, paths::LpmRoot};
use lpm_registry::RegistryClient;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const REQUEST_LIFETIME_SECS: u64 = 600;
const POLL_INTERVAL_SECS: u64 = 3;
const REQUEST_MAX_BYTES: u64 = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingLogin {
    version: u8,
    registry: String,
    code_verifier: String,
    verification_uri: String,
    expires_at: u64,
}

impl PendingLogin {
    fn pending_json(&self, id: &str, interval: u64) -> serde_json::Value {
        serde_json::json!({
            "success": true,
            "status": "authorization_pending",
            "login_id": id,
            "registry": self.registry,
            "verification_uri": self.verification_uri,
            "request_code": &super::pkce_challenge(&self.code_verifier)[..8],
            "expires_at": self.expires_at,
            "interval": interval,
        })
    }
}

pub(super) async fn start(
    client: &RegistryClient,
    registry: &str,
    json: bool,
) -> Result<(), LpmError> {
    let (verifier, challenge) = generate_pkce_pair();
    let id = {
        use rand::RngCore;
        let mut bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let mut uri = reqwest::Url::parse(&format!("{}/cli/login", registry.trim_end_matches('/')))
        .map_err(|_| LpmError::Registry("Invalid sign-in registry URL".into()))?;
    let fingerprint = lpm_auth::compute_device_fingerprint();
    let name = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "CLI".into());
    uri.query_pairs_mut()
        .append_pair("mode", "device")
        .append_pair("fp", &fingerprint)
        .append_pair("dn", &name)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let request = PendingLogin {
        version: 1,
        registry: registry.to_owned(),
        code_verifier: verifier,
        verification_uri: uri.to_string(),
        expires_at: now()?.saturating_add(REQUEST_LIFETIME_SECS),
    };
    let directory = request_directory()?;
    remove_expired_requests(&directory);
    let path = directory.join(format!("{id}.json"));
    lpm_common::write_file_atomic_with_options(
        &path,
        serde_json::to_vec(&request)?,
        AtomicWriteOptions::new()
            .unix_mode(0o600)
            .sync_file()
            .sync_parent(),
    )?;
    if json {
        print_json(&request.pending_json(&id, POLL_INTERVAL_SECS))?;
        return Ok(());
    }
    install_ui::phase("Authorize this host from a browser on any device");
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  {}",
        install_ui::url(uri.as_str())
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  Request code: {}",
        install_ui::field(&challenge[..8])
    ));
    install_ui::detail_line(crate::install_ui::terminal_line!(
        "  To resume on this host: lpm login --complete {}",
        install_ui::field(&id)
    ));
    complete_request(client, &request, &path, &id, false).await
}

pub(super) async fn complete(
    client: &RegistryClient,
    registry: &str,
    id: &str,
    json: bool,
) -> Result<(), LpmError> {
    if !valid_id(id) {
        return Err(LpmError::Registry(
            "Invalid login ID. Use the ID from `lpm login --device`.".into(),
        ));
    }
    let path = request_directory()?.join(format!("{id}.json"));
    let request = read_request(&path)?;
    if request.registry != registry {
        return Err(LpmError::Registry(
            "This login request belongs to another registry. Use the original --registry value."
                .into(),
        ));
    }
    if request.version != 1
        || request.code_verifier.len() != 43
        || !request
            .code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LpmError::Registry(
            "Invalid saved login request. Start a new sign-in.".into(),
        ));
    }
    complete_request(client, &request, &path, id, json).await
}

async fn complete_request(
    client: &RegistryClient,
    request: &PendingLogin,
    path: &Path,
    id: &str,
    json: bool,
) -> Result<(), LpmError> {
    let remaining = request.expires_at.saturating_sub(now()?);
    if remaining == 0 || remaining > REQUEST_LIFETIME_SECS {
        std::fs::remove_file(path)?;
        return Err(LpmError::Registry(
            "This sign-in request expired. Run `lpm login --device` again.".into(),
        ));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(remaining);
    let http = exchange_client(Duration::from_secs(30))?;
    let endpoint = format!("{}/api/cli/device", request.registry.trim_end_matches('/'));
    loop {
        let poll = async {
            let response = http
                .post(&endpoint)
                .json(&serde_json::json!({"code_verifier": request.code_verifier}))
                .send()
                .await
                .map_err(|error| {
                    LpmError::Network(format!(
                        "Sign-in polling failed: {}",
                        lpm_http::display_error(&error)
                    ))
                })?;
            let status = response.status();
            let interval = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(POLL_INTERVAL_SECS)
                .clamp(POLL_INTERVAL_SECS, REQUEST_LIFETIME_SECS);
            let body = read_capped_exchange_body(response).await?;
            if status == reqwest::StatusCode::OK {
                return Ok((Some(parse_cli_exchange_session(&body)?), interval));
            }
            if status == reqwest::StatusCode::ACCEPTED {
                return Ok((None, interval));
            }
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                if json {
                    return Err(LpmError::RateLimited {
                        retry_after_secs: interval,
                    });
                }
                return Ok((None, interval));
            }
            if status.is_server_error() {
                if json {
                    return Err(LpmError::Registry("Cross-device sign-in is temporarily unavailable. Retry this login ID later.".into()));
                }
                return Ok((None, interval));
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(LpmError::Registry("This registry does not support cross-device sign-in. Use local browser sign-in or update the registry server.".into()));
            }
            if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::FORBIDDEN {
                std::fs::remove_file(path)?;
                return Err(LpmError::Registry("This sign-in request was declined or already completed. Run `lpm login --device` again.".into()));
            }
            Err(LpmError::Registry(format!(
                "Cross-device sign-in failed (HTTP {status}). Start a new sign-in if this request was already completed."
            )))
        };
        let (session, interval) =
            tokio::time::timeout_at(deadline, poll)
                .await
                .map_err(|_| {
                    LpmError::Registry("Sign-in timed out. Run `lpm login --device` again.".into())
                })??;
        if let Some(session) = session {
            finish_session(client, &request.registry, session, json).await?;
            std::fs::remove_file(path)?;
            return Ok(());
        }
        if json {
            print_json(&request.pending_json(id, interval))?;
            return Ok(());
        }
        tokio::time::sleep_until(std::cmp::min(
            deadline,
            tokio::time::Instant::now() + Duration::from_secs(interval),
        ))
        .await;
    }
}

fn request_directory() -> Result<PathBuf, LpmError> {
    let root = LpmRoot::from_env()?;
    std::fs::create_dir_all(root.root())?;
    let path = root.root().join("login-requests");
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    if let Err(error) = builder.create(&path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(error.into());
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(LpmError::Registry(
            "The saved-login directory must be a private directory, not a link.".into(),
        ));
    }
    #[cfg(unix)]
    if !lpm_common::permissions_are_owner_only(&metadata.permissions()) {
        return Err(LpmError::Registry(
            "The saved-login directory must have owner-only permissions.".into(),
        ));
    }
    Ok(path)
}

fn read_request(path: &Path) -> Result<PendingLogin, LpmError> {
    #[cfg(unix)]
    {
        let metadata = std::fs::symlink_metadata(path)?;
        if !lpm_common::permissions_are_owner_only(&metadata.permissions()) {
            return Err(LpmError::Registry(
                "The saved-login request must have owner-only permissions.".into(),
            ));
        }
    }
    let text = lpm_common::read_text_file_capped_nofollow(path, REQUEST_MAX_BYTES)
        .map_err(|_| LpmError::Registry("Unable to read this login request. Start sign-in on this host with `lpm login --device`.".into()))?;
    serde_json::from_str(&text)
        .map_err(|_| LpmError::Registry("Invalid saved login request. Start a new sign-in.".into()))
}

fn remove_expired_requests(directory: &Path) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let Ok(time) = now() else { return };
    for entry in entries.take(1024).flatten() {
        let path = entry.path();
        if path
            .file_stem()
            .and_then(|value| value.to_str())
            .is_some_and(valid_id)
            && path.extension().is_some_and(|value| value == "json")
            && let Ok(request) = read_request(&path)
            && request.expires_at <= time
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now() -> Result<u64, LpmError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| LpmError::Registry("The system clock is invalid for sign-in.".into()))
}

fn print_json(value: &serde_json::Value) -> Result<(), LpmError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
