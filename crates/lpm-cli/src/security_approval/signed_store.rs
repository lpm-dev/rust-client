use super::prelude::*;

#[derive(Debug)]
enum SigningSecretReadError {
    Missing,
    Corrupt(String),
    Unavailable(String),
}

impl SigningSecretReadError {
    fn into_lpm_error(self) -> LpmError {
        match self {
            Self::Missing => security_store_error(
                "security approval signing secret is missing; existing signed security state cannot be verified",
            ),
            Self::Corrupt(message) | Self::Unavailable(message) => security_store_error(message),
        }
    }
}

struct ParsedSignedJson {
    parsed: serde_json::Value,
    payload: serde_json::Value,
    signature: String,
}

fn security_store_error(message: impl Into<String>) -> LpmError {
    LpmError::SecurityApprovalStore(message.into())
}

fn signed_state_file_error(path: &Path, message: impl AsRef<str>) -> LpmError {
    security_store_error(format!(
        "signed security state file {} {}; run `lpm security repair` to quarantine unverified local approvals, or restore the original signing secret",
        path.display(),
        message.as_ref(),
    ))
}

fn decode_signing_secret(
    raw: &str,
    source: &'static str,
) -> Result<Vec<u8>, SigningSecretReadError> {
    let secret = hex::decode(raw.trim()).map_err(|e| {
        SigningSecretReadError::Corrupt(format!("{source} is corrupt; expected hex: {e}"))
    })?;
    if secret.len() != SIGNING_SECRET_BYTES {
        return Err(SigningSecretReadError::Corrupt(format!(
            "{source} is corrupt; expected {SIGNING_SECRET_BYTES} bytes, got {} bytes",
            secret.len(),
        )));
    }
    Ok(secret)
}

fn random_signing_secret() -> [u8; SIGNING_SECRET_BYTES] {
    let mut secret = [0u8; SIGNING_SECRET_BYTES];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

fn read_file_signing_secret(path: &Path) -> Result<Vec<u8>, SigningSecretReadError> {
    if !path.exists() {
        return Err(SigningSecretReadError::Missing);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| {
        SigningSecretReadError::Unavailable(format!(
            "security approval signing secret {} could not be read: {e}",
            path.display(),
        ))
    })?;
    decode_signing_secret(&raw, "security approval file signing secret")
}

fn create_file_signing_secret(path: &Path) -> Result<Vec<u8>, LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let secret = random_signing_secret();
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            writeln!(file, "{}", hex::encode(secret))?;
            Ok(secret.to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            read_file_signing_secret(path).map_err(SigningSecretReadError::into_lpm_error)
        }
        Err(e) => Err(LpmError::Io(e)),
    }
}

fn stored_signing_secret() -> Result<Vec<u8>, SigningSecretReadError> {
    if let Some(raw) = test_secret_override() {
        return decode_signing_secret(&raw, "test security secret override");
    }

    if force_file_audit_head_backend() {
        let path = signing_secret_path()
            .map_err(|e| SigningSecretReadError::Unavailable(e.to_string()))?;
        return read_file_signing_secret(&path);
    }

    let account = keyring_account(KEYRING_ACCOUNT)
        .map_err(|e| SigningSecretReadError::Unavailable(e.to_string()))?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account).map_err(|e| {
        SigningSecretReadError::Unavailable(format!("security approval keyring error: {e}"))
    })?;

    match entry.get_password() {
        Ok(existing) => decode_signing_secret(&existing, "security approval keyring entry"),
        Err(keyring::Error::NoEntry) => Err(SigningSecretReadError::Missing),
        Err(e) => Err(SigningSecretReadError::Unavailable(format!(
            "security approval keyring read error: {e}"
        ))),
    }
}

fn read_signing_secret() -> Result<Vec<u8>, LpmError> {
    stored_signing_secret().map_err(SigningSecretReadError::into_lpm_error)
}

fn get_or_create_signing_secret() -> Result<Vec<u8>, LpmError> {
    match stored_signing_secret() {
        Ok(secret) => Ok(secret),
        Err(SigningSecretReadError::Missing) => create_signing_secret(),
        Err(e) => Err(e.into_lpm_error()),
    }
}

fn create_signing_secret() -> Result<Vec<u8>, LpmError> {
    if force_file_audit_head_backend() {
        return create_file_signing_secret(&signing_secret_path()?);
    }

    let account = keyring_account(KEYRING_ACCOUNT)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| security_store_error(format!("security approval keyring error: {e}")))?;

    let secret = random_signing_secret();
    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| security_store_error(format!("security approval keyring write error: {e}")))?;
    Ok(secret.to_vec())
}

fn sign_payload_value_with_secret(
    payload: &serde_json::Value,
    secret: &[u8],
) -> Result<String, LpmError> {
    let bytes = serde_json::to_vec(payload)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| LpmError::Registry(format!("security approval signer init failed: {e}")))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub(super) fn sign_payload_value(payload: &serde_json::Value) -> Result<String, LpmError> {
    let secret = get_or_create_signing_secret()?;
    sign_payload_value_with_secret(payload, &secret)
}

fn verify_payload_value_with_secret(
    payload: &serde_json::Value,
    signature: &str,
    secret: &[u8],
) -> Result<bool, LpmError> {
    let expected = match hex::decode(signature.trim()) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let bytes = serde_json::to_vec(payload)?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| LpmError::Registry(format!("security approval signer init failed: {e}")))?;
    mac.update(&bytes);
    Ok(mac.verify_slice(&expected).is_ok())
}

pub(super) fn verify_payload_value(
    payload: &serde_json::Value,
    signature: &str,
) -> Result<bool, LpmError> {
    let secret = read_signing_secret()?;
    verify_payload_value_with_secret(payload, signature, &secret)
}

pub(super) fn write_signed_json<T: Serialize + Clone>(
    path: &Path,
    payload: &T,
) -> Result<(), LpmError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let payload_value = serde_json::to_value(payload)?;
    let envelope = SignedEnvelope {
        payload: payload.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    let body = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(path, body)?;
    Ok(())
}

fn parse_signed_json_file(path: &Path) -> Result<Option<ParsedSignedJson>, LpmError> {
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(path)?;
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| signed_state_file_error(path, format!("has invalid JSON: {e}")))?;
    let signature = parsed
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| signed_state_file_error(path, "is missing a signature"))?
        .to_string();
    let payload = parsed
        .get("payload")
        .cloned()
        .ok_or_else(|| signed_state_file_error(path, "is missing a payload"))?;
    Ok(Some(ParsedSignedJson {
        parsed,
        payload,
        signature,
    }))
}

pub(super) fn read_signed_json<T>(path: &Path) -> Result<Option<T>, LpmError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let Some(parsed) = parse_signed_json_file(path)? else {
        return Ok(None);
    };
    if !verify_payload_value(&parsed.payload, &parsed.signature)? {
        return Err(signed_state_file_error(
            path,
            "failed signature verification",
        ));
    }
    let envelope: SignedEnvelope<T> = serde_json::from_value(parsed.parsed)
        .map_err(|e| signed_state_file_error(path, format!("has invalid payload: {e}")))?;
    Ok(Some(envelope.payload))
}

fn push_existing_path(paths: &mut Vec<PathBuf>, path: PathBuf) -> Result<(), LpmError> {
    if path.try_exists()? {
        paths.push(path);
    }
    Ok(())
}

fn push_existing_json_files(paths: &mut Vec<PathBuf>, dir: PathBuf) -> Result<(), LpmError> {
    if !dir.try_exists()? {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    Ok(())
}

fn signed_security_state_paths() -> Result<Vec<PathBuf>, LpmError> {
    let mut paths = Vec::with_capacity(8);
    push_existing_path(&mut paths, approved_posture_path()?)?;
    push_existing_path(&mut paths, approved_global_trust_path()?)?;
    push_existing_path(&mut paths, audit_head_path()?)?;
    push_existing_json_files(&mut paths, approved_projects_dir()?)?;
    push_existing_json_files(&mut paths, unlocks_dir()?)?;
    paths.sort();
    Ok(paths)
}

fn existing_nonempty_audit_log_path() -> Result<Option<PathBuf>, LpmError> {
    let path = audit_log_path()?;
    if !path.try_exists()? || path.metadata()?.len() == 0 {
        return Ok(None);
    }
    Ok(Some(path))
}

fn signed_json_unverified_reason(path: &Path, secret: &[u8]) -> Result<Option<String>, LpmError> {
    let body = std::fs::read_to_string(path)?;
    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(parsed) => parsed,
        Err(e) => return Ok(Some(format!("invalid JSON: {e}"))),
    };
    let Some(signature) = parsed.get("signature").and_then(|value| value.as_str()) else {
        return Ok(Some("missing signature".to_string()));
    };
    let Some(payload) = parsed.get("payload").cloned() else {
        return Ok(Some("missing payload".to_string()));
    };
    if verify_payload_value_with_secret(&payload, signature, secret)? {
        Ok(None)
    } else {
        Ok(Some("signature verification failed".to_string()))
    }
}

fn audit_log_unverified_reason(path: &Path, secret: &[u8]) -> Result<Option<String>, LpmError> {
    let body = std::fs::read_to_string(path)?;
    let mut previous = None;
    for (index, line) in body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let line_number = index + 1;
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(parsed) => parsed,
            Err(e) => return Ok(Some(format!("line {line_number} has invalid JSON: {e}"))),
        };

        if parsed.get("entry_hash").is_some() || parsed.get("previous_entry_hash").is_some() {
            let envelope: SignedAuditEnvelope = match serde_json::from_value(parsed) {
                Ok(envelope) => envelope,
                Err(e) => {
                    return Ok(Some(format!(
                        "line {line_number} has invalid audit entry: {e}"
                    )));
                }
            };
            if envelope.previous_entry_hash != previous {
                return Ok(Some(format!(
                    "line {line_number} breaks the audit hash chain"
                )));
            }
            let payload_value =
                audit_signature_payload(&envelope.payload, &envelope.previous_entry_hash);
            if hash_json_value(&payload_value)? != envelope.entry_hash {
                return Ok(Some(format!(
                    "line {line_number} hash does not match its payload"
                )));
            }
            if !verify_payload_value_with_secret(&payload_value, &envelope.signature, secret)? {
                return Ok(Some(format!(
                    "line {line_number} failed signature verification"
                )));
            }
            previous = Some(envelope.entry_hash);
        } else {
            let Some(signature) = parsed.get("signature").and_then(|value| value.as_str()) else {
                return Ok(Some(format!("line {line_number} is missing a signature")));
            };
            let Some(payload) = parsed.get("payload").cloned() else {
                return Ok(Some(format!("line {line_number} is missing a payload")));
            };
            if !verify_payload_value_with_secret(&payload, signature, secret)? {
                return Ok(Some(format!(
                    "line {line_number} failed signature verification"
                )));
            }
            let _: SignedEnvelope<AuditEvent> = match serde_json::from_value(parsed.clone()) {
                Ok(envelope) => envelope,
                Err(e) => {
                    return Ok(Some(format!(
                        "line {line_number} has invalid legacy audit entry: {e}"
                    )));
                }
            };
            previous = Some(hash_json_value(&parsed)?);
        }
    }
    Ok(None)
}

fn quarantine_path_for(path: &Path) -> Result<PathBuf, LpmError> {
    let parent = path.parent().ok_or_else(|| {
        security_store_error(format!(
            "signed security state file {} has no parent directory",
            path.display()
        ))
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            security_store_error(format!(
                "signed security state file {} has a non-UTF-8 file name",
                path.display()
            ))
        })?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    for index in 0..1000 {
        let suffix = if index == 0 {
            format!(".unverified-{stamp}")
        } else {
            format!(".unverified-{stamp}-{index}")
        };
        let candidate = parent.join(format!("{file_name}{suffix}"));
        if !candidate.try_exists()? {
            return Ok(candidate);
        }
    }
    Err(security_store_error(format!(
        "could not find an unused quarantine name for {}",
        path.display()
    )))
}

fn quarantine_security_state_file(
    path: &Path,
    reason: impl Into<String>,
) -> Result<QuarantinedSecurityState, LpmError> {
    let reason = reason.into();
    let quarantine_path = quarantine_path_for(path)?;
    std::fs::rename(path, &quarantine_path)?;
    Ok(QuarantinedSecurityState {
        original_path: path.display().to_string(),
        quarantine_path: quarantine_path.display().to_string(),
        reason,
    })
}

pub fn repair_security_state() -> Result<SecurityRepairReport, LpmError> {
    let security_dir = security_dir()?;
    let paths = signed_security_state_paths()?;
    let audit_log_path = existing_nonempty_audit_log_path()?;
    let mut quarantined = Vec::new();
    if paths.is_empty() && audit_log_path.is_none() {
        return Ok(SecurityRepairReport {
            security_dir: security_dir.display().to_string(),
            quarantined,
        });
    }

    match stored_signing_secret() {
        Ok(secret) => {
            for path in paths {
                if let Some(reason) = signed_json_unverified_reason(&path, &secret)? {
                    quarantined.push(quarantine_security_state_file(&path, reason)?);
                }
            }
            if let Some(path) = audit_log_path
                && let Some(reason) = audit_log_unverified_reason(&path, &secret)?
            {
                quarantined.push(quarantine_security_state_file(&path, reason)?);
            }
        }
        Err(SigningSecretReadError::Missing) => {
            for path in paths {
                quarantined.push(quarantine_security_state_file(
                    &path,
                    "signing secret missing",
                )?);
            }
            if let Some(path) = audit_log_path {
                quarantined.push(quarantine_security_state_file(
                    &path,
                    "signing secret missing",
                )?);
            }
        }
        Err(e) => return Err(e.into_lpm_error()),
    }

    Ok(SecurityRepairReport {
        security_dir: security_dir.display().to_string(),
        quarantined,
    })
}
