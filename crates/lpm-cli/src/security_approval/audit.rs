use super::prelude::*;

pub(super) fn audit_signature_payload(
    event: &AuditEvent,
    previous_entry_hash: &Option<String>,
) -> serde_json::Value {
    serde_json::json!({
        "payload": event,
        "previous_entry_hash": previous_entry_hash,
    })
}

pub(super) fn hash_json_value(value: &serde_json::Value) -> Result<String, LpmError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn verify_audit_envelope(
    envelope: &SignedAuditEnvelope,
    expected_previous: &Option<String>,
) -> Result<(), LpmError> {
    if &envelope.previous_entry_hash != expected_previous {
        return Err(LpmError::Registry(
            "security audit log hash chain is broken; possible tampering".into(),
        ));
    }
    let payload_value = audit_signature_payload(&envelope.payload, &envelope.previous_entry_hash);
    if hash_json_value(&payload_value)? != envelope.entry_hash {
        return Err(LpmError::Registry(
            "security audit log entry hash does not match payload; possible tampering".into(),
        ));
    }
    if !verify_payload_value(&payload_value, &envelope.signature)? {
        return Err(LpmError::Registry(
            "security audit log entry failed signature verification; possible tampering".into(),
        ));
    }
    Ok(())
}

fn legacy_audit_entry_hash(parsed: &serde_json::Value) -> Result<String, LpmError> {
    let Some(signature) = parsed.get("signature").and_then(|value| value.as_str()) else {
        let _: AuditEvent = serde_json::from_value(parsed.clone()).map_err(|e| {
            LpmError::Registry(format!("legacy security audit log entry parse error: {e}"))
        })?;
        return hash_json_value(parsed);
    };

    let payload = parsed.get("payload").cloned().ok_or_else(|| {
        LpmError::Registry("legacy security audit log entry is missing a payload".into())
    })?;
    if !verify_payload_value(&payload, signature)? {
        return Err(LpmError::Registry(
            "legacy security audit log entry failed signature verification; possible tampering"
                .into(),
        ));
    }
    let _: SignedEnvelope<AuditEvent> = serde_json::from_value(parsed.clone()).map_err(|e| {
        LpmError::Registry(format!("legacy security audit log entry parse error: {e}"))
    })?;
    hash_json_value(parsed)
}

pub(super) fn read_audit_log_tail(path: &Path) -> Result<(Option<String>, u64), LpmError> {
    if !path.exists() {
        return Ok((None, 0));
    }
    let body = std::fs::read_to_string(path)?;
    let mut previous = None;
    let mut count = 0;
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let parsed: serde_json::Value = serde_json::from_str(line).map_err(|e| {
            LpmError::Registry(format!("security audit log entry parse error: {e}"))
        })?;
        if parsed.get("entry_hash").is_some() || parsed.get("previous_entry_hash").is_some() {
            let envelope: SignedAuditEnvelope = serde_json::from_value(parsed).map_err(|e| {
                LpmError::Registry(format!("security audit log entry parse error: {e}"))
            })?;
            verify_audit_envelope(&envelope, &previous)?;
            previous = Some(envelope.entry_hash);
        } else {
            previous = Some(legacy_audit_entry_hash(&parsed)?);
        }
        count += 1;
    }
    Ok((previous, count))
}

#[cfg(test)]
fn load_audit_head() -> Result<Option<AuditHead>, LpmError> {
    read_signed_json(&audit_head_path()?)
}

#[cfg(test)]
fn persist_audit_head(head: &AuditHead) -> Result<(), LpmError> {
    write_signed_json(&audit_head_path()?, head)
}

#[cfg(not(test))]
fn load_audit_head() -> Result<Option<AuditHead>, LpmError> {
    if force_file_audit_head_backend() {
        return read_signed_json(&audit_head_path()?);
    }

    let account = keyring_account(KEYRING_AUDIT_HEAD_ACCOUNT)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| LpmError::Registry(format!("security audit keyring error: {e}")))?;
    let raw = match entry.get_password() {
        Ok(value) => value,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => {
            return Err(LpmError::Registry(format!(
                "security audit keyring read error: {e}"
            )));
        }
    };
    let parsed: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LpmError::Registry(format!("security audit head parse error: {e}")))?;
    let signature = parsed
        .get("signature")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LpmError::Registry("security audit head is missing a signature".into()))?;
    let payload = parsed
        .get("payload")
        .cloned()
        .ok_or_else(|| LpmError::Registry("security audit head is missing a payload".into()))?;
    if !verify_payload_value(&payload, signature)? {
        return Err(LpmError::Registry(
            "security audit head failed signature verification; possible tampering".into(),
        ));
    }
    let envelope: SignedEnvelope<AuditHead> = serde_json::from_value(parsed)
        .map_err(|e| LpmError::Registry(format!("security audit head parse error: {e}")))?;
    Ok(Some(envelope.payload))
}

#[cfg(not(test))]
fn persist_audit_head(head: &AuditHead) -> Result<(), LpmError> {
    if force_file_audit_head_backend() {
        return write_signed_json(&audit_head_path()?, head);
    }

    let payload_value = serde_json::to_value(head)?;
    let envelope = SignedEnvelope {
        payload: head.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    let body = serde_json::to_string(&envelope)?;
    let account = keyring_account(KEYRING_AUDIT_HEAD_ACCOUNT)?;
    keyring::Entry::new(KEYRING_SERVICE, &account)
        .map_err(|e| LpmError::Registry(format!("security audit keyring error: {e}")))?
        .set_password(&body)
        .map_err(|e| LpmError::Registry(format!("security audit keyring write error: {e}")))?;
    Ok(())
}

pub(super) fn append_audit_event(event: &AuditEvent) -> Result<(), LpmError> {
    let path = audit_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let (previous_entry_hash, entry_count) = read_audit_log_tail(&path)?;
    if let Some(head) = load_audit_head()?
        && (head.last_entry_hash != previous_entry_hash.as_deref().unwrap_or_default()
            || head.entry_count != entry_count)
    {
        return Err(LpmError::Registry(
            "security audit log does not match the signed audit head; possible tampering".into(),
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let payload_value = audit_signature_payload(event, &previous_entry_hash);
    let entry_hash = hash_json_value(&payload_value)?;
    let envelope = SignedAuditEnvelope {
        payload: event.clone(),
        previous_entry_hash,
        entry_hash: entry_hash.clone(),
        signature: sign_payload_value(&payload_value)?,
    };
    writeln!(file, "{}", serde_json::to_string(&envelope)?)?;
    persist_audit_head(&AuditHead {
        schema_version: AUDIT_HEAD_SCHEMA_VERSION,
        updated_at: Utc::now(),
        last_entry_hash: entry_hash,
        entry_count: entry_count + 1,
    })?;
    Ok(())
}

pub(super) struct AuditRecord {
    event: String,
    allowed: bool,
    scopes: Vec<String>,
    project_root: Option<String>,
    packages: Vec<String>,
    source: Option<String>,
    unlock_id: Option<String>,
    detail: Option<String>,
}

impl AuditRecord {
    pub(super) fn new(event: impl Into<String>, allowed: bool, scopes: Vec<String>) -> Self {
        Self {
            event: event.into(),
            allowed,
            scopes,
            project_root: None,
            packages: Vec::new(),
            source: None,
            unlock_id: None,
            detail: None,
        }
    }

    pub(super) fn project_root(mut self, project_root: impl Into<String>) -> Self {
        self.project_root = Some(project_root.into());
        self
    }

    pub(super) fn packages(mut self, packages: Vec<String>) -> Self {
        self.packages = packages;
        self
    }

    pub(super) fn source(mut self, source: ApprovalSource) -> Self {
        self.source = Some(source.as_str().to_string());
        self
    }

    pub(super) fn unlock_id(mut self, unlock_id: String) -> Self {
        self.unlock_id = Some(unlock_id);
        self
    }

    pub(super) fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

pub(super) fn record_audit_event(record: AuditRecord) {
    let event = AuditEvent {
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        occurred_at: Utc::now(),
        event: record.event,
        allowed: record.allowed,
        scopes: record.scopes,
        project_root: record.project_root,
        packages: normalized_packages(&record.packages),
        source: record.source,
        unlock_id: record.unlock_id,
        detail: record.detail,
    };
    if let Err(err) = append_audit_event(&event) {
        tracing::warn!("failed to append security audit event: {err}");
    }
}
