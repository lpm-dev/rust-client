use super::public_key::ValidatedSharingKey;
use crate::crypto;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde_json::map::Entry;

pub(super) const REQUEST_NONCE_HEADER: &str = "X-LPM-Vault-Request-Nonce";

const ENVELOPE_VERSION: i32 = 3;
const MAX_ORGANIZATION_MEMBERS: usize = 10_000;
const MAX_REVISION: i32 = i32::MAX;
const REQUEST_NONCE_BYTES: usize = 32;

#[derive(Clone, Copy)]
pub(super) enum SyncScope<'a> {
    Personal,
    Organization(&'a str),
}

#[derive(Clone, Copy)]
pub(super) enum SyncEnvelopePolicy {
    Pull,
    Inspect,
    Write,
}

impl SyncEnvelopePolicy {
    fn operation(self) -> &'static str {
        match self {
            Self::Pull => "vault.pull",
            Self::Inspect => "vault.inspect",
            Self::Write => "vault.write",
        }
    }
}

#[derive(Debug)]
pub(super) struct AuthenticatedSyncResponse {
    pub(super) outcome: String,
    pub(super) encrypted_blob: Option<String>,
    pub(super) wrapped_key: Option<String>,
    pub(super) version: Option<i32>,
    pub(super) crypto_version: Option<i32>,
    pub(super) principal_id: Option<String>,
    pub(super) caller_user_id: Option<String>,
    pub(super) content_key_version: Option<i32>,
    pub(super) recipient_public_key_version: Option<i32>,
    pub(super) recipient_public_key_fingerprint: Option<String>,
    pub(super) status: Option<String>,
    pub(super) error: Option<String>,
    pub(super) code: Option<String>,
    pub(super) server_version: Option<i32>,
    pub(super) hint: Option<String>,
}

impl AuthenticatedSyncResponse {
    fn new(outcome: String, binding: ValidatedVaultBinding) -> Self {
        Self {
            outcome,
            encrypted_blob: None,
            wrapped_key: None,
            version: None,
            crypto_version: None,
            principal_id: Some(binding.principal_id),
            caller_user_id: binding.caller_user_id,
            content_key_version: None,
            recipient_public_key_version: None,
            recipient_public_key_fingerprint: None,
            status: None,
            error: None,
            code: None,
            server_version: None,
            hint: None,
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireEnvelope {
    envelope_version: i32,
    operation: String,
    outcome: String,
    request_nonce: String,
    binding: WireBinding,
    data: StrictValue,
}

#[derive(Debug, serde::Deserialize)]
#[serde(
    tag = "scope",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum WireBinding {
    #[serde(rename = "personal")]
    Personal {
        principal_id: String,
        caller_user_id: String,
        vault_id: String,
    },
    #[serde(rename = "organization")]
    Organization {
        principal_id: String,
        caller_user_id: String,
        organization_slug: String,
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "account")]
    Account {
        principal_id: String,
        #[serde(default)]
        organization_slug: Option<String>,
        #[serde(default)]
        vault_id: Option<String>,
    },
}

#[derive(Debug)]
struct StrictValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(value.to_owned().into()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(value.into()))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(serde_json::Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <StrictValue as serde::Deserialize>::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(values.into()))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::with_capacity(map.size_hint().unwrap_or(0));
        while let Some(key) = map.next_key::<String>()? {
            match values.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(map.next_value::<StrictValue>()?.0);
                }
                Entry::Occupied(entry) => {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate JSON object key {}",
                        entry.key()
                    )));
                }
            }
        }
        Ok(StrictValue(values.into()))
    }
}

#[derive(Debug)]
struct ValidatedVaultBinding {
    principal_id: String,
    caller_user_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultPayloadData {
    encrypted_blob: String,
    wrapped_key: String,
    revision: i32,
    crypto_version: i32,
    updated_at: String,
    #[serde(default)]
    content_key_version: OptionalField<i32>,
    #[serde(default)]
    recipient_public_key_version: OptionalField<i32>,
    #[serde(default)]
    recipient_public_key_fingerprint: OptionalField<String>,
}

#[derive(Debug, Default)]
enum OptionalField<T> {
    #[default]
    Absent,
    Null,
    Value(T),
}

impl<'de, T> serde::Deserialize<'de> for OptionalField<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

impl<T> OptionalField<T> {
    fn as_value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Absent | Self::Null => None,
        }
    }

    fn into_value(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Absent | Self::Null => None,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InspectData {
    revision: i32,
    crypto_version: i32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MissingData {
    retained_revision: i32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberRewrapData {
    revision: i32,
    content_key_version: i32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommittedData {
    revision: i32,
    #[serde(default)]
    content_key_version: Option<i32>,
    crypto_version: i32,
    action: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentRevisionData {
    current_revision: i32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CiphertextRevisionMismatchData {
    required_ciphertext_revision: i32,
    #[serde(default)]
    current_revision: Option<i32>,
    #[serde(default)]
    retained_revision: Option<i32>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RejectedData {
    code: String,
    message: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyData {}

#[derive(Debug)]
pub(super) struct AuthenticatedSharingKeyResponse {
    pub(super) outcome: String,
    pub(super) principal_id: String,
    pub(super) sharing_key: Option<ValidatedSharingKey>,
    pub(super) code: Option<String>,
    pub(super) message: Option<String>,
}

#[derive(Debug)]
pub(super) struct AuthenticatedMemberInventory {
    pub(super) organization_id: String,
    pub(super) caller_user_id: String,
    pub(super) can_replace_wrapped_keys: bool,
    pub(super) members: Vec<AuthenticatedMemberKey>,
}

#[derive(Debug)]
pub(super) struct AuthenticatedMemberKey {
    pub(super) user_id: String,
    pub(super) role: String,
    pub(super) sharing_key: Option<ValidatedSharingKey>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SharingKeyContainer {
    sharing_key: WireSharingKey,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSharingKey {
    algorithm: String,
    public_key: String,
    version: i32,
    fingerprint: String,
    #[serde(default)]
    created_at: OptionalField<String>,
    #[serde(default)]
    updated_at: OptionalField<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberInventoryData {
    capability: String,
    members: Vec<WireMemberKey>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireMemberKey {
    user_id: String,
    role: String,
    sharing_key: OptionalField<WireSharingKey>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationConflictData {
    current_version: i32,
    current_fingerprint: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RateLimitedData {
    retry_after_seconds: i32,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StepUpRequiredData {
    required_scope: String,
}

pub(super) fn parse_sharing_key_response(
    body: &[u8],
    status: u16,
    expected_request_nonce: &str,
    write: bool,
    expected_principal_id: Option<&str>,
) -> Result<AuthenticatedSharingKeyResponse, String> {
    let operation = if write {
        "sharingKey.write"
    } else {
        "sharingKey.read"
    };
    let envelope = parse_wire_envelope(body, operation, expected_request_nonce)?;
    validate_sharing_key_outcome_status(write, &envelope.outcome, status)?;
    let principal_id = match envelope.binding {
        WireBinding::Account {
            principal_id,
            organization_slug: None,
            vault_id: None,
        } => principal_id,
        _ => return Err("sharing-key envelope has a mismatched account binding".into()),
    };
    validate_string(&principal_id, 128, "principal ID")?;
    if expected_principal_id.is_some_and(|expected| expected != principal_id) {
        return Err("sharing-key envelope is bound to a different principal".into());
    }

    let mut response = AuthenticatedSharingKeyResponse {
        outcome: envelope.outcome.clone(),
        principal_id,
        sharing_key: None,
        code: None,
        message: None,
    };
    match envelope.outcome.as_str() {
        "present" | "set" | "unchanged" | "rotated" => {
            let data: SharingKeyContainer = parse_data(envelope.data)?;
            response.sharing_key = Some(validate_sharing_key(data.sharing_key, true)?);
        }
        "absent" | "principalChanged" => parse_empty_data(envelope.data)?,
        "registrationConflict" => {
            let data: RegistrationConflictData = parse_data(envelope.data)?;
            validate_revision(data.current_version, false, "current sharing key version")?;
            validate_fingerprint(&data.current_fingerprint, "current sharing key fingerprint")?;
            response.message = Some("The sharing key changed concurrently".into());
        }
        "rateLimited" => {
            let data: RateLimitedData = parse_data(envelope.data)?;
            validate_revision(data.retry_after_seconds, false, "retry delay")?;
            response.message = Some("Sharing-key write rate limit exceeded".into());
        }
        "stepUpRequired" => {
            let data: StepUpRequiredData = parse_data(envelope.data)?;
            if !matches!(
                data.required_scope.as_str(),
                "vault:public-key:set" | "vault:public-key:rotate"
            ) {
                return Err("sharing-key envelope has an invalid step-up scope".into());
            }
            response.message = Some("Sharing-key write requires step-up authorization".into());
        }
        "rejected" => {
            let data: RejectedData = parse_data(envelope.data)?;
            validate_string(&data.code, 128, "error code")?;
            validate_string(&data.message, 1024, "error message")?;
            response.code = Some(data.code);
            response.message = Some(data.message);
        }
        _ => return Err("sharing-key envelope has unsupported data".into()),
    }
    Ok(response)
}

pub(super) fn parse_member_inventory_response(
    body: &[u8],
    status: u16,
    expected_request_nonce: &str,
    expected_organization_slug: &str,
) -> Result<AuthenticatedMemberInventory, String> {
    let envelope =
        parse_wire_envelope(body, "organization.memberKeys.read", expected_request_nonce)?;
    match (envelope.outcome.as_str(), status) {
        ("current", 200) => {}
        ("rejected", 403 | 404 | 413 | 500) => {
            validate_rejected_member_inventory_binding(
                &envelope.binding,
                expected_organization_slug,
            )?;
            let data: RejectedData = parse_data(envelope.data)?;
            validate_string(&data.code, 128, "error code")?;
            validate_string(&data.message, 1024, "error message")?;
            return Err(format!("{}: {}", data.code, data.message));
        }
        _ => {
            return Err(
                "organization member-key envelope has an unsupported outcome or status".into(),
            );
        }
    }
    let (organization_id, caller_user_id, organization_slug) = match envelope.binding {
        WireBinding::Organization {
            principal_id,
            caller_user_id,
            organization_slug,
            vault_id: None,
        } => (principal_id, caller_user_id, organization_slug),
        _ => {
            return Err(
                "organization member-key envelope has a mismatched organization binding".into(),
            );
        }
    };
    validate_organization_id(&organization_id)?;
    validate_string(&caller_user_id, 256, "caller user ID")?;
    if organization_slug != expected_organization_slug {
        return Err("organization member-key envelope is bound to a different organization".into());
    }

    validate_member_inventory_field_presence(&envelope.data)?;
    let data: MemberInventoryData = parse_data(envelope.data)?;
    if data.members.len() > MAX_ORGANIZATION_MEMBERS {
        return Err(
            "organization member-key inventory contains too many members; member limit is 10000"
                .into(),
        );
    }
    let can_replace_wrapped_keys = match data.capability.as_str() {
        "replaceWrappedKeysAllowed" => true,
        "replaceWrappedKeysForbidden" => false,
        _ => return Err("organization member-key envelope has an invalid capability".into()),
    };
    let mut previous_user_id: Option<&str> = None;
    let mut caller_count = 0usize;
    let mut members = Vec::with_capacity(data.members.len());
    for member in &data.members {
        validate_string(&member.user_id, 256, "member user ID")?;
        validate_string(&member.role, 64, "member role")?;
        if previous_user_id.is_some_and(|previous| member.user_id.as_str() <= previous) {
            return Err("organization member-key inventory is not uniquely ordered".into());
        }
        previous_user_id = Some(&member.user_id);
        if member.user_id == caller_user_id {
            caller_count += 1;
        }
    }
    if caller_count != 1 {
        return Err(
            "organization member-key inventory must contain the caller exactly once".into(),
        );
    }
    for member in data.members {
        let sharing_key = match member.sharing_key {
            OptionalField::Null => None,
            OptionalField::Value(key) => Some(validate_sharing_key(key, false)?),
            OptionalField::Absent => {
                return Err("organization member-key inventory omitted sharingKey".into());
            }
        };
        members.push(AuthenticatedMemberKey {
            user_id: member.user_id,
            role: member.role,
            sharing_key,
        });
    }
    Ok(AuthenticatedMemberInventory {
        organization_id,
        caller_user_id,
        can_replace_wrapped_keys,
        members,
    })
}

fn validate_rejected_member_inventory_binding(
    binding: &WireBinding,
    expected_organization_slug: &str,
) -> Result<(), String> {
    let organization_slug = match binding {
        WireBinding::Account {
            principal_id,
            organization_slug: Some(organization_slug),
            vault_id: None,
        } => {
            validate_string(principal_id, 128, "principal ID")?;
            organization_slug
        }
        WireBinding::Organization {
            principal_id,
            caller_user_id,
            organization_slug,
            vault_id: None,
        } => {
            validate_organization_id(principal_id)?;
            validate_string(caller_user_id, 256, "caller user ID")?;
            organization_slug
        }
        _ => {
            return Err(
                "organization member-key envelope has a mismatched organization binding".into(),
            );
        }
    };
    if organization_slug != expected_organization_slug {
        return Err("organization member-key envelope is bound to a different organization".into());
    }
    Ok(())
}

fn parse_wire_envelope(
    body: &[u8],
    expected_operation: &str,
    expected_request_nonce: &str,
) -> Result<WireEnvelope, String> {
    let envelope: WireEnvelope =
        serde_json::from_slice(body).map_err(|error| format!("response parse error: {error}"))?;
    if envelope.envelope_version != ENVELOPE_VERSION {
        return Err("authenticated response envelope version is missing or unsupported".into());
    }
    if envelope.operation != expected_operation {
        return Err("authenticated response envelope operation does not match the request".into());
    }
    if envelope.request_nonce != expected_request_nonce {
        return Err("authenticated response envelope does not match the request nonce".into());
    }
    validate_request_nonce(&envelope.request_nonce)?;
    Ok(envelope)
}

fn validate_sharing_key_outcome_status(
    write: bool,
    outcome: &str,
    status: u16,
) -> Result<(), String> {
    let valid = if write {
        match outcome {
            "set" | "unchanged" | "rotated" => status == 200,
            "principalChanged" | "registrationConflict" => status == 409,
            "rateLimited" => status == 429,
            "stepUpRequired" => status == 403,
            "rejected" => matches!(status, 400 | 401 | 403 | 409 | 413 | 500),
            _ => false,
        }
    } else {
        match outcome {
            "present" | "absent" => status == 200,
            "rejected" => matches!(status, 403 | 404 | 500),
            _ => false,
        }
    };
    if valid {
        Ok(())
    } else {
        Err("sharing-key envelope has an unsupported outcome or status".into())
    }
}

fn validate_sharing_key(
    key: WireSharingKey,
    timestamps_required: bool,
) -> Result<ValidatedSharingKey, String> {
    if key.algorithm != "X25519" {
        return Err("authenticated response requires an X25519 sharing key".into());
    }
    match (timestamps_required, key.created_at, key.updated_at) {
        (true, OptionalField::Value(created_at), OptionalField::Value(updated_at)) => {
            for timestamp in [created_at, updated_at] {
                chrono::DateTime::parse_from_rfc3339(&timestamp)
                    .map_err(|_| "authenticated response has an invalid sharing-key timestamp")?;
            }
        }
        (false, OptionalField::Absent, OptionalField::Absent) => {}
        _ => return Err("authenticated response has inconsistent sharing-key timestamps".into()),
    }
    ValidatedSharingKey::from_authenticated(key.public_key, key.version, key.fingerprint)
}

pub(super) fn parse_vault_response(
    body: &[u8],
    status: u16,
    expected_vault_id: &str,
    expected_scope: SyncScope<'_>,
    expected_request_nonce: &str,
    policy: SyncEnvelopePolicy,
) -> Result<AuthenticatedSyncResponse, String> {
    let envelope = parse_wire_envelope(body, policy.operation(), expected_request_nonce)?;
    validate_vault_outcome_status(policy, &envelope.outcome, status)?;
    let binding = validate_vault_binding(
        envelope.binding,
        expected_vault_id,
        expected_scope,
        &envelope.outcome,
    )?;
    let mut response = AuthenticatedSyncResponse::new(envelope.outcome.clone(), binding);

    match (policy, envelope.outcome.as_str()) {
        (SyncEnvelopePolicy::Pull, "current") => {
            let data: VaultPayloadData = parse_data(envelope.data)?;
            validate_vault_payload(&data, expected_scope)?;
            response.encrypted_blob = Some(data.encrypted_blob);
            response.wrapped_key = Some(data.wrapped_key);
            response.version = Some(data.revision);
            response.server_version = Some(data.revision);
            response.crypto_version = Some(data.crypto_version);
            response.content_key_version = data.content_key_version.into_value();
            response.recipient_public_key_version = data.recipient_public_key_version.into_value();
            response.recipient_public_key_fingerprint =
                data.recipient_public_key_fingerprint.into_value();
        }
        (SyncEnvelopePolicy::Inspect, "current") => {
            let data: InspectData = parse_data(envelope.data)?;
            validate_revision(data.revision, false, "revision")?;
            validate_crypto_version(data.crypto_version)?;
            response.version = Some(data.revision);
            response.server_version = Some(data.revision);
            response.crypto_version = Some(data.crypto_version);
        }
        (SyncEnvelopePolicy::Pull | SyncEnvelopePolicy::Inspect, "missing") => {
            let data: MissingData = parse_data(envelope.data)?;
            validate_revision(data.retained_revision, true, "retained revision")?;
            response.code = Some("vault_missing".into());
            response.error = Some("Vault not found".into());
            response.server_version = Some(data.retained_revision);
        }
        (SyncEnvelopePolicy::Pull, "memberRewrapRequired") => {
            let data: MemberRewrapData = parse_data(envelope.data)?;
            validate_revision(data.revision, false, "revision")?;
            validate_revision(data.content_key_version, false, "content key version")?;
            response.code = Some("vault_member_needs_rewrap".into());
            response.error = Some("Organization env key must be rewrapped for this member".into());
            response.server_version = Some(data.revision);
            response.content_key_version = Some(data.content_key_version);
        }
        (SyncEnvelopePolicy::Write, "committed") => {
            let data: CommittedData = parse_data(envelope.data)?;
            validate_revision(data.revision, false, "revision")?;
            validate_crypto_version(data.crypto_version)?;
            if !matches!(data.action.as_str(), "synced" | "shared" | "rotated") {
                return Err("authenticated sync envelope has an invalid committed action".into());
            }
            match expected_scope {
                SyncScope::Personal if data.content_key_version.is_some() => {
                    return Err(
                        "personal write response included an organization key version".into(),
                    );
                }
                SyncScope::Organization(_) => validate_revision(
                    data.content_key_version
                        .ok_or("organization write response omitted the content key version")?,
                    false,
                    "content key version",
                )?,
                SyncScope::Personal => {}
            }
            response.version = Some(data.revision);
            response.server_version = Some(data.revision);
            response.crypto_version = Some(data.crypto_version);
            response.content_key_version = data.content_key_version;
            response.status = Some(data.action);
        }
        (SyncEnvelopePolicy::Write, "principalChanged") => {
            parse_empty_data(envelope.data)?;
            set_outcome_error(&mut response, "vault_principal_changed", None);
        }
        (SyncEnvelopePolicy::Write, "recreationIntentRequired") => {
            let data: MissingData = parse_data(envelope.data)?;
            validate_revision(data.retained_revision, true, "retained revision")?;
            set_outcome_error(
                &mut response,
                "vault_recreation_intent_required",
                Some(data.retained_revision),
            );
        }
        (SyncEnvelopePolicy::Write, "ciphertextRevisionMismatch") => {
            let data: CiphertextRevisionMismatchData = parse_data(envelope.data)?;
            validate_revision(
                data.required_ciphertext_revision,
                false,
                "required ciphertext revision",
            )?;
            if data.current_revision.is_some() == data.retained_revision.is_some() {
                return Err(
                    "authenticated sync envelope requires exactly one revision floor".into(),
                );
            }
            let server_version = match (data.current_revision, data.retained_revision) {
                (Some(revision), None) => {
                    validate_revision(revision, false, "current revision")?;
                    revision
                }
                (None, Some(revision)) => {
                    validate_revision(revision, true, "retained revision")?;
                    revision
                }
                _ => unreachable!(),
            };
            if data.required_ciphertext_revision != server_version.saturating_add(1) {
                return Err(
                    "authenticated sync envelope has an inconsistent ciphertext revision".into(),
                );
            }
            set_outcome_error(
                &mut response,
                "vault_ciphertext_revision_mismatch",
                Some(server_version),
            );
        }
        (
            SyncEnvelopePolicy::Write,
            outcome @ ("expectedRevisionRequired"
            | "creationConflict"
            | "revisionConflict"
            | "memberRewrapRequired"
            | "contentKeyRotationRequired"),
        ) => {
            let data: CurrentRevisionData = parse_data(envelope.data)?;
            validate_revision(data.current_revision, false, "current revision")?;
            let code = match outcome {
                "expectedRevisionRequired" => "vault_expected_version_required",
                "creationConflict" => "vault_creation_conflict",
                "revisionConflict" => "vault_version_conflict",
                "memberRewrapRequired" => "vault_member_needs_rewrap",
                "contentKeyRotationRequired" => "vault_content_key_rotation_required",
                _ => unreachable!(),
            };
            set_outcome_error(&mut response, code, Some(data.current_revision));
        }
        (_, "rejected") => {
            let data: RejectedData = parse_data(envelope.data)?;
            validate_string(&data.code, 128, "error code")?;
            validate_string(&data.message, 1024, "error message")?;
            response.code = Some(data.code);
            response.error = Some(data.message);
        }
        _ => return Err("authenticated sync envelope has unsupported data".into()),
    }

    Ok(response)
}

fn set_outcome_error(
    response: &mut AuthenticatedSyncResponse,
    code: &'static str,
    server_version: Option<i32>,
) {
    response.code = Some(code.into());
    response.error = Some(
        match code {
            "vault_principal_changed" => "The authenticated principal changed",
            "vault_recreation_intent_required" => "Vault recreation intent is required",
            "vault_ciphertext_revision_mismatch" => {
                "Ciphertext revision does not follow the server revision"
            }
            "vault_expected_version_required" => "The current vault revision is required",
            "vault_creation_conflict" => "The vault was created concurrently",
            "vault_version_conflict" => "The vault changed concurrently",
            "vault_member_needs_rewrap" => "Organization env key must be rewrapped for this member",
            "vault_content_key_rotation_required" => "The organization content key must be rotated",
            _ => "Vault request failed",
        }
        .into(),
    );
    response.server_version = server_version;
}

fn validate_vault_outcome_status(
    policy: SyncEnvelopePolicy,
    outcome: &str,
    status: u16,
) -> Result<(), String> {
    let valid = match (policy, outcome) {
        (SyncEnvelopePolicy::Pull, "current")
        | (SyncEnvelopePolicy::Inspect, "current")
        | (SyncEnvelopePolicy::Write, "committed") => status == 200,
        (SyncEnvelopePolicy::Pull | SyncEnvelopePolicy::Inspect, "missing") => status == 404,
        (SyncEnvelopePolicy::Pull, "memberRewrapRequired") => status == 403,
        (
            SyncEnvelopePolicy::Write,
            "principalChanged"
            | "expectedRevisionRequired"
            | "recreationIntentRequired"
            | "ciphertextRevisionMismatch"
            | "creationConflict"
            | "revisionConflict"
            | "contentKeyRotationRequired",
        ) => status == 409,
        (SyncEnvelopePolicy::Write, "memberRewrapRequired") => status == 403,
        (SyncEnvelopePolicy::Pull, "rejected") | (SyncEnvelopePolicy::Inspect, "rejected") => {
            matches!(status, 400 | 402 | 403 | 404 | 413 | 426 | 500)
        }
        (SyncEnvelopePolicy::Write, "rejected") => {
            matches!(status, 400 | 401 | 402 | 403 | 404 | 409 | 413 | 426 | 500)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("authenticated sync envelope has an unsupported outcome or status".into())
    }
}

fn validate_vault_binding(
    binding: WireBinding,
    expected_vault_id: &str,
    expected_scope: SyncScope<'_>,
    outcome: &str,
) -> Result<ValidatedVaultBinding, String> {
    match (expected_scope, binding) {
        (
            SyncScope::Personal,
            WireBinding::Personal {
                principal_id,
                caller_user_id,
                vault_id,
            },
        ) => {
            validate_string(&principal_id, 128, "principal ID")?;
            validate_string(&caller_user_id, 256, "caller user ID")?;
            validate_string(&vault_id, 256, "vault ID")?;
            if principal_id != caller_user_id || vault_id != expected_vault_id {
                return Err("authenticated sync envelope has a mismatched personal binding".into());
            }
            Ok(ValidatedVaultBinding {
                principal_id,
                caller_user_id: Some(caller_user_id),
            })
        }
        (
            SyncScope::Organization(expected_slug),
            WireBinding::Organization {
                principal_id,
                caller_user_id,
                organization_slug,
                vault_id: Some(vault_id),
            },
        ) => {
            validate_organization_id(&principal_id)?;
            validate_string(&caller_user_id, 256, "caller user ID")?;
            validate_string(&organization_slug, 128, "organization slug")?;
            validate_string(&vault_id, 256, "vault ID")?;
            if organization_slug != expected_slug || vault_id != expected_vault_id {
                return Err(
                    "authenticated sync envelope has a mismatched organization binding".into(),
                );
            }
            Ok(ValidatedVaultBinding {
                principal_id,
                caller_user_id: Some(caller_user_id),
            })
        }
        (
            SyncScope::Organization(expected_slug),
            WireBinding::Account {
                principal_id,
                organization_slug: Some(organization_slug),
                vault_id: Some(vault_id),
            },
        ) if outcome == "rejected" => {
            validate_string(&principal_id, 128, "principal ID")?;
            if organization_slug != expected_slug || vault_id != expected_vault_id {
                return Err("authenticated sync envelope has a mismatched account binding".into());
            }
            Ok(ValidatedVaultBinding {
                principal_id,
                caller_user_id: None,
            })
        }
        _ => Err("authenticated sync envelope has a mismatched scope binding".into()),
    }
}

fn validate_vault_payload(
    data: &VaultPayloadData,
    expected_scope: SyncScope<'_>,
) -> Result<(), String> {
    validate_string(&data.encrypted_blob, 16 * 1024 * 1024, "encrypted blob")?;
    validate_string(&data.wrapped_key, 4096, "wrapped key")?;
    validate_revision(data.revision, false, "revision")?;
    validate_crypto_version(data.crypto_version)?;
    chrono::DateTime::parse_from_rfc3339(&data.updated_at)
        .map_err(|_| "authenticated sync envelope has an invalid updated timestamp")?;
    match expected_scope {
        SyncScope::Personal
            if matches!(data.content_key_version, OptionalField::Absent)
                && matches!(data.recipient_public_key_version, OptionalField::Absent)
                && matches!(data.recipient_public_key_fingerprint, OptionalField::Absent) =>
        {
            Ok(())
        }
        SyncScope::Organization(_) => {
            validate_revision(
                data.content_key_version
                    .as_value()
                    .copied()
                    .ok_or("organization pull omitted the content key version")?,
                false,
                "content key version",
            )?;
            validate_revision(
                data.recipient_public_key_version
                    .as_value()
                    .copied()
                    .ok_or("organization pull omitted the recipient key version")?,
                false,
                "recipient public key version",
            )?;
            let fingerprint = data
                .recipient_public_key_fingerprint
                .as_value()
                .map(String::as_str)
                .ok_or("organization pull omitted the recipient key fingerprint")?;
            validate_fingerprint(fingerprint, "recipient key fingerprint")
        }
        _ => Err("personal pull included organization key bindings".into()),
    }
}

fn parse_data<T>(data: StrictValue) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(data.0)
        .map_err(|error| format!("authenticated sync envelope data is invalid: {error}"))
}

fn validate_member_inventory_field_presence(data: &StrictValue) -> Result<(), String> {
    let Some(members) = data.0.get("members").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    if members.iter().any(|member| {
        member
            .as_object()
            .is_some_and(|fields| !fields.contains_key("sharingKey"))
    }) {
        return Err("organization member-key inventory omitted sharingKey".into());
    }
    Ok(())
}

fn parse_empty_data(data: StrictValue) -> Result<(), String> {
    let _: EmptyData = parse_data(data)?;
    Ok(())
}

fn validate_request_nonce(value: &str) -> Result<(), String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("authenticated sync envelope has an invalid request nonce".into());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "authenticated sync envelope has an invalid request nonce")?;
    if decoded.len() != REQUEST_NONCE_BYTES || URL_SAFE_NO_PAD.encode(decoded) != value {
        return Err("authenticated sync envelope has an invalid request nonce".into());
    }
    Ok(())
}

fn validate_string(value: &str, maximum_length: usize, name: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum_length || value.chars().any(char::is_control) {
        return Err(format!(
            "authenticated sync envelope requires a valid {name}"
        ));
    }
    Ok(())
}

fn validate_revision(value: i32, allow_zero: bool, name: &str) -> Result<(), String> {
    let minimum = i32::from(!allow_zero);
    if !(minimum..=MAX_REVISION).contains(&value) {
        return Err(format!(
            "authenticated sync envelope requires a valid {name}"
        ));
    }
    Ok(())
}

fn validate_crypto_version(value: i32) -> Result<(), String> {
    if value != crypto::CURRENT_CRYPTO_VERSION {
        return Err("authenticated sync envelope has an unsupported crypto version".into());
    }
    Ok(())
}

fn validate_fingerprint(value: &str, name: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "authenticated sync envelope requires a valid {name}"
        ));
    }
    Ok(())
}

fn validate_organization_id(value: &str) -> Result<(), String> {
    if value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
    {
        Ok(())
    } else {
        Err("authenticated sync envelope requires a valid organization ID".into())
    }
}

pub(super) fn generate_request_nonce() -> Result<String, String> {
    let mut bytes = [0u8; REQUEST_NONCE_BYTES];
    rand::thread_rng()
        .try_fill_bytes(&mut bytes)
        .map_err(|error| format!("failed to generate authenticated sync request nonce: {error}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn personal_pull_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "vault.pull",
            "outcome": "current",
            "requestNonce": NONCE,
            "binding": {
                "scope": "personal",
                "principalId": "user-123",
                "callerUserId": "user-123",
                "vaultId": "vault-123"
            },
            "data": {
                "encryptedBlob": "ciphertext",
                "wrappedKey": "wrapped",
                "revision": 42,
                "cryptoVersion": crypto::CURRENT_CRYPTO_VERSION,
                "updatedAt": "2026-09-05T12:00:00.000Z"
            }
        }))
        .unwrap()
    }

    fn member_inventory_body(members: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "current",
            "requestNonce": NONCE,
            "binding": {
                "scope": "organization",
                "principalId": "11111111-1111-4111-8111-111111111111",
                "callerUserId": "user-00000",
                "organizationSlug": "expected-org"
            },
            "data": {
                "capability": "replaceWrappedKeysAllowed",
                "members": members
            }
        }))
        .unwrap()
    }

    fn sharing_key(public_key: [u8; 32], timestamps: bool) -> serde_json::Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(public_key);
        let mut key = serde_json::json!({
            "algorithm": "X25519",
            "publicKey": encoded,
            "version": 1,
            "fingerprint": hex::encode(Sha256::digest(public_key)),
        });
        if timestamps {
            key["createdAt"] = "2026-09-05T12:00:00.000Z".into();
            key["updatedAt"] = "2026-09-05T12:00:00.000Z".into();
        }
        key
    }

    #[test]
    fn generate_request_nonce_returns_unpadded_base64url() {
        let nonce = generate_request_nonce().expect("OS randomness should be available");

        assert!(
            nonce.len() == 43
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn authenticated_pull_accepts_the_registry_nested_v3_envelope() {
        let response = parse_vault_response(
            &personal_pull_body(),
            200,
            "vault-123",
            SyncScope::Personal,
            NONCE,
            SyncEnvelopePolicy::Pull,
        );

        assert!(response.is_ok(), "{response:?}");
    }

    #[test]
    fn authenticated_pull_rejects_the_flat_v2_envelope() {
        let body = br#"{"envelopeVersion":2,"vaultId":"vault-123","version":42}"#;
        let error = parse_vault_response(
            body,
            200,
            "vault-123",
            SyncScope::Personal,
            NONCE,
            SyncEnvelopePolicy::Pull,
        )
        .expect_err("the retired flat envelope must fail closed");

        assert!(error.contains("response parse error"), "{error}");
    }

    #[test]
    fn authenticated_pull_rejects_duplicate_nested_data_keys() {
        let body = format!(
            r#"{{"envelopeVersion":3,"operation":"vault.pull","outcome":"current","requestNonce":"{NONCE}","binding":{{"scope":"personal","principalId":"user-123","callerUserId":"user-123","vaultId":"vault-123"}},"data":{{"encryptedBlob":"ciphertext","wrappedKey":"wrapped","revision":42,"revision":43,"cryptoVersion":3,"updatedAt":"2026-09-05T12:00:00.000Z"}}}}"#
        );
        let error = parse_vault_response(
            body.as_bytes(),
            200,
            "vault-123",
            SyncScope::Personal,
            NONCE,
            SyncEnvelopePolicy::Pull,
        )
        .expect_err("duplicate JSON keys must fail closed");

        assert!(
            error.contains("duplicate JSON object key revision"),
            "{error}"
        );
    }

    #[test]
    fn authenticated_pull_rejects_unknown_nested_data_keys() {
        let mut body: serde_json::Value = serde_json::from_slice(&personal_pull_body()).unwrap();
        body["data"]["serverVersion"] = 42.into();
        let error = parse_vault_response(
            &serde_json::to_vec(&body).unwrap(),
            200,
            "vault-123",
            SyncScope::Personal,
            NONCE,
            SyncEnvelopePolicy::Pull,
        )
        .expect_err("unknown JSON keys must fail closed");

        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn authenticated_sharing_key_rejects_a_mismatched_fingerprint() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let body = serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "sharingKey.read",
            "outcome": "present",
            "requestNonce": NONCE,
            "binding": {
                "scope": "account",
                "principalId": "user-123",
            },
            "data": {
                "sharingKey": {
                    "algorithm": "X25519",
                    "publicKey": public_key,
                    "version": 1,
                    "fingerprint": "0".repeat(64),
                    "createdAt": "2026-09-05T12:00:00.000Z",
                    "updatedAt": "2026-09-05T12:00:00.000Z",
                }
            }
        }))
        .unwrap();

        let error = parse_sharing_key_response(&body, 200, NONCE, false, None)
            .expect_err("the signed fingerprint must identify the signed public key");

        assert!(error.contains("fingerprint does not match"), "{error}");
    }

    #[test]
    fn authenticated_sharing_key_rejects_non_contributory_public_keys() {
        for public_key in [[0_u8; 32], {
            let mut key = [0_u8; 32];
            key[0] = 1;
            key
        }] {
            let body = serde_json::to_vec(&serde_json::json!({
                "envelopeVersion": 3,
                "operation": "sharingKey.read",
                "outcome": "present",
                "requestNonce": NONCE,
                "binding": {
                    "scope": "account",
                    "principalId": "user-123",
                },
                "data": {
                    "sharingKey": sharing_key(public_key, true)
                }
            }))
            .unwrap();

            let error = parse_sharing_key_response(&body, 200, NONCE, false, None)
                .expect_err("non-contributory sharing keys must fail closed");

            assert!(error.contains("non-contributory"), "{error}");
        }
    }

    #[test]
    fn member_inventory_rejects_non_contributory_public_keys() {
        for public_key in [[0_u8; 32], {
            let mut key = [0_u8; 32];
            key[0] = 1;
            key
        }] {
            let body = member_inventory_body(vec![serde_json::json!({
                "userId": "user-00000",
                "role": "owner",
                "sharingKey": sharing_key(public_key, false)
            })]);

            let error = parse_member_inventory_response(&body, 200, NONCE, "expected-org")
                .expect_err("non-contributory member keys must fail closed");

            assert!(error.contains("non-contributory"), "{error}");
        }
    }

    #[test]
    fn member_inventory_rejects_more_than_ten_thousand_members() {
        let members = (0..10_001)
            .map(|index| {
                serde_json::json!({
                    "userId": format!("user-{index:05}"),
                    "role": "member",
                    "sharingKey": null
                })
            })
            .collect();
        let body = member_inventory_body(members);

        let error = parse_member_inventory_response(&body, 200, NONCE, "expected-org")
            .expect_err("oversized member inventories must fail closed");

        assert!(error.contains("member limit"), "{error}");
    }

    #[test]
    fn member_inventory_accepts_exactly_ten_thousand_members() {
        let members = (0..10_000)
            .map(|index| {
                serde_json::json!({
                    "userId": format!("user-{index:05}"),
                    "role": "member",
                    "sharingKey": null
                })
            })
            .collect();
        let body = member_inventory_body(members);

        let result = parse_member_inventory_response(&body, 200, NONCE, "expected-org");

        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn member_inventory_rejects_an_omitted_sharing_key_field() {
        let body = member_inventory_body(vec![serde_json::json!({
            "userId": "user-00000",
            "role": "owner"
        })]);

        let error = parse_member_inventory_response(&body, 200, NONCE, "expected-org")
            .expect_err("the signed member shape must include sharingKey");

        assert!(error.contains("sharingKey"), "{error}");
    }

    #[test]
    fn member_inventory_rejects_null_sharing_key_timestamps() {
        let mut key = sharing_key([7_u8; 32], false);
        key["createdAt"] = serde_json::Value::Null;
        key["updatedAt"] = serde_json::Value::Null;
        let body = member_inventory_body(vec![serde_json::json!({
            "userId": "user-00000",
            "role": "owner",
            "sharingKey": key
        })]);

        let error = parse_member_inventory_response(&body, 200, NONCE, "expected-org")
            .expect_err("member sharing-key timestamps must be absent rather than null");

        assert!(error.contains("timestamps"), "{error}");
    }

    #[test]
    fn personal_pull_rejects_null_organization_key_fields() {
        for field in [
            "contentKeyVersion",
            "recipientPublicKeyVersion",
            "recipientPublicKeyFingerprint",
        ] {
            let mut body: serde_json::Value =
                serde_json::from_slice(&personal_pull_body()).unwrap();
            body["data"][field] = serde_json::Value::Null;

            let error = parse_vault_response(
                &serde_json::to_vec(&body).unwrap(),
                200,
                "vault-123",
                SyncScope::Personal,
                NONCE,
                SyncEnvelopePolicy::Pull,
            )
            .expect_err("personal payload organization fields must be absent rather than null");

            assert!(
                error.contains("organization key bindings"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn rejected_member_inventory_rejects_a_different_organization_binding() {
        let body = serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "rejected",
            "requestNonce": NONCE,
            "binding": {
                "scope": "account",
                "principalId": "user-123",
                "organizationSlug": "other-org"
            },
            "data": {
                "code": "access_denied",
                "message": "Access denied"
            }
        }))
        .unwrap();

        let error = parse_member_inventory_response(&body, 403, NONCE, "expected-org")
            .expect_err("a rejected response for another organization must fail closed");

        assert!(error.contains("different organization"), "{error}");
    }

    #[test]
    fn rejected_member_inventory_accepts_resolved_and_unresolved_current_org_bindings() {
        for binding in [
            serde_json::json!({
                "scope": "account",
                "principalId": "user-123",
                "organizationSlug": "expected-org"
            }),
            serde_json::json!({
                "scope": "organization",
                "principalId": "11111111-1111-4111-8111-111111111111",
                "callerUserId": "user-123",
                "organizationSlug": "expected-org"
            }),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "envelopeVersion": 3,
                "operation": "organization.memberKeys.read",
                "outcome": "rejected",
                "requestNonce": NONCE,
                "binding": binding,
                "data": {
                    "code": "access_denied",
                    "message": "Access denied"
                }
            }))
            .unwrap();

            let error = parse_member_inventory_response(&body, 403, NONCE, "expected-org")
                .expect_err("the authenticated rejection must propagate");

            assert_eq!(error, "access_denied: Access denied");
        }
    }

    #[test]
    fn member_inventory_rejects_uncontracted_service_unavailable_status() {
        let body = serde_json::to_vec(&serde_json::json!({
            "envelopeVersion": 3,
            "operation": "organization.memberKeys.read",
            "outcome": "rejected",
            "requestNonce": NONCE,
            "binding": {
                "scope": "account",
                "principalId": "user-123",
                "organizationSlug": "expected-org"
            },
            "data": {
                "code": "service_unavailable",
                "message": "Try again later"
            }
        }))
        .unwrap();

        let error = parse_member_inventory_response(&body, 503, NONCE, "expected-org")
            .expect_err("status codes outside the Registry contract must fail closed");

        assert!(error.contains("unsupported outcome or status"), "{error}");
    }

    #[test]
    fn rejected_member_inventory_rejects_malformed_or_unscoped_bindings() {
        for (binding, expected_error) in [
            (
                serde_json::json!({
                    "scope": "account",
                    "principalId": "user-123"
                }),
                "mismatched organization binding",
            ),
            (
                serde_json::json!({
                    "scope": "personal",
                    "principalId": "user-123",
                    "callerUserId": "user-123",
                    "vaultId": "vault-123"
                }),
                "mismatched organization binding",
            ),
            (
                serde_json::json!({
                    "scope": "organization",
                    "principalId": "not-an-organization-id",
                    "callerUserId": "user-123",
                    "organizationSlug": "expected-org"
                }),
                "valid organization ID",
            ),
            (
                serde_json::json!({
                    "scope": "organization",
                    "principalId": "11111111-1111-4111-8111-111111111111",
                    "callerUserId": "",
                    "organizationSlug": "expected-org"
                }),
                "valid caller user ID",
            ),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "envelopeVersion": 3,
                "operation": "organization.memberKeys.read",
                "outcome": "rejected",
                "requestNonce": NONCE,
                "binding": binding,
                "data": {
                    "code": "access_denied",
                    "message": "Access denied"
                }
            }))
            .unwrap();

            let error = parse_member_inventory_response(&body, 403, NONCE, "expected-org")
                .expect_err("malformed rejected bindings must fail closed");

            assert!(error.contains(expected_error), "{error}");
        }
    }
}
