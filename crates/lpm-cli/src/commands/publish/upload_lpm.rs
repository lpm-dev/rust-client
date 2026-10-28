use super::swift::extract_swift_metadata;
use crate::commands::publish_common::TarballFile;
use crate::prompt::PromptResultExt as _;
use crate::{install_ui, quality};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use serde::ser::{SerializeMap as _, SerializeSeq as _};
use std::io::Write as _;

/// Why lpm.dev's second factor couldn't be settled.
pub(super) enum OtpFailure {
    /// The account couldn't be read, as while the Registry is unavailable,
    /// which a later try may get past.
    AccountUnread(LpmError),
    /// A malformed `--otp`, a token lpm.dev refuses, or a code `--json`
    /// can't ask for, which no retry gets past.
    Final(LpmError),
}

impl From<OtpFailure> for LpmError {
    fn from(failure: OtpFailure) -> Self {
        match failure {
            OtpFailure::AccountUnread(error) | OtpFailure::Final(error) => error,
        }
    }
}

/// Whether whoami's failure is lpm.dev refusing the token, which a retry
/// with it won't get past.
fn refuses_the_token(error: &LpmError) -> bool {
    matches!(
        error,
        LpmError::AuthRequired
            | LpmError::SessionExpired
            | LpmError::EnvTokenRejected
            | LpmError::Forbidden(_)
            | LpmError::UnsupportedAuthSource { .. }
    )
}

/// The second factor an lpm.dev publish sends: `provided_otp`, checked, or,
/// for an account with 2FA on, one asked for, which `--json` can't do. Reads
/// the account through whoami, which also checks the token.
pub(super) async fn resolve_lpm_otp(
    client: &RegistryClient,
    provided_otp: Option<&str>,
    json_output: bool,
    whoami_cache: Option<&tokio::sync::OnceCell<lpm_registry::WhoamiResponse>>,
) -> Result<Option<String>, OtpFailure> {
    if provided_otp.is_some_and(|code| !is_valid_otp(code)) {
        return Err(OtpFailure::Final(LpmError::Registry(
            "--otp must be exactly six ASCII digits".into(),
        )));
    }
    let whoami = match whoami_cache {
        Some(cache) => cache
            .get_or_try_init(|| client.whoami())
            .await
            .map(|account| account.mfa_enabled),
        None => client.whoami().await.map(|account| account.mfa_enabled),
    };
    let mfa_enabled = match whoami {
        Ok(mfa_enabled) => mfa_enabled,
        Err(error) => {
            let refused = refuses_the_token(&error);
            let error = LpmError::Registry(format!("authentication failed: {error}"));
            return Err(if refused {
                OtpFailure::Final(error)
            } else {
                OtpFailure::AccountUnread(error)
            });
        }
    };

    if let Some(code) = provided_otp {
        return Ok(Some(code.to_owned()));
    }
    if mfa_enabled != Some(true) {
        return Ok(None);
    }
    if json_output {
        return Err(OtpFailure::Final(LpmError::Registry(
            "2FA required in JSON mode — pass --otp <code> or use a CI token".into(),
        )));
    }
    let code: String = cliclack::input("Enter 2FA code")
        .validate(|input: &String| {
            if is_valid_otp(input) {
                Ok(())
            } else {
                Err("Must be a 6-digit code")
            }
        })
        .interact()
        .map_prompt_err(|e| LpmError::Registry(e.to_string()))
        .map_err(OtpFailure::Final)?;
    Ok(Some(code))
}

/// Publish to the LPM registry (existing behavior).
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_to_lpm(
    client: &RegistryClient,
    body: LpmPublishBody<'_>,
    tarball_data: &std::sync::Arc<Vec<u8>>,
    provided_otp: Option<&str>,
    json_output: bool,
    whoami_cache: Option<&tokio::sync::OnceCell<lpm_registry::WhoamiResponse>>,
) -> Result<serde_json::Value, LpmError> {
    // Credentials must not travel over plain HTTP for LPM publish.
    let registry_url = client.base_url();
    if !lpm_publish_transport_is_allowed(registry_url) {
        return Err(LpmError::Registry(format!(
            "refusing to publish over HTTP to {registry_url} — credentials require HTTPS"
        )));
    }

    // Make non-default LPM registry targets visible in human output.
    if !lpm_publish_registry_is_default_or_loopback(registry_url) && !json_output {
        install_ui::detail("");
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "Publishing to non-default registry: {}",
            install_ui::url(registry_url)
        ));
    }

    let otp_code = resolve_lpm_otp(client, provided_otp, json_output, whoami_cache).await?;

    let published_integrity = body
        .version_data
        .get("dist")
        .and_then(|dist| dist.get("integrity"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            LpmError::Registry("prepared publish metadata is missing dist.integrity".into())
        })?;

    // The tarball goes to storage first and the publish names its upload,
    // so lpm.dev's limit on a request's body bounds only the metadata.
    let upload = client
        .create_publish_upload(
            body.name,
            body.version,
            tarball_data.len() as u64,
            published_integrity,
        )
        .await?;
    client.upload_publish_tarball(&upload, tarball_data).await?;
    let payload =
        lpm_http::ReplayableRequestBody::from_bytes(body.payload(&upload.id, tarball_data.len())?);

    let encoded_name = urlencoding::encode(body.name);
    client
        .publish_package(
            &encoded_name,
            body.version,
            published_integrity,
            &payload,
            otp_code.as_deref(),
            tarball_data.len(),
        )
        .await
}

/// The length of an upload's id, which the Registry gives as a UUID.
const UPLOAD_ID_LEN: usize = 36;

/// What an lpm.dev publish request carries, but its tarball.
pub(super) struct LpmPublishBody<'a> {
    pub(super) name: &'a str,
    pub(super) version: &'a str,
    pub(super) readme: Option<&'a str>,
    pub(super) version_data: &'a serde_json::Value,
    pub(super) tarball_files: &'a [TarballFile],
    pub(super) package_json_size_override: Option<u64>,
    pub(super) quality_result: Option<&'a quality::QualityResult>,
    pub(super) lpm_config: Option<&'a serde_json::Value>,
    pub(super) detected_ecosystem: &'a str,
    pub(super) swift_manifest: Option<&'a serde_json::Value>,
}

impl LpmPublishBody<'_> {
    /// The request's JSON, naming the upload `upload_id` of a tarball of
    /// `tarball_len` bytes.
    fn payload(&self, upload_id: &str, tarball_len: usize) -> Result<Vec<u8>, LpmError> {
        let tarball_key = format!(
            "{}-{}.tgz",
            self.name.replace('/', "-").replace('@', ""),
            self.version
        );
        let swift_metadata = self.swift_manifest.map(extract_swift_metadata);
        let version_object = self.version_data.as_object().ok_or_else(|| {
            LpmError::Registry("prepared publish version metadata must be a JSON object".into())
        })?;
        let pack_metadata =
            LpmPackMetadata::new(self.tarball_files, self.package_json_size_override);
        let lpm_version = LpmVersionPayload {
            base: version_object,
            quality_result: self.quality_result,
            pack_metadata: &pack_metadata,
            lpm_config: self.lpm_config,
            detected_ecosystem: self.detected_ecosystem,
            swift_metadata: swift_metadata.as_ref(),
        };
        build_lpm_publish_payload(LpmPublishPayload {
            name: self.name,
            version: self.version,
            readme: self.readme,
            detected_ecosystem: self.detected_ecosystem,
            lpm_version: &lpm_version,
            tarball_key: &tarball_key,
            attachment: LpmUploadedAttachment {
                content_type: "application/gzip",
                length: tarball_len,
                upload_id,
            },
        })
    }

    /// The length of the request `publish_to_lpm` sends for a tarball of
    /// `tarball_len` bytes, known before its upload opens.
    pub(super) fn len_with(&self, tarball_len: usize) -> Result<u64, LpmError> {
        let placeholder = "0".repeat(UPLOAD_ID_LEN);
        Ok(self.payload(&placeholder, tarball_len)?.len() as u64)
    }
}

struct LpmPackMetadata<'a> {
    files: &'a [TarballFile],
    package_json_size_override: Option<u64>,
    unpacked_size: u64,
}

impl<'a> LpmPackMetadata<'a> {
    fn new(files: &'a [TarballFile], package_json_size_override: Option<u64>) -> Self {
        let unpacked_size = files.iter().fold(0_u64, |total, file| {
            total.saturating_add(packed_file_size(file, package_json_size_override))
        });
        Self {
            files,
            package_json_size_override,
            unpacked_size,
        }
    }
}

impl serde::Serialize for LpmPackMetadata<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(
            "files",
            &LpmPackFiles {
                files: self.files,
                package_json_size_override: self.package_json_size_override,
            },
        )?;
        map.serialize_entry("unpackedSize", &self.unpacked_size)?;
        map.serialize_entry("fileCount", &self.files.len())?;
        map.end()
    }
}

struct LpmPackFiles<'a> {
    files: &'a [TarballFile],
    package_json_size_override: Option<u64>,
}

impl serde::Serialize for LpmPackFiles<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.files.len()))?;
        for file in self.files {
            sequence.serialize_element(&LpmPackFile {
                path: &file.path,
                size: packed_file_size(file, self.package_json_size_override),
            })?;
        }
        sequence.end()
    }
}

#[derive(serde::Serialize)]
struct LpmPackFile<'a> {
    path: &'a str,
    size: u64,
}

fn packed_file_size(file: &TarballFile, package_json_size_override: Option<u64>) -> u64 {
    if file.path == "package.json" {
        package_json_size_override.unwrap_or(file.size)
    } else {
        file.size
    }
}

struct LpmVersionPayload<'a> {
    base: &'a serde_json::Map<String, serde_json::Value>,
    quality_result: Option<&'a quality::QualityResult>,
    pack_metadata: &'a LpmPackMetadata<'a>,
    lpm_config: Option<&'a serde_json::Value>,
    detected_ecosystem: &'a str,
    swift_metadata: Option<&'a serde_json::Value>,
}

impl LpmVersionPayload<'_> {
    fn replaces(&self, key: &str) -> bool {
        key == "_npmPackMeta"
            || self.quality_result.is_some() && matches!(key, "_qualityChecks" | "_qualityMeta")
            || self.lpm_config.is_some() && key == "_lpmConfig"
            || self.detected_ecosystem != "js" && key == "_ecosystem"
            || self.swift_metadata.is_some() && key == "_swiftManifest"
    }
}

impl serde::Serialize for LpmVersionPayload<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let replaced = self.base.keys().filter(|key| self.replaces(key)).count();
        let additions = 1
            + usize::from(self.quality_result.is_some()) * 2
            + usize::from(self.lpm_config.is_some())
            + usize::from(self.detected_ecosystem != "js")
            + usize::from(self.swift_metadata.is_some());
        let mut map = serializer.serialize_map(Some(
            self.base
                .len()
                .saturating_sub(replaced)
                .saturating_add(additions),
        ))?;
        for (key, value) in self.base {
            if !self.replaces(key) {
                map.serialize_entry(key, value)?;
            }
        }
        if let Some(result) = self.quality_result {
            map.serialize_entry("_qualityChecks", &result.checks)?;
            map.serialize_entry(
                "_qualityMeta",
                &LpmQualityMetadata {
                    score: result.score,
                    max_score: result.max_score,
                    ecosystem: self.detected_ecosystem,
                },
            )?;
        }
        map.serialize_entry("_npmPackMeta", self.pack_metadata)?;
        if let Some(config) = self.lpm_config {
            map.serialize_entry("_lpmConfig", config)?;
        }
        if self.detected_ecosystem != "js" {
            map.serialize_entry("_ecosystem", self.detected_ecosystem)?;
        }
        if let Some(metadata) = self.swift_metadata {
            map.serialize_entry("_swiftManifest", metadata)?;
        }
        map.end()
    }
}

#[derive(serde::Serialize)]
struct LpmQualityMetadata<'a> {
    score: u32,
    #[serde(rename = "maxScore")]
    max_score: u32,
    ecosystem: &'a str,
}

struct LpmPublishPayload<'a> {
    name: &'a str,
    version: &'a str,
    readme: Option<&'a str>,
    detected_ecosystem: &'a str,
    lpm_version: &'a LpmVersionPayload<'a>,
    tarball_key: &'a str,
    attachment: LpmUploadedAttachment<'a>,
}

/// The publish's attachment: the tarball's upload in place of its data.
#[derive(serde::Serialize)]
struct LpmUploadedAttachment<'a> {
    content_type: &'a str,
    length: usize,
    upload_id: &'a str,
}

struct LpmVersions<'a> {
    version: &'a str,
    payload: &'a LpmVersionPayload<'a>,
}

impl serde::Serialize for LpmVersions<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.version, self.payload)?;
        map.end()
    }
}

fn build_lpm_publish_payload(input: LpmPublishPayload<'_>) -> Result<Vec<u8>, LpmError> {
    let mut payload = Vec::with_capacity(64 * 1024);
    payload.write_all(b"{").map_err(LpmError::Io)?;
    write_lpm_json_member(&mut payload, "_id", input.name, true)?;
    write_lpm_json_member(&mut payload, "name", input.name, false)?;
    write_lpm_json_member(
        &mut payload,
        "description",
        input
            .lpm_version
            .base
            .get("description")
            .unwrap_or(&serde_json::Value::Null),
        false,
    )?;
    write_lpm_json_member(&mut payload, "readme", &input.readme, false)?;
    write_lpm_json_member(&mut payload, "_ecosystem", input.detected_ecosystem, false)?;
    write_lpm_json_member(
        &mut payload,
        "dist-tags",
        &serde_json::json!({"latest": input.version}),
        false,
    )?;
    write_lpm_json_member(
        &mut payload,
        "versions",
        &LpmVersions {
            version: input.version,
            payload: input.lpm_version,
        },
        false,
    )?;
    payload
        .write_all(b",\"_attachments\":{")
        .map_err(LpmError::Io)?;
    serde_json::to_writer(&mut payload, input.tarball_key).map_err(publish_serialization_error)?;
    payload.write_all(b":").map_err(LpmError::Io)?;
    serde_json::to_writer(&mut payload, &input.attachment).map_err(publish_serialization_error)?;
    payload.write_all(b"}}").map_err(LpmError::Io)?;
    Ok(payload)
}

fn write_lpm_json_member<T: serde::Serialize + ?Sized>(
    writer: &mut Vec<u8>,
    key: &str,
    value: &T,
    first: bool,
) -> Result<(), LpmError> {
    if !first {
        writer.write_all(b",").map_err(LpmError::Io)?;
    }
    serde_json::to_writer(&mut *writer, key).map_err(publish_serialization_error)?;
    writer.write_all(b":").map_err(LpmError::Io)?;
    serde_json::to_writer(writer, value).map_err(publish_serialization_error)
}

fn publish_serialization_error(error: serde_json::Error) -> LpmError {
    LpmError::Registry(format!("failed to serialize publish payload: {error}"))
}

fn lpm_publish_transport_is_allowed(registry_url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(registry_url) else {
        return false;
    };
    parsed.scheme() == "https"
        || (parsed.scheme() == "http" && lpm_publish_registry_host_is_loopback(&parsed))
}

fn lpm_publish_registry_is_default_or_loopback(registry_url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(registry_url) else {
        return false;
    };
    let is_default = parsed.scheme() == "https"
        && parsed
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("lpm.dev"))
        && parsed.port_or_known_default() == Some(443);
    is_default || lpm_publish_registry_host_is_loopback(&parsed)
}

fn lpm_publish_registry_host_is_loopback(registry_url: &reqwest::Url) -> bool {
    registry_url
        .host_str()
        .is_some_and(lpm_common::is_loopback_host)
}

fn is_valid_otp(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{
        LpmPackMetadata, LpmPublishBody, LpmVersionPayload, is_valid_otp,
        lpm_publish_transport_is_allowed,
    };

    #[test]
    fn lpm_publish_payload_names_the_upload_in_place_of_the_tarball() {
        let version_data = serde_json::json!({
            "name": "@lpm.dev/owner.pkg",
            "version": "1.0.0",
            "dist": { "integrity": "sha512-abc" },
        });
        let files = [crate::commands::publish_common::TarballFile {
            path: "package.json".into(),
            size: 10,
        }];
        let body = LpmPublishBody {
            name: "@lpm.dev/owner.pkg",
            version: "1.0.0",
            readme: Some("# Pkg"),
            version_data: &version_data,
            tarball_files: &files,
            package_json_size_override: None,
            quality_result: None,
            lpm_config: None,
            detected_ecosystem: "js",
            swift_manifest: None,
        };
        let upload_id = "11111111-1111-4111-8111-111111111111";

        let bytes = body.payload(upload_id, 4096).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            payload["_attachments"],
            serde_json::json!({
                "lpm.dev-owner.pkg-1.0.0.tgz": {
                    "content_type": "application/gzip",
                    "length": 4096,
                    "upload_id": upload_id,
                }
            })
        );
        assert_eq!(
            payload["versions"]["1.0.0"]["dist"]["integrity"],
            "sha512-abc"
        );
        assert_eq!(body.len_with(4096).unwrap(), bytes.len() as u64);
    }

    #[test]
    fn lpm_pack_metadata_serializes_borrowed_files_with_the_manifest_size_override() {
        let base = serde_json::json!({
            "name": "borrowed-pack-metadata",
            "version": "1.0.0",
        });
        let files = [
            crate::commands::publish_common::TarballFile {
                path: "package.json".into(),
                size: 10,
            },
            crate::commands::publish_common::TarballFile {
                path: "index.js".into(),
                size: 20,
            },
        ];
        let pack_metadata = LpmPackMetadata::new(&files, Some(12));
        let version = LpmVersionPayload {
            base: base.as_object().unwrap(),
            quality_result: None,
            pack_metadata: &pack_metadata,
            lpm_config: None,
            detected_ecosystem: "js",
            swift_metadata: None,
        };

        let serialized = serde_json::to_value(version).unwrap();

        assert_eq!(
            serialized["_npmPackMeta"],
            serde_json::json!({
                "files": [
                    {"path": "package.json", "size": 12},
                    {"path": "index.js", "size": 20},
                ],
                "unpackedSize": 32,
                "fileCount": 2,
            }),
        );
        assert!(base.get("_npmPackMeta").is_none());
    }

    #[test]
    fn lpm_publish_transport_rejects_hosts_with_a_loopback_name_prefix() {
        assert!(!lpm_publish_transport_is_allowed(
            "http://localhost.attacker.example"
        ));
        assert!(!lpm_publish_transport_is_allowed(
            "http://127.0.0.1.attacker.example"
        ));
        assert!(!lpm_publish_transport_is_allowed(
            "http://127.0.0.1@attacker.example"
        ));
    }

    #[test]
    fn lpm_publish_transport_allows_https_and_exact_loopback_http_origins() {
        for registry in [
            "https://registry.example.test",
            "http://localhost:4873",
            "http://127.0.0.1:4873",
            "http://[::1]:4873",
        ] {
            assert!(
                lpm_publish_transport_is_allowed(registry),
                "unexpected rejected registry: {registry}"
            );
        }
    }

    #[test]
    fn lpm_publish_otp_accepts_exactly_six_ascii_digits() {
        assert!(is_valid_otp("123456"));
    }

    #[test]
    fn lpm_publish_otp_rejects_invalid_codes() {
        for code in ["12345", "1234567", "１２３４５６", "12345a"] {
            assert!(!is_valid_otp(code), "unexpected valid OTP: {code}");
        }
    }
}
