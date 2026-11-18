//! Which signers SwiftPM accepts for a registry's releases: the roots LPM CLI
//! pins for a registry, and the user-wide signing configuration that points
//! SwiftPM at them.

use super::ensure_json_object as object;
use lpm_common::LpmError;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The offline roots LPM.dev signs its Swift releases under. A release
/// verifies only when a certificate one of them issued signed it; a
/// rotation ships the new root beside the old one.
const LPM_DEV_SIGNING_ROOTS: &[&str] = &[include_str!("lpm-dev-swift-signing-root-2026.pem")];

const LPM_DEV_HOST: &str = "lpm.dev";

/// Holds one directory of roots per pinned registry. SwiftPM reads every
/// file in a registry's directory as a trusted root and fails on one that
/// isn't, so nothing else may live there; the lock and staged writes sit
/// one level up.
const ROOTS_DIRECTORY: &str = "lpm-trusted-roots";
const ROOTS_LOCK: &str = ".lpm-trusted-roots.lock";

/// The certificate earlier LPM CLI releases wrote. SwiftPM reads a trusted
/// root only from a directory its configuration names, so it never read
/// this one.
const LEGACY_CERTIFICATE: [&str; 2] = ["trusted-root-certs", "lpm.der"];

const SCOPE: &str = "lpmdev";
const MAX_ROOT_BYTES: u64 = 64 * 1024;

/// Which signers SwiftPM accepts for a registry's releases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SignerTrust {
    /// Only a signer whose certificate one of `roots` (DER) issued. SwiftPM
    /// reads the roots from `directory`.
    Pinned {
        roots: Vec<Vec<u8>>,
        directory: PathBuf,
    },
    /// Any signer; the connection to the registry is the only anchor.
    Unpinned,
}

impl SignerTrust {
    /// The trust LPM CLI configures for the registry SwiftPM knows as
    /// `host`. SwiftPM keys signing settings by host alone, so every
    /// registry on LPM.dev's host shares its pinned roots.
    pub(super) fn for_host(host: &str) -> Result<Self, LpmError> {
        if !host.eq_ignore_ascii_case(LPM_DEV_HOST) {
            return Ok(Self::Unpinned);
        }
        Ok(Self::Pinned {
            roots: LPM_DEV_SIGNING_ROOTS
                .iter()
                .map(|pem| decode_built_in_root(pem))
                .collect::<Result<_, _>>()?,
            // Written into SwiftPM's configuration, so spelled plainly
            // rather than with a canonical path's `\\?\` prefix.
            directory: lpm_common::symlink::windows_plain_path(
                &crate::swift_manifest::paths::security_dir()?
                    .join(ROOTS_DIRECTORY)
                    .join(LPM_DEV_HOST),
            ),
        })
    }

    #[inline]
    pub(super) fn is_pinned(&self) -> bool {
        matches!(self, Self::Pinned { .. })
    }
}

fn decode_built_in_root(pem: &str) -> Result<Vec<u8>, LpmError> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map(|(_, pem)| pem.contents)
        .map_err(|error| {
            LpmError::Registry(format!(
                "LPM CLI's built-in Swift signing root can't be read: {error}"
            ))
        })
}

/// What [`install_roots`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RootsOutcome {
    Installed,
    AlreadyInstalled,
    /// The registry has no pinned roots, so there was nothing to install.
    NotPinned,
}

/// Leaves a pinned registry's roots directory holding exactly its roots,
/// rewriting them all when `force` is set, and removes the certificate
/// earlier releases wrote.
pub(super) fn install_roots(trust: &SignerTrust, force: bool) -> Result<RootsOutcome, LpmError> {
    let SignerTrust::Pinned { roots, directory } = trust else {
        return Ok(RootsOutcome::NotPinned);
    };
    let (Some(roots_parent), Some(security)) = (
        directory.parent(),
        directory.parent().and_then(Path::parent),
    ) else {
        return Err(roots_error(directory, "has no parent directory"));
    };
    std::fs::create_dir_all(security).map_err(|error| roots_error(security, error))?;
    real_directory(roots_parent)?;
    real_directory(directory)?;
    let _lock = super::configuration::exclusive_lock(&roots_parent.join(ROOTS_LOCK))?;

    let expected: Vec<(String, &[u8])> = roots
        .iter()
        .map(|root| (root_file_name(root), root.as_slice()))
        .collect();
    let mut changed = remove_other_entries(directory, &expected)?;
    for (name, root) in &expected {
        let path = directory.join(name);
        if force || read_root(&path).as_deref() != Some(*root) {
            write_root(roots_parent, &path, root)?;
            changed = true;
        }
    }
    changed |= remove_legacy_certificate(security)?;
    Ok(if changed {
        RootsOutcome::Installed
    } else {
        RootsOutcome::AlreadyInstalled
    })
}

fn root_file_name(root: &[u8]) -> String {
    let mut name = hex::encode(Sha256::digest(root));
    name.push_str(".der");
    name
}

fn roots_error(path: &Path, detail: impl std::fmt::Display) -> LpmError {
    LpmError::Registry(format!(
        "Can't set up the Swift signing roots at {}: {detail}",
        path.display()
    ))
}

fn real_directory(path: &Path) -> Result<(), LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata) => {
            Ok(())
        }
        Ok(_) => Err(roots_error(
            path,
            "expected a directory, not a link or a file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    real_directory(path)
                }
                Err(error) => Err(roots_error(path, error)),
            }
        }
        Err(error) => Err(roots_error(path, error)),
    }
}

/// Removes every entry of `directory` but a regular file named for one of
/// the `expected` roots; whether it removed any.
fn remove_other_entries(directory: &Path, expected: &[(String, &[u8])]) -> Result<bool, LpmError> {
    let mut removed = false;
    let entries = std::fs::read_dir(directory).map_err(|error| roots_error(directory, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| roots_error(directory, error))?;
        let path = entry.path();
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|error| roots_error(&path, error))?;
        let linked = lpm_common::is_symlink_or_junction(&metadata);
        let name = entry.file_name();
        if metadata.is_file()
            && !linked
            && expected
                .iter()
                .any(|(expected, _)| name.to_str() == Some(expected.as_str()))
        {
            continue;
        }
        if metadata.is_dir() && !linked {
            return Err(roots_error(
                &path,
                "SwiftPM reads every entry here as a trusted root, so this directory can't stay; remove it",
            ));
        }
        lpm_common::remove_path_entry(&path).map_err(|error| roots_error(&path, error))?;
        removed = true;
    }
    Ok(removed)
}

/// The root at `path`, when it's a regular file of a plausible size.
fn read_root(path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || lpm_common::is_symlink_or_junction(&metadata) {
        return None;
    }
    lpm_common::read_file_capped(path, MAX_ROOT_BYTES).ok()
}

/// Writes `root` to `path` through a file staged in `staging`, outside the
/// roots directory, so an interrupted write never leaves SwiftPM a partial
/// root to read.
fn write_root(staging: &Path, path: &Path, root: &[u8]) -> Result<(), LpmError> {
    let mut staged =
        tempfile::NamedTempFile::new_in(staging).map_err(|error| roots_error(staging, error))?;
    staged
        .write_all(root)
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| roots_error(staged.path(), error))?;
    staged
        .persist(path)
        .map_err(|error| roots_error(path, error.error))?;
    Ok(())
}

fn remove_legacy_certificate(security: &Path) -> Result<bool, LpmError> {
    let path = LEGACY_CERTIFICATE
        .iter()
        .fold(security.to_path_buf(), |path, component| {
            path.join(component)
        });
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !lpm_common::is_symlink_or_junction(&metadata) => {
            Ok(false)
        }
        Ok(_) => {
            lpm_common::remove_path_entry(&path).map_err(|error| roots_error(&path, error))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(roots_error(&path, error)),
    }
}

/// Points `config`'s signing settings for `host` at `trust`, with strict
/// defaults for every other registry, and drops the `lpmdev` scope and
/// package settings that would override them.
pub(super) fn apply(config: &mut Value, host: &str, trust: &SignerTrust) -> Result<(), LpmError> {
    let root = object(config)?;
    root.insert("version".to_string(), Value::from(1));
    object(root.entry("registries").or_insert_with(empty_object))?;
    let security = object(root.entry("security").or_insert_with(empty_object))?;

    let default_signing = object(
        object(security.entry("default").or_insert_with(empty_object))?
            .entry("signing")
            .or_insert_with(empty_object),
    )?;
    for action in ["onUnsigned", "onUntrustedCertificate"] {
        if !is_error_action(default_signing.get(action)) {
            default_signing.insert(action.to_string(), Value::from("error"));
        }
    }

    let overriding_keys: &[&str] = if trust.is_pinned() {
        &[
            "onUntrustedCertificate",
            "trustedRootCertificatesPath",
            "includeDefaultTrustedRootCertificates",
        ]
    } else {
        &["onUntrustedCertificate"]
    };
    for (section, matches) in [
        ("scopeOverrides", is_lpm_scope as fn(&str) -> bool),
        ("packageOverrides", is_lpm_package),
    ] {
        let Some(overrides) = security.get_mut(section).and_then(Value::as_object_mut) else {
            continue;
        };
        for (key, entry) in overrides.iter_mut() {
            if !matches(key) {
                continue;
            }
            if let Some(signing) = entry.get_mut("signing").and_then(Value::as_object_mut) {
                for key in overriding_keys {
                    signing.remove(*key);
                }
            }
        }
    }

    let registry = object(
        object(
            security
                .entry("registryOverrides")
                .or_insert_with(empty_object),
        )?
        .entry(host)
        .or_insert_with(empty_object),
    )?;
    let signing = object(registry.entry("signing").or_insert_with(empty_object))?;
    match trust {
        SignerTrust::Pinned { directory, .. } => {
            signing.insert("onUnsigned".to_string(), Value::from("error"));
            signing.insert("onUntrustedCertificate".to_string(), Value::from("error"));
            signing.insert(
                "trustedRootCertificatesPath".to_string(),
                Value::from(roots_path(directory)?),
            );
            signing.insert(
                "includeDefaultTrustedRootCertificates".to_string(),
                Value::Bool(false),
            );
        }
        SignerTrust::Unpinned => {
            signing.insert(
                "onUntrustedCertificate".to_string(),
                Value::from("silentAllow"),
            );
        }
    }
    Ok(())
}

/// Whether `config` already holds what [`apply`] writes.
pub(super) fn is_applied(config: &Value, host: &str, trust: &SignerTrust) -> bool {
    config.get("version").and_then(Value::as_u64) == Some(1)
        && config.get("registries").is_some_and(Value::is_object)
        && config
            .get("security")
            .is_some_and(|security| security_keeps(security, host, trust))
}

/// Whether a project's own registries.json keeps a pinned registry's roots
/// from applying to it. SwiftPM takes a project's `security` settings in
/// place of the user's, whole, so a project that has any must restate the
/// pin itself.
pub(super) fn project_sets_aside(project_config: &Value, host: &str, trust: &SignerTrust) -> bool {
    let SignerTrust::Pinned { directory, .. } = trust else {
        return false;
    };
    project_config
        .get("security")
        .is_some_and(|security| !pin_holds(security, host, directory))
}

/// Whether the `security` settings apply `trust` to `host`, with strict
/// defaults for every other registry.
fn security_keeps(security: &Value, host: &str, trust: &SignerTrust) -> bool {
    let default_signing = security.pointer("/default/signing");
    let defaults_strict = ["onUnsigned", "onUntrustedCertificate"]
        .iter()
        .all(|action| is_error_action(default_signing.and_then(|signing| signing.get(action))));
    if !defaults_strict
        || overrides_set(
            security,
            "scopeOverrides",
            is_lpm_scope,
            &["onUntrustedCertificate"],
        )
    {
        return false;
    }
    match trust {
        SignerTrust::Pinned { directory, .. } => pin_holds(security, host, directory),
        SignerTrust::Unpinned => {
            host_signing(security, host)
                .and_then(|signing| signing.get("onUntrustedCertificate"))
                .and_then(Value::as_str)
                == Some("silentAllow")
        }
    }
}

/// Whether the `security` settings accept `host`'s `lpmdev` releases only
/// from a signer under the roots in `directory`.
fn pin_holds(security: &Value, host: &str, directory: &Path) -> bool {
    let roots_keys = [
        "trustedRootCertificatesPath",
        "includeDefaultTrustedRootCertificates",
    ];
    if overrides_set(security, "scopeOverrides", is_lpm_scope, &roots_keys)
        || overrides_set(security, "packageOverrides", is_lpm_package, &roots_keys)
    {
        return false;
    }
    let Some(signing) = host_signing(security, host) else {
        return false;
    };
    let action = |key: &str| signing.get(key).and_then(Value::as_str);
    action("onUnsigned") == Some("error")
        && action("onUntrustedCertificate") == Some("error")
        && roots_path(directory)
            .is_ok_and(|path| action("trustedRootCertificatesPath") == Some(path))
        && signing.get("includeDefaultTrustedRootCertificates") == Some(&Value::Bool(false))
}

fn host_signing<'a>(security: &'a Value, host: &str) -> Option<&'a Value> {
    security
        .get("registryOverrides")
        .and_then(|overrides| overrides.get(host))
        .and_then(|registry| registry.get("signing"))
}

/// Whether a `section` entry `matches` names sets any of `keys` in its
/// signing settings.
fn overrides_set(
    security: &Value,
    section: &str,
    matches: fn(&str) -> bool,
    keys: &[&str],
) -> bool {
    security
        .get(section)
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(key, _)| matches(key))
        .filter_map(|(_, entry)| entry.get("signing"))
        .any(|signing| {
            keys.iter()
                .any(|key| signing.get(*key).is_some_and(|value| !value.is_null()))
        })
}

fn roots_path(directory: &Path) -> Result<&str, LpmError> {
    directory.to_str().ok_or_else(|| {
        roots_error(
            directory,
            "SwiftPM's configuration needs this path in UTF-8",
        )
    })
}

/// SwiftPM compares scopes without regard to case.
fn is_lpm_scope(scope: &str) -> bool {
    scope.eq_ignore_ascii_case(SCOPE)
}

fn is_lpm_package(identity: &str) -> bool {
    identity
        .split_once('.')
        .is_some_and(|(scope, _)| is_lpm_scope(scope))
}

fn is_error_action(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str) == Some("error")
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}
