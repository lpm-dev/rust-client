//! Client for Sigstore's TUF repository, the signed channel through which
//! Sigstore publishes its trust root.
//!
//! An LPM binary holds the trust root that was current when it was built.
//! Sigstore rotates the keys and certificate authorities in it, so a copy
//! that never refreshed would end up unable to verify new signatures,
//! including the ones on later LPM releases. This client refreshes the
//! trust root the way Sigstore's own clients do: it starts from the TUF root
//! built into the binary, follows the root rotations Sigstore signed, and
//! accepts only a trust root whose hashes the current targets role signed.
//!
//! It implements the TUF 1.x client workflow for the four top-level roles
//! and the one target LPM needs. Delegated targets are not followed.

mod canonical;
mod metadata;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use metadata::{Root, Signed, Snapshot, Targets, Timestamp, check_length_and_hashes};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// The target that holds Sigstore's trust root.
pub(crate) const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";

/// Size limits, from python-tuf's client defaults. The trust root itself is
/// a few kilobytes.
const ROOT_MAX_BYTES: u64 = 512_000;
const TIMESTAMP_MAX_BYTES: u64 = 16_384;
const SNAPSHOT_MAX_BYTES: u64 = 2_000_000;
const TARGETS_MAX_BYTES: u64 = 5_000_000;
const TRUSTED_ROOT_MAX_BYTES: u64 = 1_048_576;

/// Most root versions one refresh follows. Sigstore has published one or
/// two a year.
const MAX_ROOT_ROTATIONS: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TufError {
    #[error("Sigstore's {role} metadata is malformed: {detail}")]
    Malformed { role: &'static str, detail: String },
    #[error(
        "Sigstore's {role} metadata has {valid} valid signature(s), and {threshold} are required"
    )]
    Threshold {
        role: &'static str,
        valid: usize,
        threshold: usize,
    },
    #[error("Sigstore's {role} metadata is version {actual}, and version {expected} was expected")]
    Version {
        role: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("Sigstore's {role} metadata went back from version {trusted} to {offered}")]
    Rollback {
        role: &'static str,
        trusted: u64,
        offered: u64,
    },
    #[error("Sigstore's {role} metadata expired at {expires}")]
    Expired { role: &'static str, expires: String },
    #[error("{name} doesn't match what Sigstore's metadata records: {detail}")]
    Mismatch { name: String, detail: String },
    #[error("Sigstore's repository has no {0}")]
    Missing(String),
    #[error("fetching {path} from Sigstore's repository failed: {detail}")]
    Fetch { path: String, detail: String },
}

/// Where a refresh reads repository files from.
pub(crate) trait Fetcher {
    /// Fetch the repository file at `path`, refusing more than `max_bytes`.
    /// `Ok(None)` means the repository has no such file.
    async fn fetch(&self, path: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, String>;
}

/// The verified metadata a refresh produced, kept between runs.
///
/// Each document is stored exactly as Sigstore served it, and everything is
/// checked again when it is read back, so the cache is never trusted on its
/// own: a forged entry fails the signature checks anchored in the TUF root
/// built into the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TrustedMetadata {
    /// Root metadata newer than the embedded root, oldest first.
    pub(crate) roots: Vec<String>,
    pub(crate) timestamp: String,
    pub(crate) snapshot: String,
    pub(crate) targets: String,
    pub(crate) trusted_root: String,
}

/// A trust root that Sigstore's targets role signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedTrustedRoot {
    pub(crate) bytes: Vec<u8>,
    /// Version of the targets metadata that recorded it.
    pub(crate) targets_version: u64,
}

impl TrustedMetadata {
    /// Check stored metadata again and return the trust root it holds.
    ///
    /// Expiry is not enforced here. Stored metadata stands in for the trust
    /// root built into the binary when Sigstore's repository can't be
    /// reached, and it is never older than what that binary was built with.
    pub(crate) fn verified_trusted_root(
        &self,
        embedded_root: &[u8],
    ) -> Result<VerifiedTrustedRoot, TufError> {
        let root = follow_roots(Signed::<Root>::parse(embedded_root)?, &self.roots)?;
        let targets = Signed::<Targets>::parse(self.targets.as_bytes())?;
        targets.verify_with(&root.signed)?;
        check_trusted_root(&targets, self.trusted_root.as_bytes())?;
        Ok(VerifiedTrustedRoot {
            bytes: self.trusted_root.clone().into_bytes(),
            targets_version: targets.version(),
        })
    }
}

/// Run the TUF client workflow against `fetcher` and return the metadata it
/// verified.
///
/// `stored` is what an earlier refresh returned. It anchors the rollback
/// checks, and its roots spare refetching every rotation since the embedded
/// root. Stored metadata that no longer verifies is ignored.
pub(crate) async fn refresh<F: Fetcher>(
    embedded_root: &[u8],
    stored: Option<&TrustedMetadata>,
    fetcher: &F,
    now: SystemTime,
) -> Result<TrustedMetadata, TufError> {
    let embedded = Signed::<Root>::parse(embedded_root)?;
    let stored = stored.and_then(|stored| {
        follow_roots(embedded.clone(), &stored.roots)
            .ok()
            .map(|root| (stored, root))
    });
    let (mut root, mut roots) = match &stored {
        Some((stored, root)) => (root.clone(), stored.roots.clone()),
        None => (embedded, Vec::new()),
    };
    let starting_root = root.signed.clone();

    for _ in 0..MAX_ROOT_ROTATIONS {
        let next = root.version() + 1;
        let path = format!("{next}.root.json");
        let Some(bytes) = fetch(fetcher, &path, ROOT_MAX_BYTES).await? else {
            break;
        };
        root = rotate_root(&root, &bytes)?;
        roots.push(into_text(bytes, &path)?);
    }
    root.ensure_unexpired(now)?;

    // A root that replaced the timestamp or snapshot keys may restart those
    // roles' version numbers, so the old versions no longer bound them.
    let keys_rotated = starting_root.role_keys_differ(&root.signed, "timestamp")
        || starting_root.role_keys_differ(&root.signed, "snapshot");
    let previous = stored
        .filter(|_| !keys_rotated)
        .map(|(stored, _)| PreviousVersions::from_stored(stored, &root.signed));

    let timestamp_text = fetch_required(fetcher, "timestamp.json", TIMESTAMP_MAX_BYTES).await?;
    let timestamp = Signed::<Timestamp>::parse(&timestamp_text)?;
    timestamp.verify_with(&root.signed)?;
    let snapshot_meta =
        timestamp
            .signed
            .meta
            .get("snapshot.json")
            .ok_or_else(|| TufError::Malformed {
                role: "timestamp",
                detail: "it records no snapshot.json".into(),
            })?;
    if let Some(previous) = previous.as_ref().and_then(|p| p.timestamp.as_ref()) {
        not_older("timestamp", previous.version(), timestamp.version())?;
        if let Some(old) = previous.signed.meta.get("snapshot.json") {
            not_older("snapshot", old.version, snapshot_meta.version)?;
        }
    }
    timestamp.ensure_unexpired(now)?;

    let snapshot_path = versioned_path(&root, snapshot_meta.version, "snapshot.json");
    let snapshot_text = fetch_required(
        fetcher,
        &snapshot_path,
        capped(snapshot_meta.length, SNAPSHOT_MAX_BYTES),
    )
    .await?;
    check_length_and_hashes(
        &snapshot_text,
        snapshot_meta.length,
        snapshot_meta.hashes.as_ref(),
        false,
        "snapshot.json",
    )?;
    let snapshot = Signed::<Snapshot>::parse(&snapshot_text)?;
    snapshot.verify_with(&root.signed)?;
    expect_version("snapshot", snapshot_meta.version, snapshot.version())?;
    if let Some(previous) = previous.as_ref().and_then(|p| p.snapshot.as_ref()) {
        for (name, old) in &previous.signed.meta {
            let offered = snapshot
                .signed
                .meta
                .get(name)
                .ok_or_else(|| TufError::Missing(format!("{name} in its snapshot")))?;
            not_older("snapshot", old.version, offered.version)?;
        }
    }
    snapshot.ensure_unexpired(now)?;

    let targets_meta =
        snapshot
            .signed
            .meta
            .get("targets.json")
            .ok_or_else(|| TufError::Malformed {
                role: "snapshot",
                detail: "it records no targets.json".into(),
            })?;
    let targets_path = versioned_path(&root, targets_meta.version, "targets.json");
    let targets_text = fetch_required(
        fetcher,
        &targets_path,
        capped(targets_meta.length, TARGETS_MAX_BYTES),
    )
    .await?;
    check_length_and_hashes(
        &targets_text,
        targets_meta.length,
        targets_meta.hashes.as_ref(),
        false,
        "targets.json",
    )?;
    let targets = Signed::<Targets>::parse(&targets_text)?;
    targets.verify_with(&root.signed)?;
    expect_version("targets", targets_meta.version, targets.version())?;
    targets.ensure_unexpired(now)?;

    let target = trusted_root_entry(&targets)?;
    if target.length > TRUSTED_ROOT_MAX_BYTES {
        return Err(TufError::Mismatch {
            name: TRUSTED_ROOT_TARGET.into(),
            detail: format!(
                "it is recorded as {} bytes, over the {TRUSTED_ROOT_MAX_BYTES}-byte limit",
                target.length
            ),
        });
    }
    let target_path = if root.signed.consistent_snapshot {
        let prefix = target
            .hashes
            .get("sha256")
            .or_else(|| target.hashes.get("sha512"))
            .ok_or_else(|| TufError::Mismatch {
                name: TRUSTED_ROOT_TARGET.into(),
                detail: "no SHA-256 or SHA-512 hash is recorded for it".into(),
            })?;
        format!("targets/{prefix}.{TRUSTED_ROOT_TARGET}")
    } else {
        format!("targets/{TRUSTED_ROOT_TARGET}")
    };
    let trusted_root = fetch_required(fetcher, &target_path, target.length).await?;
    check_trusted_root(&targets, &trusted_root)?;

    Ok(TrustedMetadata {
        roots,
        timestamp: into_text(timestamp_text, "timestamp.json")?,
        snapshot: into_text(snapshot_text, &snapshot_path)?,
        targets: into_text(targets_text, &targets_path)?,
        trusted_root: into_text(trusted_root, &target_path)?,
    })
}

/// Timestamp and snapshot metadata from the previous refresh that still
/// verify under the current root.
struct PreviousVersions {
    timestamp: Option<Signed<Timestamp>>,
    snapshot: Option<Signed<Snapshot>>,
}

impl PreviousVersions {
    fn from_stored(stored: &TrustedMetadata, root: &Root) -> Self {
        fn verified<T: metadata::Role>(text: &str, root: &Root) -> Option<Signed<T>> {
            let parsed = Signed::<T>::parse(text.as_bytes()).ok()?;
            parsed.verify_with(root).ok()?;
            Some(parsed)
        }
        Self {
            timestamp: verified(&stored.timestamp, root),
            snapshot: verified(&stored.snapshot, root),
        }
    }
}

/// Accept `bytes` as the root that follows `trusted` if a threshold of the
/// trusted root's keys and a threshold of its own keys signed it.
fn rotate_root(trusted: &Signed<Root>, bytes: &[u8]) -> Result<Signed<Root>, TufError> {
    let next = Signed::<Root>::parse(bytes)?;
    next.verify_with(&trusted.signed)?;
    next.verify_with(&next.signed)?;
    expect_version("root", trusted.version() + 1, next.version())?;
    Ok(next)
}

fn follow_roots(mut root: Signed<Root>, newer: &[String]) -> Result<Signed<Root>, TufError> {
    for text in newer {
        root = rotate_root(&root, text.as_bytes())?;
    }
    Ok(root)
}

fn trusted_root_entry(targets: &Signed<Targets>) -> Result<&metadata::TargetFile, TufError> {
    targets
        .signed
        .targets
        .get(TRUSTED_ROOT_TARGET)
        .ok_or_else(|| TufError::Missing(format!("{TRUSTED_ROOT_TARGET} among its targets")))
}

fn check_trusted_root(targets: &Signed<Targets>, bytes: &[u8]) -> Result<(), TufError> {
    let target = trusted_root_entry(targets)?;
    check_length_and_hashes(
        bytes,
        Some(target.length),
        Some(&target.hashes),
        true,
        TRUSTED_ROOT_TARGET,
    )
}

fn versioned_path(root: &Signed<Root>, version: u64, name: &str) -> String {
    if root.signed.consistent_snapshot {
        format!("{version}.{name}")
    } else {
        name.to_string()
    }
}

fn capped(recorded: Option<u64>, limit: u64) -> u64 {
    recorded.map_or(limit, |length| length.min(limit))
}

fn expect_version(role: &'static str, expected: u64, actual: u64) -> Result<(), TufError> {
    if expected == actual {
        Ok(())
    } else {
        Err(TufError::Version {
            role,
            expected,
            actual,
        })
    }
}

fn not_older(role: &'static str, trusted: u64, offered: u64) -> Result<(), TufError> {
    if offered >= trusted {
        Ok(())
    } else {
        Err(TufError::Rollback {
            role,
            trusted,
            offered,
        })
    }
}

async fn fetch<F: Fetcher>(
    fetcher: &F,
    path: &str,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>, TufError> {
    fetcher
        .fetch(path, max_bytes)
        .await
        .map_err(|detail| TufError::Fetch {
            path: path.to_string(),
            detail,
        })
}

async fn fetch_required<F: Fetcher>(
    fetcher: &F,
    path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, TufError> {
    fetch(fetcher, path, max_bytes)
        .await?
        .ok_or_else(|| TufError::Missing(path.to_string()))
}

fn into_text(bytes: Vec<u8>, path: &str) -> Result<String, TufError> {
    String::from_utf8(bytes).map_err(|_| TufError::Mismatch {
        name: path.to_string(),
        detail: "it is not UTF-8 text".into(),
    })
}
