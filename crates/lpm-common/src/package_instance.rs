use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};

/// Resolver-local identity for one exact node in a completed dependency graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolutionNodeId(u32);

impl ResolutionNodeId {
    pub const UNASSIGNED: Self = Self(u32::MAX);

    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Stable identity for one package instance within an exact resolved graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageInstanceId([u8; 32]);

impl PackageInstanceId {
    pub const HEX_LEN: usize = 64;

    pub fn derive(
        name: &str,
        version: &str,
        normalized_source: &str,
        canonical_path: &str,
    ) -> Self {
        Self::derive_from_path_digest(
            name,
            version,
            normalized_source,
            Sha256::digest(canonical_path.as_bytes()).into(),
        )
    }

    pub fn derive_from_path_digest(
        name: &str,
        version: &str,
        normalized_source: &str,
        path_digest: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"lpm-package-instance-v1\0");
        for value in [name, version, normalized_source] {
            hasher.update(value.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(path_digest);
        Self(hasher.finalize().into())
    }

    /// Derives a new identity after the same graph node is projected under a
    /// different normalized source path while preserving its prior context.
    pub fn rebase_source(self, name: &str, version: &str, normalized_source: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"lpm-package-instance-rebased-source-v1\0");
        for value in [name, version, normalized_source] {
            hasher.update(value.as_bytes());
            hasher.update(b"\0");
        }
        hasher.update(self.0);
        Self(hasher.finalize().into())
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() != Self::HEX_LEN {
            return Err("package instance id must be 64 lowercase hexadecimal characters".into());
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let Some(high) = lower_hex_value(pair[0]) else {
                return Err(
                    "package instance id must be 64 lowercase hexadecimal characters".into(),
                );
            };
            let Some(low) = lower_hex_value(pair[1]) else {
                return Err(
                    "package instance id must be 64 lowercase hexadecimal characters".into(),
                );
            };
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PackageInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = [0_u8; Self::HEX_LEN];
        for (index, byte) in self.0.iter().copied().enumerate() {
            output[index * 2] = HEX[usize::from(byte >> 4)];
            output[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        let encoded = std::str::from_utf8(&output).map_err(|_| fmt::Error)?;
        formatter.write_str(encoded)
    }
}

impl Serialize for PackageInstanceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PackageInstanceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_instance_id_changes_with_exact_graph_path() {
        let left = PackageInstanceId::derive("plugin", "1.0.0", "registry+npm", "root/a");
        let right = PackageInstanceId::derive("plugin", "1.0.0", "registry+npm", "root/b");

        assert_ne!(left, right);
        assert!(PackageInstanceId::parse(&left.to_string()).is_ok());
        assert!(PackageInstanceId::parse(&left.to_string().to_uppercase()).is_err());
    }

    #[test]
    fn rebased_source_identity_preserves_context_and_changes_with_source() {
        let original = PackageInstanceId::derive(
            "workspace-lib",
            "1.0.0",
            "directory+packages/workspace-lib",
            "root/workspace-lib",
        );
        let rebased = original.rebase_source(
            "workspace-lib",
            "1.0.0",
            "directory+../packages/workspace-lib",
        );

        assert_ne!(rebased, original);
        assert_eq!(
            rebased,
            original.rebase_source(
                "workspace-lib",
                "1.0.0",
                "directory+../packages/workspace-lib",
            )
        );
        assert_ne!(
            rebased,
            original.rebase_source("workspace-lib", "1.0.0", "directory+.")
        );
    }
}
