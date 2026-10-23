//! Backup files of env projects, protected by a passphrase, which the LPM
//! Vault app and the CLI write and read alike.
//!
//! A file is an 80-byte header, then the payload encrypted with
//! XChaCha20-Poly1305 under a key Argon2id derives from the passphrase.
//! Every integer is big-endian:
//!
//! | Offset | Bytes | Field |
//! |---|---|---|
//! | 0 | 8 | `LPMBKUP\0` |
//! | 8 | 2 | format version, 1 |
//! | 10 | 1 | key derivation, 1: Argon2id v0x13, 256 MiB, 3 passes, 1 lane |
//! | 11 | 1 | cipher, 1: XChaCha20-Poly1305 |
//! | 12 | 4 | reserved, zero |
//! | 16 | 32 | salt |
//! | 48 | 24 | nonce |
//! | 72 | 8 | length of what follows: ciphertext and 16-byte tag |
//!
//! The header is the associated data, so changing any of it fails
//! decryption. The plaintext is the payload's length as 8 bytes, the
//! payload, then zeros up to the next multiple of 64 KiB, so a file's size
//! shows little about what it holds. Files are at most 64 MiB. A file
//! whose header can't be a readable backup fails before the key is derived.
//!
//! [`payload`] describes what a version 1 payload holds. [`open`] returns the
//! whole plaintext, so a caller can hand the payload on without copying it.
//! The key derivation's memory, the key and every plaintext buffer are wiped
//! when freed; the copies zxcvbn makes of a passphrase aren't, unless the
//! program installs [`WipingAllocator`], as the LPM env engine does.

mod container;
#[cfg(test)]
mod freed_memory_probe;
pub mod passphrase;
pub mod payload;
pub mod wiping_allocator;

use std::ops::Range;

use zeroize::Zeroizing;

pub use container::{
    ContainerError, FORMAT_VERSION, FileInfo, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES, PAYLOAD_OFFSET,
    inspect,
};
pub use passphrase::{GenerateError, Passphrase, PassphraseError, Strength};
pub use payload::{PayloadError, PayloadErrorKind};
pub use wiping_allocator::WipingAllocator;

/// Why a backup couldn't be sealed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SealError {
    /// The passphrase is below [`passphrase::MIN_GUESSES_LOG10`].
    WeakPassphrase(Strength),
    Payload(PayloadError),
    Container(ContainerError),
}

/// Why a backup couldn't be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    Container(ContainerError),
    /// It decrypted, but its payload isn't a valid backup.
    Payload(PayloadError),
}

/// Checks `payload` and the passphrase's strength, then encrypts the
/// payload into a backup file.
pub fn seal(payload: &[u8], passphrase: &Passphrase) -> Result<Vec<u8>, SealError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(SealError::Container(ContainerError::TooLarge));
    }
    let strength = passphrase.strength();
    if !strength.acceptable {
        return Err(SealError::WeakPassphrase(strength));
    }
    payload::validate(payload).map_err(SealError::Payload)?;
    container::seal(payload, passphrase).map_err(SealError::Container)
}

/// A backup's checked payload, inside its decrypted plaintext, which is wiped
/// when dropped.
pub struct OpenedBackup(container::Plaintext);

impl OpenedBackup {
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }

    /// The whole plaintext, in an allocation exactly its length, and where
    /// the payload is in it, for a caller that releases it later.
    pub fn into_plaintext(self) -> (Zeroizing<Vec<u8>>, Range<usize>) {
        let range = PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.0.payload_len;
        (self.0.bytes, range)
    }
}

/// Decrypts a backup file and checks its payload. The passphrase's strength
/// isn't checked again.
pub fn open(file: &[u8], passphrase: &Passphrase) -> Result<OpenedBackup, OpenError> {
    let plaintext = container::open(file, passphrase).map_err(OpenError::Container)?;
    payload::validate(plaintext.payload()).map_err(OpenError::Payload)?;
    Ok(OpenedBackup(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: &[u8] = br#"{"createdAt":1761171075,"producer":{"name":"LPM Vault","version":"1.4.0"},"projects":[{"vaultId":"v1","name":"demo","hidden":false,"cliAccess":"automatic","environments":{"default":{"API_KEY":"sk_test_value"}}}]}"#;

    fn strong() -> Passphrase {
        Passphrase::new(b"harbor velvet ninety cactus orbit maple").expect("passphrase")
    }

    #[test]
    fn a_valid_payload_round_trips_through_a_file() {
        let file = seal(PAYLOAD, &strong()).expect("seal");
        assert_eq!(
            inspect(&file).expect("inspect").format_version,
            FORMAT_VERSION
        );
        assert_eq!(open(&file, &strong()).expect("open").payload(), PAYLOAD);
    }

    #[test]
    fn sealing_refuses_a_weak_passphrase_before_reading_the_payload() {
        let weak = Passphrase::new(b"password123").expect("passphrase");
        assert!(matches!(
            seal(b"not even json", &weak),
            Err(SealError::WeakPassphrase(strength)) if !strength.acceptable
        ));
    }

    #[test]
    fn sealing_refuses_an_invalid_payload() {
        assert!(matches!(
            seal(b"{}", &strong()),
            Err(SealError::Payload(PayloadError {
                kind: PayloadErrorKind::Structure,
                ..
            }))
        ));
    }

    #[test]
    fn checking_or_opening_a_backup_leaves_no_secret_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        let secret = std::str::from_utf8(MARKER).expect("ASCII");
        let head = r#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":"#;
        let with_project = |fields: &str| {
            format!(
                r#"{head}[{{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic",{fields}}}]}}"#
            )
        };
        // Escapes would make a decoding parser copy the string to decode it.
        let value = format!(r#"{secret}\n\"quoted\"\u0041"#);
        let cases: Vec<String> = vec![
            with_project(&format!(
                r#""environments":{{"default":{{"A":"{value}","B":"{secret}"}}}}"#
            )),
            with_project(&format!(r#""environments":{{"default":"{value}"}}"#)),
            with_project(&format!(
                r#""environments":{{"default":{{"A":["{value}"]}}}}"#
            )),
            with_project(&format!(r#""environments":{{}},"sync":"{value}""#)),
            with_project(&format!(
                r#""environments":{{}},"sync":{{"registry":"https://lpm.dev","scope":"{value}","principalId":"u"}}"#
            )),
            format!(
                r#"{{"createdAt":"{value}","producer":{{"name":"a","version":"1"}},"projects":[]}}"#
            ),
            format!(r#"{{"createdAt":0,"producer":"{value}","projects":[]}}"#),
            format!(r#"{head}"{value}"}}"#),
            format!(r#"{head}["{value}"]}}"#),
            format!(
                r#"{head}[{{"vaultId":"v","name":"n","hidden":"{value}","cliAccess":"automatic","environments":{{}}}}]}}"#
            ),
            format!(
                r#"{head}[{{"vaultId":"v","name":"n","hidden":false,"cliAccess":"{value}","environments":{{}}}}]}}"#
            ),
        ];
        assert_eq!(payload::validate(cases[0].as_bytes()), Ok(()));
        for (index, case) in cases.iter().enumerate() {
            let mut result = Ok(());
            let leaked = watch(|| result = payload::validate(case.as_bytes()));
            assert!(!leaked, "case {index} left the secret in freed memory");
            assert!(
                index == 0 || result.is_err_and(|error| error.kind != PayloadErrorKind::Syntax),
                "case {index} must be read, then refused: {result:?}"
            );
        }
        let file = seal(cases[0].as_bytes(), &strong()).expect("seal");
        let leaked = watch(|| {
            let opened = open(&file, &strong()).expect("open");
            drop(opened);
        });
        assert!(!leaked, "opening left the secret in freed memory");
    }

    #[test]
    fn zxcvbn_frees_copies_of_a_passphrase_that_the_wiping_allocator_zeroes() {
        use crate::freed_memory_probe::{MARKER, watch_wiping};
        let passphrase = Passphrase::new(MARKER).expect("passphrase");
        let (held, left) = watch_wiping(|| {
            let _ = passphrase.strength();
        });
        assert!(held, "zxcvbn frees blocks holding the passphrase");
        assert!(!left, "none of them still holds it once wiped");
    }

    #[test]
    fn sealing_refuses_a_payload_written_as_positional_lists() {
        assert!(matches!(
            seal(br#"[0,["lpm","1"],null,[],null]"#, &strong()),
            Err(SealError::Payload(PayloadError {
                kind: PayloadErrorKind::Structure,
                ..
            }))
        ));
    }

    #[test]
    fn opening_with_a_weak_passphrase_is_allowed_because_strength_is_checked_only_when_sealing() {
        let file = seal(PAYLOAD, &strong()).expect("seal");
        let typo = Passphrase::new(b"a").expect("passphrase");
        assert_eq!(
            open(&file, &typo).err(),
            Some(OpenError::Container(ContainerError::WrongPassphrase))
        );
    }

    #[test]
    fn opening_a_file_whose_payload_is_invalid_reports_the_payload() {
        let file = container::seal(b"{\"createdAt\":0}", &strong()).expect("seal");
        assert!(matches!(
            open(&file, &strong()),
            Err(OpenError::Payload(PayloadError {
                kind: PayloadErrorKind::Structure,
                ..
            }))
        ));
    }
}
