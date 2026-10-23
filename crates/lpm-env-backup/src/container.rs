//! The file around a backup's payload: a fixed header, then the payload
//! encrypted with a key derived from the passphrase.

use std::sync::Mutex;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::passphrase::Passphrase;

pub(crate) const MAGIC: [u8; 8] = *b"LPMBKUP\0";
/// The format version this crate writes and the only one it reads.
pub const FORMAT_VERSION: u16 = 1;
pub(crate) const HEADER_LEN: usize = 80;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const LENGTH_PREFIX_LEN: usize = 8;
const PADDING_UNIT: usize = 64 * 1024;
/// Argon2id v0x13, 256 MiB, three passes, one lane.
const KDF_PROFILE: u8 = 1;
/// XChaCha20-Poly1305.
const AEAD: u8 = 1;
const KDF_MEMORY_KIB: u32 = 256 * 1024;
const KDF_PASSES: u32 = 3;
const KDF_LANES: u32 = 1;

/// The largest backup file written or read.
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize =
    (MAX_FILE_BYTES - HEADER_LEN - TAG_LEN) / PADDING_UNIT * PADDING_UNIT;
/// The largest payload a backup file holds.
pub const MAX_PAYLOAD_BYTES: usize = MAX_PLAINTEXT_BYTES - LENGTH_PREFIX_LEN;
const _: () = assert!(
    MAX_PLAINTEXT_BYTES.is_multiple_of(PADDING_UNIT)
        && HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN <= MAX_FILE_BYTES
        && HEADER_LEN + MAX_PLAINTEXT_BYTES + PADDING_UNIT + TAG_LEN > MAX_FILE_BYTES
);

/// Each derivation holds 256 MiB, so they run one at a time.
static KDF_PERMIT: Mutex<()> = Mutex::new(());

/// What a file's header says before anything is decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo {
    pub format_version: u16,
}

/// Why a file couldn't be read as a backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerError {
    /// Over [`MAX_FILE_BYTES`].
    TooLarge,
    /// It doesn't start like a backup.
    NotABackup,
    /// It starts like a backup this crate can't read.
    NewerFormat { format_version: u16 },
    /// Truncated, extended, or with a malformed header.
    Damaged,
    /// The passphrase doesn't open it, or it was changed.
    WrongPassphrase,
    /// It opened, but what it holds isn't laid out as a backup's is.
    InvalidPlaintext,
    /// The memory for the key derivation couldn't be reserved.
    OutOfMemory,
    /// The system's random source failed.
    Random,
}

struct Header {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    fn encode(&self, ciphertext_len: usize) -> [u8; HEADER_LEN] {
        let mut header = [0_u8; HEADER_LEN];
        header[..8].copy_from_slice(&MAGIC);
        header[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        header[10] = KDF_PROFILE;
        header[11] = AEAD;
        header[16..48].copy_from_slice(&self.salt);
        header[48..72].copy_from_slice(&self.nonce);
        header[72..80].copy_from_slice(&(ciphertext_len as u64).to_be_bytes());
        header
    }

    /// Checks everything the header and the file's length can show, so a
    /// file that can't be a readable backup fails before the derivation.
    fn decode(file: &[u8]) -> Result<Self, ContainerError> {
        if file.len() > MAX_FILE_BYTES {
            return Err(ContainerError::TooLarge);
        }
        if file.len() < MAGIC.len() || file[..MAGIC.len()] != MAGIC {
            return Err(ContainerError::NotABackup);
        }
        if file.len() < HEADER_LEN {
            return Err(ContainerError::Damaged);
        }
        let format_version = u16::from_be_bytes([file[8], file[9]]);
        if format_version == 0 {
            return Err(ContainerError::Damaged);
        }
        if format_version != FORMAT_VERSION || file[10] != KDF_PROFILE || file[11] != AEAD {
            return Err(ContainerError::NewerFormat { format_version });
        }
        if file[12..16] != [0; 4] {
            return Err(ContainerError::Damaged);
        }
        let declared = u64::from_be_bytes(file[72..80].try_into().expect("eight bytes"));
        let ciphertext_len = file.len() - HEADER_LEN;
        let plaintext_len = ciphertext_len.checked_sub(TAG_LEN);
        if declared != ciphertext_len as u64
            || plaintext_len
                .is_none_or(|length| length == 0 || !length.is_multiple_of(PADDING_UNIT))
        {
            return Err(ContainerError::Damaged);
        }
        Ok(Self {
            salt: file[16..48].try_into().expect("salt bytes"),
            nonce: file[48..72].try_into().expect("nonce bytes"),
        })
    }
}

/// Reads a file's header without the passphrase.
pub fn inspect(file: &[u8]) -> Result<FileInfo, ContainerError> {
    Header::decode(file).map(|_| FileInfo {
        format_version: FORMAT_VERSION,
    })
}

/// Encrypts `payload` into a backup file. The caller has already checked
/// what the payload holds and that the passphrase is strong enough.
pub(crate) fn seal(payload: &[u8], passphrase: &Passphrase) -> Result<Vec<u8>, ContainerError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ContainerError::TooLarge);
    }
    let mut random = Zeroizing::new([0_u8; SALT_LEN + NONCE_LEN]);
    getrandom::fill(random.as_mut()).map_err(|_| ContainerError::Random)?;
    let header = Header {
        salt: random[..SALT_LEN].try_into().expect("salt bytes"),
        nonce: random[SALT_LEN..].try_into().expect("nonce bytes"),
    };
    seal_with(payload, passphrase, &header)
}

fn seal_with(
    payload: &[u8],
    passphrase: &Passphrase,
    header: &Header,
) -> Result<Vec<u8>, ContainerError> {
    let plaintext_len = (LENGTH_PREFIX_LEN + payload.len()).div_ceil(PADDING_UNIT) * PADDING_UNIT;
    let key = derive_key(passphrase, &header.salt)?;
    let total = HEADER_LEN + plaintext_len + TAG_LEN;
    let mut file = Zeroizing::new(Vec::with_capacity(total));
    file.extend_from_slice(&header.encode(plaintext_len + TAG_LEN));
    file.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    file.extend_from_slice(payload);
    file.resize(HEADER_LEN + plaintext_len, 0);
    let (aad, plaintext) = file.split_at_mut(HEADER_LEN);
    let tag = cipher(&key)
        .encrypt_in_place_detached(XNonce::from_slice(&header.nonce), aad, plaintext)
        .expect("plaintexts within the file cap are far below the cipher's limit");
    file.extend_from_slice(&tag);
    debug_assert_eq!(file.len(), file.capacity());
    Ok(std::mem::take(&mut *file))
}

/// Where the payload starts in a backup's plaintext, after its length.
pub const PAYLOAD_OFFSET: usize = LENGTH_PREFIX_LEN;

/// A backup's decrypted plaintext, in an allocation exactly its length, and
/// the length of the payload at [`PAYLOAD_OFFSET`] in it.
pub(crate) struct Plaintext {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    pub(crate) payload_len: usize,
}

impl Plaintext {
    pub(crate) fn payload(&self) -> &[u8] {
        &self.bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.payload_len]
    }
}

/// Decrypts a backup file and returns its plaintext, whose payload the
/// caller checks.
pub(crate) fn open(file: &[u8], passphrase: &Passphrase) -> Result<Plaintext, ContainerError> {
    let header = Header::decode(file)?;
    let key = derive_key(passphrase, &header.salt)?;
    let (ciphertext, tag) = file[HEADER_LEN..].split_at(file.len() - HEADER_LEN - TAG_LEN);
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher(&key)
        .decrypt_in_place_detached(
            XNonce::from_slice(&header.nonce),
            &file[..HEADER_LEN],
            plaintext.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| ContainerError::WrongPassphrase)?;

    let declared = u64::from_be_bytes(plaintext[..LENGTH_PREFIX_LEN].try_into().expect("eight"));
    let payload_len = usize::try_from(declared)
        .ok()
        .filter(|length| *length <= plaintext.len() - LENGTH_PREFIX_LEN)
        .ok_or(ContainerError::InvalidPlaintext)?;
    let padded = (LENGTH_PREFIX_LEN + payload_len).div_ceil(PADDING_UNIT) * PADDING_UNIT;
    if padded != plaintext.len()
        || plaintext[LENGTH_PREFIX_LEN + payload_len..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ContainerError::InvalidPlaintext);
    }
    debug_assert_eq!(plaintext.len(), plaintext.capacity());
    Ok(Plaintext {
        bytes: plaintext,
        payload_len,
    })
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("keys are 32 bytes")
}

fn derive_key(
    passphrase: &Passphrase,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, ContainerError> {
    #[cfg(test)]
    tests::DERIVATIONS.with(|count| count.set(count.get() + 1));
    let params = kdf_params();
    let _permit = KDF_PERMIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Argon2 leaves its working memory as it was, and the last blocks lead
    // straight to the key, so the memory is owned here and wiped on drop.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| ContainerError::OutOfMemory)?;
    memory.resize(params.block_count(), Block::default());
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            passphrase.as_bytes(),
            salt,
            key.as_mut(),
            memory.as_mut_slice(),
        )
        .expect("the parameters, salt, key and memory sizes are fixed and valid");
    Ok(key)
}

fn kdf_params() -> Params {
    #[cfg(test)]
    if tests::cheap_kdf() {
        return Params::new(64, 1, KDF_LANES, Some(32)).expect("test parameters are valid");
    }
    Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, Some(32))
        .expect("profile 1 parameters are valid")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::cell::Cell;

    thread_local! {
        static CHEAP_KDF: Cell<bool> = const { Cell::new(true) };
        pub(super) static DERIVATIONS: Cell<usize> = const { Cell::new(0) };
    }

    fn derivations() -> usize {
        DERIVATIONS.with(Cell::get)
    }

    /// Unit tests derive keys at a tiny cost unless they ask for profile 1,
    /// which the known-answer test pins.
    pub(crate) fn cheap_kdf() -> bool {
        CHEAP_KDF.with(Cell::get)
    }

    /// The expected bytes were computed independently, with libsodium's
    /// XChaCha20-Poly1305 and the reference Argon2.
    #[test]
    fn profile_one_matches_its_known_answer() {
        CHEAP_KDF.with(|cheap| cheap.set(false));
        let passphrase = passphrase();
        let header = Header {
            salt: std::array::from_fn(|index| index as u8),
            nonce: std::array::from_fn(|index| 0xA0 + index as u8),
        };
        let payload = br#"{"createdAt":0}"#;
        let file = seal_with(payload, &passphrase, &header).expect("seal");
        assert_eq!(
            hex(&Sha256::digest(&file)),
            "d0cbac7a16fba56bbad5e785311737ac0039c9d2499e992c6bd3541f72950d8b"
        );
        assert_eq!(open(&file, &passphrase).expect("open").payload(), payload);
        let key = derive_key(&passphrase, &header.salt).expect("key");
        assert_eq!(
            hex(key.as_ref()),
            "b5e8790883c41ea94e99e11c4347dececf81661894ce776618f9465c81fad616"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn passphrase() -> Passphrase {
        Passphrase::new(b"harbor velvet ninety cactus orbit maple").expect("passphrase")
    }

    #[test]
    fn a_sealed_file_opens_with_its_passphrase_and_returns_the_payload() {
        let payload = br#"{"anything":"the caller checks"}"#;
        let file = seal(payload, &passphrase()).expect("seal");
        assert_eq!(file.len(), HEADER_LEN + PADDING_UNIT + TAG_LEN);
        assert_eq!(&file[..8], b"LPMBKUP\0");
        assert_eq!(&file[8..12], &[0, 1, 1, 1]);
        assert_eq!(&file[12..16], &[0; 4]);
        assert_eq!(
            inspect(&file),
            Ok(FileInfo {
                format_version: FORMAT_VERSION
            })
        );
        assert_eq!(open(&file, &passphrase()).expect("open").payload(), payload);
    }

    #[test]
    fn padding_hides_the_payload_length_to_the_next_64_kib() {
        let passphrase = passphrase();
        let small = seal(b"{}", &passphrase).expect("seal");
        let exact = seal(&vec![b' '; PADDING_UNIT - LENGTH_PREFIX_LEN], &passphrase).expect("seal");
        let over = seal(
            &vec![b' '; PADDING_UNIT - LENGTH_PREFIX_LEN + 1],
            &passphrase,
        )
        .expect("seal");
        assert_eq!(small.len(), exact.len());
        assert_eq!(over.len(), small.len() + PADDING_UNIT);
        assert_eq!(
            open(&exact, &passphrase).expect("open").payload().len(),
            PADDING_UNIT - 8
        );
    }

    #[test]
    fn two_seals_of_one_payload_differ_in_salt_nonce_and_ciphertext() {
        let first = seal(b"{}", &passphrase()).expect("seal");
        let second = seal(b"{}", &passphrase()).expect("seal");
        assert_ne!(first[16..48], second[16..48]);
        assert_ne!(first[48..72], second[48..72]);
        assert_ne!(first[HEADER_LEN..], second[HEADER_LEN..]);
    }

    #[test]
    fn another_passphrase_fails_as_wrong_passphrase() {
        let file = seal(b"{}", &passphrase()).expect("seal");
        let other = Passphrase::new(b"harbor velvet ninety cactus orbit maples").expect("other");
        assert_eq!(
            open(&file, &other).err(),
            Some(ContainerError::WrongPassphrase)
        );
    }

    #[test]
    fn any_changed_byte_after_the_reserved_field_fails_authentication() {
        let file = seal(b"{}", &passphrase()).expect("seal");
        for index in [16, 47, 48, 71, HEADER_LEN, HEADER_LEN + 9, file.len() - 1] {
            let mut changed = file.clone();
            changed[index] ^= 0x01;
            assert_eq!(
                open(&changed, &passphrase()).err(),
                Some(ContainerError::WrongPassphrase),
                "byte {index}"
            );
        }
    }

    #[test]
    fn structural_problems_are_reported_before_any_key_is_derived() {
        let file = seal(b"{}", &passphrase()).expect("seal");
        let cases: [(Vec<u8>, ContainerError); 9] = [
            (Vec::new(), ContainerError::NotABackup),
            (b"LPMBKUP".to_vec(), ContainerError::NotABackup),
            (b"PK\x03\x04 a zip".to_vec(), ContainerError::NotABackup),
            (file[..HEADER_LEN - 1].to_vec(), ContainerError::Damaged),
            (file[..file.len() - 1].to_vec(), ContainerError::Damaged),
            ([file.as_slice(), b"\0"].concat(), ContainerError::Damaged),
            (with_byte(&file, 12, 1), ContainerError::Damaged),
            (with_byte(&file, 9, 0), ContainerError::Damaged),
            (with_byte(&file, 79, 0), ContainerError::Damaged),
        ];
        for (bytes, expected) in cases {
            assert_eq!(inspect(&bytes).err(), Some(expected));
        }
        let header_only = with_length(&file[..HEADER_LEN + TAG_LEN], TAG_LEN as u64);
        assert_eq!(inspect(&header_only).err(), Some(ContainerError::Damaged));
    }

    #[test]
    fn opening_a_structurally_bad_file_never_derives_a_key() {
        let file = seal(b"{}", &passphrase()).expect("seal");
        let before = derivations();
        for bytes in [
            Vec::new(),
            b"PK\x03\x04 a zip".to_vec(),
            file[..HEADER_LEN - 1].to_vec(),
            file[..file.len() - 1].to_vec(),
            [file.as_slice(), b"\0"].concat(),
            with_byte(&file, 12, 1),
            with_byte(&file, 9, 2),
            vec![0_u8; MAX_FILE_BYTES + 1],
        ] {
            assert!(open(&bytes, &passphrase()).is_err());
        }
        assert_eq!(derivations(), before);
        assert!(open(&file, &passphrase()).is_ok());
        assert_eq!(derivations(), before + 1);
    }

    #[test]
    fn a_later_version_profile_or_cipher_reads_as_a_newer_format() {
        let file = seal(b"{}", &passphrase()).expect("seal");
        for (index, value, format_version) in [(9, 2, 2), (10, 2, 1), (11, 2, 1)] {
            assert_eq!(
                inspect(&with_byte(&file, index, value)).err(),
                Some(ContainerError::NewerFormat { format_version })
            );
        }
    }

    #[test]
    fn a_file_over_the_cap_is_refused_before_its_header_is_read() {
        let oversized = vec![0_u8; MAX_FILE_BYTES + 1];
        assert_eq!(inspect(&oversized).err(), Some(ContainerError::TooLarge));
        assert_eq!(
            seal(&vec![b' '; MAX_PAYLOAD_BYTES + 1], &passphrase()).err(),
            Some(ContainerError::TooLarge)
        );
    }

    #[test]
    fn the_largest_payload_seals_within_the_cap_and_opens_again() {
        let payload = vec![b' '; MAX_PAYLOAD_BYTES];
        let file = seal(&payload, &passphrase()).expect("seal");
        assert!(file.len() <= MAX_FILE_BYTES);
        assert_eq!(
            open(&file, &passphrase()).expect("open").payload().len(),
            MAX_PAYLOAD_BYTES
        );
    }

    #[test]
    fn a_misdeclared_length_or_nonzero_padding_is_rejected_after_authentication() {
        let key_passphrase = passphrase();
        for (declared, padding) in [(u64::MAX, 0_u8), (PADDING_UNIT as u64, 0), (2, 1)] {
            let file = seal_raw(declared, b"{}", padding, &key_passphrase);
            assert_eq!(
                open(&file, &key_passphrase).err(),
                Some(ContainerError::InvalidPlaintext),
                "declared {declared} padding {padding}"
            );
        }
        let oversized_padding = {
            let mut plaintext = vec![0_u8; 2 * PADDING_UNIT];
            plaintext[..8].copy_from_slice(&2_u64.to_be_bytes());
            plaintext[8..10].copy_from_slice(b"{}");
            encrypt_plaintext(plaintext, &key_passphrase)
        };
        assert_eq!(
            open(&oversized_padding, &key_passphrase).err(),
            Some(ContainerError::InvalidPlaintext)
        );
    }

    fn with_byte(file: &[u8], index: usize, value: u8) -> Vec<u8> {
        let mut changed = file.to_vec();
        changed[index] = value;
        changed
    }

    fn with_length(file: &[u8], length: u64) -> Vec<u8> {
        let mut changed = file.to_vec();
        changed[72..80].copy_from_slice(&length.to_be_bytes());
        changed
    }

    fn seal_raw(declared: u64, payload: &[u8], padding: u8, passphrase: &Passphrase) -> Vec<u8> {
        let mut plaintext = vec![padding; PADDING_UNIT];
        plaintext[..8].copy_from_slice(&declared.to_be_bytes());
        plaintext[8..8 + payload.len()].copy_from_slice(payload);
        encrypt_plaintext(plaintext, passphrase)
    }

    fn encrypt_plaintext(mut plaintext: Vec<u8>, passphrase: &Passphrase) -> Vec<u8> {
        let header = Header {
            salt: [7; SALT_LEN],
            nonce: [9; NONCE_LEN],
        };
        let key = derive_key(passphrase, &header.salt).expect("key");
        let encoded = header.encode(plaintext.len() + TAG_LEN);
        let tag = cipher(&key)
            .encrypt_in_place_detached(
                XNonce::from_slice(&header.nonce),
                &encoded,
                plaintext.as_mut_slice(),
            )
            .expect("encrypt");
        [encoded.as_slice(), &plaintext, &tag].concat()
    }
}
