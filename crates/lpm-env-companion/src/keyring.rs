//! The key record that history and releases share, the envelope their parts
//! are sealed in, and the keyed digests history compares values by.
//!
//! ```text
//! key record = "LPMK" ‖ u8 version=1 ‖ u8 state (0 stable, 1 rotating)
//!              ‖ u8 approvalAtGeneration (0 automatic, 1 protected, 2 file store)
//!              ‖ digest secret [32]
//!              ‖ current: key id [16] ‖ u32be generation ‖ key [32]
//!              ‖ pending, only while rotating: key id [16] ‖ u32be generation ‖ key [32]
//!
//! header     = "LPMC" ‖ u8 version=1 ‖ u8 algorithm=1 (XChaCha20-Poly1305)
//!              ‖ key id [16] ‖ u32be generation
//! part       = header ‖ nonce [24] ‖ ciphertext ‖ tag [16]
//! associated = "lpm-vault-companion-part\x01" ‖ header ‖ u16be len ‖ vault id
//!              ‖ u8 len ‖ kind ‖ u16be part ‖ u16be schemaVersion
//! ```
//!
//! Key material lives only in [`Zeroizing`] buffers sized up front, since
//! the CLI's allocator doesn't wipe what it frees.

use std::fmt;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::marker::MAX_RECORD_BYTES;

pub const KEY_RECORD_MAGIC: [u8; 4] = *b"LPMK";
pub const KEY_RECORD_VERSION: u8 = 1;
pub const STABLE_KEY_RECORD_BYTES: usize = 91;
pub const ROTATING_KEY_RECORD_BYTES: usize = 143;

pub const ENVELOPE_MAGIC: [u8; 4] = *b"LPMC";
pub const ENVELOPE_VERSION: u8 = 1;
pub const ENVELOPE_ALGORITHM_XCHACHA20_POLY1305: u8 = 1;
const HEADER_BYTES: usize = 26;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// What the envelope adds to a part's plaintext.
pub const ENVELOPE_OVERHEAD: usize = HEADER_BYTES + NONCE_BYTES + TAG_BYTES;
/// The largest plaintext a part can seal and still fit one record.
pub const PART_CAPACITY: usize = MAX_RECORD_BYTES - ENVELOPE_OVERHEAD;

const KEY_BYTES: usize = 32;
const SLOT_BYTES: usize = 16 + 4 + KEY_BYTES;
const ASSOCIATED_DATA_LABEL: &[u8] = b"lpm-vault-companion-part\x01";
const DIGEST_SALT: &[u8] = b"lpm-vault-history-digest\x01";
const PLACE_SALT: &[u8] = b"lpm-vault-history-place\x01";

/// The first 16 bytes of an HMAC-SHA256 under one of a project's digest keys.
pub type Digest = [u8; 16];
pub type KeyId = [u8; 16];

/// Where random bytes come from: the system, or a fixed sequence in tests
/// and exported fixtures.
pub trait Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the system's random number generator failed")
    }
}

/// The operating system's random number generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandom;

impl Random for SystemRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(bytes).map_err(|_| RandomError)
    }
}

/// The values item's verified access when a key was generated. A key made
/// while approval was off could be read without approval, so turning
/// approval on rotates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Approval {
    Automatic,
    Protected,
    /// The Linux and Windows file store, which has no approval.
    FileStore,
}

impl Approval {
    fn byte(self) -> u8 {
        match self {
            Self::Automatic => 0,
            Self::Protected => 1,
            Self::FileStore => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Automatic),
            1 => Some(Self::Protected),
            2 => Some(Self::FileStore),
            _ => None,
        }
    }
}

/// One key of a key record.
pub struct KeySlot {
    id: KeyId,
    generation: u32,
    key: Zeroizing<[u8; KEY_BYTES]>,
}

impl KeySlot {
    fn generate(generation: u32, random: &mut impl Random) -> Result<Self, RandomError> {
        let mut id = [0_u8; 16];
        random.fill(&mut id)?;
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        random.fill(key.as_mut())?;
        Ok(Self {
            id,
            generation,
            key,
        })
    }

    pub fn id(&self) -> KeyId {
        self.id
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    fn decode(bytes: &[u8]) -> Self {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        key.copy_from_slice(&bytes[20..SLOT_BYTES]);
        Self {
            id: bytes[..16].try_into().expect("sixteen bytes"),
            generation: u32::from_be_bytes(bytes[16..20].try_into().expect("four bytes")),
            key,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(self.key.as_ref());
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.key.as_ref()).expect("keys are 32 bytes")
    }
}

impl fmt::Debug for KeySlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeySlot")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Why a key record can't be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRecordError {
    Length,
    Magic,
    UnknownVersion,
    UnknownState,
    UnknownApproval,
    /// A generation of 0, or a pending key that isn't the next generation.
    Generation,
    /// A pending key with the current key's ID.
    RepeatedKeyId,
}

impl fmt::Display for KeyRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Length => "the history key record has the wrong length",
            Self::Magic => "the history key record isn't a key record",
            Self::UnknownVersion => "the history key record's version is unknown",
            Self::UnknownState => "the history key record's state is unknown",
            Self::UnknownApproval => "the history key record's approval is unknown",
            Self::Generation => "the history key record's generations are inconsistent",
            Self::RepeatedKeyId => "the history key record repeats a key ID",
        })
    }
}

/// Why a key can't rotate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    AlreadyRotating,
    NotRotating,
    /// The current key is at generation `u32::MAX`, after which none follows.
    GenerationExhausted,
    Random,
}

impl fmt::Display for RotationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyRotating => "the history key is already rotating",
            Self::NotRotating => "the history key isn't rotating",
            Self::GenerationExhausted => {
                "the history key can't rotate any more. Turn history off and on to start a new history"
            }
            Self::Random => "the system's random number generator failed",
        })
    }
}

/// The `key` record: a digest secret that never rotates, the current key,
/// and while a rotation runs, the key replacing it.
pub struct KeyRecord {
    approval_at_generation: Approval,
    digest_secret: Zeroizing<[u8; KEY_BYTES]>,
    current: KeySlot,
    pending: Option<KeySlot>,
}

impl fmt::Debug for KeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyRecord")
            .field("approval_at_generation", &self.approval_at_generation)
            .field("current", &self.current)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl KeyRecord {
    /// A new record at generation 1 with a new digest secret.
    pub fn generate(approval: Approval, random: &mut impl Random) -> Result<Self, RandomError> {
        let mut digest_secret = Zeroizing::new([0_u8; KEY_BYTES]);
        random.fill(digest_secret.as_mut())?;
        Ok(Self {
            approval_at_generation: approval,
            digest_secret,
            current: KeySlot::generate(1, random)?,
            pending: None,
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KeyRecordError> {
        if bytes.len() != STABLE_KEY_RECORD_BYTES && bytes.len() != ROTATING_KEY_RECORD_BYTES {
            return Err(KeyRecordError::Length);
        }
        if bytes[..4] != KEY_RECORD_MAGIC {
            return Err(KeyRecordError::Magic);
        }
        if bytes[4] != KEY_RECORD_VERSION {
            return Err(KeyRecordError::UnknownVersion);
        }
        let rotating = match bytes[5] {
            0 => false,
            1 => true,
            _ => return Err(KeyRecordError::UnknownState),
        };
        let expected = if rotating {
            ROTATING_KEY_RECORD_BYTES
        } else {
            STABLE_KEY_RECORD_BYTES
        };
        if bytes.len() != expected {
            return Err(KeyRecordError::Length);
        }
        let approval_at_generation =
            Approval::from_byte(bytes[6]).ok_or(KeyRecordError::UnknownApproval)?;
        let mut digest_secret = Zeroizing::new([0_u8; KEY_BYTES]);
        digest_secret.copy_from_slice(&bytes[7..39]);
        let current = KeySlot::decode(&bytes[39..39 + SLOT_BYTES]);
        if current.generation == 0 {
            return Err(KeyRecordError::Generation);
        }
        let pending = if rotating {
            let pending = KeySlot::decode(&bytes[39 + SLOT_BYTES..]);
            if current.generation.checked_add(1) != Some(pending.generation) {
                return Err(KeyRecordError::Generation);
            }
            if pending.id == current.id {
                return Err(KeyRecordError::RepeatedKeyId);
            }
            Some(pending)
        } else {
            None
        };
        Ok(Self {
            approval_at_generation,
            digest_secret,
            current,
            pending,
        })
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let length = if self.pending.is_some() {
            ROTATING_KEY_RECORD_BYTES
        } else {
            STABLE_KEY_RECORD_BYTES
        };
        let mut out = Zeroizing::new(Vec::with_capacity(length));
        out.extend_from_slice(&KEY_RECORD_MAGIC);
        out.push(KEY_RECORD_VERSION);
        out.push(u8::from(self.pending.is_some()));
        out.push(self.approval_at_generation.byte());
        out.extend_from_slice(self.digest_secret.as_ref());
        self.current.encode_into(&mut out);
        if let Some(pending) = &self.pending {
            pending.encode_into(&mut out);
        }
        debug_assert_eq!(out.len(), length);
        out
    }

    pub fn is_rotating(&self) -> bool {
        self.pending.is_some()
    }

    /// The access the current key was generated under, or while rotating,
    /// the access the pending key was.
    pub fn approval_at_generation(&self) -> Approval {
        self.approval_at_generation
    }

    /// Record that the current key's access is `approval` without a new key,
    /// as a client does when the values item's access was lowered, so that
    /// raising it again rotates.
    pub fn set_approval_at_generation(&mut self, approval: Approval) {
        self.approval_at_generation = approval;
    }

    pub fn current(&self) -> &KeySlot {
        &self.current
    }

    pub fn pending(&self) -> Option<&KeySlot> {
        self.pending.as_ref()
    }

    /// The key new parts are sealed with: the pending key while rotating.
    pub fn sealing_key(&self) -> &KeySlot {
        self.pending.as_ref().unwrap_or(&self.current)
    }

    /// The key a part sealed under `id` opens with.
    pub fn key(&self, id: &KeyId) -> Option<&KeySlot> {
        std::iter::once(&self.current)
            .chain(self.pending.as_ref())
            .find(|slot| slot.id == *id)
    }

    /// Start a rotation: a new pending key at the next generation, made under
    /// `approval`.
    pub fn begin_rotation(
        &mut self,
        approval: Approval,
        random: &mut impl Random,
    ) -> Result<(), RotationError> {
        if self.pending.is_some() {
            return Err(RotationError::AlreadyRotating);
        }
        let generation = self
            .current
            .generation
            .checked_add(1)
            .ok_or(RotationError::GenerationExhausted)?;
        let mut pending =
            KeySlot::generate(generation, random).map_err(|_| RotationError::Random)?;
        while pending.id == self.current.id {
            random
                .fill(&mut pending.id)
                .map_err(|_| RotationError::Random)?;
        }
        self.pending = Some(pending);
        self.approval_at_generation = approval;
        Ok(())
    }

    /// End a rotation: the pending key becomes the only key, and the old one
    /// is wiped.
    pub fn finish_rotation(&mut self) -> Result<(), RotationError> {
        self.current = self.pending.take().ok_or(RotationError::NotRotating)?;
        Ok(())
    }

    /// The project's digest keys.
    pub fn digest_keys(&self, vault_id: &str) -> DigestKeys {
        DigestKeys::derive(self.digest_secret.as_ref(), vault_id)
    }
}

/// HMAC keys derived from the digest secret for one project: one for
/// values, one for places, in separate domains.
#[derive(Clone)]
pub struct DigestKeys {
    value: Hmac<Sha256>,
    place: Hmac<Sha256>,
}

impl fmt::Debug for DigestKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DigestKeys").finish_non_exhaustive()
    }
}

impl DigestKeys {
    fn derive(digest_secret: &[u8], vault_id: &str) -> Self {
        Self {
            value: derived_mac(digest_secret, DIGEST_SALT, vault_id),
            place: derived_mac(digest_secret, PLACE_SALT, vault_id),
        }
    }

    /// The digest of a value's exact bytes, so canonically equivalent text
    /// digests differently.
    pub fn value(&self, value: &[u8]) -> Digest {
        crate::work::note(crate::work::Work::ValueDigest);
        let mut mac = self.value.clone();
        mac.update(value);
        truncated(mac)
    }

    /// The digest of one place: a key in an environment.
    pub fn place(&self, environment: &str, key: &str) -> Digest {
        let mut mac = self.place.clone();
        update_str16(&mut mac, environment);
        update_str16(&mut mac, key);
        truncated(mac)
    }
}

fn derived_mac(digest_secret: &[u8], salt: &[u8], vault_id: &str) -> Hmac<Sha256> {
    let mut info = Vec::with_capacity(2 + vault_id.len());
    info.extend_from_slice(&length_u16(vault_id.len()).to_be_bytes());
    info.extend_from_slice(vault_id.as_bytes());
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Hkdf::<Sha256>::new(Some(salt), digest_secret)
        .expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_ref())
        .expect("HMAC takes keys of any length")
}

fn update_str16(mac: &mut Hmac<Sha256>, text: &str) {
    mac.update(&length_u16(text.len()).to_be_bytes());
    mac.update(text.as_bytes());
}

/// Names reach digests only after the part codec bounded them to `u16`.
fn length_u16(length: usize) -> u16 {
    u16::try_from(length).unwrap_or(u16::MAX)
}

fn truncated(mac: Hmac<Sha256>) -> Digest {
    let full = mac.finalize().into_bytes();
    full[..16].try_into().expect("sixteen bytes")
}

/// Which record a part is: what its associated data binds it to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartIdentity<'a> {
    pub vault_id: &'a str,
    pub kind: &'a str,
    pub part: u16,
    pub schema_version: u16,
}

impl PartIdentity<'_> {
    fn associated_data(&self, header: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(
            ASSOCIATED_DATA_LABEL.len() + header.len() + 2 + self.vault_id.len() + 1 + 32 + 4,
        );
        data.extend_from_slice(ASSOCIATED_DATA_LABEL);
        data.extend_from_slice(header);
        data.extend_from_slice(&length_u16(self.vault_id.len()).to_be_bytes());
        data.extend_from_slice(self.vault_id.as_bytes());
        data.push(u8::try_from(self.kind.len()).unwrap_or(u8::MAX));
        data.extend_from_slice(self.kind.as_bytes());
        data.extend_from_slice(&self.part.to_be_bytes());
        data.extend_from_slice(&self.schema_version.to_be_bytes());
        data
    }
}

/// Why a part won't seal or open. Opening refuses every one of these before
/// or at decryption, and returns no plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    TooLarge,
    Truncated,
    Magic,
    UnknownVersion,
    UnknownAlgorithm,
    /// Sealed under a key the record doesn't hold, or a generation that
    /// doesn't match its key.
    UnknownKey,
    /// The header, the identity or the ciphertext was changed.
    Authentication,
    Random,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "the part is larger than a record may be",
            Self::Truncated => "the part is truncated",
            Self::Magic => "the record isn't an encrypted part",
            Self::UnknownVersion => "the part's envelope version is unknown",
            Self::UnknownAlgorithm => "the part's encryption algorithm is unknown",
            Self::UnknownKey => "the part was sealed under a key this history doesn't hold",
            Self::Authentication => "the part doesn't open: it was changed or belongs elsewhere",
            Self::Random => "the system's random number generator failed",
        })
    }
}

/// Seal `plaintext` as the part `identity` under `key`.
pub fn seal(
    key: &KeySlot,
    identity: &PartIdentity<'_>,
    plaintext: &[u8],
    random: &mut impl Random,
) -> Result<Vec<u8>, EnvelopeError> {
    if plaintext.len() > PART_CAPACITY {
        return Err(EnvelopeError::TooLarge);
    }
    let mut nonce = [0_u8; NONCE_BYTES];
    random.fill(&mut nonce).map_err(|_| EnvelopeError::Random)?;
    let total = ENVELOPE_OVERHEAD + plaintext.len();
    let mut sealed = Zeroizing::new(Vec::with_capacity(total));
    sealed.extend_from_slice(&ENVELOPE_MAGIC);
    sealed.push(ENVELOPE_VERSION);
    sealed.push(ENVELOPE_ALGORITHM_XCHACHA20_POLY1305);
    sealed.extend_from_slice(&key.id);
    sealed.extend_from_slice(&key.generation.to_be_bytes());
    sealed.extend_from_slice(&nonce);
    let associated = identity.associated_data(&sealed[..HEADER_BYTES]);
    sealed.extend_from_slice(plaintext);
    let (_, body) = sealed.split_at_mut(HEADER_BYTES + NONCE_BYTES);
    let tag = key
        .cipher()
        .encrypt_inout_detached(<&XNonce>::from(&nonce), &associated, body.into())
        .map_err(|_| EnvelopeError::TooLarge)?;
    sealed.extend_from_slice(&tag);
    debug_assert_eq!(sealed.len(), total);
    Ok(std::mem::take(&mut *sealed))
}

/// The key ID and generation a part's header names, without opening it, as
/// resuming a rotation needs.
pub fn sealed_key(sealed: &[u8]) -> Result<(KeyId, u32), EnvelopeError> {
    let header = checked_header(sealed)?;
    Ok((
        header[6..22].try_into().expect("sixteen bytes"),
        u32::from_be_bytes(header[22..26].try_into().expect("four bytes")),
    ))
}

fn checked_header(sealed: &[u8]) -> Result<&[u8], EnvelopeError> {
    if sealed.len() > MAX_RECORD_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    if sealed.len() < ENVELOPE_OVERHEAD {
        return Err(EnvelopeError::Truncated);
    }
    if sealed[..4] != ENVELOPE_MAGIC {
        return Err(EnvelopeError::Magic);
    }
    if sealed[4] != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnknownVersion);
    }
    if sealed[5] != ENVELOPE_ALGORITHM_XCHACHA20_POLY1305 {
        return Err(EnvelopeError::UnknownAlgorithm);
    }
    Ok(&sealed[..HEADER_BYTES])
}

/// Open the part `identity` with whichever of `record`'s keys its header
/// names. The plaintext is exactly its length.
pub fn open(
    record: &KeyRecord,
    identity: &PartIdentity<'_>,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let (id, generation) = sealed_key(sealed)?;
    let key = record
        .key(&id)
        .filter(|key| key.generation == generation)
        .ok_or(EnvelopeError::UnknownKey)?;
    let associated = identity.associated_data(&sealed[..HEADER_BYTES]);
    let nonce: &[u8; NONCE_BYTES] = sealed[HEADER_BYTES..HEADER_BYTES + NONCE_BYTES]
        .try_into()
        .expect("twenty-four bytes");
    let (ciphertext, tag) = sealed[HEADER_BYTES + NONCE_BYTES..]
        .split_last_chunk::<TAG_BYTES>()
        .expect("a checked header leaves room for the tag");
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    key.cipher()
        .decrypt_inout_detached(
            <&XNonce>::from(nonce),
            &associated,
            plaintext.as_mut_slice().into(),
            <&Tag>::from(tag),
        )
        .map_err(|_| EnvelopeError::Authentication)?;
    Ok(plaintext)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Bytes from a counter, so records, nonces and keys are reproducible.
    #[derive(Debug, Clone)]
    pub(crate) struct CountingRandom(pub(crate) u8);

    impl Random for CountingRandom {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), RandomError> {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct FailingRandom;

    impl Random for FailingRandom {
        fn fill(&mut self, _bytes: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
    }

    fn record() -> KeyRecord {
        KeyRecord::generate(Approval::Automatic, &mut CountingRandom(1)).expect("record")
    }

    const IDENTITY: PartIdentity<'static> = PartIdentity {
        vault_id: "proj-1",
        kind: "history",
        part: 3,
        schema_version: 1,
    };

    #[test]
    fn key_records_are_91_bytes_stable_and_143_rotating_and_round_trip() {
        let mut record = record();
        let stable = record.encode();
        assert_eq!(stable.len(), STABLE_KEY_RECORD_BYTES);
        assert_eq!(stable.capacity(), STABLE_KEY_RECORD_BYTES);
        let decoded = KeyRecord::decode(&stable).expect("stable record");
        assert_eq!(decoded.encode().as_slice(), stable.as_slice());
        assert_eq!(decoded.current().generation(), 1);

        record
            .begin_rotation(Approval::Protected, &mut CountingRandom(200))
            .expect("rotation");
        let rotating = record.encode();
        assert_eq!(rotating.len(), ROTATING_KEY_RECORD_BYTES);
        let decoded = KeyRecord::decode(&rotating).expect("rotating record");
        assert!(decoded.is_rotating());
        assert_eq!(decoded.pending().map(KeySlot::generation), Some(2));
        assert_eq!(decoded.approval_at_generation(), Approval::Protected);
        assert_eq!(decoded.encode().as_slice(), rotating.as_slice());
    }

    #[test]
    fn key_records_refuse_every_unknown_or_inconsistent_byte() {
        let mut rotating_record = record();
        rotating_record
            .begin_rotation(Approval::Automatic, &mut CountingRandom(90))
            .expect("rotation");
        let stable = record().encode().to_vec();
        let rotating = rotating_record.encode().to_vec();
        let changed = |bytes: &[u8], at: usize, value: u8| {
            let mut bytes = bytes.to_vec();
            bytes[at] = value;
            bytes
        };
        let cases: Vec<(Vec<u8>, KeyRecordError)> = vec![
            (stable[..90].to_vec(), KeyRecordError::Length),
            ([stable.as_slice(), &[0]].concat(), KeyRecordError::Length),
            (rotating[..142].to_vec(), KeyRecordError::Length),
            (changed(&stable, 0, b'X'), KeyRecordError::Magic),
            (changed(&stable, 4, 2), KeyRecordError::UnknownVersion),
            (changed(&stable, 5, 2), KeyRecordError::UnknownState),
            (changed(&stable, 5, 1), KeyRecordError::Length),
            (changed(&rotating, 5, 0), KeyRecordError::Length),
            (changed(&stable, 6, 3), KeyRecordError::UnknownApproval),
            (
                [&stable[..55], &[0, 0, 0, 0], &stable[59..]].concat(),
                KeyRecordError::Generation,
            ),
            (changed(&rotating, 110, 9), KeyRecordError::Generation),
            (
                [&rotating[..91], &rotating[39..55], &rotating[107..]].concat(),
                KeyRecordError::RepeatedKeyId,
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                KeyRecord::decode(&bytes).map(|_| ()),
                Err(expected),
                "{expected:?}"
            );
        }
    }

    #[test]
    fn rotation_refuses_past_the_last_generation_and_wipes_the_old_key_when_done() {
        let mut bytes = record().encode().to_vec();
        bytes[55..59].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut exhausted = KeyRecord::decode(&bytes).expect("generation u32::MAX");
        assert_eq!(
            exhausted.begin_rotation(Approval::Automatic, &mut CountingRandom(0)),
            Err(RotationError::GenerationExhausted)
        );
        assert!(!exhausted.is_rotating());

        let mut record = record();
        let old = record.current().id();
        assert_eq!(record.finish_rotation(), Err(RotationError::NotRotating));
        record
            .begin_rotation(Approval::Protected, &mut CountingRandom(50))
            .expect("rotation");
        assert_eq!(
            record.begin_rotation(Approval::Protected, &mut CountingRandom(60)),
            Err(RotationError::AlreadyRotating)
        );
        let new = record.pending().expect("pending").id();
        assert_eq!(record.sealing_key().id(), new);
        assert!(record.key(&old).is_some() && record.key(&new).is_some());
        record.finish_rotation().expect("finish");
        assert_eq!(record.current().id(), new);
        assert!(record.key(&old).is_none());
        assert_eq!(record.encode().len(), STABLE_KEY_RECORD_BYTES);
    }

    #[test]
    fn a_pending_key_never_repeats_the_current_key_id() {
        let mut record =
            KeyRecord::generate(Approval::Automatic, &mut CountingRandom(0)).expect("record");
        let current = record.current().id();
        // The current key's ID was drawn from bytes 32 to 47, so a counter
        // starting at 32 draws the same ID first.
        assert_eq!(current, std::array::from_fn(|index| 32 + index as u8));
        record
            .begin_rotation(Approval::Automatic, &mut CountingRandom(32))
            .expect("rotation");
        assert_ne!(record.pending().expect("pending").id(), current);
    }

    #[test]
    fn failing_randomness_creates_nothing() {
        assert!(KeyRecord::generate(Approval::Automatic, &mut FailingRandom).is_err());
        let mut record = record();
        assert_eq!(
            record.begin_rotation(Approval::Automatic, &mut FailingRandom),
            Err(RotationError::Random)
        );
        assert!(!record.is_rotating());
        assert_eq!(
            seal(record.current(), &IDENTITY, b"x", &mut FailingRandom),
            Err(EnvelopeError::Random)
        );
    }

    #[test]
    fn digests_use_exact_bytes_and_separate_projects_and_domains() {
        let record = record();
        let keys = record.digest_keys("proj-1");
        let composed = keys.value("caf\u{e9}".as_bytes());
        let decomposed = keys.value("cafe\u{301}".as_bytes());
        assert_ne!(composed, decomposed, "canonically equivalent text differs");
        assert_eq!(composed, keys.value("café".as_bytes()));
        assert_ne!(keys.value("值".as_bytes()), keys.value("値".as_bytes()));
        assert_ne!(
            composed,
            record.digest_keys("proj-2").value("café".as_bytes()),
            "projects don't share digest keys"
        );
        assert_ne!(
            keys.place("production", "API_KEY"),
            keys.place("productio", "nAPI_KEY"),
            "lengths separate the names"
        );
        let mut same_bytes = Vec::new();
        same_bytes.extend_from_slice(&10_u16.to_be_bytes());
        same_bytes.extend_from_slice(b"production");
        same_bytes.extend_from_slice(&7_u16.to_be_bytes());
        same_bytes.extend_from_slice(b"API_KEY");
        assert_ne!(
            keys.place("production", "API_KEY"),
            keys.value(&same_bytes),
            "place digests are in their own domain"
        );
    }

    #[test]
    fn a_rotation_keeps_digests_comparable() {
        let mut record = record();
        let before = record.digest_keys("proj").value(b"secret");
        record
            .begin_rotation(Approval::Automatic, &mut CountingRandom(77))
            .expect("rotation");
        record.finish_rotation().expect("finish");
        assert_eq!(record.digest_keys("proj").value(b"secret"), before);
    }

    #[test]
    fn a_sealed_part_opens_only_as_itself() {
        let record = record();
        let sealed = seal(
            record.current(),
            &IDENTITY,
            b"part plaintext",
            &mut CountingRandom(9),
        )
        .expect("seal");
        assert_eq!(sealed.len(), ENVELOPE_OVERHEAD + 14);
        let opened = open(&record, &IDENTITY, &sealed).expect("open");
        assert_eq!(opened.as_slice(), b"part plaintext");
        assert_eq!(opened.len(), opened.capacity());

        for identity in [
            PartIdentity {
                part: 4,
                ..IDENTITY
            },
            PartIdentity {
                vault_id: "proj-2",
                ..IDENTITY
            },
            PartIdentity {
                kind: "releases",
                ..IDENTITY
            },
            PartIdentity {
                schema_version: 2,
                ..IDENTITY
            },
        ] {
            assert_eq!(
                open(&record, &identity, &sealed),
                Err(EnvelopeError::Authentication),
                "{identity:?}"
            );
        }
    }

    #[test]
    fn hostile_envelopes_are_refused_before_or_at_decryption() {
        let record = record();
        let sealed = seal(
            record.current(),
            &IDENTITY,
            b"secret",
            &mut CountingRandom(9),
        )
        .expect("seal");
        let other = KeyRecord::generate(Approval::Automatic, &mut CountingRandom(100))
            .expect("other record");
        assert_eq!(
            open(&other, &IDENTITY, &sealed),
            Err(EnvelopeError::UnknownKey)
        );
        for at in 0..HEADER_BYTES {
            let mut tampered = sealed.clone();
            tampered[at] ^= 0x01;
            let expected = match at {
                0..=3 => EnvelopeError::Magic,
                4 => EnvelopeError::UnknownVersion,
                5 => EnvelopeError::UnknownAlgorithm,
                _ => EnvelopeError::UnknownKey,
            };
            assert_eq!(
                open(&record, &IDENTITY, &tampered),
                Err(expected),
                "header byte {at}"
            );
        }
        for at in [HEADER_BYTES, HEADER_BYTES + NONCE_BYTES, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[at] ^= 0x80;
            assert_eq!(
                open(&record, &IDENTITY, &tampered),
                Err(EnvelopeError::Authentication),
                "byte {at}"
            );
        }
        assert_eq!(
            open(&record, &IDENTITY, &sealed[..ENVELOPE_OVERHEAD - 1]),
            Err(EnvelopeError::Truncated)
        );
        assert_eq!(
            open(&record, &IDENTITY, &sealed[..sealed.len() - 1]),
            Err(EnvelopeError::Authentication)
        );
        assert_eq!(
            open(&record, &IDENTITY, &[sealed.as_slice(), &[0]].concat()),
            Err(EnvelopeError::Authentication)
        );
        assert_eq!(
            open(&record, &IDENTITY, &vec![0; MAX_RECORD_BYTES + 1]),
            Err(EnvelopeError::TooLarge)
        );
    }

    #[test]
    fn parts_fill_a_record_exactly_at_capacity() {
        let record = record();
        let full = vec![7_u8; PART_CAPACITY];
        let sealed =
            seal(record.current(), &IDENTITY, &full, &mut CountingRandom(1)).expect("full part");
        assert_eq!(sealed.len(), MAX_RECORD_BYTES);
        assert_eq!(
            open(&record, &IDENTITY, &sealed).expect("open").len(),
            PART_CAPACITY
        );
        assert_eq!(
            seal(
                record.current(),
                &IDENTITY,
                &vec![7_u8; PART_CAPACITY + 1],
                &mut CountingRandom(1)
            ),
            Err(EnvelopeError::TooLarge)
        );
    }

    #[test]
    fn during_a_rotation_parts_open_under_either_key() {
        let mut record = record();
        let old = seal(record.current(), &IDENTITY, b"old", &mut CountingRandom(3)).expect("old");
        record
            .begin_rotation(Approval::Automatic, &mut CountingRandom(150))
            .expect("rotation");
        let new = seal(
            record.sealing_key(),
            &IDENTITY,
            b"new",
            &mut CountingRandom(4),
        )
        .expect("new");
        assert_eq!(
            sealed_key(&new).map(|(id, _)| id),
            Ok(record.pending().expect("pending").id())
        );
        assert_eq!(
            open(&record, &IDENTITY, &old).expect("old").as_slice(),
            b"old"
        );
        assert_eq!(
            open(&record, &IDENTITY, &new).expect("new").as_slice(),
            b"new"
        );
        record.finish_rotation().expect("finish");
        assert_eq!(
            open(&record, &IDENTITY, &old),
            Err(EnvelopeError::UnknownKey)
        );
    }
}
