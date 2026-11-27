use crate::error::LpmError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use subtle::ConstantTimeEq;

/// Subresource Integrity (SRI) hash.
///
/// Format: `algorithm-base64hash`
/// Example: `sha512-abc123...`
///
/// Used to verify package tarballs haven't been tampered with.
/// The LPM registry returns integrity hashes in this format for every package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub algorithm: HashAlgorithm,
    /// The raw hash bytes.
    pub hash: Vec<u8>,
}

/// Ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    /// Required digest length in bytes — exactly 32 for SHA-256 and
    /// 64 for SHA-512. Used by [`Integrity::parse`] to reject
    /// structurally-malformed SRI before any caller treats parse
    /// success as a complete invariant.
    #[inline]
    pub const fn digest_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

impl Integrity {
    /// Parse an SRI string like `sha512-abc123...`
    pub fn parse(input: &str) -> Result<Self, LpmError> {
        let (algo_str, hash_b64) = input.split_once('-').ok_or_else(|| {
            LpmError::InvalidIntegrity(format!("{input} missing algorithm prefix (e.g., sha512-)"))
        })?;

        let algorithm = match algo_str {
            "sha1" => HashAlgorithm::Sha1,
            "sha256" => HashAlgorithm::Sha256,
            "sha512" => HashAlgorithm::Sha512,
            other => {
                return Err(LpmError::InvalidIntegrity(format!(
                    "unsupported algorithm: {other} (expected sha1, sha256, or sha512)"
                )));
            }
        };

        let hash = BASE64.decode(hash_b64).map_err(|e| {
            LpmError::InvalidIntegrity(format!("invalid base64 in integrity hash: {e}"))
        })?;

        let expected = algorithm.digest_len();
        if hash.len() != expected {
            return Err(LpmError::InvalidIntegrity(format!(
                "{algo_str} digest must be {expected} bytes, got {}",
                hash.len()
            )));
        }

        Ok(Integrity { algorithm, hash })
    }

    /// Compute integrity hash from raw bytes.
    pub fn from_bytes(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let mut hasher = IntegrityHasher::new(algorithm);
        hasher.update(data);
        hasher.finish()
    }

    /// Starts hashing a stream with this integrity's algorithm, for
    /// [`Self::verify_hasher`] once the stream ends.
    #[inline]
    pub fn hasher(&self) -> IntegrityHasher {
        IntegrityHasher::new(self.algorithm)
    }

    /// Verify that the given data matches this integrity hash.
    ///
    /// Uses [`subtle::ConstantTimeEq`] so a future caller running this
    /// path against attacker-influenced timing (server-side verifier,
    /// network-observable hot loop) doesn't leak per-byte digest
    /// information through `Vec::eq`'s early-exit short-circuit.
    pub fn verify(&self, data: &[u8]) -> Result<(), LpmError> {
        self.verify_digest(Self::from_bytes(self.algorithm, data))
    }

    /// Verify a file on disk matches this integrity hash (bounded-memory).
    ///
    /// Reads the file in 64KB chunks — never buffers the full file in memory.
    /// Supports SHA-1, SHA-256, and SHA-512.
    pub fn verify_file(&self, path: &std::path::Path) -> Result<(), LpmError> {
        use std::io::Read;

        let mut file = std::fs::File::open(path).map_err(LpmError::Io)?;
        let mut buf = [0u8; 64 * 1024];
        let mut hasher = self.hasher();
        loop {
            let n = file.read(&mut buf).map_err(LpmError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        self.verify_hasher(hasher)
    }

    /// Verify the bytes `hasher` was fed against this integrity hash, in
    /// constant time like [`Self::verify`]. A hasher of another algorithm
    /// never matches.
    pub fn verify_hasher(&self, hasher: IntegrityHasher) -> Result<(), LpmError> {
        self.verify_digest(hasher.finish())
    }

    fn verify_digest(&self, computed: Integrity) -> Result<(), LpmError> {
        if computed.algorithm == self.algorithm
            && self.hash.len() == computed.hash.len()
            && bool::from(self.hash.ct_eq(&computed.hash))
        {
            Ok(())
        } else {
            Err(LpmError::IntegrityMismatch {
                expected: self.to_string(),
                actual: computed.to_string(),
            })
        }
    }

    /// Returns the base64-encoded hash string (without algorithm prefix).
    pub fn hash_base64(&self) -> String {
        BASE64.encode(&self.hash)
    }
}

/// Hashes bytes as they arrive, so a stream can be checked against an
/// [`Integrity`] without holding the whole stream or reading it twice.
#[derive(Clone)]
pub struct IntegrityHasher(StreamHasher);

#[derive(Clone)]
enum StreamHasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl IntegrityHasher {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self(match algorithm {
            HashAlgorithm::Sha1 => StreamHasher::Sha1(Sha1::new()),
            HashAlgorithm::Sha256 => StreamHasher::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => StreamHasher::Sha512(Sha512::new()),
        })
    }

    #[inline]
    pub fn algorithm(&self) -> HashAlgorithm {
        match self.0 {
            StreamHasher::Sha1(_) => HashAlgorithm::Sha1,
            StreamHasher::Sha256(_) => HashAlgorithm::Sha256,
            StreamHasher::Sha512(_) => HashAlgorithm::Sha512,
        }
    }

    #[inline]
    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.0 {
            StreamHasher::Sha1(hasher) => hasher.update(bytes),
            StreamHasher::Sha256(hasher) => hasher.update(bytes),
            StreamHasher::Sha512(hasher) => hasher.update(bytes),
        }
    }

    /// The integrity of every byte fed so far.
    pub fn finish(self) -> Integrity {
        let algorithm = self.algorithm();
        let hash = match self.0 {
            StreamHasher::Sha1(hasher) => hasher.finalize().to_vec(),
            StreamHasher::Sha256(hasher) => hasher.finalize().to_vec(),
            StreamHasher::Sha512(hasher) => hasher.finalize().to_vec(),
        };
        Integrity { algorithm, hash }
    }
}

impl fmt::Debug for IntegrityHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("IntegrityHasher")
            .field(&self.algorithm())
            .finish()
    }
}

impl std::io::Write for IntegrityHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.update(bytes);
        Ok(bytes.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algo = match self.algorithm {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        };
        write!(f, "{}-{}", algo, self.hash_base64())
    }
}

/// How two SRI metadata strings compare over the hash algorithms both name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SriComparison {
    /// They share at least one algorithm, and for each one they share, a
    /// digest on one side equals a digest on the other.
    Agree,
    /// For an algorithm both name, no digest on one side equals any on the
    /// other.
    Disagree,
    /// No algorithm appears in both, so nothing can be compared.
    NoCommonAlgorithm,
}

/// The hashes in SRI metadata: one or more space-separated
/// `algorithm-base64` tokens with optional `?options`. Tokens that don't
/// parse are ignored, as SRI ignores them.
pub fn sri_hashes(sri: &str) -> impl Iterator<Item = Integrity> + '_ {
    sri.split_ascii_whitespace().filter_map(|token| {
        Integrity::parse(token.split_once('?').map_or(token, |(hash, _)| hash)).ok()
    })
}

/// Compares two SRI metadata strings. Several digests of one algorithm are
/// alternatives, as SRI treats them, so one match among them is enough.
pub fn compare_sri(left: &str, right: &str) -> SriComparison {
    let right: Vec<Integrity> = sri_hashes(right).collect();
    let left: Vec<Integrity> = sri_hashes(left).collect();
    let mut shared = false;
    for algorithm in [
        HashAlgorithm::Sha512,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha1,
    ] {
        let mut on_right = right
            .iter()
            .filter(|hash| hash.algorithm == algorithm)
            .peekable();
        if on_right.peek().is_none() || !left.iter().any(|hash| hash.algorithm == algorithm) {
            continue;
        }
        shared = true;
        let matched = on_right.any(|right| {
            left.iter()
                .filter(|left| left.algorithm == algorithm)
                .any(|left| bool::from(left.hash.ct_eq(&right.hash)))
        });
        if !matched {
            return SriComparison::Disagree;
        }
    }
    if shared {
        SriComparison::Agree
    } else {
        SriComparison::NoCommonAlgorithm
    }
}

/// Whether two SRI strings name different bytes. Hashes of different
/// algorithms say nothing about each other, so they never contradict; a
/// string that names no hash at all is compared as written.
pub fn contradict(left: &str, right: &str) -> bool {
    match compare_sri(left, right) {
        SriComparison::Disagree => true,
        SriComparison::Agree => false,
        SriComparison::NoCommonAlgorithm => {
            (sri_hashes(left).next().is_none() || sri_hashes(right).next().is_none())
                && left != right
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sri_strings_agree_when_their_shared_algorithms_agree() {
        let sha512 = Integrity::from_bytes(HashAlgorithm::Sha512, b"package").to_string();
        let sha1 = Integrity::from_bytes(HashAlgorithm::Sha1, b"package").to_string();
        let other_sha512 = Integrity::from_bytes(HashAlgorithm::Sha512, b"other").to_string();
        assert_eq!(compare_sri(&sha512, &sha512), SriComparison::Agree);
        assert_eq!(
            compare_sri(&format!("{sha1} {sha512}?opt"), &sha512),
            SriComparison::Agree
        );
        assert_eq!(compare_sri(&sha512, &other_sha512), SriComparison::Disagree);
        assert_eq!(
            compare_sri(
                &format!("{sha1} {other_sha512}"),
                &format!("{sha512} {sha1}")
            ),
            SriComparison::Disagree,
            "one disagreeing shared algorithm is enough"
        );
        assert_eq!(
            compare_sri(&format!("{other_sha512} {sha512}"), &sha512),
            SriComparison::Agree,
            "alternatives of one algorithm agree when any one matches"
        );
        assert_eq!(
            compare_sri(&sha1, &sha512),
            SriComparison::NoCommonAlgorithm
        );
        assert_eq!(
            compare_sri("garbage", &sha512),
            SriComparison::NoCommonAlgorithm
        );
    }

    #[test]
    fn sri_metadata_yields_each_hash_that_parses_without_its_options() {
        let sha1 = Integrity::from_bytes(HashAlgorithm::Sha1, b"package");
        let sha512 = Integrity::from_bytes(HashAlgorithm::Sha512, b"package");
        assert_eq!(
            sri_hashes(&format!("{sha1} garbage {sha512}?x")).collect::<Vec<_>>(),
            vec![sha1, sha512]
        );
    }

    #[test]
    fn parse_sha512_integrity() {
        // Real 64-byte SHA-512 digest (of empty input) base64-encoded.
        let sri = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==";
        let integrity = Integrity::parse(sri).unwrap();
        assert_eq!(integrity.algorithm, HashAlgorithm::Sha512);
        assert_eq!(integrity.hash.len(), 64);
        assert_eq!(integrity.to_string(), sri);
    }

    #[test]
    fn parse_sha256_integrity() {
        // Real 32-byte SHA-256 digest (of empty input) base64-encoded.
        let sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        let integrity = Integrity::parse(sri).unwrap();
        assert_eq!(integrity.algorithm, HashAlgorithm::Sha256);
        assert_eq!(integrity.hash.len(), 32);
    }

    #[test]
    fn parse_sha1_integrity() {
        let sri = "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=";
        let integrity = Integrity::parse(sri).unwrap();
        assert_eq!(integrity.algorithm, HashAlgorithm::Sha1);
        assert_eq!(integrity.hash.len(), 20);
        assert_eq!(integrity.to_string(), sri);
    }

    #[test]
    fn reject_missing_algorithm() {
        assert!(Integrity::parse("noprefixhere").is_err());
    }

    #[test]
    fn reject_unsupported_algorithm() {
        assert!(Integrity::parse("md5-1B2M2Y8AsgTpgAmY7PhCfg==").is_err());
    }

    #[test]
    fn reject_invalid_base64() {
        assert!(Integrity::parse("sha512-!!!notbase64!!!").is_err());
    }

    /// L27: structural digest-length validation. Pre-fix `sha256-YWJjMTIz`
    /// (6-byte payload) parsed successfully and only failed at verify
    /// time. Callers that treated parse success as a complete invariant
    /// were silently accepting malformed lockfile / metadata SRI; the
    /// parser now rejects up front.
    #[test]
    fn reject_sha256_with_wrong_digest_length() {
        let err = Integrity::parse("sha256-YWJjMTIz")
            .expect_err("6-byte SHA-256 digest must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("sha256 digest must be 32 bytes"),
            "expected length-mismatch message, got: {msg}"
        );
    }

    #[test]
    fn reject_sha512_with_wrong_digest_length() {
        let err = Integrity::parse("sha512-YWJjMTIz")
            .expect_err("6-byte SHA-512 digest must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("sha512 digest must be 64 bytes"),
            "expected length-mismatch message, got: {msg}"
        );
    }

    /// L22: `verify` now goes through `subtle::ConstantTimeEq` so a
    /// future caller running this path against attacker-influenced
    /// timing doesn't leak per-byte digest information. The behavioural
    /// contract (match → Ok, mismatch → IntegrityMismatch) stays
    /// identical — this test pins the contract; the constant-time
    /// guarantee comes from the type system (`ConstantTimeEq` impl).
    #[test]
    fn verify_returns_ok_on_match_and_mismatch_on_one_byte_flip() {
        let data = b"the quick brown fox jumps over the lazy dog";
        for algo in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let i = Integrity::from_bytes(algo, data);
            assert!(
                i.verify(data).is_ok(),
                "verify must succeed on identical bytes"
            );
            // Flip the last byte and confirm verify fails.
            let mut tampered = data.to_vec();
            *tampered.last_mut().unwrap() ^= 0x01;
            assert!(
                i.verify(&tampered).is_err(),
                "verify must fail on one-byte tamper"
            );
            // Flip the first byte too — the constant-time path checks
            // every position, so an early-byte mismatch is rejected
            // identically to a late-byte mismatch.
            let mut tampered_early = data.to_vec();
            tampered_early[0] ^= 0x01;
            assert!(
                i.verify(&tampered_early).is_err(),
                "verify must fail regardless of which byte differs"
            );
        }
    }

    /// Computed digests round-trip through parse — same algorithm gives
    /// the same length back. Pins that the strict-length gate doesn't
    /// regress the legitimate from_bytes-then-display-then-parse path.
    #[test]
    fn computed_digest_roundtrips_under_strict_length() {
        for algo in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let i = Integrity::from_bytes(algo, b"payload");
            let parsed = Integrity::parse(&i.to_string()).expect("computed must roundtrip");
            assert_eq!(parsed, i);
            assert_eq!(parsed.hash.len(), algo.digest_len());
        }
    }

    #[test]
    fn compute_and_verify_sha512() {
        let data = b"hello world";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        assert!(integrity.verify(data).is_ok());
        assert!(integrity.verify(b"wrong data").is_err());
    }

    #[test]
    fn compute_and_verify_sha256() {
        let data = b"test payload";
        let integrity = Integrity::from_bytes(HashAlgorithm::Sha256, data);
        assert!(integrity.verify(data).is_ok());
        assert!(integrity.verify(b"different").is_err());
    }

    #[test]
    fn roundtrip_parse_display() {
        let data = b"roundtrip test";
        let original = Integrity::from_bytes(HashAlgorithm::Sha512, data);
        let serialized = original.to_string();
        let parsed = Integrity::parse(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn hasher_fed_in_pieces_matches_the_one_shot_digest_for_every_algorithm() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for algorithm in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
        ] {
            let mut hasher = IntegrityHasher::new(algorithm);
            for piece in data.chunks(7919) {
                hasher.update(piece);
            }
            assert_eq!(hasher.algorithm(), algorithm);
            assert_eq!(hasher.finish(), Integrity::from_bytes(algorithm, &data));
        }
    }

    #[test]
    fn verify_hasher_accepts_the_declared_stream_and_rejects_a_changed_byte() {
        let data = b"streamed tarball bytes";
        for algorithm in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
        ] {
            let declared = Integrity::from_bytes(algorithm, data);
            let mut hasher = declared.hasher();
            hasher.update(&data[..5]);
            hasher.update(&data[5..]);
            declared.verify_hasher(hasher).unwrap();

            let mut tampered = declared.hasher();
            tampered.update(b"streamed tarball bytez");
            assert!(matches!(
                declared.verify_hasher(tampered),
                Err(LpmError::IntegrityMismatch { .. })
            ));
        }
    }

    #[test]
    fn verify_hasher_rejects_a_hasher_of_another_algorithm() {
        // The same digest bytes under another algorithm's name: only the algorithm differs.
        let sha256 = Integrity::from_bytes(HashAlgorithm::Sha256, b"payload");
        let declared = Integrity {
            algorithm: HashAlgorithm::Sha512,
            hash: sha256.hash,
        };
        let mut hasher = IntegrityHasher::new(HashAlgorithm::Sha256);
        hasher.update(b"payload");
        assert!(matches!(
            declared.verify_hasher(hasher),
            Err(LpmError::IntegrityMismatch { .. })
        ));
    }

    #[test]
    fn hasher_takes_bytes_through_io_write() {
        let data = vec![7u8; 300_000];
        let declared = Integrity::from_bytes(HashAlgorithm::Sha512, &data);
        let mut hasher = declared.hasher();
        std::io::copy(&mut data.as_slice(), &mut hasher).unwrap();
        declared.verify_hasher(hasher).unwrap();
    }

    #[test]
    fn only_two_hashes_of_one_algorithm_can_contradict() {
        let sha512 = |data: &[u8]| Integrity::from_bytes(HashAlgorithm::Sha512, data).to_string();
        let sha1 = |data: &[u8]| Integrity::from_bytes(HashAlgorithm::Sha1, data).to_string();

        assert!(!contradict(&sha512(b"archive"), &sha512(b"archive")));
        assert!(contradict(&sha512(b"archive"), &sha512(b"another")));
        assert!(!contradict(&sha512(b"archive"), &sha1(b"archive")));
        assert!(!contradict(&sha512(b"archive"), &sha1(b"another")));
        assert!(contradict("sha512-one", "sha512-two"));
        assert!(!contradict("sha512-one", "sha512-one"));
    }
}
