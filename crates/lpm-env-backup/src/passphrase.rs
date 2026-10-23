//! Backup passphrases: how they're normalized, how strong they must be, and
//! the six-word phrases this crate generates.

use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The longest passphrase accepted as given, in UTF-8 bytes.
pub const MAX_INPUT_BYTES: usize = 4 * 1024;
/// The longest passphrase accepted once normalized, in UTF-8 bytes.
pub const MAX_NORMALIZED_BYTES: usize = 1024;
/// The fewest guesses, as a power of ten, that zxcvbn must estimate for a
/// passphrase a backup is sealed with: about 60 bits.
pub const MIN_GUESSES_LOG10: f64 = 18.1;
/// How many words a generated passphrase has: about 77.5 bits from the
/// 7,776-word list.
pub const GENERATED_WORDS: usize = 6;

const WORDLIST: &str = include_str!("../wordlist/eff_large_wordlist.txt");
const WORDLIST_LEN: usize = 7776;

/// A passphrase in Unicode Normalization Form C, so one typed on another
/// Mac or keyboard derives the same key. Its bytes are wiped when dropped.
pub struct Passphrase(Zeroizing<String>);

/// Why bytes can't be used as a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseError {
    Empty,
    NotUtf8,
    TooLong,
}

/// How hard zxcvbn estimates a passphrase is to guess.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// zxcvbn's estimate of the guesses needed, as a power of ten. It reads
    /// at most the first 100 characters.
    pub guesses_log10: f64,
    /// Whether a backup can be sealed with it: at least [`MIN_GUESSES_LOG10`].
    pub acceptable: bool,
}

impl Passphrase {
    /// Normalizes `raw`, which must be UTF-8 of at most [`MAX_INPUT_BYTES`]
    /// that stays within [`MAX_NORMALIZED_BYTES`] once normalized. Nothing is
    /// trimmed or folded: every character typed is part of the key.
    pub fn new(raw: &[u8]) -> Result<Self, PassphraseError> {
        if raw.is_empty() {
            return Err(PassphraseError::Empty);
        }
        if raw.len() > MAX_INPUT_BYTES {
            return Err(PassphraseError::TooLong);
        }
        let text = std::str::from_utf8(raw).map_err(|_| PassphraseError::NotUtf8)?;
        // Composition can grow text up to threefold, so the buffer never
        // reallocates and leaves a copy behind.
        let mut normalized = Zeroizing::new(String::with_capacity(raw.len() * 3));
        normalized.extend(text.nfc());
        if normalized.len() > MAX_NORMALIZED_BYTES {
            return Err(PassphraseError::TooLong);
        }
        Ok(Self(normalized))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// zxcvbn's estimate of this passphrase, which reads at most its first
    /// 100 characters and can take a quarter of a second for symbol-heavy
    /// text. zxcvbn makes copies of what it reads that it doesn't wipe; the
    /// LPM env engine wipes all memory it frees.
    pub fn strength(&self) -> Strength {
        let guesses_log10 = zxcvbn::zxcvbn(&self.0, &[]).guesses_log10();
        Strength {
            guesses_log10,
            acceptable: guesses_log10 >= MIN_GUESSES_LOG10,
        }
    }
}

/// The system's random source failed, or gave 32 draws in a row that zxcvbn
/// rated too weak, which a working source doesn't.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerateError;

/// Six words drawn uniformly from the EFF large wordlist, separated by
/// spaces. A draw zxcvbn rates below [`MIN_GUESSES_LOG10`], which takes six
/// unusually common words, is drawn again, so every phrase it returns seals.
pub fn generate() -> Result<Zeroizing<String>, GenerateError> {
    for _ in 0..32 {
        let phrase = draw()?;
        let accepted = Passphrase::new(phrase.as_bytes())
            .is_ok_and(|passphrase| passphrase.strength().acceptable);
        if accepted {
            return Ok(phrase);
        }
    }
    Err(GenerateError)
}

fn draw() -> Result<Zeroizing<String>, GenerateError> {
    let words = words();
    // 8 × 7,776 is the largest multiple below 2^16, so values under it map
    // to words without bias; about one draw in eight is discarded.
    const LIMIT: u16 = 8 * WORDLIST_LEN as u16;
    let mut random = Zeroizing::new([0_u8; 32]);
    let mut used = random.len();
    let mut phrase = Zeroizing::new(String::with_capacity(GENERATED_WORDS * 10));
    let mut chosen = 0;
    while chosen < GENERATED_WORDS {
        if used == random.len() {
            getrandom::fill(random.as_mut()).map_err(|_| GenerateError)?;
            used = 0;
        }
        let value = u16::from_be_bytes([random[used], random[used + 1]]);
        used += 2;
        if value >= LIMIT {
            continue;
        }
        if chosen > 0 {
            phrase.push(' ');
        }
        phrase.push_str(words[usize::from(value) % WORDLIST_LEN]);
        chosen += 1;
    }
    Ok(phrase)
}

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .map(|line| line.split_once('\t').map_or(line, |(_, word)| word))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;

    #[test]
    fn the_wordlist_is_effs_published_large_list() {
        let digest: String = Sha256::digest(WORDLIST.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let words = words();
        assert_eq!(words.len(), WORDLIST_LEN);
        assert_eq!(words.iter().collect::<HashSet<_>>().len(), WORDLIST_LEN);
        assert!(words.iter().all(|word| {
            word.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        }));
    }

    #[test]
    fn normalization_composes_so_both_typings_of_an_accent_match() {
        let composed = Passphrase::new("caf\u{e9} cr\u{e8}me".as_bytes()).expect("composed");
        let decomposed =
            Passphrase::new("cafe\u{301} cre\u{300}me".as_bytes()).expect("decomposed");
        assert_eq!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(composed.as_bytes(), "caf\u{e9} cr\u{e8}me".as_bytes());
    }

    #[test]
    fn whitespace_and_case_are_kept_as_typed() {
        let spaced = Passphrase::new(b" Harbor  velvet ").expect("spaced");
        assert_eq!(spaced.as_bytes(), b" Harbor  velvet ");
    }

    #[test]
    fn empty_invalid_and_oversized_input_is_refused() {
        assert_eq!(Passphrase::new(b"").err(), Some(PassphraseError::Empty));
        assert_eq!(
            Passphrase::new(b"\xff\xfe").err(),
            Some(PassphraseError::NotUtf8)
        );
        let at_limit = "a".repeat(MAX_NORMALIZED_BYTES);
        assert!(Passphrase::new(at_limit.as_bytes()).is_ok());
        let over = "a".repeat(MAX_NORMALIZED_BYTES + 1);
        assert_eq!(
            Passphrase::new(over.as_bytes()).err(),
            Some(PassphraseError::TooLong)
        );
        let raw_over = vec![b'a'; MAX_INPUT_BYTES + 1];
        assert_eq!(
            Passphrase::new(&raw_over).err(),
            Some(PassphraseError::TooLong)
        );
    }

    #[test]
    fn decomposed_input_up_to_the_raw_limit_is_measured_after_composition() {
        // 1,000 two-byte é written as e + U+0301 is 3,000 raw bytes and
        // composes to 2,000 bytes, over the normalized limit.
        let decomposed = "e\u{301}".repeat(1000);
        assert!(decomposed.len() <= MAX_INPUT_BYTES);
        assert_eq!(
            Passphrase::new(decomposed.as_bytes()).err(),
            Some(PassphraseError::TooLong)
        );
        let fits = "e\u{301}".repeat(512);
        assert_eq!(
            Passphrase::new(fits.as_bytes())
                .expect("fits")
                .as_bytes()
                .len(),
            1024
        );
    }

    #[test]
    fn common_and_short_passphrases_fall_short_and_long_random_ones_pass() {
        for weak in [
            "password",
            "Tr0ub4dor&3",
            "aaaaaaaaaaaaaaaaaaaa",
            "qwertyuiop1234567890",
            "harbor velvet ninety",
        ] {
            let strength = Passphrase::new(weak.as_bytes()).expect("weak").strength();
            assert!(!strength.acceptable, "{weak}: {}", strength.guesses_log10);
        }
        let strong = Passphrase::new(b"q7#Vt9!mZ2@xL4$wR8^kP1&nB6*hD3%s")
            .expect("strong")
            .strength();
        assert!(strong.acceptable, "{}", strong.guesses_log10);
    }

    #[test]
    fn repeats_and_input_past_zxcvbns_window_are_estimated_without_failing() {
        // zxcvbn finds repeats with backreferencing patterns over at most 100
        // characters and unwraps their results; these are its worst cases.
        for weak in [
            "ab".repeat(512),
            "a".repeat(1024),
            "abc".repeat(341),
            "a".repeat(99) + "b",
        ] {
            let strength = Passphrase::new(weak.as_bytes()).expect("valid").strength();
            assert!(!strength.acceptable, "{}", strength.guesses_log10);
        }
        let long = "q7#Vt9!mZ2@xL4$wR8^kP1&nB6*hD3%s".repeat(32);
        assert!(
            Passphrase::new(long.as_bytes())
                .expect("valid")
                .strength()
                .acceptable
        );
    }

    #[test]
    fn generated_phrases_are_six_listed_words_and_always_acceptable() {
        let listed: HashSet<&str> = words().iter().copied().collect();
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let phrase = generate().expect("random");
            let chosen: Vec<&str> = phrase.split(' ').collect();
            assert_eq!(chosen.len(), GENERATED_WORDS);
            assert!(
                chosen.iter().all(|word| listed.contains(word)),
                "{}",
                *phrase
            );
            assert!(
                Passphrase::new(phrase.as_bytes())
                    .expect("valid")
                    .strength()
                    .acceptable
            );
            seen.insert(phrase.to_string());
        }
        assert_eq!(seen.len(), 200);
    }

    #[test]
    fn draws_cover_the_whole_list_without_favoring_the_start() {
        let mut first_half = 0_u32;
        let mut drawn = 0_u32;
        let mut positions = HashSet::new();
        let index: std::collections::HashMap<&str, usize> = words()
            .iter()
            .enumerate()
            .map(|(position, word)| (*word, position))
            .collect();
        for _ in 0..4000 {
            let phrase = draw().expect("random");
            for word in phrase.split(' ') {
                let position = index[word];
                positions.insert(position);
                first_half += u32::from(position < WORDLIST_LEN / 2);
                drawn += 1;
            }
        }
        // 24,000 draws: each half expects 12,000 with a standard deviation
        // of about 77, so 11,500..12,500 is over six deviations wide.
        assert!(
            (11_500..12_500).contains(&first_half),
            "{first_half} of {drawn}"
        );
        assert!(positions.len() > 7_000, "{} distinct", positions.len());
    }
}
