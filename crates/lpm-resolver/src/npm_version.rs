//! npm-compatible version type for PubGrub.
//!
//! PubGrub's `Ranges<V>` needs `V: Ord + Clone + Display + Debug`.
//! We wrap `node_semver::Version` to satisfy these bounds while preserving
//! npm's ordering semantics (pre-release < release, build metadata ignored).

use std::cmp::Ordering;
use std::fmt;

/// Version type compatible with PubGrub's `Ranges<V>`.
///
/// Wraps a parsed semver version with npm-compatible ordering.
/// Two versions are equal if they have the same major.minor.patch and pre-release
/// (build metadata is ignored per semver spec).
#[derive(Clone, Debug, Eq)]
pub struct NpmVersion {
    inner: node_semver::Version,
}

impl NpmVersion {
    pub fn new(major: u64, minor: u64, patch: u64) -> Self {
        NpmVersion {
            inner: node_semver::Version {
                major,
                minor,
                patch,
                pre_release: vec![],
                build: vec![],
            },
        }
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        if let Some(inner) = parse_canonical(input) {
            return Ok(NpmVersion { inner });
        }
        let inner = node_semver::Version::parse(input)
            .map_err(|e| format!("invalid version '{input}': {e}"))?;
        Ok(NpmVersion { inner })
    }

    pub fn major(&self) -> u64 {
        self.inner.major
    }

    pub fn minor(&self) -> u64 {
        self.inner.minor
    }

    pub fn patch(&self) -> u64 {
        self.inner.patch
    }

    pub fn is_prerelease(&self) -> bool {
        !self.inner.pre_release.is_empty()
    }

    /// Access inner for range matching.
    pub fn as_inner(&self) -> &node_semver::Version {
        &self.inner
    }
}

/// Parses `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` written in ASCII exactly
/// as node-semver does, including its leading zeros, length limit, integer
/// ceiling and identifier typing, without running its general parser.
/// Anything outside that form, such as a `v` prefix or whitespace, is left to
/// node-semver.
fn parse_canonical(input: &str) -> Option<node_semver::Version> {
    if input.len() > node_semver::MAX_LENGTH {
        return None;
    }
    let (core, build) = match input.split_once('+') {
        Some((core, build)) => (core, Some(build)),
        None => (input, None),
    };
    let (release, pre_release) = match core.split_once('-') {
        Some((release, pre_release)) => (release, Some(pre_release)),
        None => (core, None),
    };
    let mut components = release.as_bytes().split(|byte| *byte == b'.');
    let major = release_component(components.next()?)?;
    let minor = release_component(components.next()?)?;
    let patch = release_component(components.next()?)?;
    if components.next().is_some() {
        return None;
    }
    Some(node_semver::Version {
        major,
        minor,
        patch,
        pre_release: pre_release.map_or(Some(Vec::new()), identifiers)?,
        build: build.map_or(Some(Vec::new()), identifiers)?,
    })
}

fn release_component(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for byte in digits {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
    }
    (value <= node_semver::MAX_SAFE_INTEGER).then_some(value)
}

fn identifiers(list: &str) -> Option<Vec<node_semver::Identifier>> {
    list.split('.')
        .map(|identifier| {
            if identifier.is_empty()
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return None;
            }
            Some(identifier.parse::<u64>().map_or_else(
                |_| node_semver::Identifier::AlphaNumeric(identifier.to_owned()),
                node_semver::Identifier::Numeric,
            ))
        })
        .collect()
}

impl fmt::Display for NpmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl PartialEq for NpmVersion {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl PartialOrd for NpmVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NpmVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl std::hash::Hash for NpmVersion {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.major.hash(state);
        self.inner.minor.hash(state);
        self.inner.patch.hash(state);
        // Hash pre-release identifiers for consistency with Eq
        for id in &self.inner.pre_release {
            let s: String = id.to_string();
            s.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        let v = NpmVersion::parse("1.2.3").unwrap();
        assert_eq!(v.to_string(), "1.2.3");
        assert_eq!(v.major(), 1);
        assert_eq!(v.minor(), 2);
        assert_eq!(v.patch(), 3);
    }

    #[test]
    fn ordering() {
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("1.0.1").unwrap();
        let v3 = NpmVersion::parse("2.0.0").unwrap();
        assert!(v1 < v2);
        assert!(v2 < v3);
    }

    #[test]
    fn prerelease_less_than_release() {
        let pre = NpmVersion::parse("1.0.0-alpha").unwrap();
        let rel = NpmVersion::parse("1.0.0").unwrap();
        assert!(pre < rel);
    }

    #[test]
    fn equality_ignores_build() {
        let v1 = NpmVersion::parse("1.0.0+build1").unwrap();
        let v2 = NpmVersion::parse("1.0.0+build2").unwrap();
        // node_semver treats build metadata as irrelevant for comparison
        assert_eq!(v1, v2);
    }

    #[test]
    fn canonical_parsing_matches_node_semver() {
        let max = node_semver::MAX_SAFE_INTEGER;
        let mut inputs = vec![
            "0.0.0".to_owned(),
            "1.2.3".to_owned(),
            "01.002.0003".to_owned(),
            format!("{max}.{max}.{max}"),
            format!("{}.0.0", max + 1),
            format!("0.0.{}", u64::MAX),
            format!("0.0.{}0", u64::MAX),
            format!("{}1.2.3", "0".repeat(node_semver::MAX_LENGTH - 5)),
            format!("{}1.2.3", "0".repeat(node_semver::MAX_LENGTH - 4)),
            String::new(),
            "1".to_owned(),
            "1.2".to_owned(),
            "1.2.".to_owned(),
            ".1.2".to_owned(),
            "1..2".to_owned(),
            "1.2.3.4".to_owned(),
            "v1.2.3".to_owned(),
            "V1.2.3".to_owned(),
            "=1.2.3".to_owned(),
            " 1.2.3".to_owned(),
            "1.2.3 ".to_owned(),
            "1.2.3-0".to_owned(),
            "1.2.3+7".to_owned(),
            "1.2.3-rc.1+build.5".to_owned(),
            "1.2.3--".to_owned(),
            "1.2.3--a.-".to_owned(),
            "1.2.3-0123.00".to_owned(),
            "1.2.3-18446744073709551615".to_owned(),
            "1.2.3-18446744073709551616".to_owned(),
            "1.2.3-a..b".to_owned(),
            "1.2.3-a.".to_owned(),
            "1.2.3-".to_owned(),
            "1.2.3+".to_owned(),
            "1.2.3-+b".to_owned(),
            "1.2.3+b+c".to_owned(),
            "1.2.3+b-c.-".to_owned(),
            "1.2.3alpha".to_owned(),
            "1.2.3-canary-6230622a1-20230525".to_owned(),
            "19.0.0-experimental-6230622a1-20230525+sha.abc".to_owned(),
            "1.2.3-ı".to_owned(),
            "1.2.3-é".to_owned(),
            "1.2.3-a_b".to_owned(),
            "１.2.3".to_owned(),
            "1.2.3\n".to_owned(),
            "-1.2.3".to_owned(),
            "+1.2.3".to_owned(),
        ];
        let alphabet = b"0123456789.v-+ aZ";
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 13) as usize;
            let mut input = String::with_capacity(len);
            let mut bits = state;
            for _ in 0..len {
                input.push(char::from(
                    alphabet[(bits % alphabet.len() as u64) as usize],
                ));
                bits /= alphabet.len() as u64;
            }
            inputs.push(input);
        }

        let tokens = [
            "0",
            "1",
            "00",
            "07",
            "42",
            "900719925474099",
            "900719925474100",
            "18446744073709551616",
            ".",
            ".",
            ".",
            "-",
            "+",
            "rc",
            "Z9",
            "-x",
            "1a",
            " ",
            "v",
            "é",
        ];
        for _ in 0..200_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut bits = state;
            let count = 1 + (bits % 10) as usize;
            bits /= 10;
            let mut input = String::new();
            for _ in 0..count {
                input.push_str(tokens[(bits % tokens.len() as u64) as usize]);
                bits = bits.rotate_right(5) ^ state;
            }
            inputs.push(input);
        }

        for input in inputs {
            let expected = node_semver::Version::parse(&input).ok();
            let actual = NpmVersion::parse(&input).ok().map(|version| version.inner);
            assert_eq!(actual, expected, "{input:?}");
            if let Some(canonical) = parse_canonical(&input) {
                assert_eq!(Some(canonical), expected, "{input:?}");
            }
        }
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("1.0.0").unwrap();
        let mut set = HashSet::new();
        set.insert(v1);
        assert!(set.contains(&v2));
    }
}
