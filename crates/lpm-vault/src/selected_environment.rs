use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, Visitor};
use zeroize::Zeroizing;

use crate::{EnvironmentMap, SecretMap};
pub(crate) use lpm_common::stored_env::is_valid_environment_name;
use lpm_common::stored_env::is_valid_variable_name;
use lpm_env::{DEFAULT_ENVIRONMENT, reads_default_environment};

/// Why a stored payload didn't parse.
#[derive(Debug)]
pub(crate) struct PayloadError(String);

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Every environment of the stored payload `{"environments":{name:{KEY:
/// VALUE}}}`, by the rules serde applies to it: one `environments` field,
/// unique valid environment and variable names, and string values. A
/// parser of its own, because serde_json decodes escaped strings through a
/// scratch buffer it never wipes: here each string is decoded into a buffer
/// sized to its encoded length, and a payload that doesn't parse wipes what
/// it built.
pub(crate) fn parse_all(json: &str) -> Result<EnvironmentMap, PayloadError> {
    let mut parser = PayloadParser { text: json, at: 0 };
    let mut environments = crate::history::ZeroizingValues::default();
    let mut found = false;
    parser.object(|parser, field| {
        if field != "environments" {
            return Err(parser.error(&format!("unknown field `{field}`, expected `environments`")));
        }
        if std::mem::replace(&mut found, true) {
            return Err(parser.error("duplicate field `environments`"));
        }
        parser.object(|parser, environment| {
            if !is_valid_environment_name(&environment) {
                return Err(parser.error(&format!("environment name {environment:?} is invalid")));
            }
            if environments.contains_key(&environment) {
                return Err(parser.error(&format!("duplicate environment name {environment:?}")));
            }
            let secrets = environments.entry(environment).or_default();
            parser.object(|parser, variable| {
                if !is_valid_variable_name(&variable) {
                    return Err(parser.error(&format!("env variable name {variable:?} is invalid")));
                }
                let mut value = Zeroizing::new(parser.string()?);
                if secrets.contains_key(&variable) {
                    return Err(parser.error(&format!("duplicate env variable name {variable:?}")));
                }
                secrets.insert(variable, std::mem::take(&mut *value));
                Ok(())
            })
        })
    })?;
    parser.skip_whitespace();
    if parser.at != json.len() {
        return Err(parser.error("trailing characters"));
    }
    if !found {
        return Err(parser.error("missing field `environments`"));
    }
    if environments.is_empty() {
        environments.insert(DEFAULT_ENVIRONMENT.to_owned(), HashMap::new());
    }
    Ok(std::mem::take(&mut *environments))
}

struct PayloadParser<'a> {
    text: &'a str,
    at: usize,
}

impl PayloadParser<'_> {
    fn error(&self, message: &str) -> PayloadError {
        PayloadError(format!("{message} at byte {}", self.at))
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.text.as_bytes().get(self.at),
            Some(b' ' | b'\t' | b'\n' | b'\r')
        ) {
            self.at += 1;
        }
    }

    fn next_is(&mut self, byte: u8) -> bool {
        self.skip_whitespace();
        if self.text.as_bytes().get(self.at) == Some(&byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    /// An object, calling `member` with each key once its colon is read.
    fn object(
        &mut self,
        mut member: impl FnMut(&mut Self, String) -> Result<(), PayloadError>,
    ) -> Result<(), PayloadError> {
        if !self.next_is(b'{') {
            return Err(self.error("expected an object"));
        }
        if self.next_is(b'}') {
            return Ok(());
        }
        loop {
            let key = self.string()?;
            if !self.next_is(b':') {
                return Err(self.error("expected `:`"));
            }
            member(self, key)?;
            if self.next_is(b'}') {
                return Ok(());
            }
            if !self.next_is(b',') {
                return Err(self.error("expected `,` or `}`"));
            }
        }
    }

    /// A string, decoded into a buffer the size of its encoded form, which
    /// a decoded string never exceeds, so it's never moved.
    fn string(&mut self) -> Result<String, PayloadError> {
        if !self.next_is(b'"') {
            return Err(self.error("expected a string"));
        }
        let bytes = self.text.as_bytes();
        let start = self.at;
        let mut end = start;
        loop {
            match bytes.get(end) {
                None => {
                    self.at = end;
                    return Err(self.error("unterminated string"));
                }
                Some(b'"') => break,
                Some(b'\\') => end += 2,
                Some(_) => end += 1,
            }
        }
        let mut decoded = Zeroizing::new(String::with_capacity(end - start));
        while self.at < end {
            let run = bytes[self.at..end]
                .iter()
                .position(|byte| *byte == b'\\' || *byte < 0x20)
                .map_or(end, |offset| self.at + offset);
            decoded.push_str(&self.text[self.at..run]);
            self.at = run;
            if self.at == end {
                break;
            }
            if bytes[self.at] < 0x20 {
                return Err(self.error("control character in a string"));
            }
            self.at += 1;
            let escaped = bytes.get(self.at).copied();
            self.at += 1;
            match escaped {
                Some(b'"') => decoded.push('"'),
                Some(b'\\') => decoded.push('\\'),
                Some(b'/') => decoded.push('/'),
                Some(b'b') => decoded.push('\u{8}'),
                Some(b'f') => decoded.push('\u{c}'),
                Some(b'n') => decoded.push('\n'),
                Some(b'r') => decoded.push('\r'),
                Some(b't') => decoded.push('\t'),
                Some(b'u') => decoded.push(self.unicode_escape(end)?),
                _ => return Err(self.error("invalid escape")),
            }
        }
        self.at = end + 1;
        Ok(std::mem::take(&mut *decoded))
    }

    /// The character a `\u` escape names, after its `\u`: a surrogate pair
    /// takes two escapes, and a lone surrogate is refused.
    fn unicode_escape(&mut self, end: usize) -> Result<char, PayloadError> {
        let high = self.hex4(end)?;
        let code = match high {
            0xD800..=0xDBFF => {
                if self.text.as_bytes().get(self.at..self.at + 2) != Some(b"\\u") {
                    return Err(self.error("lone leading surrogate in a \\u escape"));
                }
                self.at += 2;
                let low = self.hex4(end)?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.error("lone leading surrogate in a \\u escape"));
                }
                0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.error("lone trailing surrogate in a \\u escape")),
            code => code,
        };
        char::from_u32(code).ok_or_else(|| self.error("invalid \\u escape"))
    }

    fn hex4(&mut self, end: usize) -> Result<u32, PayloadError> {
        let digits = self
            .text
            .get(self.at..self.at + 4)
            .filter(|_| self.at + 4 <= end)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| self.error("invalid \\u escape"))?;
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|_| self.error("invalid \\u escape"))
    }
}

#[cfg(test)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteVaultPayload {
    #[serde(deserialize_with = "deserialize_environment_map")]
    environments: EnvironmentMap,
}

/// `parse_all` as serde parses it: the oracle the hand-written parser is
/// tested against.
#[cfg(test)]
fn parse_all_with_serde(json: &str) -> Result<EnvironmentMap, serde_json::Error> {
    let payload = serde_json::from_str::<CompleteVaultPayload>(json)?;
    let mut environments = payload.environments;
    if environments.is_empty() {
        environments.insert(DEFAULT_ENVIRONMENT.to_owned(), HashMap::new());
    }
    Ok(environments)
}

#[cfg(test)]
fn deserialize_environment_map<'de, D>(deserializer: D) -> Result<EnvironmentMap, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_map(EnvironmentMapVisitor)
}

#[cfg(test)]
struct EnvironmentMapVisitor;

#[cfg(test)]
impl<'de> Visitor<'de> for EnvironmentMapVisitor {
    type Value = EnvironmentMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an environment map with unique valid names")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut environments = HashMap::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(environment) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_environment_name(&environment) {
                return Err(A::Error::custom(format!(
                    "environment name {environment:?} is invalid"
                )));
            }
            let secrets = map.next_value_seed(RetainedSecretMapSeed)?;
            if environments
                .insert(environment.clone().into_owned(), secrets)
                .is_some()
            {
                return Err(A::Error::custom(format!(
                    "duplicate environment name {environment:?}"
                )));
            }
        }
        Ok(environments)
    }
}

pub(crate) enum SelectedVaultPayload {
    Versioned(Option<SecretMap>),
}

impl SelectedVaultPayload {
    pub(crate) fn into_selected(self) -> Option<SecretMap> {
        match self {
            Self::Versioned(selected) => selected,
        }
    }
}

pub(crate) fn validate_environments(environments: &EnvironmentMap) -> Result<(), String> {
    for (environment, secrets) in environments {
        if !is_valid_environment_name(environment) {
            return Err(format!("environment name {environment:?} is invalid"));
        }
        if let Some(variable) = secrets.keys().find(|name| !is_valid_variable_name(name)) {
            return Err(format!("env variable name {variable:?} is invalid"));
        }
    }
    Ok(())
}

/// The stored payload of `environments`. It holds the values, so it's wiped
/// when dropped, and no buffer it outgrows while being written keeps a copy.
pub(crate) fn serialize(environments: &EnvironmentMap) -> Result<Zeroizing<String>, String> {
    #[derive(serde::Serialize)]
    struct BorrowedPayload<'a> {
        environments: &'a EnvironmentMap,
    }

    validate_environments(environments)?;
    if environments.is_empty() {
        return Ok(Zeroizing::new(
            r#"{"environments":{"default":{}}}"#.to_owned(),
        ));
    }
    let mut payload = crate::wiping::WipingBuffer::with_capacity(unescaped_len(environments));
    serde_json::to_writer(&mut payload, &BorrowedPayload { environments })
        .map_err(|error| format!("failed to serialize environments: {error}"))?;
    crate::zeroizing_text(payload.into_bytes())
        .map_err(|_| "serialized environments are not UTF-8".to_owned())
}

/// Room for the payload when nothing in it needs escaping, a few bytes
/// over its length.
fn unescaped_len(environments: &EnvironmentMap) -> usize {
    // `{"environments":{` and `}}`; per environment `"name":{},`; per
    // value `"KEY":"value",`.
    environments.iter().fold(19, |length, (name, keys)| {
        keys.iter()
            .fold(length + name.len() + 6, |length, (key, value)| {
                length + key.len() + value.len() + 6
            })
    })
}

pub(crate) fn parse(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    parse_with_optional_fallback(json, selected_environment, false)
}

pub(crate) fn parse_with_default_fallback(
    json: &str,
    selected_environment: &str,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    parse_with_optional_fallback(json, selected_environment, true)
}

fn parse_with_optional_fallback(
    json: &str,
    selected_environment: &str,
    default_fallback: bool,
) -> Result<SelectedVaultPayload, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let payload = SelectedPayloadSeed {
        selected_environment,
        default_fallback,
    }
    .deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(payload)
}

struct SelectedPayloadSeed<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> DeserializeSeed<'de> for SelectedPayloadSeed<'_> {
    type Value = SelectedVaultPayload;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedPayloadVisitor {
            selected_environment: self.selected_environment,
            default_fallback: self.default_fallback,
        })
    }
}

struct SelectedPayloadVisitor<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> Visitor<'de> for SelectedPayloadVisitor<'_> {
    type Value = SelectedVaultPayload;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object containing exactly one environments map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut selected = None;
        let mut saw_environments = false;

        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key != "environments" {
                return Err(A::Error::unknown_field(&key, &["environments"]));
            }
            if saw_environments {
                return Err(A::Error::duplicate_field("environments"));
            }
            saw_environments = true;
            let parsed = map.next_value_seed(SelectedEnvironmentsSeed {
                selected_environment: self.selected_environment,
                default_fallback: self.default_fallback,
            })?;
            selected = if parsed.is_empty && self.selected_environment == DEFAULT_ENVIRONMENT {
                Some(HashMap::new())
            } else {
                parsed.selected
            };
        }

        if !saw_environments {
            return Err(A::Error::missing_field("environments"));
        }
        Ok(SelectedVaultPayload::Versioned(selected))
    }
}

struct SelectedEnvironments {
    selected: Option<SecretMap>,
    is_empty: bool,
}

struct SelectedEnvironmentsSeed<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> DeserializeSeed<'de> for SelectedEnvironmentsSeed<'_> {
    type Value = SelectedEnvironments;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SelectedEnvironmentsVisitor {
            selected_environment: self.selected_environment,
            default_fallback: self.default_fallback,
        })
    }
}

struct SelectedEnvironmentsVisitor<'selection> {
    selected_environment: &'selection str,
    default_fallback: bool,
}

impl<'de> Visitor<'de> for SelectedEnvironmentsVisitor<'_> {
    type Value = SelectedEnvironments;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an environment map")
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        visit_selected_environments_map(map, self.selected_environment, self.default_fallback)
    }
}

fn visit_selected_environments_map<'de, A>(
    mut map: A,
    selected_environment: &str,
    default_fallback: bool,
) -> Result<SelectedEnvironments, A::Error>
where
    A: MapAccess<'de>,
{
    let mut selected = None;
    let mut fallback = None;
    let mut names = HashSet::with_capacity(map.size_hint().unwrap_or_default());
    while let Some(environment) = map.next_key::<Cow<'de, str>>()? {
        if !is_valid_environment_name(&environment) {
            return Err(A::Error::custom(format!(
                "environment name {environment:?} is invalid"
            )));
        }
        if !names.insert(environment.clone().into_owned()) {
            return Err(A::Error::custom(format!(
                "duplicate environment name {environment:?}"
            )));
        }
        if environment == selected_environment {
            selected = Some(map.next_value_seed(RetainedSecretMapSeed)?);
        } else if default_fallback && environment == DEFAULT_ENVIRONMENT {
            fallback = Some(map.next_value_seed(RetainedSecretMapSeed)?);
        } else {
            map.next_value_seed(ValidateSecretMapSeed)?;
        }
    }
    let selected = if default_fallback
        && reads_default_environment(
            selected_environment,
            selected.as_ref().is_some_and(|values| !values.is_empty()),
        ) {
        fallback
    } else {
        selected
    };
    Ok(SelectedEnvironments {
        selected,
        is_empty: names.is_empty(),
    })
}

struct RetainedSecretMapSeed;

impl<'de> DeserializeSeed<'de> for RetainedSecretMapSeed {
    type Value = SecretMap;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RetainedSecretMapVisitor)
    }
}

struct RetainedSecretMapVisitor;

impl<'de> Visitor<'de> for RetainedSecretMapVisitor {
    type Value = SecretMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret map containing unique valid variable names and string values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut secrets = HashMap::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(variable) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_variable_name(&variable) {
                return Err(A::Error::custom(format!(
                    "env variable name {variable:?} is invalid"
                )));
            }
            let value = map.next_value::<Cow<'de, str>>()?.into_owned();
            if secrets
                .insert(variable.clone().into_owned(), value)
                .is_some()
            {
                return Err(A::Error::custom(format!(
                    "duplicate env variable name {variable:?}"
                )));
            }
        }
        Ok(secrets)
    }
}

struct ValidateSecretMapSeed;

impl<'de> DeserializeSeed<'de> for ValidateSecretMapSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ValidateSecretMapVisitor)
    }
}

struct ValidateSecretMapVisitor;

impl<'de> Visitor<'de> for ValidateSecretMapVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a secret map containing string values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = HashSet::with_capacity(map.size_hint().unwrap_or_default());
        while let Some(variable) = map.next_key::<Cow<'de, str>>()? {
            if !is_valid_variable_name(&variable) {
                return Err(A::Error::custom(format!(
                    "env variable name {variable:?} is invalid"
                )));
            }
            if !names.insert(variable.clone().into_owned()) {
                return Err(A::Error::custom(format!(
                    "duplicate env variable name {variable:?}"
                )));
            }
            map.next_value_seed(ValidateStringSeed)?;
        }
        Ok(())
    }
}

struct ValidateStringSeed;

impl<'de> DeserializeSeed<'de> for ValidateStringSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(ValidateStringVisitor)
    }
}

struct ValidateStringVisitor;

impl Visitor<'_> for ValidateStringVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string secret value")
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_parser_agrees_with_serde_on_every_payload() {
        let cases = [
            r#"{"environments":{}}"#,
            r#"{"environments":{"default":{"A":"1"}}}"#,
            " { \"environments\" : { \"default\" : { \"A\" : \"1\" , \"B\" : \"\" } ,\n\t\"staging\" : { } } }\r\n",
            r#"{"environments":{"default":{"A":"line\nbreak \"quoted\" back\\slash \/ \b\f\r\t"}}}"#,
            r#"{"environments":{"default":{"A":"é中😀 \u0000 ﻿"}}}"#,
            r#"{"environments":{"default":{"A":"é中😀"}}}"#,
            r#"{"environments":{"default":{"A":"x"}}}"#,
            "",
            "{",
            "{}",
            "null",
            "[]",
            r#"{"environments":null}"#,
            r#"{"environments":[]}"#,
            r#"{"environments":{"default":{"A":1}}}"#,
            r#"{"environments":{"default":{"A":null}}}"#,
            r#"{"environments":{"default":{"A":{"B":"c"}}}}"#,
            r#"{"environments":{"default":{"A":"1"}}} x"#,
            r#"{"environments":{"default":{"A":"1"}}}}"#,
            r#"{"environments":{},"extra":true}"#,
            r#"{"environments":{},"environments":{}}"#,
            r#"{"environments":{"default":{},"default":{}}}"#,
            r#"{"environments":{"default":{"A":"1","A":"2"}}}"#,
            r#"{"environments":{"bad name":{}}}"#,
            r#"{"environments":{"default":{"1BAD":"x"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83d"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83dx"}}}"#,
            r#"{"environments":{"default":{"A":"\ud83dA"}}}"#,
            r#"{"environments":{"default":{"A":"\ude00"}}}"#,
            r#"{"environments":{"default":{"A":"\x"}}}"#,
            r#"{"environments":{"default":{"A":"\u12"}}}"#,
            r#"{"environments":{"default":{"A":"\u12g4"}}}"#,
            "{\"environments\":{\"default\":{\"A\":\"tab\there\"}}}",
            "{\"environments\":{\"default\":{\"A\":\"new\nline\"}}}",
            r#"{"environments":{"default":{"A":"1",}}}"#,
            r#"{"environments":{"default":{"A" "1"}}}"#,
            r#"{"environments":{"default":{"A":"unterminated}}}"#,
            r#"{"environments":{"default":{"A":"ends in a backslash\"#,
            "\u{feff}{\"environments\":{}}",
        ];
        for case in cases {
            match (parse_all(case), parse_all_with_serde(case)) {
                (Ok(ours), Ok(serde)) => assert_eq!(ours, serde, "{case:?}"),
                (Err(_), Err(_)) => {}
                (ours, serde) => panic!("{case:?}: ours {ours:?}, serde {serde:?}"),
            }
        }
    }

    #[test]
    fn the_payload_parser_reads_back_whatever_serialize_writes() {
        let values = (0_u32..0x250)
            .chain([0x2028, 0x2029, 0xFEFF, 0x1F600])
            .filter_map(char::from_u32)
            .map(|character| format!("a{character}b"));
        let environments = EnvironmentMap::from([
            (
                "default".to_owned(),
                values
                    .enumerate()
                    .map(|(index, value)| (format!("KEY_{index}"), value))
                    .collect(),
            ),
            ("empty".to_owned(), SecretMap::new()),
        ]);
        let serialized = serialize(&environments).expect("serializes");
        assert_eq!(parse_all(&serialized).expect("parses"), environments);
        assert_eq!(
            parse_all_with_serde(&serialized).expect("parses"),
            environments
        );
    }

    #[cfg(not(miri))]
    #[test]
    fn parsing_escaped_values_leaves_no_copy_of_them_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        // A newline and a quote need escaping, as in a PEM private key.
        let payload = format!(
            r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n-----END-----","QUOTED":"say \"{MARKER}\""}}}}}}"#
        );
        let (read, found) = watch(|| {
            let mut environments = parse_all(&payload).expect("parses");
            let key = &environments["default"]["KEY"];
            let read = key.strip_prefix(MARKER) == Some("\n-----END-----");
            crate::history::wipe_values(&mut environments);
            read
        });
        assert!(read);
        assert!(!found, "no buffer the parser used keeps an escaped value");

        let truncated = format!(r#"{{"environments":{{"default":{{"KEY":"{MARKER}\n"#);
        let (failed, found) = watch(|| parse_all(&truncated).is_err());
        assert!(failed);
        assert!(
            !found,
            "a payload that doesn't parse leaves nothing behind either"
        );
    }

    #[test]
    fn a_payload_with_nothing_to_escape_is_written_without_moving() {
        let environments = EnvironmentMap::from([
            (
                "default".to_owned(),
                SecretMap::from([
                    ("API_KEY".to_owned(), "abc123".to_owned()),
                    ("EMPTY".to_owned(), String::new()),
                ]),
            ),
            ("preview".to_owned(), SecretMap::new()),
        ]);
        let serialized = serialize(&environments).expect("serialize");
        assert_eq!(parse_all(&serialized).expect("parse"), environments);
        assert_eq!(serialized.capacity(), unescaped_len(&environments));
        assert!(unescaped_len(&environments) - serialized.len() < 8);
    }

    #[cfg(not(miri))]
    #[test]
    fn serializing_values_leaves_no_copy_of_them_in_freed_memory() {
        use crate::freed_memory_probe::{MARKER, watch};
        // Control characters are written as six-byte escapes, so the
        // payload outgrows a buffer sized from the values' own lengths.
        let environments = EnvironmentMap::from([(
            "default".to_owned(),
            (0..64)
                .map(|index| {
                    (
                        format!("KEY_{index}"),
                        format!("{MARKER}\"{index}\n{}", "\u{1}".repeat(index)),
                    )
                })
                .collect(),
        )]);
        let (serialized, found) = watch(|| serialize(&environments).expect("serialize"));
        assert!(
            serialized.len() > unescaped_len(&environments),
            "the payload outgrew its first buffer"
        );
        assert!(!found, "no buffer outgrown while writing keeps a copy");
        assert_eq!(parse_all(&serialized).expect("parse"), environments);
        let ((), found) = watch(move || drop(serialized));
        assert!(!found, "the payload is wiped when dropped");
    }

    #[test]
    fn selects_only_the_requested_versioned_environment() {
        let payload = parse(
            r#"{"environments":{"default":{"A":"one"},"live":{"B":"two"}}}"#,
            "live",
        )
        .expect("parse versioned payload");

        assert_eq!(
            payload.into_selected(),
            Some(HashMap::from([("B".to_owned(), "two".to_owned())]))
        );
    }

    #[test]
    fn validates_an_unselected_environment_without_retaining_it() {
        let error = parse(
            r#"{"environments":{"default":{"A":"one"},"live":{"BROKEN":7}}}"#,
            "default",
        )
        .err()
        .expect("malformed unselected environment must be rejected");

        assert!(error.to_string().contains("string secret value"), "{error}");
    }

    #[test]
    fn rejects_legacy_flat_payload_selection() {
        assert!(parse(r#"{"A":"one"}"#, "default").is_err());
    }

    #[test]
    fn rejects_a_string_instead_of_the_environments_map() {
        assert!(parse(r#"{"environments":"legacy-value"}"#, "default").is_err());
    }

    #[test]
    fn selects_requested_or_default_in_one_validating_pass() {
        let payload = r#"{"environments":{"default":{"A":"fallback"},"empty":{},"live":{"A":"selected"},"other":{"B":"validated"}}}"#;

        assert_eq!(
            parse_with_default_fallback(payload, "live")
                .expect("select populated environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "selected".to_owned())]))
        );
        assert_eq!(
            parse_with_default_fallback(payload, "empty")
                .expect("fall back from empty environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "fallback".to_owned())]))
        );
        assert_eq!(
            parse_with_default_fallback(payload, "missing")
                .expect("fall back from missing environment")
                .into_selected(),
            Some(HashMap::from([("A".to_owned(), "fallback".to_owned())]))
        );
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        assert!(parse(r#"{"environments":{"default":{}},"version":3}"#, "default").is_err());
        assert!(parse_all(r#"{"environments":{},"extra":true}"#).is_err());
    }

    #[test]
    fn rejects_duplicate_top_level_environment_and_variable_keys() {
        assert!(parse(r#"{"environments":{},"environments":{}}"#, "default").is_err());
        assert!(parse_all(r#"{"environments":{"default":{},"default":{}}}"#).is_err());
        assert!(
            parse(
                r#"{"environments":{"default":{"TOKEN":"one","TOKEN":"two"}}}"#,
                "default"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_environment_and_variable_names() {
        let oversized = "a".repeat(65);
        for environment in ["", "../live", "__index__", "live/team", oversized.as_str()] {
            let payload = format!(r#"{{"environments":{{"{environment}":{{}}}}}}"#);
            assert!(parse_all(&payload).is_err(), "accepted {environment:?}");
        }
        for variable in ["", "1TOKEN", "BAD-NAME", "ÜNICODE"] {
            let payload = format!(r#"{{"environments":{{"default":{{"{variable}":"x"}}}}}}"#);
            assert!(parse_all(&payload).is_err(), "accepted {variable:?}");
        }
    }

    #[test]
    fn normalizes_an_empty_environment_wrapper_to_default() {
        assert_eq!(
            parse_all(r#"{"environments":{}}"#).unwrap(),
            HashMap::from([("default".to_owned(), HashMap::new())])
        );
        assert_eq!(
            parse(r#"{"environments":{}}"#, "default")
                .unwrap()
                .into_selected(),
            Some(HashMap::new())
        );
    }
}
