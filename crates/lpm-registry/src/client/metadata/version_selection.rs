use super::VersionMetadata;
use serde::de::{DeserializeSeed, Error, IgnoredAny, MapAccess, Visitor};
use std::borrow::Cow;

pub(super) struct SelectedVersion {
    pub(super) manifest: VersionMetadata,
    pub(super) published_at: Option<String>,
}

pub(super) fn parse_selected_version(
    bytes: &[u8],
    name: &str,
    version: &str,
) -> Result<SelectedVersion, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let selected = PackageSeed { name, version }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(selected)
}

struct PackageSeed<'a> {
    name: &'a str,
    version: &'a str,
}

impl<'de> DeserializeSeed<'de> for PackageSeed<'_> {
    type Value = SelectedVersion;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for PackageSeed<'_> {
    type Value = SelectedVersion;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a full npm package history")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut name_seen = false;
        let mut versions_seen = false;
        let mut selected = None;
        let mut published_at = None;
        while let Some(field) = map.next_key_seed(StringSeed)? {
            match field.as_ref() {
                "name" => {
                    if name_seen {
                        return Err(M::Error::duplicate_field("name"));
                    }
                    name_seen = true;
                    let actual = map.next_value_seed(StringSeed)?;
                    if actual != self.name {
                        return Err(M::Error::custom(
                            "package history name does not match the requested package",
                        ));
                    }
                }
                "versions" => {
                    if versions_seen {
                        return Err(M::Error::duplicate_field("versions"));
                    }
                    versions_seen = true;
                    selected = map.next_value_seed(VersionsSeed {
                        version: self.version,
                    })?;
                }
                "time" => {
                    published_at = map.next_value_seed(PublicationTimeSeed {
                        version: self.version,
                    })?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if !name_seen {
            return Err(M::Error::missing_field("name"));
        }
        if !versions_seen {
            return Err(M::Error::missing_field("versions"));
        }
        let selected = selected.ok_or_else(|| {
            M::Error::custom("requested version is absent from the package history")
        })?;
        if selected.name != self.name || selected.version != self.version {
            return Err(M::Error::custom(
                "selected manifest identity does not match the requested version",
            ));
        }
        Ok(SelectedVersion {
            manifest: selected,
            published_at,
        })
    }
}

struct PublicationTimeSeed<'a> {
    version: &'a str,
}

impl<'de> DeserializeSeed<'de> for PublicationTimeSeed<'_> {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for PublicationTimeSeed<'_> {
    type Value = Option<String>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("optional npm publication timestamps")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut selected = None;
        while let Some(version) = map.next_key_seed(StringSeed)? {
            if version == self.version {
                selected = map.next_value_seed(OptionalTimestamp)?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(selected)
    }
    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_str<E: Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

struct OptionalTimestamp;

impl<'de> DeserializeSeed<'de> for OptionalTimestamp {
    type Value = Option<String>;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for OptionalTimestamp {
    type Value = Option<String>;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an optional publication timestamp")
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Some(value.to_owned()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Some(value))
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }
    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_bool<E: Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
}

struct VersionsSeed<'a> {
    version: &'a str,
}

impl<'de> DeserializeSeed<'de> for VersionsSeed<'_> {
    type Value = Option<VersionMetadata>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for VersionsSeed<'_> {
    type Value = Option<VersionMetadata>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("npm versions keyed by version")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut selected = None;
        while let Some(version) = map.next_key_seed(StringSeed)? {
            if version == self.version {
                selected = Some(map.next_value()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(selected)
    }
}

pub(super) struct StringSeed;

impl<'de> DeserializeSeed<'de> for StringSeed {
    type Value = Cow<'de, str>;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for StringSeed {
    type Value = Cow<'de, str>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON string")
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(Cow::Borrowed(value))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Cow::Owned(value.to_owned()))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Cow::Owned(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_preserves_platform_and_dependencies_without_parsing_other_manifests() {
        let bytes = br#"{"name":"pkg","versions":{"0.0.1":42,"1.0.0":{"name":"pkg","version":"1.0.0","libc":["glibc"],"dependencies":{"alias":"npm:child@^1"},"peerDependencies":{"peer":"^2"}},"9.0.0":[null]},"dist-tags":{"latest":"9.0.0"}}"#;
        let selected = parse_selected_version(bytes, "pkg", "1.0.0").unwrap();
        assert_eq!(selected.manifest.libc, vec!["glibc"]);
        assert_eq!(
            selected
                .manifest
                .dependencies
                .get("alias")
                .map(String::as_str),
            Some("npm:child@^1")
        );
        assert_eq!(
            selected
                .manifest
                .peer_dependencies
                .get("peer")
                .map(String::as_str),
            Some("^2")
        );
    }

    #[test]
    fn selection_accepts_escaped_keys_and_uses_the_last_selected_version_record() {
        let bytes = br#"{"na\u006de":"pkg","versions":{"1.0.0":{"name":"wrong","version":"1.0.0"},"1.0.\u0030":{"name":"pkg","version":"1.0.0"}}}"#;
        assert_eq!(
            parse_selected_version(bytes, "pkg", "1.0.0")
                .unwrap()
                .manifest
                .name,
            "pkg"
        );
    }

    #[test]
    fn selection_retains_only_the_requested_publication_time_in_any_field_order() {
        for bytes in [
            r#"{"time":{"1.0.0":"2025-01-01","2.0.0":[]},"name":"pkg","versions":{"1.0.0":{"name":"pkg","version":"1.0.0"}}}"#,
            r#"{"name":"pkg","versions":{"1.0.0":{"name":"pkg","version":"1.0.0"}},"time":{"2.0.0":{},"1.0.0":"2025-01-01"}}"#,
        ] {
            let selected = parse_selected_version(bytes.as_bytes(), "pkg", "1.0.0").unwrap();
            assert_eq!(selected.published_at.as_deref(), Some("2025-01-01"));
        }
    }

    #[test]
    fn unusable_optional_publication_time_does_not_reject_valid_manifests() {
        for time in [
            "null",
            "false",
            "42",
            "1.5",
            r#""unknown""#,
            "[]",
            "{}",
            r#"{"1.0.0":{}}"#,
            r#"{"1.0.0":null}"#,
        ] {
            let bytes = format!(
                r#"{{"name":"pkg","versions":{{"1.0.0":{{"name":"pkg","version":"1.0.0"}}}},"time":{time}}}"#
            );
            let selected = parse_selected_version(bytes.as_bytes(), "pkg", "1.0.0").unwrap();
            assert!(selected.published_at.is_none(), "{time}");
        }
    }

    #[test]
    fn selected_timestamp_preserves_escaped_strings_and_last_occurrence() {
        for (time, expected) in [
            (r#"{"1.0.0":"\u0032first"}"#, Some("2first")),
            (r#"{"1.0.0":{},"1.0.0":"second"}"#, Some("second")),
            (
                r#"{"1.0.0":"first","1.0.0":[{"ignored":[null,true,1.5]}]}"#,
                None,
            ),
        ] {
            let body = format!(
                r#"{{"name":"pkg","versions":{{"1.0.0":{{"name":"pkg","version":"1.0.0"}}}},"time":{time}}}"#
            );
            let selected = parse_selected_version(body.as_bytes(), "pkg", "1.0.0").unwrap();
            assert_eq!(selected.published_at.as_deref(), expected);
        }
    }

    #[test]
    fn selection_rejects_invalid_identities_duplicate_fields_and_trailing_data() {
        for bytes in [
            r#"{"name":"other","versions":{"1.0.0":{"name":"pkg","version":"1.0.0"}}}"#,
            r#"{"name":"pkg","versions":{"1.0.0":{"name":"other","version":"1.0.0"}}}"#,
            r#"{"name":"pkg","versions":{"1.0.0":{"name":"pkg","version":"2.0.0"}}}"#,
            r#"{"name":"pkg","versions":{}}"#,
            r#"{"name":"pkg","name":"pkg","versions":{}}"#,
            r#"{"name":"pkg","versions":{},"versions":{}}"#,
            r#"{"name":"pkg","versions":{"1.0.0":{"name":"pkg","version":"1.0.0"}}} {}"#,
            r#"{"name":"pkg","versions":{"0.0.1":[},"1.0.0":{"name":"pkg","version":"1.0.0"}}}"#,
        ] {
            assert!(
                parse_selected_version(bytes.as_bytes(), "pkg", "1.0.0").is_err(),
                "{bytes}"
            );
        }
    }
}
