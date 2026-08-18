use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};

#[derive(Clone, Copy)]
struct CowStrSeed;

impl<'de> DeserializeSeed<'de> for CowStrSeed {
    type Value = Cow<'de, str>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CowStrVisitor)
    }
}

struct CowStrVisitor;

impl<'de> Visitor<'de> for CowStrVisitor {
    type Value = Cow<'de, str>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Borrowed(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Owned(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Cow::Owned(value))
    }
}

pub(super) fn modern_claims_binary(content: &str, binary: &str) -> Result<bool, String> {
    let mut deserializer = serde_json::Deserializer::from_str(content);
    let owned = RootSeed {
        section: "installs",
        binary,
        format: RecordFormat::Modern,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(owned)
}

pub(super) fn legacy_claims_binary(content: &str, binary: &str) -> Result<bool, String> {
    RootSeed {
        section: "v1",
        binary,
        format: RecordFormat::Legacy,
    }
    .deserialize(toml::Deserializer::new(content))
    .map_err(|error| error.to_string())
}

#[derive(Clone, Copy)]
enum RecordFormat {
    Modern,
    Legacy,
}

struct RootSeed<'a> {
    section: &'static str,
    binary: &'a str,
    format: RecordFormat,
}

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RootVisitor {
            section: self.section,
            binary: self.binary,
            format: self.format,
        })
    }
}

struct RootVisitor<'a> {
    section: &'static str,
    binary: &'a str,
    format: RecordFormat,
}

impl<'de> Visitor<'de> for RootVisitor<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cargo install metadata object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut owned = None;
        while let Some(key) = map.next_key_seed(CowStrSeed)? {
            if key == self.section {
                if owned.is_some() {
                    return Err(M::Error::duplicate_field(self.section));
                }
                owned = Some(map.next_value_seed(InstallsSeed {
                    binary: self.binary,
                    format: self.format,
                })?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        owned.ok_or_else(|| M::Error::missing_field(self.section))
    }
}

struct InstallsSeed<'a> {
    binary: &'a str,
    format: RecordFormat,
}

impl<'de> DeserializeSeed<'de> for InstallsSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(InstallsVisitor {
            binary: self.binary,
            format: self.format,
        })
    }
}

struct InstallsVisitor<'a> {
    binary: &'a str,
    format: RecordFormat,
}

impl<'de> Visitor<'de> for InstallsVisitor<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cargo installed-package map")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut matching_records = HashMap::new();
        while let Some(package) = map.next_key_seed(CowStrSeed)? {
            let record_owned = match self.format {
                RecordFormat::Modern => map.next_value_seed(ModernRecordSeed {
                    binary: self.binary,
                })?,
                RecordFormat::Legacy => map.next_value_seed(BinaryListSeed {
                    binary: self.binary,
                })?,
            };
            if package.starts_with("lpm-cli ") {
                matching_records.insert(package, record_owned);
            }
        }
        Ok(matching_records.into_values().any(|owned| owned))
    }
}

struct ModernRecordSeed<'a> {
    binary: &'a str,
}

impl<'de> DeserializeSeed<'de> for ModernRecordSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ModernRecordVisitor {
            binary: self.binary,
        })
    }
}

struct ModernRecordVisitor<'a> {
    binary: &'a str,
}

impl<'de> Visitor<'de> for ModernRecordVisitor<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cargo install record")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut owned = None;
        while let Some(key) = map.next_key_seed(CowStrSeed)? {
            if key == "bins" {
                if owned.is_some() {
                    return Err(M::Error::duplicate_field("bins"));
                }
                owned = Some(map.next_value_seed(BinaryListSeed {
                    binary: self.binary,
                })?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        owned.ok_or_else(|| M::Error::missing_field("bins"))
    }
}

struct BinaryListSeed<'a> {
    binary: &'a str,
}

impl<'de> DeserializeSeed<'de> for BinaryListSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BinaryListVisitor {
            binary: self.binary,
        })
    }
}

struct BinaryListVisitor<'a> {
    binary: &'a str,
}

impl<'de> Visitor<'de> for BinaryListVisitor<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cargo binary-name array")
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        let mut owned = false;
        while let Some(binary) = sequence.next_element_seed(CowStrSeed)? {
            owned |= binary == self.binary;
        }
        Ok(owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct RetainedModernMetadata {
        installs: HashMap<String, RetainedModernRecord>,
    }

    #[derive(serde::Deserialize)]
    struct RetainedModernRecord {
        bins: Vec<String>,
    }

    fn retained_modern_claims_binary(content: &str, binary: &str) -> Result<bool, String> {
        let parsed: RetainedModernMetadata =
            serde_json::from_str(content).map_err(|error| error.to_string())?;
        Ok(parsed.installs.iter().any(|(package, record)| {
            package.starts_with("lpm-cli ") && record.bins.iter().any(|bin| bin == binary)
        }))
    }

    #[test]
    fn modern_metadata_validates_trailing_records_after_a_match() {
        let malformed = r#"{"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]}},"later":}"#;

        assert!(modern_claims_binary(malformed, "lpm").is_err());
    }

    #[test]
    fn modern_metadata_finds_a_matching_last_record() {
        let content =
            r#"{"installs":{"other 1.0.0":{"bins":["other"]},"lpm-cli 1.0.0":{"bins":["lpm"]}}}"#;

        assert_eq!(modern_claims_binary(content, "lpm"), Ok(true));
    }

    #[test]
    fn modern_metadata_rejects_an_invalid_unrelated_record() {
        let content =
            r#"{"installs":{"other 1.0.0":{"bins":"other"},"lpm-cli 1.0.0":{"bins":["lpm"]}}}"#;

        assert!(modern_claims_binary(content, "lpm").is_err());
    }

    #[test]
    fn modern_metadata_rejects_duplicate_installs_sections() {
        let content = r#"{"installs":{},"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]}}}"#;

        assert!(modern_claims_binary(content, "lpm").is_err());
    }

    #[test]
    fn modern_metadata_rejects_duplicate_bins_fields() {
        let content = r#"{"installs":{"lpm-cli 1.0.0":{"bins":["other"],"bins":["lpm"]}}}"#;

        assert!(modern_claims_binary(content, "lpm").is_err());
    }

    #[test]
    fn modern_metadata_uses_the_last_duplicate_package_record() {
        let content =
            r#"{"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]},"lpm-cli 1.0.0":{"bins":["other"]}}}"#;

        assert_eq!(modern_claims_binary(content, "lpm"), Ok(false));
    }

    #[test]
    fn modern_metadata_rejects_a_record_without_bins() {
        let content = r#"{"installs":{"lpm-cli 1.0.0":{"features":[]}}}"#;

        assert!(modern_claims_binary(content, "lpm").is_err());
    }

    #[test]
    fn modern_streaming_parser_matches_the_retained_contract_corpus() {
        let corpus = [
            r#"{"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]}}}"#,
            r#"{"installs":{"other 1.0.0":{"bins":["other"]}}}"#,
            r#"{"installs":{"other 1.0.0":{"bins":"other"}}}"#,
            r#"{"installs":{"lpm-cli 1.0.0":{"features":[]}}}"#,
            r#"{"installs":{},"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]}}}"#,
            r#"{"installs":{"lpm-cli 1.0.0":{"bins":["other"],"bins":["lpm"]}}}"#,
            r#"{"installs":{"lpm-cli 1.0.0":{"bins":["lpm"]},"lpm-cli 1.0.0":{"bins":["other"]}}}"#,
            r#"{"other":true}"#,
            r#"{"installs":{}} trailing"#,
        ];

        for content in corpus {
            assert_eq!(
                modern_claims_binary(content, "lpm").map_err(|_| ()),
                retained_modern_claims_binary(content, "lpm").map_err(|_| ()),
                "contract mismatch for {content}"
            );
        }
    }

    #[test]
    fn legacy_metadata_finds_a_matching_binary() {
        let content = r#"[v1]
"other 1.0.0 (registry+example)" = ["other"]
"lpm-cli 1.0.0 (registry+example)" = ["lpm-rs"]
"#;

        assert_eq!(legacy_claims_binary(content, "lpm-rs"), Ok(true));
    }

    #[test]
    fn legacy_metadata_rejects_an_invalid_unrelated_record() {
        let content = r#"[v1]
"other 1.0.0 (registry+example)" = "other"
"lpm-cli 1.0.0 (registry+example)" = ["lpm-rs"]
"#;

        assert!(legacy_claims_binary(content, "lpm-rs").is_err());
    }

    #[test]
    #[ignore = "manual release-mode Cargo metadata parser memory and latency probe"]
    fn modern_metadata_parser_probe_reports_latency_at_the_input_cap() {
        use std::fmt::Write as _;

        let input_target = std::env::var("LPM_CARGO_METADATA_BENCH_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(4 * 1024 * 1024 - 256);
        let position = std::env::var("LPM_CARGO_METADATA_BENCH_POSITION")
            .unwrap_or_else(|_| "last".to_string());

        let mut content = String::with_capacity(input_target + 256);
        content.push_str("{\"installs\":{");
        let mut needs_comma = false;
        if position == "first" {
            content.push_str("\"lpm-cli 1.0.0\":{\"bins\":[\"lpm\"]}");
            needs_comma = true;
        }
        let mut index = 0_u32;
        while content.len() < input_target {
            if needs_comma {
                content.push(',');
            }
            write!(
                &mut content,
                "\"package-{index} 1.0.0\":{{\"bins\":[\"package-{index}\"]}}"
            )
            .unwrap();
            needs_comma = true;
            index += 1;
        }
        if position == "last" {
            if needs_comma {
                content.push(',');
            }
            content.push_str("\"lpm-cli 1.0.0\":{\"bins\":[\"lpm\"]}");
        } else if position != "first" && position != "absent" {
            panic!("unknown LPM_CARGO_METADATA_BENCH_POSITION `{position}`");
        }
        content.push_str("}}");
        let expected = position != "absent";

        let mode = std::env::var("LPM_CARGO_METADATA_BENCH_MODE")
            .unwrap_or_else(|_| "streaming".to_string());
        let started = std::time::Instant::now();
        let owned = match mode.as_str() {
            "streaming" => modern_claims_binary(&content, "lpm").unwrap(),
            "retained" => retained_modern_claims_binary(&content, "lpm").unwrap(),
            "fixture" => expected,
            other => panic!("unknown LPM_CARGO_METADATA_BENCH_MODE `{other}`"),
        };

        assert_eq!(owned, expected);
        std::hint::black_box(&content);
        eprintln!(
            "cargo_metadata mode={mode} position={position} bytes={} records={index} elapsed_us={}",
            content.len(),
            started.elapsed().as_micros()
        );
    }
}
