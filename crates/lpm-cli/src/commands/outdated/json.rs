use super::{LookupFailure, OUTDATED_JSON_SCHEMA_VERSION, OutdatedResult};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use std::collections::BTreeSet;

pub(super) fn write(
    writer: impl std::io::Write,
    results: &[OutdatedResult],
    failures: &[LookupFailure],
    skipped_private: &BTreeSet<String>,
    skipped_non_registry: &BTreeSet<String>,
) -> serde_json::Result<()> {
    serde_json::to_writer_pretty(
        writer,
        &OutdatedJson {
            results,
            failures,
            skipped_private,
            skipped_non_registry,
        },
    )
}

struct OutdatedJson<'a> {
    results: &'a [OutdatedResult],
    failures: &'a [LookupFailure],
    skipped_private: &'a BTreeSet<String>,
    skipped_non_registry: &'a BTreeSet<String>,
}

impl Serialize for OutdatedJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("schema_version", &OUTDATED_JSON_SCHEMA_VERSION)?;
        map.serialize_entry("success", &self.failures.is_empty())?;
        map.serialize_entry("packages", &PackageRows(self.results))?;
        map.serialize_entry("count", &self.results.len())?;
        map.serialize_entry(
            "outdated_count",
            &self.results.iter().filter(|result| result.outdated).count(),
        )?;
        if !self.failures.is_empty() {
            map.serialize_entry("unresolved", &FailureRows(self.failures))?;
            map.serialize_entry("unresolved_count", &self.failures.len())?;
            map.serialize_entry(
                "error",
                &format!(
                    "could not check {} package(s) due to registry lookup failures",
                    self.failures.len()
                ),
            )?;
            map.serialize_entry("error_code", "registry")?;
        }
        if !self.skipped_private.is_empty() {
            map.serialize_entry("skipped_private_count", &self.skipped_private.len())?;
            map.serialize_entry("skipped_private", self.skipped_private)?;
            map.serialize_entry("skipped_private_reason", "Packages without a recorded public npm or LPM-registry source were skipped to avoid leaking private names to registry.npmjs.org. Run `lpm install` to resolve sources, then re-run.")?;
        }
        if !self.skipped_non_registry.is_empty() {
            map.serialize_entry(
                "skipped_non_registry_count",
                &self.skipped_non_registry.len(),
            )?;
            map.serialize_entry("skipped_non_registry", self.skipped_non_registry)?;
            map.serialize_entry("skipped_non_registry_reason", "Local, workspace, Git, tarball, and JSR dependencies do not use registry version metadata and were skipped.")?;
        }
        map.end()
    }
}

struct PackageRows<'a>(&'a [OutdatedResult]);
impl Serialize for PackageRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|result| {
            serde_json::json!({
                "name": result.name,
                "current": result.current,
                "wanted": result.wanted,
                "wanted_range": result.wanted_range,
                "latest": result.latest,
                "section": result.section,
                "outdated": result.outdated,
            })
        }))
    }
}

struct FailureRows<'a>(&'a [LookupFailure]);
impl Serialize for FailureRows<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|failure| {
            serde_json::json!({
                "name": failure.name,
                "section": failure.section,
                "reason": failure.reason.as_ref(),
            })
        }))
    }
}
