//! The companion contract fixtures the LPM Vault app's tests read too.

use serde::Deserialize;

use super::account::CompanionAccount;
#[cfg(target_os = "macos")]
use super::graph::{AccessClass, record_access_class};
use super::lifecycle::needs_resume;
use super::marker::{Level, Marker};
use super::overrides::parse_selected;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture<T> {
    schema_version: u8,
    cases: Vec<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkerCase {
    name: String,
    vault_id: String,
    json: String,
    valid: bool,
    level: Option<Level>,
    needs_resume: Option<bool>,
}

#[test]
fn every_marker_fixture_validates_and_levels_as_recorded() {
    let fixture: Fixture<MarkerCase> =
        serde_json::from_str(include_str!("../../tests/fixtures/companion/markers.json"))
            .expect("marker fixtures decode");
    assert_eq!(fixture.schema_version, 1);
    for case in fixture.cases {
        let parsed = Marker::parse(&case.vault_id, case.json.as_bytes());
        assert_eq!(parsed.is_ok(), case.valid, "{}: {parsed:?}", case.name);
        if let Ok(marker) = parsed {
            assert_eq!(Some(marker.level()), case.level, "{}", case.name);
            assert_eq!(
                Some(needs_resume(&marker)),
                case.needs_resume,
                "{}",
                case.name
            );
            assert_eq!(
                marker.encode().expect("a valid marker encodes"),
                case.json.as_bytes(),
                "{} has one spelling",
                case.name
            );
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountCase {
    account: String,
    valid: bool,
    #[serde(rename = "type")]
    kind_of_account: Option<String>,
    vault_id: Option<String>,
    kind: Option<String>,
    part: Option<u16>,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    access_class: Option<String>,
}

#[test]
fn every_account_fixture_parses_as_recorded() {
    let fixture: Fixture<AccountCase> =
        serde_json::from_str(include_str!("../../tests/fixtures/companion/accounts.json"))
            .expect("account fixtures decode");
    for case in fixture.cases {
        let parsed = CompanionAccount::parse(&case.account);
        assert_eq!(parsed.is_some(), case.valid, "{}", case.account);
        let Some(parsed) = parsed else {
            continue;
        };
        let expected_type = match &parsed {
            CompanionAccount::Marker { .. } => "marker",
            CompanionAccount::Record { .. } => "record",
            CompanionAccount::Staged { .. } => "staged",
        };
        assert_eq!(
            case.kind_of_account.as_deref(),
            Some(expected_type),
            "{}",
            case.account
        );
        assert_eq!(
            case.vault_id.as_deref(),
            Some(parsed.vault_id()),
            "{}",
            case.account
        );
        assert_eq!(case.kind.as_deref(), parsed.kind(), "{}", case.account);
        assert_eq!(case.part, parsed.part(), "{}", case.account);
        #[cfg(target_os = "macos")]
        if let Some(kind) = parsed.kind() {
            let class = match record_access_class(kind, parsed.part()) {
                AccessClass::Open => "open",
                AccessClass::FollowsValues => "followsValues",
            };
            assert_eq!(
                case.access_class.as_deref(),
                Some(class),
                "{}",
                case.account
            );
        }
        assert_eq!(parsed.name(), case.account);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverridesCase {
    name: String,
    vault_id: String,
    version: u16,
    environment: String,
    json: String,
    valid: bool,
    #[serde(default)]
    set: std::collections::HashMap<String, String>,
    #[serde(default)]
    unset: Vec<String>,
}

#[test]
fn every_overrides_fixture_validates_and_selects_as_recorded() {
    let fixture: Fixture<OverridesCase> = serde_json::from_str(include_str!(
        "../../tests/fixtures/companion/overrides.json"
    ))
    .expect("overrides fixtures decode");
    for case in fixture.cases {
        let parsed = parse_selected(
            case.json.as_bytes(),
            &case.vault_id,
            case.version,
            &case.environment,
        );
        assert_eq!(parsed.is_ok(), case.valid, "{}: {parsed:?}", case.name);
        if let Ok(overrides) = parsed {
            assert_eq!(overrides.set, case.set, "{}", case.name);
            assert_eq!(overrides.unset, case.unset, "{}", case.name);
        }
    }
}
