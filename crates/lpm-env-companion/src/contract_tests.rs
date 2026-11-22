//! The companion contract fixtures the LPM Vault app's tests read too.

use serde::Deserialize;

use crate::account::CompanionAccount;
use crate::graph::{AccessClass, record_access_class};
use crate::lifecycle::needs_resume;
use crate::marker::{Level, Marker};
use crate::overrides::parse_selected;

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
        serde_json::from_str(include_str!("../tests/fixtures/markers.json"))
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
    access_class: Option<String>,
}

#[test]
fn every_account_fixture_parses_as_recorded() {
    let fixture: Fixture<AccountCase> =
        serde_json::from_str(include_str!("../tests/fixtures/accounts.json"))
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
    let fixture: Fixture<OverridesCase> =
        serde_json::from_str(include_str!("../tests/fixtures/overrides.json"))
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeCase {
    name: String,
    vault_id: String,
    marker: Option<String>,
    record: Option<String>,
    names: Option<Vec<String>>,
    edits: Vec<serde_json::Value>,
    expect: ChangeExpectation,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeExpectation {
    result: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    writes: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    deletes: Vec<String>,
    #[serde(default)]
    marker_after: Option<String>,
    #[serde(default)]
    activated: Option<bool>,
}

fn fixture_edit(edit: &serde_json::Value) -> crate::overrides::change::Edit {
    use crate::overrides::change::Edit;
    let text = |field: &str| edit[field].as_str().expect(field).to_owned();
    match edit["action"].as_str().expect("an action") {
        "set" => Edit::Set {
            environment: text("environment"),
            key: text("key"),
            value: zeroize::Zeroizing::new(text("value")),
        },
        "unset" => Edit::Unset {
            environment: text("environment"),
            key: text("key"),
        },
        "remove" => Edit::Remove {
            environment: text("environment"),
            key: text("key"),
        },
        "clearEnvironment" => Edit::ClearEnvironment {
            environment: text("environment"),
        },
        "clearAll" => Edit::ClearAll,
        "environmentRenamed" => Edit::EnvironmentRenamed {
            from: text("from"),
            to: text("to"),
        },
        "environmentRemoved" => Edit::EnvironmentRemoved {
            environment: text("environment"),
        },
        "environmentDuplicated" => Edit::EnvironmentDuplicated {
            from: text("from"),
            to: text("to"),
        },
        "environmentCreated" => Edit::EnvironmentCreated {
            environment: text("environment"),
        },
        other => panic!("unknown action {other}"),
    }
}

#[test]
fn every_override_change_fixture_plans_the_transaction_it_records() {
    use crate::gate::ProjectGate;
    use crate::lifecycle::Mutation;
    use crate::overrides::change::{Inventory, PlanError, plan_change};

    let fixture: Fixture<ChangeCase> =
        serde_json::from_str(include_str!("../tests/fixtures/override-changes.json"))
            .expect("override change fixtures decode");
    assert_eq!(fixture.schema_version, 1);
    assert!(!fixture.cases.is_empty());
    for case in fixture.cases {
        let gate = match &case.marker {
            None => ProjectGate::Plain,
            Some(json) => match Marker::parse(&case.vault_id, json.as_bytes()) {
                Ok(marker) => ProjectGate::Marked(marker),
                Err(error) => ProjectGate::Damaged(error.into()),
            },
        };
        let inventory = case
            .names
            .as_ref()
            .map(|names| Inventory::from_names(&case.vault_id, names.iter().map(String::as_str)));
        let edits: Vec<_> = case.edits.iter().map(fixture_edit).collect();
        let planned = plan_change(
            &case.vault_id,
            &gate,
            case.record.as_deref().map(str::as_bytes),
            &edits,
            inventory.as_ref(),
        );
        let expect = &case.expect;
        match (expect.result.as_str(), planned) {
            ("needsNames", Err(PlanError::NeedsInventory { .. })) => {}
            ("refused", Err(error)) => assert_eq!(
                Some(format!("overrides.{}", error.code())),
                expect.code,
                "{}",
                case.name
            ),
            ("unchanged", Ok(plan)) => assert!(plan.mutations.is_empty(), "{}", case.name),
            ("planned", Ok(plan)) => {
                let mut writes = std::collections::BTreeMap::new();
                let mut deletes = Vec::new();
                for mutation in &plan.mutations {
                    match mutation {
                        Mutation::Write { account, value } => {
                            writes.insert(
                                account.name(),
                                String::from_utf8(value.to_vec()).expect("UTF-8"),
                            );
                        }
                        Mutation::Delete { account } => deletes.push(account.name()),
                    }
                }
                assert_eq!(writes, expect.writes, "{}", case.name);
                assert_eq!(deletes, expect.deletes, "{}", case.name);
                assert_eq!(
                    Some(if plan.gate == ProjectGate::Plain {
                        "absent"
                    } else {
                        "present"
                    }),
                    expect.marker_after.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(Some(plan.activated), expect.activated, "{}", case.name);
            }
            (expected, planned) => {
                panic!("{}: expected {expected}, planned {planned:?}", case.name)
            }
        }
    }
}
