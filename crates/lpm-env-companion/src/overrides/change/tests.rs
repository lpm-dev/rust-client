use super::*;
use crate::invariants::check_transaction;
use crate::marker::{FeatureEntry, FeatureState, Level};

const VAULT: &str = "proj";

fn set(environment: &str, key: &str, value: &str) -> Edit {
    Edit::Set {
        environment: environment.to_owned(),
        key: key.to_owned(),
        value: Zeroizing::new(value.to_owned()),
    }
}

fn unset(environment: &str, key: &str) -> Edit {
    Edit::Unset {
        environment: environment.to_owned(),
        key: key.to_owned(),
    }
}

fn remove(environment: &str, key: &str) -> Edit {
    Edit::Remove {
        environment: environment.to_owned(),
        key: key.to_owned(),
    }
}

fn overrides_marker() -> Marker {
    let mut marker = Marker::empty(VAULT, ProjectState::Active);
    marker
        .features
        .insert(OVERRIDES_KIND.to_owned(), feature_entry());
    marker
}

fn with_history(mut marker: Marker) -> Marker {
    marker.features.insert(
        crate::history::FEATURE.to_owned(),
        crate::history::feature_entry(),
    );
    marker
}

fn history_inventory() -> Vec<CompanionAccount> {
    vec![
        crate::history::key_account(VAULT),
        crate::history::head_account(VAULT),
        crate::history::part_account(VAULT, 0),
    ]
}

fn overrides_account() -> CompanionAccount {
    CompanionAccount::parse(&record_account(OVERRIDES_KIND, VAULT, None)).expect("valid")
}

fn inventory(project: Vec<CompanionAccount>) -> Inventory {
    let service_records = project.len();
    Inventory {
        project,
        service_records,
    }
}

fn plan(
    gate: &ProjectGate,
    record: Option<&str>,
    edits: Vec<Edit>,
    inventory: Option<&Inventory>,
) -> Result<ChangePlan, PlanError> {
    plan_change_with_case_policy(
        VAULT,
        gate,
        record.map(str::as_bytes),
        &edits,
        inventory,
        false,
    )
}

/// The record bytes a plan writes, as text.
fn written_record(plan: &ChangePlan) -> Option<String> {
    plan.mutations.iter().find_map(|mutation| match mutation {
        Mutation::Write { account, value } if account.kind() == Some(OVERRIDES_KIND) => {
            Some(String::from_utf8(value.to_vec()).expect("UTF-8 record"))
        }
        _ => None,
    })
}

fn written_marker(plan: &ChangePlan) -> Option<Marker> {
    plan.mutations.iter().find_map(|mutation| match mutation {
        Mutation::Write {
            account: CompanionAccount::Marker { .. },
            value,
        } => Some(Marker::parse(VAULT, value).expect("a valid marker")),
        _ => None,
    })
}

fn deleted(plan: &ChangePlan) -> Vec<String> {
    plan.mutations
        .iter()
        .filter_map(|mutation| match mutation {
            Mutation::Delete { account } => Some(account.name()),
            Mutation::Write { .. } => None,
        })
        .collect()
}

/// Check `plan`'s transaction the way a commit and its recovery do, against
/// the store it was planned from.
fn passes_the_commit_check(
    plan: &ChangePlan,
    marker_before: Option<&Marker>,
    before: &[CompanionAccount],
) {
    let names: Vec<(String, Option<Vec<u8>>)> = plan
        .mutations
        .iter()
        .map(|mutation| match mutation {
            Mutation::Write { account, value } => (account.name(), Some(value.to_vec())),
            Mutation::Delete { account } => (account.name(), None),
        })
        .collect();
    let changes: Vec<(&str, Option<&[u8]>)> = names
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_deref()))
        .collect();
    let marker_bytes = marker_before.map(|marker| marker.encode().expect("encode"));
    check_transaction(
        &changes,
        |_| Ok(marker_bytes.clone()),
        |_| Ok(before.to_vec()),
    )
    .unwrap_or_else(|refusal| panic!("{}", refusal.describe("overrides change")));
}

const ONE_OVERRIDE: &str = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"http://localhost:4000"},"unset":[]}}}"#;

#[test]
fn the_first_override_adds_the_feature_and_creates_the_marker_once_the_inventory_is_known() {
    let edits = || vec![set("development", "API_URL", "http://localhost:4000")];
    assert_eq!(
        plan(&ProjectGate::Plain, None, edits(), None).unwrap_err(),
        PlanError::NeedsInventory
    );
    let planned = plan(
        &ProjectGate::Plain,
        None,
        edits(),
        Some(&inventory(Vec::new())),
    )
    .unwrap();
    assert!(planned.activated);
    assert_eq!(planned.mutations.len(), 2);
    assert_eq!(written_record(&planned).as_deref(), Some(ONE_OVERRIDE));
    let marker = written_marker(&planned).expect("a marker");
    assert_eq!(marker, overrides_marker());
    assert_eq!(
        marker.features[OVERRIDES_KIND].if_unsupported,
        Level::Refuse,
        "a client that can't apply overrides must not run without them"
    );
    assert_eq!(planned.gate, ProjectGate::Marked(marker));
    assert_eq!(
        planned.effects,
        [Effect::Key {
            environment: "development".to_owned(),
            key: "API_URL".to_owned(),
            previous: Previous::None,
            changed: true,
        }]
    );
    passes_the_commit_check(&planned, None, &[]);
}

#[test]
fn the_first_override_keeps_every_feature_already_in_the_marker() {
    let marker = with_history(Marker::empty(VAULT, ProjectState::Active));
    let gate = ProjectGate::Marked(marker.clone());
    let planned = plan(
        &gate,
        None,
        vec![unset("staging", "SENTRY_DSN")],
        Some(&inventory(history_inventory())),
    )
    .unwrap();
    let written = written_marker(&planned).expect("a marker");
    assert_eq!(written, with_history(overrides_marker()));
    passes_the_commit_check(&planned, Some(&marker), &history_inventory());
}

#[test]
fn a_change_to_existing_overrides_rewrites_only_the_record_and_needs_no_inventory() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![
            set("development", "API_URL", "http://localhost:5000"),
            set("development", "EMPTY", ""),
            unset("development", "SENTRY_DSN"),
        ],
        None,
    )
    .unwrap();
    assert!(!planned.activated);
    assert_eq!(planned.mutations.len(), 1);
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"http://localhost:5000","EMPTY":""},"unset":["SENTRY_DSN"]}}}"#
        )
    );
    assert_eq!(planned.gate, gate);
    let previous: Vec<(Previous, bool)> = planned
        .effects
        .iter()
        .map(|effect| match effect {
            Effect::Key {
                previous, changed, ..
            } => (*previous, *changed),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        previous,
        [
            (Previous::Set, true),
            (Previous::None, true),
            (Previous::None, true)
        ]
    );
    passes_the_commit_check(&planned, Some(&overrides_marker()), &[overrides_account()]);
}

#[test]
fn edits_that_change_nothing_write_nothing_and_say_so() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![
            set("development", "API_URL", "http://localhost:4000"),
            remove("development", "NEVER_SET"),
            remove("production", "API_URL"),
            Edit::ClearEnvironment {
                environment: "staging".to_owned(),
            },
        ],
        None,
    )
    .unwrap();
    assert!(planned.mutations.is_empty());
    assert_eq!(planned.gate, gate);
    assert!(matches!(
        planned.effects[0],
        Effect::Key {
            previous: Previous::Set,
            changed: false,
            ..
        }
    ));
    assert!(matches!(
        planned.effects[1],
        Effect::Key {
            previous: Previous::None,
            changed: false,
            ..
        }
    ));
    assert_eq!(
        planned.effects[3],
        Effect::Cleared {
            environment: Some("staging".to_owned()),
            removed: 0
        }
    );
}

#[test]
fn an_unset_replaces_a_set_and_a_set_replaces_an_unset() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![unset("development", "API_URL")],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{},"unset":["API_URL"]}}}"#
        )
    );
    let unset_record = written_record(&planned).unwrap();
    let planned = plan(
        &gate,
        Some(&unset_record),
        vec![set("development", "API_URL", "mine")],
        None,
    )
    .unwrap();
    assert!(matches!(
        planned.effects[0],
        Effect::Key {
            previous: Previous::Unset,
            changed: true,
            ..
        }
    ));
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"mine"},"unset":[]}}}"#
        )
    );
}

#[test]
fn removing_the_last_override_deletes_the_record_and_a_marker_left_with_nothing() {
    let gate = ProjectGate::Marked(overrides_marker());
    let edits = || vec![remove("development", "API_URL")];
    assert_eq!(
        plan(&gate, Some(ONE_OVERRIDE), edits(), None).unwrap_err(),
        PlanError::NeedsInventory
    );
    let before = [overrides_account()];
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        edits(),
        Some(&inventory(before.to_vec())),
    )
    .unwrap();
    assert_eq!(
        deleted(&planned),
        [
            record_account(OVERRIDES_KIND, VAULT, None),
            marker_account(VAULT)
        ]
    );
    assert_eq!(planned.mutations.len(), 2);
    assert_eq!(planned.gate, ProjectGate::Plain);
    passes_the_commit_check(&planned, Some(&overrides_marker()), &before);
}

#[test]
fn removing_the_last_override_keeps_the_marker_for_other_features() {
    let marker = with_history(overrides_marker());
    let gate = ProjectGate::Marked(marker.clone());
    let mut before = history_inventory();
    before.push(overrides_account());
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![Edit::ClearAll],
        Some(&inventory(before.clone())),
    )
    .unwrap();
    assert_eq!(
        deleted(&planned),
        [record_account(OVERRIDES_KIND, VAULT, None)]
    );
    let left = written_marker(&planned).expect("the marker stays");
    assert_eq!(
        left,
        with_history(Marker::empty(VAULT, ProjectState::Active))
    );
    assert_eq!(planned.gate, ProjectGate::Marked(left));
    assert_eq!(
        planned.effects,
        [Effect::Cleared {
            environment: None,
            removed: 1
        }]
    );
    passes_the_commit_check(&planned, Some(&marker), &before);
}

const TWO_ENVIRONMENTS: &str = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"stage":{"set":{"A":"1","B":"2"},"unset":["C"]},"staging":{"set":{"OLD":"x"},"unset":[]}}}"#;

#[test]
fn a_rename_moves_the_overrides_and_replaces_what_a_removed_environment_left() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![Edit::EnvironmentRenamed {
            from: "stage".to_owned(),
            to: "staging".to_owned(),
        }],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1","B":"2"},"unset":["C"]}}}"#
        )
    );
    assert_eq!(
        planned.effects,
        [Effect::Moved {
            from: "stage".to_owned(),
            to: "staging".to_owned(),
            moved: 3,
            replaced: 1
        }]
    );
}

#[test]
fn renaming_an_environment_without_overrides_drops_what_was_left_under_the_new_name() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![Edit::EnvironmentRenamed {
            from: "qa".to_owned(),
            to: "staging".to_owned(),
        }],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"stage":{"set":{"A":"1","B":"2"},"unset":["C"]}}}"#
        )
    );
    assert_eq!(
        planned.effects,
        [Effect::Moved {
            from: "qa".to_owned(),
            to: "staging".to_owned(),
            moved: 0,
            replaced: 1
        }]
    );
}

#[test]
fn a_removed_environment_loses_its_overrides_and_a_duplicate_copies_none() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![
            Edit::EnvironmentDuplicated {
                from: "stage".to_owned(),
                to: "stage-copy".to_owned(),
            },
            Edit::EnvironmentRemoved {
                environment: "staging".to_owned(),
            },
        ],
        None,
    )
    .unwrap();
    assert_eq!(
        planned.effects,
        [
            Effect::NotCopied {
                from: "stage".to_owned(),
                to: "stage-copy".to_owned(),
                count: 3
            },
            Effect::EnvironmentRemoved {
                environment: "staging".to_owned(),
                removed: 1
            }
        ]
    );
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"stage":{"set":{"A":"1","B":"2"},"unset":["C"]}}}"#
        )
    );
    let only_duplicate = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![Edit::EnvironmentDuplicated {
            from: "stage".to_owned(),
            to: "qa".to_owned(),
        }],
        None,
    )
    .unwrap();
    assert!(only_duplicate.mutations.is_empty());
}

#[test]
fn names_lpm_never_passes_are_refused_when_written_but_can_be_removed() {
    let gate = ProjectGate::Marked(overrides_marker());
    for edit in [
        set("development", "NODE_OPTIONS", "--inspect"),
        set("development", "java_tool_options", "-javaagent:x.jar"),
        unset("development", "GIT_CONFIG_KEY_0"),
        set("development", "PATH", "/tmp"),
    ] {
        let error = plan(&gate, Some(ONE_OVERRIDE), vec![edit.clone()], None).unwrap_err();
        assert!(
            matches!(error, PlanError::DeniedName(_)),
            "{edit:?}: {error:?}"
        );
        assert_eq!(error.code(), "denied_name");
    }
    let stored_before_the_rule = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"x","NODE_OPTIONS":"--inspect"},"unset":[]}}}"#;
    let planned = plan(
        &gate,
        Some(stored_before_the_rule),
        vec![remove("development", "NODE_OPTIONS")],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"x"},"unset":[]}}}"#
        )
    );
}

#[test]
fn invalid_names_values_and_sizes_are_refused_without_showing_values() {
    let gate = ProjectGate::Marked(overrides_marker());
    let refused = |edit: Edit| plan(&gate, Some(ONE_OVERRIDE), vec![edit], None).unwrap_err();
    assert_eq!(
        refused(set("bad name", "A", "1")),
        PlanError::InvalidEnvironment("bad name".to_owned())
    );
    let invalid_key = refused(set("development", "sk-live-0123", "1"));
    assert_eq!(invalid_key, PlanError::InvalidKey);
    assert!(!invalid_key.to_string().contains("sk-live"));
    let nul = refused(set("development", "A", "fixture\0secret"));
    assert_eq!(nul, PlanError::NulValue("A".to_owned()));
    assert!(!nul.to_string().contains("fixture"));
    assert_eq!(
        refused(Edit::EnvironmentRenamed {
            from: "dev".to_owned(),
            to: "dev".to_owned()
        }),
        PlanError::SameEnvironment("dev".to_owned())
    );
    let too_large = refused(set("development", "BIG", &"x".repeat(MAX_RECORD_BYTES)));
    assert!(matches!(too_large, PlanError::TooLarge(bytes) if bytes > MAX_RECORD_BYTES));
}

#[test]
fn the_largest_record_is_accepted_and_one_byte_more_is_refused() {
    let gate = ProjectGate::Marked(overrides_marker());
    let empty_value = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![set("development", "BIG", "")],
        None,
    )
    .unwrap();
    let base = written_record(&empty_value).unwrap().len();
    let fits = "x".repeat(MAX_RECORD_BYTES - base);
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![set("development", "BIG", &fits)],
        None,
    )
    .unwrap();
    assert_eq!(written_record(&planned).unwrap().len(), MAX_RECORD_BYTES);
    let one_more = format!("{fits}x");
    assert_eq!(
        plan(
            &gate,
            Some(ONE_OVERRIDE),
            vec![set("development", "BIG", &one_more)],
            None
        )
        .unwrap_err(),
        PlanError::TooLarge(MAX_RECORD_BYTES + 1)
    );
}

#[test]
fn a_later_invalid_edit_refuses_the_whole_batch() {
    let gate = ProjectGate::Marked(overrides_marker());
    assert!(matches!(
        plan(
            &gate,
            Some(ONE_OVERRIDE),
            vec![
                set("development", "GOOD", "1"),
                set("development", "NODE_OPTIONS", "x")
            ],
            None,
        ),
        Err(PlanError::DeniedName(_))
    ));
}

#[test]
fn names_the_host_cant_tell_apart_replace_each_other_where_it_ignores_case() {
    let gate = ProjectGate::Marked(overrides_marker());
    let edits = || vec![set("development", "api_url", "mine")];
    let insensitive = plan_change_with_case_policy(
        VAULT,
        &gate,
        Some(ONE_OVERRIDE.as_bytes()),
        &edits(),
        None,
        true,
    )
    .unwrap();
    assert_eq!(
        written_record(&insensitive).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"api_url":"mine"},"unset":[]}}}"#
        )
    );
    assert!(matches!(
        insensitive.effects[0],
        Effect::Key {
            previous: Previous::Set,
            changed: true,
            ..
        }
    ));
    let sensitive = plan(&gate, Some(ONE_OVERRIDE), edits(), None).unwrap();
    assert_eq!(
        written_record(&sensitive).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"development":{"set":{"API_URL":"http://localhost:4000","api_url":"mine"},"unset":[]}}}"#
        )
    );
    let removed = plan_change_with_case_policy(
        VAULT,
        &gate,
        Some(ONE_OVERRIDE.as_bytes()),
        &[remove("development", "Api_Url")],
        Some(&inventory(vec![overrides_account()])),
        true,
    )
    .unwrap();
    assert_eq!(removed.gate, ProjectGate::Plain);
}

#[test]
fn the_gate_refuses_damaged_unsupported_and_unfinished_projects() {
    let gate = ProjectGate::Marked(overrides_marker());
    let edits = || vec![set("development", "A", "1")];
    let damaged = plan(&gate, Some("{not json"), edits(), None).unwrap_err();
    assert_eq!(damaged.code(), "damaged");
    assert!(!damaged.to_string().contains("not json"));
    assert_eq!(
        plan(&gate, None, edits(), None).unwrap_err().code(),
        "damaged",
        "a listed record that's missing is damage, never an empty start"
    );
    assert_eq!(
        plan(&ProjectGate::Plain, Some(ONE_OVERRIDE), edits(), None)
            .unwrap_err()
            .code(),
        "damaged",
        "a record no marker lists is damage"
    );

    let mut newer = overrides_marker();
    newer.features.get_mut(OVERRIDES_KIND).unwrap().version = 2;
    let unsupported = plan(
        &ProjectGate::Marked(newer),
        Some(ONE_OVERRIDE),
        edits(),
        None,
    )
    .unwrap_err();
    assert_eq!(unsupported.code(), "unsupported");

    let mut removing = overrides_marker();
    removing.features.get_mut(OVERRIDES_KIND).unwrap().state = FeatureState::Removing;
    assert_eq!(
        plan(
            &ProjectGate::Marked(removing),
            Some(ONE_OVERRIDE),
            edits(),
            None
        )
        .unwrap_err(),
        PlanError::NeedsResume
    );
}

#[test]
fn creating_the_record_keeps_the_project_and_service_budgets() {
    let edits = || vec![set("development", "A", "1")];
    let mut marker = Marker::empty(VAULT, ProjectState::Active);
    let full: Vec<CompanionAccount> = (0..budgets::MAX_SINGLE_RECORDS)
        .map(|index| {
            let kind = format!("future-{index}");
            marker.features.insert(
                kind.clone(),
                FeatureEntry {
                    version: 1,
                    if_unsupported: Level::Ignore,
                    kinds: vec![kind.clone()],
                    state: FeatureState::Active,
                },
            );
            CompanionAccount::parse(&record_account(&kind, VAULT, None)).expect("valid")
        })
        .collect();
    let gate = ProjectGate::Marked(marker);
    assert!(matches!(
        plan(&gate, None, edits(), Some(&inventory(full))).unwrap_err(),
        PlanError::OverBudget(OverBudget::SingleRecords(9))
    ));

    let at_cap = Inventory {
        project: Vec::new(),
        service_records: budgets::ADMISSION_CAP,
    };
    assert_eq!(
        plan(&ProjectGate::Plain, None, edits(), Some(&at_cap)).unwrap_err(),
        PlanError::AdmissionRefused(budgets::ADMISSION_CAP)
    );
    let past_target = Inventory {
        project: Vec::new(),
        service_records: budgets::ADMISSION_TARGET,
    };
    let planned = plan(&ProjectGate::Plain, None, edits(), Some(&past_target)).unwrap();
    assert!(planned.over_admission_target);
    let below_target = Inventory {
        project: Vec::new(),
        service_records: budgets::ADMISSION_TARGET - 1,
    };
    assert!(
        !plan(&ProjectGate::Plain, None, edits(), Some(&below_target))
            .unwrap()
            .over_admission_target
    );
}

#[test]
fn the_inventory_comes_from_names_of_every_project_in_the_service() {
    let names = [
        marker_account(VAULT),
        record_account(OVERRIDES_KIND, VAULT, None),
        record_account("notes", "other", None),
        crate::account::staged_account("history", "other", Some(1)),
        VAULT.to_owned(),
    ];
    let inventory = Inventory::from_names(VAULT, names.iter().map(String::as_str));
    assert_eq!(inventory.project, [overrides_account()]);
    assert_eq!(inventory.service_records, 3);
}

#[test]
fn what_a_plan_writes_reads_back_as_the_overrides_it_planned() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![
            set("stage", "Z", "last"),
            unset("staging", "B"),
            set("development", "MULTI", "line one\nline two\n"),
        ],
        None,
    )
    .unwrap();
    let written = written_record(&planned).unwrap();
    let read = super::super::evaluate_all(&gate, VAULT, Some(written.as_bytes())).expect("valid");
    assert_eq!(read["development"].set["MULTI"], "line one\nline two\n");
    assert_eq!(read["stage"].set["Z"], "last");
    assert_eq!(read["staging"].unset, ["B"]);
    assert_eq!(read["staging"].set["OLD"], "x");
}

#[test]
fn a_planned_edit_never_prints_its_value() {
    let printed = format!("{:?}", set("development", "TOKEN", "fixture-secret"));
    assert!(!printed.contains("fixture-secret"), "{printed}");
    assert!(printed.contains("TOKEN"), "{printed}");
}
