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
        service_records: Some(service_records),
    }
}

fn project_inventory(project: Vec<CompanionAccount>) -> Inventory {
    Inventory {
        project,
        service_records: None,
    }
}

/// What inventory a refusal asks for, if it asks for one.
fn needed(result: Result<ChangePlan, PlanError>) -> Option<InventoryNeed> {
    match result {
        Err(PlanError::NeedsInventory { need, .. }) => Some(need),
        _ => None,
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
        needed(plan(&ProjectGate::Plain, None, edits(), None)),
        Some(InventoryNeed::ProjectAndService)
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
        needed(plan(&gate, Some(ONE_OVERRIDE), edits(), None)),
        Some(InventoryNeed::Project)
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
fn a_rename_merges_into_what_the_new_name_has_the_moved_overrides_winning() {
    let gate = ProjectGate::Marked(overrides_marker());
    let record = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"stage":{"set":{"A":"1","B":"2"},"unset":["C"]},"staging":{"set":{"A":"old","OWN":"x"},"unset":[]}}}"#;
    let planned = plan(
        &gate,
        Some(record),
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
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"staging":{"set":{"A":"1","B":"2","OWN":"x"},"unset":["C"]}}}"#
        )
    );
    assert_eq!(
        planned.effects,
        [Effect::Moved {
            from: "stage".to_owned(),
            to: "staging".to_owned(),
            moved: 3,
            replaced: 1,
            kept: 1,
        }]
    );
}

#[test]
fn renaming_an_environment_without_overrides_keeps_what_the_new_name_has() {
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
    assert!(planned.mutations.is_empty());
    assert_eq!(
        planned.effects,
        [Effect::Moved {
            from: "qa".to_owned(),
            to: "staging".to_owned(),
            moved: 0,
            replaced: 0,
            kept: 1,
        }]
    );
}

#[test]
fn only_removing_an_environment_removes_its_overrides() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(TWO_ENVIRONMENTS),
        vec![
            Edit::EnvironmentDuplicated {
                from: "stage".to_owned(),
                to: "staging".to_owned(),
            },
            Edit::EnvironmentCreated {
                environment: "qa".to_owned(),
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
                to: "staging".to_owned(),
                count: 3,
                existing: 1,
            },
            Effect::Existing {
                environment: "qa".to_owned(),
                count: 0,
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
}

#[test]
fn creating_or_duplicating_onto_a_name_with_overrides_keeps_them_and_says_how_many() {
    let gate = ProjectGate::Marked(overrides_marker());
    for edit in [
        Edit::EnvironmentDuplicated {
            from: "stage".to_owned(),
            to: "staging".to_owned(),
        },
        Edit::EnvironmentCreated {
            environment: "staging".to_owned(),
        },
    ] {
        let planned = plan(&gate, Some(TWO_ENVIRONMENTS), vec![edit], None).unwrap();
        assert!(planned.mutations.is_empty());
        let existing = match &planned.effects[..] {
            [Effect::NotCopied { existing, .. }] => *existing,
            [Effect::Existing { count, .. }] => *count,
            other => panic!("{other:?}"),
        };
        assert_eq!(existing, 1);
    }
}

#[test]
fn renaming_or_copying_an_environment_to_itself_says_which() {
    let gate = ProjectGate::Marked(overrides_marker());
    let renamed = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![Edit::EnvironmentRenamed {
            from: "dev".to_owned(),
            to: "dev".to_owned(),
        }],
        None,
    )
    .unwrap_err();
    assert_eq!(
        renamed.to_string(),
        "environment \"dev\" can't be renamed to itself"
    );
    let copied = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![Edit::EnvironmentDuplicated {
            from: "dev".to_owned(),
            to: "dev".to_owned(),
        }],
        None,
    )
    .unwrap_err();
    assert_eq!(
        copied.to_string(),
        "environment \"dev\" can't be copied to itself"
    );
    assert_eq!(copied.code(), "same_environment");
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
            matches!(
                error,
                PlanError::Edit {
                    index: 0,
                    reason: EditError::DeniedName(_)
                }
            ),
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
        PlanError::Edit {
            index: 0,
            reason: EditError::InvalidEnvironment("bad name".to_owned())
        }
    );
    let invalid_key = refused(set("development", "sk-live-0123", "1"));
    assert_eq!(
        invalid_key,
        PlanError::Edit {
            index: 0,
            reason: EditError::InvalidKey
        }
    );
    assert!(!invalid_key.to_string().contains("sk-live"));
    let nul = refused(set("development", "A", "fixture\0secret"));
    assert_eq!(
        nul,
        PlanError::Edit {
            index: 0,
            reason: EditError::NulValue("A".to_owned())
        }
    );
    assert!(!nul.to_string().contains("fixture"));
    assert_eq!(
        refused(Edit::EnvironmentRenamed {
            from: "dev".to_owned(),
            to: "dev".to_owned()
        }),
        PlanError::Edit {
            index: 0,
            reason: EditError::SameEnvironment {
                environment: "dev".to_owned(),
                copy: false
            }
        }
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
        Err(PlanError::Edit {
            index: 1,
            reason: EditError::DeniedName(_)
        })
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
        service_records: Some(budgets::ADMISSION_CAP),
    };
    assert_eq!(
        plan(&ProjectGate::Plain, None, edits(), Some(&at_cap)).unwrap_err(),
        PlanError::AdmissionRefused(budgets::ADMISSION_CAP)
    );
    let past_target = Inventory {
        project: Vec::new(),
        service_records: Some(budgets::ADMISSION_TARGET),
    };
    let planned = plan(&ProjectGate::Plain, None, edits(), Some(&past_target)).unwrap();
    assert!(planned.over_admission_target);
    let below_target = Inventory {
        project: Vec::new(),
        service_records: Some(budgets::ADMISSION_TARGET - 1),
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
    assert_eq!(inventory.service_records, Some(3));
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

#[test]
fn removing_the_last_override_deletes_the_record_even_when_the_inventory_missed_it() {
    let gate = ProjectGate::Marked(overrides_marker());
    for listed in [Vec::new(), vec![overrides_account(), overrides_account()]] {
        let planned = plan(
            &gate,
            Some(ONE_OVERRIDE),
            vec![remove("development", "API_URL")],
            Some(&project_inventory(listed)),
        )
        .unwrap();
        assert_eq!(
            deleted(&planned),
            [
                record_account(OVERRIDES_KIND, VAULT, None),
                marker_account(VAULT)
            ]
        );
        passes_the_commit_check(&planned, Some(&overrides_marker()), &[overrides_account()]);
    }
}

#[test]
fn deleting_the_record_needs_only_the_projects_own_inventory() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![Edit::ClearAll],
        Some(&project_inventory(vec![overrides_account()])),
    )
    .unwrap();
    assert_eq!(planned.gate, ProjectGate::Plain);
    assert_eq!(
        needed(plan(
            &ProjectGate::Plain,
            None,
            vec![set("development", "A", "1")],
            Some(&project_inventory(Vec::new())),
        )),
        Some(InventoryNeed::ProjectAndService),
        "creating the record counts the service too"
    );
}

#[test]
fn removing_the_last_override_beside_staged_records_is_one_transaction_that_keeps_their_marker() {
    let gate = ProjectGate::Marked(overrides_marker());
    let mut listed = vec![overrides_account()];
    listed.extend((0..64).map(|index| {
        CompanionAccount::parse(&crate::account::staged_account(
            OVERRIDES_KIND,
            VAULT,
            Some(index),
        ))
        .expect("valid")
    }));
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![Edit::ClearAll],
        Some(&project_inventory(listed.clone())),
    )
    .unwrap();
    assert_eq!(
        deleted(&planned),
        [record_account(OVERRIDES_KIND, VAULT, None)]
    );
    assert_eq!(
        written_marker(&planned),
        Some(Marker::empty(VAULT, ProjectState::Active))
    );
    passes_the_commit_check(&planned, Some(&overrides_marker()), &listed);
}

#[test]
fn a_record_with_no_overrides_left_is_deleted_by_the_next_change() {
    let gate = ProjectGate::Marked(overrides_marker());
    let empty = r#"{"schemaVersion":1,"vaultId":"proj","environments":{}}"#;
    let edits = || vec![remove("development", "NOTHING")];
    assert_eq!(
        needed(plan(&gate, Some(empty), edits(), None)),
        Some(InventoryNeed::Project)
    );
    let planned = plan(
        &gate,
        Some(empty),
        edits(),
        Some(&project_inventory(vec![overrides_account()])),
    )
    .unwrap();
    assert_eq!(
        deleted(&planned),
        [
            record_account(OVERRIDES_KIND, VAULT, None),
            marker_account(VAULT)
        ]
    );
    assert!(matches!(
        planned.effects[..],
        [Effect::Key { changed: false, .. }]
    ));
}

#[test]
fn a_record_too_large_says_its_size_in_kib() {
    assert_eq!(
        PlanError::TooLarge(MAX_RECORD_BYTES + 1).to_string(),
        "the personal overrides would take 100.1 KiB, more than the 100 KiB a project's overrides can use"
    );
}

#[test]
fn a_refused_edit_says_which_one_it_was_and_a_needed_inventory_brings_the_effects() {
    let gate = ProjectGate::Marked(overrides_marker());
    let refused = plan(
        &gate,
        Some(ONE_OVERRIDE),
        vec![
            set("development", "A", "1"),
            remove("development", "B"),
            set("development", "NODE_OPTIONS", "x"),
        ],
        None,
    )
    .unwrap_err();
    assert!(
        matches!(refused, PlanError::Edit { index: 2, .. }),
        "{refused:?}"
    );
    match plan(&gate, Some(ONE_OVERRIDE), vec![Edit::ClearAll], None) {
        Err(PlanError::NeedsInventory { need, effects }) => {
            assert_eq!(need, InventoryNeed::Project);
            assert_eq!(
                effects,
                [Effect::Cleared {
                    environment: None,
                    removed: 1
                }]
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn edits_that_give_no_key_an_override_have_effects_without_any_overrides() {
    assert_eq!(
        effects_without_overrides(&[remove("development", "A"), Edit::ClearAll]).unwrap(),
        Some(vec![
            Effect::Key {
                environment: "development".to_owned(),
                key: "A".to_owned(),
                previous: Previous::None,
                changed: false,
            },
            Effect::Cleared {
                environment: None,
                removed: 0
            },
        ])
    );
    assert_eq!(
        effects_without_overrides(&[set("development", "A", "1")]).unwrap(),
        None
    );
    assert_eq!(
        effects_without_overrides(&[remove("development", "sk-live")])
            .unwrap_err()
            .code(),
        "invalid_key"
    );
}

#[test]
fn removing_the_environment_that_held_the_last_overrides_deletes_the_record_and_marker() {
    let gate = ProjectGate::Marked(overrides_marker());
    let edits = || {
        vec![Edit::EnvironmentRemoved {
            environment: "development".to_owned(),
        }]
    };
    assert_eq!(
        needed(plan(&gate, Some(ONE_OVERRIDE), edits(), None)),
        Some(InventoryNeed::Project)
    );
    let before = [overrides_account()];
    let planned = plan(
        &gate,
        Some(ONE_OVERRIDE),
        edits(),
        Some(&project_inventory(before.to_vec())),
    )
    .unwrap();
    assert_eq!(
        deleted(&planned),
        [
            record_account(OVERRIDES_KIND, VAULT, None),
            marker_account(VAULT)
        ]
    );
    assert_eq!(planned.gate, ProjectGate::Plain);
    passes_the_commit_check(&planned, Some(&overrides_marker()), &before);
}

fn changed(renamed: &[(&str, &str)], removed: &[&str]) -> Edit {
    Edit::EnvironmentsChanged {
        renamed: renamed
            .iter()
            .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
            .collect(),
        removed: removed.iter().map(|name| (*name).to_owned()).collect(),
    }
}

const SWAP_RECORD: &str = r#"{"schemaVersion":1,"vaultId":"proj","environments":{"a":{"set":{"K":"from-a","X":"1"},"unset":[]},"b":{"set":{"K":"from-b","Y":"2"},"unset":[]},"c":{"set":{"Z":"3"},"unset":[]}}}"#;

#[test]
fn environments_renamed_together_keep_their_own_overrides_when_names_swap_or_chain() {
    let gate = ProjectGate::Marked(overrides_marker());
    let swapped = plan(
        &gate,
        Some(SWAP_RECORD),
        vec![changed(&[("a", "b"), ("b", "a")], &[])],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&swapped).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"a":{"set":{"K":"from-b","Y":"2"},"unset":[]},"b":{"set":{"K":"from-a","X":"1"},"unset":[]},"c":{"set":{"Z":"3"},"unset":[]}}}"#
        )
    );
    let into_a_removed_name = plan(
        &gate,
        Some(SWAP_RECORD),
        vec![changed(&[("b", "c"), ("a", "b")], &["c"])],
        None,
    );
    assert!(
        matches!(
            into_a_removed_name,
            Err(PlanError::Edit {
                reason: EditError::EnvironmentNamedTwice(_),
                ..
            })
        ),
        "a chain can't end in a name it removes: {into_a_removed_name:?}"
    );
    let chained = plan(
        &gate,
        Some(SWAP_RECORD),
        vec![changed(&[("a", "b"), ("b", "c")], &[])],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&chained).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"b":{"set":{"K":"from-a","X":"1"},"unset":[]},"c":{"set":{"K":"from-b","Y":"2","Z":"3"},"unset":[]}}}"#
        )
    );
    match &chained.effects[..] {
        [Effect::EnvironmentsChanged { moved, removed }] => {
            assert_eq!(moved.len(), 2);
            assert_eq!(
                (moved[1].moved, moved[1].replaced, moved[1].kept),
                (2, 0, 1)
            );
            assert!(removed.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn environments_changed_together_take_removals_out_with_the_renames() {
    let gate = ProjectGate::Marked(overrides_marker());
    let planned = plan(
        &gate,
        Some(SWAP_RECORD),
        vec![changed(&[("a", "c")], &["b"])],
        None,
    )
    .unwrap();
    assert_eq!(
        written_record(&planned).as_deref(),
        Some(
            r#"{"schemaVersion":1,"vaultId":"proj","environments":{"c":{"set":{"K":"from-a","X":"1","Z":"3"},"unset":[]}}}"#
        )
    );
    for edit in [
        changed(&[("a", "b"), ("a", "c")], &[]),
        changed(&[("a", "c"), ("b", "c")], &[]),
        changed(&[("a", "b")], &["b"]),
        changed(&[("a", "b")], &["a"]),
    ] {
        assert_eq!(
            plan(&gate, Some(SWAP_RECORD), vec![edit], None)
                .unwrap_err()
                .code(),
            "environment_named_twice"
        );
    }
}

#[test]
fn the_first_override_beside_a_full_marker_is_over_budget_not_damage() {
    let mut marker = Marker::empty(VAULT, ProjectState::Active);
    for index in 0..crate::marker::MAX_FEATURES {
        let kind = format!("future-{index}");
        marker.features.insert(
            kind.clone(),
            FeatureEntry {
                version: 1,
                if_unsupported: Level::Ignore,
                kinds: vec![kind],
                state: FeatureState::Active,
            },
        );
    }
    let refused = plan(
        &ProjectGate::Marked(marker),
        None,
        vec![set("development", "A", "1")],
        Some(&inventory(Vec::new())),
    )
    .unwrap_err();
    assert_eq!(
        refused,
        PlanError::OverBudget(OverBudget::Features(crate::marker::MAX_FEATURES + 1))
    );
}

#[test]
fn a_project_without_values_removes_nothing_and_refuses_the_rest() {
    let removed = plan_without_values(&ProjectGate::Plain, &[remove("development", "A")])
        .expect("a removal of nothing succeeds");
    assert!(removed.mutations.is_empty());
    assert!(!removed.activated);
    assert_eq!(
        removed.effects,
        vec![Effect::Key {
            environment: "development".to_owned(),
            key: "A".to_owned(),
            previous: Previous::None,
            changed: false,
        }]
    );
    assert_eq!(
        plan_without_values(&ProjectGate::Plain, &[set("development", "A", "1")])
            .unwrap_err()
            .code(),
        "no_values"
    );
    for edits in [
        vec![set("development", "A", "1"), remove("development", "A")],
        vec![unset("development", "A"), Edit::ClearAll],
    ] {
        assert_eq!(
            plan_without_values(&ProjectGate::Plain, &edits)
                .unwrap_err()
                .code(),
            "no_values",
            "a batch that gives a key an override anywhere needs values"
        );
    }
}

#[test]
fn a_project_without_values_keeps_the_gate_a_plan_with_values_keeps() {
    let edits = [remove("development", "A")];
    let mut newer = overrides_marker();
    newer.features.get_mut(OVERRIDES_KIND).unwrap().version = 2;
    assert_eq!(
        plan_without_values(&ProjectGate::Marked(newer), &edits)
            .unwrap_err()
            .code(),
        "unsupported"
    );
    let mut removing = overrides_marker();
    removing.features.get_mut(OVERRIDES_KIND).unwrap().state = FeatureState::Removing;
    assert_eq!(
        plan_without_values(&ProjectGate::Marked(removing), &edits).unwrap_err(),
        PlanError::NeedsResume
    );
    assert_eq!(
        plan_without_values(
            &ProjectGate::Damaged(crate::gate::Damage::Access("fixture".to_owned())),
            &edits
        )
        .unwrap_err()
        .code(),
        "damaged"
    );
}
