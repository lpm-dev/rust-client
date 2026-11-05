use super::*;
use crate::history::codec::{Actor, Detail, Remote};
use crate::history::read::{
    EntryLookup, Filter, KeyMatch, SourceGroup, TimelineRow, read_timeline, reveal_entry,
};
use crate::history::test_support::{Project, Recorded, Store, VAULT};
use crate::history::values::Rename;
use crate::history::{head_account, key_account, part_account};

fn id(n: u8) -> EntryId {
    let mut id = [0xa0; 16];
    id[15] = n;
    id
}

fn after(n: u8) -> Point {
    Point {
        entry: id(n),
        side: RelatedSide::After,
    }
}

fn before(n: u8) -> Point {
    Point {
        entry: id(n),
        side: RelatedSide::Before,
    }
}

fn opened(store: &Store) -> Opened {
    Opened::open(
        VAULT,
        store.get(&head_account(VAULT)).expect("head"),
        store.get(&key_account(VAULT)).expect("key"),
    )
    .expect("opens")
}

fn source(store: &Store) -> impl FnMut(u16) -> Result<Option<Vec<u8>>, String> + '_ {
    move |part| Ok(store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec))
}

/// Record each project in turn as one change from the one before it.
fn history(steps: &[Project]) -> Store {
    let mut store = Store::new();
    for pair in steps.windows(2) {
        let recorded = store
            .record(Action::Set, &pair[0], &pair[1], &[])
            .expect("recorded");
        assert!(
            !matches!(recorded, Recorded::Unchanged | Recorded::NoKeyChanges),
            "{recorded:?}"
        );
    }
    store
}

fn rows(plan: &RollbackPlan) -> Vec<(String, String)> {
    plan.environments
        .iter()
        .flat_map(|environment| {
            environment.rows.iter().map(|row| {
                (
                    row.key.clone(),
                    match &row.target {
                        TargetValue::Known(value) => format!("= {}", value.as_str()),
                        TargetValue::Absent => "absent".to_owned(),
                        TargetValue::Unknown(reason) => format!("unknown {reason:?}"),
                    },
                )
            })
        })
        .collect()
}

fn row(key: &str, target: &str) -> (String, String) {
    (key.to_owned(), target.to_owned())
}

type Written = (String, Option<String>, Option<Vec<(String, String)>>);

fn written(writes: &[EnvironmentWrite]) -> Vec<Written> {
    writes
        .iter()
        .map(|write| {
            (
                write.name.clone(),
                write.renamed_from.clone(),
                write.values.as_ref().map(|values| {
                    values
                        .iter()
                        .map(|(key, value)| (key.clone(), value.as_str().to_owned()))
                        .collect()
                }),
            )
        })
        .collect()
}

fn steps() -> Vec<Project> {
    vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[("A", "1")])]),
        Project::with(&[("production", &[("A", "2")])]),
        Project::with(&[("production", &[("A", "2"), ("B", "b")])]),
    ]
}

#[test]
fn an_environment_rolls_back_to_its_whole_state_after_an_entry() {
    let steps = steps();
    let store = history(&steps);
    let current = steps[3].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        after(1),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= 1"), row("B", "absent")]);
    assert_eq!(plan.environments[0].changing_rows(), 2);
    let writes = apply_rollback(
        &plan,
        &Choices::default(),
        &current,
        &opened(&store).keys,
        plan.generation,
    )
    .expect("applies");
    assert_eq!(
        written(&writes),
        vec![(
            "production".to_owned(),
            None,
            Some(vec![("A".to_owned(), "1".to_owned())])
        )]
    );
    let skip_b = Choices {
        skipped: HashSet::from([(0, 1)]),
        ..Choices::default()
    };
    let writes = apply_rollback(
        &plan,
        &skip_b,
        &current,
        &opened(&store).keys,
        plan.generation,
    )
    .expect("applies");
    assert_eq!(
        written(&writes)[0].2,
        Some(vec![
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "b".to_owned())
        ]),
        "a switched-off row keeps its current value"
    );
}

#[test]
fn a_key_rolls_back_to_its_value_before_a_change_even_the_newest() {
    let steps = steps();
    let store = history(&steps);
    let current = steps[3].values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        "A",
        id(2),
    )
    .expect("plan");
    assert_eq!(plan.kind, RollbackKind::Key);
    assert_eq!(rows(&plan), vec![row("A", "= 1")]);
    let newest = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        "B",
        id(3),
    )
    .expect("plan");
    assert_eq!(rows(&newest), vec![row("B", "absent")]);
}

#[test]
fn an_undo_reverts_only_the_keys_its_entry_changed() {
    let steps = steps();
    let store = history(&steps);
    let current = steps[3].values();
    let plan = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= 1")]);
    let plan = plan_undo(&opened(&store), &mut source(&store), &current, id(3)).expect("plan");
    assert_eq!(rows(&plan), vec![row("B", "absent")]);
}

#[test]
fn an_undo_of_a_key_changed_again_says_so() {
    let mut steps = steps();
    steps.push(Project::with(&[("production", &[("A", "3"), ("B", "b")])]));
    let store = history(&steps);
    let current = steps[4].values();
    let plan = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    let changed_again = plan.environments[0].rows[0]
        .changed_again
        .clone()
        .expect("changed again");
    assert_eq!(changed_again.action, Action::Set);
}

#[test]
fn an_undo_of_an_entry_that_touched_several_environments_covers_and_binds_each() {
    let start = Project::with(&[("production", &[("A", "1")]), ("staging", &[("A", "1")])]);
    let pulled = Project::with(&[
        ("production", &[("A", "p")]),
        ("staging", &[("A", "s"), ("FLAGS", "{}")]),
    ]);
    let mut store = Store::new();
    store
        .record(
            Action::Set,
            &Project::with(&[("production", &[])]),
            &start,
            &[],
        )
        .expect("created");
    store
        .record_with_id(
            id(2),
            Action::Pull,
            Detail {
                remote: Some(Remote::Org("acme")),
                remote_version: Some(14),
                ..Detail::default()
            },
            &start,
            &pulled,
            &[],
        )
        .expect("pulled");
    let current = pulled.values();
    let plan = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    assert_eq!(plan.environments.len(), 2);
    assert_eq!(
        rows(&plan),
        vec![row("A", "= 1"), row("A", "= 1"), row("FLAGS", "absent")]
    );
    let pulled_from = plan.environments[0].rows[0].pulled.clone().expect("pulled");
    assert_eq!(pulled_from.remote, Some(RemoteName::Org("acme".to_owned())));
    assert_eq!(pulled_from.version, Some(14));

    let mut changed = pulled.clone();
    changed.set("staging", "OTHER", "x");
    let changed_values = changed.values();
    assert_eq!(
        apply_rollback(
            &plan,
            &Choices::default(),
            &changed_values,
            &opened(&store).keys,
            plan.generation
        ),
        Err(Refusal::ChangedSinceReview),
        "each environment it covers is bound"
    );
}

#[test]
fn a_rollback_recreates_a_deleted_environment() {
    let steps = vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[]), ("local", &[("DB", "d"), ("R", "r")])]),
        Project::with(&[("production", &[("X", "x")])]),
    ];
    let store = history(&steps);
    let current = steps[2].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "local",
        after(1),
    )
    .expect("plan");
    let environment = &plan.environments[0];
    assert!(environment.recreates());
    assert_eq!(rows(&plan), vec![row("DB", "= d"), row("R", "= r")]);
    let writes = apply_rollback(
        &plan,
        &Choices::default(),
        &current,
        &opened(&store).keys,
        plan.generation,
    )
    .expect("applies");
    assert_eq!(
        written(&writes),
        vec![(
            "local".to_owned(),
            None,
            Some(vec![
                ("DB".to_owned(), "d".to_owned()),
                ("R".to_owned(), "r".to_owned())
            ])
        )]
    );
}

#[test]
fn a_rollback_to_before_an_environment_existed_removes_its_keys_and_deletes_it() {
    let steps = vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[("A", "1")])]),
        Project::with(&[
            ("production", &[("A", "1")]),
            ("preview", &[("U", "u"), ("F", "f")]),
        ]),
    ];
    let store = history(&steps);
    let current = steps[2].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "preview",
        after(1),
    )
    .expect("plan");
    assert!(plan.environments[0].offers_deletion());
    assert_eq!(rows(&plan), vec![row("F", "absent"), row("U", "absent")]);
    let keys = opened(&store).keys;
    let writes = apply_rollback(&plan, &Choices::default(), &current, &keys, plan.generation)
        .expect("applies");
    assert_eq!(written(&writes), vec![("preview".to_owned(), None, None)]);
    let keep = Choices {
        keep_empty: HashSet::from([0]),
        ..Choices::default()
    };
    let writes = apply_rollback(&plan, &keep, &current, &keys, plan.generation).expect("applies");
    assert_eq!(
        written(&writes),
        vec![("preview".to_owned(), None, Some(vec![]))]
    );
}

#[test]
fn rollbacks_follow_key_and_environment_renames() {
    let before_rename = Project::with(&[("stage", &[("OLD", "1")])]);
    let renamed = Project::with(&[("staging", &[("NEW", "1")])]);
    let changed = Project::with(&[("staging", &[("NEW", "2")])]);
    let mut store = Store::new();
    store
        .record(
            Action::Set,
            &Project::with(&[("stage", &[])]),
            &before_rename,
            &[],
        )
        .expect("created");
    store
        .record(
            Action::RenameKey,
            &before_rename,
            &renamed,
            &[
                Rename::Environment {
                    from: "stage",
                    to: "staging",
                },
                Rename::Key {
                    environment: "staging",
                    from: "OLD",
                    to: "NEW",
                },
            ],
        )
        .expect("renamed");
    store
        .record(Action::Set, &renamed, &changed, &[])
        .expect("changed");
    let current = changed.values();
    let key = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "staging",
        "NEW",
        id(3),
    )
    .expect("plan");
    assert_eq!(rows(&key), vec![row("NEW", "= 1")]);

    let environment = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "stage",
        after(1),
    )
    .expect("plan");
    assert_eq!(
        environment.environments[0].current.as_deref(),
        Some("staging")
    );
    assert_eq!(environment.environments[0].target.as_deref(), Some("stage"));
    assert_eq!(
        rows(&environment),
        vec![row("NEW", "absent"), row("OLD", "= 1")]
    );
    let writes = apply_rollback(
        &environment,
        &Choices::default(),
        &current,
        &opened(&store).keys,
        environment.generation,
    )
    .expect("applies");
    assert_eq!(
        written(&writes),
        vec![(
            "stage".to_owned(),
            Some("staging".to_owned()),
            Some(vec![("OLD".to_owned(), "1".to_owned())])
        )]
    );

    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    assert_eq!(undo.environments[0].target.as_deref(), Some("stage"));
    assert_eq!(
        rows(&undo),
        vec![row("NEW", "absent"), row("OLD", "= 1")],
        "an undo restores the value before the rename, replacing the later change"
    );
    assert!(undo.environments[0].rows[0].changed_again.is_some());
}

#[test]
fn a_gap_resolves_against_a_kept_value_with_the_same_digest() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let one = Project::with(&[("e", &[("A", "1")])]);
    let two = Project::with(&[("e", &[("A", "2")])]);
    store
        .record(Action::Set, &base, &one, &[])
        .expect("created");
    store.record(Action::Set, &one, &two, &[]).expect("two");
    // Outside history, A went back to 1 and then to 5; the next recorded
    // change finds 5 and records a gap whose before side is 2's digest.
    let outside = Project::with(&[("e", &[("A", "5")])]);
    let next = Project::with(&[("e", &[("A", "5"), ("B", "b")])]);
    store
        .record(Action::Set, &outside, &next, &[])
        .expect("gap and change");
    let current = next.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "e",
        after(2),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= 2"), row("B", "absent")]);
    let gaps = &plan.environments[0].rows[0].gaps;
    assert_eq!(gaps.len(), 1, "the rollback crosses the gap");
    assert!(gaps[0].until.is_some());
}

#[test]
fn a_value_history_never_kept_stays_unknown() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let one = Project::with(&[("e", &[("A", "1")])]);
    store
        .record(Action::Set, &base, &one, &[])
        .expect("created");
    let outside = Project::with(&[("e", &[("A", "seen nowhere")])]);
    let next = Project::with(&[("e", &[("A", "3")])]);
    store
        .record(Action::Set, &outside, &next, &[])
        .expect("gap and change");
    let current = next.values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "e",
        "A",
        id(2),
    )
    .expect("plan");
    assert_eq!(
        rows(&plan),
        vec![row("A", "= seen nowhere")],
        "the gap entry kept it"
    );
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "e",
        after(1),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= 1")]);

    // With a live gap, the newest value before it is known only by digest.
    let live = Project::with(&[("e", &[("A", "live")])]);
    let live_values = live.values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &live_values,
        "e",
        "A",
        id(2),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= seen nowhere")]);
    assert!(
        plan.environments[0].rows[0]
            .gaps
            .iter()
            .any(|gap| gap.until.is_none())
    );
}

#[test]
fn oversized_entries_leave_their_keys_unknown() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let mut imported = base.clone();
    for index in 0..1_460 {
        imported.set("e", &format!("KEY_{index:026}"), "v");
    }
    store
        .record(Action::Import, &base, &imported, &[])
        .expect("created");
    let mut changed = imported.clone();
    changed.set("e", "KEY_00000000000000000000000000", "w");
    store
        .record(Action::Set, &imported, &changed, &[])
        .expect("changed");
    let current = changed.values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "e",
        "KEY_00000000000000000000000001",
        id(1),
    )
    .expect("plan");
    assert_eq!(
        rows(&plan),
        vec![row("KEY_00000000000000000000000001", "unknown TooLarge")]
    );
}

#[test]
fn an_unreadable_part_makes_the_keys_that_changed_across_it_unknown() {
    let mut store = Store::new();
    let mut project = Project::with(&[("e", &[("KEEP", "k"), ("A", "1")])]);
    store
        .record(Action::Set, &Project::with(&[("e", &[])]), &project, &[])
        .expect("created");
    // Fill part 0 and roll into part 1 with changes to A only.
    let big = "x".repeat(6 * 1024);
    let mut round = 0;
    while store.head().parts.len() < 3 {
        round += 1;
        let mut next = project.clone();
        next.set("e", "A", &format!("{round}{big}"));
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    let middle = store.head().parts[1];
    let bytes = store
        .records
        .get_mut(&part_account(VAULT, middle).name())
        .expect("part");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let current = project.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "e",
        after(1),
    )
    .expect("plan");
    assert_eq!(
        rows(&plan),
        vec![row("A", "= 1")],
        "A's first value is in part 0 and resolves; KEEP never changed"
    );

    let timeline = read_timeline(
        &opened(&store),
        &mut source(&store),
        &current,
        &Filter::default(),
    )
    .expect("timeline");
    assert_eq!(timeline.unreadable_parts, 1);
    assert!(!timeline.damaged_tail);
    let unreadable = timeline
        .rows
        .iter()
        .find_map(|row| match row {
            TimelineRow::Unreadable { after, before, .. } => Some((*after, *before)),
            TimelineRow::Entry(_) => None,
        })
        .expect("an unreadable row");
    assert!(
        unreadable.0.is_some() && unreadable.1.is_some(),
        "bounded by its neighbours"
    );
    assert!(unreadable.0 < unreadable.1);
}

#[test]
fn every_binding_refuses_a_rollback_after_its_values_or_key_changed() {
    let steps = steps();
    let store = history(&steps);
    let current = steps[3].values();
    let keys = opened(&store).keys;
    let environment = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        after(1),
    )
    .expect("plan");
    let mut edited = steps[3].clone();
    edited.set("production", "C", "c");
    let edited_values = edited.values();
    assert_eq!(
        apply_rollback(
            &environment,
            &Choices::default(),
            &edited_values,
            &keys,
            environment.generation
        ),
        Err(Refusal::ChangedSinceReview)
    );
    assert_eq!(
        apply_rollback(
            &environment,
            &Choices::default(),
            &current,
            &keys,
            environment.generation + 1
        ),
        Err(Refusal::ChangedSinceReview),
        "a removal in between rotates the key"
    );

    let key = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        "A",
        id(2),
    )
    .expect("plan");
    assert!(
        apply_rollback(
            &key,
            &Choices::default(),
            &edited_values,
            &keys,
            key.generation
        )
        .is_ok(),
        "a key rollback is bound to its key only"
    );
    let mut a_changed = steps[3].clone();
    a_changed.set("production", "A", "9");
    let a_changed = a_changed.values();
    assert_eq!(
        apply_rollback(&key, &Choices::default(), &a_changed, &keys, key.generation),
        Err(Refusal::ChangedSinceReview)
    );
    let all_off = Choices {
        skipped: HashSet::from([(0, 0)]),
        ..Choices::default()
    };
    assert_eq!(
        apply_rollback(&key, &all_off, &current, &keys, key.generation),
        Err(Refusal::NothingToApply)
    );
}

#[test]
fn an_unknown_entry_or_environment_is_refused() {
    let steps = steps();
    let store = history(&steps);
    let current = steps[3].values();
    assert_eq!(
        plan_undo(&opened(&store), &mut source(&store), &current, [9; 16]),
        Err(PlanError::EntryNotFound)
    );
    assert_eq!(
        plan_environment_rollback(
            &opened(&store),
            &mut source(&store),
            &current,
            "nowhere",
            after(1)
        ),
        Err(PlanError::UnknownEnvironment)
    );
}

#[test]
fn undoing_a_rollback_puts_back_what_it_replaced() {
    let steps = steps();
    let mut store = history(&steps);
    let current = steps[3].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        "production",
        before(2),
    )
    .expect("plan");
    let writes = apply_rollback(
        &plan,
        &Choices::default(),
        &current,
        &opened(&store).keys,
        plan.generation,
    )
    .expect("applies");
    let rolled_back = Project::with(&[("production", &[("A", "1")])]);
    assert_eq!(
        written(&writes)[0].2,
        Some(vec![("A".to_owned(), "1".to_owned())])
    );
    store
        .record_with_id(
            id(4),
            Action::Rollback,
            Detail::default(),
            &steps[3],
            &rolled_back,
            &[],
        )
        .expect("rollback recorded");
    let now = rolled_back.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &now, id(4)).expect("plan");
    assert_eq!(rows(&undo), vec![row("A", "= 2"), row("B", "= b")]);
}

#[test]
fn the_timeline_lists_newest_first_with_partitioned_counts_and_filters() {
    let start = Project::with(&[("production", &[]), ("staging", &[])]);
    let one = Project::with(&[("production", &[("A", "1")]), ("staging", &[])]);
    let two = Project::with(&[("production", &[("A", "1")]), ("staging", &[("S", "s")])]);
    let three = Project::with(&[
        ("production", &[("A", "1"), ("P", "p")]),
        ("staging", &[("S", "s")]),
    ]);
    let mut store = Store::new();
    store.record(Action::Set, &start, &one, &[]).expect("one");
    store
        .record_with_id(
            id(2),
            Action::Import,
            Detail {
                file_name: Some(".env"),
                ..Detail::default()
            },
            &one,
            &two,
            &[],
        )
        .expect("two");
    store
        .record_with_id(
            id(3),
            Action::Pull,
            Detail {
                remote: Some(Remote::Personal),
                ..Detail::default()
            },
            &two,
            &three,
            &[],
        )
        .expect("three");
    let live = Project::with(&[
        ("production", &[("A", "changed")]),
        ("staging", &[("S", "s")]),
    ]);
    let live_values = live.values();
    let opened = opened(&store);
    let timeline = read_timeline(
        &opened,
        &mut source(&store),
        &live_values,
        &Filter::default(),
    )
    .expect("timeline");
    let ids: Vec<EntryId> = timeline
        .rows
        .iter()
        .filter_map(|row| match row {
            TimelineRow::Entry(info) => Some(info.id),
            TimelineRow::Unreadable { .. } => None,
        })
        .collect();
    assert_eq!(ids, vec![id(3), id(2), id(1)]);
    assert_eq!(timeline.readable, 3);
    assert_eq!(
        timeline.counts.values().sum::<usize>(),
        3,
        "the groups partition entries"
    );
    assert_eq!(timeline.counts[&SourceGroup::Cli], 1);
    assert_eq!(timeline.counts[&SourceGroup::Import], 1);
    assert_eq!(timeline.counts[&SourceGroup::Pull], 1);
    let gap = timeline.live_gap.clone().expect("a live gap");
    assert_eq!(gap.environments[0].name, "production");
    assert_eq!(timeline.oldest, Some(store.time - 2 * 60_000));

    let staging = read_timeline(
        &opened,
        &mut source(&store),
        &live_values,
        &Filter {
            environment: Some("staging"),
            ..Filter::default()
        },
    )
    .expect("timeline");
    assert_eq!(staging.readable, 1);
    assert!(staging.live_gap.is_none(), "the live gap is in production");

    let by_key = read_timeline(
        &opened,
        &mut source(&store),
        &live_values,
        &Filter {
            key: Some(KeyMatch::Contains("p")),
            source: Some(SourceGroup::Pull),
            limit: Some(5),
            ..Filter::default()
        },
    )
    .expect("timeline");
    assert_eq!(by_key.rows.len(), 1);
    assert_eq!(by_key.readable, 1);

    let found = reveal_entry(&opened, &mut source(&store), &id(2)[..3]);
    assert!(
        matches!(found, Ok(EntryLookup::Ambiguous)),
        "every test ID shares 3 bytes"
    );
    let Ok(EntryLookup::Found(revealed)) = reveal_entry(&opened, &mut source(&store), &id(2))
    else {
        panic!("found");
    };
    assert_eq!(revealed.info.detail.file_name.as_deref(), Some(".env"));
    assert_eq!(
        revealed.values[0][0]
            .after
            .as_ref()
            .map(|value| value.as_str()),
        Some("s")
    );
    assert_eq!(revealed.info.actor, Actor::Cli);
}

#[test]
fn the_timeline_names_deleted_environments_with_when_they_went() {
    let steps = vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[("A", "1")]), ("local", &[("L", "l")])]),
        Project::with(&[("production", &[("A", "1")])]),
    ];
    let store = history(&steps);
    let current = steps[2].values();
    let timeline = read_timeline(
        &opened(&store),
        &mut source(&store),
        &current,
        &Filter::default(),
    )
    .expect("timeline");
    let local = timeline
        .environments
        .iter()
        .find(|environment| environment.name == "local")
        .expect("local is listed");
    assert_eq!(local.deleted_at, Some(store.time));
    assert!(timeline
        .environments
        .iter()
        .any(|environment| environment.name == "production" && environment.deleted_at.is_none()));
}
