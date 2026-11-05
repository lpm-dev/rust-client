use super::*;
use crate::history::codec::{Actor, Detail, Remote};
use crate::history::read::{
    EntryLookup, Filter, IdPrefix, KeyMatch, SourceGroup, TimelineRow, read_timeline, reveal_entry,
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
        EnvironmentRef::AtPoint("production"),
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
        EnvironmentRef::Now("production"),
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
        EnvironmentRef::Now("production"),
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
        EnvironmentRef::AtPoint("local"),
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
        EnvironmentRef::AtPoint("preview"),
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
        EnvironmentRef::Now("staging"),
        "NEW",
        id(3),
    )
    .expect("plan");
    assert_eq!(rows(&key), vec![row("NEW", "= 1")]);

    let environment = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("stage"),
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
        EnvironmentRef::AtPoint("e"),
        after(2),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("A", "= 2"), row("B", "absent")]);
    let gaps = &plan.environments[0].rows[0].gaps;
    assert_eq!(gaps.len(), 1, "the rollback crosses the gap");
    assert!(gaps[0].until.is_some());
}

/// The ID of the newest entry recorded for a change made outside history.
fn outside_entry(store: &Store, current: &Values<'_>) -> EntryId {
    read_timeline(
        &opened(store),
        &mut source(store),
        current,
        &Filter::default(),
        false,
    )
    .expect("timeline")
    .rows
    .iter()
    .find_map(|row| match row {
        TimelineRow::Entry(info) if info.action == Action::Outside => Some(info.id),
        _ => None,
    })
    .expect("an outside entry")
}

#[test]
fn rolling_back_to_right_after_an_outside_change_keeps_it_and_says_nothing_of_it() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let one = Project::with(&[("e", &[("A", "1")])]);
    store
        .record(Action::Set, &base, &one, &[])
        .expect("created");
    // A changed to 2 outside history, then B was added: a gap entry comes
    // before the change's own entry.
    let outside = Project::with(&[("e", &[("A", "2")])]);
    let with_b = Project::with(&[("e", &[("A", "2"), ("B", "x")])]);
    store
        .record(Action::Set, &outside, &with_b, &[])
        .expect("gap and change");
    let three = Project::with(&[("e", &[("A", "3"), ("B", "x")])]);
    store
        .record(Action::Set, &with_b, &three, &[])
        .expect("three");
    let current = three.values();
    let gap = outside_entry(&store, &current);
    let plan = |side| {
        plan_environment_rollback(
            &opened(&store),
            &mut source(&store),
            &current,
            EnvironmentRef::Now("e"),
            Point { entry: gap, side },
        )
        .expect("plan")
    };

    let after_it = plan(RelatedSide::After);
    assert_eq!(rows(&after_it), vec![row("A", "= 2"), row("B", "absent")]);
    assert!(
        after_it.environments[0].rows[0].gaps.is_empty(),
        "the rollback keeps the outside change, so it doesn't replace it"
    );
    let before_it = plan(RelatedSide::Before);
    assert_eq!(rows(&before_it), vec![row("A", "= 1"), row("B", "absent")]);
    assert_eq!(
        before_it.environments[0].rows[0].gaps.len(),
        1,
        "rolling back to before it replaces it"
    );
}

#[test]
fn an_unknown_earlier_value_resolves_from_the_current_value_and_newer_kept_values() {
    // History starts with B: A was v, but history never kept v.
    let v_only = Project::with(&[("e", &[("A", "v")])]);
    let with_b = Project::with(&[("e", &[("A", "v"), ("B", "1")])]);
    // A changed to u outside history, then B changed, then A was set back
    // to v, recorded with both values.
    let outside = Project::with(&[("e", &[("A", "u"), ("B", "1")])]);
    let b2 = Project::with(&[("e", &[("A", "u"), ("B", "2")])]);
    let back = Project::with(&[("e", &[("A", "v"), ("B", "2")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &v_only, &with_b, &[])
        .expect("created");
    store
        .record(Action::Set, &outside, &b2, &[])
        .expect("gap and change");
    store.record(Action::Set, &b2, &back, &[]).expect("back");

    let current = back.values();
    let gap = outside_entry(&store, &current);
    let to_before_gap = |store: &Store, current: &Values<'_>| {
        plan_environment_rollback(
            &opened(store),
            &mut source(store),
            current,
            EnvironmentRef::Now("e"),
            Point {
                entry: gap,
                side: RelatedSide::Before,
            },
        )
        .expect("plan")
    };
    assert_eq!(
        rows(&to_before_gap(&store, &current)),
        vec![row("B", "= 1")],
        "A is v now and was v then, so nothing changes it"
    );

    // Once A changes again, v is only in the newer entries history kept.
    let later = Project::with(&[("e", &[("A", "w"), ("B", "2")])]);
    store
        .record(Action::Set, &back, &later, &[])
        .expect("later");
    let current = later.values();
    assert_eq!(
        rows(&to_before_gap(&store, &current)),
        vec![row("A", "= v"), row("B", "= 1")]
    );
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
        EnvironmentRef::Now("e"),
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
        EnvironmentRef::AtPoint("e"),
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
        EnvironmentRef::Now("e"),
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
        EnvironmentRef::Now("e"),
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
        EnvironmentRef::AtPoint("e"),
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
        false,
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
        EnvironmentRef::AtPoint("production"),
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
        EnvironmentRef::Now("production"),
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
            EnvironmentRef::AtPoint("nowhere"),
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
        EnvironmentRef::AtPoint("production"),
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
        false,
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
        false,
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
        false,
    )
    .expect("timeline");
    assert_eq!(by_key.rows.len(), 1);
    assert_eq!(by_key.readable, 1);

    let found = reveal_entry(
        &opened,
        &mut source(&store),
        &IdPrefix::parse(
            &id(2)[..3]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
        .expect("a prefix"),
    );
    assert!(
        matches!(found, Ok(EntryLookup::Ambiguous)),
        "every test ID shares 3 bytes"
    );
    let Ok(EntryLookup::Found(revealed)) =
        reveal_entry(&opened, &mut source(&store), &IdPrefix::whole(id(2)))
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
        false,
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

#[test]
fn damaged_history_records_are_found_beyond_the_listing() {
    use crate::history::read::check_records;
    let steps = steps();
    let store = history(&steps);
    let head = store.get(&head_account(VAULT)).expect("head").to_vec();
    let key = store.get(&key_account(VAULT)).expect("key").to_vec();
    let tail = |part: u16| {
        store
            .get(&part_account(VAULT, part))
            .map(std::borrow::Cow::Borrowed)
    };
    assert!(check_records(VAULT, Some(&head), Some(&key), tail).is_empty());

    let damage = check_records(VAULT, Some(b"{}"), Some(&key), tail);
    assert!(
        matches!(&damage[..], [crate::gate::Damage::InvalidRecord { kind, .. }] if kind == "history-head")
    );
    let damage = check_records(VAULT, Some(&head), Some(b"LPMK"), tail);
    assert!(
        matches!(&damage[..], [crate::gate::Damage::InvalidRecord { kind, .. }] if kind == "key")
    );
    let damage = check_records(VAULT, Some(&head), Some(&key), |_| {
        Some(std::borrow::Cow::Borrowed(&b"garbage"[..]))
    });
    assert!(
        matches!(&damage[..], [crate::gate::Damage::InvalidRecord { kind, .. }] if kind == "history")
    );
    let mut rolled = Store::new();
    let mut project = Project::with(&[("e", &[("A", "1")])]);
    rolled
        .record(Action::Set, &Project::with(&[("e", &[])]), &project, &[])
        .expect("created");
    while rolled.head().parts.len() < 2 {
        let mut next = project.clone();
        next.set(
            "e",
            "A",
            &format!("{}{}", rolled.time, "x".repeat(6 * 1024)),
        );
        rolled
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    let head = rolled.get(&head_account(VAULT)).expect("head").to_vec();
    let key = rolled.get(&key_account(VAULT)).expect("key").to_vec();
    let tail = rolled.head().tail();
    let without_tail = |part: u16| {
        (part != tail)
            .then(|| {
                rolled
                    .get(&part_account(VAULT, part))
                    .map(std::borrow::Cow::Borrowed)
            })
            .flatten()
    };
    assert!(
        check_records(VAULT, Some(&head), Some(&key), without_tail).is_empty(),
        "an absent tail with a readable part before it is an interrupted rollover"
    );
    let damage = check_records(VAULT, Some(&head), Some(&key), |_| None);
    assert!(
        matches!(&damage[..], [crate::gate::Damage::InvalidRecord { kind, .. }] if kind == "history"),
        "with the part before it missing too, no append can recover: {damage:?}"
    );
}

fn renamed_environment_history() -> (Store, Project) {
    let first = Project::with(&[("stage", &[("K", "1")])]);
    let renamed = Project::with(&[("staging", &[("K", "1")])]);
    let recreated = Project::with(&[("stage", &[("J", "2")]), ("staging", &[("K", "1")])]);
    let changed = Project::with(&[("stage", &[("J", "2")]), ("staging", &[("K", "3")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &Project::with(&[("stage", &[])]), &first, &[])
        .expect("created");
    store
        .record(
            Action::RenameEnvironment,
            &first,
            &renamed,
            &[Rename::Environment {
                from: "stage",
                to: "staging",
            }],
        )
        .expect("renamed");
    store
        .record(Action::Set, &renamed, &recreated, &[])
        .expect("a new stage");
    store
        .record(Action::Set, &recreated, &changed, &[])
        .expect("changed");
    (store, changed)
}

#[test]
fn a_key_rolls_back_through_a_removal_and_a_re_add() {
    let steps = vec![
        Project::with(&[("e", &[])]),
        Project::with(&[("e", &[("K", "a")])]),
        Project::with(&[("e", &[("K", "b")])]),
        Project::with(&[("e", &[])]),
        Project::with(&[("e", &[("K", "c")])]),
    ];
    let store = history(&steps);
    let current = steps[4].values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::Now("e"),
        "K",
        id(3),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("K", "= b")]);

    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    assert_eq!(rows(&undo), vec![row("K", "= a")]);
    let undone = &undo.environments[0].rows[0];
    assert_eq!(undone.current.as_deref().map(String::as_str), Some("c"));
    assert!(
        undone.changed_again.is_some(),
        "undoing it replaces the later value"
    );
}

#[test]
fn a_key_rolls_back_through_a_deleted_and_recreated_environment() {
    let steps = vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[]), ("stage", &[("K", "a")])]),
        Project::with(&[("production", &[]), ("stage", &[("K", "b")])]),
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[]), ("stage", &[("K", "c")])]),
    ];
    let store = history(&steps);
    let current = steps[4].values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::Now("stage"),
        "K",
        id(3),
    )
    .expect("plan");
    assert_eq!(rows(&plan), vec![row("K", "= b")]);
}

#[test]
fn a_rollback_never_overwrites_another_environment_with_its_earlier_name() {
    let (store, changed) = renamed_environment_history();
    let current = changed.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("stage"),
        after(1),
    );
    assert_eq!(plan, Err(PlanError::NameTaken("stage".to_owned())));
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2));
    assert_eq!(undo, Err(PlanError::NameTaken("stage".to_owned())));
}

#[test]
fn a_recreating_rollback_is_refused_once_another_environment_takes_the_name() {
    let steps = vec![
        Project::with(&[("production", &[])]),
        Project::with(&[("production", &[]), ("local", &[("DB", "d")])]),
        Project::with(&[("production", &[("X", "x")])]),
    ];
    let store = history(&steps);
    let reviewed = steps[2].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &reviewed,
        EnvironmentRef::AtPoint("local"),
        after(1),
    )
    .expect("plan");
    assert!(plan.environments[0].recreates());
    let taken = Project::with(&[("local", &[("MINE", "m")]), ("production", &[("X", "x")])]);
    assert_eq!(
        apply_rollback(
            &plan,
            &Choices::default(),
            &taken.values(),
            &opened(&store).keys,
            plan.generation,
        ),
        Err(Refusal::ChangedSinceReview)
    );
}

#[test]
fn undoing_a_change_that_kept_no_values_resolves_them_from_older_entries() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let mut small = base.clone();
    small.set("e", "A", "kept");
    store
        .record(Action::Set, &base, &small, &[])
        .expect("created");
    let mut imported = small.clone();
    imported.set("e", "A", "imported");
    for index in 0..700 {
        imported.set("e", &format!("KEY_{index:04}"), &"v".repeat(100));
    }
    let recorded = store
        .record(Action::Import, &small, &imported, &[])
        .expect("imported");
    assert!(
        matches!(recorded, Recorded::Appended { write, .. } if !write.values_kept),
        "{recorded:?}"
    );
    let current = imported.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    let a = undo.environments[0]
        .rows
        .iter()
        .find(|row| row.key == "A")
        .expect("A");
    assert_eq!(
        a.target,
        TargetValue::Known(zeroize::Zeroizing::new("kept".to_owned())),
        "its earlier value is kept in the entry before"
    );
}

#[test]
fn a_rollback_recreates_an_environment_that_was_empty_at_the_point() {
    let steps = vec![
        Project::with(&[("production", &[("A", "1")])]),
        Project::with(&[("production", &[("A", "2")]), ("preview", &[])]),
        Project::with(&[("production", &[("A", "3")])]),
    ];
    let store = history(&steps);
    let current = steps[2].values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("preview"),
        after(1),
    )
    .expect("plan");
    assert!(plan.environments[0].recreates());
    assert!(plan.changes_anything());
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
        vec![("preview".to_owned(), None, Some(vec![]))]
    );
}

#[test]
fn a_key_an_oversized_change_hid_stays_too_large_across_the_boundary_before_it() {
    let mut store = Store::new();
    // A existed before history began, so history never kept its value.
    let mut project = Project::with(&[("big", &[("A", "before history")])]);
    let mut next = project.clone();
    next.set("big", "B", "b");
    store
        .record(Action::Set, &project, &next, &[])
        .expect("created");
    project = next;
    let name = |index: usize| format!("{index:03}{}", "K".repeat(197));
    for step in 0..4 {
        let mut next = project.clone();
        for index in step * 95..(step + 1) * 95 {
            next.set("big", &name(index), "v");
        }
        store
            .record(Action::Set, &project, &next, &[])
            .expect("added");
        project = next;
    }
    let mut pulled = project.clone();
    pulled.set("big", "A", "pulled");
    for index in 0..380 {
        pulled.set("big", &name(index), "w");
    }
    store
        .record(Action::Pull, &project, &pulled, &[])
        .expect("pulled");
    store.with_entries(store.head().tail(), |entries| {
        assert_eq!(entries[0].id, id(6), "the pull starts its part");
        assert!(matches!(entries[0].environments[0].keys, Keys::Count(_)));
    });
    let current = pulled.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("big"),
        before(6),
    )
    .expect("plan");
    let a = plan.environments[0]
        .rows
        .iter()
        .find(|row| row.key == "A")
        .expect("A's row");
    assert!(
        matches!(a.target, TargetValue::Unknown(UnknownReason::TooLarge)),
        "the pull was too large to keep, not a change made outside history: {:?}",
        a.target
    );
}

#[test]
fn an_oversized_change_that_removed_keys_says_so_and_its_boundary_names_them() {
    let mut store = Store::new();
    let mut project = Project::with(&[("big", &[("X", "x")])]);
    store
        .record(Action::Set, &Project::with(&[("big", &[])]), &project, &[])
        .expect("created");
    let name = |index: usize| format!("{index:03}{}", "K".repeat(197));
    for step in 0..4 {
        let mut next = project.clone();
        for index in step * 95..(step + 1) * 95 {
            next.set("big", &name(index), "v");
        }
        store
            .record(Action::Set, &project, &next, &[])
            .expect("added");
        project = next;
    }
    let mut pulled = project.clone();
    pulled.environments.get_mut("big").expect("big").remove("X");
    for index in 0..380 {
        pulled.set("big", &name(index), "w");
    }
    store
        .record(Action::Pull, &project, &pulled, &[])
        .expect("pulled");
    let pull = id(6);
    store.with_entries(store.head().tail(), |entries| {
        assert_eq!(entries[0].id, pull, "the pull starts its part");
        assert!(matches!(entries[0].environments[0].keys, Keys::Count(_)));
    });
    let current = pulled.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, pull).expect("plan");
    assert_eq!(
        undo.environments[0].unnamed_keys,
        Some(UnknownReason::TooLarge)
    );
    assert!(undo.environments[0].rows.is_empty());

    let before_pull = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("big"),
        before(6),
    )
    .expect("plan");
    assert_eq!(before_pull.environments[0].unnamed_keys, None);
    let x = before_pull.environments[0]
        .rows
        .iter()
        .find(|row| row.key == "X")
        .expect("the part before names X");
    assert_eq!(
        x.target,
        TargetValue::Known(zeroize::Zeroizing::new("x".to_owned()))
    );
    assert_eq!(before_pull.environments[0].changing_rows(), 381);
}

#[test]
fn undoing_a_rename_whose_key_was_renamed_back_lists_the_key_once() {
    let first = Project::with(&[("e", &[("A", "1")])]);
    let renamed = Project::with(&[("e", &[("B", "1")])]);
    let changed = Project::with(&[("e", &[("B", "2")])]);
    let back = Project::with(&[("e", &[("A", "2")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &Project::with(&[("e", &[])]), &first, &[])
        .expect("created");
    store
        .record(
            Action::RenameKey,
            &first,
            &renamed,
            &[Rename::Key {
                environment: "e",
                from: "A",
                to: "B",
            }],
        )
        .expect("renamed");
    store
        .record(Action::Set, &renamed, &changed, &[])
        .expect("changed");
    store
        .record(
            Action::RenameKey,
            &changed,
            &back,
            &[Rename::Key {
                environment: "e",
                from: "B",
                to: "A",
            }],
        )
        .expect("renamed back");
    let current = back.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    assert_eq!(rows(&undo), vec![row("A", "= 1")]);
}

#[test]
fn the_rows_of_a_renamed_key_are_linked_and_apply_together() {
    let before_rename = Project::with(&[("e", &[("OLD", "1"), ("OTHER", "o")])]);
    let renamed = Project::with(&[("e", &[("NEW", "1"), ("OTHER", "p")])]);
    let mut store = Store::new();
    store
        .record(
            Action::Set,
            &Project::with(&[("e", &[])]),
            &before_rename,
            &[],
        )
        .expect("created");
    store
        .record(
            Action::RenameKey,
            &before_rename,
            &renamed,
            &[Rename::Key {
                environment: "e",
                from: "OLD",
                to: "NEW",
            }],
        )
        .expect("renamed");
    let current = renamed.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("e"),
        after(1),
    )
    .expect("plan");
    let linked: Vec<(String, Vec<String>)> = plan.environments[0]
        .rows
        .iter()
        .map(|row| (row.key.clone(), row.linked.clone()))
        .collect();
    assert_eq!(
        linked,
        vec![
            ("NEW".to_owned(), vec!["OLD".to_owned()]),
            ("OLD".to_owned(), vec!["NEW".to_owned()]),
            ("OTHER".to_owned(), vec![]),
        ]
    );
    let new_row = plan.environments[0]
        .rows
        .iter()
        .position(|row| row.key == "NEW")
        .expect("NEW");
    let skip_new = Choices {
        skipped: HashSet::from([(0, new_row)]),
        ..Choices::default()
    };
    let writes = apply_rollback(
        &plan,
        &skip_new,
        &current,
        &opened(&store).keys,
        plan.generation,
    )
    .expect("applies");
    assert_eq!(
        written(&writes),
        vec![(
            "e".to_owned(),
            None,
            Some(vec![
                ("NEW".to_owned(), "1".to_owned()),
                ("OTHER".to_owned(), "o".to_owned())
            ])
        )],
        "skipping one half of the rename skips the other, so the value stays"
    );
}

#[test]
fn a_rollback_resolves_digests_with_one_pass_over_the_keys() {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let mut first = base.clone();
    for index in 0..400 {
        first.set("e", &format!("K{index:03}"), &format!("first {index}"));
    }
    store
        .record(Action::Set, &base, &first, &[])
        .expect("created");
    let mut outside = first.clone();
    for index in 0..400 {
        outside.set("e", &format!("K{index:03}"), &format!("outside {index}"));
    }
    let mut next = outside.clone();
    next.set("e", "NEW", "n");
    store
        .record(Action::Set, &outside, &next, &[])
        .expect("gap and change");
    let current = next.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("e"),
        after(1),
    )
    .expect("plan");
    assert_eq!(plan.environments[0].changing_rows(), 401);
    assert!(
        plan.environments[0]
            .rows
            .iter()
            .all(|row| !matches!(row.target, TargetValue::Unknown(_)))
    );
}

#[test]
fn the_timeline_follows_a_key_and_an_environment_back_through_renames() {
    let first = Project::with(&[("stage", &[("OLD", "1")])]);
    let changed = Project::with(&[("stage", &[("OLD", "2")])]);
    let renamed = Project::with(&[("staging", &[("NEW", "2")])]);
    let after_rename = Project::with(&[("staging", &[("NEW", "3")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &Project::with(&[("stage", &[])]), &first, &[])
        .expect("created");
    store
        .record(Action::Set, &first, &changed, &[])
        .expect("changed");
    store
        .record(
            Action::RenameKey,
            &changed,
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
        .record(Action::Set, &renamed, &after_rename, &[])
        .expect("changed again");
    let current = after_rename.values();
    let timeline = |filter: Filter<'_>| {
        read_timeline(
            &opened(&store),
            &mut source(&store),
            &current,
            &filter,
            false,
        )
        .expect("timeline")
    };
    let by_key = timeline(Filter {
        key: Some(KeyMatch::Exact("NEW")),
        ..Filter::default()
    });
    assert_eq!(
        by_key.readable, 4,
        "every change to the key, under both names"
    );
    let by_environment = timeline(Filter {
        environment: Some("staging"),
        ..Filter::default()
    });
    assert_eq!(by_environment.readable, 4);
    assert_eq!(
        timeline(Filter::default())
            .environments
            .iter()
            .map(|environment| environment.name.as_str())
            .collect::<Vec<_>>(),
        vec!["staging"],
        "stage is staging's earlier name, not another environment"
    );
}

#[test]
fn a_missing_newest_part_with_nothing_before_it_is_damage() {
    let steps = steps();
    let store = history(&steps[..2]);
    let head = store.get(&head_account(VAULT)).expect("head").to_vec();
    let key = store.get(&key_account(VAULT)).expect("key").to_vec();
    let damage = crate::history::read::check_records(VAULT, Some(&head), Some(&key), |_| None);
    assert_eq!(damage.len(), 1, "{damage:?}");
}

/// A project of `keys` keys whose history spans several parts, every key
/// changed once outside history at the end.
fn spread_history(keys: usize) -> (Store, Project) {
    let mut store = Store::new();
    let base = Project::with(&[("e", &[])]);
    let mut project = base.clone();
    for index in 0..keys {
        project.set("e", &format!("K{index:04}"), &format!("first {index}"));
    }
    store
        .record(Action::Set, &base, &project, &[])
        .expect("created");
    let mut round = 0;
    while store.head().parts.len() < 6 {
        round += 1;
        let mut next = project.clone();
        next.set("e", "BULK", &format!("{round}{}", "x".repeat(6 * 1024)));
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    let mut outside = project.clone();
    for index in 0..keys {
        outside.set("e", &format!("K{index:04}"), &format!("outside {index}"));
    }
    let mut next = outside.clone();
    next.set("e", "NEW", "n");
    store
        .record(Action::Set, &outside, &next, &[])
        .expect("gap and change");
    (store, next)
}

#[test]
fn a_rollback_digests_each_value_once_and_visits_each_key_a_bounded_number_of_times() {
    let keys = 300;
    let (store, current_project) = spread_history(keys);
    let parts = store.head().parts.len();
    let current = current_project.values();
    let opened = opened(&store);
    crate::work::reset();
    let plan = plan_environment_rollback(
        &opened,
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("e"),
        after(1),
    )
    .expect("plan");
    assert_eq!(plan.environments[0].changing_rows(), keys + 2);
    let digests = crate::work::count(crate::work::Work::ValueDigest);
    assert!(
        digests <= keys + 2 + 2,
        "{digests} value digests for {keys} keys over {parts} parts"
    );
    let visits = crate::work::count(crate::work::Work::KeyVisit);
    assert!(
        visits <= (keys + 2) * (parts + 2),
        "{visits} key visits for {keys} keys over {parts} parts"
    );
    assert_eq!(
        crate::work::count(crate::work::Work::PartDecode),
        parts,
        "each part is decoded once"
    );
}

#[test]
fn an_environment_named_as_it_is_now_is_found_at_the_point_under_its_earlier_name() {
    let before_rename = Project::with(&[("stage", &[("K", "1")])]);
    let renamed = Project::with(&[("staging", &[("K", "1")])]);
    let changed = Project::with(&[("staging", &[("K", "2")])]);
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
            Action::RenameEnvironment,
            &before_rename,
            &renamed,
            &[Rename::Environment {
                from: "stage",
                to: "staging",
            }],
        )
        .expect("renamed");
    store
        .record(Action::Set, &renamed, &changed, &[])
        .expect("changed");
    let current = changed.values();
    let by_now = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::Now("staging"),
        after(1),
    )
    .expect("plan");
    let at_point = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("stage"),
        after(1),
    )
    .expect("plan");
    assert_eq!(by_now, at_point);
    assert_eq!(by_now.environments[0].target.as_deref(), Some("stage"));
    assert!(by_now.environments[0].renames());

    let key = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("stage"),
        "K",
        id(2),
    )
    .expect("plan");
    assert_eq!(key.environments[0].current.as_deref(), Some("staging"));
    assert_eq!(rows(&key), vec![row("K", "= 1")]);
}

#[test]
fn an_id_prefix_matches_by_hex_digit_and_a_whole_id_stops_at_its_entry() {
    let id = [0xab, 0xcd, 0xef, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert!(IdPrefix::parse("abcde").is_none(), "too short");
    assert!(IdPrefix::parse("abcdeg").is_none(), "not hex");
    assert!(IdPrefix::parse("ABCDEF1").expect("odd").matches(&id));
    assert!(!IdPrefix::parse("abcdef2").expect("odd").matches(&id));
    assert!(IdPrefix::whole(id).matches(&id));

    let steps = steps();
    let store = history(&steps);
    let mut reads = 0;
    let mut counted = |part: u16| {
        reads += 1;
        Ok(store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec))
    };
    let found =
        crate::history::read::find_entry(&opened(&store), &mut counted, &IdPrefix::whole(id_of(3)))
            .expect("lookup");
    assert!(matches!(found, EntryLookup::Found(info) if info.id == id_of(3)));
    assert_eq!(reads, 1);
}

fn id_of(n: u8) -> EntryId {
    id(n)
}

fn record_all(steps: &[(Action, Project, Vec<Rename<'static>>)]) -> Store {
    let mut store = Store::new();
    for pair in steps.windows(2) {
        let (_, before, _) = &pair[0];
        let (action, after, renames) = &pair[1];
        store
            .record(*action, before, after, renames)
            .expect("recorded");
    }
    store
}

#[test]
fn an_environment_created_after_a_rename_away_rolls_back_to_before_it_existed() {
    let x1 = Project::with(&[("X", &[("A", "1")])]);
    let y1 = Project::with(&[("Y", &[("A", "1")])]);
    let new_x = Project::with(&[("X", &[("B", "2")]), ("Y", &[("A", "1")])]);
    let store = record_all(&[
        (Action::Set, Project::with(&[("X", &[])]), vec![]),
        (Action::Set, x1, vec![]),
        (
            Action::RenameEnvironment,
            y1,
            vec![Rename::Environment { from: "X", to: "Y" }],
        ),
        (Action::Set, new_x.clone(), vec![]),
    ]);
    let current = new_x.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::Now("X"),
        before(2),
    )
    .expect("the new X didn't exist then");
    assert!(plan.environments[0].offers_deletion(), "{plan:?}");

    let c = Project::with(&[("C", &[("B", "2")]), ("Y", &[("A", "1")])]);
    let mut renaming = record_all(&[
        (Action::Set, Project::with(&[("X", &[])]), vec![]),
        (Action::Set, Project::with(&[("X", &[("A", "1")])]), vec![]),
        (
            Action::RenameEnvironment,
            Project::with(&[("Y", &[("A", "1")])]),
            vec![Rename::Environment { from: "X", to: "Y" }],
        ),
        (Action::Set, new_x.clone(), vec![]),
    ]);
    renaming
        .record(
            Action::RenameEnvironment,
            &new_x,
            &c,
            &[Rename::Environment { from: "X", to: "C" }],
        )
        .expect("renamed");
    let current = c.values();
    let plan = plan_environment_rollback(
        &opened(&renaming),
        &mut source(&renaming),
        &current,
        EnvironmentRef::Now("C"),
        before(2),
    )
    .expect("C exists now and didn't then");
    assert!(plan.environments[0].offers_deletion(), "{plan:?}");
}

#[test]
fn a_key_rollback_in_an_environment_renamed_away_and_deleted_refuses_a_taken_name() {
    let store = record_all(&[
        (Action::Set, Project::with(&[("P", &[])]), vec![]),
        (
            Action::Set,
            Project::with(&[("P", &[("K", "old1")])]),
            vec![],
        ),
        (
            Action::Set,
            Project::with(&[("P", &[("K", "old2")])]),
            vec![],
        ),
        (
            Action::RenameEnvironment,
            Project::with(&[("Q", &[("K", "old2")])]),
            vec![Rename::Environment { from: "P", to: "Q" }],
        ),
        (Action::DeleteEnvironment, Project::with(&[]), vec![]),
        (
            Action::Set,
            Project::with(&[("P", &[("K", "new")])]),
            vec![],
        ),
    ]);
    let current = Project::with(&[("P", &[("K", "new")])]);
    let current = current.values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::AtPoint("P"),
        "K",
        id(2),
    );
    assert_eq!(plan, Err(PlanError::NameTaken("P".to_owned())));
}

#[test]
fn undoing_a_change_keeps_the_environment_s_name_now() {
    let store = record_all(&[
        (Action::Set, Project::with(&[("E", &[])]), vec![]),
        (Action::Set, Project::with(&[("E", &[("A", "1")])]), vec![]),
        (Action::Set, Project::with(&[("E", &[("A", "2")])]), vec![]),
        (
            Action::RenameEnvironment,
            Project::with(&[("F", &[("A", "2")])]),
            vec![Rename::Environment { from: "E", to: "F" }],
        ),
    ]);
    let current = Project::with(&[("F", &[("A", "2")])]);
    let current = current.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    let environment = &undo.environments[0];
    assert_eq!(
        (
            environment.current.as_deref(),
            environment.target.as_deref()
        ),
        (Some("F"), Some("F")),
        "an undo restores values, not the name"
    );
    assert_eq!(rows(&undo), vec![row("A", "= 1")]);
}

#[test]
fn a_key_rolled_back_by_its_earlier_name_rolls_back_the_key_it_became() {
    let store = record_all(&[
        (Action::Set, Project::with(&[("e", &[])]), vec![]),
        (Action::Set, Project::with(&[("e", &[("A", "1")])]), vec![]),
        (Action::Set, Project::with(&[("e", &[("A", "2")])]), vec![]),
        (
            Action::RenameKey,
            Project::with(&[("e", &[("B", "2")])]),
            vec![Rename::Key {
                environment: "e",
                from: "A",
                to: "B",
            }],
        ),
    ]);
    let current = Project::with(&[("e", &[("B", "2")])]);
    let current = current.values();
    let plan = plan_key_rollback(
        &opened(&store),
        &mut source(&store),
        &current,
        EnvironmentRef::Now("e"),
        "A",
        id(2),
    )
    .expect("plan");
    assert_eq!(
        rows(&plan),
        vec![row("B", "= 1")],
        "no copy under the old name"
    );
}

#[test]
fn a_rollback_to_after_an_outside_change_reads_only_the_parts_it_needs() {
    let keys = 50;
    let (store, current_project) = spread_history(keys);
    let current = current_project.values();
    let opened = opened(&store);
    let mut reads = 0;
    let mut counted = |part: u16| {
        reads += 1;
        Ok(store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec))
    };
    // The newest entry is the change; the one before it, in the same part,
    // is the outside entry.
    let timeline = read_timeline(
        &opened,
        &mut source(&store),
        &current,
        &Filter::default(),
        false,
    )
    .expect("timeline");
    let TimelineRow::Entry(gap) = &timeline.rows[1] else {
        panic!("an entry");
    };
    assert_eq!(gap.action, Action::Outside);
    plan_environment_rollback(
        &opened,
        &mut counted,
        &current,
        EnvironmentRef::AtPoint("e"),
        Point {
            entry: gap.id,
            side: RelatedSide::After,
        },
    )
    .expect("plan");
    assert_eq!(reads, 1, "the state after the outside entry is fully known");
}

#[test]
fn a_timeline_filter_stops_where_its_name_was_renamed_away() {
    let store = record_all(&[
        (Action::Set, Project::with(&[("e", &[])]), vec![]),
        (Action::Set, Project::with(&[("e", &[("K", "1")])]), vec![]),
        (Action::Set, Project::with(&[("e", &[("K", "2")])]), vec![]),
        (
            Action::RenameKey,
            Project::with(&[("e", &[("J", "2")])]),
            vec![Rename::Key {
                environment: "e",
                from: "K",
                to: "J",
            }],
        ),
        (
            Action::Set,
            Project::with(&[("e", &[("J", "2"), ("K", "n")])]),
            vec![],
        ),
    ]);
    let current = Project::with(&[("e", &[("J", "2"), ("K", "n")])]);
    let current = current.values();
    let count = |key: &'static str| {
        read_timeline(
            &opened(&store),
            &mut source(&store),
            &current,
            &Filter {
                key: Some(KeyMatch::Exact(key)),
                ..Filter::default()
            },
            false,
        )
        .expect("timeline")
        .readable
    };
    assert_eq!(count("K"), 1, "only the new K's own entry");
    assert_eq!(count("J"), 3, "J's rename and the changes it made as K");

    let x = record_all(&[
        (Action::Set, Project::with(&[("X", &[])]), vec![]),
        (Action::Set, Project::with(&[("X", &[("A", "1")])]), vec![]),
        (
            Action::RenameEnvironment,
            Project::with(&[("Y", &[("A", "1")])]),
            vec![Rename::Environment { from: "X", to: "Y" }],
        ),
        (
            Action::Set,
            Project::with(&[("X", &[("B", "2")]), ("Y", &[("A", "1")])]),
            vec![],
        ),
    ]);
    let current = Project::with(&[("X", &[("B", "2")]), ("Y", &[("A", "1")])]);
    let current = current.values();
    let count = |environment: &'static str| {
        read_timeline(
            &opened(&x),
            &mut source(&x),
            &current,
            &Filter {
                environment: Some(environment),
                ..Filter::default()
            },
            false,
        )
        .expect("timeline")
        .readable
    };
    assert_eq!(count("X"), 1, "only the new X's own entry");
    assert_eq!(count("Y"), 2);
}

#[test]
fn a_missing_newest_part_with_nothing_before_it_reads_as_a_damaged_tail() {
    let steps = steps();
    let mut store = history(&steps[..2]);
    store.delete(&part_account(VAULT, 0));
    let current = steps[1].values();
    let retained = crate::history::read::read_retained(&opened(&store), &mut source(&store))
        .expect("retained");
    assert!(retained.damaged_tail);
    let timeline = read_timeline(
        &opened(&store),
        &mut source(&store),
        &current,
        &Filter::default(),
        false,
    )
    .expect("timeline");
    assert!(timeline.damaged_tail);
}

#[test]
fn a_timeline_builds_only_the_rows_it_shows_and_reveals_them_in_the_same_walk() {
    let (store, current_project) = spread_history(50);
    let current = current_project.values();
    let parts = store.head().parts.len();
    let mut reads = 0;
    let mut counted = |part: u16| {
        reads += 1;
        Ok(store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec))
    };
    crate::work::reset();
    let timeline = read_timeline(
        &opened(&store),
        &mut counted,
        &current,
        &Filter {
            limit: Some(2),
            ..Filter::default()
        },
        true,
    )
    .expect("timeline");
    assert_eq!(timeline.rows.len(), 2);
    assert_eq!(
        crate::work::count(crate::work::Work::Listed),
        2,
        "two rows built"
    );
    assert_eq!(timeline.values.len(), 2, "both shown rows revealed");
    assert_eq!(reads, parts, "one walk");
    assert!(timeline.readable > 2, "counts still cover every entry");
}

#[test]
fn undoing_one_step_of_a_key_swap_shows_the_value_it_replaces() {
    let store = record_all(&[
        (Action::Set, Project::with(&[("e", &[])]), vec![]),
        (
            Action::Set,
            Project::with(&[("e", &[("A", "a"), ("B", "b")])]),
            vec![],
        ),
        (
            Action::RenameKey,
            Project::with(&[("e", &[("B", "b"), ("T", "a")])]),
            vec![Rename::Key {
                environment: "e",
                from: "A",
                to: "T",
            }],
        ),
        (
            Action::RenameKey,
            Project::with(&[("e", &[("A", "b"), ("T", "a")])]),
            vec![Rename::Key {
                environment: "e",
                from: "B",
                to: "A",
            }],
        ),
        (
            Action::RenameKey,
            Project::with(&[("e", &[("A", "b"), ("B", "a")])]),
            vec![Rename::Key {
                environment: "e",
                from: "T",
                to: "B",
            }],
        ),
    ]);
    let current = Project::with(&[("e", &[("A", "b"), ("B", "a")])]);
    let current = current.values();
    let undo = plan_undo(&opened(&store), &mut source(&store), &current, id(2)).expect("plan");
    let a = undo.environments[0]
        .rows
        .iter()
        .find(|row| row.key == "A")
        .expect("A");
    assert_eq!(
        a.current.as_deref().map(String::as_str),
        Some("b"),
        "the review shows A's value now"
    );
    assert!(
        a.changed_again.is_some(),
        "and says it changed after the undone step"
    );
    assert_eq!(
        a.linked,
        vec!["B".to_owned()],
        "the rename's two rows go together"
    );
}

#[test]
fn a_key_removed_outside_history_carries_the_gap_into_its_rollback() {
    let mut store = Store::new();
    let empty = Project::with(&[("e", &[])]);
    let first = Project::with(&[("e", &[("A", "1"), ("B", "1")])]);
    store
        .record(Action::Set, &empty, &first, &[])
        .expect("created");
    let current = Project::with(&[("e", &[("B", "1")])]);
    let values = current.values();
    let plan = plan_environment_rollback(
        &opened(&store),
        &mut source(&store),
        &values,
        EnvironmentRef::AtPoint("e"),
        after(1),
    )
    .expect("plan");
    let a = plan.environments[0]
        .rows
        .iter()
        .find(|row| row.key == "A")
        .expect("A comes back");
    assert!(
        a.gaps.iter().any(|gap| gap.until.is_none()),
        "putting A back replaces its removal outside history"
    );
}
