use super::*;
use crate::history::codec::{EnvironmentKind, KeyKind, Keys, Side, Unkept};
use crate::history::test_support::{Project, Recorded, Store, VAULT};
use crate::history::{head_account, key_account, part_account};
use crate::keyring::STABLE_KEY_RECORD_BYTES;

fn appended(recorded: Result<Recorded, NotRecorded>) -> (bool, AppendShape, u16, bool, bool) {
    match recorded.expect("recorded") {
        Recorded::Appended {
            head_written,
            write,
        } => (
            head_written,
            write.shape,
            write.part,
            write.gap,
            write.values_kept,
        ),
        other => panic!("expected an append, got {other:?}"),
    }
}

fn big(byte: char, kib: usize) -> String {
    std::iter::repeat_n(byte, kib * 1024).collect()
}

/// A store with history created by setting `A`, and the project after it.
fn created() -> (Store, Project) {
    let mut store = Store::new();
    let before = Project::with(&[("default", &[])]);
    let after = Project::with(&[("default", &[("A", "1")])]);
    assert!(matches!(
        store.record(Action::Set, &before, &after, &[]),
        Ok(Recorded::Created)
    ));
    (store, after)
}

#[test]
fn creation_needs_a_key_change_and_writes_the_marker_key_head_and_part_zero() {
    let mut store = Store::new();
    let empty = Project::default();
    let with_environment = Project::with(&[("default", &[])]);
    assert!(matches!(
        store.record(Action::CreateEnvironment, &empty, &with_environment, &[]),
        Ok(Recorded::NoKeyChanges)
    ));
    assert!(
        store.records.is_empty(),
        "nothing exists before a key changes"
    );

    let (store, _) = created();
    let marker = store.marker().expect("marker");
    assert_eq!(
        marker.feature("history"),
        Some(&crate::history::feature_entry())
    );
    assert_eq!(
        store.get(&key_account(VAULT)).map(<[u8]>::len),
        Some(STABLE_KEY_RECORD_BYTES)
    );
    let head = store.head();
    assert_eq!(
        (head.parts.clone(), head.tail_epoch, head.ring_limit),
        (vec![0], 1, 16)
    );
    store.with_entries(0, |entries| {
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].seq, 1);
        let Keys::Changes(changes) = &entries[0].environments[0].keys else {
            panic!("keys")
        };
        assert_eq!(changes[0].kind, KeyKind::Added);
        assert!(matches!(changes[0].after, Side::Value { value: "1", .. }));
    });
}

#[test]
fn a_change_without_key_changes_is_recorded_once_history_exists() {
    let (mut store, project) = created();
    let mut with_environment = project.clone();
    with_environment
        .environments
        .insert("preview".to_owned(), Default::default());
    let (head_written, shape, _, gap, _) =
        appended(store.record(Action::CreateEnvironment, &project, &with_environment, &[]));
    assert!(!head_written && !gap);
    assert_eq!(shape, AppendShape::Steady);
    store.with_entries(0, |entries| {
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].environments[0].kind, EnvironmentKind::Created);
        assert_eq!(entries[1].key_count(), 0);
    });
}

#[test]
fn steady_appends_record_values_before_and_after_and_update_the_summary() {
    let (mut store, project) = created();
    let mut changed = project.clone();
    changed.set("default", "A", "2");
    let (head_written, shape, part, gap, values_kept) =
        appended(store.record(Action::Set, &project, &changed, &[]));
    assert_eq!(
        (head_written, shape, part, gap, values_kept),
        (false, AppendShape::Steady, 0, false, true)
    );
    store.with_entries(0, |entries| {
        let Keys::Changes(changes) = &entries[1].environments[0].keys else {
            panic!("keys")
        };
        assert!(matches!(changes[0].before, Side::Value { value: "1", .. }));
        assert!(matches!(changes[0].after, Side::Value { value: "2", .. }));
        assert_eq!(entries[1].seq, 2);
    });
    let plaintext = store.plaintext(0);
    let part = Part::decode(&plaintext).expect("part");
    assert_eq!(
        part.summary,
        changed.values().summary(&store.key().digest_keys(VAULT))
    );
    assert!(matches!(
        store.record(Action::Set, &changed, &changed, &[]),
        Ok(Recorded::Unchanged)
    ));
}

#[test]
fn a_retried_change_is_recorded_once() {
    let (mut store, project) = created();
    let mut changed = project.clone();
    changed.set("default", "B", "b");
    let id = store.next_change_id();
    appended(store.record_with_id(id, Action::Set, Detail::default(), &project, &changed, &[]));
    let records = store.records.clone();
    assert!(matches!(
        store.record_with_id(id, Action::Set, Detail::default(), &project, &changed, &[]),
        Ok(Recorded::AlreadyRecorded)
    ));
    assert_eq!(store.records, records, "a retry writes nothing");
}

#[test]
fn changes_made_outside_history_are_recorded_as_a_gap_before_the_change() {
    let (mut store, project) = created();
    let mut outside = project;
    outside.set("default", "A", "changed elsewhere");
    outside.set("staging", "X", "x");
    let mut changed = outside.clone();
    changed.set("default", "B", "b");
    let (_, _, _, gap, _) = appended(store.record(Action::Set, &outside, &changed, &[]));
    assert!(gap);
    let keys = store.key().digest_keys(VAULT);
    store.with_entries(0, |entries| {
        assert_eq!(entries.len(), 3);
        let gap = &entries[1];
        assert_eq!((gap.actor, gap.action), (Actor::Outside, Action::Outside));
        assert_eq!(gap.since, Some(entries[0].time));
        assert_eq!(gap.seq, 2);
        assert_eq!(entries[2].seq, 3);
        let Keys::Changes(default) = &gap.environments[0].keys else {
            panic!("keys")
        };
        assert_eq!(
            default[0].before,
            Side::DigestOnly {
                digest: keys.value(b"1"),
                reason: Unkept::NotRecorded
            }
        );
        assert!(matches!(
            default[0].after,
            Side::Value {
                value: "changed elsewhere",
                ..
            }
        ));
        assert_eq!(gap.environments[1].kind, EnvironmentKind::Created);
    });
}

/// Append changes to `A` of `kib` KiB each until a write isn't steady,
/// returning that write and the project after it.
fn append_until_not_steady(
    store: &mut Store,
    mut project: Project,
    kib: usize,
) -> ((bool, AppendShape, u16, bool, bool), Project) {
    for round in 0..64 {
        let mut changed = project.clone();
        changed.set(
            "default",
            "A",
            &big(char::from(b'a' + (round % 26) as u8), kib),
        );
        let result = appended(store.record(Action::Set, &project, &changed, &[]));
        project = changed;
        if result.1 != AppendShape::Steady {
            return (result, project);
        }
    }
    panic!("the tail never filled");
}

#[test]
fn a_new_ring_grows_at_its_first_rollover_into_part_one() {
    let (mut store, project) = created();
    let ((head_written, shape, part, _, _), project) =
        append_until_not_steady(&mut store, project, 4);
    assert!(head_written, "a rollover writes the head first");
    assert_eq!((shape, part), (AppendShape::Rollover { grew: true }, 1));
    let head = store.head();
    assert_eq!((head.parts, head.tail_epoch), (vec![0, 1], 2));
    let plaintext = store.plaintext(1);
    let tail = Part::decode(&plaintext).expect("tail");
    assert_eq!(tail.epoch, 2);
    assert_eq!(
        tail.entries.len(),
        1,
        "the new part holds only the new entry"
    );
    assert_eq!(
        tail.summary,
        project.values().summary(&store.key().digest_keys(VAULT))
    );
}

#[test]
fn a_full_ring_reuses_its_oldest_part() {
    let (mut store, project) = created();
    let mut head = store.head();
    head.ring_limit = 2;
    store.put(crate::history::RecordWrite::new(
        head_account(VAULT),
        head.encode(HISTORY).expect("head"),
    ));
    let (_, project) = append_until_not_steady(&mut store, project, 4);
    assert_eq!(store.head().parts, vec![0, 1]);
    store.growth = Some(false);
    let ((head_written, shape, part, _, _), _) = append_until_not_steady(&mut store, project, 4);
    assert!(head_written);
    assert_eq!((shape, part), (AppendShape::Rollover { grew: false }, 0));
    let head = store.head();
    assert_eq!(
        (head.parts, head.tail_epoch, head.ring_limit),
        (vec![1, 0], 3, 2)
    );
}

#[test]
fn refused_growth_reuses_the_oldest_part_and_keeps_the_ring_size_as_its_limit() {
    let (mut store, project) = created();
    let (_, project) = append_until_not_steady(&mut store, project, 4);
    store.growth = Some(false);
    let ((_, shape, part, _, _), _) = append_until_not_steady(&mut store, project, 4);
    assert_eq!((shape, part), (AppendShape::Rollover { grew: false }, 0));
    let head = store.head();
    assert_eq!((head.parts, head.ring_limit), (vec![1, 0], 2));
}

#[test]
fn a_one_part_ring_that_cannot_grow_slides_instead_of_replacing_its_only_part() {
    let (mut store, project) = created();
    store.growth = Some(false);
    let ((head_written, shape, part, _, _), _) = append_until_not_steady(&mut store, project, 4);
    assert!(matches!(shape, AppendShape::Slid { dropped } if dropped > 0));
    assert_eq!(part, 0);
    assert!(head_written, "the head records one part as the limit, once");
    let head = store.head();
    assert_eq!(
        (head.parts, head.ring_limit, head.tail_epoch),
        (vec![0], 1, 1)
    );
}

#[test]
fn a_one_part_ring_drops_its_oldest_entries_and_keeps_its_summary_and_epoch() {
    let mut store = Store::new();
    store.ring_limit = 1;
    let before = Project::with(&[("default", &[])]);
    let mut project = Project::with(&[("default", &[("A", "1")])]);
    store
        .record(Action::Set, &before, &project, &[])
        .expect("created");
    let ((head_written, shape, part, _, _), after) =
        append_until_not_steady(&mut store, project.clone(), 4);
    project = after;
    assert!(!head_written, "sliding writes no head");
    let AppendShape::Slid { dropped } = shape else {
        panic!("expected a slide, got {shape:?}");
    };
    assert!(dropped >= 1);
    assert_eq!(part, 0);
    let head = store.head();
    assert_eq!((head.parts, head.tail_epoch), (vec![0], 1));
    let plaintext = store.plaintext(0);
    let tail = Part::decode(&plaintext).expect("tail");
    assert_eq!(tail.epoch, 1);
    assert!(plaintext.len() <= part_target(tail.summary.encoded_len()));
    assert_eq!(
        tail.summary,
        project.values().summary(&store.key().digest_keys(VAULT))
    );
    let first = tail.decoded_entries().next().expect("an entry").seq;
    assert!(first > 1, "the oldest entries are gone");
}

#[test]
fn a_rollover_interrupted_before_its_part_is_recovered_with_the_lost_change_as_a_gap() {
    let (mut store, project) = created();
    let ((_, shape, part, _, _), project) = append_until_not_steady(&mut store, project, 4);
    assert_eq!((shape, part), (AppendShape::Rollover { grew: true }, 1));
    // The head was written, then the crash: part 1 never was.
    store.delete(&part_account(VAULT, 1));
    let mut next = project.clone();
    next.set("default", "B", "b");
    let (head_written, shape, part, gap, _) =
        appended(store.record(Action::Set, &project, &next, &[]));
    assert_eq!(
        (head_written, shape, part, gap),
        (false, AppendShape::Recovered, 1, true)
    );
    let head = store.head();
    let plaintext = store.plaintext(1);
    let tail = Part::decode(&plaintext).expect("tail");
    assert_eq!(tail.epoch, head.tail_epoch);
    let entries: Vec<_> = tail.decoded_entries().collect();
    assert_eq!(entries.len(), 2);
    assert!(entries[0].flags.interrupted_rollover);
    assert_eq!(entries[0].action, Action::Outside);
    assert!(!entries[1].flags.interrupted_rollover);
}

#[test]
fn a_reused_part_that_still_holds_an_older_epoch_is_an_interrupted_rollover() {
    let (mut store, project) = created();
    let mut head = store.head();
    head.ring_limit = 2;
    store.put(crate::history::RecordWrite::new(
        head_account(VAULT),
        head.encode(HISTORY).expect("head"),
    ));
    let (_, project) = append_until_not_steady(&mut store, project, 4);
    store.growth = Some(false);
    let stale = store.get(&part_account(VAULT, 0)).expect("part 0").to_vec();
    let ((_, shape, part, _, _), project) = append_until_not_steady(&mut store, project, 4);
    assert_eq!((shape, part), (AppendShape::Rollover { grew: false }, 0));
    // The crash came before part 0 was rewritten.
    store.records.insert(part_account(VAULT, 0).name(), stale);
    let mut next = project.clone();
    next.set("default", "C", "c");
    let (_, shape, part, gap, _) = appended(store.record(Action::Set, &project, &next, &[]));
    assert_eq!((shape, part, gap), (AppendShape::Recovered, 0, true));
    let plaintext = store.plaintext(0);
    assert_eq!(
        Part::decode(&plaintext).expect("tail").epoch,
        store.head().tail_epoch
    );
}

#[test]
fn a_part_holds_exactly_its_target_and_one_byte_more_rolls_over() {
    let (store, project) = created();
    let base_len = store.plaintext(0).len();
    let summary_len = Part::decode(&store.plaintext(0))
        .expect("part")
        .summary
        .encoded_len();
    let target = part_target(summary_len);
    let attempt = |length: usize| {
        let mut store = Store {
            records: store.records.clone(),
            next_id: store.next_id,
            time: store.time,
            ..Store::new()
        };
        let mut changed = project.clone();
        changed.set("default", "A", &"x".repeat(length));
        let shape = appended(store.record(Action::Set, &project, &changed, &[])).1;
        (shape, store.plaintext(0).len())
    };
    // The entry grows by one byte per value byte, so the room left is exact.
    let probe = 100;
    let (shape, with_probe) = attempt(probe);
    assert_eq!(shape, AppendShape::Steady);
    let at_target = probe + (target - with_probe);
    assert!(at_target > probe && base_len < target);
    let (shape, length) = attempt(at_target);
    assert_eq!((shape, length), (AppendShape::Steady, target));
    let (shape, _) = attempt(at_target + 1);
    assert_eq!(shape, AppendShape::Rollover { grew: true });
}

#[test]
fn a_part_larger_than_the_target_reads_and_appends_normally() {
    let mut store = Store::new();
    let before = Project::with(&[("default", &[])]);
    let project = Project::with(&[("default", &[("A", &big('a', 60))])]);
    store
        .record(Action::Set, &before, &project, &[])
        .expect("created");
    assert!(
        store.plaintext(0).len() > PART_TARGET,
        "part 0 is past the target"
    );
    let mut next = project.clone();
    next.set("default", "B", "b");
    let (_, shape, part, _, _) = appended(store.record(Action::Set, &project, &next, &[]));
    assert_eq!((shape, part), (AppendShape::Rollover { grew: true }, 1));
}

#[test]
fn a_change_too_large_for_a_part_keeps_digests_and_then_only_counts() {
    let mut store = Store::new();
    let before = Project::with(&[("default", &[("A", &big('a', 50))])]);
    let after = Project::with(&[("default", &[("A", &big('b', 50))])]);
    store
        .record(Action::Set, &before, &after, &[])
        .expect("created");
    store.with_entries(0, |entries| {
        assert!(entries[0].flags.values_not_kept);
        assert!(!entries[0].flags.oversized);
        let Keys::Changes(changes) = &entries[0].environments[0].keys else {
            panic!("keys")
        };
        assert!(matches!(
            changes[0].before,
            Side::DigestOnly {
                reason: Unkept::TooLarge,
                ..
            }
        ));
    });

    let names: Vec<String> = (0..1_460).map(|index| format!("KEY_{index:026}")).collect();
    let mut many = Store::new();
    let empty = Project::with(&[("default", &[])]);
    let mut imported = empty.clone();
    for name in &names {
        imported.set("default", name, "v");
    }
    many.record(Action::Import, &empty, &imported, &[])
        .expect("created");
    many.with_entries(0, |entries| {
        assert!(entries[0].flags.oversized);
        assert_eq!(entries[0].environments[0].keys, Keys::Count(1_460));
    });
}

#[test]
fn a_summary_that_leaves_no_room_for_entries_pauses_history() {
    let mut store = Store::new();
    let empty = Project::with(&[("default", &[])]);
    let mut imported = empty.clone();
    for index in 0..2_000 {
        imported.set("default", &format!("KEY_{index:026}"), "v");
    }
    assert_eq!(
        store
            .record(Action::Import, &empty, &imported, &[])
            .map(|_| ()),
        Err(NotRecorded::TooManyValues)
    );
    assert!(store.records.is_empty());
}

#[test]
fn appends_stop_for_a_rotating_key_a_running_removal_and_damage() {
    let (store, project) = created();
    let mut changed = project.clone();
    changed.set("default", "B", "b");

    let mut rotating = Store {
        records: store.records.clone(),
        ..Store::new()
    };
    let mut key = rotating.key();
    key.begin_rotation(
        Approval::Automatic,
        &mut crate::keyring::tests::CountingRandom(3),
    )
    .expect("rotation");
    rotating.put(RecordWrite {
        account: key_account(VAULT),
        bytes: key.encode(),
    });
    assert_eq!(
        rotating
            .record(Action::Set, &project, &changed, &[])
            .map(|_| ()),
        Err(NotRecorded::NeedsMaintenance)
    );

    let mut removing = Store {
        records: store.records.clone(),
        ..Store::new()
    };
    let mut head = removing.head();
    head.removing = Some(crate::append_log::Removing {
        value: [1; 16],
        places: vec![[2; 16]],
    });
    removing.put(RecordWrite::new(
        head_account(VAULT),
        head.encode(HISTORY).expect("head"),
    ));
    assert_eq!(
        removing
            .record(Action::Set, &project, &changed, &[])
            .map(|_| ()),
        Err(NotRecorded::NeedsMaintenance)
    );

    for account in [
        head_account(VAULT),
        key_account(VAULT),
        part_account(VAULT, 0),
    ] {
        let mut damaged = Store {
            records: store.records.clone(),
            ..Store::new()
        };
        let bytes = damaged.records.get_mut(&account.name()).expect("record");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(
            matches!(
                damaged.record(Action::Set, &project, &changed, &[]),
                Err(NotRecorded::Damaged(_))
            ),
            "{}",
            account.name()
        );
    }
}

#[test]
fn a_shrunk_ring_grows_back_to_a_full_limit_once_admission_allows() {
    let (mut store, project) = created();
    let (_, project) = append_until_not_steady(&mut store, project, 4);
    store.growth = Some(false);
    let (_, project) = append_until_not_steady(&mut store, project, 4);
    assert_eq!(
        store.head().ring_limit,
        2,
        "shrunk while the service was full"
    );
    let asked = store.admissions;
    store.growth = Some(true);
    let ((head_written, shape, part, _, _), _) = append_until_not_steady(&mut store, project, 4);
    assert!(head_written);
    assert_eq!((shape, part), (AppendShape::Rollover { grew: true }, 2));
    let head = store.head();
    assert_eq!((head.parts, head.ring_limit), (vec![1, 0, 2], 16));
    assert_eq!(store.admissions, asked + 1, "asked once, at the rollover");
}

#[test]
fn a_sliding_ring_asks_to_grow_again_only_every_interval() {
    let (mut store, mut project) = created();
    store.growth = Some(false);
    let (_, slid) = append_until_not_steady(&mut store, project, 4);
    project = slid;
    assert_eq!(store.head().ring_limit, 1);
    let asked = store.admissions;
    for round in 0..REGROW_CHECK_INTERVAL as usize {
        let mut changed = project.clone();
        changed.set("default", "A", &format!("{round}{}", big('s', 4)));
        store
            .record(Action::Set, &project, &changed, &[])
            .expect("recorded");
        project = changed;
        if store.head().parts.len() > 1 {
            break;
        }
    }
    assert!(
        store.admissions - asked <= 1,
        "{} admissions for {} slides",
        store.admissions - asked,
        REGROW_CHECK_INTERVAL
    );
    store.growth = Some(true);
    for round in 0..REGROW_CHECK_INTERVAL as usize {
        let mut changed = project.clone();
        changed.set("default", "A", &format!("{round}{}", big('t', 4)));
        store
            .record(Action::Set, &project, &changed, &[])
            .expect("recorded");
        project = changed;
        if store.head().parts.len() > 1 {
            break;
        }
    }
    let head = store.head();
    assert_eq!(
        (head.parts.len(), head.ring_limit),
        (2, 16),
        "a sliding ring grows again once the service has room"
    );
}

#[test]
fn a_growth_rollover_digests_each_value_once_across_its_plans() {
    let (mut store, mut project) = created();
    for index in 0..200 {
        project.set("default", &format!("K{index:03}"), "v");
    }
    let base = project.clone();
    let mut changed = base.clone();
    changed.set("default", "A", "2");
    store
        .record(Action::Set, &created().1, &base, &[])
        .expect("many keys");
    let mut round = 0;
    loop {
        round += 1;
        let mut next = project.clone();
        next.set("default", "A", &format!("{round}{}", big('g', 4)));
        let admissions = store.admissions;
        crate::work::reset();
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
        if store.admissions > admissions {
            let digests = crate::work::count(crate::work::Work::ValueDigest);
            assert!(
                digests <= 202 + 4,
                "{digests} digests for 202 values across a growth rollover's two plans"
            );
            break;
        }
        assert!(round < 64, "the ring grows within a few large changes");
    }
}

#[test]
fn a_change_tells_whether_it_touches_a_key_without_digests() {
    use crate::history::values::Rename;
    let cases: Vec<(Project, Project, Vec<Rename<'static>>)> = vec![
        (Project::default(), Project::with(&[("e", &[])]), vec![]),
        (Project::with(&[("e", &[])]), Project::default(), vec![]),
        (
            Project::with(&[("e", &[("A", "1")])]),
            Project::with(&[("f", &[("A", "1")])]),
            vec![Rename::Environment { from: "e", to: "f" }],
        ),
        (
            Project::with(&[("e", &[("A", "1")])]),
            Project::with(&[("f", &[("A", "1")])]),
            vec![],
        ),
        (
            Project::with(&[("e", &[("A", "1")])]),
            Project::with(&[("e", &[("B", "1")])]),
            vec![Rename::Key {
                environment: "e",
                from: "A",
                to: "B",
            }],
        ),
        (
            Project::with(&[("e", &[("A", "1")])]),
            Project::with(&[("e", &[("A", "2")])]),
            vec![],
        ),
        (
            Project::with(&[("e", &[("A", "1")]), ("g", &[])]),
            Project::with(&[("e", &[("A", "1")])]),
            vec![],
        ),
        (
            Project::with(&[("e", &[("A", "1")])]),
            Project::with(&[("e", &[("A", "1")]), ("f", &[("A", "1")])]),
            vec![Rename::Environment { from: "e", to: "f" }],
        ),
    ];
    let keys = KeyRecord::generate(
        Approval::Automatic,
        &mut crate::keyring::tests::CountingRandom(3),
    )
    .expect("record")
    .digest_keys(VAULT);
    for (before, after, renames) in &cases {
        let before_values = before.values();
        let after_values = after.values();
        let change = Change {
            id: [1; 16],
            time: 0,
            actor: Actor::Cli,
            action: Action::Set,
            detail: Detail::default(),
            before: &before_values,
            after: &after_values,
            renames,
        };
        let entry_changes_keys = crate::history::values::net_change(
            &before_values,
            &before_values.summary(&keys),
            &after_values,
            renames,
            &keys,
        )
        .iter()
        .any(|environment| environment.key_count() > 0);
        assert_eq!(
            change.changes_keys(),
            entry_changes_keys,
            "{before:?} -> {after:?} with {renames:?}"
        );
    }
}

#[test]
fn too_many_values_agrees_with_the_summary_check() {
    for keys in [10_usize, 2_000, 2_400, 2_600, 3_000] {
        let mut project = Project::with(&[("e", &[])]);
        for index in 0..keys {
            project.set("e", &format!("KEY_NUMBER_{index:08}"), "v");
        }
        let values = project.values();
        let record = KeyRecord::generate(
            Approval::Automatic,
            &mut crate::keyring::tests::CountingRandom(4),
        )
        .expect("record");
        let summary = values.summary(&record.digest_keys(VAULT));
        assert_eq!(
            too_many_values(&values),
            check_summary(&summary).is_err(),
            "{keys} keys"
        );
    }
}
