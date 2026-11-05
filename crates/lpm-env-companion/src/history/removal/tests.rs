use super::*;
use crate::history::codec::Action;
use crate::history::read::{EntryLookup, IdPrefix, reveal_entry};
use crate::history::rebuild::{EnvironmentRef, TargetValue, UnknownReason, plan_key_rollback};
use crate::history::test_support::{Project, Store, VAULT};
use crate::history::values::Rename;
use crate::keyring::tests::CountingRandom;

fn id(n: u8) -> EntryId {
    let mut id = [0xa0; 16];
    id[15] = n;
    id
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

/// A history where API_KEY held "secret" in production and staging, an
/// unrelated FLAG held "secret" too, and both API_KEYs then changed.
fn shared_value() -> (Store, Project) {
    let steps = [
        Project::with(&[("production", &[]), ("staging", &[])]),
        Project::with(&[
            ("production", &[("API_KEY", "secret"), ("FLAG", "secret")]),
            ("staging", &[("API_KEY", "secret")]),
        ]),
        Project::with(&[
            ("production", &[("API_KEY", "rotated"), ("FLAG", "secret")]),
            ("staging", &[("API_KEY", "secret")]),
        ]),
        Project::with(&[
            ("production", &[("API_KEY", "rotated"), ("FLAG", "secret")]),
            ("staging", &[("API_KEY", "rotated")]),
        ]),
    ];
    let mut store = Store::new();
    for pair in steps.windows(2) {
        store
            .record(Action::Set, &pair[0], &pair[1], &[])
            .expect("recorded");
    }
    (store, steps[3].clone())
}

fn chosen(entry: u8, environment: &'static str, key: &'static str) -> Chosen<'static> {
    Chosen {
        entry: id(entry),
        environment,
        key,
        side: RelatedSide::Before,
    }
}

fn places(review: &RemovalReview) -> Vec<(String, String, PlaceGroup, bool)> {
    review
        .places
        .iter()
        .map(|place| {
            (
                place.environment.clone(),
                place.key.clone(),
                place.group,
                place.current,
            )
        })
        .collect()
}

/// Run every part of a running rotation, then its last transaction.
fn finish(store: &mut Store, random: &mut CountingRandom) {
    let opened = opened(store);
    for part in opened.head.parts.clone() {
        let sealed = store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec);
        if let Some(write) = rotate_part(&opened, part, sealed.as_deref(), random).expect("rotates")
        {
            store.put(write);
        }
    }
    let opened = self::opened(store);
    for write in finish_rotation(&opened).expect("finishes") {
        store.put(write);
    }
}

fn remove(
    store: &mut Store,
    current: &Project,
    review: &RemovalReview,
    selection: &BTreeSet<usize>,
) {
    let values = current.values();
    let mut random = CountingRandom(90);
    for write in start_removal(
        &opened(store),
        review,
        selection,
        &values,
        Approval::Automatic,
        &mut random,
    )
    .expect("starts")
    {
        store.put(write);
    }
    finish(store, &mut random);
}

#[test]
fn the_review_groups_the_chosen_key_in_every_environment_apart_from_other_keys() {
    let (store, current) = shared_value();
    let values = current.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(2, "production", "API_KEY"),
    )
    .expect("review");
    assert_eq!(
        places(&review),
        vec![
            (
                "production".to_owned(),
                "API_KEY".to_owned(),
                PlaceGroup::ThisKey,
                false
            ),
            (
                "staging".to_owned(),
                "API_KEY".to_owned(),
                PlaceGroup::ThisKey,
                false
            ),
            (
                "production".to_owned(),
                "FLAG".to_owned(),
                PlaceGroup::OtherKey,
                true
            ),
        ]
    );
    assert_eq!(review.default_selection(), BTreeSet::from([0, 1]));
    let production = &review.places[0];
    assert_eq!(production.occurrences.len(), 1);
    assert!(
        production.occurrences[0].set.is_some() && production.occurrences[0].replaced.is_some()
    );
}

#[test]
fn removing_scrubs_the_checked_places_and_keeps_a_shared_value_elsewhere() {
    let (mut store, current) = shared_value();
    let values = current.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(2, "production", "API_KEY"),
    )
    .expect("review");
    let old_key = store.key().current().id();
    let old_generation = store.key().current().generation();
    remove(&mut store, &current, &review, &review.default_selection());

    let key = store.key();
    assert!(!key.is_rotating());
    assert_ne!(key.current().id(), old_key, "the whole key rotated");
    assert_eq!(key.current().generation(), old_generation + 1);
    assert_eq!(store.head().removing, None);

    let opened = opened(&store);
    let Ok(EntryLookup::Found(first)) =
        reveal_entry(&opened, &mut source(&store), &IdPrefix::whole(id(1)))
    else {
        panic!("found");
    };
    let after_values: Vec<Option<&str>> = first
        .values
        .iter()
        .flatten()
        .map(|values| values.after.as_deref().map(String::as_str))
        .collect();
    assert_eq!(
        after_values,
        vec![None, Some("secret"), None],
        "API_KEY's values are gone in both environments; FLAG keeps its own"
    );

    for part in store.head().parts {
        let plaintext = store.plaintext(part);
        let decoded = Part::decode(&plaintext).expect("part");
        let digest = opened.keys.value(b"secret");
        for entry in decoded.decoded_entries() {
            for environment in &entry.environments {
                let Keys::Changes(changes) = &environment.keys else {
                    continue;
                };
                for change in changes {
                    if change.key == "API_KEY" {
                        assert_ne!(
                            change.before.digest(),
                            Some(digest),
                            "no digest left to guess against"
                        );
                        assert_ne!(change.after.digest(), Some(digest));
                    }
                }
            }
        }
    }

    let plan = plan_key_rollback(
        &opened,
        &mut source(&store),
        &values,
        EnvironmentRef::Now("production"),
        "API_KEY",
        id(2),
    )
    .expect("plan");
    assert_eq!(
        plan.environments[0].rows[0].target,
        TargetValue::Unknown(UnknownReason::Removed)
    );
}

#[test]
fn a_current_place_cannot_be_checked_and_with_none_left_the_removal_is_refused() {
    let (store, current) = shared_value();
    let values = current.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(1, "production", "FLAG").with_side(RelatedSide::After),
    )
    .expect("review");
    let flag = review
        .places
        .iter()
        .position(|place| place.key == "FLAG")
        .expect("FLAG");
    assert!(review.places[flag].current);
    assert_eq!(review.places[flag].group, PlaceGroup::ThisKey);
    assert!(!review.default_selection().contains(&flag));
    assert_eq!(
        start_removal(
            &opened(&store),
            &review,
            &BTreeSet::from([flag]),
            &values,
            Approval::Automatic,
            &mut CountingRandom(1)
        )
        .err(),
        Some(RemovalError::ValueIsCurrent)
    );

    let mut changed = current.clone();
    changed.set("staging", "API_KEY", "secret");
    let changed = changed.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(2, "production", "API_KEY"),
    )
    .expect("review");
    assert_eq!(
        start_removal(
            &opened(&store),
            &review,
            &review.default_selection(),
            &changed,
            Approval::Automatic,
            &mut CountingRandom(1)
        )
        .err(),
        Some(RemovalError::ChangedSinceReview),
        "a checked place that holds the value now refuses"
    );
}

#[test]
fn a_rename_keeps_one_place_and_is_scrubbed_under_either_name() {
    let base = Project::with(&[("stage", &[])]);
    let one = Project::with(&[("stage", &[("STRIPE_KEY", "sk")])]);
    let renamed = Project::with(&[("staging", &[("STRIPE_SECRET_KEY", "sk")])]);
    let changed = Project::with(&[("staging", &[("STRIPE_SECRET_KEY", "new")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &base, &one, &[])
        .expect("created");
    store
        .record(
            Action::RenameKey,
            &one,
            &renamed,
            &[
                Rename::Environment {
                    from: "stage",
                    to: "staging",
                },
                Rename::Key {
                    environment: "staging",
                    from: "STRIPE_KEY",
                    to: "STRIPE_SECRET_KEY",
                },
            ],
        )
        .expect("renamed");
    store
        .record(Action::Set, &renamed, &changed, &[])
        .expect("changed");
    let values = changed.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(3, "staging", "STRIPE_SECRET_KEY"),
    )
    .expect("review");
    assert_eq!(review.places.len(), 1, "one place through the renames");
    let place = &review.places[0];
    assert_eq!(
        (place.environment.as_str(), place.key.as_str()),
        ("staging", "STRIPE_SECRET_KEY")
    );
    assert_eq!(place.renamed_from, vec!["STRIPE_KEY".to_owned()]);
    assert_eq!(
        place.digests.len(),
        4,
        "every environment and key name pair"
    );
    remove(&mut store, &changed, &review, &review.default_selection());

    let opened = opened(&store);
    for entry in [id(1), id(2), id(3)] {
        let Ok(EntryLookup::Found(found)) =
            reveal_entry(&opened, &mut source(&store), &IdPrefix::whole(entry))
        else {
            panic!("found");
        };
        for values in found.values.iter().flatten() {
            for value in [&values.before, &values.after].into_iter().flatten() {
                assert_ne!(value.as_str(), "sk", "{entry:?}");
            }
        }
    }
}

#[test]
fn summaries_are_scrubbed_too() {
    let base = Project::with(&[("e", &[])]);
    let one = Project::with(&[("e", &[("A", "old")])]);
    let mut store = Store::new();
    store
        .record(Action::Set, &base, &one, &[])
        .expect("created");
    // Fill part 0 so its summary holds A's old value, then change A in part 1.
    let mut project = one.clone();
    let mut round = 0;
    while store.head().parts.len() < 2 {
        round += 1;
        let mut next = project.clone();
        next.set("e", "FILL", &format!("{round}{}", "x".repeat(6 * 1024)));
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    let mut changed = project.clone();
    changed.set("e", "A", "new");
    store
        .record(Action::Set, &project, &changed, &[])
        .expect("changed");
    let values = changed.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(1, "e", "A").with_side(RelatedSide::After),
    )
    .expect("review");
    remove(&mut store, &changed, &review, &review.default_selection());
    let plaintext = store.plaintext(0);
    let part = Part::decode(&plaintext).expect("part 0");
    assert_eq!(
        part.summary.environments["e"]["A"],
        crate::history::codec::Slot::Removed
    );
}

impl<'a> Chosen<'a> {
    fn with_side(self, side: RelatedSide) -> Self {
        Self { side, ..self }
    }
}

#[test]
fn readers_scrub_while_a_removal_is_partway_and_any_client_finishes_it() {
    let (mut store, current) = shared_value();
    let values = current.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(2, "production", "API_KEY"),
    )
    .expect("review");
    let mut random = CountingRandom(5);
    for write in start_removal(
        &opened(&store),
        &review,
        &review.default_selection(),
        &values,
        Approval::Automatic,
        &mut random,
    )
    .expect("starts")
    {
        store.put(write);
    }
    // The crash came before any part was rewritten.
    let opened_partway = opened(&store);
    assert!(needs_finishing(&opened_partway));
    let Ok(EntryLookup::Found(first)) = reveal_entry(
        &opened_partway,
        &mut source(&store),
        &IdPrefix::whole(id(1)),
    ) else {
        panic!("found");
    };
    assert_eq!(
        first.values[0][0].after, None,
        "production's API_KEY reads as removed"
    );
    assert_eq!(first.values[1][0].after, None, "staging's too");

    // Another client resumes: parts under the old key are rewritten once.
    finish(&mut store, &mut CountingRandom(77));
    assert!(!needs_finishing(&opened(&store)));
    let opened = opened(&store);
    for part in opened.head.parts.clone() {
        let sealed = store
            .get(&part_account(VAULT, part))
            .expect("part")
            .to_vec();
        assert_eq!(
            keyring::sealed_key(&sealed).map(|(id, _)| id),
            Ok(opened.record.current().id())
        );
        assert!(
            rotate_part(&opened, part, Some(&sealed), &mut CountingRandom(1))
                .expect("nothing to do")
                .is_none()
        );
    }
}

#[test]
fn more_than_128_name_pairs_are_refused() {
    let mut environments: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for index in 0..129 {
        environments.push((
            format!("env-{index:03}"),
            vec![("A".to_owned(), "same".to_owned())],
        ));
    }
    let start = Project {
        environments: environments
            .iter()
            .map(|(name, _)| (name.clone(), Default::default()))
            .collect(),
    };
    let set = Project {
        environments: environments
            .iter()
            .map(|(name, keys)| (name.clone(), keys.iter().cloned().collect()))
            .collect(),
    };
    let mut changed = set.clone();
    for keys in changed.environments.values_mut() {
        keys.insert("A".to_owned(), "other".to_owned());
    }
    let mut store = Store::new();
    store
        .record(Action::Set, &start, &set, &[])
        .expect("created");
    store
        .record(Action::Set, &set, &changed, &[])
        .expect("changed");
    let values = changed.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &values,
        chosen(2, "env-000", "A"),
    )
    .expect("review");
    assert_eq!(review.default_selection().len(), 129);
    assert_eq!(
        start_removal(
            &opened(&store),
            &review,
            &review.default_selection(),
            &values,
            Approval::Automatic,
            &mut CountingRandom(1)
        )
        .err(),
        Some(RemovalError::Limit)
    );
    let fewer: BTreeSet<usize> = review.default_selection().into_iter().take(128).collect();
    assert!(
        start_removal(
            &opened(&store),
            &review,
            &fewer,
            &values,
            Approval::Automatic,
            &mut CountingRandom(1)
        )
        .is_ok()
    );
}

#[test]
fn raising_approval_rotates_and_lowering_it_only_records_the_access() {
    let (mut store, _) = shared_value();
    assert!(matches!(
        key_maintenance(&opened(&store), Approval::Automatic),
        KeyMaintenance::Nothing
    ));
    assert!(matches!(
        key_maintenance(&opened(&store), Approval::Protected),
        KeyMaintenance::Rotate
    ));
    let old = store.key().current().id();
    let mut random = CountingRandom(31);
    for write in start_rotation(&opened(&store), Approval::Protected, &mut random).expect("starts")
    {
        store.put(write);
    }
    assert!(store.key().is_rotating());
    finish(&mut store, &mut random);
    let key = store.key();
    assert_ne!(key.current().id(), old);
    assert_eq!(key.approval_at_generation(), Approval::Protected);

    let KeyMaintenance::Lower(write) = key_maintenance(&opened(&store), Approval::Automatic) else {
        panic!("lowered approval is recorded");
    };
    store.put(write);
    let key = store.key();
    assert_eq!(key.approval_at_generation(), Approval::Automatic);
    assert_ne!(key.current().id(), old);
    assert!(matches!(
        key_maintenance(&opened(&store), Approval::Protected),
        KeyMaintenance::Rotate
    ));
}

#[test]
fn a_removal_or_rotation_cannot_start_while_one_runs() {
    let (mut store, current) = shared_value();
    let values = current.values();
    for write in start_rotation(&opened(&store), Approval::Automatic, &mut CountingRandom(4))
        .expect("starts")
    {
        store.put(write);
    }
    assert_eq!(
        review_removal(
            &opened(&store),
            &mut source(&store),
            &values,
            chosen(2, "production", "API_KEY")
        )
        .err(),
        Some(RemovalError::Running)
    );
    assert!(matches!(
        start_rotation(&opened(&store), Approval::Automatic, &mut CountingRandom(4)),
        Err(RemovalError::Running)
    ));
}

#[test]
fn a_place_holding_the_value_under_its_renamed_environment_is_current() {
    let mut store = Store::new();
    let empty = Project::with(&[("stage", &[])]);
    let first = Project::with(&[("stage", &[("K", "secret")])]);
    store
        .record(Action::Set, &empty, &first, &[])
        .expect("created");
    let renamed = Project::with(&[("staging", &[("K", "secret")])]);
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
    let current = renamed.values();
    let review = review_removal(
        &opened(&store),
        &mut source(&store),
        &current,
        Chosen {
            entry: id(1),
            environment: "stage",
            key: "K",
            side: RelatedSide::After,
        },
    )
    .expect("review");
    assert_eq!(review.places.len(), 1);
    assert_eq!(review.places[0].renamed_environments, vec!["staging"]);
    assert!(review.places[0].current, "staging's K holds it now");
    assert!(review.default_selection().is_empty());
}

#[test]
fn a_review_reads_each_part_once_and_groups_places_in_linear_steps() {
    let mut store = Store::new();
    let empty = Project::with(&[("e", &[])]);
    let mut project = empty.clone();
    for index in 0..300 {
        project.set("e", &format!("K{index:03}"), "true");
    }
    store
        .record(Action::Set, &empty, &project, &[])
        .expect("created");
    let mut round = 0;
    while store.head().parts.len() < 4 {
        round += 1;
        let mut next = project.clone();
        next.set("e", "BULK", &format!("{round}{}", "x".repeat(6 * 1024)));
        store
            .record(Action::Set, &project, &next, &[])
            .expect("recorded");
        project = next;
    }
    let mut changed = project.clone();
    changed.set("e", "K000", "false");
    store
        .record(Action::Set, &project, &changed, &[])
        .expect("changed");
    let newest = id(store.next_id);
    let parts = store.head().parts.len();
    let current = changed.values();
    let mut reads = 0;
    let mut counted = |part: u16| {
        reads += 1;
        Ok(store.get(&part_account(VAULT, part)).map(<[u8]>::to_vec))
    };
    crate::work::reset();
    let review = review_removal(
        &opened(&store),
        &mut counted,
        &current,
        Chosen {
            entry: newest,
            environment: "e",
            key: "K000",
            side: RelatedSide::Before,
        },
    )
    .expect("review");
    assert_eq!(review.places.len(), 300);
    assert_eq!(reads, parts, "one walk");
    let steps = crate::work::count(crate::work::Work::AliasStep);
    assert!(steps <= 300 * 6, "{steps} alias steps for 300 places");
}
