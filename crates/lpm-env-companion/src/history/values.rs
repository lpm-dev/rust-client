//! A project's values as history sees them, their digest summaries, the net
//! change between two states, and the gaps between what history last
//! recorded and what's stored now.
//!
//! Values are compared as exact code points: Rust `str` equality and
//! digests of the UTF-8 bytes, never the stored payload's bytes, whose key
//! order isn't fixed, and never Swift strings, whose `==` treats
//! canonically equivalent text as equal.

use std::collections::{BTreeMap, BTreeSet};

use crate::history::codec::{
    EnvironmentChange, EnvironmentKind, KeyChange, KeyKind, Keys, Side, Slot, Summary, Unkept,
};
use crate::keyring::DigestKeys;

/// Every environment of a project and its values, sorted by name bytes.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Values<'a> {
    environments: BTreeMap<&'a str, BTreeMap<&'a str, &'a str>>,
}

impl std::fmt::Debug for Values<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_map()
            .entries(
                self.environments
                    .iter()
                    .map(|(name, keys)| (name, keys.keys().collect::<Vec<_>>())),
            )
            .finish()
    }
}

impl<'a> Values<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The values of `environments`, each with its keys and values.
    pub fn from_environments<E, K>(environments: E) -> Self
    where
        E: IntoIterator<Item = (&'a str, K)>,
        K: IntoIterator<Item = (&'a str, &'a str)>,
    {
        Self {
            environments: environments
                .into_iter()
                .map(|(name, keys)| (name, keys.into_iter().collect()))
                .collect(),
        }
    }

    pub fn insert_environment(&mut self, name: &'a str) {
        self.environments.entry(name).or_default();
    }

    pub fn insert(&mut self, environment: &'a str, key: &'a str, value: &'a str) {
        self.environments
            .entry(environment)
            .or_default()
            .insert(key, value);
    }

    pub fn remove_environment(&mut self, name: &str) -> Option<BTreeMap<&'a str, &'a str>> {
        self.environments.remove(name)
    }

    pub fn remove(&mut self, environment: &str, key: &str) -> Option<&'a str> {
        self.environments.get_mut(environment)?.remove(key)
    }

    pub fn environments(&self) -> &BTreeMap<&'a str, BTreeMap<&'a str, &'a str>> {
        &self.environments
    }

    pub fn environment(&self, name: &str) -> Option<&BTreeMap<&'a str, &'a str>> {
        self.environments.get(name)
    }

    pub fn get(&self, environment: &str, key: &str) -> Option<&'a str> {
        self.environments.get(environment)?.get(key).copied()
    }

    pub fn is_empty(&self) -> bool {
        self.environments.is_empty()
    }

    pub fn key_count(&self) -> usize {
        self.environments.values().map(BTreeMap::len).sum()
    }

    /// The digest summary of these values: one HMAC per value.
    pub fn summary(&self, keys: &DigestKeys) -> Summary<'a> {
        Summary {
            environments: self
                .environments
                .iter()
                .map(|(name, values)| {
                    (
                        *name,
                        values
                            .iter()
                            .map(|(key, value)| (*key, Slot::Digest(keys.value(value.as_bytes()))))
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

/// A rename the operation made, which the net change can't tell apart from
/// a removal and an addition on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rename<'a> {
    Environment {
        from: &'a str,
        to: &'a str,
    },
    /// A key renamed within `environment`, named as it is after the change.
    Key {
        environment: &'a str,
        from: &'a str,
        to: &'a str,
    },
}

/// A summary slot as the "before" side of a change history didn't see.
fn unrecorded(slot: Slot) -> Side<'static> {
    match slot {
        Slot::Digest(digest) => Side::DigestOnly {
            digest,
            reason: Unkept::NotRecorded,
        },
        Slot::Removed => Side::Removed,
    }
}

fn recorded<'a>(value: &'a str, summary: Option<&Slot>, keys: &DigestKeys) -> Side<'a> {
    Side::Value {
        value,
        digest: match summary {
            Some(Slot::Digest(digest)) => *digest,
            Some(Slot::Removed) | None => keys.value(value.as_bytes()),
        },
    }
}

/// The net change from `before` to `after`, as one entry's environments,
/// sorted. `before_summary` is `before`'s summary, whose digests are reused,
/// so only changed values are digested again. A rename hint applies only
/// when its old name is gone from `after` and its new one absent from
/// `before`; otherwise the change is a removal and an addition.
pub fn net_change<'a>(
    before: &Values<'a>,
    before_summary: &Summary<'a>,
    after: &Values<'a>,
    renames: &[Rename<'a>],
    keys: &DigestKeys,
) -> Vec<EnvironmentChange<'a>> {
    let mut origins: BTreeMap<&'a str, &'a str> = BTreeMap::new();
    for rename in renames {
        if let Rename::Environment { from, to } = *rename
            && from != to
            && before.environments.contains_key(from)
            && !before.environments.contains_key(to)
            && after.environments.contains_key(to)
            && !after.environments.contains_key(from)
            && !origins.values().any(|origin| *origin == from)
        {
            origins.entry(to).or_insert(from);
        }
    }
    let renamed_away: BTreeSet<&str> = origins.values().copied().collect();
    let empty_summary = BTreeMap::new();
    let mut changes = Vec::new();
    for (name, after_values) in &after.environments {
        let origin = origins
            .get(name)
            .copied()
            .or_else(|| before.environments.contains_key(name).then_some(*name));
        let Some(origin) = origin else {
            let keys_changed = after_values
                .iter()
                .map(|(key, value)| KeyChange {
                    key,
                    kind: KeyKind::Added,
                    before: Side::Absent,
                    after: recorded(value, None, keys),
                })
                .collect();
            changes.push(EnvironmentChange {
                name,
                kind: EnvironmentKind::Created,
                keys: Keys::Changes(keys_changed),
            });
            continue;
        };
        let key_renames: Vec<(&'a str, &'a str)> = renames
            .iter()
            .filter_map(|rename| match *rename {
                Rename::Key {
                    environment,
                    from,
                    to,
                } if environment == *name => Some((from, to)),
                _ => None,
            })
            .collect();
        let key_changes = diff_keys(
            &before.environments[origin],
            before_summary
                .environments
                .get(origin)
                .unwrap_or(&empty_summary),
            after_values,
            &key_renames,
            keys,
        );
        let kind = if origin == *name {
            EnvironmentKind::Unchanged
        } else {
            EnvironmentKind::RenamedFrom(origin)
        };
        if kind != EnvironmentKind::Unchanged || !key_changes.is_empty() {
            changes.push(EnvironmentChange {
                name,
                kind,
                keys: Keys::Changes(key_changes),
            });
        }
    }
    for (name, before_values) in &before.environments {
        if after.environments.contains_key(name) || renamed_away.contains(name) {
            continue;
        }
        let summary = before_summary
            .environments
            .get(name)
            .unwrap_or(&empty_summary);
        changes.push(EnvironmentChange {
            name,
            kind: EnvironmentKind::Removed,
            keys: Keys::Changes(
                before_values
                    .iter()
                    .map(|(key, value)| KeyChange {
                        key,
                        kind: KeyKind::Removed,
                        before: recorded(value, summary.get(key), keys),
                        after: Side::Absent,
                    })
                    .collect(),
            ),
        });
    }
    changes.sort_by(|left, right| left.name.cmp(right.name));
    changes
}

fn diff_keys<'a>(
    before: &BTreeMap<&'a str, &'a str>,
    before_summary: &BTreeMap<&'a str, Slot>,
    after: &BTreeMap<&'a str, &'a str>,
    renames: &[(&'a str, &'a str)],
    keys: &DigestKeys,
) -> Vec<KeyChange<'a>> {
    let mut origins: BTreeMap<&'a str, &'a str> = BTreeMap::new();
    for (from, to) in renames {
        if from != to
            && before.contains_key(from)
            && !before.contains_key(to)
            && after.contains_key(to)
            && !after.contains_key(from)
            && !origins.values().any(|origin| origin == from)
        {
            origins.entry(to).or_insert(from);
        }
    }
    let renamed_away: BTreeSet<&str> = origins.values().copied().collect();
    let mut changes = Vec::new();
    for (key, value) in after {
        if let Some(origin) = origins.get(key) {
            changes.push(KeyChange {
                key,
                kind: KeyKind::RenamedFrom(origin),
                before: recorded(before[origin], before_summary.get(origin), keys),
                after: if before[origin] == *value {
                    recorded(value, before_summary.get(origin), keys)
                } else {
                    recorded(value, None, keys)
                },
            });
            continue;
        }
        match before.get(key) {
            None => changes.push(KeyChange {
                key,
                kind: KeyKind::Added,
                before: Side::Absent,
                after: recorded(value, None, keys),
            }),
            Some(old) if old != value => changes.push(KeyChange {
                key,
                kind: KeyKind::Changed,
                before: recorded(old, before_summary.get(key), keys),
                after: recorded(value, None, keys),
            }),
            Some(_) => {}
        }
    }
    for (key, value) in before {
        if !after.contains_key(key) && !renamed_away.contains(key) {
            changes.push(KeyChange {
                key,
                kind: KeyKind::Removed,
                before: recorded(value, before_summary.get(key), keys),
                after: Side::Absent,
            });
        }
    }
    changes.sort_by(|left, right| left.key.cmp(right.key));
    changes
}

/// Every difference between `baseline`, the summary of what history last
/// recorded, and `current`, the stored values with their summary, as an
/// `outside` entry's environments. Each changed key's before side keeps
/// the baseline's digest, and its after side the stored value.
pub fn gap_changes<'a>(
    baseline: &Summary<'a>,
    current: &Values<'a>,
    current_summary: &Summary<'a>,
) -> Vec<EnvironmentChange<'a>> {
    let mut changes = Vec::new();
    let names: BTreeSet<&'a str> = baseline
        .environments
        .keys()
        .chain(current.environments.keys())
        .copied()
        .collect();
    for name in names {
        let recorded_keys = baseline.environments.get(name);
        let stored = current.environments.get(name);
        let digests = current_summary.environments.get(name);
        let after_side = |key: &'a str, value: &'a str| Side::Value {
            value,
            digest: match digests.and_then(|digests| digests.get(key)) {
                Some(Slot::Digest(digest)) => *digest,
                _ => unreachable!("a summary of the stored values digests every value"),
            },
        };
        match (recorded_keys, stored) {
            (None, None) => {}
            (Some(recorded_keys), None) => changes.push(EnvironmentChange {
                name,
                kind: EnvironmentKind::Removed,
                keys: Keys::Changes(
                    recorded_keys
                        .iter()
                        .map(|(key, slot)| KeyChange {
                            key,
                            kind: KeyKind::Removed,
                            before: unrecorded(*slot),
                            after: Side::Absent,
                        })
                        .collect(),
                ),
            }),
            (None, Some(stored)) => changes.push(EnvironmentChange {
                name,
                kind: EnvironmentKind::Created,
                keys: Keys::Changes(
                    stored
                        .iter()
                        .map(|(key, value)| KeyChange {
                            key,
                            kind: KeyKind::Added,
                            before: Side::Absent,
                            after: after_side(key, value),
                        })
                        .collect(),
                ),
            }),
            (Some(recorded_keys), Some(stored)) => {
                let mut key_changes = Vec::new();
                let keys: BTreeSet<&'a str> =
                    recorded_keys.keys().chain(stored.keys()).copied().collect();
                for key in keys {
                    match (recorded_keys.get(key), stored.get(key)) {
                        (None, None) => {}
                        (Some(slot), None) => key_changes.push(KeyChange {
                            key,
                            kind: KeyKind::Removed,
                            before: unrecorded(*slot),
                            after: Side::Absent,
                        }),
                        (None, Some(value)) => key_changes.push(KeyChange {
                            key,
                            kind: KeyKind::Added,
                            before: Side::Absent,
                            after: after_side(key, value),
                        }),
                        (Some(slot), Some(value)) => {
                            let after = after_side(key, value);
                            if *slot != Slot::Digest(after.digest().expect("a value side")) {
                                key_changes.push(KeyChange {
                                    key,
                                    kind: KeyKind::Changed,
                                    before: unrecorded(*slot),
                                    after,
                                });
                            }
                        }
                    }
                }
                if !key_changes.is_empty() {
                    changes.push(EnvironmentChange {
                        name,
                        kind: EnvironmentKind::Unchanged,
                        keys: Keys::Changes(key_changes),
                    });
                }
            }
        }
    }
    changes
}

impl<'a> Summary<'a> {
    /// The summary after `changes`, which must list their keys: an
    /// oversized entry's counts don't say which keys changed.
    pub fn apply(&mut self, changes: &[EnvironmentChange<'a>]) {
        for change in changes {
            let Keys::Changes(key_changes) = &change.keys else {
                continue;
            };
            let mut environment = match change.kind {
                EnvironmentKind::Removed => {
                    self.environments.remove(change.name);
                    continue;
                }
                EnvironmentKind::Created => BTreeMap::new(),
                EnvironmentKind::RenamedFrom(from) => {
                    self.environments.remove(from).unwrap_or_default()
                }
                EnvironmentKind::Unchanged => {
                    self.environments.remove(change.name).unwrap_or_default()
                }
            };
            for key_change in key_changes {
                if let KeyKind::RenamedFrom(from) = key_change.kind {
                    environment.remove(from);
                }
                let slot = match key_change.after {
                    Side::Absent => {
                        environment.remove(key_change.key);
                        continue;
                    }
                    Side::Removed => Slot::Removed,
                    Side::Value { digest, .. } | Side::DigestOnly { digest, .. } => {
                        Slot::Digest(digest)
                    }
                };
                environment.insert(key_change.key, slot);
            }
            self.environments.insert(change.name, environment);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::tests::CountingRandom;
    use crate::keyring::{Approval, KeyRecord};

    fn keys() -> DigestKeys {
        KeyRecord::generate(Approval::Automatic, &mut CountingRandom(1))
            .expect("record")
            .digest_keys("proj")
    }

    fn values<'a>(environments: &[(&'a str, &[(&'a str, &'a str)])]) -> Values<'a> {
        Values::from_environments(
            environments
                .iter()
                .map(|(name, keys)| (*name, keys.iter().copied())),
        )
    }

    fn change<'a>(
        before: &Values<'a>,
        after: &Values<'a>,
        renames: &[Rename<'a>],
    ) -> Vec<EnvironmentChange<'a>> {
        let keys = keys();
        net_change(before, &before.summary(&keys), after, renames, &keys)
    }

    fn kinds<'a>(changes: &[EnvironmentChange<'a>]) -> Vec<(String, Vec<String>)> {
        changes
            .iter()
            .map(|environment| {
                let Keys::Changes(keys) = &environment.keys else {
                    panic!("listed keys");
                };
                (
                    format!("{} {:?}", environment.name, environment.kind),
                    keys.iter()
                        .map(|change| format!("{} {:?}", change.key, change.kind))
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn a_net_change_lists_added_changed_and_removed_keys_and_skips_unchanged_ones() {
        let before = values(&[
            ("production", &[("A", "1"), ("B", "2"), ("C", "3")]),
            ("staging", &[("A", "1")]),
        ]);
        let after = values(&[
            ("production", &[("A", "1"), ("B", "two"), ("D", "4")]),
            ("staging", &[("A", "1")]),
        ]);
        assert_eq!(
            kinds(&change(&before, &after, &[])),
            vec![(
                "production Unchanged".to_owned(),
                vec![
                    "B Changed".to_owned(),
                    "C Removed".to_owned(),
                    "D Added".to_owned()
                ]
            )]
        );
        assert!(
            change(&before, &before, &[]).is_empty(),
            "no change, no entry"
        );
    }

    #[test]
    fn canonically_equivalent_values_are_a_change() {
        let before = values(&[("e", &[("NAME", "caf\u{e9}")])]);
        let after = values(&[("e", &[("NAME", "cafe\u{301}")])]);
        assert_eq!(
            kinds(&change(&before, &after, &[])),
            vec![("e Unchanged".to_owned(), vec!["NAME Changed".to_owned()])]
        );
    }

    #[test]
    fn created_and_removed_environments_list_every_key() {
        let before = values(&[("old", &[("A", "1")]), ("empty", &[])]);
        let after = values(&[("new", &[("B", "2")]), ("blank", &[])]);
        assert_eq!(
            kinds(&change(&before, &after, &[])),
            vec![
                ("blank Created".to_owned(), vec![]),
                ("empty Removed".to_owned(), vec![]),
                ("new Created".to_owned(), vec!["B Added".to_owned()]),
                ("old Removed".to_owned(), vec!["A Removed".to_owned()]),
            ]
        );
    }

    #[test]
    fn renames_apply_only_when_the_hint_matches_the_states() {
        let before = values(&[("stage", &[("OLD", "1"), ("KEEP", "k")])]);
        let after = values(&[("staging", &[("NEW", "1"), ("KEEP", "k")])]);
        let renames = [
            Rename::Environment {
                from: "stage",
                to: "staging",
            },
            Rename::Key {
                environment: "staging",
                from: "OLD",
                to: "NEW",
            },
        ];
        let renamed = change(&before, &after, &renames);
        assert_eq!(
            kinds(&renamed),
            vec![(
                "staging RenamedFrom(\"stage\")".to_owned(),
                vec!["NEW RenamedFrom(\"OLD\")".to_owned()]
            )]
        );
        let Keys::Changes(keys) = &renamed[0].keys else {
            panic!("keys")
        };
        assert_eq!(keys[0].before.digest(), keys[0].after.digest());

        assert_eq!(
            kinds(&change(&before, &after, &[])),
            vec![
                (
                    "stage Removed".to_owned(),
                    vec!["KEEP Removed".to_owned(), "OLD Removed".to_owned()]
                ),
                (
                    "staging Created".to_owned(),
                    vec!["KEEP Added".to_owned(), "NEW Added".to_owned()]
                ),
            ],
            "without hints a rename is a removal and an addition"
        );

        let still_there = values(&[
            ("stage", &[("OLD", "1")]),
            ("staging", &[("NEW", "1"), ("KEEP", "k")]),
        ]);
        assert_eq!(
            kinds(&change(&before, &still_there, &renames)),
            vec![
                (
                    "stage Unchanged".to_owned(),
                    vec!["KEEP Removed".to_owned()]
                ),
                (
                    "staging Created".to_owned(),
                    vec!["KEEP Added".to_owned(), "NEW Added".to_owned()]
                ),
            ],
            "a hint whose old name remains is ignored"
        );
    }

    #[test]
    fn a_rename_that_also_changes_the_value_digests_the_new_value() {
        let before = values(&[("e", &[("OLD", "1")])]);
        let after = values(&[("e", &[("NEW", "2")])]);
        let renamed = change(
            &before,
            &after,
            &[Rename::Key {
                environment: "e",
                from: "OLD",
                to: "NEW",
            }],
        );
        let Keys::Changes(keys) = &renamed[0].keys else {
            panic!("keys")
        };
        assert_ne!(keys[0].before.digest(), keys[0].after.digest());
    }

    #[test]
    fn gaps_list_every_kind_of_difference_against_the_recorded_summary() {
        let keys = keys();
        let recorded = values(&[
            ("gone", &[("A", "1")]),
            (
                "kept",
                &[("SAME", "s"), ("CHANGED", "old"), ("DROPPED", "d")],
            ),
        ]);
        let mut baseline = recorded.summary(&keys);
        baseline
            .environments
            .get_mut("kept")
            .expect("kept")
            .insert("SCRUBBED", Slot::Removed);
        let stored = values(&[
            (
                "kept",
                &[
                    ("SAME", "s"),
                    ("CHANGED", "new"),
                    ("ADDED", "a"),
                    ("SCRUBBED", "x"),
                ],
            ),
            ("new", &[("B", "2")]),
        ]);
        let gaps = gap_changes(&baseline, &stored, &stored.summary(&keys));
        assert_eq!(
            kinds(&gaps),
            vec![
                ("gone Removed".to_owned(), vec!["A Removed".to_owned()]),
                (
                    "kept Unchanged".to_owned(),
                    vec![
                        "ADDED Added".to_owned(),
                        "CHANGED Changed".to_owned(),
                        "DROPPED Removed".to_owned(),
                        "SCRUBBED Changed".to_owned(),
                    ]
                ),
                ("new Created".to_owned(), vec!["B Added".to_owned()]),
            ]
        );
        let Keys::Changes(kept) = &gaps[1].keys else {
            panic!("keys")
        };
        assert_eq!(
            kept[1].before,
            Side::DigestOnly {
                digest: keys.value(b"old"),
                reason: Unkept::NotRecorded
            }
        );
        assert_eq!(kept[3].before, Side::Removed);
        assert!(matches!(kept[1].after, Side::Value { value: "new", .. }));
        assert!(gap_changes(&stored.summary(&keys), &stored, &stored.summary(&keys)).is_empty());
    }

    #[test]
    fn applying_a_change_to_a_summary_matches_summarizing_the_result() {
        let keys = keys();
        let before = values(&[
            ("stage", &[("OLD", "1"), ("X", "x")]),
            ("gone", &[("G", "g")]),
            ("prod", &[("A", "1")]),
        ]);
        let after = values(&[
            ("staging", &[("NEW", "1"), ("X", "y")]),
            ("prod", &[("A", "2"), ("B", "b")]),
            ("fresh", &[]),
        ]);
        let renames = [
            Rename::Environment {
                from: "stage",
                to: "staging",
            },
            Rename::Key {
                environment: "staging",
                from: "OLD",
                to: "NEW",
            },
        ];
        let mut summary = before.summary(&keys);
        let changes = net_change(&before, &summary, &after, &renames, &keys);
        summary.apply(&changes);
        assert_eq!(summary, after.summary(&keys));
    }
}
