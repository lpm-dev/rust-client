//! Recording through the file store, which every platform runs.

use std::collections::BTreeSet;

use super::*;
use crate::companion::CompanionBackend as _;
use crate::companion::account::CompanionAccount;
use crate::companion::lifecycle::{self, LifecycleStore as _};
use crate::fallback::companion::FileCompanion;
use crate::fallback::tests::{force_file_vault, with_temp_vault_home};
use crate::history::store::HistoryStore as _;
use crate::storage_transaction::with_vault_transaction;
use lpm_env_companion::history::read::{Filter, Opened, TimelineRow, read_timeline};
use lpm_env_companion::history::switch::plan_off;
use lpm_env_companion::history::{head_account, key_account, part_account};

const VAULT: &str = "proj";

fn write(change: impl FnOnce(&mut crate::SecretMap), source: &Source) -> Vec<Recorded> {
    take_outcomes();
    crate::fallback::mutate_vault_file_env(VAULT, "default", change, source).expect("values write");
    take_outcomes()
}

fn set(key: &str, value: &str) -> Outcome {
    let mut outcomes = write(
        |secrets| {
            secrets.insert(key.to_owned(), value.to_owned());
        },
        &Source::new(Action::Set),
    );
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    let recorded = outcomes.remove(0);
    assert_eq!(recorded.vault_id, VAULT);
    recorded.outcome
}

fn records() -> BTreeSet<String> {
    with_vault_transaction(|directory| {
        let mut companion = FileCompanion::open(directory)?;
        Ok(companion
            .inventory(VAULT)?
            .iter()
            .map(CompanionAccount::name)
            .collect())
    })
    .expect("inventory")
}

/// Every entry's action, oldest first.
fn timeline() -> Vec<Action> {
    with_vault_transaction(|directory| {
        let mut companion = FileCompanion::open(directory)?;
        let head = companion.read(&head_account(VAULT))?.expect("head");
        let key = companion.read(&key_account(VAULT))?.expect("key");
        let opened = Opened::open(VAULT, &head, &key).map_err(|error| error.to_string())?;
        let values =
            crate::fallback::read_all_environments_unlocked(directory, VAULT)?.unwrap_or_default();
        let current = values_of(&values);
        let timeline = read_timeline(
            &opened,
            &mut |part| companion.read(&part_account(VAULT, part)),
            &current,
            &Filter::default(),
        )
        .map_err(|error| error.to_string())?;
        Ok(timeline
            .rows
            .iter()
            .rev()
            .filter_map(|row| match row {
                TimelineRow::Entry(info) => Some(info.action),
                TimelineRow::Unreadable { .. } => None,
            })
            .collect())
    })
    .expect("timeline")
}

#[test]
fn the_first_values_write_creates_history_and_later_ones_append() {
    with_temp_vault_home(|_| {
        force_file_vault();
        assert_eq!(
            set("A", "1"),
            Outcome::Recorded {
                crowded: None,
                gap: false
            }
        );
        let created = records();
        for account in [
            head_account(VAULT),
            key_account(VAULT),
            part_account(VAULT, 0),
        ] {
            assert!(created.contains(&account.name()), "{}", account.name());
        }
        assert!(matches!(set("A", "2"), Outcome::Recorded { .. }));
        assert_eq!(timeline(), vec![Action::Set, Action::Set]);
    });
}

#[test]
fn a_write_that_changes_nothing_records_nothing() {
    with_temp_vault_home(|_| {
        force_file_vault();
        set("A", "1");
        assert_eq!(set("A", "1"), Outcome::Nothing);
        assert_eq!(timeline(), vec![Action::Set]);
    });
}

#[test]
fn history_off_is_honored_by_values_writes() {
    with_temp_vault_home(|_| {
        force_file_vault();
        set("A", "1");
        with_vault_transaction(|directory| {
            let mut companion = FileCompanion::open(directory)?;
            let marker = crate::companion::open_project(&mut companion, VAULT)?;
            let inventory = companion.inventory(VAULT)?;
            let plan = plan_off(VAULT, marker.marker(), inventory)?;
            lifecycle::execute(&mut companion, plan)?;
            Ok(())
        })
        .expect("turned off");
        assert!(records().is_empty(), "turning off deletes history");
        assert_eq!(set("A", "2"), Outcome::Off);
        assert!(records().is_empty(), "nothing is recorded while off");
    });
}

#[test]
fn a_change_made_without_recording_becomes_a_gap_before_the_next_entry() {
    with_temp_vault_home(|_| {
        force_file_vault();
        set("A", "1");
        // A client that doesn't record history changes A.
        with_vault_transaction(|directory| {
            let source = Source::new(Action::Set);
            let recording = scope::begin(VAULT, &source);
            let mut values = crate::fallback::read_all_environments_unlocked(directory, VAULT)?
                .unwrap_or_default();
            values
                .entry("default".to_owned())
                .or_default()
                .insert("A".to_owned(), "elsewhere".to_owned());
            crate::fallback::write_all_environments_unlocked(
                directory, VAULT, &values, &recording,
            )?;
            scope::forget(VAULT);
            Ok(())
        })
        .expect("outside write");
        assert_eq!(
            set("B", "b"),
            Outcome::Recorded {
                crowded: None,
                gap: true
            }
        );
        assert_eq!(timeline(), vec![Action::Set, Action::Outside, Action::Set]);
    });
}

#[test]
fn a_values_write_succeeds_and_reports_why_when_history_is_damaged() {
    with_temp_vault_home(|_| {
        force_file_vault();
        set("A", "1");
        with_vault_transaction(|directory| {
            FileCompanion::open(directory)?.replace(&head_account(VAULT), b"not a head")
        })
        .expect("damage the head");
        assert_eq!(set("A", "2"), Outcome::NotRecorded(NotRecorded::Damaged));
        let stored = crate::fallback::read_vault_file_env(VAULT, "default")
            .expect("read")
            .expect("values");
        assert_eq!(
            stored.get("A").map(String::as_str),
            Some("2"),
            "the write went through"
        );
    });
}

mod api {
    use super::*;
    use crate::history::{
        Choices, ChosenValue, EntryLookup, HistoryError, HistoryState, Point, RollbackRequest,
        TimelineRow,
    };

    fn project_set(dir: &std::path::Path, key: &str, value: &str) {
        crate::set(dir, &[(key, value)], &Source::new(Action::Set)).expect("set");
        take_outcomes();
    }

    fn ids(dir: &std::path::Path) -> Vec<[u8; 16]> {
        crate::history::timeline(dir, &Filter::default())
            .expect("timeline")
            .expect("history exists")
            .rows
            .iter()
            .rev()
            .filter_map(|row| match row {
                TimelineRow::Entry(info) => Some(info.id),
                TimelineRow::Unreadable { .. } => None,
            })
            .collect()
    }

    fn stored(dir: &std::path::Path, key: &str) -> Option<String> {
        crate::try_get(dir, key).expect("read")
    }

    #[test]
    fn the_timeline_status_and_an_entry_read_through_the_cli_api() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            assert_eq!(
                crate::history::timeline(&dir, &Filter::default()),
                Err(HistoryError::NoProject)
            );
            project_set(&dir, "A", "1");
            project_set(&dir, "A", "2");
            let status = crate::history::status(&dir).expect("status");
            assert_eq!((status.state, status.retained), (HistoryState::On, 2));
            let entries = ids(&dir);
            let timeline = crate::history::timeline(&dir, &Filter::default())
                .expect("timeline")
                .expect("history");
            let short = hex::encode(entries[1])[..8].to_owned();
            assert_eq!(
                crate::history::resolve_entry(&timeline, &short),
                Ok(entries[1])
            );
            assert_eq!(
                crate::history::resolve_entry(&timeline, "zzzzzz"),
                Err(HistoryError::EntryNotFound)
            );
            let Some(EntryLookup::Found(found)) =
                crate::history::show(&dir, entries[1]).expect("show")
            else {
                panic!("found");
            };
            let values = &found.values[0][0];
            assert_eq!(values.before.as_deref().map(String::as_str), Some("1"));
            assert_eq!(values.after.as_deref().map(String::as_str), Some("2"));
        });
    }

    #[test]
    fn a_reviewed_rollback_commits_once_and_is_recorded_and_bound_to_the_review() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            project_set(&dir, "A", "2");
            project_set(&dir, "B", "b");
            let entries = ids(&dir);
            let request = RollbackRequest::Environment {
                environment: "default".to_owned(),
                point: Point {
                    entry: entries[0],
                    side: RelatedSide::After,
                },
            };
            let plan = crate::history::review_rollback(&dir, &request).expect("review");
            assert_eq!(plan.environments[0].changing_rows(), 2);

            let stale = plan.clone();
            let written =
                crate::history::commit_rollback(&dir, &plan, &Choices::default()).expect("commit");
            assert_eq!(written, vec!["default".to_owned()]);
            assert_eq!(stored(&dir, "A").as_deref(), Some("1"));
            assert_eq!(stored(&dir, "B"), None);
            let outcomes = take_outcomes();
            assert!(
                matches!(
                    outcomes.last().map(|recorded| &recorded.outcome),
                    Some(Outcome::Recorded { .. })
                ),
                "{outcomes:?}"
            );
            let timeline = crate::history::timeline(&dir, &Filter::default())
                .expect("timeline")
                .expect("history");
            let TimelineRow::Entry(newest) = &timeline.rows[0] else {
                panic!("an entry");
            };
            assert_eq!(newest.action, Action::Rollback);
            assert_eq!(
                newest.detail.related.map(|related| related.id),
                Some(entries[0])
            );

            assert_eq!(
                crate::history::commit_rollback(&dir, &stale, &Choices::default()),
                Err(HistoryError::ChangedSinceReview),
                "the values changed since that review"
            );
        });
    }

    #[test]
    fn removing_a_value_scrubs_it_and_leaves_the_current_values_alone() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "TOKEN", "leaked");
            project_set(&dir, "TOKEN", "rotated");
            let entries = ids(&dir);
            let chosen = ChosenValue {
                entry: entries[1],
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::Before,
            };
            let review = crate::history::review_forget(&dir, &chosen).expect("review");
            assert_eq!(review.places.len(), 1);
            crate::history::forget(&dir, &review, &review.default_selection()).expect("forget");
            let Some(EntryLookup::Found(found)) =
                crate::history::show(&dir, entries[1]).expect("show")
            else {
                panic!("found");
            };
            assert_eq!(found.values[0][0].before, None, "the value is gone");
            assert_eq!(stored(&dir, "TOKEN").as_deref(), Some("rotated"));

            let current = ChosenValue {
                entry: entries[1],
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::After,
            };
            let review = crate::history::review_forget(&dir, &current).expect("review");
            assert_eq!(
                crate::history::forget(&dir, &review, &review.default_selection()),
                Err(HistoryError::ValueIsCurrent)
            );
        });
    }

    #[test]
    fn turning_history_off_deletes_it_and_turning_it_on_starts_empty() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            crate::history::turn_off(&dir).expect("off");
            assert_eq!(
                crate::history::status(&dir).expect("status").state,
                HistoryState::Off
            );
            assert_eq!(
                crate::history::timeline(&dir, &Filter::default()),
                Err(HistoryError::Off)
            );
            crate::set(&dir, &[("A", "2")], &Source::new(Action::Set)).expect("set");
            assert_eq!(
                take_outcomes()
                    .last()
                    .map(|recorded| recorded.outcome.clone()),
                Some(Outcome::Off)
            );
            crate::history::turn_on(&dir).expect("on");
            let status = crate::history::status(&dir).expect("status");
            assert_eq!((status.state, status.retained), (HistoryState::On, 0));
            project_set(&dir, "A", "3");
            assert_eq!(ids(&dir).len(), 1, "history starts at the next change");
        });
    }
}
