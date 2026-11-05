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
            false,
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
        Choices, ChosenSide, EnvironmentName, HistoryError, HistoryState, Target, TimelineRow,
    };

    fn project_set(dir: &std::path::Path, key: &str, value: &str) {
        crate::set(dir, &[(key, value)], &Source::new(Action::Set)).expect("set");
        take_outcomes();
    }

    fn ids(dir: &std::path::Path) -> Vec<[u8; 16]> {
        crate::history::timeline(dir, &Filter::default(), false)
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
                crate::history::timeline(&dir, &Filter::default(), false),
                Err(HistoryError::NoProject)
            );
            project_set(&dir, "A", "1");
            project_set(&dir, "A", "2");
            let status = crate::history::status(&dir).expect("status");
            assert_eq!((status.state, status.retained), (HistoryState::On, 2));
            let entries = ids(&dir);
            let short = hex::encode(entries[1])[..8].to_owned();
            let shown = crate::history::show(&dir, &short, false).expect("show");
            assert_eq!((shown.info.id, shown.revealed), (entries[1], None));
            assert_eq!(
                crate::history::show(&dir, "zzzzzz", false),
                Err(HistoryError::EntryNotFound)
            );
            let found = crate::history::show(&dir, &hex::encode(entries[1]), true)
                .expect("show")
                .revealed
                .expect("revealed");
            let values = &found.values[0][0];
            assert_eq!(values.before.as_deref().map(String::as_str), Some("1"));
            assert_eq!(values.after.as_deref().map(String::as_str), Some("2"));
            let listing = crate::history::timeline(&dir, &Filter::default(), true)
                .expect("timeline")
                .expect("history");
            assert_eq!(listing.values.len(), 2, "every shown entry's values");
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
            let request = Target::Environment {
                environment: EnvironmentName::Now("default".to_owned()),
                side: RelatedSide::After,
            };
            let (_, plan) =
                crate::history::review_rollback(&dir, &hex::encode(entries[0]), |_| Ok(request))
                    .expect("review");
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
            let listing = crate::history::timeline(&dir, &Filter::default(), false)
                .expect("timeline")
                .expect("history");
            let TimelineRow::Entry(newest) = &listing.rows[0] else {
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
            let chosen = ChosenSide {
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::Before,
            };
            let (_, review) =
                crate::history::review_forget(&dir, &hex::encode(entries[1]), |_| Ok(chosen))
                    .expect("review");
            assert_eq!(review.places.len(), 1);
            crate::history::forget(&dir, &review, &review.default_selection()).expect("forget");
            let found = crate::history::show(&dir, &hex::encode(entries[1]), true)
                .expect("show")
                .revealed
                .expect("revealed");
            assert_eq!(found.values[0][0].before, None, "the value is gone");
            assert_eq!(stored(&dir, "TOKEN").as_deref(), Some("rotated"));

            let current = ChosenSide {
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::After,
            };
            let (_, review) =
                crate::history::review_forget(&dir, &hex::encode(entries[1]), |_| Ok(current))
                    .expect("review");
            assert_eq!(
                crate::history::forget(&dir, &review, &review.default_selection()),
                Err(HistoryError::ValueIsCurrent)
            );
        });
    }

    fn companion_folder(home: &std::path::Path) -> std::path::PathBuf {
        std::fs::read_dir(home.join(".lpm").join("vaults"))
            .expect("vaults")
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().ends_with(".companion"))
            .expect("the project's companion folder")
            .path()
    }

    #[test]
    fn a_rollback_that_renames_an_environment_back_records_a_rename() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            let vault_id = crate::vault_id::read_vault_id(&dir).expect("vault id");
            with_vault_transaction(|directory| {
                let recording = crate::history::scope::begin(
                    &vault_id,
                    &Source::new(Action::RenameEnvironment),
                );
                crate::history::scope::renamed_environment(&recording, "default", "prod");
                let renamed = std::collections::HashMap::from([(
                    "prod".to_owned(),
                    std::collections::HashMap::from([("A".to_owned(), "1".to_owned())]),
                )]);
                crate::write_all_environments_unlocked(
                    directory, &vault_id, "project", "/project", &renamed, &recording,
                )
            })
            .expect("renamed");
            take_outcomes();
            let entries = ids(&dir);
            let newest_kind = |dir: &std::path::Path| {
                let listing = crate::history::timeline(dir, &Filter::default(), false)
                    .expect("timeline")
                    .expect("history");
                let TimelineRow::Entry(newest) = &listing.rows[0] else {
                    panic!("an entry");
                };
                newest
                    .environments
                    .iter()
                    .map(|environment| (environment.name.clone(), environment.kind.clone()))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                newest_kind(&dir),
                vec![(
                    "prod".to_owned(),
                    crate::history::EnvironmentKindInfo::RenamedFrom("default".to_owned())
                )]
            );
            let (_, plan) = crate::history::review_rollback(&dir, &hex::encode(entries[0]), |_| {
                Ok(Target::Environment {
                    environment: EnvironmentName::AtPoint("default".to_owned()),
                    side: RelatedSide::After,
                })
            })
            .expect("review");
            crate::history::commit_rollback(&dir, &plan, &Choices::default()).expect("commit");
            assert_eq!(
                newest_kind(&dir),
                vec![(
                    "default".to_owned(),
                    crate::history::EnvironmentKindInfo::RenamedFrom("prod".to_owned())
                )],
                "the rollback is recorded as a rename, not a removal and a creation"
            );
        });
    }

    #[test]
    fn removing_a_value_after_history_was_removed_says_it_changed_since_the_review() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "TOKEN", "leaked");
            project_set(&dir, "TOKEN", "rotated");
            let entries = ids(&dir);
            let chosen = ChosenSide {
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::Before,
            };
            let (_, review) =
                crate::history::review_forget(&dir, &hex::encode(entries[1]), |_| Ok(chosen))
                    .expect("review");
            crate::history::turn_off(&dir).expect("off");
            crate::history::turn_on(&dir).expect("on");
            assert_eq!(
                crate::history::forget(&dir, &review, &review.default_selection()),
                Err(HistoryError::ChangedSinceReview)
            );
        });
    }

    #[test]
    fn status_pauses_for_damage_for_a_store_that_fails_and_for_too_many_values() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            let head = companion_folder(home).join("record.history-head");
            let sealed = std::fs::read(&head).expect("head");

            std::fs::write(&head, b"damaged").expect("damage the head");
            assert_eq!(
                crate::history::status(&dir).expect("status").state,
                HistoryState::Paused(crate::history::Paused::Damaged)
            );

            std::fs::write(&head, &sealed).expect("restore the head");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&head, std::fs::Permissions::from_mode(0o000))
                    .expect("lock the head");
                let state = crate::history::status(&dir).expect("status").state;
                std::fs::set_permissions(&head, std::fs::Permissions::from_mode(0o600))
                    .expect("unlock the head");
                assert!(
                    matches!(
                        state,
                        HistoryState::Paused(crate::history::Paused::Unavailable(_))
                    ),
                    "{state:?}"
                );
            }
            assert_eq!(
                crate::history::status(&dir).expect("status").state,
                HistoryState::On
            );

            let pairs: Vec<(String, String)> = (0..3_000)
                .map(|index| (format!("A_RATHER_LONG_KEY_NAME_{index:08}"), "v".to_owned()))
                .collect();
            let borrowed: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            crate::set(&dir, &borrowed, &Source::new(Action::Import)).expect("set");
            take_outcomes();
            assert_eq!(
                crate::history::status(&dir).expect("status").state,
                HistoryState::Paused(crate::history::Paused::TooManyValues)
            );
        });
    }

    #[test]
    fn a_part_the_file_store_cant_decrypt_reads_as_an_unreadable_part() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            let mut round = 0;
            while !companion_folder(home).join("record.history.001").exists() {
                round += 1;
                assert!(round < 64, "the ring grows within a few large changes");
                project_set(&dir, "A", &format!("{round}{}", "x".repeat(6 * 1024)));
            }
            std::fs::write(
                companion_folder(home).join("record.history.000"),
                b"garbage",
            )
            .expect("damage part 0");
            let listing = crate::history::timeline(&dir, &Filter::default(), false)
                .expect("a part that won't read doesn't fail the read")
                .expect("history");
            assert_eq!(listing.unreadable_parts, 1);
            assert!(!listing.damaged_tail);
        });
    }

    #[test]
    fn a_scope_records_what_its_last_successful_write_stored() {
        with_temp_vault_home(|_| {
            force_file_vault();
            let one = std::collections::HashMap::from([(
                "default".to_owned(),
                std::collections::HashMap::from([("A".to_owned(), "1".to_owned())]),
            )]);
            let two = std::collections::HashMap::from([(
                "default".to_owned(),
                std::collections::HashMap::from([("A".to_owned(), "2".to_owned())]),
            )]);
            with_vault_transaction(|_| {
                let recording = crate::history::scope::begin(VAULT, &Source::new(Action::Pull));
                crate::history::scope::observe_read(VAULT, Some(&one));
                crate::history::scope::committed(&recording, std::borrow::Cow::Borrowed(&two));
                // A compensation that failed never reports a write, so what the
                // pull stored is what history records.
                let tracked = crate::history::scope::tracked(VAULT).expect("tracked");
                assert_eq!(
                    (tracked.before.clone(), tracked.after.clone()),
                    (Some(one.clone()), Some(two.clone()))
                );
                crate::history::scope::forget(VAULT);
                Ok(())
            })
            .expect("transaction");
        });
    }

    #[test]
    fn a_rollback_is_refused_while_a_removal_that_started_after_its_review_runs() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "TOKEN", "leaked");
            project_set(&dir, "TOKEN", "rotated");
            let entries = ids(&dir);
            let (_, plan) = crate::history::review_rollback(&dir, &hex::encode(entries[0]), |_| {
                Ok(Target::Environment {
                    environment: EnvironmentName::AtPoint("default".to_owned()),
                    side: RelatedSide::After,
                })
            })
            .expect("review");
            let chosen = ChosenSide {
                environment: "default".to_owned(),
                key: "TOKEN".to_owned(),
                side: RelatedSide::Before,
            };
            let (_, review) =
                crate::history::review_forget(&dir, &hex::encode(entries[1]), |_| Ok(chosen))
                    .expect("review");
            let vault_id = crate::vault_id::read_vault_id(&dir).expect("vault id");
            // The removal's first transaction committed, then the client stopped.
            with_vault_transaction(|directory| {
                let mut companion = FileCompanion::open(directory)?;
                let head = companion.read(&head_account(&vault_id))?.expect("head");
                let key = companion.read(&key_account(&vault_id))?.expect("key");
                let opened =
                    Opened::open(&vault_id, &head, &key).map_err(|error| error.to_string())?;
                let values = crate::fallback::read_all_environments_unlocked(directory, &vault_id)?
                    .unwrap_or_default();
                let writes = lpm_env_companion::history::removal::start_removal(
                    &opened,
                    &review,
                    &review.default_selection(),
                    &values_of(&values),
                    lpm_env_companion::keyring::Approval::FileStore,
                    &mut lpm_env_companion::keyring::SystemRandom,
                )
                .map_err(|error| error.to_string())?;
                companion.commit(
                    writes
                        .into_iter()
                        .map(|write| lifecycle::Mutation::Write {
                            account: write.account,
                            value: write.bytes,
                        })
                        .collect(),
                )
            })
            .expect("start the removal");
            assert_eq!(
                crate::history::commit_rollback(&dir, &plan, &Choices::default()),
                Err(HistoryError::ChangedSinceReview),
                "the rollback would put back the value being removed"
            );
            assert_eq!(stored(&dir, "TOKEN").as_deref(), Some("rotated"));
        });
    }

    #[test]
    fn status_reads_no_values_when_history_is_off() {
        with_temp_vault_home(|home| {
            force_file_vault();
            let dir = home.join("project");
            std::fs::create_dir_all(&dir).expect("project dir");
            project_set(&dir, "A", "1");
            crate::history::turn_off(&dir).expect("off");
            let before =
                crate::ENVIRONMENT_FULL_DECODE_COUNT.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                crate::history::status(&dir).expect("status").state,
                HistoryState::Off
            );
            assert_eq!(
                crate::ENVIRONMENT_FULL_DECODE_COUNT.load(std::sync::atomic::Ordering::SeqCst),
                before,
                "the marker answers; the values aren't read"
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
                crate::history::timeline(&dir, &Filter::default(), false),
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

#[test]
fn what_a_scope_tracks_never_prints_values_and_is_wiped_when_dropped() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let environments = std::collections::HashMap::from([(
        "default".to_owned(),
        std::collections::HashMap::from([("TOKEN".to_owned(), "value-sentinel".to_owned())]),
    )]);
    let tracked = scope::Tracked {
        source: Source::new(Action::Set),
        before: Some(environments.clone()),
        after: Some(environments.clone()),
        environment_renames: Vec::new(),
    };
    let shown = format!("{tracked:?}");
    assert!(!shown.contains("value-sentinel"), "{shown}");
    wipes_on_drop(&tracked);

    let mut wiped = environments;
    crate::history::wipe_values(&mut wiped);
    assert!(
        wiped["default"]["TOKEN"].bytes().all(|byte| byte == 0),
        "values are zeroed in place"
    );
}
