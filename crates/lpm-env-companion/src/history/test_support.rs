//! An in-memory store that runs history plans the way a client does, for
//! the engine's tests.

use std::collections::BTreeMap;

use crate::account::CompanionAccount;
use crate::append_log::{HISTORY, Head};
use crate::history::append::{
    AppendCache, AppendPlan, AppendWrite, Change, CreationPlan, Growth, NotRecorded, Stored,
    plan_append, plan_creation,
};
use crate::history::codec::{Action, Actor, Detail, Entry, Part};
use crate::history::values::{Rename, Values};
use crate::history::{RecordWrite, head_account, key_account, part_account, part_identity};
use crate::keyring::tests::CountingRandom;
use crate::keyring::{self, Approval, KeyRecord};
use crate::marker::Marker;

pub(crate) const VAULT: &str = "proj";

/// Owned values a test changes, then lends to a change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Project {
    pub(crate) environments: BTreeMap<String, BTreeMap<String, String>>,
}

impl Project {
    pub(crate) fn with(environments: &[(&str, &[(&str, &str)])]) -> Self {
        Self {
            environments: environments
                .iter()
                .map(|(name, keys)| {
                    (
                        (*name).to_owned(),
                        keys.iter()
                            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    pub(crate) fn values(&self) -> Values<'_> {
        Values::from_environments(self.environments.iter().map(|(name, keys)| {
            (
                name.as_str(),
                keys.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
        }))
    }

    pub(crate) fn set(&mut self, environment: &str, key: &str, value: &str) {
        self.environments
            .entry(environment.to_owned())
            .or_default()
            .insert(key.to_owned(), value.to_owned());
    }
}

#[derive(Debug, Default)]
pub(crate) struct Store {
    pub(crate) records: BTreeMap<String, Vec<u8>>,
    pub(crate) random: u8,
    pub(crate) next_id: u8,
    pub(crate) time: i64,
    pub(crate) growth: Option<bool>,
    pub(crate) ring_limit: u16,
    /// How many times a plan asked admission whether its ring may grow.
    pub(crate) admissions: usize,
}

/// What one recording did, for assertions.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Recorded {
    Created,
    NoKeyChanges,
    Unchanged,
    AlreadyRecorded,
    Appended {
        head_written: bool,
        write: AppendWriteSummary,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppendWriteSummary {
    pub(crate) gap: bool,
    pub(crate) values_kept: bool,
    pub(crate) shape: crate::history::append::AppendShape,
    pub(crate) part: u16,
}

impl Store {
    pub(crate) fn new() -> Self {
        Self {
            random: 1,
            time: 1_762_000_000_000,
            growth: Some(true),
            ring_limit: 16,
            ..Self::default()
        }
    }

    pub(crate) fn get(&self, account: &CompanionAccount) -> Option<&[u8]> {
        self.records.get(&account.name()).map(Vec::as_slice)
    }

    pub(crate) fn put(&mut self, write: RecordWrite) {
        self.records
            .insert(write.account.name(), write.bytes.to_vec());
    }

    pub(crate) fn delete(&mut self, account: &CompanionAccount) {
        self.records.remove(&account.name());
    }

    fn random(&mut self) -> CountingRandom {
        self.random = self.random.wrapping_add(37);
        CountingRandom(self.random)
    }

    pub(crate) fn next_change_id(&mut self) -> [u8; 16] {
        self.next_id = self.next_id.wrapping_add(1);
        let mut id = [0xa0; 16];
        id[15] = self.next_id;
        id
    }

    pub(crate) fn marker(&self) -> Option<Marker> {
        self.get(&CompanionAccount::Marker {
            vault_id: VAULT.to_owned(),
        })
        .map(|bytes| Marker::parse(VAULT, bytes).expect("marker"))
    }

    pub(crate) fn head(&self) -> Head {
        Head::parse(
            HISTORY,
            VAULT,
            self.get(&head_account(VAULT)).expect("head"),
        )
        .expect("head")
    }

    pub(crate) fn key(&self) -> KeyRecord {
        KeyRecord::decode(self.get(&key_account(VAULT)).expect("key")).expect("key")
    }

    pub(crate) fn has_history(&self) -> bool {
        self.get(&head_account(VAULT)).is_some()
    }

    /// Record a change from `before` to `after` the way a client does:
    /// create history when there's none, otherwise append, answering the
    /// plan's requests for more reads.
    pub(crate) fn record(
        &mut self,
        action: Action,
        before: &Project,
        after: &Project,
        renames: &[Rename<'_>],
    ) -> Result<Recorded, NotRecorded> {
        let id = self.next_change_id();
        self.record_with_id(id, action, Detail::default(), before, after, renames)
    }

    pub(crate) fn record_with_id(
        &mut self,
        id: [u8; 16],
        action: Action,
        detail: Detail<'_>,
        before: &Project,
        after: &Project,
        renames: &[Rename<'_>],
    ) -> Result<Recorded, NotRecorded> {
        self.time += 60_000;
        let before_values = before.values();
        let after_values = after.values();
        let change = Change {
            id,
            time: self.time,
            actor: Actor::Cli,
            action,
            detail,
            before: &before_values,
            after: &after_values,
            renames,
        };
        if !self.has_history() {
            if !change.changes_values() {
                return Ok(Recorded::Unchanged);
            }
            let mut random = self.random();
            let marker = self.marker();
            return match plan_creation(
                VAULT,
                marker.as_ref(),
                &change,
                Approval::Automatic,
                self.ring_limit,
                &mut random,
            )? {
                CreationPlan::NoKeyChanges => Ok(Recorded::NoKeyChanges),
                CreationPlan::Create(creation) => {
                    for write in creation.writes {
                        self.put(write);
                    }
                    Ok(Recorded::Created)
                }
            };
        }
        let mut growth = Growth::Unasked;
        let mut previous: Option<Vec<u8>> = None;
        let mut cache = AppendCache::default();
        loop {
            let tail = Head::parse(
                HISTORY,
                VAULT,
                self.get(&head_account(VAULT)).expect("head"),
            )
            .ok()
            .and_then(|head| self.get(&part_account(VAULT, head.tail())))
            .map(<[u8]>::to_vec);
            let key = self.get(&key_account(VAULT)).expect("key").to_vec();
            let head_bytes = self.get(&head_account(VAULT)).expect("head").to_vec();
            let stored = Stored {
                head: &head_bytes,
                key: &key,
                tail: tail.as_deref(),
                previous: previous.as_deref(),
            };
            let mut random = self.random();
            match plan_append(VAULT, &stored, &change, growth, &mut cache, &mut random)? {
                AppendPlan::Unchanged => return Ok(Recorded::Unchanged),
                AppendPlan::AlreadyRecorded => return Ok(Recorded::AlreadyRecorded),
                AppendPlan::NeedsPrevious { part } => {
                    previous = self.get(&part_account(VAULT, part)).map(<[u8]>::to_vec);
                    assert!(previous.is_some(), "the part before the tail exists");
                }
                AppendPlan::NeedsGrowthAdmission => {
                    assert_eq!(growth, Growth::Unasked, "admission is asked once");
                    self.admissions += 1;
                    growth = if self.growth.unwrap_or(true) {
                        Growth::Allowed
                    } else {
                        Growth::Refused
                    };
                }
                AppendPlan::Write(write) => return Ok(self.apply(write)),
            }
        }
    }

    fn apply(&mut self, write: AppendWrite) -> Recorded {
        let head_written = write.head.is_some();
        let part = write.part.account.part().expect("a part");
        let summary = AppendWriteSummary {
            gap: write.gap,
            values_kept: write.values_kept,
            shape: write.shape,
            part,
        };
        if let Some(head) = write.head {
            self.put(head);
        }
        self.put(write.part);
        Recorded::Appended {
            head_written,
            write: summary,
        }
    }

    /// The plaintext of `part`.
    pub(crate) fn plaintext(&self, part: u16) -> zeroize::Zeroizing<Vec<u8>> {
        keyring::open(
            &self.key(),
            &part_identity(VAULT, part),
            self.get(&part_account(VAULT, part)).expect("part"),
        )
        .expect("part opens")
    }

    /// Run `check` on every entry of `part`.
    pub(crate) fn with_entries(&self, part: u16, check: impl FnOnce(&[Entry<'_>])) {
        let plaintext = self.plaintext(part);
        let decoded = Part::decode(&plaintext).expect("part decodes");
        let entries: Vec<Entry<'_>> = decoded.decoded_entries().cloned().collect();
        check(&entries);
    }
}
