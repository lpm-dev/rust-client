//! Append-only kinds: a head record naming a ring of encrypted parts, oldest
//! first and the tail last, that history uses now and releases later.
//!
//! ```json
//! {"schemaVersion": 1, "vaultId": "…", "ringLimit": 16, "parts": [5, 6, 7, 0],
//!  "tailEpoch": 42, "removing": null}
//! ```
//!
//! - A steady append replaces the tail, outside the journal.
//! - A rollover writes the head first: the next part joins the ring, the
//!   oldest leaves it when its account is reused, and `tailEpoch` rises by
//!   one. Then it writes the next part, which stores the same epoch. A tail
//!   that's absent, or whose epoch differs from the head's, is a rollover a
//!   crash interrupted.
//! - A ring limited to one part slides instead: the oldest entries leave the
//!   tail in the same replacement.
//! - A trim writes the head without the oldest part, then deletes that part.
//!   Parts the head doesn't list are ignored and collected.
//!
//! The head says nothing about what parts hold; each kind brings its codec.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::keyring::Digest;
use crate::marker::describe_json_error;

/// The largest head a client writes or reads.
pub const MAX_HEAD_BYTES: usize = 4 * 1024;
/// The most place digests a running removal names.
pub const MAX_REMOVAL_PLACES: usize = 128;

/// One append-only kind: its parts' kind, its head's kind, how many parts
/// its ring may hold, and its feature's version, which the head and every
/// part's associated data carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogKind {
    pub kind: &'static str,
    pub head_kind: &'static str,
    pub max_parts: u16,
    pub schema_version: u16,
}

pub const HISTORY: LogKind = LogKind {
    kind: "history",
    head_kind: "history-head",
    max_parts: 16,
    schema_version: 1,
};

/// A removal in progress: the removed value's digest and the places it's
/// removed from, each a place digest, sorted and distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removing {
    pub value: Digest,
    pub places: Vec<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub vault_id: String,
    pub ring_limit: u16,
    /// Part numbers, oldest first; the last is the tail.
    pub parts: Vec<u16>,
    pub tail_epoch: u64,
    pub removing: Option<Removing>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeadJson {
    schema_version: u16,
    vault_id: String,
    ring_limit: u16,
    parts: Vec<u16>,
    tail_epoch: u64,
    /// Required even when `null`: `deserialize_with` makes a missing field an
    /// error, where serde would otherwise read it as `None`.
    #[serde(deserialize_with = "Option::deserialize")]
    removing: Option<RemovingJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovingJson {
    value: String,
    places: Vec<String>,
}

/// Why a head can't be used, which damages its feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidHead(pub String);

impl fmt::Display for InvalidHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn invalid(reason: impl Into<String>) -> InvalidHead {
    InvalidHead(reason.into())
}

impl Head {
    /// The head a new log starts with: part 0 alone, at epoch 1.
    pub fn new(vault_id: &str, ring_limit: u16) -> Self {
        Self {
            vault_id: vault_id.to_owned(),
            ring_limit,
            parts: vec![0],
            tail_epoch: 1,
            removing: None,
        }
    }

    pub fn parse(log: LogKind, vault_id: &str, bytes: &[u8]) -> Result<Self, InvalidHead> {
        if bytes.len() > MAX_HEAD_BYTES {
            return Err(invalid(format!("the {} head is too large", log.kind)));
        }
        let json: HeadJson = serde_json::from_slice(bytes).map_err(|error| {
            invalid(format!(
                "the {} head is malformed: {}",
                log.kind,
                describe_json_error(&error)
            ))
        })?;
        if json.schema_version != log.schema_version {
            return Err(invalid(format!(
                "the {} head's schema version is unknown",
                log.kind
            )));
        }
        if json.vault_id != vault_id {
            return Err(invalid(format!(
                "the {} head names another env project",
                log.kind
            )));
        }
        let removing = json
            .removing
            .map(|removing| {
                Ok::<_, InvalidHead>(Removing {
                    value: decode_digest(&removing.value)
                        .ok_or_else(|| invalid("a removal's value digest is invalid"))?,
                    places: removing
                        .places
                        .iter()
                        .map(|place| decode_digest(place))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| invalid("a removal's place digest is invalid"))?,
                })
            })
            .transpose()?;
        let head = Self {
            vault_id: json.vault_id,
            ring_limit: json.ring_limit,
            parts: json.parts,
            tail_epoch: json.tail_epoch,
            removing,
        };
        head.validate(log)?;
        Ok(head)
    }

    pub fn encode(&self, log: LogKind) -> Result<Vec<u8>, InvalidHead> {
        self.validate(log)?;
        let json = HeadJson {
            schema_version: log.schema_version,
            vault_id: self.vault_id.clone(),
            ring_limit: self.ring_limit,
            parts: self.parts.clone(),
            tail_epoch: self.tail_epoch,
            removing: self.removing.as_ref().map(|removing| RemovingJson {
                value: URL_SAFE_NO_PAD.encode(removing.value),
                places: removing
                    .places
                    .iter()
                    .map(|place| URL_SAFE_NO_PAD.encode(place))
                    .collect(),
            }),
        };
        let encoded = serde_json::to_vec(&json)
            .map_err(|error| invalid(format!("the {} head can't be encoded: {error}", log.kind)))?;
        if encoded.len() > MAX_HEAD_BYTES {
            return Err(invalid(format!("the {} head is too large", log.kind)));
        }
        Ok(encoded)
    }

    fn validate(&self, log: LogKind) -> Result<(), InvalidHead> {
        if !lpm_common::stored_env::is_safe_vault_id(&self.vault_id) {
            return Err(invalid(format!(
                "the {} head's env project ID is invalid",
                log.kind
            )));
        }
        if self.ring_limit == 0 || self.ring_limit > log.max_parts {
            return Err(invalid(format!(
                "the {} head's ring limit is invalid",
                log.kind
            )));
        }
        if self.parts.is_empty() || self.parts.len() > usize::from(self.ring_limit) {
            return Err(invalid(format!(
                "the {} head lists an invalid number of parts",
                log.kind
            )));
        }
        let mut seen = 0_u32;
        for part in &self.parts {
            if *part >= log.max_parts {
                return Err(invalid(format!(
                    "the {} head lists an invalid part",
                    log.kind
                )));
            }
            if seen & (1 << part) != 0 {
                return Err(invalid(format!("the {} head lists a part twice", log.kind)));
            }
            seen |= 1 << part;
        }
        if self.tail_epoch == 0 {
            return Err(invalid(format!("the {} head's epoch is invalid", log.kind)));
        }
        if let Some(removing) = &self.removing {
            if removing.places.is_empty() || removing.places.len() > MAX_REMOVAL_PLACES {
                return Err(invalid("a removal names an invalid number of places"));
            }
            if removing.places.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid("a removal's places aren't sorted and distinct"));
            }
        }
        Ok(())
    }

    pub fn tail(&self) -> u16 {
        *self.parts.last().expect("a valid head lists a part")
    }

    /// The part before the tail, which an interrupted rollover's tail takes
    /// its summary from.
    pub fn before_tail(&self) -> Option<u16> {
        self.parts
            .len()
            .checked_sub(2)
            .map(|index| self.parts[index])
    }

    pub fn lists(&self, part: u16) -> bool {
        self.parts.contains(&part)
    }

    /// Whether appends slide within one part instead of rolling over.
    pub fn slides(&self) -> bool {
        self.ring_limit == 1
    }

    /// Whether the next rollover would add an account, which only admission
    /// allows.
    pub fn would_grow(&self) -> bool {
        self.parts.len() < usize::from(self.ring_limit)
    }

    /// Whether the ring is full at a limit below a full ring's, which it got
    /// while the service held too many records: a rollover asks admission
    /// whether it may grow again.
    pub fn may_regrow(&self, log: LogKind) -> bool {
        self.ring_limit < log.max_parts && !self.would_grow()
    }

    /// The head a rollover writes, and the part it writes next. With
    /// `may_grow`, a ring below its limit takes the smallest free part
    /// number; otherwise the oldest part's account is reused, and a ring
    /// that couldn't grow keeps its size as its limit, so later rollovers
    /// don't ask admission again.
    pub fn rollover(&self, log: LogKind, may_grow: bool) -> Rollover {
        let mut next = self.clone();
        next.tail_epoch = self.tail_epoch.saturating_add(1);
        let grows = may_grow && self.would_grow();
        let part = if grows {
            (0..log.max_parts)
                .find(|part| !self.lists(*part))
                .expect("a ring below its limit has a free part")
        } else {
            if self.would_grow() {
                next.ring_limit = u16::try_from(self.parts.len()).expect("at most 16 parts");
            }
            next.parts.remove(0)
        };
        next.parts.push(part);
        Rollover {
            head: next,
            part,
            reused: !grows,
        }
    }

    /// The head after its oldest part is trimmed, and that part, or `None`
    /// when one part is left. The ring keeps its new size as its limit.
    pub fn trim_oldest(&self) -> Option<(Self, u16)> {
        if self.parts.len() < 2 {
            return None;
        }
        let mut next = self.clone();
        let oldest = next.parts.remove(0);
        next.ring_limit = u16::try_from(next.parts.len()).expect("at most 16 parts");
        Some((next, oldest))
    }
}

/// What a rollover writes: the head first, then the part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollover {
    pub head: Head,
    pub part: u16,
    /// Whether the part's account held the oldest part before.
    pub reused: bool,
}

/// What a client finds at the tail, against the head's epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailState {
    Current,
    /// Absent, or holding another epoch: a rollover wrote the head and
    /// crashed before the part.
    InterruptedRollover,
}

/// Whether the tail is the head's: `epoch` is the tail part's, or `None`
/// when the tail account is absent.
pub fn tail_state(head: &Head, epoch: Option<u64>) -> TailState {
    if epoch == Some(head.tail_epoch) {
        TailState::Current
    } else {
        TailState::InterruptedRollover
    }
}

fn decode_digest(encoded: &str) -> Option<Digest> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let digest: Digest = bytes.try_into().ok()?;
    (URL_SAFE_NO_PAD.encode(digest) == encoded).then_some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(parts: &[u16], ring_limit: u16) -> Head {
        Head {
            vault_id: "proj".to_owned(),
            ring_limit,
            parts: parts.to_vec(),
            tail_epoch: 7,
            removing: None,
        }
    }

    #[test]
    fn a_head_round_trips_through_its_exact_json() {
        let json = br#"{"schemaVersion":1,"vaultId":"proj","ringLimit":16,"parts":[5,6,7,0,1,2,3,4],"tailEpoch":42,"removing":null}"#;
        let parsed = Head::parse(HISTORY, "proj", json).expect("valid head");
        assert_eq!(parsed.tail(), 4);
        assert_eq!(parsed.before_tail(), Some(3));
        assert_eq!(parsed.encode(HISTORY).expect("encode"), json.to_vec());

        let removing = Head {
            removing: Some(Removing {
                value: [1; 16],
                places: vec![[2; 16], [3; 16]],
            }),
            ..parsed
        };
        let encoded = removing.encode(HISTORY).expect("encode");
        assert!(
            String::from_utf8_lossy(&encoded).contains(
                r#""removing":{"value":"AQEBAQEBAQEBAQEBAQEBAQ","places":["AgICAgICAgICAgICAgICAg","AwMDAwMDAwMDAwMDAwMDAw"]}"#
            ),
            "{}",
            String::from_utf8_lossy(&encoded)
        );
        assert_eq!(Head::parse(HISTORY, "proj", &encoded), Ok(removing));
    }

    #[test]
    fn heads_are_strict() {
        let valid = r#"{"schemaVersion":1,"vaultId":"proj","ringLimit":16,"parts":[0],"tailEpoch":1,"removing":null}"#;
        assert!(Head::parse(HISTORY, "proj", valid.as_bytes()).is_ok());
        for (bytes, why) in [
            (valid.replace("\"schemaVersion\":1", "\"schemaVersion\":2"), "version"),
            (valid.replace("proj", "other"), "another project"),
            (valid.replace("\"ringLimit\":16", "\"ringLimit\":17"), "ring limit over 16"),
            (valid.replace("\"ringLimit\":16", "\"ringLimit\":0"), "ring limit 0"),
            (valid.replace("[0]", "[]"), "no parts"),
            (valid.replace("[0]", "[16]"), "part 16"),
            (valid.replace("[0]", "[1,1]"), "repeated part"),
            (
                valid.replace("\"ringLimit\":16", "\"ringLimit\":1").replace("[0]", "[0,1]"),
                "more parts than the limit",
            ),
            (valid.replace("\"tailEpoch\":1", "\"tailEpoch\":0"), "epoch 0"),
            (valid.replace(",\"removing\":null", ""), "missing removing"),
            (valid.replace("}", ",\"extra\":1}"), "unknown field"),
            (
                valid.replace("\"tailEpoch\":1", "\"tailEpoch\":1,\"tailEpoch\":2"),
                "repeated field",
            ),
            (
                valid.replace(
                    "null",
                    r#"{"value":"AQEBAQEBAQEBAQEBAQEBAQ","places":[]}"#,
                ),
                "no places",
            ),
            (
                valid.replace(
                    "null",
                    r#"{"value":"AQEBAQEBAQEBAQEBAQEBAQ","places":["AwMDAwMDAwMDAwMDAwMDAw","AgICAgICAgICAgICAgICAg"]}"#,
                ),
                "unsorted places",
            ),
            (
                valid.replace(
                    "null",
                    r#"{"value":"AQEBAQEBAQEBAQEBAQEBAQ==","places":["AgICAgICAgICAgICAgICAg"]}"#,
                ),
                "padded digest",
            ),
            (
                valid.replace(
                    "null",
                    r#"{"value":"AQEBAQEBAQEBAQEBAQEBAR","places":["AgICAgICAgICAgICAgICAg"]}"#,
                ),
                "non-canonical digest",
            ),
            (
                valid.replace(
                    "null",
                    r#"{"value":"AQEBAQEBAQEBAQEBAQEB","places":["AgICAgICAgICAgICAgICAg"]}"#,
                ),
                "short digest",
            ),
        ] {
            assert!(
                Head::parse(HISTORY, "proj", bytes.as_bytes()).is_err(),
                "{why}: {bytes}"
            );
        }
        let oversized = format!("{valid}{}", " ".repeat(MAX_HEAD_BYTES));
        assert!(Head::parse(HISTORY, "proj", oversized.as_bytes()).is_err());
    }

    #[test]
    fn a_removal_of_128_places_fits_the_head_with_the_longest_vault_id() {
        let vault_id = "a".repeat(lpm_common::stored_env::MAX_VAULT_ID_BYTES);
        let mut head = Head::new(&vault_id, 16);
        head.parts = (0..16).collect();
        head.tail_epoch = u64::MAX;
        head.removing = Some(Removing {
            value: [0xff; 16],
            places: (0..MAX_REMOVAL_PLACES)
                .map(|index| {
                    let mut place = [0xff; 16];
                    place[..2].copy_from_slice(&(index as u16).to_be_bytes());
                    place
                })
                .collect(),
        });
        let encoded = head.encode(HISTORY).expect("128 places fit");
        assert!(encoded.len() <= MAX_HEAD_BYTES, "{}", encoded.len());
        assert_eq!(Head::parse(HISTORY, &vault_id, &encoded), Ok(head.clone()));

        let removing = head.removing.as_mut().expect("removing");
        removing.places.push([0xff; 16]);
        assert!(head.encode(HISTORY).is_err(), "129 places are refused");
    }

    #[test]
    fn rollover_grows_into_the_smallest_free_part_while_below_the_limit() {
        let ring = head(&[0, 2], 16);
        let rollover = ring.rollover(HISTORY, true);
        assert_eq!(rollover.part, 1);
        assert!(!rollover.reused);
        assert_eq!(rollover.head.parts, vec![0, 2, 1]);
        assert_eq!(rollover.head.tail_epoch, 8);
        assert_eq!(rollover.head.ring_limit, 16);
    }

    #[test]
    fn rollover_reuses_the_oldest_part_when_full_or_refused_growth() {
        let full = head(&[3, 0, 1, 2], 4);
        let rollover = full.rollover(HISTORY, true);
        assert_eq!((rollover.part, rollover.reused), (3, true));
        assert_eq!(rollover.head.parts, vec![0, 1, 2, 3]);
        assert_eq!(rollover.head.ring_limit, 4);

        let refused = head(&[0, 1], 16).rollover(HISTORY, false);
        assert_eq!((refused.part, refused.reused), (0, true));
        assert_eq!(refused.head.parts, vec![1, 0]);
        assert_eq!(
            refused.head.ring_limit, 2,
            "a ring that couldn't grow keeps its size as its limit"
        );
        assert!(!refused.head.would_grow());
    }

    #[test]
    fn a_new_ring_grows_at_its_first_rollover_and_a_one_part_limit_slides() {
        let new = Head::new("proj", 16);
        assert!(!new.slides());
        assert!(new.would_grow());
        assert_eq!(new.rollover(HISTORY, true).head.parts, vec![0, 1]);
        assert!(Head::new("proj", 1).slides());
    }

    #[test]
    fn trims_drop_the_oldest_part_and_keep_the_new_size_as_the_limit() {
        let ring = head(&[4, 5, 6], 16);
        let (trimmed, oldest) = ring.trim_oldest().expect("trim");
        assert_eq!(oldest, 4);
        assert_eq!(trimmed.parts, vec![5, 6]);
        assert_eq!(trimmed.ring_limit, 2);
        let (single, _) = trimmed.trim_oldest().expect("trim");
        assert!(single.slides());
        assert_eq!(single.trim_oldest(), None);
    }

    #[test]
    fn a_tail_that_is_absent_or_from_another_epoch_is_an_interrupted_rollover() {
        let ring = head(&[0, 1], 16);
        assert_eq!(tail_state(&ring, Some(7)), TailState::Current);
        assert_eq!(tail_state(&ring, Some(6)), TailState::InterruptedRollover);
        assert_eq!(tail_state(&ring, None), TailState::InterruptedRollover);
    }
}
