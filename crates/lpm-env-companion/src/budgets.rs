//! The budgets every write that adds companion accounts keeps within: how
//! many records a project holds, and how many companion and staged records
//! the whole service holds. Replacing an account adds none, and deletion,
//! discard and recovery are allowed over every budget, so only an operation
//! that creates accounts checks them, against the names-only inventory it
//! already takes. A record's size and a transaction's operations and bytes
//! are bounded by [`crate::marker::MAX_RECORD_BYTES`] and the transaction
//! limits in [`crate::lifecycle`].

use std::collections::HashMap;
use std::fmt;

use crate::account::CompanionAccount;

/// Single records a project may hold, the shared `key` included.
pub const MAX_SINGLE_RECORDS: usize = 8;
/// Companion records a project may hold, besides its marker.
pub const MAX_PROJECT_RECORDS: usize = 32;
/// Staged records a project may hold during a restore.
pub const MAX_STAGED_RECORDS: usize = 32;
/// Companion and staged records in the service, markers excluded, past which
/// a write that adds accounts warns.
pub const ADMISSION_TARGET: usize = 4_096;
/// Companion and staged records in the service, markers excluded, that a
/// write that adds accounts may never exceed.
pub const ADMISSION_CAP: usize = 8_192;

/// Parts a kind may have, for the kinds that are split into parts.
pub fn max_parts(kind: &str) -> Option<usize> {
    match kind {
        "history" => Some(16),
        "releases" => Some(8),
        _ => None,
    }
}

/// A budget a project's records would exceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverBudget {
    SingleRecords(usize),
    Parts { kind: String, count: usize },
    Records(usize),
    Staged(usize),
}

impl fmt::Display for OverBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleRecords(count) => write!(
                formatter,
                "this env project would hold {count} single records of newer data, more than {MAX_SINGLE_RECORDS}"
            ),
            Self::Parts { kind, count } => write!(
                formatter,
                "this env project's {kind} would have {count} parts, more than {}",
                max_parts(kind).unwrap_or_default()
            ),
            Self::Records(count) => write!(
                formatter,
                "this env project would hold {count} records of newer data, more than {MAX_PROJECT_RECORDS}"
            ),
            Self::Staged(count) => write!(
                formatter,
                "this env project's restore would stage {count} records, more than {MAX_STAGED_RECORDS}"
            ),
        }
    }
}

/// Check the companion and staged records one project would hold after a
/// write that adds accounts. Its marker never counts.
pub fn check_project<'account>(
    accounts: impl IntoIterator<Item = &'account CompanionAccount>,
) -> Result<(), OverBudget> {
    let (mut singles, mut records, mut staged) = (0, 0, 0);
    let mut parts: HashMap<&str, usize> = HashMap::new();
    for account in accounts {
        match account {
            CompanionAccount::Marker { .. } => {}
            CompanionAccount::Staged { .. } => staged += 1,
            CompanionAccount::Record { kind, part, .. } => {
                records += 1;
                match part {
                    None => singles += 1,
                    Some(_) => *parts.entry(kind.as_str()).or_default() += 1,
                }
            }
        }
    }
    if singles > MAX_SINGLE_RECORDS {
        return Err(OverBudget::SingleRecords(singles));
    }
    let mut over: Vec<(&str, usize)> = parts
        .into_iter()
        .filter(|(kind, count)| max_parts(kind).is_some_and(|limit| *count > limit))
        .collect();
    over.sort_unstable();
    if let Some((kind, count)) = over.into_iter().next() {
        return Err(OverBudget::Parts {
            kind: kind.to_owned(),
            count,
        });
    }
    if records > MAX_PROJECT_RECORDS {
        return Err(OverBudget::Records(records));
    }
    if staged > MAX_STAGED_RECORDS {
        return Err(OverBudget::Staged(staged));
    }
    Ok(())
}

/// Whether a write may add accounts to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admitted,
    /// Admitted, past the target, which the person should hear about.
    OverTarget,
    /// Past the cap: the write is refused.
    Refused,
}

/// Admission for a write that adds `adding` accounts to a service whose
/// names-only inventory holds `existing` companion and staged records,
/// orphans included and markers not.
pub fn admit(existing: usize, adding: usize) -> Admission {
    let after = existing.saturating_add(adding);
    if adding == 0 || after <= ADMISSION_TARGET {
        Admission::Admitted
    } else if after <= ADMISSION_CAP {
        Admission::OverTarget
    } else {
        Admission::Refused
    }
}

/// How many accounts in `names` admission counts: companion and staged
/// records of every project, orphans included, but not markers.
pub fn admission_count<'name>(names: impl IntoIterator<Item = &'name str>) -> usize {
    names
        .into_iter()
        .filter_map(CompanionAccount::parse)
        .filter(|account| !matches!(account, CompanionAccount::Marker { .. }))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, part: Option<u16>) -> CompanionAccount {
        CompanionAccount::Record {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part,
        }
    }

    fn staged(kind: &str, part: Option<u16>) -> CompanionAccount {
        CompanionAccount::Staged {
            kind: kind.to_owned(),
            vault_id: "proj".to_owned(),
            part,
        }
    }

    fn singles(count: usize) -> Vec<CompanionAccount> {
        (0..count)
            .map(|index| record(&format!("kind-{index}"), None))
            .collect()
    }

    #[test]
    fn every_project_budget_holds_at_its_limit_and_refuses_one_more() {
        let marker = CompanionAccount::Marker {
            vault_id: "proj".to_owned(),
        };
        let mut at_limit = singles(MAX_SINGLE_RECORDS);
        at_limit.push(marker);
        assert_eq!(check_project(&at_limit), Ok(()), "the marker never counts");
        assert_eq!(
            check_project(&singles(MAX_SINGLE_RECORDS + 1)),
            Err(OverBudget::SingleRecords(MAX_SINGLE_RECORDS + 1))
        );

        for (kind, limit) in [("history", 16), ("releases", 8)] {
            let parts: Vec<CompanionAccount> =
                (0..limit).map(|part| record(kind, Some(part))).collect();
            assert_eq!(check_project(&parts), Ok(()), "{kind}");
            let mut over = parts;
            over.push(record(kind, Some(limit)));
            assert_eq!(
                check_project(&over),
                Err(OverBudget::Parts {
                    kind: kind.to_owned(),
                    count: usize::from(limit) + 1
                })
            );
        }

        let mut records: Vec<CompanionAccount> = (0..24)
            .map(|part| record("future-log", Some(part)))
            .collect();
        records.extend(singles(MAX_SINGLE_RECORDS));
        assert_eq!(records.len(), MAX_PROJECT_RECORDS);
        assert_eq!(check_project(&records), Ok(()));
        records.push(record("future-log", Some(24)));
        assert_eq!(
            check_project(&records),
            Err(OverBudget::Records(MAX_PROJECT_RECORDS + 1))
        );

        let staged_at_limit: Vec<CompanionAccount> = (0..MAX_STAGED_RECORDS)
            .map(|part| staged("future-log", Some(part as u16)))
            .collect();
        assert_eq!(check_project(&staged_at_limit), Ok(()));
        let mut staged_over = staged_at_limit;
        staged_over.push(staged("overrides", None));
        assert_eq!(
            check_project(&staged_over),
            Err(OverBudget::Staged(MAX_STAGED_RECORDS + 1))
        );
    }

    #[test]
    fn admission_warns_past_the_target_and_refuses_past_the_cap() {
        assert_eq!(admit(ADMISSION_TARGET - 1, 1), Admission::Admitted);
        assert_eq!(admit(ADMISSION_TARGET, 1), Admission::OverTarget);
        assert_eq!(admit(ADMISSION_CAP - 1, 1), Admission::OverTarget);
        assert_eq!(admit(ADMISSION_CAP, 1), Admission::Refused);
        assert_eq!(
            admit(ADMISSION_CAP + 10, 0),
            Admission::Admitted,
            "a write that adds nothing, such as a replacement, is never refused"
        );
        assert_eq!(admit(usize::MAX, 1), Admission::Refused);
    }

    #[test]
    fn admission_counts_orphans_and_staged_records_but_not_markers() {
        let names = [
            crate::account::marker_account("proj"),
            crate::account::record_account("overrides", "proj", None),
            crate::account::record_account("notes", "gone", None),
            crate::account::staged_account("history", "proj", Some(3)),
            "proj".to_owned(),
            "__vault_project_index_marker__".to_owned(),
        ];
        assert_eq!(admission_count(names.iter().map(String::as_str)), 3);
    }
}
