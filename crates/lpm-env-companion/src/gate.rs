//! What an operation may do to a project, given its feature marker: the
//! operation matrix every gate-aware client applies inside the lock.

use std::fmt;

use crate::marker::{FeatureEntry, InvalidMarker, Level, Marker};

/// What an operation does with a project's values and companion records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Reads values to run, show or send them, without personal overrides.
    ReadExcludingOverrides,
    /// Reads values together with personal overrides, to run or show them.
    ReadApplyingOverrides,
    /// Writes values or companion records.
    Write,
    /// Recovery, resume and project deletion, which never depend on content.
    Maintenance,
}

/// What a damaged project lacks or holds that it shouldn't.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Damage {
    InvalidMarker(String),
    MissingRecord {
        kind: String,
    },
    InvalidRecord {
        kind: String,
        reason: String,
    },
    UnlistedRecord {
        kind: String,
    },
    /// Approval attributes that contradict each other, which only the macOS
    /// Keychain has.
    Access(String),
    /// An interrupted change whose journal or files are in a state no LPM
    /// client leaves them in, so it can't be finished or undone.
    Unfinished(String),
}

impl Damage {
    /// Whether only the personal overrides are damaged, which reads that
    /// exclude them don't depend on.
    fn only_overrides(&self) -> bool {
        matches!(
            self,
            Self::MissingRecord { kind } | Self::InvalidRecord { kind, .. } | Self::UnlistedRecord { kind }
                if kind == crate::overrides::OVERRIDES_KIND
        )
    }
}

impl fmt::Display for Damage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMarker(reason) => write!(formatter, "{reason}"),
            Self::MissingRecord { kind } => write!(formatter, "missing record \"{kind}\""),
            Self::InvalidRecord { kind, reason } => {
                write!(formatter, "record \"{kind}\" is invalid: {reason}")
            }
            Self::UnlistedRecord { kind } => {
                write!(formatter, "record \"{kind}\" belongs to no feature")
            }
            Self::Access(reason) => write!(formatter, "{reason}"),
            Self::Unfinished(reason) => {
                write!(
                    formatter,
                    "an interrupted change can't be finished: {reason}"
                )
            }
        }
    }
}

impl From<InvalidMarker> for Damage {
    fn from(error: InvalidMarker) -> Self {
        Self::InvalidMarker(error.0)
    }
}

/// Why the gate stopped an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    Unsupported {
        feature: String,
        version: u16,
        level: Level,
    },
    Damaged(Damage),
}

/// How every [`GateError`] message begins, so a client whose storage layer
/// passes errors as text can tell a refusal from a storage failure.
const MESSAGE_PREFIX: &str = "This env project";

impl GateError {
    /// Whether `message` is a [`GateError`]'s.
    pub fn describes(message: &str) -> bool {
        message.starts_with(MESSAGE_PREFIX)
    }
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported {
                feature,
                version,
                level: Level::ReadOnly,
            } => write!(
                formatter,
                "This env project uses {} v{version}, which this LPM CLI can only read. Update the LPM CLI to change it: lpm self-update",
                feature_description(feature)
            ),
            Self::Unsupported {
                feature, version, ..
            } => write!(
                formatter,
                "This env project uses {} v{version}, which this LPM CLI doesn't support. Update the LPM CLI: lpm self-update",
                feature_description(feature)
            ),
            Self::Damaged(Damage::Access(reason)) => {
                write!(
                    formatter,
                    "This env project's CLI approval is damaged: {reason}."
                )?;
                if cfg!(target_os = "macos") {
                    formatter
                        .write_str(" Switch its CLI approval in LPM Vault to set it again.")?;
                }
                Ok(())
            }
            Self::Damaged(damage) => {
                write!(
                    formatter,
                    "This env project's newer data is damaged ({damage})."
                )?;
                if cfg!(target_os = "macos") {
                    formatter.write_str(" Repair it in LPM Vault, or with: lpm env repair")
                } else {
                    formatter.write_str(" Repair it: lpm env repair")
                }
            }
        }
    }
}

/// How messages name a feature. Feature names follow the identifier grammar,
/// so an unknown one is safe to show quoted.
pub fn feature_description(feature: &str) -> String {
    match feature {
        "overrides" => "personal overrides".to_owned(),
        "history" => "local history".to_owned(),
        "releases" => "a release log".to_owned(),
        "details" => "project details".to_owned(),
        other => format!("the feature \"{other}\""),
    }
}

/// What the gate knows about one project inside one lock scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectGate {
    /// No marker: the project has no companion data a client must understand.
    Plain,
    Marked(Marker),
    Damaged(Damage),
}

impl ProjectGate {
    pub fn marker(&self) -> Option<&Marker> {
        match self {
            Self::Marked(marker) => Some(marker),
            Self::Plain | Self::Damaged(_) => None,
        }
    }

    /// Apply the operation matrix.
    pub fn authorize(&self, operation: Operation) -> Result<(), GateError> {
        if operation == Operation::Maintenance {
            return Ok(());
        }
        let marker = match self {
            Self::Plain => return Ok(()),
            Self::Damaged(damage) => {
                if operation == Operation::ReadExcludingOverrides && damage.only_overrides() {
                    return Ok(());
                }
                return Err(GateError::Damaged(damage.clone()));
            }
            Self::Marked(marker) => marker,
        };
        let level = marker.level();
        let allowed = match operation {
            Operation::ReadExcludingOverrides | Operation::ReadApplyingOverrides => {
                level <= Level::ReadOnly
            }
            Operation::Write => level == Level::Ignore,
            Operation::Maintenance => true,
        };
        if allowed {
            return Ok(());
        }
        let (feature, entry) = marker
            .strictest_unsupported()
            .map_or(("", None), |(name, entry)| (name, Some(entry)));
        Err(GateError::Unsupported {
            feature: feature.to_owned(),
            version: entry.map_or(0, |entry: &FeatureEntry| entry.version),
            level,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marker::{FeatureState, ProjectState};

    fn marked(name: &str, version: u16, level: Level, kinds: &[&str]) -> ProjectGate {
        let mut marker = Marker::empty("proj", ProjectState::Active);
        marker.features.insert(
            name.to_owned(),
            FeatureEntry {
                version,
                if_unsupported: level,
                kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
                state: FeatureState::Active,
            },
        );
        marker.validate().expect("valid marker");
        ProjectGate::Marked(marker)
    }

    const OPERATIONS: [Operation; 4] = [
        Operation::ReadExcludingOverrides,
        Operation::ReadApplyingOverrides,
        Operation::Write,
        Operation::Maintenance,
    ];

    #[test]
    fn every_matrix_cell_matches_the_design() {
        let ignore = marked("future", 1, Level::Ignore, &["thing"]);
        let read_only = marked("future", 1, Level::ReadOnly, &["thing"]);
        let refuse = marked("future", 1, Level::Refuse, &["thing"]);
        let damaged = ProjectGate::Damaged(Damage::InvalidMarker("broken".to_owned()));
        let expectations = [
            (&ProjectGate::Plain, [true, true, true, true]),
            (&ignore, [true, true, true, true]),
            (&read_only, [true, true, false, true]),
            (&refuse, [false, false, false, true]),
            (&damaged, [false, false, false, true]),
        ];
        for (gate, allowed) in expectations {
            for (operation, expected) in OPERATIONS.iter().zip(allowed) {
                assert_eq!(
                    gate.authorize(*operation).is_ok(),
                    expected,
                    "{gate:?} {operation:?}"
                );
            }
        }
    }

    #[test]
    fn damaged_overrides_block_only_reads_that_apply_them() {
        for damage in [
            Damage::MissingRecord {
                kind: "overrides".to_owned(),
            },
            Damage::UnlistedRecord {
                kind: "overrides".to_owned(),
            },
            Damage::InvalidRecord {
                kind: "overrides".to_owned(),
                reason: "bad".to_owned(),
            },
        ] {
            let gate = ProjectGate::Damaged(damage);
            assert!(gate.authorize(Operation::ReadExcludingOverrides).is_ok());
            assert!(gate.authorize(Operation::ReadApplyingOverrides).is_err());
            assert!(gate.authorize(Operation::Write).is_err());
        }
        let access = ProjectGate::Damaged(Damage::Access("weak".to_owned()));
        assert!(access.authorize(Operation::ReadExcludingOverrides).is_err());
    }

    #[test]
    fn unsupported_overrides_refuse_whatever_the_marker_says() {
        let gate = marked("overrides", 2, Level::Ignore, &["overrides"]);
        let error = gate
            .authorize(Operation::ReadApplyingOverrides)
            .expect_err("unsupported overrides refuse");
        assert_eq!(
            error.to_string(),
            "This env project uses personal overrides v2, which this LPM CLI doesn't support. Update the LPM CLI: lpm self-update"
        );
    }

    #[test]
    fn read_only_features_explain_that_changes_need_an_update() {
        let gate = marked(
            "history",
            2,
            Level::ReadOnly,
            &["history-head", "history", "key"],
        );
        assert!(gate.authorize(Operation::ReadApplyingOverrides).is_ok());
        assert_eq!(
            gate.authorize(Operation::Write)
                .expect_err("read-only refuses writes")
                .to_string(),
            "This env project uses local history v2, which this LPM CLI can only read. Update the LPM CLI to change it: lpm self-update"
        );
    }

    #[test]
    fn every_refusal_is_recognized_by_its_message() {
        let refusals = [
            GateError::Unsupported {
                feature: "overrides".to_owned(),
                version: 2,
                level: Level::Refuse,
            },
            GateError::Unsupported {
                feature: "history".to_owned(),
                version: 2,
                level: Level::ReadOnly,
            },
            GateError::Damaged(Damage::InvalidMarker("x".to_owned())),
            GateError::Damaged(Damage::MissingRecord {
                kind: "overrides".to_owned(),
            }),
            GateError::Damaged(Damage::InvalidRecord {
                kind: "overrides".to_owned(),
                reason: "x".to_owned(),
            }),
            GateError::Damaged(Damage::UnlistedRecord {
                kind: "notes".to_owned(),
            }),
            GateError::Damaged(Damage::Access("x".to_owned())),
            GateError::Damaged(Damage::Unfinished("x".to_owned())),
        ];
        for refusal in refusals {
            assert!(GateError::describes(&refusal.to_string()), "{refusal:?}");
        }
        assert!(!GateError::describes(
            "failed to read companion entry: denied"
        ));
    }

    #[test]
    fn damaged_access_names_the_approval_not_the_newer_data() {
        let message = GateError::Damaged(Damage::Access(
            "the values' approval attributes contradict each other".to_owned(),
        ))
        .to_string();
        assert!(
            message.starts_with(
                "This env project's CLI approval is damaged: the values' approval attributes contradict each other."
            ),
            "{message}"
        );
        assert!(!message.contains("newer data"), "{message}");
    }

    #[test]
    fn damage_names_the_missing_record() {
        let message = GateError::Damaged(Damage::MissingRecord {
            kind: "overrides".to_owned(),
        })
        .to_string();
        assert!(
            message.starts_with(
                "This env project's newer data is damaged (missing record \"overrides\")."
            ),
            "{message}"
        );
    }
}
