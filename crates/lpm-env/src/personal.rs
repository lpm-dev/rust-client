//! Layer 4 of a project's environment: this computer's personal overrides,
//! and which validation failures they caused. The runner, `lpm env check`
//! and LPM Vault's engine apply them through this one implementation.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{EnvName, ValidationError, ValidationErrorKind, is_denied_env_var};

/// One environment's personal overrides: values that replace the project's,
/// an empty string included, and names whose project value is removed.
#[derive(Clone, Copy)]
pub struct PersonalOverrideLayer<'a> {
    pub set: &'a HashMap<String, String>,
    pub unset: &'a [String],
}

/// Names only: an override's value is a secret.
impl std::fmt::Debug for PersonalOverrideLayer<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersonalOverrideLayer")
            .field("set", &self.set.keys().collect::<BTreeSet<_>>())
            .field("unset", &self.unset)
            .finish()
    }
}

impl PersonalOverrideLayer<'_> {
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }

    pub fn len(&self) -> usize {
        self.set.len() + self.unset.len()
    }
}

/// Layer 4: set and unset `overrides` in one pass over `vars`. Where the
/// host ignores case, a name matches without case, so the override's
/// spelling replaces the project's.
pub fn apply_personal_overrides(
    vars: &mut HashMap<String, String>,
    overrides: PersonalOverrideLayer<'_>,
    case_insensitive: bool,
) {
    if overrides.is_empty() {
        return;
    }
    if case_insensitive {
        // Override names are validated ASCII, so an ASCII name matches by
        // ASCII case folding; only a non-ASCII name needs the host's rule.
        let names: HashSet<CaselessAscii<'_>> = overrides
            .set
            .keys()
            .chain(overrides.unset)
            .map(|name| CaselessAscii(name))
            .collect();
        let mut host_names: Option<BTreeSet<EnvName>> = None;
        vars.retain(|existing, _| {
            if existing.is_ascii() {
                return !names.contains(&CaselessAscii(existing));
            }
            let host_names = host_names
                .get_or_insert_with(|| names.iter().map(|name| EnvName::new(name.0)).collect());
            !host_names.contains(&EnvName::new(existing))
        });
    } else {
        for name in overrides.unset {
            vars.remove(name);
        }
    }
    vars.extend(
        overrides
            .set
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
}

/// An ASCII name compared and hashed without case, without allocating.
#[derive(Clone, Copy)]
struct CaselessAscii<'name>(&'name str);

impl PartialEq for CaselessAscii<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for CaselessAscii<'_> {}

impl std::hash::Hash for CaselessAscii<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_uppercase());
        }
        state.write_u8(0xff);
    }
}

/// What the personal overrides decided for one name. A `Set` reads its
/// value from the overrides it was decided from, so the origins never copy
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Set,
    Unset,
}

/// The names whose value the personal overrides still decide, compared as
/// the host compares names. A later layer that writes a name takes it back,
/// so a validation failure names an override only while it's the value's
/// final origin.
#[derive(Debug, Clone, Default)]
pub struct PersonalOverrideOrigins {
    /// Each name as the host compares it.
    decided: HashMap<String, Decided>,
    case_insensitive: bool,
}

#[derive(Debug, Clone)]
struct Decided {
    spelling: String,
    decision: Decision,
    /// What the name held before the override, which a group rule's verdict
    /// before it counts.
    before: Before,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Before {
    Absent,
    Empty,
    Present,
}

impl Before {
    fn of(value: Option<&str>) -> Self {
        match value {
            None => Self::Absent,
            Some("") => Self::Empty,
            Some(_) => Self::Present,
        }
    }
}

impl PersonalOverrideOrigins {
    /// The overrides that change `vars`, the environment before layer 4: a
    /// `set` of a name it lacks or holds another value for, and an `unset` of
    /// a name it has. Names LPM never passes to a process change nothing.
    pub fn changing(
        vars: &HashMap<String, String>,
        overrides: PersonalOverrideLayer<'_>,
        case_insensitive: bool,
    ) -> Self {
        let mut origins = Self {
            decided: HashMap::with_capacity(overrides.len()),
            case_insensitive,
        };
        if overrides.is_empty() {
            return origins;
        }
        let caseless: Option<HashMap<CaselessAscii<'_>, &str>> = case_insensitive.then(|| {
            vars.iter()
                .map(|(name, value)| (CaselessAscii(name), value.as_str()))
                .collect()
        });
        let current = |name: &str| match &caseless {
            Some(caseless) => caseless.get(&CaselessAscii(name)).copied(),
            None => vars.get(name).map(String::as_str),
        };
        for (name, value) in overrides.set {
            let before = current(name);
            if !is_denied_env_var(name) && before != Some(value.as_str()) {
                let key = origins.key(name);
                origins.decided.insert(
                    key,
                    Decided {
                        spelling: name.clone(),
                        decision: Decision::Set,
                        before: Before::of(before),
                    },
                );
            }
        }
        for name in overrides.unset {
            let before = current(name);
            if !is_denied_env_var(name) && before.is_some() {
                let key = origins.key(name);
                origins.decided.insert(
                    key,
                    Decided {
                        spelling: name.clone(),
                        decision: Decision::Unset,
                        before: Before::of(before),
                    },
                );
            }
        }
        origins
    }

    /// How many overrides change the environment.
    pub fn len(&self) -> usize {
        self.decided.len()
    }

    pub fn is_empty(&self) -> bool {
        self.decided.is_empty()
    }

    /// The spelling of the override that still decides `name`, compared as
    /// the host compares names.
    pub fn decides(&self, name: &str) -> Option<&str> {
        if self.decided.is_empty() {
            return None;
        }
        self.decided
            .get(&self.key(name))
            .map(|decided| decided.spelling.as_str())
    }

    /// The names of the overrides that change the environment, as they're
    /// spelled, in order.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .decided
            .values()
            .map(|decided| decided.spelling.as_str())
            .collect();
        names.sort_unstable();
        names
    }

    /// Override names are validated ASCII, so where the host ignores case
    /// they compare by ASCII case.
    fn key(&self, name: &str) -> String {
        if self.case_insensitive {
            name.to_ascii_uppercase()
        } else {
            name.to_owned()
        }
    }

    /// A later layer wrote `name`.
    pub fn release(&mut self, name: &str) {
        if !self.decided.is_empty() {
            let key = self.key(name);
            self.decided.remove(&key);
        }
    }

    /// For each of `errors`, the schema's verdict on `vars`, in order,
    /// whether one of `overrides`, the ones these origins were decided from,
    /// caused it. A group rule's violation names every member of the group,
    /// so it's the overrides' when the group kept its rule with each member
    /// as it would have been without them and breaks it now. Any other error
    /// is an override's when the override still gives the value the schema
    /// judged, or its `unset` left missing or empty a value that held one
    /// before it. Names are looked up once each, without case where the host
    /// ignores it.
    ///
    /// `vars` is the environment the schema judged, with everything its
    /// evaluation added, such as inherited values and defaults. For a member
    /// an override decides that lacked a value before it (`None`) or held an
    /// empty one (`Some("")`), `filled` says whether that evaluation would
    /// have given it a non-empty value. It's asked only about names LPM
    /// passes to a process.
    pub fn attribute(
        &self,
        errors: &[ValidationError],
        vars: &HashMap<String, String>,
        overrides: PersonalOverrideLayer<'_>,
        filled: impl Fn(&str, Option<&str>) -> bool,
    ) -> Vec<bool> {
        if errors.is_empty() {
            return Vec::new();
        }
        if self.decided.is_empty() {
            return vec![false; errors.len()];
        }
        let caseless: Option<HashMap<CaselessAscii<'_>, &str>> = self.case_insensitive.then(|| {
            vars.iter()
                .map(|(name, value)| (CaselessAscii(name), value.as_str()))
                .collect()
        });
        let value_of = |name: &str| match &caseless {
            Some(caseless) => caseless.get(&CaselessAscii(name)).copied(),
            None => vars.get(name).map(String::as_str),
        };
        let mut groups: HashMap<&str, (crate::VarGroupMode, Vec<&str>)> = HashMap::new();
        for error in errors {
            if let ValidationErrorKind::GroupViolation { group, mode } = &error.kind {
                groups
                    .entry(group)
                    .or_insert_with(|| (*mode, Vec::new()))
                    .1
                    .push(&error.key);
            }
        }
        let present_now = |name: &str| value_of(name).is_some_and(|value| !value.is_empty());
        // What a member an override decides held before it stands whatever
        // the evaluation then made of it, such as a default that fills it
        // after an unset; a later layer that wrote it took it back.
        let held_before = |name: &str, decided: &Decided| match decided.before {
            Before::Present => true,
            Before::Empty => filled(name, Some("")),
            Before::Absent => filled(name, None),
        };
        let present_before = |name: &str| match self.decided.get(&self.key(name)) {
            Some(decided) => held_before(name, decided),
            None => present_now(name),
        };
        let broken: HashSet<&str> = groups
            .iter()
            .filter(|(_, (mode, members))| {
                let before = members.iter().filter(|name| present_before(name)).count();
                let now = members.iter().filter(|name| present_now(name)).count();
                crate::constraints::group_holds(*mode, before, members.len())
                    && !crate::constraints::group_holds(*mode, now, members.len())
            })
            .map(|(group, _)| *group)
            .collect();
        errors
            .iter()
            .map(|error| match &error.kind {
                ValidationErrorKind::GroupViolation { group, .. } => {
                    broken.contains(group.as_str())
                }
                _ => self
                    .decided
                    .get(&self.key(&error.key))
                    .is_some_and(|decided| {
                        let value = value_of(&error.key);
                        match decided.decision {
                            Decision::Set => decided.still_gives(value, overrides),
                            Decision::Unset => {
                                matches!(
                                    error.kind,
                                    ValidationErrorKind::Missing | ValidationErrorKind::Empty
                                ) && value.is_none_or(str::is_empty)
                                    && held_before(&error.key, decided)
                            }
                        }
                    }),
            })
            .collect()
    }
}

impl Decided {
    /// Whether a set override still gives the name its final `value`, rather
    /// than a later layer or a schema default.
    fn still_gives(&self, value: Option<&str>, overrides: PersonalOverrideLayer<'_>) -> bool {
        value.is_some() && value == overrides.set.get(&self.spelling).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn layer<'a>(
        set: &'a HashMap<String, String>,
        unset: &'a [String],
    ) -> PersonalOverrideLayer<'a> {
        PersonalOverrideLayer { set, unset }
    }

    fn error(key: &str, kind: ValidationErrorKind) -> ValidationError {
        ValidationError {
            key: key.to_owned(),
            kind,
            description: None,
            is_secret: false,
        }
    }

    #[test]
    fn overrides_match_names_without_case_where_the_host_ignores_case() {
        let mut vars = map(&[
            ("api_url", "team"),
            ("Sentry_Dsn", "team"),
            ("KEEP", "team"),
        ]);
        let set = map(&[("API_URL", "mine")]);
        let unset = names(&["SENTRY_DSN"]);
        apply_personal_overrides(&mut vars, layer(&set, &unset), true);
        assert_eq!(vars, map(&[("API_URL", "mine"), ("KEEP", "team")]));

        let mut exact = map(&[("api_url", "team")]);
        apply_personal_overrides(&mut exact, layer(&set, &[]), false);
        assert_eq!(exact, map(&[("api_url", "team"), ("API_URL", "mine")]));
    }

    #[test]
    fn non_ascii_names_use_the_hosts_own_comparison() {
        let mut vars = map(&[("ÄPI", "team"), ("API", "team")]);
        let set = map(&[("API", "mine")]);
        apply_personal_overrides(&mut vars, layer(&set, &[]), true);
        assert_eq!(vars["API"], "mine");
        assert_eq!(vars["ÄPI"], "team");
    }

    #[test]
    fn an_unset_is_blamed_only_for_the_value_it_left_missing() {
        let unset = names(&["PORT"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("PORT", "8080")]),
            layer(&HashMap::new(), &unset),
            false,
        );
        let empty = HashMap::new();
        let invalid = error(
            "PORT",
            ValidationErrorKind::ConstraintViolation { constraint: "port" },
        );
        assert_eq!(
            origins.attribute(
                &[error("PORT", ValidationErrorKind::Missing), invalid],
                &empty,
                layer(&HashMap::new(), &unset),
                unfilled,
            ),
            [true, false],
            "an invalid value came from somewhere the unset didn't"
        );
    }

    #[test]
    fn an_unset_that_lets_an_empty_value_through_is_blamed_for_its_presence_error() {
        let unset = names(&["PORT"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("PORT", "8080")]),
            layer(&HashMap::new(), &unset),
            false,
        );
        assert_eq!(
            origins.attribute(
                &[
                    error("PORT", ValidationErrorKind::Missing),
                    error("PORT", ValidationErrorKind::Empty),
                ],
                &map(&[("PORT", "")]),
                layer(&HashMap::new(), &unset),
                unfilled,
            ),
            [true, true],
            "the unset removed a value that passed, and an inherited empty one showed through"
        );
    }

    #[test]
    fn an_unset_of_an_empty_value_is_blamed_only_where_the_empty_value_would_have_passed() {
        let unset = names(&["PORT"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("PORT", "")]),
            layer(&HashMap::new(), &unset),
            false,
        );
        let missing = [error("PORT", ValidationErrorKind::Missing)];
        let attribute = |filled: fn(&str, Option<&str>) -> bool| {
            origins.attribute(
                &missing,
                &HashMap::new(),
                layer(&HashMap::new(), &unset),
                filled,
            )
        };
        assert_eq!(
            attribute(unfilled),
            [false],
            "the empty value was missing to the schema before the unset too"
        );
        assert_eq!(
            attribute(|_, _| true),
            [true],
            "a default would have filled the empty value the unset removed"
        );
    }

    #[test]
    fn an_override_is_found_under_the_declared_spelling_where_the_host_ignores_case() {
        let set = map(&[("api_url", "not a url")]);
        let invalid = [error(
            "API_URL",
            ValidationErrorKind::ConstraintViolation { constraint: "url" },
        )];
        let vars = map(&[("API_URL", "not a url")]);
        let attribute = |case_insensitive| {
            PersonalOverrideOrigins::changing(&HashMap::new(), layer(&set, &[]), case_insensitive)
                .attribute(&invalid, &vars, layer(&set, &[]), unfilled)
        };
        assert_eq!(attribute(true), [true]);
        assert_eq!(attribute(false), [false]);
    }

    #[test]
    fn the_override_deciding_a_name_is_found_as_the_host_compares_names() {
        let set = map(&[("api_url", "mine")]);
        let decides = |case_insensitive| {
            PersonalOverrideOrigins::changing(
                &map(&[("API_URL", "team")]),
                layer(&set, &[]),
                case_insensitive,
            )
            .decides("API_URL")
            .map(str::to_owned)
        };
        assert_eq!(decides(true).as_deref(), Some("api_url"));
        assert_eq!(decides(false), None);
    }

    #[test]
    fn the_names_of_changing_overrides_leave_out_no_ops_and_names_lpm_never_passes() {
        let set = map(&[
            ("SAME", "team"),
            ("NEW", "mine"),
            ("NODE_OPTIONS", "--inspect"),
        ]);
        let unset = names(&["GONE", "ABSENT"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("SAME", "team"), ("GONE", "team")]),
            layer(&set, &unset),
            false,
        );
        assert_eq!(origins.names(), ["GONE", "NEW"]);
        assert_eq!(origins.len(), 2);
    }

    #[test]
    fn debug_output_names_overrides_and_never_shows_their_values() {
        let set = HashMap::from([("TOKEN".to_owned(), "fixture-secret".to_owned())]);
        let unset = vec!["SENTRY_DSN".to_owned()];
        let layer = PersonalOverrideLayer {
            set: &set,
            unset: &unset,
        };
        let origins = PersonalOverrideOrigins::changing(&HashMap::new(), layer, false);
        for printed in [format!("{layer:?}"), format!("{origins:?}")] {
            assert!(!printed.contains("fixture-secret"), "{printed}");
            assert!(printed.contains("TOKEN"), "{printed}");
        }
    }

    /// No evaluation fills a name the overrides decide.
    fn unfilled(_: &str, _: Option<&str>) -> bool {
        false
    }

    fn group_error(key: &str, group: &str) -> ValidationError {
        error(
            key,
            ValidationErrorKind::GroupViolation {
                group: group.to_owned(),
                mode: crate::VarGroupMode::ExactlyOne,
            },
        )
    }

    #[test]
    fn a_group_rule_an_override_broke_is_blamed_on_it_for_every_member() {
        let unset = names(&["PRIMARY"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("PRIMARY", "team"), ("OTHER", "x")]),
            layer(&HashMap::new(), &unset),
            false,
        );
        let errors = [
            group_error("PRIMARY", "database"),
            group_error("FALLBACK", "database"),
            group_error("A", "unrelated"),
            group_error("B", "unrelated"),
        ];
        assert_eq!(
            origins.attribute(
                &errors,
                &map(&[("OTHER", "x")]),
                layer(&HashMap::new(), &unset),
                unfilled
            ),
            [true, true, false, false]
        );
    }

    #[test]
    fn an_override_that_leaves_a_members_presence_alone_never_breaks_its_group() {
        let set = map(&[("PRIMARY", "mine")]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("PRIMARY", "team")]),
            layer(&set, &[]),
            false,
        );
        let errors = [
            group_error("PRIMARY", "database"),
            group_error("FALLBACK", "database"),
        ];
        assert_eq!(
            origins.attribute(
                &errors,
                &map(&[("PRIMARY", "mine")]),
                layer(&set, &[]),
                unfilled
            ),
            [false, false]
        );
    }

    fn all_or_none(key: &str, group: &str) -> ValidationError {
        error(
            key,
            ValidationErrorKind::GroupViolation {
                group: group.to_owned(),
                mode: crate::VarGroupMode::AllOrNone,
            },
        )
    }

    #[test]
    fn each_error_of_one_key_is_blamed_on_its_own() {
        let set = map(&[("PORT", "not-a-port")]);
        let origins = PersonalOverrideOrigins::changing(&HashMap::new(), layer(&set, &[]), false);
        let vars = map(&[("PORT", "not-a-port")]);
        let errors = [
            error(
                "PORT",
                ValidationErrorKind::ConstraintViolation { constraint: "port" },
            ),
            all_or_none("PORT", "network"),
            all_or_none("HOST", "network"),
        ];
        assert_eq!(
            origins.attribute(&errors, &vars, layer(&set, &[]), unfilled),
            [true, true, true]
        );
        let empty = PersonalOverrideOrigins::default();
        assert_eq!(
            empty.attribute(&errors, &vars, layer(&set, &[]), unfilled),
            [false, false, false]
        );
    }

    #[test]
    fn a_group_that_failed_before_the_overrides_is_never_blamed_on_them() {
        let set = map(&[("B", "mine")]);
        let origins =
            PersonalOverrideOrigins::changing(&map(&[("A", "team")]), layer(&set, &[]), false);
        let errors = [
            all_or_none("A", "three"),
            all_or_none("B", "three"),
            all_or_none("C", "three"),
        ];
        assert_eq!(
            origins.attribute(
                &errors,
                &map(&[("A", "team"), ("B", "mine")]),
                layer(&set, &[]),
                unfilled
            ),
            [false, false, false],
            "one of three present before, two now: broken both ways"
        );
    }

    #[test]
    fn a_member_an_override_decides_counts_what_evaluation_would_have_given_it() {
        let set = map(&[("ABSENT", "mine"), ("EMPTY", "mine")]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("EMPTY", ""), ("OTHER", "")]),
            layer(&set, &[]),
            false,
        );
        let errors = [
            all_or_none("ABSENT", "three"),
            all_or_none("EMPTY", "three"),
            all_or_none("OTHER", "three"),
        ];
        let vars = map(&[("ABSENT", "mine"), ("EMPTY", "mine"), ("OTHER", "")]);
        let asked = std::cell::RefCell::new(Vec::new());
        let filled = |name: &str, before: Option<&str>| {
            asked
                .borrow_mut()
                .push((name.to_owned(), before.map(str::to_owned)));
            true
        };

        assert_eq!(
            origins.attribute(&errors, &vars, layer(&set, &[]), filled),
            [false, false, false],
            "two of three before and now"
        );
        let mut asked = asked.into_inner();
        asked.sort_unstable();
        asked.dedup();
        assert_eq!(
            asked,
            [
                ("ABSENT".to_owned(), None),
                ("EMPTY".to_owned(), Some(String::new()))
            ],
            "only members an override decides"
        );
        assert_eq!(
            origins.attribute(&errors, &vars, layer(&set, &[]), unfilled),
            [true, true, true],
            "none of three before, two now"
        );
    }

    #[test]
    fn a_member_a_default_fills_again_after_an_unset_keeps_the_group_as_it_was() {
        let unset = names(&["A"]);
        let origins = PersonalOverrideOrigins::changing(
            &map(&[("A", "team"), ("B", "team")]),
            layer(&HashMap::new(), &unset),
            false,
        );
        let errors = [group_error("A", "auth"), group_error("B", "auth")];
        assert_eq!(
            origins.attribute(
                &errors,
                &map(&[("A", "fallback"), ("B", "team")]),
                layer(&HashMap::new(), &unset),
                unfilled
            ),
            [false, false]
        );
    }
}
