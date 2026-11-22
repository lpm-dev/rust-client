//! Layer 4 of a project's environment: this computer's personal overrides,
//! and which validation failures they caused. The runner, `lpm env check`
//! and LPM Vault's engine apply them through this one implementation.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::{EnvName, ValidationError, ValidationErrorKind, is_denied_env_var};

/// One environment's personal overrides: values that replace the project's,
/// an empty string included, and names whose project value is removed.
#[derive(Debug, Clone, Copy)]
pub struct PersonalOverrideLayer<'a> {
    pub set: &'a HashMap<String, String>,
    pub unset: &'a [String],
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

/// What the personal overrides decided for one name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Set(String),
    Unset,
}

/// The names whose value the personal overrides still decide, compared as
/// the host compares names. A later layer that writes a name takes it back,
/// so a validation failure names an override only while it's the value's
/// final origin.
#[derive(Debug, Clone, Default)]
pub struct PersonalOverrideOrigins {
    /// Each name as the host compares it, with its spelling.
    decided: HashMap<String, (String, Decision)>,
    case_insensitive: bool,
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
            if !is_denied_env_var(name) && current(name) != Some(value.as_str()) {
                let key = origins.key(name);
                origins
                    .decided
                    .insert(key, (name.clone(), Decision::Set(value.clone())));
            }
        }
        for name in overrides.unset {
            if !is_denied_env_var(name) && current(name).is_some() {
                let key = origins.key(name);
                origins.decided.insert(key, (name.clone(), Decision::Unset));
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

    /// The names of the overrides that change the environment, as they're
    /// spelled, in order.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .decided
            .values()
            .map(|(name, _)| name.as_str())
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

    /// Whether a personal override caused `error` in `vars`: it still decides
    /// the value the schema judged, or its `unset` left the value missing.
    pub fn caused(&self, error: &ValidationError, vars: &HashMap<String, String>) -> bool {
        let Some((_, decision)) = self.decided.get(&self.key(&error.key)) else {
            return false;
        };
        let value = vars.get(&error.key).or_else(|| {
            self.case_insensitive
                .then(|| {
                    vars.iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(&error.key))
                        .map(|(_, value)| value)
                })
                .flatten()
        });
        match decision {
            Decision::Set(set) => value == Some(set),
            Decision::Unset => error.kind == ValidationErrorKind::Missing && value.is_none(),
        }
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
        assert!(origins.caused(&error("PORT", ValidationErrorKind::Missing), &empty));
        let invalid = error(
            "PORT",
            ValidationErrorKind::ConstraintViolation { constraint: "port" },
        );
        assert!(
            !origins.caused(&invalid, &empty),
            "an invalid value came from somewhere the unset didn't"
        );
    }

    #[test]
    fn an_override_is_found_under_the_declared_spelling_where_the_host_ignores_case() {
        let set = map(&[("api_url", "not a url")]);
        let origins = PersonalOverrideOrigins::changing(&HashMap::new(), layer(&set, &[]), true);
        let invalid = error(
            "API_URL",
            ValidationErrorKind::ConstraintViolation { constraint: "url" },
        );
        assert!(origins.caused(&invalid, &map(&[("API_URL", "not a url")])));
        assert!(
            !PersonalOverrideOrigins::changing(&HashMap::new(), layer(&set, &[]), false)
                .caused(&invalid, &map(&[("API_URL", "not a url")]))
        );
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
}
