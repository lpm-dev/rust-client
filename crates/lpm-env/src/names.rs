use crate::EnvSchema;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

/// An environment variable name compared the way Windows compares them, for
/// hosts where process environment names ignore case.
#[derive(Eq)]
pub struct EnvName(Vec<u16>);

impl EnvName {
    pub fn new(name: &str) -> Self {
        #[cfg(windows)]
        let name = name.encode_utf16().collect();
        // The insensitive policy is exercised on other hosts by unit tests.
        #[cfg(not(windows))]
        let name = name.to_uppercase().encode_utf16().collect();
        Self(name)
    }
}

impl PartialEq for EnvName {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for EnvName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EnvName {
    fn cmp(&self, other: &Self) -> Ordering {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Globalization::{
                CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
            };
            if let (Ok(left_len), Ok(right_len)) =
                (i32::try_from(self.0.len()), i32::try_from(other.0.len()))
            {
                // Match the comparison used by std::process::Command for
                // Windows environment keys, including non-ASCII names.
                // SAFETY: both pointers reference initialized UTF-16 buffers
                // for the exact lengths passed to the read-only API.
                match unsafe {
                    CompareStringOrdinal(self.0.as_ptr(), left_len, other.0.as_ptr(), right_len, 1)
                } {
                    CSTR_LESS_THAN => return Ordering::Less,
                    CSTR_EQUAL => return Ordering::Equal,
                    CSTR_GREATER_THAN => return Ordering::Greater,
                    _ => {}
                }
            }
        }
        self.0.cmp(&other.0)
    }
}

/// Two names that differ only in case, where the host compares them without case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasingConflict {
    /// Two declared keys.
    Declared(String),
    /// Two values.
    Stored(String),
}

impl std::fmt::Display for CasingConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Declared(key) => {
                write!(
                    f,
                    "ambiguous environment schema variable casing for '{key}'"
                )
            }
            Self::Stored(key) => write!(f, "ambiguous environment variable casing for '{key}'"),
        }
    }
}

impl std::error::Error for CasingConflict {}

/// Gives each value whose name matches a declared key without case the
/// declared spelling, as a process sees it on a host that compares names
/// without case. Returns the declared keys by their caseless names.
pub fn align_declared_casing<'a>(
    vars: &mut HashMap<String, String>,
    schema: &'a EnvSchema,
) -> Result<BTreeMap<EnvName, &'a str>, CasingConflict> {
    let mut declared = BTreeMap::new();
    for key in schema.vars.keys() {
        if declared.insert(EnvName::new(key), key.as_str()).is_some() {
            return Err(CasingConflict::Declared(key.clone()));
        }
    }
    let mut stored = BTreeMap::new();
    for key in vars.keys() {
        if stored.insert(EnvName::new(key), key.clone()).is_some() {
            return Err(CasingConflict::Stored(key.clone()));
        }
    }
    for key in schema.vars.keys() {
        if let Some(existing) = stored.get(&EnvName::new(key))
            && existing != key
            && let Some(value) = vars.remove(existing)
        {
            vars.insert(key.clone(), value);
        }
    }
    Ok(declared)
}

#[cfg(test)]
mod casing_tests {
    use super::*;

    #[test]
    fn values_take_the_declared_spelling_and_ambiguous_names_fail() {
        let schema: EnvSchema = serde_json::from_str(r#"{"vars":{"PORT":{}}}"#).unwrap();
        let mut vars = HashMap::from([("port".to_owned(), "1".to_owned())]);
        let declared = align_declared_casing(&mut vars, &schema).unwrap();
        assert_eq!(vars, HashMap::from([("PORT".to_owned(), "1".to_owned())]));
        assert_eq!(declared.get(&EnvName::new("Port")), Some(&"PORT"));

        let mut ambiguous = HashMap::from([
            ("PORT".to_owned(), "1".to_owned()),
            ("port".to_owned(), "2".to_owned()),
        ]);
        assert!(matches!(
            align_declared_casing(&mut ambiguous, &schema),
            Err(CasingConflict::Stored(_))
        ));
        let duplicate: EnvSchema =
            serde_json::from_str(r#"{"vars":{"PORT":{},"port":{}}}"#).unwrap();
        assert!(matches!(
            align_declared_casing(&mut HashMap::new(), &duplicate),
            Err(CasingConflict::Declared(_))
        ));
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn environment_name_comparison_matches_process_command() {
        for (left, right) in [("É_VAR", "é_var"), ("ß_VAR", "SS_VAR"), ("ı_VAR", "I_VAR")] {
            let mut command = std::process::Command::new("unused");
            command.env(left, "first").env(right, "last");
            assert_eq!(
                EnvName::new(left) == EnvName::new(right),
                command.get_envs().count() == 1,
                "{left} and {right}"
            );
        }
    }
}
