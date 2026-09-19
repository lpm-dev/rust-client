use std::cmp::Ordering;

#[derive(Eq)]
pub(super) struct EnvName(Vec<u16>);

impl EnvName {
    pub(super) fn new(name: &str) -> Self {
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
