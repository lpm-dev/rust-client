use std::ffi::OsString;
use std::path::Path;

const TEST_SECURITY_SECRET_HEX: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub(super) fn isolated_security_env_vars(root: &Path) -> Vec<(&'static str, OsString)> {
    vec![
        (
            "LPM_SECURITY_DIR",
            root.join("security").as_os_str().to_owned(),
        ),
        (
            "LPM_TEST_SECURITY_SECRET_HEX",
            OsString::from(TEST_SECURITY_SECRET_HEX),
        ),
    ]
}
