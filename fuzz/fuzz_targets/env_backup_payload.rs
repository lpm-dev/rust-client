#![no_main]

use libfuzzer_sys::fuzz_target;
use lpm_env_backup::payload::PayloadErrorKind;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    // The payload reader is written by hand: whatever it accepts must be JSON,
    // and whatever it calls malformed must not be. IgnoredAny checks syntax
    // without bounding numbers, which the reader allows up to the largest
    // finite double; Value also refuses lone surrogates, as the reader does.
    match lpm_env_backup::payload::validate(data) {
        Ok(()) => assert!(serde_json::from_slice::<serde::de::IgnoredAny>(data).is_ok()),
        Err(error) if error.kind == PayloadErrorKind::Syntax => {
            assert!(serde_json::from_slice::<serde_json::Value>(data).is_err());
        }
        Err(_) => {}
    }
});
