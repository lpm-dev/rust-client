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
        Ok(()) => {
            assert!(serde_json::from_slice::<serde::de::IgnoredAny>(data).is_ok());
            // Taking the keys out of a valid payload always works, leaves a
            // valid payload without them, and keeps the records in its bytes.
            let mut buffer = data.to_vec();
            let (payload, keys) = lpm_env_backup::payload::take_keys(&mut buffer, 0..data.len())
                .expect("a valid payload's keys can be taken out");
            assert_eq!((payload.start, keys.start), (0, payload.end));
            assert!(keys.end <= data.len());
            let rest = &buffer[payload];
            assert!(lpm_env_backup::payload::validate(rest).is_ok());
            if let Ok(serde_json::Value::Object(fields)) = serde_json::from_slice(rest) {
                assert!(!fields.contains_key("keys"));
            }
        }
        Err(error) if error.kind == PayloadErrorKind::Syntax => {
            assert!(serde_json::from_slice::<serde_json::Value>(data).is_err());
        }
        Err(_) => {}
    }
});
