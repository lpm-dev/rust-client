#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    // The payload reader is written by hand: whatever it accepts must be JSON.
    if lpm_env_backup::payload::validate(data).is_ok() {
        assert!(serde_json::from_slice::<serde_json::Value>(data).is_ok());
    }
});
