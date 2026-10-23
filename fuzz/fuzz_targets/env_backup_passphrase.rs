#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(passphrase) = lpm_env_backup::Passphrase::new(data) {
        let _ = passphrase.strength();
    }
});
