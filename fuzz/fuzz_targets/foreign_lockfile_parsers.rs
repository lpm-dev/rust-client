#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };

    let _ = lpm_migrate::npm::parse_snapshot(content);
    let _ = lpm_migrate::pnpm::parse_str(content);
    let _ = lpm_migrate::yarn::parse_str(content);
    let _ = lpm_migrate::bun::parse_json_str(content);
});
