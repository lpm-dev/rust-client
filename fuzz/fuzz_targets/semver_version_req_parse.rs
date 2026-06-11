#![no_main]

use libfuzzer_sys::fuzz_target;
use lpm_semver::{Version, VersionReq};

const PROBE_VERSIONS: &[&str] = &[
    "0.0.0",
    "0.0.1-alpha",
    "1.0.0",
    "1.2.3",
    "2.0.0-rc.1",
    "999.999.999",
];

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(req) = VersionReq::parse(input) else {
        return;
    };

    let _ = req.original();
    let _ = req.to_string();
    let _ = req == req.clone();

    for version in PROBE_VERSIONS {
        if let Ok(parsed) = Version::parse(version) {
            let _ = req.matches(&parsed);
        }
    }
});
