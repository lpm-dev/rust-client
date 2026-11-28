//! An error that forgets its value leaves none of it in freed memory. Its own
//! test binary, since the probe replaces the global allocator.

#[cfg(not(miri))]
#[path = "../../lpm-vault/src/freed_memory_probe.rs"]
mod freed_memory_probe;

#[cfg(not(miri))]
#[test]
fn an_error_that_forgets_its_value_wipes_it() {
    for kind in [
        lpm_env::ValidationErrorKind::InvalidFormat {
            expected: lpm_env::VarFormat::Url,
            got: freed_memory_probe::MARKER.to_owned(),
        },
        lpm_env::ValidationErrorKind::NotInEnum {
            got: freed_memory_probe::MARKER.to_owned(),
            allowed: vec!["a".to_owned()],
        },
    ] {
        let mut error = lpm_env::ValidationError {
            key: "API_URL".to_owned(),
            kind,
            description: None,
            is_secret: false,
        };
        let ((), left) = freed_memory_probe::watch(|| error.forget_value());
        assert!(!left, "{error}");
        assert!(!error.to_string().contains(freed_memory_probe::MARKER));
    }
}
