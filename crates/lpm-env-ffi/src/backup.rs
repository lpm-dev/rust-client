//! Backup files: passphrases, sealing and opening, through `lpm-env-backup`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use lpm_env_backup::passphrase::{self, MAX_INPUT_BYTES};
use lpm_env_backup::{
    ContainerError, MAX_FILE_BYTES, MAX_PAYLOAD_BYTES, OpenError, Passphrase, PassphraseError,
    PayloadError, SealError,
};
use serde_json::{Value, json};

use crate::{ABI_VERSION, LPMEnvResult, failure, result};

const REFUSED: u32 = 5;

/// A result holding a copy of `secret` in a buffer of exactly its length,
/// so release wipes all of it and no larger allocation is left behind.
fn secret_result(secret: &[u8]) -> LPMEnvResult {
    result(0, Box::<[u8]>::from(secret).into_vec(), None)
}

fn refusal(code: &str, details: Value) -> LPMEnvResult {
    let mut output = json!({ "abiVersion": ABI_VERSION, "code": code });
    if let (Some(output), Value::Object(details)) = (output.as_object_mut(), details) {
        output.extend(details);
    }
    result(
        REFUSED,
        serde_json::to_vec(&output).unwrap_or_default(),
        None,
    )
}

fn passphrase_refusal(error: PassphraseError) -> LPMEnvResult {
    let code = match error {
        PassphraseError::Empty => "backup.passphrase_empty",
        PassphraseError::NotUtf8 => "backup.passphrase_not_utf8",
        PassphraseError::TooLong => "backup.passphrase_too_long",
    };
    refusal(code, Value::Null)
}

fn payload_refusal(error: PayloadError) -> LPMEnvResult {
    let mut details = json!({ "reason": error.kind.code() });
    if let Some((line, column)) = error.position {
        details["line"] = json!(line);
        details["column"] = json!(column);
    }
    refusal("backup.invalid_contents", details)
}

fn container_refusal(error: ContainerError) -> LPMEnvResult {
    match error {
        ContainerError::TooLarge => refusal("backup.too_large", Value::Null),
        ContainerError::NotABackup => refusal("backup.not_a_backup", Value::Null),
        ContainerError::NewerFormat { format_version } => refusal(
            "backup.newer_format",
            json!({ "formatVersion": format_version }),
        ),
        ContainerError::Damaged => refusal("backup.damaged", Value::Null),
        ContainerError::WrongPassphrase => refusal("backup.wrong_passphrase", Value::Null),
        ContainerError::InvalidPlaintext => {
            refusal("backup.invalid_contents", json!({ "reason": "layout" }))
        }
        ContainerError::OutOfMemory => failure(3, "backup.out_of_memory"),
        ContainerError::Random => failure(3, "backup.random_failed"),
    }
}

/// A borrowed range, or `None` for a null pointer with a nonzero length.
///
/// # Safety
/// A non-null pointer must reference `length` readable bytes for the call.
unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        Some(&[])
    } else if pointer.is_null() {
        None
    } else {
        // SAFETY: The caller supplies a live readable range of `length` bytes.
        Some(unsafe { std::slice::from_raw_parts(pointer, length) })
    }
}

/// # Safety
/// The pointer must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_backup_check_passphrase(
    passphrase: *const u8,
    length: usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let Some(raw) = (unsafe { bytes(passphrase, length) }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| match Passphrase::new(raw) {
        Ok(passphrase) => {
            let strength = passphrase.strength();
            let output = json!({
                "abiVersion": ABI_VERSION,
                "acceptable": strength.acceptable,
                "guessesLog10": strength.guesses_log10,
                "minimumGuessesLog10": passphrase::MIN_GUESSES_LOG10,
            });
            result(0, serde_json::to_vec(&output).unwrap_or_default(), None)
        }
        Err(error) => passphrase_refusal(error),
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

#[unsafe(no_mangle)]
pub extern "C" fn lpm_env_backup_generate_passphrase() -> LPMEnvResult {
    catch_unwind(AssertUnwindSafe(|| match passphrase::generate() {
        Ok(phrase) => secret_result(phrase.as_bytes()),
        Err(_) => failure(3, "backup.random_failed"),
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// Each pointer must reference its length in readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_backup_seal(
    payload: *const u8,
    payload_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let (Some(payload), Some(raw)) = (unsafe { bytes(payload, payload_length) }, unsafe {
        bytes(passphrase, passphrase_length)
    }) else {
        return failure(2, "env.invalid_input");
    };
    if payload.len() > MAX_PAYLOAD_BYTES {
        return refusal("backup.too_large", Value::Null);
    }
    catch_unwind(AssertUnwindSafe(|| {
        let passphrase = match Passphrase::new(raw) {
            Ok(passphrase) => passphrase,
            Err(error) => return passphrase_refusal(error),
        };
        match lpm_env_backup::seal(payload, &passphrase) {
            Ok(file) => result(0, file, None),
            Err(SealError::WeakPassphrase(strength)) => refusal(
                "backup.passphrase_weak",
                json!({ "guessesLog10": strength.guesses_log10 }),
            ),
            Err(SealError::Payload(error)) => payload_refusal(error),
            Err(SealError::Container(error)) => container_refusal(error),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// The pointer must reference `length` readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_backup_inspect(file: *const u8, length: usize) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let Some(file) = (unsafe { bytes(file, length) }) else {
        return failure(2, "env.invalid_input");
    };
    catch_unwind(AssertUnwindSafe(|| match lpm_env_backup::inspect(file) {
        Ok(info) => {
            let output = json!({ "abiVersion": ABI_VERSION, "formatVersion": info.format_version });
            result(0, serde_json::to_vec(&output).unwrap_or_default(), None)
        }
        Err(error) => container_refusal(error),
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// Each pointer must reference its length in readable bytes during the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_backup_open(
    file: *const u8,
    file_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let (Some(file), Some(raw)) = (unsafe { bytes(file, file_length) }, unsafe {
        bytes(passphrase, passphrase_length)
    }) else {
        return failure(2, "env.invalid_input");
    };
    if file.len() > MAX_FILE_BYTES {
        return refusal("backup.too_large", Value::Null);
    }
    if raw.len() > MAX_INPUT_BYTES {
        return passphrase_refusal(PassphraseError::TooLong);
    }
    catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = lpm_env_backup::inspect(file) {
            return container_refusal(error);
        }
        let passphrase = match Passphrase::new(raw) {
            Ok(passphrase) => passphrase,
            Err(error) => return passphrase_refusal(error),
        };
        match lpm_env_backup::open(file, &passphrase) {
            Ok(payload) => secret_result(&payload),
            Err(OpenError::Container(error)) => container_refusal(error),
            Err(OpenError::Payload(error)) => payload_refusal(error),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lpm_env_release;

    const PASSPHRASE: &[u8] = b"harbor velvet ninety cactus orbit maple";
    const PAYLOAD: &[u8] = br#"{"createdAt":1761171075,"producer":{"name":"LPM Vault","version":"1.4.0"},"deviceName":"Studio","projects":[{"vaultId":"v1","name":"demo","folder":"/Users/me/demo","hidden":false,"cliAccess":"requireApproval","environments":{"default":{"API_KEY":"sk_test_value"}}}],"app":{"settings":{}}}"#;

    struct Owned(LPMEnvResult);

    impl Owned {
        fn status(&self) -> u32 {
            self.0.status
        }

        fn data(&self) -> &[u8] {
            if self.0.data.is_null() {
                return &[];
            }
            // SAFETY: The result stays owned and unreleased while borrowed.
            unsafe { std::slice::from_raw_parts(self.0.data, self.0.length) }
        }

        fn json(&self) -> Value {
            serde_json::from_slice(self.data()).expect("JSON output")
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            let released = LPMEnvResult {
                status: self.0.status,
                data: std::mem::replace(&mut self.0.data, std::ptr::null_mut()),
                length: self.0.length,
                snapshot: std::ptr::null_mut(),
            };
            // SAFETY: Each result is released exactly once, here.
            unsafe { lpm_env_release(released) };
        }
    }

    fn seal(payload: &[u8], passphrase: &[u8]) -> Owned {
        // SAFETY: Both slices stay live for the synchronous call.
        Owned(unsafe {
            lpm_env_backup_seal(
                payload.as_ptr(),
                payload.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            )
        })
    }

    fn open(file: &[u8], passphrase: &[u8]) -> Owned {
        // SAFETY: Both slices stay live for the synchronous call.
        Owned(unsafe {
            lpm_env_backup_open(
                file.as_ptr(),
                file.len(),
                passphrase.as_ptr(),
                passphrase.len(),
            )
        })
    }

    fn inspect(file: &[u8]) -> Owned {
        // SAFETY: The slice stays live for the synchronous call.
        Owned(unsafe { lpm_env_backup_inspect(file.as_ptr(), file.len()) })
    }

    fn check(passphrase: &[u8]) -> Owned {
        // SAFETY: The slice stays live for the synchronous call.
        Owned(unsafe { lpm_env_backup_check_passphrase(passphrase.as_ptr(), passphrase.len()) })
    }

    #[test]
    fn a_sealed_backup_opens_to_the_same_payload_with_profile_one() {
        let sealed = seal(PAYLOAD, PASSPHRASE);
        assert_eq!(sealed.status(), 0);
        let file = sealed.data().to_vec();
        assert_eq!(&file[..12], b"LPMBKUP\0\0\x01\x01\x01");
        let opened = open(&file, PASSPHRASE);
        assert_eq!(opened.status(), 0);
        assert_eq!(opened.data(), PAYLOAD);
        let wrong = open(&file, b"harbor velvet ninety cactus orbit maples");
        assert_eq!(wrong.status(), REFUSED);
        assert_eq!(wrong.json()["code"], "backup.wrong_passphrase");
    }

    #[test]
    fn inspection_reads_the_header_and_refuses_what_isnt_a_backup() {
        let file = seal(PAYLOAD, PASSPHRASE).data().to_vec();
        let info = inspect(&file);
        assert_eq!(info.status(), 0);
        assert_eq!(info.json(), json!({ "abiVersion": 1, "formatVersion": 1 }));
        let mut newer = file.clone();
        newer[9] = 2;
        assert_eq!(inspect(&newer).json()["formatVersion"], 2);
        for (bytes, code) in [
            (b"not a backup".to_vec(), "backup.not_a_backup"),
            (file[..100].to_vec(), "backup.damaged"),
            (newer, "backup.newer_format"),
        ] {
            let refused = inspect(&bytes);
            assert_eq!(refused.status(), REFUSED);
            assert_eq!(refused.json()["code"], code);
            let opened = open(&bytes, PASSPHRASE);
            assert_eq!(
                opened.json()["code"],
                code,
                "open refuses before deriving a key"
            );
        }
    }

    #[test]
    fn sealing_reports_weak_passphrases_and_invalid_contents_by_code() {
        let weak = seal(PAYLOAD, b"password123");
        assert_eq!(weak.status(), REFUSED);
        assert_eq!(weak.json()["code"], "backup.passphrase_weak");
        assert!(weak.json()["guessesLog10"].as_f64().expect("number") < 18.1);

        let secret_misplaced = br#"{"createdAt":0,"producer":{"name":"a","version":"1"},"projects":[{"vaultId":"v","name":"n","hidden":false,"cliAccess":"automatic","environments":{"default":"sk_live_do_not_echo"}}]}"#;
        let invalid = seal(secret_misplaced, PASSPHRASE);
        assert_eq!(invalid.status(), REFUSED);
        let output = invalid.json();
        assert_eq!(output["code"], "backup.invalid_contents");
        assert_eq!(output["reason"], "structure");
        assert!(output["line"].as_u64().is_some() && output["column"].as_u64().is_some());
        assert!(!String::from_utf8_lossy(invalid.data()).contains("sk_live"));

        for (passphrase, code) in [
            (&b""[..], "backup.passphrase_empty"),
            (&b"\xff"[..], "backup.passphrase_not_utf8"),
            (
                &[b'a'; MAX_INPUT_BYTES + 1][..],
                "backup.passphrase_too_long",
            ),
        ] {
            assert_eq!(seal(PAYLOAD, passphrase).json()["code"], code);
        }
        let too_large = vec![b' '; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            seal(&too_large, PASSPHRASE).json()["code"],
            "backup.too_large"
        );
    }

    #[test]
    fn passphrase_checks_report_the_estimate_and_the_floor() {
        let weak = check(b"password");
        assert_eq!(weak.status(), 0);
        assert_eq!(weak.json()["acceptable"], false);
        assert_eq!(weak.json()["minimumGuessesLog10"], 18.1);
        let strong = check(PASSPHRASE);
        assert_eq!(strong.json()["acceptable"], true);
        assert!(strong.json()["guessesLog10"].as_f64().expect("number") >= 18.1);
        assert_eq!(check(b"").json()["code"], "backup.passphrase_empty");
    }

    #[test]
    fn generated_passphrases_are_six_words_that_seal() {
        let generated = Owned(lpm_env_backup_generate_passphrase());
        assert_eq!(generated.status(), 0);
        let phrase = std::str::from_utf8(generated.data()).expect("UTF-8");
        assert_eq!(phrase.split(' ').count(), 6);
        assert_eq!(check(phrase.as_bytes()).json()["acceptable"], true);
        assert_eq!(generated.0.length, phrase.len());
    }

    #[test]
    fn the_header_declares_every_backup_function_and_the_rust_limits() {
        let header = include_str!("../include/lpm_env.h");
        assert!(header.contains("#define LPM_ENV_BACKUP_FILE_LIMIT (64 * 1024 * 1024)"));
        assert_eq!(MAX_FILE_BYTES, 64 * 1024 * 1024);
        assert!(header.contains("#define LPM_ENV_BACKUP_PASSPHRASE_LIMIT (4 * 1024)"));
        assert_eq!(MAX_INPUT_BYTES, 4 * 1024);
        for function in [
            "lpm_env_backup_check_passphrase(const uint8_t *passphrase, size_t length);",
            "lpm_env_backup_generate_passphrase(void);",
            "lpm_env_backup_seal(const uint8_t *payload, size_t payload_length,",
            "lpm_env_backup_inspect(const uint8_t *file, size_t length);",
            "lpm_env_backup_open(const uint8_t *file, size_t file_length,",
        ] {
            assert!(
                header.contains(&format!("LPMEnvResult {function}")),
                "{function}"
            );
        }
    }

    #[test]
    fn null_pointers_with_a_length_are_invalid_input() {
        // SAFETY: Null pointers with nonzero lengths are refused before any read.
        let results = unsafe {
            [
                lpm_env_backup_check_passphrase(std::ptr::null(), 1),
                lpm_env_backup_inspect(std::ptr::null(), 1),
                lpm_env_backup_seal(std::ptr::null(), 1, PASSPHRASE.as_ptr(), PASSPHRASE.len()),
                lpm_env_backup_open(PAYLOAD.as_ptr(), PAYLOAD.len(), std::ptr::null(), 1),
            ]
        };
        for result in results {
            let owned = Owned(result);
            assert_eq!(owned.status(), 2);
            assert_eq!(owned.json()["code"], "env.invalid_input");
        }
    }
}
