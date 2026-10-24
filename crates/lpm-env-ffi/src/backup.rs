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
    refusal(
        "backup.invalid_contents",
        json!({ "reason": error.kind.code(), "offset": error.offset }),
    )
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
/// Callers refuse lengths over their limits first, which keeps every length
/// here far below `isize::MAX`.
///
/// # Safety
/// A non-null pointer must reference `length` readable bytes for the call.
unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        Some(&[])
    } else if pointer.is_null() || length > isize::MAX as usize {
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
    if length > MAX_INPUT_BYTES {
        return passphrase_refusal(PassphraseError::TooLong);
    }
    // SAFETY: Forwarded from this function's contract; the length is bounded above.
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
        // A buffer of exactly the phrase's length, so release wipes all of it.
        Ok(phrase) => result(0, Box::<[u8]>::from(phrase.as_bytes()).into_vec(), None),
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
    if payload_length > MAX_PAYLOAD_BYTES {
        return refusal("backup.too_large", Value::Null);
    }
    if passphrase_length > MAX_INPUT_BYTES {
        return passphrase_refusal(PassphraseError::TooLong);
    }
    // SAFETY: Forwarded from this function's contract; the lengths are bounded above.
    let (Some(payload), Some(raw)) = (unsafe { bytes(payload, payload_length) }, unsafe {
        bytes(passphrase, passphrase_length)
    }) else {
        return failure(2, "env.invalid_input");
    };
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
    if length > MAX_FILE_BYTES {
        return refusal("backup.too_large", Value::Null);
    }
    // SAFETY: Forwarded from this function's contract; the length is bounded above.
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

/// The file and raw passphrase an open call was given, or the result that
/// refuses them.
///
/// # Safety
/// Each pointer must reference its length in readable bytes during the call.
unsafe fn open_inputs<'a>(
    file: *const u8,
    file_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
) -> Result<(&'a [u8], &'a [u8]), LPMEnvResult> {
    if file_length > MAX_FILE_BYTES {
        return Err(refusal("backup.too_large", Value::Null));
    }
    if passphrase_length > MAX_INPUT_BYTES {
        return Err(passphrase_refusal(PassphraseError::TooLong));
    }
    // SAFETY: Forwarded from this function's contract; the lengths are bounded above.
    match (unsafe { bytes(file, file_length) }, unsafe {
        bytes(passphrase, passphrase_length)
    }) {
        (Some(file), Some(raw)) => Ok((file, raw)),
        _ => Err(failure(2, "env.invalid_input")),
    }
}

/// Opens `file` with `open` once its header reads as a backup and `raw` as a
/// passphrase, turning a panic into a failure.
fn opening(
    file: &[u8],
    raw: &[u8],
    open: impl FnOnce(&[u8], &Passphrase) -> Result<LPMEnvResult, OpenError>,
) -> LPMEnvResult {
    catch_unwind(AssertUnwindSafe(|| {
        if let Err(error) = lpm_env_backup::inspect(file) {
            return container_refusal(error);
        }
        let passphrase = match Passphrase::new(raw) {
            Ok(passphrase) => passphrase,
            Err(error) => return passphrase_refusal(error),
        };
        match open(file, &passphrase) {
            Ok(result) => result,
            Err(OpenError::Container(error)) => container_refusal(error),
            Err(OpenError::Payload(error)) => payload_refusal(error),
        }
    }))
    .unwrap_or_else(|_| failure(3, "env.engine_panic"))
}

/// # Safety
/// Each pointer must reference its length in readable bytes during the call,
/// and both out-pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lpm_env_backup_open(
    file: *const u8,
    file_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
    payload_offset: *mut usize,
    payload_length: *mut usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let (file, raw) = match unsafe { open_inputs(file, file_length, passphrase, passphrase_length) }
    {
        Ok(inputs) => inputs,
        Err(refused) => return refused,
    };
    if payload_offset.is_null() || payload_length.is_null() {
        return failure(2, "env.invalid_input");
    }
    opening(file, raw, |file, passphrase| {
        let opened = lpm_env_backup::open(file, passphrase)?;
        // The plaintext's allocation is exactly its length, so it becomes
        // the output without a copy, and release wipes it.
        let (mut plaintext, range) = opened.into_plaintext();
        let plaintext = std::mem::take(&mut *plaintext);
        debug_assert_eq!(plaintext.len(), plaintext.capacity());
        // SAFETY: The caller supplies writable out-pointers, checked non-null above.
        unsafe {
            payload_offset.write(range.start);
            payload_length.write(range.len());
        }
        Ok(result(0, plaintext, None))
    })
}

/// # Safety
/// Each pointer must reference its length in readable bytes during the call,
/// and all four out-pointers must be writable.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn lpm_env_backup_open_split(
    file: *const u8,
    file_length: usize,
    passphrase: *const u8,
    passphrase_length: usize,
    payload_offset: *mut usize,
    payload_length: *mut usize,
    keys_offset: *mut usize,
    keys_length: *mut usize,
) -> LPMEnvResult {
    // SAFETY: Forwarded from this function's contract.
    let (file, raw) = match unsafe { open_inputs(file, file_length, passphrase, passphrase_length) }
    {
        Ok(inputs) => inputs,
        Err(refused) => return refused,
    };
    if [payload_offset, payload_length, keys_offset, keys_length]
        .iter()
        .any(|out| out.is_null())
    {
        return failure(2, "env.invalid_input");
    }
    opening(file, raw, |file, passphrase| {
        let split = lpm_env_backup::open_split(file, passphrase)?;
        let (mut plaintext, payload, keys) = split.into_plaintext();
        let plaintext = std::mem::take(&mut *plaintext);
        debug_assert_eq!(plaintext.len(), plaintext.capacity());
        // SAFETY: The caller supplies writable out-pointers, checked non-null above.
        unsafe {
            payload_offset.write(payload.start);
            payload_length.write(payload.len());
            keys_offset.write(keys.start);
            keys_length.write(keys.len());
        }
        Ok(result(0, plaintext, None))
    })
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

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

    /// The result, and the payload's offset and length in its output.
    fn open(file: &[u8], passphrase: &[u8]) -> (Owned, usize, usize) {
        let (mut offset, mut length) = (usize::MAX, usize::MAX);
        // SAFETY: Both slices and both out-values stay live for the synchronous call.
        let result = Owned(unsafe {
            lpm_env_backup_open(
                file.as_ptr(),
                file.len(),
                passphrase.as_ptr(),
                passphrase.len(),
                &mut offset,
                &mut length,
            )
        });
        (result, offset, length)
    }

    /// The result, and the payload's and the keys' ranges in its output.
    fn open_split(file: &[u8], passphrase: &[u8]) -> (Owned, Range<usize>, Range<usize>) {
        let (mut payload_offset, mut payload_length) = (usize::MAX, usize::MAX);
        let (mut keys_offset, mut keys_length) = (usize::MAX, usize::MAX);
        // SAFETY: Both slices and all out-values stay live for the synchronous call.
        let result = Owned(unsafe {
            lpm_env_backup_open_split(
                file.as_ptr(),
                file.len(),
                passphrase.as_ptr(),
                passphrase.len(),
                &mut payload_offset,
                &mut payload_length,
                &mut keys_offset,
                &mut keys_length,
            )
        });
        (
            result,
            payload_offset..payload_offset.wrapping_add(payload_length),
            keys_offset..keys_offset.wrapping_add(keys_length),
        )
    }

    #[test]
    fn opening_split_hands_over_the_payload_without_its_keys_and_their_records() {
        let keyed = br#"{"keys":{"personalRoots":[{"account":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","key":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}]},"createdAt":1761171075,"producer":{"name":"LPM Vault","version":"1.4.0"},"projects":[]}"#;
        let sealed = seal(keyed, PASSPHRASE);
        assert_eq!(sealed.status(), 0);
        let file = sealed.data().to_vec();
        let (opened, payload, keys) = open_split(&file, PASSPHRASE);
        assert_eq!(opened.status(), 0);
        assert_eq!(
            &opened.data()[payload.clone()],
            br#"{"createdAt":1761171075,"producer":{"name":"LPM Vault","version":"1.4.0"},"projects":[]}"#
        );
        assert_eq!(keys.start, payload.end);
        let record = &opened.data()[keys];
        assert_eq!(record.len(), 1 + 32 + 64);
        assert_eq!(record[0], 1);
        assert_eq!(
            record[1..33],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef].repeat(4)
        );
        assert_eq!(&record[33..], [b'a', b'1'].repeat(32));

        let plain = seal(PAYLOAD, PASSPHRASE).data().to_vec();
        let (opened, payload, keys) = open_split(&plain, PASSPHRASE);
        assert_eq!(&opened.data()[payload], PAYLOAD);
        assert!(keys.is_empty());

        let (wrong, ..) = open_split(&file, b"harbor velvet ninety cactus orbit maples");
        assert_eq!(wrong.json()["code"], "backup.wrong_passphrase");
        let mut unused = 0;
        // SAFETY: The file stays live; a null out-pointer is refused before anything is read.
        let refused = Owned(unsafe {
            lpm_env_backup_open_split(
                file.as_ptr(),
                file.len(),
                PASSPHRASE.as_ptr(),
                PASSPHRASE.len(),
                &mut unused,
                &mut unused,
                std::ptr::null_mut(),
                &mut unused,
            )
        });
        assert_eq!(refused.status(), 2);
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
        let (opened, offset, length) = open(&file, PASSPHRASE);
        assert_eq!(opened.status(), 0);
        assert_eq!(&opened.data()[offset..offset + length], PAYLOAD);
        let (wrong, ..) = open(&file, b"harbor velvet ninety cactus orbit maples");
        assert_eq!(wrong.status(), REFUSED);
        assert_eq!(wrong.json()["code"], "backup.wrong_passphrase");
    }

    #[test]
    fn opening_hands_over_the_plaintext_without_copying_its_payload() {
        let file = seal(PAYLOAD, PASSPHRASE).data().to_vec();
        let (opened, offset, length) = open(&file, PASSPHRASE);
        assert_eq!(opened.status(), 0);
        assert_eq!(
            (offset, length),
            (lpm_env_backup::PAYLOAD_OFFSET, PAYLOAD.len())
        );
        // The output is the whole plaintext: the payload's length, the
        // payload and its zero padding, exactly as large as the ciphertext.
        assert_eq!(opened.data().len(), file.len() - 80 - 16);
        assert_eq!(opened.data()[..8], (PAYLOAD.len() as u64).to_be_bytes());
        assert!(
            opened.data()[offset + length..]
                .iter()
                .all(|byte| *byte == 0)
        );
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
            let (opened, ..) = open(&bytes, PASSPHRASE);
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
        assert!(output["offset"].as_u64().is_some());
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
            "size_t *payload_offset, size_t *payload_length);",
            "lpm_env_backup_open_split(const uint8_t *file, size_t file_length,",
            "size_t *keys_offset, size_t *keys_length);",
        ] {
            assert!(header.contains(function), "{function}");
        }
    }

    #[test]
    fn the_wordlists_attribution_ships_beside_the_header() {
        let notice = include_str!("../include/WORDLIST_NOTICE.md");
        for credit in [
            "EFF Large Wordlist for Passphrases",
            "Electronic Frontier Foundation",
            "https://www.eff.org/dice",
            "https://creativecommons.org/licenses/by/3.0/us/",
        ] {
            assert!(notice.contains(credit), "{credit}");
        }
    }

    #[test]
    fn lengths_past_the_limits_are_refused_before_anything_is_read() {
        let byte = [0_u8];
        let pointer = byte.as_ptr();
        // SAFETY: Each length is over its limit, so nothing behind the pointer is read.
        let results = unsafe {
            [
                (
                    lpm_env_backup_check_passphrase(pointer, usize::MAX),
                    "backup.passphrase_too_long",
                ),
                (
                    lpm_env_backup_inspect(pointer, usize::MAX),
                    "backup.too_large",
                ),
                (
                    lpm_env_backup_seal(pointer, usize::MAX, PASSPHRASE.as_ptr(), PASSPHRASE.len()),
                    "backup.too_large",
                ),
                (
                    lpm_env_backup_seal(PAYLOAD.as_ptr(), PAYLOAD.len(), pointer, usize::MAX),
                    "backup.passphrase_too_long",
                ),
                (
                    lpm_env_backup_open(
                        pointer,
                        usize::MAX,
                        PASSPHRASE.as_ptr(),
                        PASSPHRASE.len(),
                        &mut 0,
                        &mut 0,
                    ),
                    "backup.too_large",
                ),
                (
                    lpm_env_backup_open(
                        PAYLOAD.as_ptr(),
                        PAYLOAD.len(),
                        pointer,
                        usize::MAX,
                        &mut 0,
                        &mut 0,
                    ),
                    "backup.passphrase_too_long",
                ),
            ]
        };
        for (result, code) in results {
            let owned = Owned(result);
            assert_eq!(owned.status(), REFUSED);
            assert_eq!(owned.json()["code"], code);
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
                lpm_env_backup_open(
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    std::ptr::null(),
                    1,
                    &mut 0,
                    &mut 0,
                ),
                lpm_env_backup_open(
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    PASSPHRASE.as_ptr(),
                    PASSPHRASE.len(),
                    std::ptr::null_mut(),
                    &mut 0,
                ),
                lpm_env_backup_open(
                    PAYLOAD.as_ptr(),
                    PAYLOAD.len(),
                    PASSPHRASE.as_ptr(),
                    PASSPHRASE.len(),
                    &mut 0,
                    std::ptr::null_mut(),
                ),
            ]
        };
        for result in results {
            let owned = Owned(result);
            assert_eq!(owned.status(), 2);
            assert_eq!(owned.json()["code"], "env.invalid_input");
        }
    }
}
