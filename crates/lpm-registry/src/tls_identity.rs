//! mTLS client identity loading. Phase 58.3.
//!
//! Translates `.npmrc`-derived `(certfile, keyfile)` paths into a
//! [`reqwest::Identity`] that the per-origin client builder can attach
//! to a [`reqwest::ClientBuilder`].
//!
//! ## What this module does
//!
//! 1. Reads both files from disk, citing source/line on IO errors.
//! 2. Detects encrypted PKCS#8 keys (`-----BEGIN ENCRYPTED PRIVATE
//!    KEY-----` PEM header) and decrypts them via the [`pkcs8`] crate
//!    (RustCrypto, no openssl). Passphrase resolution order:
//!    1. `LPM_KEY_PASSPHRASE` env var (CI / non-interactive).
//!    2. TTY prompt via [`rpassword`], gated on **both** stdin AND
//!       stdout being terminals (matches `install_global.rs` precedent).
//!    3. Hard error citing the keyfile line.
//! 3. Detects PKCS#12 (`.p12`/`.pfx`) input and emits a cited error
//!    with the `openssl` conversion recipe — rustls cannot ingest
//!    PKCS#12 and we deliberately don't pull in `native-tls`.
//! 4. Concatenates `<unencrypted-key-pem><cert-pem>` and feeds to
//!    [`reqwest::Identity::from_pem`].
//!
//! ## What this module does NOT do
//!
//! - Build the per-origin client. That's [`crate::client`]'s job
//!   (Phase 58.3 / T3); this module is the loader seam.
//! - Validate per-origin XOR pairs. The caller in T3 checks
//!   `cert.is_some() == key.is_some()` for the specific origin
//!   being built; this module assumes both are present.
//! - Cache identities. Identities are reusable but the loader is
//!   called rarely (once per per-origin client, eager or lazy);
//!   the [`PassphraseCache`] memoizes the *passphrase*, not the
//!   parsed identity, since cert/key files can change between
//!   eager and lazy builds in the same process.

use lpm_common::error::LpmError;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::npmrc::TaggedPath;

/// Env var consulted before any TTY prompt for a keyfile passphrase.
/// Single-value for v1 (one passphrase shared across all encrypted
/// keys this invocation needs). Multi-key invocations with distinct
/// passphrases are out of v1 scope — see Phase 58.3 plan doc.
pub const KEY_PASSPHRASE_ENV: &str = "LPM_KEY_PASSPHRASE";

/// PEM marker for encrypted PKCS#8 keys. Matches what `openssl
/// genpkey -aes256` and `openssl pkcs8 -topk8` produce.
const ENCRYPTED_PKCS8_HEADER: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

/// PEM markers for unencrypted private keys that `Identity::from_pem`
/// accepts directly. PKCS#8 (`PRIVATE KEY`), PKCS#1 RSA (`RSA
/// PRIVATE KEY`), and SEC1 EC (`EC PRIVATE KEY`).
const PEM_KEY_HEADERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
];

/// PEM marker for *encrypted* PKCS#1 RSA keys (`Proc-Type: 4,ENCRYPTED`
/// header inside an RSA PRIVATE KEY block). Older format; not handled
/// by the [`pkcs8`] crate. Surfaced as a cited error directing the
/// user to convert.
const LEGACY_RSA_ENCRYPTED_TAG: &str = "Proc-Type: 4,ENCRYPTED";

/// Whether a byte slice looks like a PKCS#12 binary archive. PKCS#12
/// uses ASN.1 DER (`30 82 …` SEQUENCE) — the leading bytes are never
/// printable ASCII, which lets us distinguish from PEM cleanly.
fn looks_like_pkcs12(bytes: &[u8]) -> bool {
    // Heuristic: PEM is ASCII (markers + base64). PKCS#12 starts with
    // ASN.1 SEQUENCE tag 0x30 followed by a length byte. Non-ASCII at
    // byte 0 is a strong signal for binary.
    bytes.first().copied() == Some(0x30) && !bytes.iter().take(64).all(|b| b.is_ascii())
}

/// Provider for keyfile passphrases. Production uses
/// [`EnvThenTtyPassphrase`]; tests inject a deterministic stub.
pub trait PassphraseProvider {
    /// Return the passphrase for the given keyfile, or an
    /// [`LpmError::Cert`] citing why one couldn't be obtained.
    fn for_keyfile(&mut self, key: &TaggedPath) -> Result<SecretString, LpmError>;
}

/// Production passphrase provider: env first, then TTY prompt
/// (gated on `is_terminal(stdin) && is_terminal(stdout)`), else
/// hard error.
///
/// **JSON-mode skip.** When `disable_prompt` is set (e.g., the CLI is
/// running with `--json` or some other non-interactive flow), the TTY
/// branch is bypassed and the loader fails with a cited error
/// instructing the user to set `LPM_KEY_PASSPHRASE`. This avoids
/// blocking on a prompt when stdout is being parsed by an agent.
pub struct EnvThenTtyPassphrase {
    cache: PassphraseCache,
    disable_prompt: bool,
}

impl EnvThenTtyPassphrase {
    /// Build a provider that may prompt on the TTY when both stdin
    /// and stdout are terminals.
    pub fn new() -> Self {
        Self {
            cache: PassphraseCache::default(),
            disable_prompt: false,
        }
    }

    /// Build a provider that never prompts (e.g., `--json` flows).
    /// Falls back to env-only; missing env → cited error.
    pub fn new_no_prompt() -> Self {
        Self {
            cache: PassphraseCache::default(),
            disable_prompt: true,
        }
    }
}

impl Default for EnvThenTtyPassphrase {
    fn default() -> Self {
        Self::new()
    }
}

impl PassphraseProvider for EnvThenTtyPassphrase {
    fn for_keyfile(&mut self, key: &TaggedPath) -> Result<SecretString, LpmError> {
        // Cache lookup (process-lifetime memoize, keyed by absolute
        // keyfile path). Resolves the same encrypted key being loaded
        // for both metadata and tarball clients without re-prompting.
        let canonical = std::fs::canonicalize(&key.path).unwrap_or_else(|_| key.path.clone());
        if let Some(pp) = self.cache.get(&canonical) {
            return Ok(pp);
        }

        // Tier 1: env var.
        if let Ok(val) = std::env::var(KEY_PASSPHRASE_ENV)
            && !val.is_empty()
        {
            let pp = SecretString::from(val);
            self.cache.insert(canonical, pp.clone());
            return Ok(pp);
        }

        // Tier 2: TTY prompt (both stdin and stdout must be terminals,
        // and `--json`-equivalent must not have disabled prompting).
        if !self.disable_prompt
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
        {
            let raw = rpassword::prompt_password(format!(
                "Enter passphrase for keyfile {} (configured at {}:{}): ",
                key.path.display(),
                key.source,
                key.line
            ))
            .map_err(|e| {
                LpmError::Cert(format!(
                    "{}:{}: failed to read passphrase from TTY: {e}",
                    key.source, key.line
                ))
            })?;
            if raw.is_empty() {
                return Err(LpmError::Cert(format!(
                    "{}:{}: empty passphrase entered for encrypted keyfile {}",
                    key.source,
                    key.line,
                    key.path.display()
                )));
            }
            let pp = SecretString::from(raw);
            self.cache.insert(canonical, pp.clone());
            return Ok(pp);
        }

        // Tier 3: hard error.
        Err(LpmError::Cert(format!(
            "{}:{}: keyfile {} is encrypted but no passphrase is available; \
             set the {} environment variable or run interactively with both \
             stdin and stdout connected to a terminal",
            key.source,
            key.line,
            key.path.display(),
            KEY_PASSPHRASE_ENV
        )))
    }
}

/// Process-lifetime cache of resolved passphrases, keyed by canonical
/// keyfile path. Lifetime-scoped to the [`EnvThenTtyPassphrase`]
/// instance (which lives as long as the [`crate::client::RegistryClient`]
/// it backs). Secrets are zeroized when the cache drops.
#[derive(Default)]
pub struct PassphraseCache {
    inner: Mutex<HashMap<PathBuf, SecretString>>,
}

impl PassphraseCache {
    fn get(&self, key: &Path) -> Option<SecretString> {
        self.inner.lock().ok()?.get(key).cloned()
    }

    fn insert(&self, key: PathBuf, value: SecretString) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key, value);
        }
    }
}

/// Load a [`reqwest::Identity`] from a `(certfile, keyfile)` pair.
///
/// Failure modes (all surfaced as [`LpmError::Cert`] citing the
/// contributing source/line):
///
/// - Either file unreadable.
/// - Cert file is empty / contains no PEM CERTIFICATE block.
/// - Key file is PKCS#12 (binary) — emits the openssl conversion recipe.
/// - Key file is PKCS#1 RSA with `Proc-Type: 4,ENCRYPTED` (legacy
///   encrypted RSA) — emits a cited error directing the user to
///   convert via `openssl pkcs8 -topk8 -in legacy.key -out new.pem`.
/// - Key file is encrypted PKCS#8 and passphrase resolution fails.
/// - Key file is encrypted PKCS#8 and decryption fails (wrong passphrase).
/// - The concatenated (key + cert) bundle fails [`reqwest::Identity::from_pem`].
pub fn load_identity(
    cert: &TaggedPath,
    key: &TaggedPath,
    passphrase: &mut dyn PassphraseProvider,
) -> Result<reqwest::Identity, LpmError> {
    let cert_bytes = std::fs::read(&cert.path).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: failed to read certfile {}: {e}",
            cert.source,
            cert.line,
            cert.path.display()
        ))
    })?;
    let key_bytes = std::fs::read(&key.path).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: failed to read keyfile {}: {e}",
            key.source,
            key.line,
            key.path.display()
        ))
    })?;

    // PKCS#12 detection — informative cited error, not a generic
    // "rustls failed to parse." Catches both .p12 and .pfx file
    // shapes since both are PKCS#12 wire format.
    if looks_like_pkcs12(&key_bytes) {
        return Err(LpmError::Cert(format!(
            "{}:{}: keyfile {} looks like PKCS#12 (.p12/.pfx). \
             lpm uses rustls, which accepts PEM-encoded cert chains plus an \
             unencrypted PKCS#8 / PKCS#1 / SEC1 private key. Convert with:\n\
             \n  openssl pkcs12 -in <file>.pfx -clcerts -nokeys -out cert.pem\n\
             \n  openssl pkcs12 -in <file>.pfx -nocerts -nodes  -out key.pem\n\
             \nThen point certfile= at cert.pem and keyfile= at key.pem.",
            key.source,
            key.line,
            key.path.display()
        )));
    }
    if looks_like_pkcs12(&cert_bytes) {
        // Standalone recipe — a user whose certfile is PKCS#12 may not
        // also have a PKCS#12 keyfile, so don't refer them to a
        // sibling error that may not exist.
        return Err(LpmError::Cert(format!(
            "{}:{}: certfile {} looks like PKCS#12 (.p12/.pfx). \
             lpm uses rustls, which requires a PEM-encoded cert chain at certfile=. \
             Convert with:\n\
             \n  openssl pkcs12 -in <file>.pfx -clcerts -nokeys -out cert.pem\n\
             \nThen point certfile= at cert.pem (and if your keyfile is also \
             PKCS#12, extract it separately with `-nocerts -nodes -out key.pem`).",
            cert.source,
            cert.line,
            cert.path.display()
        )));
    }

    // Cert sanity — must be PEM with at least one CERTIFICATE block.
    let cert_text = std::str::from_utf8(&cert_bytes).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: certfile {} is not valid UTF-8 (PEM expected): {e}",
            cert.source,
            cert.line,
            cert.path.display()
        ))
    })?;
    if !cert_text.contains("-----BEGIN CERTIFICATE-----") {
        return Err(LpmError::Cert(format!(
            "{}:{}: certfile {} contains no '-----BEGIN CERTIFICATE-----' block",
            cert.source,
            cert.line,
            cert.path.display()
        )));
    }

    // Key shape detection — encrypted-PKCS#8 / unencrypted / legacy.
    let key_text = std::str::from_utf8(&key_bytes).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: keyfile {} is not valid UTF-8 (PEM expected): {e}",
            key.source,
            key.line,
            key.path.display()
        ))
    })?;

    // Reject legacy encrypted RSA (`Proc-Type: 4,ENCRYPTED` header)
    // explicitly — the pkcs8 crate doesn't decrypt those, and a silent
    // "rustls couldn't parse" would be opaque.
    if key_text.contains(LEGACY_RSA_ENCRYPTED_TAG) {
        return Err(LpmError::Cert(format!(
            "{}:{}: keyfile {} is encrypted using the legacy PKCS#1 \
             format (Proc-Type: 4,ENCRYPTED header). lpm requires \
             encrypted PKCS#8. Convert with:\n\
             \n  openssl pkcs8 -topk8 -in <legacy>.key -out key.pem\n\
             \nThen point keyfile= at the new key.pem.",
            key.source,
            key.line,
            key.path.display()
        )));
    }

    let unencrypted_key_pem: String = if key_text.contains(ENCRYPTED_PKCS8_HEADER) {
        decrypt_pkcs8(key_text, key, passphrase)?
    } else if PEM_KEY_HEADERS.iter().any(|m| key_text.contains(m)) {
        // Already unencrypted — feed verbatim.
        key_text.to_string()
    } else {
        return Err(LpmError::Cert(format!(
            "{}:{}: keyfile {} contains no recognized PEM private-key block \
             ('PRIVATE KEY' / 'RSA PRIVATE KEY' / 'EC PRIVATE KEY' / \
             'ENCRYPTED PRIVATE KEY')",
            key.source,
            key.line,
            key.path.display()
        )));
    };

    // Concat: key first, then cert chain. `Identity::from_pem` accepts
    // both orderings, but key-first is the more common convention.
    let mut bundle = unencrypted_key_pem.into_bytes();
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(&cert_bytes);

    reqwest::Identity::from_pem(&bundle).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{} + {}:{}: failed to build TLS identity from cert+key: {e}",
            cert.source, cert.line, key.source, key.line
        ))
    })
}

/// Decrypt an encrypted PKCS#8 PEM block using the supplied passphrase
/// provider. Returns the unencrypted PKCS#8 PEM ready for
/// [`reqwest::Identity::from_pem`].
///
/// Pulled out of [`load_identity`] so the encrypted-key flow is one
/// readable function — and so tests can call it directly with a
/// deterministic [`PassphraseProvider`] stub.
fn decrypt_pkcs8(
    pem_text: &str,
    key_meta: &TaggedPath,
    passphrase: &mut dyn PassphraseProvider,
) -> Result<String, LpmError> {
    use pkcs8::EncryptedPrivateKeyInfo;
    use pkcs8::der::Decode;
    use pkcs8::der::pem::PemLabel;

    // Extract the base64 body from the PEM.
    let (label, der) = pkcs8::der::pem::decode_vec(pem_text.as_bytes()).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: failed to decode encrypted PKCS#8 PEM body: {e}",
            key_meta.source, key_meta.line
        ))
    })?;
    if label != EncryptedPrivateKeyInfo::PEM_LABEL {
        return Err(LpmError::Cert(format!(
            "{}:{}: expected '{}' PEM label, got '{label}'",
            key_meta.source,
            key_meta.line,
            EncryptedPrivateKeyInfo::PEM_LABEL,
        )));
    }
    let info = EncryptedPrivateKeyInfo::from_der(&der).map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: encrypted PKCS#8 DER is malformed: {e}",
            key_meta.source, key_meta.line
        ))
    })?;

    // Resolve passphrase (env → TTY → cached).
    let pp = passphrase.for_keyfile(key_meta)?;
    let plaintext = info
        .decrypt(pp.expose_secret().as_bytes())
        .map_err(|e| {
            LpmError::Cert(format!(
                "{}:{}: encrypted PKCS#8 decryption failed (wrong passphrase?): {e}",
                key_meta.source, key_meta.line
            ))
        })?;

    // Re-encode as unencrypted PKCS#8 PEM.
    let der_bytes = plaintext.as_bytes();
    let pem = pkcs8::der::pem::encode_string(
        "PRIVATE KEY",
        pkcs8::der::pem::LineEnding::LF,
        der_bytes,
    )
    .map_err(|e| {
        LpmError::Cert(format!(
            "{}:{}: failed to re-encode decrypted PKCS#8 as PEM: {e}",
            key_meta.source, key_meta.line
        ))
    })?;
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tempfile::TempDir;

    /// Test stub: returns a fixed passphrase, panics if asked twice
    /// when `expect_one_call` is set (verifies passphrase memoization
    /// when paired with a real `PassphraseCache`).
    struct FixedPassphrase {
        pp: SecretString,
        calls: RefCell<usize>,
    }

    impl FixedPassphrase {
        fn new(pp: &str) -> Self {
            Self {
                pp: SecretString::from(pp.to_string()),
                calls: RefCell::new(0),
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.borrow()
        }
    }

    impl PassphraseProvider for FixedPassphrase {
        fn for_keyfile(&mut self, _key: &TaggedPath) -> Result<SecretString, LpmError> {
            *self.calls.borrow_mut() += 1;
            Ok(self.pp.clone())
        }
    }

    /// Stub that always errors — exercises the no-passphrase path.
    struct NoPassphrase;

    impl PassphraseProvider for NoPassphrase {
        fn for_keyfile(&mut self, key: &TaggedPath) -> Result<SecretString, LpmError> {
            Err(LpmError::Cert(format!(
                "{}:{}: stub: no passphrase available",
                key.source, key.line
            )))
        }
    }

    /// Generate a self-signed leaf cert with rcgen (sync API).
    /// Returns (cert_pem, unencrypted_pkcs8_key_pem).
    fn gen_rsa_pair() -> (String, String) {
        // rcgen 0.13 emits PKCS#8 ("PRIVATE KEY") PEM for the keypair
        // by default — exactly what `Identity::from_pem` accepts.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("rcgen self-sign");
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).expect("write fixture");
        p
    }

    fn tagged(path: PathBuf) -> TaggedPath {
        TaggedPath {
            path,
            source: "test:.npmrc".into(),
            line: 1,
        }
    }

    #[test]
    fn unencrypted_pem_pair_loads() {
        let (cert_pem, key_pem) = gen_rsa_pair();
        let dir = TempDir::new().unwrap();
        let cert = tagged(write(dir.path(), "cert.pem", &cert_pem));
        let key = tagged(write(dir.path(), "key.pem", &key_pem));
        let mut pp = NoPassphrase;
        load_identity(&cert, &key, &mut pp).expect("identity ok");
    }

    #[test]
    fn pkcs12_certfile_returns_standalone_cited_error_with_recipe() {
        // Finding 3 (GPT pre-T3 audit): when certfile is PKCS#12 but
        // keyfile is PEM, the error must include the conversion
        // recipe inline — referring the user to a "keyfile error"
        // that doesn't exist is self-contradictory.
        let dir = TempDir::new().unwrap();
        let (_, key_pem) = gen_rsa_pair();
        let cert_path = dir.path().join("cert.pfx");
        std::fs::write(&cert_path, [0x30u8, 0x82, 0x04, 0x00, 0xff, 0xfe, 0xfd]).unwrap();
        let cert = tagged(cert_path);
        let key = tagged(write(dir.path(), "key.pem", &key_pem));
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("PKCS#12"), "msg: {msg}");
                // Self-contained recipe — must NOT punt to a sibling error.
                assert!(msg.contains("openssl pkcs12"), "msg: {msg}");
                assert!(
                    !msg.contains("noted in the keyfile error"),
                    "must not refer to nonexistent sibling error: {msg}"
                );
                assert!(msg.contains("test:.npmrc:1"), "msg: {msg}");
            }
            other => panic!("expected Cert error with standalone recipe, got: {other:?}"),
        }
    }

    #[test]
    fn pkcs12_keyfile_returns_cited_error_with_recipe() {
        // PKCS#12 is binary DER; the heuristic is "starts with 0x30
        // and is not pure ASCII." Synthesize a minimal byte sequence
        // that satisfies that.
        let dir = TempDir::new().unwrap();
        let cert_path = write(dir.path(), "cert.pem", "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n");
        let key_path = dir.path().join("key.pfx");
        // Real-ish PKCS#12 prefix: SEQUENCE tag + length + non-ASCII body.
        std::fs::write(&key_path, [0x30u8, 0x82, 0x04, 0x00, 0xff, 0xfe, 0xfd]).unwrap();
        let cert = tagged(cert_path);
        let key = tagged(key_path);
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("PKCS#12"), "msg: {msg}");
                assert!(msg.contains("openssl pkcs12"), "msg: {msg}");
                assert!(msg.contains("test:.npmrc:1"), "msg: {msg}");
            }
            other => panic!("expected Cert error with recipe, got: {other:?}"),
        }
    }

    #[test]
    fn legacy_rsa_encrypted_returns_cited_conversion_recipe() {
        let dir = TempDir::new().unwrap();
        let (cert_pem, _) = gen_rsa_pair();
        let cert = tagged(write(dir.path(), "cert.pem", &cert_pem));
        let legacy_key = "-----BEGIN RSA PRIVATE KEY-----\n\
                          Proc-Type: 4,ENCRYPTED\n\
                          DEK-Info: AES-256-CBC,abc\n\
                          \n\
                          deadbeef\n\
                          -----END RSA PRIVATE KEY-----\n";
        let key = tagged(write(dir.path(), "key.pem", legacy_key));
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("legacy PKCS#1"), "msg: {msg}");
                assert!(msg.contains("openssl pkcs8 -topk8"), "msg: {msg}");
                assert!(msg.contains("test:.npmrc:1"), "msg: {msg}");
            }
            other => panic!("expected legacy-encrypted error, got: {other:?}"),
        }
    }

    #[test]
    fn unrecognized_pem_block_in_keyfile_returns_cited_error() {
        let dir = TempDir::new().unwrap();
        let (cert_pem, _) = gen_rsa_pair();
        let cert = tagged(write(dir.path(), "cert.pem", &cert_pem));
        let bogus = "-----BEGIN SOMETHING ELSE-----\nbody\n-----END SOMETHING ELSE-----\n";
        let key = tagged(write(dir.path(), "key.pem", bogus));
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("no recognized PEM private-key"), "msg: {msg}");
            }
            other => panic!("expected unrecognized-PEM error, got: {other:?}"),
        }
    }

    #[test]
    fn certfile_with_no_certificate_block_returns_cited_error() {
        let dir = TempDir::new().unwrap();
        let (_, key_pem) = gen_rsa_pair();
        let cert = tagged(write(dir.path(), "cert.pem", "this is not pem"));
        let key = tagged(write(dir.path(), "key.pem", &key_pem));
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("BEGIN CERTIFICATE"), "msg: {msg}");
            }
            other => panic!("expected no-cert-block error, got: {other:?}"),
        }
    }

    #[test]
    fn missing_certfile_returns_cited_error() {
        let dir = TempDir::new().unwrap();
        let (_, key_pem) = gen_rsa_pair();
        let cert = tagged(dir.path().join("does-not-exist.pem"));
        let key = tagged(write(dir.path(), "key.pem", &key_pem));
        let mut pp = NoPassphrase;
        match load_identity(&cert, &key, &mut pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("failed to read certfile"), "msg: {msg}");
                assert!(msg.contains("test:.npmrc:1"), "msg: {msg}");
            }
            other => panic!("expected missing-certfile error, got: {other:?}"),
        }
    }

    /// Generate a real encrypted PKCS#8 key + cert pair via the
    /// `pkcs8` crate's public encrypt API. Round-trips through
    /// `load_identity` to prove the decryption path works end-to-end.
    #[test]
    fn encrypted_pkcs8_round_trips_with_correct_passphrase() {
        use pkcs8::EncryptedPrivateKeyInfo;
        use pkcs8::PrivateKeyInfo;
        use pkcs8::der::Decode;
        use pkcs8::der::pem::PemLabel;

        let (cert_pem, key_pem) = gen_rsa_pair();

        // Parse the unencrypted PKCS#8 PEM, encrypt with a known
        // passphrase using the crate's public encrypt API. This
        // matches what `openssl pkcs8 -topk8` produces.
        let (label, plain_der) =
            pkcs8::der::pem::decode_vec(key_pem.as_bytes()).expect("decode key pem");
        assert_eq!(
            label, "PRIVATE KEY",
            "rcgen 0.13 must emit PKCS#8 PEM (got label '{label}')"
        );
        let plain_info = PrivateKeyInfo::try_from(plain_der.as_slice()).expect("parse pkcs8 info");

        // Use the rng-backed `encrypt` (scrypt + AES-256-CBC by
        // default). The exact ciphertext varies per run; that's
        // fine — we test the round-trip, not byte-equality.
        let mut rng = rand::thread_rng();
        let passphrase = "correct horse battery staple";
        let encrypted_doc = plain_info
            .encrypt(&mut rng, passphrase.as_bytes())
            .expect("encrypt pkcs8");
        let encrypted_pem = pkcs8::der::pem::encode_string(
            EncryptedPrivateKeyInfo::PEM_LABEL,
            pkcs8::der::pem::LineEnding::LF,
            encrypted_doc.as_bytes(),
        )
        .expect("encode encrypted pem");

        // Sanity: the encrypted DER round-trips through our parser.
        let _info =
            EncryptedPrivateKeyInfo::from_der(encrypted_doc.as_bytes()).expect("decode info");

        let dir = TempDir::new().unwrap();
        let cert = tagged(write(dir.path(), "cert.pem", &cert_pem));
        let key = tagged(write(dir.path(), "key.pem", &encrypted_pem));

        // Correct passphrase → identity loads.
        let mut good_pp = FixedPassphrase::new(passphrase);
        load_identity(&cert, &key, &mut good_pp).expect("decryption ok");
        assert_eq!(good_pp.call_count(), 1);

        // Wrong passphrase → cited decryption error.
        let mut bad_pp = FixedPassphrase::new("nope");
        match load_identity(&cert, &key, &mut bad_pp) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("decryption failed"), "msg: {msg}");
                assert!(msg.contains("test:.npmrc:1"), "msg: {msg}");
            }
            other => panic!("expected decryption error, got: {other:?}"),
        }
    }

    #[test]
    fn passphrase_cache_memoizes_per_canonical_path() {
        let cache = PassphraseCache::default();
        let path = PathBuf::from("/tmp/some-key.pem");
        cache.insert(path.clone(), SecretString::from("secret".to_string()));
        let got = cache.get(&path).expect("cache hit");
        assert_eq!(got.expose_secret(), "secret");
        assert!(cache.get(Path::new("/tmp/other-key.pem")).is_none());
    }

    /// Serialize env-mutation across the two tiers exercised here.
    /// Without this guard, `cargo test` (which parallelizes by default)
    /// races `set_var` from one test against `remove_var` in another.
    /// One test == one acquire == zero races.
    static ENV_PASSPHRASE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// **Single test** for both env tiers — env-set resolves; env-unset +
    /// no-prompt fails with cited error.
    ///
    /// Keeping these two tiers in one `#[test]` is intentional. Earlier
    /// drafts had them as two separate `#[test]`s, but `cargo test` runs
    /// the file in parallel by default, and the `set_var` / `remove_var`
    /// operations on `LPM_KEY_PASSPHRASE` raced — one test would see the
    /// other's mid-flight state and false-fail under a normal
    /// `cargo test -p lpm-registry` (caught in GPT's pre-T3 audit).
    /// Combining the assertions into one serially-executed test
    /// removes the race entirely.
    #[test]
    fn env_then_tty_provider_env_tiers() {
        // Hold the env guard for the full body — `cargo test` may have
        // OTHER tests in this module that touch the same env var (none
        // today, but the guard is the cheap defensive contract). A
        // poisoned mutex doesn't matter for test isolation; recover.
        let _guard = ENV_PASSPHRASE_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Tier 1: env set → resolves to env value.
        // SAFETY: env mutation is serialized by the guard above.
        unsafe {
            std::env::set_var(KEY_PASSPHRASE_ENV, "from-env");
        }
        let mut provider = EnvThenTtyPassphrase::new_no_prompt();
        let got = provider
            .for_keyfile(&TaggedPath {
                path: PathBuf::from("/nonexistent"),
                source: "test".into(),
                line: 1,
            })
            .expect("env tier resolves");
        assert_eq!(got.expose_secret(), "from-env");

        // Tier 3: env unset + no-prompt → cited error citing the env var.
        // Build a fresh provider so the in-process passphrase cache from
        // Tier 1 doesn't short-circuit the lookup.
        unsafe {
            std::env::remove_var(KEY_PASSPHRASE_ENV);
        }
        let mut provider = EnvThenTtyPassphrase::new_no_prompt();
        match provider.for_keyfile(&TaggedPath {
            path: PathBuf::from("/nonexistent"),
            source: "test:.npmrc".into(),
            line: 9,
        }) {
            Err(LpmError::Cert(msg)) => {
                assert!(msg.contains("test:.npmrc:9"), "msg: {msg}");
                assert!(msg.contains(KEY_PASSPHRASE_ENV), "msg: {msg}");
            }
            other => panic!("expected hard error, got: {other:?}"),
        }
    }
}
