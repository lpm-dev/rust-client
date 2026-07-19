use std::path::PathBuf;

use lpm_common::LpmError;
use lpm_common::integrity::{HashAlgorithm, Integrity};

use crate::integrity::validate_sha256_hex;
use crate::{PackageStore, STORE_VERSION, is_complete_package_dir};

impl PackageStore {
    /// Content-addressable store path for a remote `Source::Tarball`,
    /// keyed by SRI integrity hash.
    ///
    /// Layout: `~/.lpm/store/v1/tarball/{algo}-{hex}/` where `{algo}`
    /// is `sha1`, `sha256`, or `sha512` and `{hex}` is lowercase hex of the
    /// raw hash bytes. Hex keeps the directory filesystem-safe on
    /// every platform (no `/`, `+`, or `=`).
    ///
    /// The Registry arm uses [`Self::package_dir`] keyed by
    /// `(name, version)`. Both arms share the `STORE_VERSION` root
    /// so a future schema bump moves them together.
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `integrity_sri`
    /// can't be parsed as a canonical SRI string.
    pub fn tarball_store_path(&self, integrity_sri: &str) -> Result<PathBuf, LpmError> {
        let int = Integrity::parse(integrity_sri)?;
        let algo = match int.algorithm {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        };
        let hex: String = int.hash.iter().map(|b| format!("{b:02x}")).collect();
        Ok(self
            .root()
            .join(STORE_VERSION)
            .join("tarball")
            .join(format!("{algo}-{hex}")))
    }

    /// Whether a remote `Source::Tarball` payload is already extracted
    /// at its CAS path. Mirrors [`Self::has_package`] for the Registry
    /// arm.
    pub fn has_tarball(&self, integrity_sri: &str) -> bool {
        match self.tarball_store_path(integrity_sri) {
            Ok(dir) => is_complete_package_dir(&dir),
            Err(_) => false,
        }
    }

    /// Content-addressable store path for a local-file tarball
    /// (`file:./foo.tgz`), keyed by the SHA-256 of the tarball bytes.
    ///
    /// Layout: `~/.lpm/store/v1/tarball-local/sha256-{hex}/`
    ///
    /// Distinct from [`Self::tarball_store_path`] because identity
    /// differs. A remote tarball's identity is the SRI declared in
    /// the manifest (or computed on first fetch); a local tarball
    /// has no manifest-declared integrity so identity is always the
    /// SHA-256 of the bytes. Two different `file:` paths to the same
    /// content dedupe to one CAS slot here.
    ///
    /// `content_sha256_hex` MUST be exactly 64 lowercase hex
    /// characters; returns [`LpmError::InvalidIntegrity`] otherwise.
    pub fn tarball_local_store_path(&self, content_sha256_hex: &str) -> Result<PathBuf, LpmError> {
        validate_sha256_hex(content_sha256_hex)?;
        Ok(self
            .root()
            .join(STORE_VERSION)
            .join("tarball-local")
            .join(format!("sha256-{content_sha256_hex}")))
    }

    /// Whether a local-file tarball payload is already extracted at
    /// its CAS path. Mirrors [`Self::has_tarball`] for the remote arm.
    pub fn has_local_tarball(&self, content_sha256_hex: &str) -> bool {
        match self.tarball_local_store_path(content_sha256_hex) {
            Ok(dir) => is_complete_package_dir(&dir),
            Err(_) => false,
        }
    }

    /// Extract a remote `Source::Tarball` payload into the
    /// content-addressable tarball CAS path keyed by SRI integrity.
    ///
    /// Mirrors [`Self::store_package`] but uses
    /// [`Self::tarball_store_path`] instead of `(name, version)`. All
    /// TOCTOU + integrity + behavioral-analysis machinery is shared
    /// via the private [`Self::store_at_dir`] helper.
    ///
    /// `integrity_sri` MUST be the SRI of `tarball_data` — usually
    /// the value returned by
    /// [`lpm_registry::RegistryClient::download_tarball_with_integrity`].
    /// The caller is responsible for keeping them aligned; this method
    /// does not re-hash (the download already did).
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `integrity_sri`
    /// can't be parsed.
    pub fn store_tarball_at_cas_path(
        &self,
        integrity_sri: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.tarball_store_path(integrity_sri)?;
        // The label appears in tracing/error messages — keep it
        // short. The full SRI is long (sha512 + 88 base64 chars);
        // truncate at the first '-' + 16 chars for readability.
        let label = format!(
            "tarball:{}",
            integrity_sri.chars().take(24).collect::<String>()
        );
        self.store_at_dir_with_integrity(dir, &label, tarball_data, integrity_sri)
    }

    /// Extract a local-file tarball into the content-addressable
    /// `tarball-local` CAS path keyed by content SHA-256.
    ///
    /// Mirrors [`Self::store_tarball_at_cas_path`] but routes through
    /// [`Self::tarball_local_store_path`]. All TOCTOU + integrity +
    /// behavioral-analysis machinery is shared via [`Self::store_at_dir`]
    /// — `.integrity` and `.lpm-security.json` are written in the same
    /// atomic-rename window.
    ///
    /// `content_sha256_hex` MUST be the lowercase-hex SHA-256 of
    /// `tarball_data` — caller's responsibility (same contract as
    /// [`Self::store_tarball_at_cas_path`]).
    ///
    /// Returns [`LpmError::InvalidIntegrity`] if `content_sha256_hex`
    /// fails the validation in [`Self::tarball_local_store_path`].
    pub fn store_local_tarball_at_cas_path(
        &self,
        content_sha256_hex: &str,
        tarball_data: &[u8],
    ) -> Result<PathBuf, LpmError> {
        let dir = self.tarball_local_store_path(content_sha256_hex)?;
        // Truncate to the first 16 hex chars in tracing labels —
        // matching the remote-tarball arm's labelling style. Adds a
        // `local:` prefix so log/error messages disambiguate at a
        // glance from the integrity-keyed remote arm.
        let label = format!(
            "local-tarball:sha256-{}",
            &content_sha256_hex[..16.min(content_sha256_hex.len())]
        );
        self.store_at_dir(dir, &label, tarball_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::create_test_tarball;

    fn sha512_sri(body: &[u8]) -> String {
        Integrity::from_bytes(HashAlgorithm::Sha512, body).to_string()
    }

    fn sha256_sri(body: &[u8]) -> String {
        Integrity::from_bytes(HashAlgorithm::Sha256, body).to_string()
    }

    fn sha256_hex(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(body);
        format!("{:x}", h.finalize())
    }
    #[test]
    fn tarball_store_path_under_versioned_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store.tarball_store_path(&sha512_sri(b"x")).unwrap();
        // Lives under the v1/ root + tarball/ subtree, distinct from
        // the registry arm's `v1/{name}@{version}/` layout.
        let expected_prefix = dir.path().join(STORE_VERSION).join("tarball");
        assert!(
            path.starts_with(&expected_prefix),
            "expected prefix {:?}, got {:?}",
            expected_prefix,
            path,
        );
    }

    #[test]
    fn tarball_store_path_filename_is_filesystem_safe() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store
            .tarball_store_path(&sha512_sri(b"hello world"))
            .unwrap();
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("leaf must be utf-8");
        // No '/', '+', or '=' — those break filesystem semantics
        // or are unsanitary in path components on Windows.
        assert!(!leaf.contains('/'), "got {leaf:?}");
        assert!(!leaf.contains('+'), "got {leaf:?}");
        assert!(!leaf.contains('='), "got {leaf:?}");
        assert!(leaf.starts_with("sha512-"), "got {leaf:?}");
        // sha512-<128 hex chars> = 7 + 128 = 135 chars
        assert_eq!(leaf.len(), 7 + 128, "got {leaf:?}");
        // After the prefix, only hex.
        assert!(leaf[7..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tarball_store_path_distinguishes_algorithms() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let body = b"same content, different algo";
        let p256 = store.tarball_store_path(&sha256_sri(body)).unwrap();
        let p512 = store.tarball_store_path(&sha512_sri(body)).unwrap();
        // Same body, different algorithms → distinct CAS paths so a
        // sha256-declared dep can't accidentally collide with a
        // sha512-declared dep on the same content.
        assert_ne!(p256, p512);
        assert!(
            p256.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sha256-")
        );
        assert!(
            p512.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sha512-")
        );
        // sha256 path = 7 + 64 hex chars
        assert_eq!(p256.file_name().unwrap().to_string_lossy().len(), 7 + 64);
    }

    #[test]
    fn tarball_store_path_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let sri = sha512_sri(b"stable content");
        let p1 = store.tarball_store_path(&sri).unwrap();
        let p2 = store.tarball_store_path(&sri).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn tarball_store_path_distinguishes_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let p1 = store.tarball_store_path(&sha512_sri(b"first")).unwrap();
        let p2 = store.tarball_store_path(&sha512_sri(b"second")).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn tarball_store_path_rejects_invalid_sri() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        // Missing algorithm prefix.
        assert!(store.tarball_store_path("not-a-real-sri").is_err());
        // Unsupported algorithm.
        assert!(store.tarball_store_path("md5-deadbeef").is_err());
        // Non-base64 hash body.
        assert!(store.tarball_store_path("sha512-!!!").is_err());
    }

    #[test]
    fn has_tarball_returns_false_when_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_tarball(&sha512_sri(b"never stored")));
    }

    #[test]
    fn has_tarball_returns_false_for_invalid_sri() {
        // Mirrors has_package: invalid input → false (don't propagate
        // an error from a query method that callers expect to be
        // total).
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_tarball("not-a-real-sri"));
    }

    // ── store_tarball_at_cas_path ───────────────────────────────────────────

    #[test]
    fn store_tarball_at_cas_path_extracts_to_cas_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            ("package.json", b"{\"name\":\"foo\",\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 42"),
        ]);
        let sri = sha512_sri(&tarball);

        assert!(!store.has_tarball(&sri));

        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert!(store.has_tarball(&sri));
        // Path equals the public CAS path getter for the same SRI.
        assert_eq!(path, store.tarball_store_path(&sri).unwrap());
        // Files extracted into the CAS dir.
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_writes_integrity_file() {
        // Same .integrity post-extraction contract as store_package
        // (the shared store_at_dir helper). Required for
        // `store verify --deep` to detect post-extraction tampering.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha256_sri(&tarball);
        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert_eq!(
            std::fs::read_to_string(path.join(".integrity")).unwrap(),
            sri
        );
    }

    #[test]
    fn store_tarball_at_cas_path_runs_security_analysis() {
        // .lpm-security.json must be present at extraction time so
        // the install path's security gate has the analysis cache
        // ready before linking.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);
        let path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert!(path.join(".lpm-security.json").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);

        let path1 = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        let mtime1 = std::fs::metadata(path1.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();

        // Second call must hit the existing CAS dir and skip
        // extraction. We verify by mtime — a re-extract would
        // bump the package.json mtime.
        let path2 = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();
        assert_eq!(path1, path2);
        let mtime2 = std::fs::metadata(path2.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime1, mtime2, "second call must not re-extract");
    }

    #[test]
    fn store_tarball_at_cas_path_rejects_invalid_sri() {
        // Mirrors tarball_store_path's contract: parsing failure
        // surfaces as InvalidIntegrity rather than running through
        // extraction.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        assert!(
            store
                .store_tarball_at_cas_path("not-a-real-sri", &tarball)
                .is_err()
        );
    }

    #[test]
    fn store_tarball_at_cas_path_distinct_content_distinct_paths() {
        // Two different tarballs (different content) get distinct
        // CAS slots, preserving identity correctness.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball_a = create_test_tarball(&[("a.js", b"alpha")]);
        let tarball_b = create_test_tarball(&[("b.js", b"beta")]);
        let sri_a = sha512_sri(&tarball_a);
        let sri_b = sha512_sri(&tarball_b);
        assert_ne!(sri_a, sri_b);

        let path_a = store.store_tarball_at_cas_path(&sri_a, &tarball_a).unwrap();
        let path_b = store.store_tarball_at_cas_path(&sri_b, &tarball_b).unwrap();
        assert_ne!(path_a, path_b);
        assert!(path_a.join("a.js").exists());
        assert!(path_b.join("b.js").exists());
        // No leakage either way.
        assert!(!path_a.join("b.js").exists());
        assert!(!path_b.join("a.js").exists());
    }

    #[test]
    fn store_tarball_at_cas_path_does_not_collide_with_registry_arm() {
        // The Registry arm uses `v1/{name}@{version}/` and the
        // Tarball arm uses `v1/tarball/{algo}-{hex}/` — two distinct
        // subtrees under the shared STORE_VERSION root. This identity
        // protection: a registry package and a tarball-source
        // package with the same content never share a slot.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let sri = sha512_sri(&tarball);

        let registry_path = store.store_package("foo", "1.0.0", &tarball).unwrap();
        let tarball_path = store.store_tarball_at_cas_path(&sri, &tarball).unwrap();

        assert_ne!(registry_path, tarball_path);
        // Both exist independently (no co-location).
        assert!(registry_path.exists());
        assert!(tarball_path.exists());
    }

    // ── Local tarball CAS path ──────────────────────────────────────────────

    #[test]
    fn tarball_local_store_path_under_versioned_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store.tarball_local_store_path(&sha256_hex(b"x")).unwrap();
        // Lives under v1/tarball-local/, distinct from both the
        // Registry arm (`v1/{name}@{version}/`) and the remote-tarball
        // arm (`v1/tarball/{algo}-{hex}/`). Carving a parallel subtree
        // under the shared v1 root keeps a future schema bump atomic
        // across all source kinds.
        let expected_prefix = dir.path().join(STORE_VERSION).join("tarball-local");
        assert!(
            path.starts_with(&expected_prefix),
            "expected prefix {:?}, got {:?}",
            expected_prefix,
            path,
        );
    }

    #[test]
    fn tarball_local_store_path_filename_is_filesystem_safe() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let path = store
            .tarball_local_store_path(&sha256_hex(b"hello"))
            .unwrap();
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("leaf must be utf-8");
        assert!(leaf.starts_with("sha256-"), "got {leaf:?}");
        // sha256-<64 hex chars> = 7 + 64 = 71 chars
        assert_eq!(leaf.len(), 7 + 64, "got {leaf:?}");
        assert!(leaf[7..].chars().all(|c| c.is_ascii_hexdigit()));
        // Lowercase only (uppercase would fork dedupe).
        assert!(leaf[7..].chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn tarball_local_store_path_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let hex = sha256_hex(b"stable content");
        let p1 = store.tarball_local_store_path(&hex).unwrap();
        let p2 = store.tarball_local_store_path(&hex).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn tarball_local_store_path_distinguishes_content() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let p1 = store
            .tarball_local_store_path(&sha256_hex(b"first"))
            .unwrap();
        let p2 = store
            .tarball_local_store_path(&sha256_hex(b"second"))
            .unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn tarball_local_store_path_rejects_invalid_input() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        // Wrong length (63 chars).
        assert!(
            store
                .tarball_local_store_path(
                    "deadbeef00000000000000000000000000000000000000000000000000000000"[..63]
                        .as_ref(),
                )
                .is_err()
        );
        // Wrong length (65 chars).
        assert!(
            store
                .tarball_local_store_path(
                    "deadbeef000000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // Uppercase hex (would fork dedupe).
        assert!(
            store
                .tarball_local_store_path(
                    "DEADBEEF00000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // Non-hex characters.
        assert!(
            store
                .tarball_local_store_path(
                    "zzzzzzzz00000000000000000000000000000000000000000000000000000000",
                )
                .is_err()
        );
        // SRI shape (not raw hex) — sha256-<base64> would slip past a
        // length check; assert the strict-hex validator catches it.
        assert!(
            store
                .tarball_local_store_path("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",)
                .is_err()
        );
    }

    #[test]
    fn tarball_local_does_not_collide_with_remote_tarball_arm() {
        // Remote tarball CAS: `v1/tarball/{algo}-{hex}/`.
        // Local tarball CAS: `v1/tarball-local/sha256-{hex}/`.
        // Distinct subtrees: a remote SHA-256-keyed tarball and a
        // local tarball with bytes that hash to the same SHA-256 land
        // in different slots. Local tarball
        // identity is content-only (no URL); remote tarball identity
        // includes the URL via `Source::Tarball { url }`. Sharing a
        // CAS slot would let `lpm update` silently swap one for the
        // other.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let body = b"identical bytes";
        let remote = store.tarball_store_path(&sha256_sri(body)).unwrap();
        let local = store.tarball_local_store_path(&sha256_hex(body)).unwrap();
        assert_ne!(remote, local);
        assert!(
            remote
                .ancestors()
                .any(|p| p.file_name().is_some_and(|n| n == "tarball")),
            "remote tarball must live under v1/tarball/, got {remote:?}",
        );
        assert!(
            local
                .ancestors()
                .any(|p| p.file_name().is_some_and(|n| n == "tarball-local")),
            "local tarball must live under v1/tarball-local/, got {local:?}",
        );
    }

    #[test]
    fn has_local_tarball_returns_false_when_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_local_tarball(&sha256_hex(b"never stored")));
    }

    #[test]
    fn has_local_tarball_returns_false_for_invalid_hex() {
        // Mirrors has_tarball: invalid input → false (don't propagate
        // an error from a query method that callers expect to be
        // total).
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        assert!(!store.has_local_tarball("not-a-real-hex"));
    }

    // ── store_local_tarball_at_cas_path ─────────────────────────────────────

    #[test]
    fn store_local_tarball_at_cas_path_extracts_to_cas_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[
            (
                "package.json",
                b"{\"name\":\"local-foo\",\"version\":\"1.0.0\"}",
            ),
            ("index.js", b"module.exports = 42"),
        ]);
        let hex = sha256_hex(&tarball);

        assert!(!store.has_local_tarball(&hex));

        let path = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert!(store.has_local_tarball(&hex));
        assert_eq!(path, store.tarball_local_store_path(&hex).unwrap());
        assert!(path.join("package.json").exists());
        assert!(path.join("index.js").exists());
    }

    #[test]
    fn store_local_tarball_at_cas_path_writes_integrity_and_security() {
        // Same .integrity and .lpm-security.json post-extraction
        // contract as the registry/remote-tarball arms — shared via
        // the private store_at_dir helper.
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let hex = sha256_hex(&tarball);
        let path = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert!(path.join(".integrity").exists());
        assert!(path.join(".lpm-security.json").exists());
    }

    #[test]
    fn store_local_tarball_at_cas_path_cache_hit_skips_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        let hex = sha256_hex(&tarball);

        let path1 = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        let mtime1 = std::fs::metadata(path1.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        let path2 = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert_eq!(path1, path2);
        let mtime2 = std::fs::metadata(path2.join("package.json"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime1, mtime2, "second call must not re-extract");
    }

    #[test]
    fn store_local_tarball_at_cas_path_rejects_invalid_hex() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[("package.json", b"{}")]);
        assert!(
            store
                .store_local_tarball_at_cas_path("not-a-real-hex", &tarball)
                .is_err()
        );
    }

    #[test]
    fn store_local_tarball_at_cas_path_dedupes_same_content() {
        // Two consumers using `file:./a.tgz` and `file:../shared/a.tgz`
        // of the same bytes share one extracted store dir — the
        // content-keyed CAS contract. (Identity is content-only
        // for local tarballs; the URL/path is not part of the key.)
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());
        let tarball = create_test_tarball(&[(
            "package.json",
            b"{\"name\":\"shared\",\"version\":\"1.0.0\"}",
        )]);
        let hex = sha256_hex(&tarball);

        // Consumer A extracts.
        let path_a = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        // Consumer B with the same bytes from a different file: path
        // hits the same CAS slot. (Caller-supplied hex is the key —
        // the path it came from never enters the helper.)
        let path_b = store
            .store_local_tarball_at_cas_path(&hex, &tarball)
            .unwrap();
        assert_eq!(path_a, path_b);
    }
}
