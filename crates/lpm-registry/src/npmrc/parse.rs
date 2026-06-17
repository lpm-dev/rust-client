use super::config::NpmrcConfig;
use super::types::{OriginKey, RegistryTarget, TaggedBool, TaggedPath, TaggedRoot, TaggedValue};
use std::path::{Path, PathBuf};

impl NpmrcConfig {
    /// Parse a single `.npmrc` file's textual content as one layer.
    /// Auth buffers are populated but **not** resolved — call
    /// `finalize()` after merging all layers, or use `parse()` for the
    /// single-file convenience that does both.
    ///
    /// `source_label` is folded into warning/error messages so the user
    /// can tell which file (project / user / system) caused a complaint.
    /// `env_lookup` is injected so tests can pass a fake env without
    /// mutating process state.
    pub fn parse_layer(
        content: &str,
        source_label: &str,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        Self::parse_layer_with_source_dir(content, source_label, None, env_lookup)
    }

    /// Parse a single `.npmrc` layer and tag every TLS path entry with the
    /// source directory.
    ///
    /// `source_dir` is the parent directory of the `.npmrc` file
    /// being parsed. Used by [`TaggedPath::resolve`] to compose
    /// absolute paths from relative `certfile=` / `keyfile=` /
    /// per-origin `cafile=` values. Pass `None` for in-memory tests
    /// or any caller whose source isn't a file on disk.
    ///
    /// Production: [`Self::load_from_paths`] passes
    /// `Some(file_path.parent())` for each layer.
    pub fn parse_layer_with_source_dir(
        content: &str,
        source_label: &str,
        source_dir: Option<&Path>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        Self::parse_layer_with_options(content, source_label, source_dir, false, env_lookup)
    }

    /// Same as [`Self::parse_layer_with_source_dir`] but allows callers
    /// to mark the layer as project-local. A project-local layer is
    /// owned by the repo and may be hostile under a malicious-clone
    /// threat model. Settings that downgrade TLS or use repo-controlled
    /// env expansion for registry/auth/TLS destinations are refused when
    /// sourced from this layer.
    pub fn parse_layer_with_options(
        content: &str,
        source_label: &str,
        source_dir: Option<&Path>,
        is_project_layer: bool,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut cfg = NpmrcConfig::default();

        // Strip leading UTF-8 BOM if present. Some Windows editors save
        // .npmrc with one and npm tolerates it.
        let content = content.strip_prefix('\u{feff}').unwrap_or(content);

        for (lineno, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            let Some(eq_idx) = line.find('=') else {
                cfg.warnings.push(format!(
                    "{}:{}: line has no '=' separator; skipped",
                    source_label,
                    lineno + 1
                ));
                continue;
            };
            let key = line[..eq_idx].trim();
            let raw_value = line[eq_idx + 1..].trim();
            let value = strip_surrounding_quotes(raw_value);

            if is_project_layer
                && contains_env_interpolation(value)
                && project_layer_env_expansion_is_sensitive(key)
            {
                cfg.security_warnings.push(format!(
                    "{source_label}:{}: env expansion in project-local .npmrc for '{key}' refused: \
                     move this registry/auth/TLS setting to user config or use registry-scoped auth",
                    lineno + 1,
                ));
                continue;
            }

            // Env-var interpolation. Missing var is fatal per npm.
            let interpolated = match interpolate_env(value, env_lookup) {
                Ok(s) => s,
                Err(missing) => {
                    cfg.errors.push(format!(
                        "{}:{}: environment variable '${{{}}}' is not set; refusing to use this config",
                        source_label,
                        lineno + 1,
                        missing
                    ));
                    continue;
                }
            };

            classify_and_apply(
                key,
                &interpolated,
                source_label,
                source_dir,
                is_project_layer,
                lineno + 1,
                &mut cfg,
            );
        }

        cfg
    }

    /// Single-file convenience: `parse_layer` then `finalize`. Used by
    /// tests and by callers (like the existing `lpm setup local` helper) that
    /// don't need to compose layers.
    pub fn parse(
        content: &str,
        source_label: &str,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut cfg = Self::parse_layer(content, source_label, env_lookup);
        cfg.finalize();
        cfg
    }
}

/// Strip surrounding single or double quotes from a value, if any.
/// `"foo"` → `foo`, `'foo'` → `foo`. Mismatched quotes left alone.
fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        let last = bytes[s.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn contains_env_interpolation(value: &str) -> bool {
    value.contains("${")
}

fn project_layer_env_expansion_is_sensitive(key: &str) -> bool {
    if matches!(
        key,
        "registry"
            | "cafile"
            | "ca"
            | "certfile"
            | "keyfile"
            | "proxy"
            | "https-proxy"
            | "http-proxy"
            | "noproxy"
            | "no-proxy"
    ) {
        return true;
    }

    if key.starts_with('@') && key.ends_with(":registry") {
        return true;
    }

    let Some(rest) = key.strip_prefix("//") else {
        return false;
    };
    let Some(split_idx) = rest.rfind("/:") else {
        return false;
    };
    let attr = &rest[split_idx + 2..];
    matches!(
        attr,
        "_authToken" | "_auth" | "_password" | "_username" | "cafile" | "certfile" | "keyfile"
    )
}

/// Expand `${VAR}` references in `value`. On the first missing var, return
/// `Err(var_name)` so the caller can surface a fatal parse error matching
/// npm's behavior.
///
/// We only expand `${NAME}` — bare `$NAME` is left as-is, matching npm.
fn interpolate_env(
    value: &str,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    if !value.contains("${") {
        return Ok(value.to_string());
    }
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'{'
            && let Some(rel) = value[i + 2..].find('}')
        {
            let var_name = &value[i + 2..i + 2 + rel];
            match env_lookup(var_name) {
                Some(v) => out.push_str(&v),
                None => return Err(var_name.to_string()),
            }
            i += 2 + rel + 1;
            continue;
        }
        // Advance one Unicode scalar — `value` is &str so `i` is on a
        // valid char boundary on entry to each iteration.
        let ch = value[i..].chars().next().expect("non-empty by loop guard");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Classify a key/value pair and apply it to the config-being-built.
/// All control flow lives here so the parser loop stays readable. Auth
/// subkeys are written into `cfg.auth_buffers` as `TaggedValue`s; they
/// don't get resolved into `RegistryAuth` until `NpmrcConfig::finalize`.
///
/// `source_dir` is the directory of the `.npmrc` file being parsed;
/// when populated, every emitted [`TaggedPath`] carries it so
/// [`TaggedPath::resolve`] can turn relative paths into absolute ones
/// at load time. Test stubs pass `None`.
fn classify_and_apply(
    key: &str,
    value: &str,
    source_label: &str,
    source_dir: Option<&Path>,
    is_project_layer: bool,
    lineno: usize,
    cfg: &mut NpmrcConfig,
) {
    // Scope registry: `@foo:registry`.
    if key.starts_with('@')
        && let Some(scope) = key.strip_suffix(":registry")
    {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty registry URL for scope '{scope}'; skipped"
            ));
            return;
        }
        cfg.scope_registries.insert(
            scope.to_ascii_lowercase(),
            RegistryTarget::from_npmrc_url(value),
        );
        return;
    }

    // Default registry.
    if key == "registry" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty registry URL; skipped"
            ));
            return;
        }
        cfg.default_registry = Some(RegistryTarget::from_npmrc_url(value));
        return;
    }

    // Origin-scoped auth: `//host[:port][/path]/:_<attr>`.
    if let Some(rest) = key.strip_prefix("//") {
        // The auth attribute is the substring after the LAST occurrence
        // of `/:` in the key. Everything before that slash is the
        // (path-aware) URL prefix; we use its origin only in v1.
        if let Some(split_idx) = rest.rfind("/:") {
            let origin_part = &rest[..split_idx]; // host[:port][/path] without trailing slash
            let attr = &rest[split_idx + 2..]; // attribute name after `:`
            let Some(origin) = OriginKey::from_npmrc_origin(origin_part) else {
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: cannot parse origin from auth key '{key}'; skipped"
                ));
                return;
            };
            // Path-scoped credentials cannot be represented safely by the
            // origin-only matcher. For shared-host registries such as GitLab
            // or Artifactory, widening a project-scoped token to the whole
            // origin would over-disclose it to sibling projects. Refuse those
            // credential attrs with a warning; TLS attrs are still materialized
            // because they are not credentials and per-path TLS overrides are
            // uncommon enough that origin-wide application is the better UX.
            let is_credential_attr =
                matches!(attr, "_authToken" | "_auth" | "_password" | "_username");
            if origin_part.contains('/') {
                if is_credential_attr {
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: path-scoped npmrc credential key ('{key}') would \
                         be widened to ALL paths on {origin} (v1 matches by origin only); \
                         refusing to materialize — narrow the host config OR rewrite the key as \
                         `//{origin}/:{attr}` to opt into origin-wide reach."
                    ));
                    return;
                }
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: path-scoped npmrc key ('{key}') is parsed as origin-only in v1; \
                     setting will apply to ALL paths on {origin}"
                ));
            }
            let tagged = TaggedValue::new(value.to_string(), source_label, lineno);
            // Auth subkeys go into the per-origin auth buffer; TLS subkeys
            // go into the per-origin TLS buffer. Two distinct entry maps share
            // the same `OriginKey` so a matching-origin lookup fetches both.
            match attr {
                "_authToken" => {
                    cfg.auth_buffers.entry(origin).or_default().auth_token = Some(tagged);
                }
                "_auth" => {
                    cfg.auth_buffers.entry(origin).or_default().auth_b64 = Some(tagged);
                }
                "_username" => {
                    cfg.auth_buffers.entry(origin).or_default().username = Some(tagged);
                }
                "_password" => {
                    cfg.auth_buffers.entry(origin).or_default().password_b64 = Some(tagged);
                }
                "always-auth" | "email" => {
                    // Silently accepted at origin scope. `always-auth` is
                    // vestigial — modern npm 7+ removed
                    // the per-registry distinction; lpm always sends
                    // matching-origin tokens. `email` is publish-flow
                    // metadata, irrelevant to install routing.
                }
                "cafile" => {
                    // Per-origin extra root. DEFERRED-READ by design: the PEM
                    // is read at client-build time for the matching origin,
                    // NOT at parse time. Unrelated `.npmrc` entries (e.g., a
                    // stale path on a shared `~/.npmrc`) cannot break installs
                    // that never reach the configured origin.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin cafile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls
                        .per_origin
                        .entry(origin)
                        .or_default()
                        .cafiles
                        .push(TaggedPath {
                            path: PathBuf::from(value),
                            source: source_label.to_string(),
                            line: lineno,
                            source_dir: source_dir.map(|p| p.to_path_buf()),
                        });
                }
                "certfile" => {
                    // Per-origin mTLS client cert path. Path-only at parse
                    // time; XOR-pair validation + file read deferred to
                    // client-build time. Configured-but-unreached half-configs
                    // do not abort the install.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin certfile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls.per_origin.entry(origin).or_default().certfile = Some(TaggedPath {
                        path: PathBuf::from(value),
                        source: source_label.to_string(),
                        line: lineno,
                        source_dir: source_dir.map(|p| p.to_path_buf()),
                    });
                }
                "keyfile" => {
                    // Per-origin mTLS private key path.
                    // Same deferred-read contract as `certfile`.
                    if value.is_empty() {
                        cfg.warnings.push(format!(
                            "{source_label}:{lineno}: empty per-origin keyfile path; skipped"
                        ));
                        return;
                    }
                    cfg.tls.per_origin.entry(origin).or_default().keyfile = Some(TaggedPath {
                        path: PathBuf::from(value),
                        source: source_label.to_string(),
                        line: lineno,
                        source_dir: source_dir.map(|p| p.to_path_buf()),
                    });
                }
                _ => {
                    // Unknown attribute on a `//host` key. Silent ignore
                    // matches npm: unknown keys aren't an error.
                }
            }
            return;
        }
        // Malformed: starts with `//` but no `/:` separator.
        cfg.warnings.push(format!(
            "{source_label}:{lineno}: auth key '{key}' has no '/:<attr>' suffix; skipped"
        ));
        return;
    }

    // Globally-scoped TLS settings.
    if key == "cafile" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty cafile path; skipped"
            ));
            return;
        }
        match std::fs::read(value) {
            Ok(bytes) => {
                // No `decode_npmrc_pem_escapes` here — `cafile=<path>` reads
                // the PEM from disk where newlines are real (`\n` bytes),
                // not the escape-encoded `\\n` sequences npm uses for
                // inline `ca=` values on a single `.npmrc` line. The
                // asymmetry is intentional and matches npm.
                if !contains_pem_certificate_block(&bytes) {
                    cfg.warnings.push(format!(
                        "{source_label}:{lineno}: cafile='{value}' contains no \
                         '-----BEGIN CERTIFICATE-----' block; skipped"
                    ));
                    return;
                }
                cfg.tls.extra_roots.push(TaggedRoot {
                    pem_bytes: bytes,
                    source: source_label.to_string(),
                    line: lineno,
                });
            }
            Err(e) => {
                // Fail-fast: a typo'd cafile path silently falls back to
                // system roots, which means the user hits a confusing
                // handshake error mid-install. Surface it at config-load
                // instead so the install aborts before any network.
                cfg.errors.push(format!(
                    "{source_label}:{lineno}: cafile='{value}': failed to read: {e}"
                ));
            }
        }
        return;
    }
    if key == "ca" {
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty ca PEM value; skipped"
            ));
            return;
        }
        // `.npmrc` is line-based; npm encodes multi-line PEMs as a single
        // line using literal `\n` escapes:
        //   ca = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
        // Decode those to real newlines so the marker check and downstream
        // `reqwest::Certificate::from_pem` see structurally-valid PEM.
        let decoded = decode_npmrc_pem_escapes(value);
        let bytes = decoded.as_bytes();
        if !contains_pem_certificate_block(bytes) {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: ca PEM contains no \
                 '-----BEGIN CERTIFICATE-----' block; skipped"
            ));
            return;
        }
        cfg.tls.extra_roots.push(TaggedRoot {
            pem_bytes: bytes.to_vec(),
            source: source_label.to_string(),
            line: lineno,
        });
        return;
    }
    if key == "strict-ssl" {
        match value.to_ascii_lowercase().as_str() {
            "false" => {
                if is_project_layer {
                    // Project-local `.npmrc` is owned by the repo and can be
                    // committed by anyone with push access; a hostile clone
                    // with `strict-ssl=false` would silently disable cert
                    // validation for every user who runs `lpm install`.
                    // User-level (`~/.npmrc`) and system-level files keep the
                    // existing behaviour — the operator can still opt in there.
                    //
                    // Push to `security_warnings` (NOT `warnings`) so
                    // the refusal is surfaced under `--json` too —
                    // CI / agents need to know a malicious config was
                    // refused, not just silently no-op'd.
                    cfg.security_warnings.push(format!(
                        "{source_label}:{lineno}: strict-ssl=false refused — \
                         project-local .npmrc cannot disable TLS verification; \
                         move the setting to ~/.npmrc if you really want it"
                    ));
                    return;
                }
                cfg.tls.strict_ssl = Some(TaggedBool {
                    value: false,
                    source: source_label.to_string(),
                    line: lineno,
                });
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: strict-ssl=false — TLS certificate \
                     verification will be DISABLED for this install"
                ));
            }
            "true" => {
                // Explicit =true: silent no-op (the default). Still
                // recorded so a higher-precedence layer can flip an
                // earlier `=false` back on.
                cfg.tls.strict_ssl = Some(TaggedBool {
                    value: true,
                    source: source_label.to_string(),
                    line: lineno,
                });
            }
            _ => {
                cfg.warnings.push(format!(
                    "{source_label}:{lineno}: strict-ssl='{value}' is not a \
                     boolean; ignored"
                ));
            }
        }
        return;
    }
    if key == "certfile" || key == "keyfile" {
        // Global mTLS identity (cert chain + private key). Path-only at parse
        // time; the actual cert/key file is read at client-build time. The
        // XOR-pair contract (both set or both absent) is enforced at
        // finalize() across all merged layers, so `certfile=` in `~/.npmrc`
        // plus `keyfile=` in a project `.npmrc` legitimately compose.
        if value.is_empty() {
            cfg.warnings.push(format!(
                "{source_label}:{lineno}: empty {key} path; skipped"
            ));
            return;
        }
        let tagged_path = TaggedPath {
            path: PathBuf::from(value),
            source: source_label.to_string(),
            line: lineno,
            source_dir: source_dir.map(|p| p.to_path_buf()),
        };
        if key == "certfile" {
            cfg.tls.identity_certfile = Some(tagged_path);
        } else {
            cfg.tls.identity_keyfile = Some(tagged_path);
        }
        return;
    }
    if key == "always-auth" {
        // Silently accepted. lpm always sends a matching-origin token, which
        // is what `always-auth=true` users want; `=false` is a no-op.
        // Modern npm 7+ removed the per-registry distinction.
    }

    // Anything else — silent ignore. Matches npm: unknown keys aren't
    // an error. Things like `engine-strict`, `save-prefix`, `lockfile`
    // are lpm's own concerns and the npmrc value (if any) is just
    // noise from this module's perspective.
}

/// Cheap parse-time validation: does this byte slice contain at least one
/// PEM certificate block? We don't decode the body here — that's
/// [`crate::client::validate_pem_root`]'s job at install start, which
/// runs the full base64 + per-block walk and cites the offending block
/// in `LpmError::Cert(..)`.
///
/// **Two-layer defense, by design.** This parse-time check exists so a
/// user who points `cafile=` at `/etc/passwd` learns at config-load
/// (with `cfg.errors` populated) before any other parsing decisions are
/// made. The builder-time check exists so `_strictly_ valid PEM_ at
/// parse time but with malformed base64 inside one of the blocks` (rare
/// but real) gets cited cleanly with source/line + block number rather
/// than as a generic "HTTP client build failed" — see
/// [`crate::client::validate_pem_root`] for the full rationale on why
/// reqwest's permissive `from_pem` makes the second layer necessary.
fn contains_pem_certificate_block(bytes: &[u8]) -> bool {
    // PEM marker is ASCII-only; byte-search is correct.
    const MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    bytes.windows(MARKER.len()).any(|w| w == MARKER)
}

/// Decode npm's PEM-escape form: `\n` → real newline, `\r` → carriage return.
/// `.npmrc` is line-based, so npm encodes multi-line PEMs as a single
/// line with literal backslash-n / backslash-r sequences. We decode those
/// before storing so downstream consumers (`reqwest::Certificate::from_pem`)
/// see structurally-valid PEM.
///
/// **Scope limitation (intentional):** only `\n` and `\r` are decoded.
/// We do NOT process backslash-escaping (`\\` → `\`), so a hypothetical
/// input containing `\\n` (escaped backslash followed by `n`) would be
/// transformed into `\` + literal newline rather than the literal
/// 2-char string `\n`. This is unreachable in practice — PEM bodies are
/// pure ASCII (base64 + 5-dash headers) and contain no backslash
/// characters in the unencoded form. Documenting the limitation here
/// so a future "let's also support `\\` escaping" change is a deliberate
/// decision, not an accidental rewrite of the contract.
fn decode_npmrc_pem_escapes(s: &str) -> String {
    s.replace("\\n", "\n").replace("\\r", "\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npmrc::{RegistryAuth, RegistryKind};
    use secrecy::{ExposeSecret, SecretString};

    fn no_env(_name: &str) -> Option<String> {
        None
    }

    fn fixed_env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    fn encoded_npmrc_password(password: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(password.as_bytes())
    }

    fn encoded_basic_credential(username: &str, password: &str) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}").as_bytes())
    }

    #[test]
    fn empty_file_yields_default_config() {
        let cfg = NpmrcConfig::parse("", "test", &no_env);
        assert!(cfg.default_registry.is_none());
        assert!(cfg.scope_registries.is_empty());
        assert!(cfg.origin_auth.is_empty());
        assert!(cfg.warnings.is_empty());
        assert!(cfg.errors.is_empty());
    }

    #[test]
    fn comments_only_yields_default_config() {
        let content = "; comment one\n# comment two\n\n   ; indented comment\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_none());
        assert!(cfg.warnings.is_empty());
        assert!(cfg.errors.is_empty());
    }

    #[test]
    fn default_registry_is_captured_and_trimmed() {
        let cfg = NpmrcConfig::parse("registry=https://npm.example.com/", "test", &no_env);
        let target = cfg.default_registry.expect("registry should be set");
        assert_eq!(target.base_url.as_ref(), "https://npm.example.com");
        assert_eq!(target.kind, RegistryKind::NpmCompatible);
    }

    #[test]
    fn scope_registry_lowercases_and_routes() {
        // User contract: an `.npmrc` with `@MyCompany:registry=...` and
        // an install of either `@mycompany/foo` or `@MyCompany/foo` must
        // both resolve to that registry. Storage and lookup both
        // lowercase, mirroring npm-the-CLI.
        let content = "@MyCompany:registry=https://npm.internal/\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.scope_registries.len(), 1);
        // Lowercase package name resolves.
        let lower = cfg
            .target_for_package("@mycompany/foo")
            .expect("lowercase scope target should resolve");
        assert_eq!(lower.base_url.as_ref(), "https://npm.internal");
        // Mixed-case package name resolves to the SAME target.
        let mixed = cfg
            .target_for_package("@MyCompany/foo")
            .expect("mixed-case scope target should resolve");
        assert_eq!(mixed.base_url.as_ref(), "https://npm.internal");
        // Unrelated scope falls through to `default_registry` (None here).
        assert!(cfg.target_for_package("@other/foo").is_none());
    }

    #[test]
    fn bearer_token_parses_for_origin() {
        let content = "//npm.internal/:_authToken=ABC123\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://npm.internal/some/pkg")
            .expect("auth should match");
        match auth {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "ABC123"),
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn env_var_interpolation_present() {
        let content = "//npm.internal/:_authToken=${NPM_TOKEN}\n";
        let env = fixed_env(&[("NPM_TOKEN", "secret-value")]);
        let cfg = NpmrcConfig::parse(content, "test", &env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        let auth = cfg
            .auth_for_url("https://npm.internal/")
            .expect("auth should match");
        match auth {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "secret-value"),
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    #[test]
    fn env_var_interpolation_missing_is_fatal() {
        let content = "//npm.internal/:_authToken=${NPM_TOKEN}\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.errors.len(), 1);
        assert!(
            cfg.errors[0].contains("NPM_TOKEN"),
            "error mentions var name: {:?}",
            cfg.errors[0]
        );
        // No partial credential should be stored.
        assert!(cfg.origin_auth.is_empty());
    }

    #[test]
    fn project_layer_env_expansion_for_registry_and_auth_is_refused() {
        let content = "registry=${MALICIOUS_REGISTRY}\n\
                       @private:registry=${MALICIOUS_REGISTRY}\n\
                       //packages.example.test/:_authToken=${NPM_TOKEN}\n";
        let env = fixed_env(&[
            ("MALICIOUS_REGISTRY", "https://packages.example.test"),
            ("NPM_TOKEN", "secret-value"),
        ]);
        let cfg =
            NpmrcConfig::parse_layer_with_options(content, "project/.npmrc", None, true, &env);

        assert!(cfg.default_registry.is_none());
        assert!(cfg.scope_registries.is_empty());
        assert!(cfg.auth_buffers.is_empty());
        assert_eq!(
            cfg.security_warnings.len(),
            3,
            "project env expansion refusals must be surfaced as security warnings: {:?}",
            cfg.security_warnings
        );
    }

    #[test]
    fn project_layer_env_expansion_for_tls_destinations_is_refused() {
        let content = "cafile=${CA_FILE}\n\
                       certfile=${CLIENT_CERT}\n\
                       keyfile=${CLIENT_KEY}\n\
                       //packages.example.test/:cafile=${CA_FILE}\n";
        let env = fixed_env(&[
            ("CA_FILE", "/tmp/ca.pem"),
            ("CLIENT_CERT", "/tmp/client.pem"),
            ("CLIENT_KEY", "/tmp/client.key"),
        ]);
        let cfg =
            NpmrcConfig::parse_layer_with_options(content, "project/.npmrc", None, true, &env);

        assert!(cfg.tls.extra_roots.is_empty());
        assert!(cfg.tls.identity_certfile.is_none());
        assert!(cfg.tls.identity_keyfile.is_none());
        assert!(cfg.tls.per_origin.is_empty());
        assert_eq!(
            cfg.security_warnings.len(),
            4,
            "project TLS env expansion refusals must be surfaced: {:?}",
            cfg.security_warnings
        );
    }

    #[test]
    fn basic_auth_via_combined_field() {
        let credential = encoded_basic_credential("user", "pass");
        let content = format!("//npm.internal/:_auth={credential}\n");
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), credential.as_str())
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn basic_auth_via_split_username_password() {
        let password = encoded_npmrc_password("pass");
        let content = format!(
            "//npm.internal/:_username=user\n\
             //npm.internal/:_password={password}\n"
        );
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), encoded_basic_credential("user", "pass"))
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn token_with_special_chars() {
        // Ensure we don't choke on `:`, `/`, `=` inside the token value.
        // The split is on the FIRST `=`; everything after is the value.
        let content = "//npm.internal/:_authToken=ab:cd/ef=gh+ij\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Bearer { token: s, .. } => {
                assert_eq!(s.expose_secret(), "ab:cd/ef=gh+ij")
            }
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let content = "registry=https://npm.example.com/\r\n@s:registry=https://b/\r\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.scope_registries.len(), 1);
    }

    #[test]
    fn utf8_bom_is_stripped() {
        let content = "\u{feff}registry=https://npm.example.com/\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    #[test]
    fn malformed_line_warns_and_continues() {
        // No `=` separator: should warn, not abort.
        let content = "registry=https://good.example.com/\nthis-line-is-bad\nstill-parsing=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("test:2"));
    }

    #[test]
    fn unknown_keys_are_silently_ignored() {
        // `engine-strict`, `save-prefix` etc. are lpm's own concerns.
        let content = concat!(
            "engine-strict=true\n",
            "save-prefix=^\n",
            "lockfile=true\n",
            "registry=https://good.example.com/\n",
        );
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
    }

    // ---- TLS overrides: cafile / ca / strict-ssl / always-auth ----

    /// Generate a self-signed test PEM (cert + key); only the cert PEM
    /// is used by these parser tests. Key is dropped. Used in lieu of a
    /// committed binary fixture so future test-cert rotations are free.
    fn generate_test_cert_pem() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen self-signed cert");
        cert.cert.pem()
    }

    #[test]
    fn cafile_path_loads_pem_into_extra_roots() {
        let pem = generate_test_cert_pem();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, &pem).unwrap();
        let content = format!("cafile={}\n", path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let root = &cfg.tls.extra_roots[0];
        assert_eq!(root.pem_bytes, pem.as_bytes());
        assert_eq!(root.source, "test");
        assert_eq!(root.line, 1);
    }

    #[test]
    fn cafile_path_with_io_error_pushes_to_errors_not_warnings() {
        // Non-existent path. Fail-fast contract: this is fatal, not a
        // silent system-root fallback.
        let content = "cafile=/this/path/should/never/exist/ca.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(
            cfg.errors[0].contains("cafile=") && cfg.errors[0].contains("failed to read"),
            "error message: {}",
            cfg.errors[0]
        );
    }

    #[test]
    fn cafile_path_with_garbage_content_pushes_warning_and_skips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-cert.pem");
        std::fs::write(&path, b"this is not a PEM file at all\n").unwrap();
        let content = format!("cafile={}\n", path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("contains no")
                && cfg.warnings[0].contains("BEGIN CERTIFICATE")
        );
    }

    #[test]
    fn ca_inline_pem_appends_to_extra_roots() {
        let pem = generate_test_cert_pem();
        // npm convention: multi-line PEM on a single ca= line, real
        // newlines encoded as literal `\n`. Round-trip through escape →
        // decode and assert the stored bytes match the original PEM.
        let escaped = pem.replace('\n', "\\n");
        let content = format!("ca={escaped}\n");
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let root = &cfg.tls.extra_roots[0];
        assert_eq!(root.source, "test");
        assert_eq!(
            root.pem_bytes,
            pem.as_bytes(),
            "decoded PEM bytes should match the original"
        );
    }

    #[test]
    fn ca_inline_pem_with_literal_escapes_decodes_correctly() {
        // Synthetic minimal PEM-shaped value (validation only checks for
        // the BEGIN marker, not the body) — this test specifically pins
        // the `\n` / `\r` decoding.
        let content = "ca=-----BEGIN CERTIFICATE-----\\nABCDEF\\n-----END CERTIFICATE-----\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        let stored = &cfg.tls.extra_roots[0].pem_bytes;
        assert_eq!(
            stored,
            b"-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----"
        );
    }

    #[test]
    fn ca_inline_empty_value_warns_and_skips() {
        let cfg = NpmrcConfig::parse("ca=\n", "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("empty ca PEM"));
    }

    #[test]
    fn ca_inline_garbage_warns_and_skips() {
        let cfg = NpmrcConfig::parse("ca=hunter2\n", "test", &no_env);
        assert!(cfg.tls.extra_roots.is_empty());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("contains no")
                && cfg.warnings[0].contains("BEGIN CERTIFICATE")
        );
    }

    #[test]
    fn multiple_cafile_and_ca_mixed_all_present_in_extra_roots() {
        let pem_a = generate_test_cert_pem();
        let pem_b = generate_test_cert_pem();
        let dir = tempfile::tempdir().unwrap();
        let cafile_path = dir.path().join("a.pem");
        std::fs::write(&cafile_path, &pem_a).unwrap();
        let escaped_b = pem_b.replace('\n', "\\n");
        let content = format!("cafile={}\nca={escaped_b}\n", cafile_path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.tls.extra_roots.len(), 2);
        // Order is insertion order (cafile= line 1, ca= line 2).
        assert_eq!(cfg.tls.extra_roots[0].line, 1);
        assert_eq!(cfg.tls.extra_roots[1].line, 2);
    }

    #[test]
    fn merge_over_concatenates_extra_roots_lower_first() {
        let pem_lower = generate_test_cert_pem().replace('\n', "\\n");
        let pem_higher = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem_lower}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem_higher}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(acc.tls.extra_roots.len(), 2);
        assert_eq!(acc.tls.extra_roots[0].source, "lower");
        assert_eq!(acc.tls.extra_roots[1].source, "higher");
    }

    #[test]
    fn merge_over_dedupes_identical_extra_roots_preserving_first_source() {
        // Regression — if two layers contribute the same PEM bytes
        // (common in shops where `~/.npmrc` and a project `.npmrc`
        // both set `cafile=/etc/ssl/corp-ca.pem`), the merged
        // `extra_roots` should NOT duplicate the cert. Rustls handles
        // duplicate roots without erroring, but we'd still pay an
        // extra `validate_pem_root` + `Certificate::from_pem` round
        // for nothing, AND the source attribution would silently
        // shift from "the file you set first" to "the file you set
        // later" depending on which one wins downstream.
        //
        // Dedup by `pem_bytes`, keeping the FIRST source seen (the
        // lower-precedence / earliest layer). That preserves
        // chronological attribution and matches the lower-first
        // ordering used everywhere else in this merge.
        let pem = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.tls.extra_roots.len(),
            1,
            "duplicate PEM bytes across layers must be deduplicated"
        );
        assert_eq!(
            acc.tls.extra_roots[0].source, "lower",
            "first source must persist on dedup so attribution doesn't shift"
        );
    }

    #[test]
    fn strict_ssl_false_sets_some_false_with_loud_warning() {
        let cfg = NpmrcConfig::parse("strict-ssl=false\n", "test", &no_env);
        let tagged = cfg.tls.strict_ssl.expect("strict_ssl should be Some");
        assert!(!tagged.value);
        assert_eq!(tagged.source, "test");
        assert_eq!(tagged.line, 1);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(
            cfg.warnings[0].contains("DISABLED"),
            "warning: {}",
            cfg.warnings[0]
        );
    }

    #[test]
    fn strict_ssl_true_sets_some_true_silently() {
        let cfg = NpmrcConfig::parse("strict-ssl=true\n", "test", &no_env);
        let tagged = cfg.tls.strict_ssl.expect("strict_ssl should be Some(true)");
        assert!(tagged.value);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    #[test]
    fn strict_ssl_missing_remains_none() {
        let cfg = NpmrcConfig::parse("registry=https://example.com/\n", "test", &no_env);
        assert!(cfg.tls.strict_ssl.is_none());
    }

    #[test]
    fn strict_ssl_other_values_warn_and_remain_none() {
        let cfg = NpmrcConfig::parse("strict-ssl=maybe\n", "test", &no_env);
        assert!(cfg.tls.strict_ssl.is_none());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("not a"));
    }

    #[test]
    fn merge_over_strict_ssl_higher_silent_does_not_clear_lower() {
        // (a) precedence: lower-explicit persists when higher is silent.
        // Same shape as `default_registry`. A user's `~/.npmrc` strict-ssl=false
        // applies to projects that don't say anything.
        let mut lower = NpmrcConfig::parse_layer("strict-ssl=false\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("registry=https://x/\n", "higher", &no_env);
        lower.merge_over(higher);
        let tagged = lower.tls.strict_ssl.expect("lower setting should persist");
        assert!(!tagged.value);
        assert_eq!(tagged.source, "lower");
    }

    #[test]
    fn merge_over_strict_ssl_higher_explicit_overrides_lower() {
        // Higher-explicit wins (any value, even back-to-true).
        let mut lower = NpmrcConfig::parse_layer("strict-ssl=false\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("strict-ssl=true\n", "higher", &no_env);
        lower.merge_over(higher);
        let tagged = lower.tls.strict_ssl.expect("higher should override");
        assert!(tagged.value);
        assert_eq!(tagged.source, "higher");
    }

    /// A project-local `.npmrc` is owned by the repo and may be hostile
    /// in a malicious-clone scenario. `strict-ssl=false` committed there
    /// must NOT silently disable TLS verification for anyone who runs
    /// `lpm install` in the clone. The refusal lands in
    /// `security_warnings` (not `warnings`) so it survives `--json` mode
    /// where routine npmrc warnings are silenced.
    #[test]
    fn strict_ssl_false_from_project_layer_is_refused() {
        let cfg = NpmrcConfig::parse_layer_with_options(
            "strict-ssl=false\n",
            "proj/.npmrc",
            None,
            true, // is_project_layer
            &no_env,
        );
        assert!(
            cfg.tls.strict_ssl.is_none(),
            "project-layer strict-ssl=false must not be applied: {:?}",
            cfg.tls.strict_ssl
        );
        assert!(
            cfg.warnings.is_empty(),
            "refusal must NOT land in routine warnings (silenced under --json): {:?}",
            cfg.warnings
        );
        assert_eq!(cfg.security_warnings.len(), 1);
        assert!(
            cfg.security_warnings[0].contains("refused"),
            "security warning must label the refusal: {}",
            cfg.security_warnings[0]
        );
    }

    /// A user-level `~/.npmrc` (is_project_layer = false) still honours
    /// `strict-ssl=false` — the operator's explicit choice for their own
    /// machine remains respected.
    #[test]
    fn strict_ssl_false_from_user_layer_is_still_honoured() {
        let cfg = NpmrcConfig::parse_layer_with_options(
            "strict-ssl=false\n",
            "/home/me/.npmrc",
            None,
            false, // not a project layer
            &no_env,
        );
        let tagged = cfg.tls.strict_ssl.expect("user-layer must still apply");
        assert!(!tagged.value);
        assert_eq!(tagged.source, "/home/me/.npmrc");
    }

    /// A project-layer `strict-ssl=true` is silently accepted because
    /// re-enabling verification is never dangerous, even from a hostile
    /// repo.
    #[test]
    fn strict_ssl_true_from_project_layer_is_accepted() {
        let cfg = NpmrcConfig::parse_layer_with_options(
            "strict-ssl=true\n",
            "proj/.npmrc",
            None,
            true,
            &no_env,
        );
        let tagged = cfg.tls.strict_ssl.expect("strict-ssl=true must apply");
        assert!(tagged.value);
    }

    #[test]
    fn always_auth_global_silently_accepted_no_warning() {
        for v in ["true", "false", "always"] {
            let content = format!("always-auth={v}\n");
            let cfg = NpmrcConfig::parse(&content, "test", &no_env);
            assert!(
                cfg.warnings.is_empty(),
                "warnings for value {v}: {:?}",
                cfg.warnings
            );
            assert!(
                cfg.errors.is_empty(),
                "errors for value {v}: {:?}",
                cfg.errors
            );
        }
    }

    #[test]
    fn always_auth_per_origin_silently_accepted_no_warning() {
        let content = "//npm.internal/:always-auth=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
    }

    // ---- per-origin TLS / mTLS parsing ----

    #[test]
    fn global_certfile_xor_keyfile_is_fatal_with_cited_line() {
        // Half-configured global identity at finalize time → fatal, citing
        // the line of the present key and naming the missing one. This is
        // GLOBAL state — wrong here breaks every fetch, so install must
        // abort before any network.
        let cfg = NpmrcConfig::parse("certfile=/path/cert.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("certfile"));
        assert!(cfg.errors[0].contains("keyfile"));

        let cfg = NpmrcConfig::parse("keyfile=/path/key.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("keyfile"));
        assert!(cfg.errors[0].contains("certfile"));
    }

    #[test]
    fn global_certfile_and_keyfile_complete_pair_is_clean() {
        let content = "certfile=/path/cert.pem\nkeyfile=/path/key.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(
            cfg.tls.identity_certfile.as_ref().unwrap().path,
            PathBuf::from("/path/cert.pem")
        );
        assert_eq!(
            cfg.tls.identity_keyfile.as_ref().unwrap().path,
            PathBuf::from("/path/key.pem")
        );
    }

    #[test]
    fn global_certfile_keyfile_compose_across_layers() {
        // certfile in lower-precedence + keyfile in higher-precedence
        // should compose into a complete pair, NOT trigger the XOR
        // fatal — the contract is across all merged layers.
        let mut acc = NpmrcConfig::parse_layer("certfile=/etc/cert.pem\n", "system", &no_env);
        let higher = NpmrcConfig::parse_layer("keyfile=/home/u/key.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert!(acc.errors.is_empty(), "errors: {:?}", acc.errors);
        assert_eq!(acc.tls.identity_certfile.as_ref().unwrap().source, "system");
        assert_eq!(acc.tls.identity_keyfile.as_ref().unwrap().source, "user");
    }

    #[test]
    fn global_certfile_empty_value_warns_skipped() {
        let cfg = NpmrcConfig::parse("certfile=\n", "test", &no_env);
        // Empty value warned + skipped means no certfile is set,
        // which means no XOR fatal either.
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("empty certfile"));
        assert!(cfg.tls.identity_certfile.is_none());
    }

    #[test]
    fn per_origin_cafile_populates_per_origin_not_global_roots() {
        let cfg = NpmrcConfig::parse("//npm.internal/:cafile=/path/ca.pem\n", "test", &no_env);
        // Per-origin cafile is path-only at parse time (deferred-read), so a
        // non-existent path here is NOT a parse-time error. Only loaded at
        // client-build time for the matching origin.
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(
            cfg.tls.extra_roots.is_empty(),
            "per-origin cafile must not feed global extra_roots"
        );
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(per_origin.cafiles.len(), 1);
        assert_eq!(per_origin.cafiles[0].path, PathBuf::from("/path/ca.pem"));
        assert_eq!(per_origin.cafiles[0].source, "test");
        assert_eq!(per_origin.cafiles[0].line, 1);
    }

    #[test]
    fn per_origin_certfile_keyfile_populate_per_origin_not_global() {
        let content = "//npm.internal/:certfile=/path/cert.pem\n\
                       //npm.internal/:keyfile=/path/key.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(cfg.tls.identity_certfile.is_none());
        assert!(cfg.tls.identity_keyfile.is_none());
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().path,
            PathBuf::from("/path/cert.pem")
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().path,
            PathBuf::from("/path/key.pem")
        );
    }

    #[test]
    fn per_origin_half_configured_identity_does_not_abort_at_finalize() {
        // Per-origin half-configs are NOT fatal at finalize. They become fatal
        // only when that origin is actually built into a client (eager or
        // lazy). Configured-but-unreached half-configs do not break unrelated
        // installs.
        let cfg = NpmrcConfig::parse(
            "//unused.internal/:certfile=/path/cert.pem\n",
            "test",
            &no_env,
        );
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
    }

    #[test]
    fn tls_for_origin_falls_back_to_any_port() {
        let cfg = NpmrcConfig::parse("//npm.internal/:cafile=/path/ca.pem\n", "test", &no_env);
        // Lookup with a concrete port should fall back to the
        // port-less entry, mirroring auth_for_url's semantics.
        let with_port = OriginKey {
            host_lower: "npm.internal".into(),
            port: Some(443),
        };
        assert!(cfg.tls_for_origin(&with_port).is_some());
        let other_host = OriginKey {
            host_lower: "other.internal".into(),
            port: Some(443),
        };
        assert!(cfg.tls_for_origin(&other_host).is_none());
    }

    #[test]
    fn merge_over_per_origin_cafiles_concatenate() {
        let mut acc =
            NpmrcConfig::parse_layer("//npm.internal/:cafile=/system/ca.pem\n", "system", &no_env);
        let higher =
            NpmrcConfig::parse_layer("//npm.internal/:cafile=/user/ca.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = acc.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(per_origin.cafiles.len(), 2);
        assert_eq!(per_origin.cafiles[0].source, "system");
        assert_eq!(per_origin.cafiles[1].source, "user");
    }

    #[test]
    fn parse_layer_with_source_dir_tags_certfile_for_resolve() {
        // When parse_layer_with_source_dir is given a directory, every
        // TaggedPath in this layer (global + per-origin) must carry it so
        // `TaggedPath::resolve()` can compose absolute paths from relative
        // `.npmrc` values.
        let dir = std::path::Path::new("/etc/npm");
        let content = "certfile=corp-cert.pem\n\
                       keyfile=corp-key.pem\n\
                       //npm.internal/:cafile=ca.pem\n\
                       //npm.internal/:certfile=client.pem\n\
                       //npm.internal/:keyfile=client.key\n";
        let cfg =
            NpmrcConfig::parse_layer_with_source_dir(content, "/etc/npmrc", Some(dir), &no_env);

        // Global identity tags both paths with source_dir.
        let global_cert = cfg.tls.identity_certfile.as_ref().unwrap();
        assert_eq!(global_cert.path, PathBuf::from("corp-cert.pem"));
        assert_eq!(global_cert.source_dir.as_deref(), Some(dir));
        assert_eq!(
            global_cert.resolve(),
            PathBuf::from("/etc/npm/corp-cert.pem")
        );

        let global_key = cfg.tls.identity_keyfile.as_ref().unwrap();
        assert_eq!(global_key.resolve(), PathBuf::from("/etc/npm/corp-key.pem"));

        // Per-origin entries: same scoping.
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = cfg.tls.per_origin.get(&origin).expect("per_origin entry");
        assert_eq!(per_origin.cafiles.len(), 1);
        assert_eq!(
            per_origin.cafiles[0].resolve(),
            PathBuf::from("/etc/npm/ca.pem")
        );
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().resolve(),
            PathBuf::from("/etc/npm/client.pem")
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().resolve(),
            PathBuf::from("/etc/npm/client.key")
        );
    }

    #[test]
    fn parse_layer_without_source_dir_leaves_path_unchanged_on_resolve() {
        // Tests / single-file convenience callers pass None — the
        // resolve() helper returns the verbatim path so loaders
        // fall back to ${PWD}-relative resolution (matching the
        // pre-58.3 behavior).
        let cfg = NpmrcConfig::parse(
            "certfile=/abs/cert.pem\nkeyfile=relative.pem\n",
            "test",
            &no_env,
        );
        let cert = cfg.tls.identity_certfile.as_ref().unwrap();
        assert!(cert.source_dir.is_none());
        // Absolute path: unchanged regardless.
        assert_eq!(cert.resolve(), PathBuf::from("/abs/cert.pem"));

        let key = cfg.tls.identity_keyfile.as_ref().unwrap();
        assert!(key.source_dir.is_none());
        // Relative + no source_dir → returned as-is (loader resolves vs cwd).
        assert_eq!(key.resolve(), PathBuf::from("relative.pem"));
    }

    #[test]
    fn merge_over_per_origin_certfile_higher_wins() {
        let mut acc = NpmrcConfig::parse_layer(
            "//npm.internal/:certfile=/system/cert.pem\n\
             //npm.internal/:keyfile=/system/key.pem\n",
            "system",
            &no_env,
        );
        let higher =
            NpmrcConfig::parse_layer("//npm.internal/:certfile=/user/cert.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        let origin = OriginKey {
            host_lower: "npm.internal".into(),
            port: None,
        };
        let per_origin = acc.tls.per_origin.get(&origin).expect("entry");
        assert_eq!(
            per_origin.certfile.as_ref().unwrap().source,
            "user",
            "higher layer's certfile must win"
        );
        assert_eq!(
            per_origin.keyfile.as_ref().unwrap().source,
            "system",
            "lower layer's keyfile is preserved when higher doesn't set it"
        );
    }

    #[test]
    fn password_containing_colon_round_trips() {
        // Defensive regression test against a hypothetical future "split on
        // every `:`" refactor of the _username/_password join.
        //
        // Per RFC 7617, the userid:password wire format reserves only
        // the FIRST `:` as the separator; the password may contain
        // any number of additional `:` characters. The current
        // [`AuthBuffer::resolve`] does `format!("{user}:{pw}")` which
        // is correct (the encoded blob places the user-pass split at
        // the first `:` in the decoded form). A future change that
        // base64-decoded `_password`, joined, and then re-split on
        // every `:` would break passwords like `p@ss:word`.
        //
        // npm itself preserves the colons via the same path; this
        // test pins parity. The cost is ~10 LOC and it shields the
        // contract.
        use base64::Engine as _;
        let raw_pw = "p@ss:word";
        let encoded_pw = base64::engine::general_purpose::STANDARD.encode(raw_pw.as_bytes());
        let content = format!(
            "//npm.internal/:_username=user\n\
             //npm.internal/:_password={encoded_pw}\n"
        );
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.origin_auth.len(), 1);
        let auth = cfg.origin_auth.values().next().unwrap();
        match auth {
            RegistryAuth::Basic { credential, .. } => {
                let combined = base64::engine::general_purpose::STANDARD
                    .decode(credential.expose_secret())
                    .expect("credential is valid base64");
                let combined_str = std::str::from_utf8(&combined).unwrap();
                // The wire form must be `user:p@ss:word` (FIRST `:` is
                // the separator, all subsequent `:` are part of the
                // password). A buggy "split-on-every-:" round-trip
                // would either drop bytes or rejoin them in the wrong
                // place — pin the exact expected wire form.
                assert_eq!(combined_str, "user:p@ss:word");
            }
            other => panic!("expected Basic auth, got {other:?}"),
        }
    }

    // ---- Beyond the contract tests: defense-in-depth checks ----

    #[test]
    fn merge_over_lets_higher_layer_win() {
        // Layered API: parse_layer per file, merge, then finalize.
        let lower = NpmrcConfig::parse_layer("registry=https://lower/\n", "lower", &no_env);
        let higher = NpmrcConfig::parse_layer("registry=https://higher/\n", "higher", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://higher"
        );
    }

    #[test]
    fn merge_preserves_non_overlapping_keys() {
        let lower = NpmrcConfig::parse_layer(
            "registry=https://lower/\n@a:registry=https://a/\n",
            "lower",
            &no_env,
        );
        let higher = NpmrcConfig::parse_layer("@b:registry=https://b/\n", "higher", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://lower"
        );
        assert_eq!(acc.scope_registries.len(), 2);
    }

    // ---- cross-layer credential merge ----

    #[test]
    fn cross_layer_username_password_merge() {
        // System-level file declares the username; user-level adds the
        // password. Finalize must combine them into Basic auth, not emit two
        // partial-credential warnings.
        let system =
            NpmrcConfig::parse_layer("//npm.internal/:_username=alice\n", "/etc/npmrc", &no_env);
        let password = encoded_npmrc_password("pass");
        let user = NpmrcConfig::parse_layer(
            &format!("//npm.internal/:_password={password}\n"),
            "~/.npmrc",
            &no_env,
        );
        let mut acc = system;
        acc.merge_over(user);
        acc.finalize();
        assert!(
            acc.warnings.is_empty(),
            "no partial-credential warnings expected: {:?}",
            acc.warnings
        );
        let auth = acc
            .auth_for_url("https://npm.internal/foo")
            .expect("composed Basic credential should resolve");
        match auth {
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(s.expose_secret(), encoded_basic_credential("alice", "pass"))
            }
            other => panic!("expected Basic, got {other:?}"),
        }
    }

    #[test]
    fn higher_layer_password_overrides_lower_layer_password() {
        // Per-subkey last-wins: lower layer's _password is replaced by
        // higher layer's, but lower layer's _username survives because
        // higher doesn't set one.
        let old_password = encoded_npmrc_password("old-pw");
        let lower = NpmrcConfig::parse_layer(
            &format!("//npm.internal/:_username=alice\n//npm.internal/:_password={old_password}\n"),
            "/etc/npmrc",
            &no_env,
        );
        let new_password = encoded_npmrc_password("new-pw");
        let higher = NpmrcConfig::parse_layer(
            &format!("//npm.internal/:_password={new_password}\n"),
            "~/.npmrc",
            &no_env,
        );
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        let auth = acc.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Basic { credential: s, .. } => {
                assert_eq!(
                    s.expose_secret(),
                    encoded_basic_credential("alice", "new-pw")
                )
            }
            _ => panic!("expected Basic"),
        }
    }

    // ---- scheme-agnostic implicit-port match ----

    #[test]
    fn implicit_port_npmrc_matches_both_http_and_https() {
        // The user wrote `//host/:_authToken=X` with no explicit port.
        // Stored as port=None — matches a request on either http or https
        // (any port for that host).
        let content = "//npm.internal/:_authToken=AGNOSTIC\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let https_auth = cfg
            .auth_for_url("https://npm.internal/foo")
            .expect("https should match");
        let http_auth = cfg
            .auth_for_url("http://npm.internal/foo")
            .expect("http should match");
        match (https_auth, http_auth) {
            (RegistryAuth::Bearer { token: a, .. }, RegistryAuth::Bearer { token: b, .. }) => {
                assert_eq!(a.expose_secret(), "AGNOSTIC");
                assert_eq!(b.expose_secret(), "AGNOSTIC");
            }
            _ => panic!("expected Bearer on both"),
        }
    }

    #[test]
    fn explicit_port_443_does_not_leak_to_http() {
        // An explicit `:443` in the npmrc key means "this auth is for port 443 specifically",
        // so an http request (default port 80) must NOT pick it up.
        // This test exists to catch regressions where someone "fixes"
        // the implicit-port case by widening matching too aggressively.
        let content = "//npm.internal:443/:_authToken=HTTPS_ONLY\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.auth_for_url("https://npm.internal/").is_some());
        assert!(
            cfg.auth_for_url("http://npm.internal/").is_none(),
            "explicit :443 must not leak to http (port 80)"
        );
    }

    // ---- source-label in finalize warnings ----

    #[test]
    fn partial_credential_warning_cites_source() {
        // Single-file partial: only _username, no _password.
        // Warning must mention `~/.npmrc:7` (the source + line) and
        // the origin, so a user with multiple .npmrc files can find
        // and fix the offender.
        let content = "\n\n\n\n\n\n//npm.internal/:_username=alice\n";
        let cfg = NpmrcConfig::parse(content, "~/.npmrc", &no_env);
        assert!(cfg.origin_auth.is_empty());
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        let w = &cfg.warnings[0];
        assert!(
            w.contains("~/.npmrc:7"),
            "warning must cite source:line, got {w:?}"
        );
        assert!(
            w.contains("//npm.internal/"),
            "warning must cite the origin via Display impl, got {w:?}"
        );
    }

    #[test]
    fn cross_layer_partial_warning_cites_contributing_layer() {
        // After cross-layer merge: only one half ever set, so the
        // tagged source identifies which layer contributed the
        // half-credential. The other layer didn't write anything for
        // that origin, so there's nothing else to cite.
        let lower =
            NpmrcConfig::parse_layer("//npm.internal/:_username=alice\n", "/etc/npmrc", &no_env);
        // Higher layer adds nothing to this origin — different host.
        let higher = NpmrcConfig::parse_layer("//other.host/:_authToken=X\n", "~/.npmrc", &no_env);
        let mut acc = lower;
        acc.merge_over(higher);
        acc.finalize();
        let warning = acc
            .warnings
            .iter()
            .find(|w| w.contains("npm.internal"))
            .expect("partial-credential warning expected");
        assert!(
            warning.contains("/etc/npmrc:1"),
            "warning must cite the layer that set the partial subkey, got {warning:?}"
        );
    }

    // ---- contract guards ----

    #[test]
    #[should_panic(expected = "merge_over called after finalize")]
    fn merge_after_finalize_panics() {
        let mut a = NpmrcConfig::parse("registry=https://a/\n", "a", &no_env);
        let b = NpmrcConfig::parse_layer("registry=https://b/\n", "b", &no_env);
        // a is finalized (parse() does it), b is not.
        a.merge_over(b);
    }

    #[test]
    fn debug_impl_redacts_secret() {
        let auth = RegistryAuth::Bearer {
            origin: OriginKey {
                host_lower: "example.com".to_string(),
                port: None,
            },
            token: SecretString::from("very-secret"),
        };
        let formatted = format!("{auth:?}");
        assert!(!formatted.contains("very-secret"));
        assert!(formatted.contains("REDACTED"));
        // Origin must still be visible — it's not a secret.
        assert!(formatted.contains("example.com"));
    }

    #[test]
    fn origin_with_explicit_port_matches_request_url_with_same_port() {
        let content = "//npm.internal:8443/:_authToken=PORTED\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        // With matching port — hit.
        assert!(
            cfg.auth_for_url("https://npm.internal:8443/foo").is_some(),
            "explicit port should match"
        );
        // Without matching port — miss. (Documented gotcha.)
        assert!(
            cfg.auth_for_url("https://npm.internal/foo").is_none(),
            "default 443 should NOT match explicit 8443"
        );
    }

    #[test]
    fn token_does_not_leak_to_unrelated_origin() {
        // SECURITY: the whole point of this module. A token for host A
        // must NOT match a request to host B.
        let content = "//npm.internal/:_authToken=A_TOKEN\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.auth_for_url("https://npm.internal/x").is_some());
        assert!(cfg.auth_for_url("https://registry.npmjs.org/x").is_none());
        assert!(cfg.auth_for_url("https://attacker.example/x").is_none());
    }

    /// A URL of the shape `https://<userinfo>@<host>/...` resolves to
    /// `<host>` per RFC 3986. Auth matching must use the same parser as
    /// reqwest so userinfo cannot confuse origin matching.
    #[test]
    fn from_request_url_strips_userinfo_before_host_match() {
        let key =
            OriginKey::from_request_url("https://attacker.com@registry.npmjs.org/foo").unwrap();
        assert_eq!(key.host_lower, "registry.npmjs.org");
        assert_eq!(key.port, Some(443));
    }

    #[test]
    fn from_request_url_strips_user_and_password_userinfo() {
        let key = OriginKey::from_request_url("https://user:pass@registry.npmjs.org/foo").unwrap();
        assert_eq!(key.host_lower, "registry.npmjs.org");
        assert_eq!(key.port, Some(443));
    }

    #[test]
    fn from_request_url_with_userinfo_does_not_match_attacker_origin() {
        // An injected `https://attacker.com@npm.internal/...` lockfile or
        // metadata URL must be classified by the real connect host, not by
        // the userinfo prefix.
        let content = "//npm.internal/:_authToken=INT_TOKEN\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        // The userinfo URL resolves to host npm.internal and matches the
        // configured auth, matching reqwest's dispatch behavior.
        assert!(
            cfg.auth_for_url("https://attacker.com@npm.internal/x")
                .is_some(),
            "userinfo URL must resolve to npm.internal and match the configured auth — \
             this proves the parser is not misled by the userinfo blob",
        );
        // A URL whose actual host is attacker.example must NOT match.
        assert!(
            cfg.auth_for_url("https://npm.internal@attacker.example/x")
                .is_none(),
            "userinfo `npm.internal` must NOT confuse the parser into matching \
             the configured `npm.internal` auth — the real host is attacker.example",
        );
    }

    #[test]
    fn from_request_url_handles_ipv6_host_without_brackets() {
        // Sanity that the reqwest::Url-based parser produces the
        // bracket-stripped form, matching what the previous parser
        // emitted via [`from_host_port_str`].
        let key = OriginKey::from_request_url("https://[::1]:8443/foo").unwrap();
        assert_eq!(key.host_lower, "[::1]");
        assert_eq!(key.port, Some(8443));
    }

    #[test]
    fn from_request_url_rejects_unsupported_scheme() {
        assert!(OriginKey::from_request_url("ftp://npm.internal/x").is_none());
        assert!(OriginKey::from_request_url("file:///tmp/foo").is_none());
    }

    #[test]
    fn quoted_values_are_unwrapped() {
        let content = "registry=\"https://quoted.example.com/\"\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(
            cfg.default_registry.unwrap().base_url.as_ref(),
            "https://quoted.example.com"
        );
    }

    /// A path-scoped `_authToken` key is refused instead of being widened
    /// to the entire origin. The warning explains how to opt in to
    /// origin-wide reach without silently over-disclosing a narrow
    /// GitLab-style project token to sibling projects on the same host.
    #[test]
    fn path_prefixed_auth_key_is_refused_with_explanatory_warning() {
        let content = "//gitlab.com/api/v4/projects/123/packages/npm/:_authToken=glpat-x\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(
            cfg.auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
                .is_none(),
            "path-scoped credential must NOT be materialized",
        );
        assert!(
            cfg.warnings
                .iter()
                .any(|w| w.contains("refusing to materialize")
                    && w.contains("path-scoped npmrc credential")),
            "explanatory warning required; got {:?}",
            cfg.warnings
        );
    }

    /// Origin-scoped (no path) credentials still work; only path-scoped
    /// credential keys are refused.
    #[test]
    fn origin_scoped_auth_key_still_materialized_when_path_scoped_keys_are_refused() {
        let content = "//gitlab.com/:_authToken=glpat-y\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
            .expect("origin-only key should hit");
        match auth {
            RegistryAuth::Bearer { token, .. } => assert_eq!(token.expose_secret(), "glpat-y"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn _authtoken_beats_auth_within_same_origin() {
        // Precedence: _authToken > _auth > _username/_password.
        let credential = encoded_basic_credential("user", "pass");
        let content = format!(
            "//npm.internal/:_authToken=BEARER\n\
             //npm.internal/:_auth={credential}\n"
        );
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        let auth = cfg.auth_for_url("https://npm.internal/").unwrap();
        match auth {
            RegistryAuth::Bearer { token: s, .. } => assert_eq!(s.expose_secret(), "BEARER"),
            other => panic!("expected Bearer (precedence rule), got {other:?}"),
        }
    }
}
