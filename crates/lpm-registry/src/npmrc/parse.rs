use super::config::NpmrcConfig;
use super::types::{AuthScope, RegistryTarget, TaggedBool, TaggedPath, TaggedRoot, TaggedValue};
use lpm_common::{
    TLS_MATERIAL_FILE_SIZE_CAP_BYTES, interpolate_npmrc_env, parse_npmrc_ini_settings,
    read_regular_file_capped_with_metadata,
};
#[cfg(test)]
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum CredentialPolicy<'a> {
    Accept,
    Refuse { warning: &'a str },
}

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
        Self::parse_layer_with_credential_policy(
            content,
            source_label,
            source_dir,
            is_project_layer,
            CredentialPolicy::Accept,
            env_lookup,
        )
    }

    pub(super) fn parse_layer_with_credential_policy(
        content: &str,
        source_label: &str,
        source_dir: Option<&Path>,
        is_project_layer: bool,
        credential_policy: CredentialPolicy<'_>,
        env_lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let mut cfg = NpmrcConfig::default();
        let mut emitted_credential_refusal = false;

        // Strip leading UTF-8 BOM if present. Some Windows editors save
        // .npmrc with one and npm tolerates it.
        let content = content.strip_prefix('\u{feff}').unwrap_or(content);

        for setting in parse_npmrc_ini_settings(content, source_label, &mut cfg.warnings) {
            let diagnostic_key = Arc::clone(&setting.key);
            let key = match interpolate_npmrc_env(&setting.key, env_lookup) {
                Ok(key) => key,
                Err(error) => {
                    cfg.push_error(source_label, || {
                        format!("{source_label}: npm config key interpolation failed: {error}")
                    });
                    continue;
                }
            };
            if !reserve_expanded_npmrc_data(&mut cfg, key.len(), source_label) {
                break;
            }

            if npmrc_key_is_credential(key.as_ref())
                && let CredentialPolicy::Refuse { warning } = credential_policy
            {
                if !emitted_credential_refusal {
                    cfg.push_security_warning(source_label, || warning.to_string());
                    emitted_credential_refusal = true;
                }
                continue;
            }

            if key == "ca" && !is_project_layer {
                cfg.pending_ca_roots = Some(Vec::with_capacity(setting.values.len()));
            }

            for raw_value in setting.values {
                if is_project_layer
                    && project_layer_env_expansion_is_sensitive(key.as_ref())
                    && (contains_active_env_interpolation(&setting.key)
                        || contains_active_env_interpolation(raw_value.value.as_ref()))
                {
                    cfg.push_security_warning(source_label, || {
                        format!(
                            "{source_label}:{}: env expansion in project-local .npmrc for '{diagnostic_key}' refused: \
                             move this registry/auth/TLS setting to user config or use registry-scoped auth",
                            raw_value.line,
                        )
                    });
                    continue;
                }

                let value = match interpolate_npmrc_env(raw_value.value.as_ref(), env_lookup) {
                    Ok(value) => value,
                    Err(error) => {
                        cfg.push_error(source_label, || {
                            format!(
                                "{source_label}:{}: npm config value interpolation failed: {error}",
                                raw_value.line
                            )
                        });
                        continue;
                    }
                };
                if !reserve_expanded_npmrc_data(&mut cfg, value.len(), source_label) {
                    return cfg;
                }
                classify_and_apply(
                    key.as_ref(),
                    value.as_ref(),
                    ApplyContext {
                        diagnostic_key: diagnostic_key.as_ref(),
                        source_label,
                        source_dir,
                        is_project_layer,
                        lineno: raw_value.line,
                    },
                    &mut cfg,
                );
            }
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

fn reserve_expanded_npmrc_data(
    config: &mut NpmrcConfig,
    additional_bytes: usize,
    source_label: &str,
) -> bool {
    let next = config.expanded_data_bytes.saturating_add(additional_bytes);
    if next > lpm_common::NPMRC_INTERPOLATED_VALUE_CAP_BYTES {
        config.push_error(source_label, || {
            format!(
                "{source_label}: aggregate npm configuration expansion exceeds the {}-byte limit",
                lpm_common::NPMRC_INTERPOLATED_VALUE_CAP_BYTES
            )
        });
        return false;
    }
    config.expanded_data_bytes = next;
    true
}

fn npmrc_key_is_credential(key: &str) -> bool {
    if matches!(key, "_authToken" | "_auth" | "username" | "_password") {
        return true;
    }

    let Some((_, attr)) = split_scoped_key(key) else {
        return false;
    };
    matches!(attr, "_authToken" | "_auth" | "username" | "_password")
}

fn split_scoped_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("//")?;
    let (scope, attr) = rest.rsplit_once(':')?;
    (!scope.is_empty() && !attr.is_empty()).then_some((scope, attr))
}

fn contains_active_env_interpolation(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'\\' {
            let start = index;
            while index < bytes.len() && bytes[index] == b'\\' {
                index += 1;
            }
            if index + 1 < bytes.len()
                && bytes[index] == b'$'
                && bytes[index + 1] == b'{'
                && (index - start) % 2 == 0
            {
                return true;
            }
            continue;
        }
        if bytes[index] == b'$' && bytes[index + 1] == b'{' {
            return true;
        }
        index += value[index..]
            .chars()
            .next()
            .expect("index is within value")
            .len_utf8();
    }
    false
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

    let Some((_, attr)) = split_scoped_key(key) else {
        return false;
    };
    matches!(
        attr,
        "_authToken" | "_auth" | "_password" | "username" | "cafile" | "certfile" | "keyfile"
    )
}

fn is_unscoped_legacy_auth_key(key: &str) -> bool {
    matches!(
        key,
        "_auth" | "_authToken" | "username" | "_password" | "email" | "certfile" | "keyfile"
    )
}

fn is_known_npm_config_key(key: &str) -> bool {
    const KNOWN: &[&str] = &[
        "_auth",
        "access",
        "all",
        "allow-directory",
        "allow-file",
        "allow-git",
        "allow-remote",
        "allow-same-version",
        "allow-scripts",
        "allow-scripts-pending",
        "allow-scripts-pin",
        "allow-unused-patches",
        "also",
        "audit",
        "audit-level",
        "auth-type",
        "before",
        "bin-links",
        "browser",
        "bypass-2fa",
        "ca",
        "cache",
        "cache-max",
        "cache-min",
        "cafile",
        "call",
        "cert",
        "cidr",
        "color",
        "commit-hooks",
        "cpu",
        "dangerously-allow-all-scripts",
        "depth",
        "description",
        "dev",
        "diff",
        "diff-dst-prefix",
        "diff-ignore-all-space",
        "diff-name-only",
        "diff-no-prefix",
        "diff-src-prefix",
        "diff-text",
        "diff-unified",
        "dry-run",
        "edit-dir",
        "editor",
        "engine-strict",
        "expect-result-count",
        "expect-results",
        "expires",
        "extension-file",
        "fetch-retries",
        "fetch-retry-factor",
        "fetch-retry-maxtimeout",
        "fetch-retry-mintimeout",
        "fetch-timeout",
        "force",
        "foreground-scripts",
        "format-package-lock",
        "fund",
        "git",
        "git-tag-version",
        "global",
        "global-ignore-file",
        "global-style",
        "globalconfig",
        "heading",
        "https-proxy",
        "if-present",
        "ignore-existing",
        "ignore-extension",
        "ignore-patch-failures",
        "ignore-scripts",
        "include",
        "include-attestations",
        "include-staged",
        "include-workspace-root",
        "init-author-email",
        "init-author-name",
        "init-author-url",
        "init-license",
        "init-module",
        "init-private",
        "init-type",
        "init-version",
        "init.author.email",
        "init.author.name",
        "init.author.url",
        "init.license",
        "init.module",
        "init.version",
        "install-links",
        "install-strategy",
        "json",
        "keep-edit-dir",
        "key",
        "legacy-bundling",
        "legacy-peer-deps",
        "libc",
        "link",
        "local-address",
        "location",
        "lockfile-version",
        "loglevel",
        "logs-dir",
        "logs-max",
        "long",
        "maxsockets",
        "message",
        "min-release-age",
        "min-release-age-exclude",
        "name",
        "node-gyp",
        "node-options",
        "noproxy",
        "offline",
        "omit",
        "omit-lockfile-registry-resolved",
        "only",
        "optional",
        "orgs",
        "orgs-permission",
        "os",
        "otp",
        "pack-destination",
        "package",
        "package-lock",
        "package-lock-only",
        "packages",
        "packages-all",
        "packages-and-scopes-permission",
        "parseable",
        "password",
        "patches-dir",
        "prefer-dedupe",
        "prefer-offline",
        "prefer-online",
        "prefix",
        "preid",
        "production",
        "progress",
        "provenance",
        "provenance-file",
        "proxy",
        "read-only",
        "rebuild-bundle",
        "registry",
        "replace-registry-host",
        "save",
        "save-bundle",
        "save-dev",
        "save-exact",
        "save-optional",
        "save-peer",
        "save-prefix",
        "save-prod",
        "sbom-format",
        "sbom-type",
        "scope",
        "scopes",
        "script-shell",
        "searchexclude",
        "searchlimit",
        "searchopts",
        "searchstaleness",
        "shell",
        "sign-git-commit",
        "sign-git-tag",
        "strict-allow-scripts",
        "strict-npmrc",
        "strict-peer-deps",
        "strict-ssl",
        "tag",
        "tag-version-prefix",
        "timing",
        "to",
        "token-description",
        "umask",
        "unicode",
        "update-notifier",
        "usage",
        "user-agent",
        "userconfig",
        "version",
        "versions",
        "viewer",
        "which",
        "workspace",
        "workspaces",
        "workspaces-update",
        "yes",
    ];

    KNOWN.binary_search(&key).is_ok()
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
#[derive(Clone, Copy)]
struct ApplyContext<'a> {
    diagnostic_key: &'a str,
    source_label: &'a str,
    source_dir: Option<&'a Path>,
    is_project_layer: bool,
    lineno: usize,
}

fn classify_and_apply(key: &str, value: &str, context: ApplyContext<'_>, cfg: &mut NpmrcConfig) {
    let ApplyContext {
        diagnostic_key,
        source_label,
        source_dir,
        is_project_layer,
        lineno,
    } = context;
    // Scope registry: `@foo:registry`.
    if key.starts_with('@')
        && let Some(scope) = key.strip_suffix(":registry")
    {
        if value.is_empty() {
            cfg.push_warning(source_label, || {
                format!(
                    "{source_label}:{lineno}: empty registry URL for '{diagnostic_key}'; skipped"
                )
            });
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
            cfg.push_warning(source_label, || {
                format!("{source_label}:{lineno}: empty registry URL; skipped")
            });
            return;
        }
        cfg.default_registry = Some(RegistryTarget::from_npmrc_url(value));
        return;
    }

    if is_unscoped_legacy_auth_key(key) {
        if value.is_empty() {
            return;
        }
        if is_project_layer && matches!(key, "certfile" | "keyfile") {
            cfg.push_security_warning(source_label, || {
                format!(
                    "{source_label}:{lineno}: project-local '{diagnostic_key}' refused; TLS client identities must come from user or system config"
                )
            });
            return;
        }
        cfg.push_error(source_label, || {
            format!(
                "{source_label}:{lineno}: unscoped legacy auth key '{diagnostic_key}' is invalid; use '//host/:{diagnostic_key}=...' registry-scoped auth syntax"
            )
        });
        return;
    }

    // Origin-scoped auth: `//host[:port][/path]/:_<attr>`.
    if key.starts_with("//") {
        if let Some((origin_part, attr)) = split_scoped_key(key) {
            let Some(scope) = AuthScope::from_npmrc_scope(origin_part) else {
                cfg.push_warning(source_label, || {
                    format!(
                        "{source_label}:{lineno}: cannot parse origin from auth key '{diagnostic_key}'; skipped"
                    )
                });
                return;
            };
            let is_tls_attr = matches!(attr, "cafile" | "certfile" | "keyfile");
            if is_project_layer && is_tls_attr {
                cfg.push_security_warning(source_label, || {
                    format!(
                        "{source_label}:{lineno}: project-local TLS key '{diagnostic_key}' refused; TLS trust and client identities must come from user or system config"
                    )
                });
                return;
            }
            if scope.path_prefix.as_ref() != "/" && is_tls_attr {
                cfg.push_security_warning(source_label, || {
                    format!(
                        "{source_label}:{lineno}: path-scoped TLS key '{diagnostic_key}' refused because the HTTP client cache cannot safely confine TLS state by path"
                    )
                });
                return;
            }
            // Auth subkeys go into the per-origin auth buffer; TLS subkeys
            // go into the per-origin TLS buffer. Two distinct entry maps share
            // the same `OriginKey` so a matching-origin lookup fetches both.
            match attr {
                "_authToken" => {
                    cfg.auth_buffers.entry(scope).or_default().auth_token =
                        Some(TaggedValue::new(value.to_string(), source_label, lineno));
                }
                "_auth" => {
                    cfg.auth_buffers.entry(scope).or_default().auth_b64 =
                        Some(TaggedValue::new(value.to_string(), source_label, lineno));
                }
                "username" => {
                    cfg.auth_buffers.entry(scope).or_default().username =
                        Some(TaggedValue::new(value.to_string(), source_label, lineno));
                }
                "_password" => {
                    cfg.auth_buffers.entry(scope).or_default().password_b64 =
                        Some(TaggedValue::new(value.to_string(), source_label, lineno));
                }
                "email" => {}
                "cafile" => {
                    // Per-origin extra root. DEFERRED-READ by design: the PEM
                    // is read at client-build time for the matching origin,
                    // NOT at parse time. Unrelated `.npmrc` entries (e.g., a
                    // stale path on a shared `~/.npmrc`) cannot break installs
                    // that never reach the configured origin.
                    if value.is_empty() {
                        cfg.push_warning(source_label, || {
                            format!(
                                "{source_label}:{lineno}: empty per-origin cafile path; skipped"
                            )
                        });
                        return;
                    }
                    cfg.tls
                        .per_origin
                        .entry(scope.origin)
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
                        cfg.push_warning(source_label, || {
                            format!(
                                "{source_label}:{lineno}: empty per-origin certfile path; skipped"
                            )
                        });
                        return;
                    }
                    cfg.tls.per_origin.entry(scope.origin).or_default().certfile =
                        Some(TaggedPath {
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
                        cfg.push_warning(source_label, || {
                            format!(
                                "{source_label}:{lineno}: empty per-origin keyfile path; skipped"
                            )
                        });
                        return;
                    }
                    cfg.tls.per_origin.entry(scope.origin).or_default().keyfile =
                        Some(TaggedPath {
                            path: PathBuf::from(value),
                            source: source_label.to_string(),
                            line: lineno,
                            source_dir: source_dir.map(|p| p.to_path_buf()),
                        });
                }
                _ if !is_known_npm_config_key(attr) => {
                    cfg.push_unknown_config(diagnostic_key, source_label, lineno);
                }
                _ => {}
            }
            return;
        }
        // Malformed: starts with `//` but has no scoped attribute suffix.
        cfg.push_warning(source_label, || {
            format!(
                "{source_label}:{lineno}: auth key '{diagnostic_key}' has no ':<attr>' suffix; skipped"
            )
        });
        return;
    }

    // Globally-scoped TLS settings.
    if is_project_layer && matches!(key, "ca" | "cafile") {
        cfg.push_security_warning(source_label, || {
            format!(
                "{source_label}:{lineno}: project-local '{diagnostic_key}' refused; TLS trust and client identities must come from user or system config"
            )
        });
        return;
    }
    if key == "cafile" {
        if value.is_empty() {
            cfg.push_warning(source_label, || {
                format!("{source_label}:{lineno}: empty cafile path; skipped")
            });
            return;
        }
        cfg.pending_cafile = Some(TaggedPath {
            path: PathBuf::from(value),
            source: source_label.to_string(),
            line: lineno,
            source_dir: source_dir.map(Path::to_path_buf),
        });
        return;
    }
    if key == "ca" {
        if value == "null" {
            cfg.pending_ca_roots = Some(Vec::new());
            return;
        }
        if value.is_empty() {
            cfg.push_warning(source_label, || {
                format!("{source_label}:{lineno}: empty ca PEM value; skipped")
            });
            return;
        }
        // `.npmrc` is line-based; npm encodes multi-line PEMs as a single
        // line using literal `\n` escapes:
        //   ca = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
        // Decode those to real newlines so the marker check and downstream
        // `reqwest::Certificate::from_pem` see structurally-valid PEM.
        let decoded = decode_npmrc_pem_escapes(value);
        if !contains_pem_certificate_block(decoded.as_bytes()) {
            cfg.push_warning(source_label, || {
                format!(
                    "{source_label}:{lineno}: ca PEM contains no \
                     '-----BEGIN CERTIFICATE-----' block; skipped"
                )
            });
            return;
        }
        cfg.pending_ca_roots
            .get_or_insert_with(Vec::new)
            .push(TaggedRoot {
                pem_bytes: Arc::new(decoded.into_owned().into_bytes()),
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
                    cfg.push_security_warning(source_label, || {
                        format!(
                            "{source_label}:{lineno}: strict-ssl=false refused — \
                             project-local .npmrc cannot disable TLS verification; \
                             move the setting to ~/.npmrc if you really want it"
                        )
                    });
                    return;
                }
                cfg.tls.strict_ssl = Some(TaggedBool {
                    value: false,
                    source: source_label.to_string(),
                    line: lineno,
                });
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
                cfg.push_warning(source_label, || {
                    format!("{source_label}:{lineno}: strict-ssl is not a boolean; ignored")
                });
            }
        }
        return;
    }
    if key == "strict-npmrc" {
        match value {
            "true" | "false" => {
                cfg.strict_npmrc = Some(TaggedBool {
                    value: value == "true",
                    source: source_label.to_string(),
                    line: lineno,
                });
            }
            _ => cfg.push_warning(source_label, || {
                format!("{source_label}:{lineno}: strict-npmrc expects true or false; skipped")
            }),
        }
        return;
    }

    if !is_known_npm_config_key(key) {
        cfg.push_unknown_config(diagnostic_key, source_label, lineno);
    }
}

impl NpmrcConfig {
    pub(super) fn materialize_global_tls(&mut self) {
        if let Some(cafile) = self.pending_cafile.take() {
            let resolved = cafile.resolve();
            match read_regular_file_capped_with_metadata(
                &resolved,
                TLS_MATERIAL_FILE_SIZE_CAP_BYTES,
            ) {
                Ok((bytes, _)) if contains_pem_certificate_block(&bytes) => {
                    self.tls.extra_roots = vec![TaggedRoot {
                        pem_bytes: Arc::new(bytes),
                        source: cafile.source,
                        line: cafile.line,
                    }];
                }
                Ok(_) => {
                    self.tls.extra_roots.clear();
                    self.push_warning(&cafile.source, || {
                        format!(
                            "{}:{}: cafile contains no '-----BEGIN CERTIFICATE-----' block; skipped",
                            cafile.source, cafile.line
                        )
                    });
                }
                Err(error) => {
                    self.tls.extra_roots.clear();
                    self.push_error(&cafile.source, || {
                        format!(
                            "{}:{}: cafile='{}': failed to read: {error}",
                            cafile.source,
                            cafile.line,
                            resolved.display()
                        )
                    });
                }
            }
            self.pending_ca_roots = None;
        } else if let Some(roots) = self.pending_ca_roots.take() {
            self.tls.extra_roots = roots;
        }
    }
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
fn decode_npmrc_pem_escapes(s: &str) -> std::borrow::Cow<'_, str> {
    let bytes = s.as_bytes();
    let Some(first_escape) = bytes
        .windows(2)
        .position(|pair| pair == b"\\n" || pair == b"\\r")
    else {
        return std::borrow::Cow::Borrowed(s);
    };

    let mut decoded = String::with_capacity(s.len());
    decoded.push_str(&s[..first_escape]);
    let mut copied_until = first_escape;
    let mut index = first_escape;
    while index + 1 < bytes.len() {
        let replacement = match &bytes[index..index + 2] {
            b"\\n" => Some('\n'),
            b"\\r" => Some('\r'),
            _ => None,
        };
        if let Some(replacement) = replacement {
            decoded.push_str(&s[copied_until..index]);
            decoded.push(replacement);
            index += 2;
            copied_until = index;
        } else {
            index += 1;
        }
    }
    decoded.push_str(&s[copied_until..]);
    std::borrow::Cow::Owned(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::npmrc::{OriginKey, RegistryAuth, RegistryKind};
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

    #[test]
    fn plain_ini_values_and_uninterpolated_env_values_remain_borrowed() {
        assert!(matches!(
            lpm_common::decode_npmrc_ini_fragment("plain-value"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            interpolate_npmrc_env("plain-value", &no_env).unwrap(),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            lpm_common::decode_npmrc_ini_fragment("value # comment"),
            Cow::Owned(_)
        ));
        assert!(matches!(
            interpolate_npmrc_env("${TOKEN}", &no_env).unwrap(),
            Cow::Borrowed(_)
        ));
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
    fn missing_env_var_remains_literal() {
        let content = "//npm.internal/:_authToken=${NPM_TOKEN}\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.errors.is_empty());
        match cfg.auth_for_url("https://npm.internal/").unwrap() {
            RegistryAuth::Bearer { token, .. } => {
                assert_eq!(token.expose_secret(), "${NPM_TOKEN}")
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
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
            "//npm.internal/:username=user\n\
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
        let content = "registry=https://good.example.com/\nfund\nfund=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.warnings.len(), 1);
        assert!(cfg.warnings[0].contains("test:2"));
    }

    #[test]
    fn unknown_file_keys_warn_by_default() {
        let content = concat!(
            "engine-strict=true\n",
            "save-prefix=^\n",
            "registri=https://typo.example/\n",
            "registry=https://good.example.com/\n",
        );
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.default_registry.is_some());
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("registri"));
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
    }

    #[test]
    fn unknown_npmrc_diagnostics_are_bounded_before_formatting() {
        let content = (0..1_000)
            .map(|index| format!("unknown-{index}=value\n"))
            .collect::<String>();

        let cfg = NpmrcConfig::parse(&content, "test", &no_env);

        assert!(cfg.warnings.len() <= lpm_common::NPMRC_DIAGNOSTIC_LIMIT + 1);
        assert!(
            cfg.warnings
                .last()
                .is_some_and(|warning| warning.contains("suppressed")),
            "suppression must be visible: {:?}",
            cfg.warnings
        );
    }

    #[test]
    fn strict_npmrc_makes_unknown_file_keys_fatal() {
        let cfg = NpmrcConfig::parse(
            "strict-npmrc=true\nregistri=https://typo.example/\n",
            "test",
            &no_env,
        );
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("registri"));
    }

    #[test]
    fn interpolated_npmrc_secrets_are_not_echoed_in_diagnostics() {
        let secret = "npm_secret_diagnostic_canary";
        let config = NpmrcConfig::parse(
            "${UNKNOWN_KEY}=value\nstrict-ssl=${SECRET}\nstrict-npmrc=${SECRET}\n",
            "test",
            &|name| match name {
                "UNKNOWN_KEY" | "SECRET" => Some(secret.to_string()),
                _ => None,
            },
        );

        for diagnostic in config
            .warnings
            .iter()
            .chain(config.errors.iter())
            .chain(config.security_warnings.iter())
        {
            assert!(
                !diagnostic.contains(secret),
                "interpolated secret leaked through npmrc diagnostics: {diagnostic}"
            );
        }
        assert!(
            !format!("{config:?}").contains(secret),
            "interpolated secrets must not appear in configuration Debug output"
        );
    }

    #[test]
    fn aggregate_npmrc_interpolation_is_bounded_per_configuration() {
        let mut content = String::new();
        for index in 0..700 {
            use std::fmt::Write as _;
            writeln!(
                content,
                "//registry-{index}.example/${{LONG_PATH}}/:_authToken=token-{index}"
            )
            .unwrap();
        }
        let config = NpmrcConfig::parse(&content, "test", &|name| {
            (name == "LONG_PATH").then(|| "x".repeat(8 * 1024))
        });

        assert!(
            config
                .errors
                .iter()
                .any(|error| error.contains("aggregate") && error.contains("limit")),
            "expanded settings must have one cumulative memory bound: {:?}",
            config.errors
        );
    }

    #[test]
    fn effective_strict_npmrc_applies_after_layer_merging() {
        let mut config = NpmrcConfig::parse_layer("strict-npmrc=true\n", "user", &no_env);
        config.merge_over(NpmrcConfig::parse_layer(
            "registri=value\n",
            "project",
            &no_env,
        ));
        config.finalize();
        assert_eq!(config.errors.len(), 1);
        assert!(config.errors[0].contains("project:1"));
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
        assert_eq!(root.pem_bytes.as_ref(), pem.as_bytes());
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
    fn cafile_larger_than_tls_limit_is_a_fatal_configuration_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-ca.pem");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(TLS_MATERIAL_FILE_SIZE_CAP_BYTES + 1).unwrap();
        let content = format!("cafile={}\n", path.display());

        let cfg = NpmrcConfig::parse(&content, "test", &no_env);

        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(
            cfg.errors[0].contains(&path.display().to_string())
                && cfg.errors[0].contains("1048576-byte limit"),
            "error must identify CA path and limit: {}",
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
            root.pem_bytes.as_ref(),
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
        let stored = cfg.tls.extra_roots[0].pem_bytes.as_ref();
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
    fn cafile_takes_precedence_over_ca_in_the_same_layer() {
        let pem_a = generate_test_cert_pem();
        let pem_b = generate_test_cert_pem();
        let dir = tempfile::tempdir().unwrap();
        let cafile_path = dir.path().join("a.pem");
        std::fs::write(&cafile_path, &pem_a).unwrap();
        let escaped_b = pem_b.replace('\n', "\\n");
        let content = format!("cafile={}\nca={escaped_b}\n", cafile_path.display());
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert_eq!(cfg.tls.extra_roots.len(), 1);
        assert_eq!(cfg.tls.extra_roots[0].pem_bytes.as_ref(), pem_a.as_bytes());
        assert_eq!(cfg.tls.extra_roots[0].line, 1);
    }

    #[test]
    fn lower_cafile_remains_effective_when_higher_layer_sets_ca() {
        let lower_pem = generate_test_cert_pem();
        let higher_pem = generate_test_cert_pem().replace('\n', "\\n");
        let dir = tempfile::tempdir().unwrap();
        let cafile_path = dir.path().join("lower.pem");
        std::fs::write(&cafile_path, &lower_pem).unwrap();
        let mut config = NpmrcConfig::parse_layer(
            &format!("cafile={}\n", cafile_path.display()),
            "lower",
            &no_env,
        );
        config.merge_over(NpmrcConfig::parse_layer(
            &format!("ca={higher_pem}\n"),
            "higher",
            &no_env,
        ));
        config.finalize();

        assert!(config.errors.is_empty(), "errors: {:?}", config.errors);
        assert_eq!(config.tls.extra_roots.len(), 1);
        assert_eq!(
            config.tls.extra_roots[0].pem_bytes.as_ref(),
            lower_pem.as_bytes()
        );
        assert_eq!(config.tls.extra_roots[0].source, "lower");
    }

    #[test]
    fn higher_ca_replaces_lower_ca() {
        let pem_lower = generate_test_cert_pem().replace('\n', "\\n");
        let pem_higher = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem_lower}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem_higher}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(acc.tls.extra_roots.len(), 1);
        assert_eq!(acc.tls.extra_roots[0].source, "higher");
    }

    #[test]
    fn higher_ca_null_clears_lower_custom_roots() {
        let pem = generate_test_cert_pem().replace('\n', "\\n");
        let mut config = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "lower", &no_env);
        config.merge_over(NpmrcConfig::parse_layer("ca=null\n", "higher", &no_env));
        config.finalize();
        assert!(config.tls.extra_roots.is_empty());
        assert!(
            config.warnings.is_empty(),
            "warnings: {:?}",
            config.warnings
        );
    }

    #[test]
    fn identical_higher_ca_replaces_lower_source_attribution() {
        let pem = generate_test_cert_pem().replace('\n', "\\n");
        let mut acc = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "lower", &no_env);
        let higher = NpmrcConfig::parse_layer(&format!("ca={pem}\n"), "higher", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(
            acc.tls.extra_roots.len(),
            1,
            "the effective scalar CA has one value"
        );
        assert_eq!(
            acc.tls.extra_roots[0].source, "higher",
            "the winning layer owns error attribution"
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

    #[cfg(unix)]
    #[test]
    fn global_cafile_rejects_a_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("ca.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let content = format!("cafile={}\n", fifo.display());

        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(NpmrcConfig::parse(&content, "test", &no_env))
                .unwrap();
        });
        let config = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(config) => config,
            Err(error) => {
                let writer = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                drop(writer);
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                worker.join().unwrap();
                panic!("global cafile loading blocked on a FIFO: {error}");
            }
        };
        worker.join().unwrap();
        assert!(
            config
                .errors
                .iter()
                .any(|error| error.contains("regular file")),
            "a special-file cafile must be rejected explicitly: {:?}",
            config.errors
        );
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
    fn removed_always_auth_key_warns_as_unknown() {
        for v in ["true", "false", "always"] {
            let content = format!("always-auth={v}\n");
            let cfg = NpmrcConfig::parse(&content, "test", &no_env);
            assert_eq!(
                cfg.warnings.len(),
                1,
                "warnings for value {v}: {:?}",
                cfg.warnings
            );
            assert!(cfg.warnings[0].contains("always-auth"));
            assert!(
                cfg.errors.is_empty(),
                "errors for value {v}: {:?}",
                cfg.errors
            );
        }
    }

    #[test]
    fn removed_scoped_always_auth_key_warns_as_unknown() {
        let content = "//npm.internal/:always-auth=true\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.warnings.len(), 1, "warnings: {:?}", cfg.warnings);
        assert!(cfg.warnings[0].contains("always-auth"));
    }

    // ---- per-origin TLS / mTLS parsing ----

    #[test]
    fn unscoped_certfile_and_keyfile_are_invalid_auth() {
        let cfg = NpmrcConfig::parse("certfile=/path/cert.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("certfile"));
        assert!(cfg.errors[0].contains("unscoped"));

        let cfg = NpmrcConfig::parse("keyfile=/path/key.pem\n", "test", &no_env);
        assert_eq!(cfg.errors.len(), 1, "errors: {:?}", cfg.errors);
        assert!(cfg.errors[0].contains("test:1"));
        assert!(cfg.errors[0].contains("keyfile"));
        assert!(cfg.errors[0].contains("unscoped"));
    }

    #[test]
    fn unscoped_auth_values_report_registry_scoping_repairs() {
        let password = encoded_npmrc_password("pass");
        let cfg = NpmrcConfig::parse(
            &format!(
                "_authToken=token\n_auth=dXNlcjpwYXNz\nusername=alice\n_password={password}\nemail=alice@example.test\n"
            ),
            "user/.npmrc",
            &no_env,
        );
        assert_eq!(cfg.errors.len(), 5, "errors: {:?}", cfg.errors);
        assert!(
            cfg.errors
                .iter()
                .all(|error| error.contains("unscoped") && error.contains("//host/:"))
        );
        assert!(cfg.origin_auth.is_empty());
    }

    #[test]
    fn unscoped_certfile_and_keyfile_pair_is_not_materialized() {
        let content = "certfile=/path/cert.pem\nkeyfile=/path/key.pem\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert_eq!(cfg.errors.len(), 2, "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert!(cfg.tls.identity_certfile.is_none());
        assert!(cfg.tls.identity_keyfile.is_none());
    }

    #[test]
    fn unscoped_identity_errors_survive_layer_merging() {
        let mut acc = NpmrcConfig::parse_layer("certfile=/etc/cert.pem\n", "system", &no_env);
        let higher = NpmrcConfig::parse_layer("keyfile=/home/u/key.pem\n", "user", &no_env);
        acc.merge_over(higher);
        acc.finalize();
        assert_eq!(acc.errors.len(), 2, "errors: {:?}", acc.errors);
        assert!(acc.tls.identity_certfile.is_none());
        assert!(acc.tls.identity_keyfile.is_none());
    }

    #[test]
    fn empty_unscoped_certfile_is_ignored() {
        let cfg = NpmrcConfig::parse("certfile=\n", "test", &no_env);
        // Empty value warned + skipped means no certfile is set,
        // which means no XOR fatal either.
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty());
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
    fn portless_tls_does_not_match_an_explicit_nondefault_port() {
        let cfg = NpmrcConfig::parse("//npm.internal/:cafile=/path/ca.pem\n", "test", &no_env);
        assert!(cfg.tls_for_url("https://npm.internal/pkg").is_some());
        let with_port = OriginKey {
            host_lower: "npm.internal".into(),
            port: Some(8443),
        };
        assert!(cfg.tls_for_origin(&with_port).is_none());
        let other_host = OriginKey {
            host_lower: "other.internal".into(),
            port: Some(443),
        };
        assert!(cfg.tls_for_origin(&other_host).is_none());
    }

    #[test]
    fn higher_per_origin_cafile_replaces_the_lower_scalar() {
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
        assert_eq!(per_origin.cafiles.len(), 1);
        assert_eq!(per_origin.cafiles[0].source, "user");
    }

    #[test]
    fn parse_layer_with_source_dir_tags_scoped_tls_paths_for_resolve() {
        let dir = std::path::Path::new("/etc/npm");
        let content = "//npm.internal/:cafile=ca.pem\n\
                       //npm.internal/:certfile=client.pem\n\
                       //npm.internal/:keyfile=client.key\n";
        let cfg =
            NpmrcConfig::parse_layer_with_source_dir(content, "/etc/npmrc", Some(dir), &no_env);
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
    fn parse_layer_without_source_dir_leaves_scoped_paths_unchanged() {
        let cfg = NpmrcConfig::parse(
            "//npm.internal/:certfile=/abs/cert.pem\n\
             //npm.internal/:keyfile=relative.pem\n",
            "test",
            &no_env,
        );
        let tls = cfg.tls_for_url("https://npm.internal/pkg").unwrap();
        let cert = tls.certfile.as_ref().unwrap();
        assert!(cert.source_dir.is_none());
        assert_eq!(cert.resolve(), PathBuf::from("/abs/cert.pem"));

        let key = tls.keyfile.as_ref().unwrap();
        assert!(key.source_dir.is_none());
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
        // every `:`" refactor of the username/_password join.
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
            "//npm.internal/:username=user\n\
             //npm.internal/:_password={encoded_pw}\n"
        );
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        assert!(cfg.errors.is_empty(), "errors: {:?}", cfg.errors);
        assert!(cfg.warnings.is_empty(), "warnings: {:?}", cfg.warnings);
        assert_eq!(cfg.origin_auth.len(), 1);
        let auth = cfg.origin_auth.values().next().unwrap();
        match auth.as_ref() {
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
            NpmrcConfig::parse_layer("//npm.internal/:username=alice\n", "/etc/npmrc", &no_env);
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
        // higher layer's, but lower layer's username survives because
        // higher doesn't set one.
        let old_password = encoded_npmrc_password("old-pw");
        let lower = NpmrcConfig::parse_layer(
            &format!("//npm.internal/:username=alice\n//npm.internal/:_password={old_password}\n"),
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
    fn explicit_default_port_key_does_not_match_a_normalized_url() {
        let content = "//npm.internal:443/:_authToken=HTTPS_ONLY\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(cfg.auth_for_url("https://npm.internal/").is_none());
        assert!(
            cfg.auth_for_url("http://npm.internal/").is_none(),
            "explicit :443 must not leak to normalized portless URLs"
        );
    }

    // ---- source-label in finalize warnings ----

    #[test]
    fn partial_credential_warning_cites_source() {
        // Single-file partial: only username, no _password.
        // Warning must mention `~/.npmrc:7` (the source + line) and
        // the origin, so a user with multiple .npmrc files can find
        // and fix the offender.
        let content = "\n\n\n\n\n\n//npm.internal/:username=alice\n";
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
            NpmrcConfig::parse_layer("//npm.internal/:username=alice\n", "/etc/npmrc", &no_env);
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
            scope: AuthScope::from_origin(OriginKey {
                host_lower: "example.com".to_string(),
                port: None,
            }),
            token: SecretString::from("very-secret"),
        };
        let formatted = format!("{auth:?}");
        assert!(!formatted.contains("very-secret"));
        assert!(formatted.contains("REDACTED"));
        assert!(!formatted.contains("example.com"));
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
        assert_eq!(key.port, None);
    }

    #[test]
    fn from_request_url_strips_user_and_password_userinfo() {
        let key = OriginKey::from_request_url("https://user:pass@registry.npmjs.org/foo").unwrap();
        assert_eq!(key.host_lower, "registry.npmjs.org");
        assert_eq!(key.port, None);
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
        assert_eq!(key.host_lower, "::1");
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

    #[test]
    fn path_prefixed_auth_key_is_confined_to_its_registry_path() {
        let content = "//gitlab.com/api/v4/projects/123/packages/npm/:_authToken=glpat-x\n";
        let cfg = NpmrcConfig::parse(content, "test", &no_env);
        assert!(
            cfg.auth_for_url("https://gitlab.com/api/v4/projects/123/packages/npm/foo")
                .is_some(),
            "path-scoped credential must match its declared path",
        );
        assert!(
            cfg.auth_for_url("https://gitlab.com/api/v4/projects/other/packages/npm/foo")
                .is_none(),
            "path-scoped credential must not reach a sibling path",
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
        // Precedence: _authToken > _auth > username/_password.
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

    #[test]
    fn standard_username_and_password_materialize_basic_auth() {
        let password = encoded_npmrc_password("pass");
        let content =
            format!("//npm.internal/:username=alice\n//npm.internal/:_password={password}\n");
        let cfg = NpmrcConfig::parse(&content, "test", &no_env);
        let auth = cfg
            .auth_for_url("https://npm.internal/package")
            .expect("standard npm username key must combine with _password");
        match auth {
            RegistryAuth::Basic { credential, .. } => assert_eq!(
                credential.expose_secret(),
                encoded_basic_credential("alice", "pass")
            ),
            other => panic!("expected Basic auth, got {other:?}"),
        }
    }

    #[test]
    fn path_scoped_auth_uses_the_longest_matching_prefix() {
        let cfg = NpmrcConfig::parse(
            "//registry.example/:_authToken=root\n\
             //registry.example/api/:_authToken=api\n\
             //registry.example/api/projects/one/:_authToken=project\n",
            "test",
            &no_env,
        );

        let project = cfg
            .auth_for_url("https://registry.example/api/projects/one/pkg")
            .expect("project prefix must match");
        let api = cfg
            .auth_for_url("https://registry.example/api/projects/two/pkg")
            .expect("api prefix must match");
        let root = cfg
            .auth_for_url("https://registry.example/other/pkg")
            .expect("root prefix must match");
        fn bearer_token(auth: &RegistryAuth) -> &str {
            match auth {
                RegistryAuth::Bearer { token, .. } => token.expose_secret(),
                other => panic!("expected Bearer auth, got {other:?}"),
            }
        }
        assert_eq!(bearer_token(project), "project");
        assert_eq!(bearer_token(api), "api");
        assert_eq!(bearer_token(root), "root");
        assert!(
            cfg.auth_for_url("https://registry.example/apiv2/pkg")
                .is_some_and(|auth| bearer_token(auth) == "root"),
            "path matching must respect segment boundaries"
        );
    }

    #[test]
    fn path_scoped_auth_without_a_slash_before_the_attribute_matches_segment_boundaries() {
        let cfg = NpmrcConfig::parse("//registry.example/api:_authToken=api\n", "test", &no_env);
        assert!(cfg.auth_for_url("https://registry.example/api").is_some());
        assert!(
            cfg.auth_for_url("https://registry.example/api/pkg")
                .is_some()
        );
        assert!(cfg.auth_for_url("https://registry.example/apiv2").is_none());
    }

    #[test]
    fn portless_auth_does_not_match_an_explicit_nondefault_port() {
        let cfg = NpmrcConfig::parse(
            "//npm.internal/:_authToken=default\n//npm.internal:8443/:_authToken=alternate\n",
            "test",
            &no_env,
        );
        let ordinary = cfg
            .auth_for_url("https://npm.internal/pkg")
            .expect("portless URL must match portless auth");
        let alternate = cfg
            .auth_for_url("https://npm.internal:8443/pkg")
            .expect("explicit port must match exact auth");
        match (ordinary, alternate) {
            (
                RegistryAuth::Bearer {
                    token: ordinary, ..
                },
                RegistryAuth::Bearer {
                    token: alternate, ..
                },
            ) => {
                assert_eq!(ordinary.expose_secret(), "default");
                assert_eq!(alternate.expose_secret(), "alternate");
            }
            other => panic!("expected bearer credentials, got {other:?}"),
        }

        let portless_only =
            NpmrcConfig::parse("//npm.internal/:_authToken=default\n", "test", &no_env);
        assert!(
            portless_only
                .auth_for_url("https://npm.internal:8443/pkg")
                .is_none(),
            "portless auth must not widen to an explicitly different port"
        );
    }

    #[test]
    fn ipv6_auth_and_tls_origins_match_request_urls() {
        let cfg = NpmrcConfig::parse(
            "//[::1]:8443/:_authToken=ipv6\n//[::1]:8443/:cafile=/unused/ca.pem\n",
            "test",
            &no_env,
        );
        assert!(
            cfg.auth_for_url("https://[::1]:8443/pkg").is_some(),
            "IPv6 auth key must use the request URL's canonical host form"
        );
        assert!(
            cfg.tls_for_url("https://[::1]:8443/pkg").is_some(),
            "IPv6 TLS key must use the request URL's canonical host form"
        );
    }

    #[test]
    fn npm_env_interpolation_keeps_missing_values_and_supports_optional_and_escaped_forms() {
        let cfg = NpmrcConfig::parse(
            "ignored=${MISSING}\n\
             @${SCOPE}:registry=https://registry.example/${MISSING}\n\
             //registry.example/:_authToken=${TOKEN?}\n\
             literal=\\${ESCAPED}\n",
            "test",
            &fixed_env(&[("SCOPE", "private")]),
        );

        assert!(cfg.errors.is_empty(), "npm leaves missing values literal");
        assert_eq!(
            cfg.scope_registries["@private"].base_url.as_ref(),
            "https://registry.example/${MISSING}"
        );
        assert!(
            cfg.auth_for_url("https://registry.example/pkg").is_none(),
            "an unset optional token must not materialize an empty credential"
        );
    }

    #[test]
    fn ini_comments_escapes_and_quoted_json_values_match_npm() {
        let cfg = NpmrcConfig::parse(
            "registry=https://registry.example/ ; comment\n\
             //registry.example/:_authToken=abc\\;def ; comment\n\
             @quoted:registry=\"https://registry.example/\\u0061\"\n",
            "test",
            &no_env,
        );
        assert_eq!(
            cfg.default_registry.as_ref().unwrap().base_url.as_ref(),
            "https://registry.example"
        );
        assert_eq!(
            cfg.scope_registries["@quoted"].base_url.as_ref(),
            "https://registry.example/a"
        );
        match cfg
            .auth_for_url("https://registry.example/pkg")
            .expect("escaped token must parse")
        {
            RegistryAuth::Bearer { token, .. } => assert_eq!(token.expose_secret(), "abc;def"),
            other => panic!("expected Bearer auth, got {other:?}"),
        }
    }

    #[test]
    fn ca_arrays_preserve_order_and_scalar_ca_uses_last_value() {
        let first = generate_test_cert_pem();
        let second = generate_test_cert_pem();
        let third = generate_test_cert_pem();
        let array_cfg = NpmrcConfig::parse(
            &format!(
                "ca[]={first}\nca[]={second}\n",
                first = first.replace('\n', "\\n"),
                second = second.replace('\n', "\\n")
            ),
            "test",
            &no_env,
        );
        assert_eq!(array_cfg.tls.extra_roots.len(), 2);
        assert_eq!(
            array_cfg.tls.extra_roots[0].pem_bytes.as_ref(),
            first.as_bytes()
        );
        assert_eq!(
            array_cfg.tls.extra_roots[1].pem_bytes.as_ref(),
            second.as_bytes()
        );

        let scalar_cfg = NpmrcConfig::parse(
            &format!(
                "ca={first}\nca={third}\n",
                first = first.replace('\n', "\\n"),
                third = third.replace('\n', "\\n")
            ),
            "test",
            &no_env,
        );
        assert_eq!(scalar_cfg.tls.extra_roots.len(), 1);
        assert_eq!(
            scalar_cfg.tls.extra_roots[0].pem_bytes.as_ref(),
            third.as_bytes()
        );
    }

    #[test]
    fn higher_cafile_replaces_a_missing_lower_cafile_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let pem = generate_test_cert_pem();
        let valid = dir.path().join("valid.pem");
        std::fs::write(&valid, &pem).unwrap();
        let lower = NpmrcConfig::parse_layer_with_source_dir(
            "cafile=missing.pem\n",
            "lower/.npmrc",
            Some(dir.path()),
            &no_env,
        );
        let higher = NpmrcConfig::parse_layer_with_source_dir(
            "cafile=valid.pem\n",
            "higher/.npmrc",
            Some(dir.path()),
            &no_env,
        );
        let mut merged = lower;
        merged.merge_over(higher);
        merged.finalize();

        assert!(
            merged.errors.is_empty(),
            "a missing lower cafile must not remain an effective configuration error"
        );
        assert_eq!(merged.tls.extra_roots.len(), 1);
        assert_eq!(merged.tls.extra_roots[0].pem_bytes.as_ref(), pem.as_bytes());
    }

    #[test]
    fn relative_scoped_identity_paths_resolve_beside_their_npmrc() {
        let config_dir = tempfile::tempdir().unwrap();
        let cfg = NpmrcConfig::parse_layer_with_source_dir(
            "//registry.example/:certfile=client.pem\n\
             //registry.example/:keyfile=client.key\n",
            "user/.npmrc",
            Some(config_dir.path()),
            &no_env,
        );
        let tls = cfg
            .tls_for_url("https://registry.example/pkg")
            .expect("scoped identity");
        assert_eq!(
            tls.certfile.as_ref().map(TaggedPath::resolve),
            Some(config_dir.path().join("client.pem"))
        );
        assert_eq!(
            tls.keyfile.as_ref().map(TaggedPath::resolve),
            Some(config_dir.path().join("client.key"))
        );
    }

    #[test]
    fn higher_strict_ssl_true_suppresses_a_shadowed_false_warning() {
        let mut merged = NpmrcConfig::parse_layer("strict-ssl=false\n", "lower", &no_env);
        merged.merge_over(NpmrcConfig::parse_layer(
            "strict-ssl=true\n",
            "higher",
            &no_env,
        ));
        merged.finalize();
        assert_eq!(
            merged.tls.strict_ssl.as_ref().map(|value| value.value),
            Some(true)
        );
        assert!(
            merged
                .warnings
                .iter()
                .all(|warning| !warning.contains("DISABLED")),
            "shadowed warning is false: {:?}",
            merged.warnings
        );
    }

    #[test]
    fn empty_credentials_shadow_lower_values_without_materializing_auth() {
        for key in ["_authToken", "_auth"] {
            let mut merged = NpmrcConfig::parse_layer(
                &format!("//registry.example/:{key}=secret\n"),
                "lower",
                &no_env,
            );
            merged.merge_over(NpmrcConfig::parse_layer(
                &format!("//registry.example/:{key}=\n"),
                "higher",
                &no_env,
            ));
            merged.finalize();
            assert!(
                merged
                    .auth_for_url("https://registry.example/pkg")
                    .is_none(),
                "empty {key} must clear lower auth"
            );
        }
    }

    #[test]
    fn project_layer_refuses_literal_tls_trust_and_identity_settings() {
        let pem = generate_test_cert_pem().replace('\n', "\\n");
        let cfg = NpmrcConfig::parse_layer_with_options(
            &format!(
                "ca={pem}\ncafile=ca.pem\ncertfile=client.pem\nkeyfile=client.key\n\
                 //registry.example/:cafile=ca.pem\n\
                 //registry.example/:certfile=client.pem\n\
                 //registry.example/:keyfile=client.key\n"
            ),
            "project/.npmrc",
            None,
            true,
            &no_env,
        );
        assert!(cfg.tls.extra_roots.is_empty());
        assert!(cfg.tls.identity_certfile.is_none());
        assert!(cfg.tls.identity_keyfile.is_none());
        assert!(cfg.tls.per_origin.is_empty());
        assert_eq!(cfg.security_warnings.len(), 7);
    }

    #[test]
    fn debug_redacts_credentials_before_finalize() {
        let cfg = NpmrcConfig::parse_layer(
            "//registry.example/:_authToken=raw-token\n\
             //other.example/:_auth=dXNlcjpwYXNz\n\
             //third.example/:_password=c2VjcmV0\n",
            "test",
            &no_env,
        );
        let debug = format!("{cfg:?}");
        for secret in ["raw-token", "dXNlcjpwYXNz", "c2VjcmV0"] {
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
    }

    #[test]
    fn merged_layers_share_one_aggregate_interpolation_budget() {
        let expansion = "x".repeat(lpm_common::NPMRC_INTERPOLATED_VALUE_CAP_BYTES / 2);
        let env = |name: &str| (name == "LARGE_SCOPE").then(|| expansion.clone());
        let content = "//registry.example/${LARGE_SCOPE}/:_authToken=secret\n";
        let mut merged = NpmrcConfig::parse_layer(content, "lower", &env);
        let higher = NpmrcConfig::parse_layer(content, "higher", &env);

        assert!(merged.errors.is_empty());
        assert!(higher.errors.is_empty());
        merged.merge_over(higher);

        assert!(
            merged
                .errors
                .iter()
                .any(|error| error.contains("across merged layers")),
            "merged expansion budget must fail closed: {:?}",
            merged.errors
        );
    }
}
