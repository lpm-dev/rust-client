//! Shared secret-file path catalog consumed by Seatbelt (macOS),
//! the Linux user-namespace bind-mount overlay, and Windows
//! AppContainer DACL policy.
//!
//! Single source of truth so a new entry in one backend can't drift
//! out of sync with the other. Previously each backend kept its own
//! private const list and a `cfg(target_os = "macos")` symmetry test
//! caught drift only on macOS hosts; centralising the lists makes
//! the invariant a type-system one (all backends import the same
//! `&'static [&'static str]` and any add lands in both places).
//!
//! The lists describe paths LIFECYCLE SCRIPTS may not read despite
//! sitting inside the project tree — `.env`, `.npmrc`, `.aws/...`,
//! `*.pem`, etc. Backends apply them differently:
//!
//! - **macOS**: `seatbelt::render_secret_denies` emits SBPL
//!   `(literal ...)` / `(subpath ...)` / `(regex ...)` deny rules
//!   after the broad project_dir allow; last-match-wins makes the
//!   deny override the allow for these paths.
//! - **Linux**: `linux_secret_overlay::enumerate_project_secrets`
//!   stats / walks the project tree and produces a list of
//!   existing-file paths; the child pre_exec then bind-mounts
//!   `/dev/null` over each.
//! - **Windows**: the same enumerator removes the AppContainer SID's
//!   grants from each secret and blocks inheritance of the broad
//!   project read grant while the child runs, then restores the
//!   original DACL.
//!
//! Per-user / per-project `script-read-allow` overrides are
//! applied at consumption time by each backend.

/// Project-relative paths whose `file-read*` is denied even though
/// they sit under the project root.
///
/// `.env.<variant>` is enumerated rather than regex-matched because
/// the common variants are well-known, the flat list is grep-able
/// from one place, and an exact `(literal ...)` rule cannot
/// accidentally over-match a sibling file (e.g. a hypothetical
/// `.environment` config that some tool ships).
pub(crate) const SECRET_LITERAL_PATHS: &[&str] = &[
    // dotenv conventions (next.js, vite, dotenv-flow, etc.)
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.staging",
    ".env.staging.local",
    ".env.test",
    ".env.test.local",
    ".envrc",
    // package-manager auth files (npm / yarn / pnpm / pip)
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
    ".pypirc",
    // shell / HTTP auth files
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".htpasswd",
    // git config (can carry credential URLs)
    ".git/config",
    ".git/credentials",
    // ssh keys conventionally committed at project root
    "id_rsa",
    "id_rsa.pub",
    "id_ecdsa",
    "id_ecdsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "id_dsa",
    "id_dsa.pub",
];

/// Project-relative subdirs whose `file-read*` is denied wholesale.
/// macOS uses a single `(subpath ...)` rule per entry. Linux and
/// Windows walk inside with a depth cap and protect each regular file.
pub(crate) const SECRET_SUBPATH_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".kube",
    ".gcp",
    ".config/gcloud",
    ".terraform",
    "secrets",
    "secret",
];

/// Filename suffixes denied under `project_dir` wherever the backend's
/// documented traversal reaches.
///
/// macOS converts each suffix into an SBPL regex
/// (`/.*<escaped-ext>$`) anchored at the canonicalized project_dir
/// prefix. Linux and Windows match the raw encoded filename bytes
/// during the bounded, pruned project walk.
///
/// Each entry starts with `.` and may contain multiple dots
/// (`.tfvars.json` is one entry, not `.json`). The macOS regex
/// builder escapes dots accordingly.
pub(crate) const SECRET_FILE_EXTENSIONS: &[&str] = &[
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".tfstate",
    ".tfvars",
    ".tfvars.json",
];
