//! Typosquatting detection for LPM.
//!
//! Compares package names against a curated list of popular npm packages
//! using low-noise typo techniques plus Levenshtein distance.
//!
//! Operates entirely offline — no network required.

use strsim::levenshtein;

/// Popular npm packages plus well-known framework package names.
/// Hardcoded for offline operation — no network needed.
const POPULAR_PACKAGES: &[&str] = &[
    "lodash",
    "chalk",
    "react",
    "express",
    "debug",
    "moment",
    "commander",
    "axios",
    "tslib",
    "semver",
    "uuid",
    "glob",
    "yargs",
    "minimist",
    "dotenv",
    "fs-extra",
    "mkdirp",
    "rimraf",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "underscore",
    "async",
    "bluebird",
    "request",
    "inquirer",
    "body-parser",
    "cors",
    "jsonwebtoken",
    "mongoose",
    "mysql",
    "pg",
    "redis",
    "socket.io",
    "passport",
    "bcrypt",
    "nodemailer",
    "multer",
    "helmet",
    "morgan",
    "compression",
    "cookie-parser",
    "cross-env",
    "http-errors",
    "serve-static",
    "path-to-regexp",
    "accepts",
    "content-type",
    "type-is",
    "mime",
    "negotiator",
    "fresh",
    "etag",
    "on-finished",
    "statuses",
    "depd",
    "inherits",
    "readable-stream",
    "safe-buffer",
    "string_decoder",
    "buffer",
    "events",
    "fsevents",
    "util",
    "process",
    "punycode",
    "qs",
    "url",
    "querystring",
    "crypto-browserify",
    "stream-browserify",
    "assert",
    "os-browserify",
    "path-browserify",
    "vm-browserify",
    "next",
    "nuxt",
    "vue",
    "angular",
    "astro",
    "svelte",
    "solid-js",
    "preact",
    "lit",
    "tailwindcss",
    "postcss",
    "autoprefixer",
    "sass",
    "less",
    "babel",
    "rollup",
    "vite",
    "esbuild",
    "storybook",
    "swc",
    "turbo",
    "prisma",
    "drizzle-orm",
    "sequelize",
    "typeorm",
    "knex",
    "zod",
    "yup",
    "joi",
    "ajv",
    "superstruct",
    "date-fns",
    "dayjs",
    "luxon",
    "sharp",
    "jimp",
    "canvas",
    "puppeteer",
    "playwright",
    "cypress",
];

const KNOWN_LEGITIMATE_COLLISIONS: &[&str] = &[
    "bcryptjs",
    "canvafy",
    "canvg",
    "chat",
    "croact",
    "deps",
    "enquirer",
    "eslintcc",
    "esplint",
    "evnty",
    "globo",
    "json-web-token",
    "mssql",
    "mysql2",
    "negotiate",
    "never",
    "ngreact",
    "oxlint",
    "prism",
    "prismjs",
    "storyblok",
    "sveld",
    "ts-extras",
    "ttypescript",
    "type-fns",
    "typeit",
    "typeon",
    "uuid4",
    "vike",
];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TyposquatTechnique {
    DelimiterVariant,
    AdjacentTransposition,
    EditDistance,
}

impl TyposquatTechnique {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DelimiterVariant => "delimiter_variant",
            Self::AdjacentTransposition => "adjacent_transposition",
            Self::EditDistance => "edit_distance",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TyposquatFinding {
    pub similar: &'static str,
    pub technique: TyposquatTechnique,
}

/// Extract the bare package name from a potentially scoped package name.
///
/// - `@lpm.dev/owner.loadash` → `loadash` (strips scope + owner prefix)
/// - `@scope/lodash` → `lodash` (strips npm scope)
/// - `lodash` → `lodash` (unchanged)
pub fn extract_package_name(name: &str) -> &str {
    if let Some(rest) = name.strip_prefix("@lpm.dev/") {
        return rest.find('.').map_or(rest, |dot_pos| &rest[dot_pos + 1..]);
    }

    if name.starts_with('@') {
        name.split('/').nth(1).unwrap_or(name)
    } else {
        name
    }
}

/// Check if a package name is suspiciously similar to a popular package.
///
/// Returns the popular package name if a potential typosquat is detected.
/// For scoped packages (`@lpm.dev/owner.pkg` or `@scope/pkg`), the package
/// name is extracted before comparison so typosquats in scoped names are caught.
///
/// Threshold logic:
/// - If either name is short (<=5 chars): distance must be exactly 1 (very
///   strict to avoid false positives on common short words like "glob", "cors")
/// - Longer names (>5 chars): distance up to 2 allowed
///
/// Exact matches return `None` (user wants the real package).
pub fn check_typosquatting(name: &str) -> Option<&'static str> {
    analyze_typosquatting(name).map(|finding| finding.similar)
}

pub fn analyze_typosquatting(name: &str) -> Option<TyposquatFinding> {
    if name.starts_with('@') && !name.starts_with("@lpm.dev/") {
        return None;
    }

    let bare_name = extract_package_name(name);

    // Exact match = user wants the real thing
    if POPULAR_PACKAGES.contains(&bare_name) {
        return None;
    }
    if KNOWN_LEGITIMATE_COLLISIONS.contains(&bare_name) {
        return None;
    }

    for &popular in POPULAR_PACKAGES {
        if is_delimiter_variant(bare_name, popular) {
            return Some(TyposquatFinding {
                similar: popular,
                technique: TyposquatTechnique::DelimiterVariant,
            });
        }
    }

    for &popular in POPULAR_PACKAGES {
        if popular.len() >= 5 && is_adjacent_transposition(bare_name, popular) {
            return Some(TyposquatFinding {
                similar: popular,
                technique: TyposquatTechnique::AdjacentTransposition,
            });
        }
    }

    for &popular in POPULAR_PACKAGES {
        if bare_name.len() < 4 || popular.len() < 4 {
            continue;
        }
        let distance = levenshtein(bare_name, popular);
        let threshold = if bare_name.len() <= 5 || popular.len() <= 5 {
            1
        } else {
            2
        };
        if distance > 0 && distance <= threshold {
            return Some(TyposquatFinding {
                similar: popular,
                technique: TyposquatTechnique::EditDistance,
            });
        }
    }

    None
}

fn is_delimiter_variant(candidate: &str, popular: &str) -> bool {
    if candidate == popular {
        return false;
    }
    let candidate_has_delimiter = has_name_delimiter(candidate);
    let popular_has_delimiter = has_name_delimiter(popular);
    if !candidate_has_delimiter && !popular_has_delimiter {
        return false;
    }

    normalized_without_delimiters(candidate) == normalized_without_delimiters(popular)
}

fn has_name_delimiter(name: &str) -> bool {
    name.bytes().any(|b| matches!(b, b'-' | b'_' | b'.'))
}

fn normalized_without_delimiters(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for b in name.bytes() {
        if !matches!(b, b'-' | b'_' | b'.') {
            normalized.push(char::from(b));
        }
    }
    normalized
}

fn is_adjacent_transposition(candidate: &str, popular: &str) -> bool {
    if candidate.len() != popular.len() || candidate == popular {
        return false;
    }

    let candidate = candidate.as_bytes();
    let popular = popular.as_bytes();
    let mut first_mismatch = None;

    for idx in 0..candidate.len() {
        if candidate[idx] == popular[idx] {
            continue;
        }

        if let Some(first) = first_mismatch {
            return idx == first + 1
                && candidate[first] == popular[idx]
                && candidate[idx] == popular[first]
                && candidate
                    .iter()
                    .zip(popular.iter())
                    .enumerate()
                    .all(|(pos, (left, right))| pos == first || pos == idx || left == right);
        }

        first_mismatch = Some(idx);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_loadash() {
        assert_eq!(check_typosquatting("loadash"), Some("lodash"));
    }

    #[test]
    fn detects_expres() {
        assert_eq!(check_typosquatting("expres"), Some("express"));
    }

    #[test]
    fn detects_expresss() {
        assert_eq!(check_typosquatting("expresss"), Some("express"));
    }

    #[test]
    fn detects_reactt() {
        assert_eq!(check_typosquatting("reactt"), Some("react"));
    }

    #[test]
    fn detects_axois_adjacent_transposition() {
        let finding = analyze_typosquatting("axois").unwrap();
        assert_eq!(finding.similar, "axios");
        assert_eq!(finding.technique, TyposquatTechnique::AdjacentTransposition);
    }

    #[test]
    fn detects_axio() {
        // "axio" is distance 1 from "axios" — should detect
        assert_eq!(check_typosquatting("axio"), Some("axios"));
    }

    #[test]
    fn no_warn_exact() {
        assert_eq!(check_typosquatting("lodash"), None);
    }

    #[test]
    fn no_warn_exact_react() {
        assert_eq!(check_typosquatting("react"), None);
    }

    #[test]
    fn no_warn_exact_fsevents() {
        assert_eq!(check_typosquatting("fsevents"), None);
    }

    #[test]
    fn no_warn_nuxt_framework_package() {
        assert_eq!(check_typosquatting("nuxt"), None);
    }

    #[test]
    fn no_warn_known_legitimate_prism_package() {
        assert_eq!(check_typosquatting("prism"), None);
    }

    #[test]
    fn no_warn_known_legitimate_prismjs_package() {
        assert_eq!(check_typosquatting("prismjs"), None);
    }

    #[test]
    fn no_warn_popular_clean_packages_that_resemble_other_popular_packages() {
        for package in [
            "bcryptjs",
            "chat",
            "enquirer",
            "canvg",
            "canvafy",
            "croact",
            "deps",
            "oxlint",
            "eslintcc",
            "evnty",
            "storyblok",
            "typeit",
            "esplint",
            "globo",
            "json-web-token",
            "mssql",
            "mysql2",
            "negotiate",
            "never",
            "ngreact",
            "sveld",
            "ts-extras",
            "ttypescript",
            "type-fns",
            "typeon",
            "uuid4",
            "vike",
        ] {
            assert_eq!(
                check_typosquatting(package),
                None,
                "{package} is a popular package and must not be reported as a typo"
            );
        }
    }

    #[test]
    fn no_warn_unique() {
        assert_eq!(check_typosquatting("my-cool-package"), None);
    }

    #[test]
    fn no_warn_scoped() {
        assert_eq!(check_typosquatting("@scope/lodash"), None);
    }

    #[test]
    fn no_warn_npm_scoped_typosquat_like_name() {
        assert_eq!(check_typosquatting("@scope/loadash"), None);
    }

    #[test]
    fn no_warn_workspace_scoped_internal_names() {
        assert_eq!(check_typosquatting("@test/utils"), None);
        assert_eq!(check_typosquatting("@smoke/core"), None);
    }

    #[test]
    fn no_warn_dotted_exact_name() {
        assert_eq!(check_typosquatting("socket.io"), None);
    }

    #[test]
    fn detects_delimiter_variant() {
        let finding = analyze_typosquatting("crossenv").unwrap();
        assert_eq!(finding.similar, "cross-env");
        assert_eq!(finding.technique, TyposquatTechnique::DelimiterVariant);
    }

    #[test]
    fn detects_scoped_lpm_typosquat() {
        // @lpm.dev/owner.loadash should detect "lodash" typosquat
        assert_eq!(
            check_typosquatting("@lpm.dev/owner.loadash"),
            Some("lodash")
        );
    }

    #[test]
    fn no_warn_scoped_lpm_exact() {
        // Exact match should not warn
        assert_eq!(check_typosquatting("@lpm.dev/owner.lodash"), None);
    }

    #[test]
    fn extract_package_name_lpm_scoped() {
        assert_eq!(extract_package_name("@lpm.dev/owner.loadash"), "loadash");
    }

    #[test]
    fn extract_package_name_npm_scoped() {
        assert_eq!(extract_package_name("@scope/lodash"), "lodash");
    }

    #[test]
    fn extract_package_name_unscoped() {
        assert_eq!(extract_package_name("lodash"), "lodash");
    }

    #[test]
    fn no_false_positive_on_short_unrelated() {
        // "glob" is 4 chars. "blog" is distance 2, which exceeds threshold 1 for short names.
        assert_eq!(check_typosquatting("blog"), None);
    }

    #[test]
    fn no_warn_legitimate_tiny_package_name() {
        assert_eq!(check_typosquatting("ms"), None);
    }

    #[test]
    fn no_warn_legitimate_short_serve_package() {
        assert_eq!(check_typosquatting("serve"), None);
    }

    #[test]
    fn detects_single_char_typo_short_name() {
        // "glop" is distance 1 from "glob" — should detect
        assert_eq!(check_typosquatting("glop"), Some("glob"));
    }

    #[test]
    fn detects_webpakc() {
        assert_eq!(check_typosquatting("webpakc"), Some("webpack"));
    }

    #[test]
    fn popular_packages_list_is_nonempty() {
        assert!(POPULAR_PACKAGES.len() >= 100);
    }
}
