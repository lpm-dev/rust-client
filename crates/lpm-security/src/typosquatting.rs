//! Typosquatting detection for LPM.
//!
//! Compares package names against a curated list of popular npm packages
//! using Levenshtein distance. Warns (but does not block) when a name
//! is suspiciously similar to a well-known package.
//!
//! Operates entirely offline — no network required.

use strsim::levenshtein;

/// Top ~100 most popular npm packages by weekly downloads.
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
	"vue",
	"angular",
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

/// Check if a package name is suspiciously similar to a popular package.
///
/// Returns the popular package name if a potential typosquat is detected.
/// Scoped packages (starting with `@`) are skipped because they have
/// owner verification via the registry.
///
/// Threshold logic:
/// - Short names (<=5 chars): distance must be exactly 1 (very strict to avoid
///   false positives on common short words like "glob", "cors")
/// - Longer names (>5 chars): distance up to 2 allowed
///
/// Exact matches return `None` (user wants the real package).
pub fn check_typosquatting(name: &str) -> Option<&'static str> {
	// Scoped packages have owner verification — skip
	if name.starts_with('@') {
		return None;
	}

	// Exact match = user wants the real thing
	if POPULAR_PACKAGES.contains(&name) {
		return None;
	}

	for &popular in POPULAR_PACKAGES {
		let distance = levenshtein(name, popular);
		let threshold = if popular.len() <= 5 { 1 } else { 2 };
		if distance > 0 && distance <= threshold {
			return Some(popular);
		}
	}

	None
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
	fn no_detect_axois_transposition() {
		// "axois" is distance 2 from "axios" (5 chars, threshold 1) — no match
		assert_eq!(check_typosquatting("axois"), None);
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
	fn no_warn_unique() {
		assert_eq!(check_typosquatting("my-cool-package"), None);
	}

	#[test]
	fn no_warn_scoped() {
		assert_eq!(check_typosquatting("@scope/lodash"), None);
	}

	#[test]
	fn no_warn_scoped_lpm() {
		assert_eq!(check_typosquatting("@lpm.dev/owner.lodash"), None);
	}

	#[test]
	fn no_false_positive_on_short_unrelated() {
		// "glob" is 4 chars. "blog" is distance 2, which exceeds threshold 1 for short names.
		assert_eq!(check_typosquatting("blog"), None);
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
