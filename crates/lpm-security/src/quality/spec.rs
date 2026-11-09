//! Every quality check, in the order reports list them: its category, its
//! points, who decides it, and what earns it. Each ecosystem's checks total
//! 100 points.

use serde::Serialize;

/// The four bars of the quality score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Documentation,
    Api,
    Provenance,
    Health,
}

impl Category {
    pub const ALL: [Self; 4] = [
        Self::Documentation,
        Self::Api,
        Self::Provenance,
        Self::Health,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Documentation => "documentation",
            Self::Api => "api",
            Self::Provenance => "provenance",
            Self::Health => "health",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Documentation => "Docs",
            Self::Api => "API",
            Self::Provenance => "Provenance",
            Self::Health => "Health",
        }
    }
}

/// Who decides a check: the archive alone, which the LPM CLI reads, or
/// data only LPM.dev Registry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decider {
    Archive,
    Registry,
}

#[derive(Debug)]
pub struct CheckSpec {
    pub id: &'static str,
    pub category: Category,
    pub max_points: u32,
    pub decider: Decider,
    pub label: &'static str,
    /// How an author earns the check's points.
    pub tip: &'static str,
}

const fn archive(
    id: &'static str,
    category: Category,
    max_points: u32,
    label: &'static str,
    tip: &'static str,
) -> CheckSpec {
    CheckSpec {
        id,
        category,
        max_points,
        decider: Decider::Archive,
        label,
        tip,
    }
}

const fn registry(
    id: &'static str,
    category: Category,
    max_points: u32,
    label: &'static str,
    tip: &'static str,
) -> CheckSpec {
    CheckSpec {
        id,
        category,
        max_points,
        decider: Decider::Registry,
        label,
        tip,
    }
}

use Category::{Api, Documentation, Health, Provenance};

const README: CheckSpec = archive(
    "readme",
    Documentation,
    6,
    "README",
    "Add a README.md at the package root with at least 300 characters of prose, not counting code blocks, badges and HTML.",
);
const CHANGELOG: CheckSpec = archive(
    "changelog",
    Documentation,
    3,
    "Changelog",
    "Add a CHANGELOG.md (or CHANGES or HISTORY) at the package root with an entry that names this version.",
);
const AGENT_SKILLS: CheckSpec = registry(
    "agent-skills",
    Documentation,
    5,
    "Agent Skills",
    "Publish at least one Agent Skill with the package. LPM.dev Registry counts it once its security scan approves it.",
);
const TRUSTED_PUBLISHING: CheckSpec = registry(
    "trusted-publishing",
    Provenance,
    5,
    "Trusted publishing",
    "Publish from CI with trusted publishing (OIDC), such as `lpm publish` in a GitHub Actions job with `id-token: write`.",
);
const SIGNED_PROVENANCE: CheckSpec = registry(
    "signed-provenance",
    Provenance,
    2,
    "Signed provenance",
    "Publish from CI with a Sigstore provenance bundle (`lpm publish --provenance`).",
);
const REPOSITORY_VERIFIED: CheckSpec = registry(
    "repository-verified",
    Provenance,
    2,
    "Repository matches provenance",
    "Publish with trusted publishing from the repository that package.json \"repository\" names.",
);
const VERIFIED_DOMAIN: CheckSpec = registry(
    "verified-domain",
    Provenance,
    3,
    "Owner's verified domain",
    "Verify a domain for the package's owner (the organization, for an organization package) with a DNS TXT record in its LPM.dev settings.",
);
const LICENSE: CheckSpec = archive(
    "license",
    Health,
    5,
    "License",
    "Set \"license\" to a current SPDX expression such as \"MIT\", a LicenseRef-*, or \"SEE LICENSE IN <file>\" with that file in the package. UNLICENSED earns no points: use SEE LICENSE IN for proprietary terms.",
);
const LICENSE_FILE: CheckSpec = archive(
    "license-file",
    Health,
    2,
    "License file",
    "Add a LICENSE, LICENCE or COPYING file at the package root.",
);
const DESCRIPTION: CheckSpec = archive(
    "description",
    Health,
    2,
    "Description",
    "Set \"description\" in package.json to 20 to 280 characters that say what the package does.",
);
const KEYWORDS: CheckSpec = archive(
    "keywords",
    Health,
    1,
    "Keywords",
    "Add at least one entry to \"keywords\" in package.json.",
);
const REPOSITORY: CheckSpec = archive(
    "repository",
    Health,
    3,
    "Repository",
    "Set \"repository\" in package.json to the source repository's URL, such as \"github:owner/repo\" or { \"type\": \"git\", \"url\": \"https://github.com/owner/repo\" }.",
);

static JS_CHECKS: [CheckSpec; 23] = [
    README,
    archive(
        "readme-install",
        Documentation,
        3,
        "Install command",
        "Add a code block to the README with the command that installs this exact package, such as `lpm install @lpm.dev/owner.name` or `npm install @lpm.dev/owner.name`.",
    ),
    archive(
        "readme-example",
        Documentation,
        5,
        "Usage example",
        "Add a ```js or ```ts code block to the README that imports the package by its name (2 points). Import only names the package exports for all 5.",
    ),
    archive(
        "api-docs",
        Documentation,
        10,
        "API docs",
        "Write a doc comment of at least 20 characters above each exported function, class, type and constant in your .d.ts files, or in your ESM entry if you ship none. 80% of exports earn 10 points, 50% earn 6, 20% earn 3.",
    ),
    CHANGELOG,
    AGENT_SKILLS,
    archive(
        "entry-points",
        Api,
        5,
        "Entry points exist",
        "Make every path in main, module, types, typings, bin and exports name a file in the package.",
    ),
    archive(
        "types",
        Api,
        10,
        "Type declarations",
        "Ship type declarations for every exports entry, under import and require: a \"types\" condition, or a .d.ts next to each .js (.d.mts for .mjs, .d.cts for .cjs). Some entries earn 5 points, all earn 10.",
    ),
    archive(
        "esm",
        Api,
        4,
        "ESM entry",
        "Point the \"import\" condition of \"exports\" (or \"module\") at a file with ESM import/export syntax: .mjs, or .js in a package with \"type\": \"module\".",
    ),
    archive(
        "exports-map",
        Api,
        4,
        "Exports map",
        "Add an \"exports\" map whose targets all exist, with \"types\" first and \"default\" last in each condition object.",
    ),
    archive(
        "side-effects",
        Api,
        2,
        "Side effects declared",
        "Declare \"sideEffects\": false in package.json, or list the files that have side effects.",
    ),
    archive(
        "engines",
        Api,
        1,
        "Node.js engines",
        "Add a valid range to \"engines\": { \"node\": \">=20\" } in package.json.",
    ),
    TRUSTED_PUBLISHING,
    SIGNED_PROVENANCE,
    REPOSITORY_VERIFIED,
    VERIFIED_DOMAIN,
    LICENSE,
    LICENSE_FILE,
    DESCRIPTION,
    KEYWORDS,
    REPOSITORY,
    archive(
        "lean-install",
        Health,
        6,
        "Lean install",
        "Depend on fewer packages: dependencies, optional dependencies and required peers count. None earn 6 points; up to 2 earn 5, 5 earn 4, 10 earn 3, 20 earn 2, 40 earn 1.",
    ),
    archive(
        "no-install-scripts",
        Health,
        5,
        "No install scripts",
        "Remove preinstall, install and postinstall scripts, and a root binding.gyp (npm runs node-gyp for it at install). Ship prebuilt files instead.",
    ),
];

const JS_CLEAN_ARCHIVE: CheckSpec = archive(
    "clean-archive",
    Health,
    6,
    "Clean archive",
    "Keep .env files (.env.example, .env.sample and .env.template are fine), .git/, coverage/, OS and editor files, nested .tgz archives and unbundled node_modules out of the package with \"files\" or .npmignore, and keep it under 10 MB unpacked.",
);

static SWIFT_CHECKS: [CheckSpec; 22] = [
    README,
    archive(
        "readme-install",
        Documentation,
        3,
        "Install instructions",
        "Add a code block to the README with `.package(id: \"lpmdev.owner_name\", from: \"1.0.0\")` or `lpm install @lpm.dev/owner.name`.",
    ),
    archive(
        "readme-example",
        Documentation,
        5,
        "Usage example",
        "Add a ```swift code block to the README that imports one of the package's library modules (2 points) and uses its public API (all 5).",
    ),
    archive(
        "api-docs",
        Documentation,
        10,
        "API docs",
        "Write a /// doc comment of at least 20 characters directly above each public or open declaration outside Tests/. 80% of them earn 10 points, 50% earn 6, 20% earn 3.",
    ),
    CHANGELOG,
    AGENT_SKILLS,
    archive(
        "public-api",
        Api,
        4,
        "Public API",
        "Mark the declarations consumers use as public or open.",
    ),
    archive(
        "platforms",
        Api,
        5,
        "Platforms",
        "Declare the platforms you support with minimum versions in Package.swift, such as platforms: [.iOS(.v17), .macOS(.v14)].",
    ),
    archive(
        "swift-6",
        Api,
        6,
        "Swift 6",
        "Use swift-tools-version 5.9 or later for 3 points, and the Swift 6 language mode on every target (swift-tools-version: 6.0 with no .v5 language mode) for all 6.",
    ),
    archive(
        "versioned-deps",
        Api,
        5,
        "Versioned dependencies",
        "Give every dependency a version requirement (from:, exact: or a range) instead of a branch, a revision or a local path.",
    ),
    archive(
        "no-unsafe-flags",
        Api,
        4,
        "No unsafe flags",
        "Remove unsafeFlags from target settings. SwiftPM refuses them in a versioned dependency.",
    ),
    archive(
        "has-tests",
        Api,
        6,
        "Tests",
        "Add a test target whose directory holds a Swift file with an XCTestCase subclass or a @Test function.",
    ),
    TRUSTED_PUBLISHING,
    SIGNED_PROVENANCE,
    REPOSITORY_VERIFIED,
    VERIFIED_DOMAIN,
    LICENSE,
    LICENSE_FILE,
    DESCRIPTION,
    KEYWORDS,
    REPOSITORY,
    archive(
        "lean-deps",
        Health,
        7,
        "Lean dependencies",
        "Depend on fewer packages. None earn 7 points; 1 earns 6, 2 earn 5, up to 4 earn 4, 6 earn 3, 10 earn 2, 20 earn 1.",
    ),
];

const SWIFT_CLEAN_ARCHIVE: CheckSpec = archive(
    "clean-archive",
    Health,
    6,
    "Clean archive",
    "Keep .build/, .swiftpm/, xcuserdata, DerivedData and .git/ out of the package.",
);

/// The ecosystems the quality score covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QualityEcosystem {
    Js,
    Swift,
}

impl QualityEcosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Js => "js",
            Self::Swift => "swift",
        }
    }
}

/// An ecosystem's checks in report order.
pub fn checks(ecosystem: QualityEcosystem) -> impl Iterator<Item = &'static CheckSpec> {
    let (list, clean): (&'static [CheckSpec], &'static CheckSpec) = match ecosystem {
        QualityEcosystem::Js => (&JS_CHECKS, &JS_CLEAN_ARCHIVE),
        QualityEcosystem::Swift => (&SWIFT_CHECKS, &SWIFT_CLEAN_ARCHIVE),
    };
    list.iter().chain(std::iter::once(clean))
}

/// The check `id` of `ecosystem`.
pub fn check(ecosystem: QualityEcosystem, id: &str) -> Option<&'static CheckSpec> {
    checks(ecosystem).find(|spec| spec.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ecosystem_totals_100_points_with_unique_ids() {
        for ecosystem in [QualityEcosystem::Js, QualityEcosystem::Swift] {
            let total: u32 = checks(ecosystem).map(|spec| spec.max_points).sum();
            assert_eq!(total, 100, "{ecosystem:?}");
            let mut ids: Vec<_> = checks(ecosystem).map(|spec| spec.id).collect();
            let count = ids.len();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(ids.len(), count, "{ecosystem:?} repeats an id");
        }
    }

    #[test]
    fn category_totals_match_the_published_bars() {
        let totals = |ecosystem| {
            Category::ALL.map(|category| {
                checks(ecosystem)
                    .filter(|spec| spec.category == category)
                    .map(|spec| spec.max_points)
                    .sum::<u32>()
            })
        };
        assert_eq!(totals(QualityEcosystem::Js), [32, 26, 12, 30]);
        assert_eq!(totals(QualityEcosystem::Swift), [32, 30, 12, 26]);
    }

    #[test]
    fn every_check_has_a_tip() {
        for ecosystem in [QualityEcosystem::Js, QualityEcosystem::Swift] {
            for spec in checks(ecosystem) {
                assert!(spec.tip.len() > 20, "{}", spec.id);
            }
        }
    }
}
