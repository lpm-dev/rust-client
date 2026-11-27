//! Agent Skill files as LPM reads them: frontmatter parsing, the security
//! patterns that block a skill, the rules a package's authored skills meet
//! to publish, and the checks a `skills/<name>/SKILL.md` directory passes
//! before LPM exposes it to coding agents. The CLI checks them before upload
//! and before linking, and the registry, running this crate as WebAssembly,
//! checks them on upload, so both apply the same rules with the same
//! messages.

mod review;
mod scan;
mod skill_directory;
mod validate;

pub use review::*;
pub use scan::*;
pub use skill_directory::*;
pub use validate::*;
