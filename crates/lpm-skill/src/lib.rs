//! Agent Skill files as LPM reads them: frontmatter parsing, the security
//! patterns that block a skill, and the rules a package's authored skills
//! meet to publish. The CLI checks them before upload and the registry,
//! running this crate as WebAssembly, checks them on upload, so both apply
//! the same rules with the same messages.

mod scan;
mod validate;

pub use scan::*;
pub use validate::*;
