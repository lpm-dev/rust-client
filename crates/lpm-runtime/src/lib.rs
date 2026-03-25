//! Runtime version management for LPM.
//!
//! Downloads, installs, and manages Node.js versions. Integrates with
//! the runner to auto-switch per project based on `lpm.json`, `package.json`
//! engines, `.nvmrc`, or `.node-version`.
//!
//! Storage layout:
//! ```text
//! ~/.lpm/runtimes/
//!   node/
//!     22.5.0/
//!       bin/node
//!       bin/npm
//!       bin/npx
//!     20.18.0/
//!       ...
//!   index-cache.json   ← cached Node.js release index (1h TTL)
//! ```

pub mod detect;
pub mod download;
pub mod node;
pub mod platform;
