//! Script execution engine for LPM.
//!
//! Provides:
//! - `run_script()` — execute package.json scripts with `.bin` PATH injection and pre/post hooks
//! - `exec_file()` — run a JS/TS file directly (auto-detect runtime)
//! - `dlx()` — run a package binary without installing it into the project
//! - PATH injection for `node_modules/.bin`
//! - Pre/post script hook execution (npm convention)
//!
//! # Architecture
//!
//! ```text
//! lpm-runner
//! ├── bin_path   — discover .bin dirs, build PATH
//! ├── hooks      — pre/post script detection and execution
//! ├── script     — package.json script execution with full env
//! ├── shell      — cross-platform shell abstraction
//! ├── exec       — direct file execution (JS/TS)
//! └── dlx        — temporary package execution
//! ```

pub mod bin_path;
pub mod dag;
pub mod dlx;
pub mod dotenv;
pub mod exec;
pub mod hooks;
pub mod lpm_json;
pub mod orchestrator;
pub mod ports;
pub mod ready;
pub mod script;
pub mod service_graph;
pub mod shell;
pub mod task_graph;
