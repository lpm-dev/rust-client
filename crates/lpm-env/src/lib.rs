//! Environment variable schema validation for LPM.
//!
//! Parses an `env.schema` section from `lpm.json` and validates a set of
//! environment variables against it. Validation is synchronous and pure —
//! no network calls, no file I/O. Takes `(schema, env_map)`, returns
//! `Vec<ValidationError>`.
//!
//! # Schema Format
//!
//! ```json
//! {
//!   "env": {
//!     "schema": {
//!       "DATABASE_URL": { "required": true, "format": "url" },
//!       "PORT": { "default": "3000", "format": "port" },
//!       "STRIPE_SECRET_KEY": { "required": true, "secret": true, "pattern": "sk_(test|live)_.*" }
//!     }
//!   }
//! }
//! ```

mod example;
mod inheritance;
mod print;
pub mod resolver;
mod schema;
mod validate;

pub use example::generate as generate_env_example;
pub use inheritance::{EnvDefinition, EnvironmentsConfig, list_environments, resolve_chain};
pub use print::{PrintFormat, format_env};
pub use resolver::{EnvSource, ResolvedEnv, extract_mode_from_env_path};
pub use schema::{EnvSchema, EnvVarRule, VarFormat};
pub use validate::{ValidationError, ValidationErrorKind, validate};
