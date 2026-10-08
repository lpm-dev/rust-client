//! Environment variable schema validation for LPM.
//!
//! Parses an `envSchema` section from `lpm.json` and validates a set of
//! environment variables against it. Validation is synchronous and pure —
//! no network calls, no file I/O. Takes `(schema, env_map)`, returns
//! `Vec<ValidationError>`.
//!
//! # Schema Format
//!
//! ```json
//! {
//!   "envSchema": {
//!     "vars": {
//!       "DATABASE_URL": { "required": true, "format": "url" },
//!       "PORT": { "default": "3000", "format": "port" },
//!       "STRIPE_SECRET_KEY": { "required": true, "secret": true, "pattern": "^sk_(test|live)_.*$" }
//!     }
//!   }
//! }
//! ```

mod constraints;
mod definition;
mod example;
mod inheritance;
mod object;
mod print;
pub mod resolver;
mod schema;
mod scopes;
mod stored;
mod validate;

pub use example::generate as generate_env_example;
pub use inheritance::{EnvDefinition, EnvironmentsConfig, list_environments, resolve_chain};
pub use print::{PrintFormat, format_env, is_valid_env_var_name};
pub use resolver::{EnvSource, ResolvedEnv, extract_mode_from_env_path};
pub use schema::{
    CiStorage, EmptyPolicy, EnvSchema, EnvVarRule, EqualityCondition, PresenceCondition,
    RequiredWhen, VarFormat, VarGroup, VarGroupMode,
};
pub use scopes::{EnvStage, EvalContext, ScopeSelector, ScopedDefault};
pub use stored::{DEFAULT_ENVIRONMENT, is_denied_env_var, reads_default_environment};
pub use validate::{EnvValidator, ValidationError, ValidationErrorKind, validate, validate_schema};

pub use definition::{EnvSchemaDefinition, env_schema_preset};
