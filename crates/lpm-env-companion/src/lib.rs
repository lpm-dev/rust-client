//! Companion storage: records kept next to an env project's values item,
//! never inside it, with a feature marker that tells every client what they
//! are and what a client that doesn't support them may do.
//!
//! This crate is the contract the LPM CLI and the LPM Vault app share,
//! the app through the engine's C interface: account names, the marker, the
//! operation matrix, personal overrides, which records a marker lists, and
//! the plans that finish interrupted lifecycle steps. It touches no storage;
//! each client runs it against its own.

pub mod account;
pub mod assessment;
pub mod budgets;
pub mod gate;
pub mod graph;
pub mod invariants;
pub mod lifecycle;
pub mod marker;
pub mod overrides;

#[cfg(test)]
mod contract_tests;
