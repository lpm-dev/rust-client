//! Phase 66 Phase 4a — v2 store layout primitives.
//!
//! This module ships the on-disk shape and identity helpers for the
//! virtual-store rewrite ([Phase 66 preplan §2]). It is **dead code in
//! Phase 4a**: no install or read pipeline references the types yet.
//! Phase 4b wires writes behind `LPM_STORE_VERSION=v2`; Phase 4c teaches
//! the read paths to honor v2; Phase 4d flips the default.
//!
//! [Phase 66 preplan §2]: ../../../../../tolgaergin/a-package-manager/DOCS/new-features/37-rust-client-RUNNER-VISION-phase66-preplan.md
//!
//! # Layout
//!
//! ```text
//! $HOME/.lpm/store/v2/
//! ├── objects/<sri>/                 # Content-addressable extracted bytes
//! └── links/<graph-key>/
//!     ├── node_modules/
//!     │   ├── <pkg>/                 # Clonefile from objects/<sri>
//!     │   └── <dep_local>/           # Symlink → ../../<other-graph-key>/node_modules/<dep>
//!     └── .lpm-link-meta.json        # Sidecar (see [`link_meta`])
//! ```
//!
//! # Identity model
//!
//! Two installations of the same `(name, version)` are interchangeable
//! iff their [`GraphKey`] inputs match. The key folds in:
//!
//! - canonical name + exact version
//! - platform tuple `(os, cpu, libc)` — libc is `Some` only on Linux
//!   (sharp / esbuild ship per-libc binaries, so collapsing it would
//!   produce incorrect cross-distro reuse — preplan §2.2 audit lock-in)
//! - peer-context (empty in hoisted mode; sorted `name@version` list
//!   in isolated mode)
//! - dep edges `(local_name → target_name@version)` — preserves the
//!   isolated linker's [`LinkTarget::dependencies`] identity contract
//! - npm-alias edges `(local_name → canonical_target_name)` —
//!   preserves [`LinkTarget::aliases`]
//! - root-link names — preserves [`LinkTarget::root_link_names`]
//!
//! [`LinkTarget::dependencies`]: ../../../lpm-linker/src/lib.rs
//! [`LinkTarget::aliases`]: ../../../lpm-linker/src/lib.rs
//! [`LinkTarget::root_link_names`]: ../../../lpm-linker/src/lib.rs
//!
//! See [`GraphKey::derive`] for the exact byte layout fed into BLAKE3.

pub mod graph_key;
pub mod link_meta;
pub mod platform;
pub mod store;

pub use graph_key::{GraphKey, GraphKeyInputs};
pub use link_meta::{LINK_META_FILENAME, LINK_META_SCHEMA_VERSION, LinkMeta, LinkMetaDep};
pub use platform::PlatformTuple;
pub use store::{LinkEntry, LinkEntryRequest, Store, StoreV2Paths};
