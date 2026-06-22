//! v2 store layout primitives — on-disk shape and identity helpers
//! for the virtual-store rewrite. Writes are gated behind
//! `LPM_STORE_VERSION=v2` until the default flip lands.
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
//!   produce incorrect cross-distro reuse)
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

pub use graph_key::{DepEdge, GraphKey, GraphKeyInputs, LinkerModeTag, PeerEntry};
pub use link_meta::{
    LINK_META_FILENAME, LINK_META_SCHEMA_VERSION, LinkMeta, LinkMetaDep, LinkMetaPlatform,
};
pub use platform::PlatformTuple;
pub use store::{
    COMPAT_ISLAND_COMPLETE_FILENAME, CompatIslandKeyEntry, DepLink, ExtractedObject,
    FreshObjectIntegrity, LinkEntry, LinkEntryRequest, LinkEntryTimings, ReusableObject,
    ReusableObjectCheckTimings, Store, StoreV2Paths, VerifiedObjectIntegrity, compat_island_key,
};
