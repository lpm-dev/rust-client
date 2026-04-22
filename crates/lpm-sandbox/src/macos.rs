//! macOS Seatbelt (`sandbox-exec`) backend. Phase 46 P5 Chunk 1 stub —
//! the real profile synthesis + `sandbox-exec` wrapping lands in Chunk 2.
//!
//! The stub constructs successfully (so [`crate::new_for_platform`] can
//! return a concrete backend on macOS) but every spawn surfaces a
//! [`crate::SandboxError::ProfileRenderFailed`] naming the deferral.
//! That keeps the factory contract stable between chunks without
//! silently no-op'ing containment on a platform that's supposed to
//! have it.

#![cfg(target_os = "macos")]

use crate::{Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxedCommand};

pub(crate) struct SeatbeltSandbox {
    #[allow(dead_code)] // consumed by the real impl in Chunk 2
    spec: SandboxSpec,
    mode: SandboxMode,
}

impl SeatbeltSandbox {
    pub(crate) fn new(spec: SandboxSpec, mode: SandboxMode) -> Result<Self, SandboxError> {
        Ok(Self { spec, mode })
    }
}

impl Sandbox for SeatbeltSandbox {
    fn spawn(&self, _cmd: SandboxedCommand) -> Result<std::process::Child, SandboxError> {
        Err(SandboxError::ProfileRenderFailed {
            reason: "Seatbelt backend not yet implemented — Phase 46 P5 Chunk 2 wires the \
				sandbox-exec profile + spawn path"
                .to_string(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "seatbelt"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }
}
