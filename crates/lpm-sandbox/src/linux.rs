//! Linux landlock backend. Phase 46 P5 Chunk 1 stub — the real
//! ruleset construction + `pre_exec` hook lands in Chunk 3.
//!
//! The stub constructs successfully but every spawn surfaces a
//! [`crate::SandboxError::ProfileRenderFailed`] naming the deferral.
//! Chunk 3 replaces this impl with one that negotiates the landlock
//! ABI, builds the ruleset, and installs it in the forked child
//! before `execve` via [`std::os::unix::process::CommandExt::pre_exec`].
//!
//! Kernels older than 5.13 will surface
//! [`crate::SandboxError::KernelTooOld`] per the refuse-to-run stance
//! agreed in the Chunk 1 signoff (symmetric with the Windows path);
//! that detection logic lands in Chunk 3.

#![cfg(target_os = "linux")]

use crate::{Sandbox, SandboxError, SandboxMode, SandboxSpec, SandboxedCommand};

pub(crate) struct LandlockSandbox {
    #[allow(dead_code)] // consumed by the real impl in Chunk 3
    spec: SandboxSpec,
    mode: SandboxMode,
}

impl LandlockSandbox {
    pub(crate) fn new(spec: SandboxSpec, mode: SandboxMode) -> Result<Self, SandboxError> {
        Ok(Self { spec, mode })
    }
}

impl Sandbox for LandlockSandbox {
    fn spawn(&self, _cmd: SandboxedCommand) -> Result<std::process::Child, SandboxError> {
        Err(SandboxError::ProfileRenderFailed {
            reason: "landlock backend not yet implemented — Phase 46 P5 Chunk 3 wires the \
				ruleset + pre_exec path"
                .to_string(),
        })
    }

    fn backend_name(&self) -> &'static str {
        "landlock"
    }

    fn mode(&self) -> SandboxMode {
        self.mode
    }
}
