//! Cooperative, resolver-authorized WASI command execution.
//!
//! One task owns a fresh private instance from initialization through `_start`.
//! It never exposes an instance or unchecked VM. The original VM work budget
//! covers both phases, and each consuming resume needs a current policy.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::WasmNativeLoadError;
use crate::module_resolver::{CapabilityPolicyHook, ResolutionContext};

/// Terminal status and total charged work, including binary startup, `_start`,
/// host dispatch, replay hashing and bulk/setup work. Normal return means zero.
/// A guest's u32 status is not projected onto the host's signed process status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmCommandExecution {
    pub exit_code: u32,
    pub instructions_executed: u64,
}

type Driver<'vm> = dyn FnMut(
        NonZeroU64,
        &ResolutionContext,
        &CapabilityPolicyHook,
    ) -> Result<(u64, Option<u32>), WasmNativeLoadError>
    + Send
    + Sync
    + 'vm;

/// Created only by `WasmNativeModule::prepare_command`. Consuming each resume
/// prevents reuse after success, failure or provider panic. Dropping/cancelling
/// releases all unfinished state; completed external effects are not undone.
#[must_use = "resume the command or explicitly cancel it"]
pub struct WasmCommandTask<'vm> {
    driver: Box<Driver<'vm>>,
    instructions: u64,
}

impl fmt::Debug for WasmCommandTask<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmCommandTask")
            .field("instructions_executed", &self.instructions)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
#[must_use = "retain pending command work or consume its terminal result"]
pub enum WasmCommandStep<'vm> {
    Pending(WasmCommandTask<'vm>),
    Complete(WasmCommandExecution),
}

impl<'vm> WasmCommandTask<'vm> {
    pub(crate) fn new<F>(driver: F) -> Self
    where
        F: FnMut(
                NonZeroU64,
                &ResolutionContext,
                &CapabilityPolicyHook,
            ) -> Result<(u64, Option<u32>), WasmNativeLoadError>
            + Send
            + Sync
            + 'vm,
    {
        Self {
            driver: Box::new(driver),
            instructions: 0,
        }
    }

    /// Advance at most one lifecycle phase with a soft work quantum. A mandatory
    /// yield between binary startup and `_start` gives the embedder another
    /// policy/cancellation decision before command entry. Changing the quantum
    /// never resets the combined hard budget. Policy is a caller-supplied current
    /// snapshot, not a cached grant or a subscription to asynchronous changes.
    ///
    /// Only typed guest ProcessExit becomes an exit status. VM faults, recording
    /// failures and denial remain errors. Initial allocation, individual bulk
    /// instructions and native providers remain indivisible; this is not native
    /// callback preemption. Retain explicit stdio/replay observers for effects.
    pub fn resume(
        mut self,
        work: NonZeroU64,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmCommandStep<'vm>, WasmNativeLoadError> {
        let (instructions, status) = (self.driver)(work, context, policy)?;
        self.instructions = instructions;
        match status {
            Some(exit_code) => Ok(WasmCommandStep::Complete(WasmCommandExecution {
                exit_code,
                instructions_executed: instructions,
            })),
            None => Ok(WasmCommandStep::Pending(self)),
        }
    }

    pub fn instructions_executed(&self) -> u64 {
        self.instructions
    }

    pub fn cancel(self) {}
}
