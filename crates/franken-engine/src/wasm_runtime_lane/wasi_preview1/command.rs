//! One-shot WASI command execution, not host-process termination.
//!
//! A runner owns the instance from binary startup through `_start` and never
//! returns it. Returning, exiting, trapping or dropping unfinished work releases
//! that state. External/captured host effects already completed are not undone.

use super::super::numeric::{
    WasmHostError, WasmHostImports, WasmNumericExecution, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};

/// The point at which an explicit guest exit ended the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasiCommandPhase {
    /// A binary start-section function exited before an instance was published.
    Instantiation,
    /// The `_start` export or one of its callees requested exit.
    Command,
}

/// A normal command result. Resource, policy, provider and replay failures are
/// errors, never exit codes. Nonlocal exits do not fabricate execution metrics:
/// the underlying VM does not return its final meter on an abrupt completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WasiCommandOutcome {
    Returned {
        startup: Option<WasmNumericExecution>,
        execution: WasmNumericExecution,
    },
    Exited {
        code: u32,
        phase: WasiCommandPhase,
    },
}

impl WasiCommandOutcome {
    /// Preserve the complete WASI u32 status. Do not truncate to an OS exit byte
    /// or reinterpret the status as a signed i32. Normal `_start` return is zero.
    pub fn exit_code(&self) -> u32 {
        match self {
            Self::Returned { .. } => 0,
            Self::Exited { code, .. } => *code,
        }
    }
}

fn validate_entry(vm: &WasmNumericVm) -> Result<(), WasmNumericVmError> {
    let signature = vm.export_signature("_start")?;
    if !signature.params.is_empty() || !signature.results.is_empty() {
        return Err(WasmNumericVmError::InvalidModule {
            detail: "WASI command _start must have no parameters or results".into(),
        });
    }
    Ok(())
}

fn exited(
    error: WasmNumericVmError,
    phase: WasiCommandPhase,
) -> Result<WasiCommandOutcome, WasmNumericVmError> {
    match error {
        WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ProcessExit { code })) => {
            Ok(WasiCommandOutcome::Exited { code, phase })
        }
        error => Err(error),
    }
}

/// Run one command, retaining its termination phase and normal-return metrics.
/// This is the detailed form of [`super::run_command`], which returns only the
/// exit status. Both APIs execute through this same path. Validate
/// `_start: () -> ()` BEFORE binary startup can produce any guest/host effects.
/// All declared imports still link before startup, even imports never reached.
/// A memory export is not required: providers use their scoped memory-zero API.
///
/// The registry is consumed, and no instance escapes on any outcome. Calling
/// this function again is a NEW command with new providers, never a continuation
/// after `proc_exit`. Raw numeric instances also retain their terminal exit
/// status; this owning API additionally releases all instance/provider state.
///
/// Binary startup and `_start` retain their existing separate invocation limits;
/// a command may spend up to both work budgets. No program is granted ambient
/// stdio/environment/filesystem access, and the host process never exits.
pub fn run_command_with_outcome(
    vm: &WasmNumericVm,
    imports: WasmHostImports,
) -> Result<WasiCommandOutcome, WasmNumericVmError> {
    validate_entry(vm)?;
    let mut instance = match vm.instantiate_with_imports(imports) {
        Ok(instance) => instance,
        Err(error) => return exited(error, WasiCommandPhase::Instantiation),
    };
    let startup = instance.start_execution().cloned();
    match instance.call_export("_start", &[]) {
        Ok(execution) => Ok(WasiCommandOutcome::Returned { startup, execution }),
        Err(error) => exited(error, WasiCommandPhase::Command),
    }
}
