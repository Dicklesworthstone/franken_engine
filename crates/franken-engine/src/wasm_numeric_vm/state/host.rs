//! Explicit, typed host-function linking for the native numeric VM.
//!
//! No host service is installed or inferred from an import name. A trusted
//! embedder supplies each implementation, its exact ABI, required canonical
//! capabilities and nonzero call cost. All declared imports are checked before
//! state allocation/startup; capabilities are checked again on every call.
//!
//! Host callbacks are trusted Rust, not sandboxed Wasm: the instruction meter
//! cannot preempt blocking I/O, native loops, panics or allocations inside a
//! callback. Providers must meter variable work and enforce their service's
//! resource, IFC and replay contracts. This API does not install ambient I/O,
//! claim deterministic host behavior, or grant JavaScript hostcall authority.

use super::*;
use crate::capability::RuntimeCapability;
use crate::checkpoint::{CancellationToken, CheckpointAction, CheckpointGuard, DensityConfig, LoopSite};
use crate::wasm_runtime_lane::WasmFunctionSignature;
use std::collections::BTreeSet;
use crate::hash_tiers::ContentHash;
use crate::wasm_runtime_lane::host_replay::{
    self, WasmHostRecording, WasmHostReplay, WasmHostTraceError,
    WasmHostTraceLimits, WasmHostTranscript,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmHostError {
    DuplicateBinding { module: String, name: String },
    MissingBinding { module: String, name: String },
    SignatureMismatch { module: String, name: String },
    CapabilityDenied { module: String, name: String, capability: RuntimeCapability },
    MissingAuthority,
    ZeroCallCost,
    MissingMemory,
    Cancelled,
    CancellationAlreadyBound,
    ExecutionCancelled,
    ExecutionCancellationAlreadyBound,
    CapabilityRevocationAlreadyBound { capability: RuntimeCapability },
    Trace(WasmHostTraceError),
    Trap { message: String },
}

impl WasmHostError {
    /// Bound provider diagnostics without splitting a UTF-8 code point.
    pub fn trap(message: &str) -> Self {
        let mut end = message.len().min(4096);
        while !message.is_char_boundary(end) { end -= 1; }
        Self::Trap { message: message[..end].to_owned() }
    }
}

impl fmt::Display for WasmHostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateBinding { module, name } => write!(f, "duplicate wasm host binding {module}.{name}"),
            Self::MissingBinding { module, name } => write!(f, "missing wasm host binding {module}.{name}"),
            Self::SignatureMismatch { module, name } => write!(f, "wasm host binding {module}.{name} has the wrong signature"),
            Self::CapabilityDenied { module, name, capability } => write!(f, "wasm host binding {module}.{name} requires {capability}"),
            Self::MissingAuthority => f.write_str("wasm host binding requires explicit capability authority"),
            Self::ZeroCallCost => f.write_str("wasm host binding requires a nonzero call cost"),
            Self::MissingMemory => f.write_str("wasm host buffer access requires guest memory zero"),
            Self::Cancelled => f.write_str("wasm host execution scope was cancelled"),
            Self::CancellationAlreadyBound => f.write_str("wasm host cancellation scope is already bound"),
            Self::ExecutionCancelled => f.write_str("wasm instance execution was cancelled"),
            Self::ExecutionCancellationAlreadyBound => f.write_str("wasm instance execution cancellation is already bound"),
            Self::CapabilityRevocationAlreadyBound { capability } => {
                write!(f, "wasm host revocation signal is already bound for {capability}")
            }
            Self::Trace(error) => write!(f, "{error}"),
            Self::Trap { message } => write!(f, "wasm host trap: {message}"),
        }
    }
}

impl std::error::Error for WasmHostError {}

impl From<WasmHostError> for WasmNumericVmError {
    fn from(error: WasmHostError) -> Self { WasmStateError::Host(error).into() }
}

type Callback = dyn FnMut(
    &mut WasmHostCaller<'_, '_>,
    &[WasmBoundaryValue],
) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync;

struct Binding {
    signature: WasmFunctionSignature,
    required: BTreeSet<RuntimeCapability>,
    call_cost: u64,
    callback: Box<Callback>,
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binding")
            .field("signature", &self.signature)
            .field("required", &self.required)
            .field("call_cost", &self.call_cost)
            .finish_non_exhaustive()
    }
}

/// A persistent epoch observer, not a second work meter. The canonical guard
/// remembers cancellation across token reset; the sticky bit prevents a later
/// invocation from reusing a drained scope. We do not tick this guard: the VM
/// meter owns instruction/work limits, and observing a signal must not build
/// an unbounded periodic-event log inside a long-running native callback.
#[derive(Debug)]
struct HostCancellation {
    guard: CheckpointGuard,
    cancelled: bool,
}

impl HostCancellation {
    fn new(token: CancellationToken, trace_id: impl Into<String>) -> Self {
        Self::at_site(token, trace_id, LoopSite::Custom("wasm_host".to_string()))
    }

    fn at_site(token: CancellationToken, trace_id: impl Into<String>, site: LoopSite) -> Self {
        let mut scope = Self {
            guard: CheckpointGuard::new(
                site,
                WASM_NUMERIC_VM_COMPONENT,
                trace_id,
                DensityConfig::default(),
                token,
            ),
            cancelled: false,
        };
        // Capture an already-pending request before handing the scope back.
        scope.is_cancelled();
        scope
    }

    fn is_cancelled(&mut self) -> bool {
        if !self.cancelled {
            self.cancelled = self.guard.check() != CheckpointAction::Continue;
        }
        self.cancelled
    }
}

/// An owned host registry and its explicit authority envelope. Instantiation
/// consumes it, so callback state is instance-local unless the trusted provider
/// deliberately captures shared state. The running instance can only revoke,
/// not extend, this envelope or replace a linked implementation.
#[derive(Debug)]
pub struct WasmHostImports {
    bindings: BTreeMap<String, BTreeMap<String, Binding>>,
    granted: BTreeSet<RuntimeCapability>,
    trace: host_replay::TraceMode,
    cancellation: Option<HostCancellation>,
    execution_cancellation: Option<HostCancellation>,
    revocations: BTreeMap<RuntimeCapability, HostCancellation>,
}

impl WasmHostImports {
    pub fn new(granted: BTreeSet<RuntimeCapability>) -> Self {
        Self {
            bindings: BTreeMap::new(), granted,
            trace: host_replay::TraceMode::default(), cancellation: None,
            execution_cancellation: None,
            revocations: BTreeMap::new(),
        }
    }

    /// Bind the canonical control-plane cancellation signal before linking.
    /// This may be called only once: replacing a token cannot erase a request.
    /// Cancellation is sticky for this registry and the instance that consumes
    /// it, even if the token is reset for a different execution session.
    ///
    /// Checks occur before instantiation, at host dispatch, on provider
    /// checkpoints/buffer access/work charges, and after callback return.
    /// Native callbacks must cooperate; this does not preempt native code or
    /// guest-only loops, and already-completed effects are not rolled back.
    pub fn bind_cancellation(
        &mut self,
        token: CancellationToken,
        trace_id: impl Into<String>,
    ) -> Result<(), WasmHostError> {
        if self.cancellation.is_some() {
            return Err(WasmHostError::CancellationAlreadyBound);
        }
        self.cancellation = Some(HostCancellation::new(token, trace_id));
        Ok(())
    }

    /// Bind cancellation for the entire instance, including hostless guest
    /// loops. An empty registry can carry this control without granting any
    /// host capability. Unlike `bind_cancellation`, this scope is checked
    /// before each guest opcode, at activation entry/return, and at the same
    /// cooperative host/replay boundaries as the host-only scope.
    ///
    /// The first observed cancellation permanently stops execution in this
    /// instance. Resetting the token cannot resurrect it; construct a new
    /// authorized instance for a new session. Completed stores remain visible
    /// for inspection. Native callbacks and individual bulk operations are
    /// not preempted: callbacks must poll between bounded units of work.
    /// This live signal does not itself provide deterministic replay of the
    /// guest instruction at which an asynchronous request was observed.
    pub fn bind_execution_cancellation(
        &mut self,
        token: CancellationToken,
        trace_id: impl Into<String>,
    ) -> Result<(), WasmHostError> {
        if self.execution_cancellation.is_some() {
            return Err(WasmHostError::ExecutionCancellationAlreadyBound);
        }
        self.execution_cancellation = Some(HostCancellation::at_site(
            token, trace_id, LoopSite::BytecodeDispatch,
        ));
        Ok(())
    }

    /// Bind a live, permanent revocation signal for one service capability.
    /// This never grants the capability. A revoked service stops only bindings
    /// that require it; unrelated host functions remain usable. VmDispatch is
    /// required by every binding and therefore revokes all host dispatch.
    ///
    /// Like whole-scope cancellation, requests survive reset and are checked
    /// before linking, at dispatch, at provider checkpoints and after return.
    /// A signal cannot be replaced, even before the registry is instantiated.
    /// The map is bounded by the canonical RuntimeCapability enum, not by guest
    /// function count or caller-supplied string identities.
    pub fn bind_capability_revocation(
        &mut self,
        capability: RuntimeCapability,
        token: CancellationToken,
        trace_id: impl Into<String>,
    ) -> Result<(), WasmHostError> {
        if self.revocations.contains_key(&capability) {
            return Err(WasmHostError::CapabilityRevocationAlreadyBound { capability });
        }
        self.revocations.insert(capability, HostCancellation::new(token, trace_id));
        Ok(())
    }

    fn check_cancellation(&mut self) -> Result<(), WasmNumericVmError> {
        check_execution_scope(&mut self.execution_cancellation)?;
        if self.cancellation.as_mut().is_some_and(HostCancellation::is_cancelled) {
            return Err(WasmHostError::Cancelled.into());
        }
        Ok(())
    }

    /// Record entered providers, including startup. The observer survives a
    /// failed start. Recording is opt-in and adds metered memory hashing;
    /// callers must protect the resulting buffers as sensitive incident data.
    pub fn record_calls(&mut self, limits: WasmHostTraceLimits) -> Result<WasmHostRecording, WasmHostTraceError> {
        self.trace.record(limits)
    }

    /// Replay trusted recorded effects instead of invoking providers. Existing
    /// binding signatures, fixed costs and capability requirements still apply.
    /// Verify the returned observer's complete consumption after the run.
    pub fn replay_calls(&mut self, transcript: WasmHostTranscript, limits: WasmHostTraceLimits) -> Result<WasmHostReplay, WasmHostTraceError> {
        self.trace.replay(transcript, limits)
    }

    /// Bind only from the consuming, authorized resolver path. A public
    /// provider cannot relabel an unscoped tape as a resolved-module tape.
    pub(crate) fn bind_module(&mut self, hash: ContentHash) -> Result<(), WasmHostTraceError> {
        self.trace.bind_module(hash)
    }

    /// Narrow a provider envelope to a resolved module's declared authority.
    /// Never infer a grant from a binding requirement or a process-wide policy.
    pub(crate) fn restrict_capabilities(&mut self, permitted: &BTreeSet<RuntimeCapability>) {
        self.granted.retain(|capability| permitted.contains(capability));
    }

    /// Define an exact (module, name) binding. Duplicate registration fails
    /// without replacing the existing callback. VmDispatch is always required
    /// in addition to the provider's nonempty service-capability set.
    pub fn define<F>(
        &mut self,
        module: impl Into<String>,
        name: impl Into<String>,
        signature: WasmFunctionSignature,
        mut required: BTreeSet<RuntimeCapability>,
        call_cost: u64,
        callback: F,
    ) -> Result<(), WasmHostError>
    where
        F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue])
                -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError>
            + Send + Sync + 'static,
    {
        if required.is_empty() { return Err(WasmHostError::MissingAuthority); }
        if call_cost == 0 { return Err(WasmHostError::ZeroCallCost); }
        let module = module.into();
        let name = name.into();
        if self.bindings.get(&module).is_some_and(|bindings| bindings.contains_key(&name)) {
            return Err(WasmHostError::DuplicateBinding { module, name });
        }
        required.insert(RuntimeCapability::VmDispatch);
        self.bindings.entry(module).or_default().insert(name, Binding {
            signature, required, call_cost, callback: Box::new(callback),
        });
        Ok(())
    }

    fn validate(&mut self, vm: &WasmNumericVm) -> Result<(), WasmNumericVmError> {
        self.trace.validate_module_scope()?;
        for import in &vm.imports {
            let binding = self.bindings.get(&import.module)
                .and_then(|bindings| bindings.get(&import.name))
                .ok_or_else(|| WasmHostError::MissingBinding {
                    module: import.module.clone(), name: import.name.clone(),
                })?;
            let signature = vm.function_type(import.type_index)?;
            if binding.signature.params != signature.params || binding.signature.results != signature.results {
                return Err(WasmHostError::SignatureMismatch {
                    module: import.module.clone(), name: import.name.clone(),
                }.into());
            }
            check_authority(&self.granted, binding, import)?;
            check_revocations(&mut self.revocations, &binding.required, import)?;
        }
        Ok(())
    }
}

fn check_execution_scope(scope: &mut Option<HostCancellation>) -> Result<(), WasmNumericVmError> {
    if scope.as_mut().is_some_and(HostCancellation::is_cancelled) {
        return Err(WasmHostError::ExecutionCancelled.into());
    }
    Ok(())
}

fn check_authority(
    granted: &BTreeSet<RuntimeCapability>,
    binding: &Binding,
    import: &FunctionImport,
) -> Result<(), WasmNumericVmError> {
    if let Some(capability) = binding.required.difference(granted).next() {
        return Err(WasmHostError::CapabilityDenied {
            module: import.module.clone(), name: import.name.clone(), capability: *capability,
        }.into());
    }
    Ok(())
}

fn check_revocations(
    revocations: &mut BTreeMap<RuntimeCapability, HostCancellation>,
    required: &BTreeSet<RuntimeCapability>,
    import: &FunctionImport,
) -> Result<(), WasmNumericVmError> {
    for capability in required {
        if revocations.get_mut(capability).is_some_and(HostCancellation::is_cancelled) {
            return Err(WasmHostError::CapabilityDenied {
                module: import.module.clone(),
                name: import.name.clone(),
                capability: *capability,
            }.into());
        }
    }
    Ok(())
}

/// Scoped access to the same budget as the enclosing Wasm invocation. A
/// provider cannot erase a refusal by ignoring the returned Result: failures
/// are latched and take precedence when the callback returns.
/// Guest-memory borrows cannot outlive this call or overlap a later write.
/// Access does not require a memory export (notably during startup), but is
/// available only inside an explicitly linked, authorized host callback.
pub struct WasmHostCaller<'call, 'vm> {
    meter: &'call mut ExecutionMeter<'vm>,
    memory: &'call mut Option<LinearMemory>,
    failure: Option<WasmNumericVmError>,
    recording: Option<&'call mut host_replay::CallRecording>,
    cancellation: &'call mut Option<HostCancellation>,
    execution_cancellation: &'call mut Option<HostCancellation>,
    revocations: &'call mut BTreeMap<RuntimeCapability, HostCancellation>,
    required: &'call BTreeSet<RuntimeCapability>,
    import: &'call FunctionImport,
}

impl WasmHostCaller<'_, '_> {
    /// Cooperatively observe cancellation and required-capability revocation
    /// without charging work or allocating an event on every poll. A refusal
    /// is latched just like a budget/buffer
    /// failure; ignoring it cannot resume guest execution when the callback
    /// returns. Poll between bounded units of provider work or external I/O.
    pub fn checkpoint(&mut self) -> Result<(), WasmNumericVmError> {
        if let Some(error) = &self.failure { return Err(error.clone()); }
        if let Err(error) = check_execution_scope(self.execution_cancellation) {
            self.failure = Some(error.clone());
            return Err(error);
        }
        if self.cancellation.as_mut().is_some_and(HostCancellation::is_cancelled) {
            let error: WasmNumericVmError = WasmHostError::Cancelled.into();
            self.failure = Some(error.clone());
            return Err(error);
        }
        if let Err(error) = check_revocations(self.revocations, self.required, self.import) {
            self.failure = Some(error.clone());
            return Err(error);
        }
        Ok(())
    }

    /// Size of the caller's memory zero, or None when the module has no memory.
    /// This neither grows memory nor exposes the underlying allocation.
    pub fn memory_size_bytes(&self) -> Option<usize> {
        self.memory.as_ref().map(|memory| memory.bytes.len())
    }

    /// Borrow a checked guest buffer. Interpret Wasm i32 pointers as u32, not
    /// signed host offsets. The full range is checked without wrapping; an
    /// empty range is valid at, but never beyond, the end of an existing memory.
    /// Charge one work unit per 64 bytes before exposing any bytes. Processing
    /// beyond this access charge still needs the provider's own work metering.
    pub fn read_memory(
        &mut self,
        address: u32,
        length: u32,
    ) -> Result<&[u8], WasmNumericVmError> {
        let range = self.prepare_memory_access(address, length as usize)?;
        let memory = self.memory.as_ref().ok_or(WasmHostError::MissingMemory)?;
        Ok(&memory.bytes[range])
    }

    /// Copy host output into guest memory after checking the entire range and
    /// precharging copy work. Refusal never leaves a partial write. Completed
    /// writes remain visible if a later host operation or guest instruction
    /// traps, just like completed guest stores; this is not a transaction.
    pub fn write_memory(
        &mut self,
        address: u32,
        bytes: &[u8],
    ) -> Result<(), WasmNumericVmError> {
        let range = self.prepare_memory_access(address, bytes.len())?;
        // Retain the effect before mutation. A recorder refusal is latched
        // just like a bounds/budget refusal and cannot be ignored by providers.
        if let Some(recording) = self.recording.as_mut()
            && let Err(error) = recording.write(address, bytes)
        {
            let error = WasmNumericVmError::from(error);
            self.failure = Some(error.clone());
            return Err(error);
        }
        let memory = self.memory.as_mut().ok_or(WasmHostError::MissingMemory)?;
        memory.bytes[range].copy_from_slice(bytes);
        Ok(())
    }

    fn prepare_memory_access(
        &mut self,
        address: u32,
        length: usize,
    ) -> Result<std::ops::Range<usize>, WasmNumericVmError> {
        self.checkpoint()?;
        let checked = match self.memory.as_ref() {
            Some(memory) => memory.range(address, 0, length),
            None => Err(WasmHostError::MissingMemory.into()),
        };
        let range = match checked {
            Ok(range) => range,
            Err(error) => {
                self.failure = Some(error.clone());
                return Err(error);
            }
        };
        self.charge_work((length as u64).div_ceil(64))?;
        Ok(range)
    }

    pub fn remaining_work(&self) -> u64 {
        self.meter.limits.max_instructions.saturating_sub(self.meter.instructions)
    }

    pub fn charge_work(&mut self, units: u64) -> Result<(), WasmNumericVmError> {
        self.checkpoint()?;
        if let Err(error) = self.meter.charge_work(units) {
            self.failure = Some(error.clone());
            return Err(error);
        }
        Ok(())
    }
}

impl WasmNumericVm {
    /// Link every declared function import before allocating state or running
    /// startup. Missing bindings, ABI mismatches and absent grants cannot
    /// produce host side effects. Once a valid start runs, its external host
    /// effects cannot be rolled back if a later startup instruction traps.
    pub fn instantiate_with_imports(
        &self,
        mut imports: WasmHostImports,
    ) -> Result<WasmNumericInstance<'_>, WasmNumericVmError> {
        imports.check_cancellation()?;
        imports.validate(self)?;
        let mut instance = self.instantiate_with_host_bindings(Some(imports))?;
        // Also observe a request that arrived during allocation when there
        // was no start function to cross a guest instruction boundary.
        instance.state.check_execution_cancellation()?;
        Ok(instance)
    }
}

impl WasmNumericInstance<'_> {
    /// Attenuate host authority between invocations. Subsequent direct,
    /// indirect, and exported-import calls all recheck this same envelope.
    pub fn revoke_host_capability(&mut self, capability: RuntimeCapability) -> bool {
        self.state.host_imports.as_mut()
            .is_some_and(|imports| imports.granted.remove(&capability))
    }
}

impl InstanceState {
    /// Instruction/activation polling must not turn a host-only revocation
    /// into guest cancellation. No registry means no execution subscription.
    pub(in super::super) fn check_execution_cancellation(&mut self) -> Result<(), WasmNumericVmError> {
        if let Some(imports) = self.host_imports.as_mut() {
            check_execution_scope(&mut imports.execution_cancellation)?;
        }
        Ok(())
    }

    pub(in super::super) fn invoke_import(
        &mut self,
        vm: &WasmNumericVm,
        function_index: u32,
        arguments: &[WasmBoundaryValue],
        meter: &mut ExecutionMeter<'_>,
    ) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> {
        let import = vm.imports.get(function_index as usize)
            .ok_or(WasmNumericVmError::UnknownFunction { function_index })?;
        let Some(imports) = self.host_imports.as_mut() else {
            // Preserve the compute-only/default API's fail-closed behavior.
            return Err(WasmNumericVmError::ImportedFunctionUnsupported {
                function_index, module: import.module.clone(), name: import.name.clone(),
            });
        };
        imports.check_cancellation()?;
        let signature = vm.function_type(import.type_index)?;
        validate_arguments(function_index, signature, arguments)?;
        let binding = imports.bindings.get_mut(&import.module)
            .and_then(|bindings| bindings.get_mut(&import.name))
            .ok_or_else(|| WasmHostError::MissingBinding {
                module: import.module.clone(), name: import.name.clone(),
            })?;
        check_authority(&imports.granted, binding, import)?;
        check_revocations(&mut imports.revocations, &binding.required, import)?;
        // Precharge ABI checking as well as the provider's declared fixed cost.
        // Overflow is a refusal, never a wrapped/saturated cheap host call.
        let abi_work = (signature.params.len().saturating_add(signature.results.len()) as u64).div_ceil(64);
        let cost = binding.call_cost.checked_add(abi_work)
            .ok_or(WasmNumericVmError::InstructionBudgetExceeded { max: meter.limits.max_instructions })?;
        meter.charge_work(cost)?;
        let memory_identity = if imports.trace.enabled() {
            if let Some(memory) = &self.memory {
                meter.charge_work((memory.bytes.len() as u64).div_ceil(64))?;
                Some((memory.bytes.len() as u64, ContentHash::compute(&memory.bytes)))
            } else { None }
        } else { None };
        let entry_work = meter.instructions;
        let mut trace = imports.trace.begin(host_replay::CallContext {
            module: &import.module, name: &import.name, function_index, arguments,
            signature: &binding.signature, required: &binding.required,
            call_cost: binding.call_cost, limits: meter.limits, entry_work,
            call_depth: meter.max_call_depth, memory: memory_identity,
        })?;
        let outcome = if let host_replay::TraceCall::Replay(mut playback) = trace {
            // Validate every destination and charge all recorded provider work
            // before the first replay write. Divergence never partly replays a
            // callback. Earlier completed guest instructions remain intact.
            for write in &playback.call.writes {
                self.memory.as_ref().ok_or(WasmHostError::MissingMemory)?
                    .range(write.address, 0, write.bytes.len())?;
            }
            meter.charge_work(playback.call.work)?;
            for write in &playback.call.writes {
                check_execution_scope(&mut imports.execution_cancellation)?;
                if imports.cancellation.as_mut().is_some_and(HostCancellation::is_cancelled) {
                    return Err(WasmHostError::Cancelled.into());
                }
                check_revocations(&mut imports.revocations, &binding.required, import)?;
                let memory = self.memory.as_mut().ok_or(WasmHostError::MissingMemory)?;
                let range = memory.range(write.address, 0, write.bytes.len())?;
                memory.bytes[range].copy_from_slice(&write.bytes);
            }
            check_execution_scope(&mut imports.execution_cancellation)?;
            if imports.cancellation.as_mut().is_some_and(HostCancellation::is_cancelled) {
                return Err(WasmHostError::Cancelled.into());
            }
            check_revocations(&mut imports.revocations, &binding.required, import)?;
            playback.complete()?;
            playback.call.outcome.clone()
        } else {
            let outcome = {
                let mut caller = WasmHostCaller {
                    meter, memory: &mut self.memory, failure: None,
                    recording: trace.recording(), cancellation: &mut imports.cancellation,
                    execution_cancellation: &mut imports.execution_cancellation,
                    revocations: &mut imports.revocations, required: &binding.required, import,
                };
                let outcome = (binding.callback)(&mut caller, arguments);
                // Finish the recording even when cancellation or a latched
                // provider fault wins over its return value. Using `?` here
                // would discard the entered call's completed-effect evidence.
                match caller.checkpoint() {
                    Ok(()) => outcome,
                    Err(error) => Err(error),
                }
            };
            trace.finish(meter.instructions - entry_work, &outcome)?;
            outcome
        };
        let results = outcome?;
        if results.len() != signature.results.len() {
            return Err(WasmNumericVmError::ResultStackMismatch {
                function_index, expected: signature.results.len(), actual: results.len(),
            });
        }
        for (index, (expected, actual)) in signature.results.iter()
            .zip(results.iter().map(WasmBoundaryValue::value_type)).enumerate()
        {
            ensure_same_type(function_index, index, *expected, actual)?;
        }
        meter.observe_stack(results.len())?;
        Ok(results)
    }
}
