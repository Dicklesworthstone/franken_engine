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
use crate::wasm_runtime_lane::WasmFunctionSignature;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmHostError {
    DuplicateBinding { module: String, name: String },
    MissingBinding { module: String, name: String },
    SignatureMismatch { module: String, name: String },
    CapabilityDenied { module: String, name: String, capability: RuntimeCapability },
    MissingAuthority,
    ZeroCallCost,
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

/// An owned host registry and its explicit authority envelope. Instantiation
/// consumes it, so callback state is instance-local unless the trusted provider
/// deliberately captures shared state. The running instance can only revoke,
/// not extend, this envelope or replace a linked implementation.
#[derive(Debug)]
pub struct WasmHostImports {
    bindings: BTreeMap<String, BTreeMap<String, Binding>>,
    granted: BTreeSet<RuntimeCapability>,
}

impl WasmHostImports {
    pub fn new(granted: BTreeSet<RuntimeCapability>) -> Self {
        Self { bindings: BTreeMap::new(), granted }
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

    fn validate(&self, vm: &WasmNumericVm) -> Result<(), WasmNumericVmError> {
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
        }
        Ok(())
    }
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

/// Scoped access to the same budget as the enclosing Wasm invocation. A
/// provider cannot erase a refusal by ignoring the returned Result: failures
/// are latched and take precedence when the callback returns.
pub struct WasmHostCaller<'call, 'vm> {
    meter: &'call mut ExecutionMeter<'vm>,
    failure: Option<WasmNumericVmError>,
}

impl WasmHostCaller<'_, '_> {
    pub fn remaining_work(&self) -> u64 {
        self.meter.limits.max_instructions.saturating_sub(self.meter.instructions)
    }

    pub fn charge_work(&mut self, units: u64) -> Result<(), WasmNumericVmError> {
        if let Some(error) = &self.failure { return Err(error.clone()); }
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
        imports: WasmHostImports,
    ) -> Result<WasmNumericInstance<'_>, WasmNumericVmError> {
        imports.validate(self)?;
        self.instantiate_with_host_bindings(Some(imports))
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
        let signature = vm.function_type(import.type_index)?;
        validate_arguments(function_index, signature, arguments)?;
        let binding = imports.bindings.get_mut(&import.module)
            .and_then(|bindings| bindings.get_mut(&import.name))
            .ok_or_else(|| WasmHostError::MissingBinding {
                module: import.module.clone(), name: import.name.clone(),
            })?;
        check_authority(&imports.granted, binding, import)?;
        // Precharge ABI checking as well as the provider's declared fixed cost.
        // Overflow is a refusal, never a wrapped/saturated cheap host call.
        let abi_work = (signature.params.len().saturating_add(signature.results.len()) as u64).div_ceil(64);
        let cost = binding.call_cost.checked_add(abi_work)
            .ok_or(WasmNumericVmError::InstructionBudgetExceeded { max: meter.limits.max_instructions })?;
        meter.charge_work(cost)?;
        let outcome = {
            let mut caller = WasmHostCaller { meter, failure: None };
            let outcome = (binding.callback)(&mut caller, arguments);
            match caller.failure {
                Some(error) => Err(error),
                None => outcome,
            }
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
