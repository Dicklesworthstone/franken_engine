//! Capability-gated native execution of resolved WebAssembly imports.
//!
//! The deterministic resolver owns names, provenance and resolution policy;
//! the numeric VM owns validation and execution. A loaded module pins those
//! exact source bytes. Startup, calls and state inspection require the current
//! capability policy. Host functions are unbound by default; explicit linking
//! intersects provider authority with the module's declared capabilities and
//! validates every imported ABI before startup. No live-policy grant is cached.
//!
//! This is the embedding-facing import path, not JavaScript import-expression
//! evaluation or automatic ESM namespace binding. The constant-body ABI route
//! remains separate. Binary definitions use an explicit lossless text envelope
//! because the resolver's existing source contract is UTF-8.

use std::borrow::Cow;
use std::fmt;

use crate::capability::RuntimeCapability;
use crate::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModulePolicyHook, ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
    ResolutionError, ResolutionOutcome, wasm_module_required_capabilities,
};

use super::WasmBoundaryValue;
use super::numeric::{
    WasmHostImports, WasmNumericExecution, WasmNumericInstance, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError,
};

const BINARY_SOURCE_PREFIX: &str = "franken-wasm-hex-v1:";

#[derive(Debug)]
pub enum WasmNativeLoadError {
    Resolution(Box<ResolutionError>),
    Execution(WasmNumericVmError),
    UnsupportedImportStyle,
    UnsupportedSyntax { syntax: ModuleSyntax },
    InvalidModuleContract,
    ContentHashMismatch,
    InvalidBinarySource,
    AllocationFailed { bytes: usize },
}

impl fmt::Display for WasmNativeLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution(error) => write!(f, "{error}"),
            Self::Execution(error) => write!(f, "{error}"),
            Self::UnsupportedImportStyle => write!(f, "native wasm requires import, not require"),
            Self::UnsupportedSyntax { syntax } => {
                write!(f, "cannot execute {} source as native wasm", syntax.as_str())
            }
            Self::InvalidModuleContract => {
                write!(f, "wasm module contract must require module_load and vm_dispatch")
            }
            Self::ContentHashMismatch => write!(f, "resolved wasm content hash does not match its record"),
            Self::InvalidBinarySource => write!(f, "invalid canonical wasm binary source envelope"),
            Self::AllocationFailed { bytes } => write!(f, "cannot allocate {bytes} bytes for wasm source"),
        }
    }
}

impl std::error::Error for WasmNativeLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolution(error) => Some(error.as_ref()),
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Box<ResolutionError>> for WasmNativeLoadError {
    fn from(error: Box<ResolutionError>) -> Self { Self::Resolution(error) }
}

impl From<WasmNumericVmError> for WasmNativeLoadError {
    fn from(error: WasmNumericVmError) -> Self { Self::Execution(error) }
}

fn check_size(actual: usize, max: usize) -> Result<(), WasmNativeLoadError> {
    if actual > max {
        return Err(WasmNumericVmError::ModuleTooLarge { actual, max }.into());
    }
    Ok(())
}

impl ModuleDefinition {
    /// Preserve arbitrary binary bytes in the resolver's UTF-8 source field.
    /// The envelope is versioned lowercase hex, without whitespace. Limits are
    /// checked before allocating; loading rechecks its own independent limits.
    pub fn wasm_binary(
        bytes: &[u8],
        limits: &WasmNumericLimits,
    ) -> Result<Self, WasmNativeLoadError> {
        check_size(bytes.len(), limits.max_module_bytes)?;
        let capacity = bytes.len().checked_mul(2)
            .and_then(|length| length.checked_add(BINARY_SOURCE_PREFIX.len()))
            .ok_or(WasmNativeLoadError::AllocationFailed { bytes: usize::MAX })?;
        let mut source = String::new();
        source.try_reserve_exact(capacity)
            .map_err(|_| WasmNativeLoadError::AllocationFailed { bytes: capacity })?;
        source.push_str(BINARY_SOURCE_PREFIX);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            source.push(char::from(HEX[usize::from(byte >> 4)]));
            source.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let mut definition = Self::new(ModuleSyntax::Wasm, source);
        definition.required_capabilities = wasm_module_required_capabilities();
        Ok(definition)
    }
}

fn source_bytes(source: &str, max: usize) -> Result<Cow<'_, [u8]>, WasmNativeLoadError> {
    let Some(hex) = source.strip_prefix(BINARY_SOURCE_PREFIX) else {
        // Preserve the existing raw, UTF-8-compatible binary source contract.
        check_size(source.len(), max)?;
        return Ok(Cow::Borrowed(source.as_bytes()));
    };
    if hex.len() % 2 != 0 {
        return Err(WasmNativeLoadError::InvalidBinarySource);
    }
    let length = hex.len() / 2;
    check_size(length, max)?;
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    // Validate the whole envelope before allocating from its advertised size.
    if !hex.bytes().all(|byte| nibble(byte).is_some()) {
        return Err(WasmNativeLoadError::InvalidBinarySource);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)
        .map_err(|_| WasmNativeLoadError::AllocationFailed { bytes: length })?;
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = nibble(pair[0]).ok_or(WasmNativeLoadError::InvalidBinarySource)?;
        let low = nibble(pair[1]).ok_or(WasmNativeLoadError::InvalidBinarySource)?;
        bytes.push((high << 4) | low);
    }
    Ok(Cow::Owned(bytes))
}

/// A validated, immutable module pinned to its authorized resolution record.
/// Loading compiles only; no start function or exported body executes yet.
#[derive(Debug)]
pub struct WasmNativeModule {
    request: ModuleRequest,
    resolution: ResolutionOutcome,
    vm: WasmNumericVm,
}

impl DeterministicModuleResolver {
    /// Resolve an import and compile its exact bytes into the Rust-native VM.
    /// This never delegates execution to an external engine or binds host imports.
    pub fn load_wasm(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
        limits: WasmNumericLimits,
    ) -> Result<WasmNativeModule, WasmNativeLoadError> {
        if request.style != ImportStyle::Import {
            return Err(WasmNativeLoadError::UnsupportedImportStyle);
        }
        let resolution = self.resolve(request, context, policy)?;
        WasmNativeModule::compile(request.clone(), resolution, context, policy, limits)
    }
}

impl WasmNativeModule {
    fn compile(
        request: ModuleRequest,
        resolution: ResolutionOutcome,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
        limits: WasmNumericLimits,
    ) -> Result<Self, WasmNativeLoadError> {
        let record = &resolution.module.record;
        if record.syntax != ModuleSyntax::Wasm {
            return Err(WasmNativeLoadError::UnsupportedSyntax { syntax: record.syntax });
        }
        // Do not trust a deserialized registry to have passed registration's
        // mandatory capability augmentation, or an altered resolution record.
        if !wasm_module_required_capabilities().is_subset(&record.required_capabilities) {
            return Err(WasmNativeLoadError::InvalidModuleContract);
        }
        policy.authorize(&request, record, context)?;
        // Bound decoding before the VM can allocate from the guest module.
        let bytes = source_bytes(&record.source, limits.max_module_bytes)?;
        if record.canonical_hash() != resolution.module.content_hash {
            return Err(WasmNativeLoadError::ContentHashMismatch);
        }
        let vm = WasmNumericVm::parse(bytes.as_ref(), limits)?;
        drop(bytes);
        Ok(Self { request, resolution, vm })
    }

    /// Resolution identity, provenance and the original resolution trace.
    /// No mutable access is exposed: changing a registry requires a fresh load.
    pub fn resolution(&self) -> &ResolutionOutcome { &self.resolution }

    pub fn export_names(&self) -> impl Iterator<Item = &str> { self.vm.export_names() }

    fn authorize(
        &self,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<(), WasmNativeLoadError> {
        policy.authorize(&self.request, &self.resolution.module.record, context)?;
        Ok(())
    }

    /// Reauthorize before allocating instance state or executing startup.
    /// Each returned instance is isolated; subsequent calls on that instance
    /// preserve globals, memory, tables and segment drop state.
    pub fn instantiate(
        &self,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmNativeInstance<'_>, WasmNativeLoadError> {
        self.authorize(context, policy)?;
        let instance = self.vm.instantiate()?;
        Ok(WasmNativeInstance { module: self, instance })
    }

    /// Link explicit host implementations without broadening module authority.
    /// Every imported service capability must be present in all three places:
    /// the provider's grant, this pinned module's declaration, and the current
    /// policy. All imports are validated before allocation or startup effects.
    ///
    /// The returned instance uses the same policy-checked call and inspection
    /// methods as a compute-only instance. A policy denial precedes *all* guest
    /// instructions, including stores before a host call. This policy is a
    /// caller-supplied snapshot, not an asynchronous revocation subscription.
    /// Host callbacks remain trusted code responsible for I/O, IFC and replay;
    /// successful host effects are not rolled back by a later startup trap.
    /// Configured host recordings are bound to this exact module record;
    /// replay rejects other modules and unscoped tapes before startup.
    pub fn instantiate_with_imports(
        &self,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
        mut imports: WasmHostImports,
    ) -> Result<WasmNativeInstance<'_>, WasmNativeLoadError> {
        self.authorize(context, policy)?;
        imports.restrict_capabilities(&self.resolution.module.record.required_capabilities);
        imports.bind_module(self.resolution.module.content_hash).map_err(WasmNumericVmError::from)?;
        let instance = self.vm.instantiate_with_imports(imports)?;
        Ok(WasmNativeInstance { module: self, instance })
    }
}

/// Persistent guest state with no cached live-policy grant or unchecked VM accessor.
#[derive(Debug)]
pub struct WasmNativeInstance<'a> {
    module: &'a WasmNativeModule,
    instance: WasmNumericInstance<'a>,
}

impl WasmNativeInstance<'_> {
    /// Permanently attenuate this instance's linked host authority. Passing a
    /// broader policy later cannot restore the removed provider grant. A fresh
    /// authorized instantiation is required to link that capability again.
    pub fn revoke_host_capability(&mut self, capability: RuntimeCapability) -> bool {
        self.instance.revoke_host_capability(capability)
    }

    /// Use the caller's current policy, not the grant used when this module
    /// loaded. A denied call cannot run instructions or change guest state.
    pub fn call_export(
        &mut self,
        name: &str,
        arguments: &[WasmBoundaryValue],
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmNumericExecution, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        Ok(self.instance.call_export(name, arguments)?)
    }

    pub fn memory_export(
        &self, name: &str, context: &ResolutionContext, policy: &CapabilityPolicyHook,
    ) -> Result<Option<&[u8]>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        Ok(self.instance.memory_export(name))
    }

    pub fn table_export(
        &self, name: &str, context: &ResolutionContext, policy: &CapabilityPolicyHook,
    ) -> Result<Option<&[Option<u32>]>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        Ok(self.instance.table_export(name))
    }

    pub fn global_export(
        &self, name: &str, context: &ResolutionContext, policy: &CapabilityPolicyHook,
    ) -> Result<Option<&WasmBoundaryValue>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        Ok(self.instance.global_export(name))
    }

    pub fn start_execution(
        &self, context: &ResolutionContext, policy: &CapabilityPolicyHook,
    ) -> Result<Option<&WasmNumericExecution>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        Ok(self.instance.start_execution())
    }
}

/// One resolver-backed invocation. Every resume rechecks the supplied current
/// policy before executing even one more guest opcode or pending host call.
/// Cancelling/dropping it releases the instance without undoing earlier effects.
#[derive(Debug)]
#[must_use = "resume the call or explicitly drop it to cancel"]
pub struct WasmNativeCall<'call, 'vm> {
    module: &'vm WasmNativeModule,
    call: super::numeric::WasmCall<'call, 'vm>,
}

#[derive(Debug)]
#[must_use = "retain a pending continuation or drop it to cancel"]
pub enum WasmNativeCallStep<'call, 'vm> {
    Pending(WasmNativeCall<'call, 'vm>),
    Complete(WasmNumericExecution),
}

impl<'vm> WasmNativeInstance<'vm> {
    /// Prepare an export without executing it. The exclusive instance borrow
    /// prevents a second call from changing state underneath this continuation.
    /// Startup has already run. A fresh policy is required on EVERY resume.
    pub fn begin_call<'call>(
        &'call mut self,
        name: &str,
        arguments: &[WasmBoundaryValue],
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmNativeCall<'call, 'vm>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        let call = self.instance.begin_call(name, arguments)?;
        Ok(WasmNativeCall { module: self.module, call })
    }
}

impl<'call, 'vm> WasmNativeCall<'call, 'vm> {
    /// Consume one cooperative work slice. Policy denial cancels the unfinished
    /// invocation before any new guest effects; previous slices stay committed.
    /// A pending host callback therefore cannot use a grant cached before yield.
    /// Native callbacks and individual bulk instructions remain indivisible and
    /// may overrun this soft quantum, but never the VM's hard invocation budget.
    pub fn resume(
        self,
        work: std::num::NonZeroU64,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> Result<WasmNativeCallStep<'call, 'vm>, WasmNativeLoadError> {
        self.module.authorize(context, policy)?;
        match self.call.resume(work)? {
            super::numeric::WasmCallStep::Pending(call) => {
                Ok(WasmNativeCallStep::Pending(Self { module: self.module, call }))
            }
            super::numeric::WasmCallStep::Complete(execution) => {
                Ok(WasmNativeCallStep::Complete(execution))
            }
        }
    }

    pub fn instructions_executed(&self) -> u64 { self.call.instructions_executed() }

    pub fn peak_stack_values(&self) -> usize { self.call.peak_stack_values() }

    pub fn max_call_depth(&self) -> u32 { self.call.max_call_depth() }

    pub fn cancel(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::RuntimeCapability;
    use crate::module_resolver::ResolutionErrorCode;
    use super::super::numeric::WasmStateError;

    // Binary fixtures are also executable by an independent Wasm engine.
    // STATE_MODULE starts g at 40, exports a stateful step, and exposes a
    // passive non-UTF-8 payload through memory.init/data.drop.
    const STATE_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x03, 0x60, 0x00, 0x00, 0x60, 0x01,
        0x7f, 0x01, 0x7f, 0x60, 0x03, 0x7f, 0x7f, 0x7f, 0x00, 0x03, 0x05, 0x04, 0x00, 0x01, 0x02, 0x00,
        0x05, 0x04, 0x01, 0x01, 0x01, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x1e,
        0x05, 0x04, 0x73, 0x74, 0x65, 0x70, 0x00, 0x01, 0x04, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x02, 0x04,
        0x64, 0x72, 0x6f, 0x70, 0x00, 0x03, 0x01, 0x67, 0x03, 0x00, 0x01, 0x6d, 0x02, 0x00, 0x08, 0x01,
        0x00, 0x0c, 0x01, 0x01, 0x0a, 0x2e, 0x04, 0x06, 0x00, 0x41, 0x28, 0x24, 0x00, 0x0b, 0x12, 0x00,
        0x23, 0x00, 0x20, 0x00, 0x6a, 0x24, 0x00, 0x41, 0x00, 0x23, 0x00, 0x36, 0x02, 0x00, 0x23, 0x00,
        0x0b, 0x0c, 0x00, 0x20, 0x00, 0x20, 0x01, 0x20, 0x02, 0xfc, 0x08, 0x00, 0x00, 0x0b, 0x05, 0x00,
        0xfc, 0x09, 0x00, 0x0b, 0x0b, 0x06, 0x01, 0x01, 0x03, 0xff, 0x80, 0xfe,
    ];

    const TRAP_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00,
        0x0b, 0x07, 0x10, 0x03, 0x04, 0x73, 0x74, 0x65, 0x70, 0x00, 0x00, 0x01, 0x67, 0x03, 0x00, 0x01,
        0x6d, 0x02, 0x00, 0x0a, 0x15, 0x01, 0x13, 0x00, 0x23, 0x00, 0x20, 0x00, 0x6a, 0x24, 0x00, 0x41,
        0x00, 0x23, 0x00, 0x36, 0x02, 0x00, 0x23, 0x00, 0x00, 0x0b,
    ];

    const HOST_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x02,
        0x0c, 0x01, 0x03, 0x65, 0x6e, 0x76, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x03, 0x02, 0x01,
        0x00, 0x07, 0x08, 0x01, 0x04, 0x63, 0x61, 0x6c, 0x6c, 0x00, 0x01, 0x0a, 0x06, 0x01, 0x04, 0x00,
        0x10, 0x00, 0x0b,
    ];

    fn context(policy_id: &str) -> ResolutionContext {
        ResolutionContext::new("trace-native-import", "decision-native-import", policy_id)
    }

    fn policy() -> CapabilityPolicyHook {
        CapabilityPolicyHook::new(wasm_module_required_capabilities())
    }

    fn request() -> ModuleRequest {
        ModuleRequest::new("./state.wasm", ImportStyle::Import).with_referrer("/app/main.mjs")
    }

    fn registry_with_referrer() -> DeterministicModuleResolver {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver.register_workspace_module("/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './state.wasm';")).unwrap();
        resolver
    }

    fn resolver(bytes: &[u8]) -> DeterministicModuleResolver {
        let mut resolver = registry_with_referrer();
        resolver.register_workspace_module(
            "/app/state.wasm",
            ModuleDefinition::wasm_binary(bytes, &WasmNumericLimits::default())
                .unwrap().with_provenance("native-import-test"),
        ).unwrap();
        resolver
    }

    fn load(resolver: &DeterministicModuleResolver) -> WasmNativeModule {
        resolver.load_wasm(&request(), &context("allow"), &policy(), WasmNumericLimits::default()).unwrap()
    }

    fn denied<T: fmt::Debug>(result: Result<T, WasmNativeLoadError>) {
        match result {
            Err(WasmNativeLoadError::Resolution(error)) => {
                assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
            }
            other => panic!("expected policy denial, got {other:?}"),
        }
    }

    fn args(values: [i32; 3]) -> [WasmBoundaryValue; 3] {
        values.map(WasmBoundaryValue::I32)
    }

    #[test]
    fn binary_envelope_round_trips_all_bytes_and_preserves_raw_source_support() {
        let bytes: Vec<u8> = (0..=255).collect();
        let definition = ModuleDefinition::wasm_binary(&bytes, &WasmNumericLimits::default()).unwrap();
        assert_eq!(source_bytes(&definition.source, 256).unwrap().as_ref(), bytes.as_slice());
        assert_eq!(definition.required_capabilities, wasm_module_required_capabilities());
        assert!(std::str::from_utf8(STATE_MODULE).is_err());
        let raw = "\0asm\x01\0\0\0";
        let mut registry = registry_with_referrer();
        registry.register_workspace_module("/app/state.wasm", ModuleDefinition::new(ModuleSyntax::Wasm, raw)).unwrap();
        let module = load(&registry);
        assert!(module.export_names().next().is_none());
        module.instantiate(&context("allow"), &policy()).unwrap();
    }

    #[test]
    fn resolver_import_executes_nonconstant_exports_with_persistent_isolated_state() {
        let module = load(&resolver(STATE_MODULE));
        let ctx = context("allow");
        let grants = policy();
        assert_eq!(module.resolution().module.canonical_specifier, "/app/state.wasm");
        assert_eq!(module.export_names().collect::<Vec<_>>(), ["drop", "init", "step"]);
        let mut a = module.instantiate(&ctx, &grants).unwrap();
        let b = module.instantiate(&ctx, &grants).unwrap();
        assert_eq!(a.start_execution(&ctx, &grants).unwrap().unwrap().instructions_executed, 3);
        for (input, expected) in [(2, 42), (1, 43)] {
            let execution = a.call_export("step", &[WasmBoundaryValue::I32(input)], &ctx, &grants).unwrap();
            assert_eq!(execution.results, [WasmBoundaryValue::I32(expected)]);
            assert_eq!(execution.instructions_executed, 9);
            assert_eq!(&a.memory_export("m", &ctx, &grants).unwrap().unwrap()[..4], &expected.to_le_bytes());
        }
        assert_eq!(b.global_export("g", &ctx, &grants).unwrap(), Some(&WasmBoundaryValue::I32(40)));
        assert_eq!(a.global_export("hidden", &ctx, &grants).unwrap(), None);
        assert_eq!(a.table_export("m", &ctx, &grants).unwrap(), None);
    }

    #[test]
    fn missing_intrinsic_grants_fail_before_decoding_or_executing_source() {
        let mut registry = registry_with_referrer();
        registry.register_workspace_module(
            "/app/state.wasm", ModuleDefinition::new(ModuleSyntax::Wasm, "not wasm"),
        ).unwrap();
        for caps in [
            std::collections::BTreeSet::new(),
            [RuntimeCapability::ModuleLoad].into_iter().collect(),
            [RuntimeCapability::VmDispatch].into_iter().collect(),
        ] {
            denied(registry.load_wasm(&request(), &context("deny"), &CapabilityPolicyHook::new(caps), WasmNumericLimits::default()));
        }
        assert!(matches!(registry.load_wasm(&request(), &context("allow"), &policy(), WasmNumericLimits::default()),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::InvalidModule { .. }))));
    }

    #[test]
    fn revocation_blocks_startup_calls_and_inspection_without_mutating_state() {
        let module = load(&resolver(STATE_MODULE));
        let ctx = context("current-policy");
        let grants = policy();
        let revoked = CapabilityPolicyHook::new([RuntimeCapability::ModuleLoad].into_iter().collect());
        denied(module.instantiate(&ctx, &revoked));
        let mut instance = module.instantiate(&ctx, &grants).unwrap();
        denied(instance.call_export("step", &[WasmBoundaryValue::I32(99)], &ctx, &revoked));
        denied(instance.call_export("drop", &[], &ctx, &revoked));
        denied(instance.memory_export("m", &ctx, &revoked));
        denied(instance.global_export("g", &ctx, &revoked));
        denied(instance.table_export("any", &ctx, &revoked));
        denied(instance.start_execution(&ctx, &revoked));
        assert_eq!(instance.call_export("step", &[WasmBoundaryValue::I32(2)], &ctx, &grants).unwrap().results,
            [WasmBoundaryValue::I32(42)]);
        // The denied drop must not have consumed the passive segment.
        instance.call_export("init", &args([16, 0, 3]), &ctx, &grants).unwrap();
        assert_eq!(&instance.memory_export("m", &ctx, &grants).unwrap().unwrap()[16..19], &[0xff, 0x80, 0xfe]);
    }

    #[test]
    fn request_alias_and_canonical_denials_are_rechecked_after_loading() {
        let module = load(&resolver(STATE_MODULE));
        let ctx = context("deny-list-update");
        let mut instance = module.instantiate(&ctx, &policy()).unwrap();
        for specifier in ["./state.wasm", "/app/state.wasm"] {
            let denied_policy = policy().deny_specifier(specifier);
            denied(instance.call_export("step", &[WasmBoundaryValue::I32(99)], &ctx, &denied_policy));
            denied(module.instantiate(&ctx, &denied_policy));
        }
        assert_eq!(instance.global_export("g", &ctx, &policy()).unwrap(), Some(&WasmBoundaryValue::I32(40)));
    }

    #[test]
    fn declared_additional_capabilities_are_not_lost_at_native_dispatch() {
        let mut registry = registry_with_referrer();
        registry.register_workspace_module("/app/state.wasm",
            ModuleDefinition::wasm_binary(STATE_MODULE, &WasmNumericLimits::default()).unwrap()
                .require_capability(RuntimeCapability::FsRead)).unwrap();
        denied(registry.load_wasm(&request(), &context("deny"), &policy(), WasmNumericLimits::default()));
        let mut grants = policy();
        grants.granted_capabilities.insert(RuntimeCapability::FsRead);
        let module = registry.load_wasm(&request(), &context("allow"), &grants, WasmNumericLimits::default()).unwrap();
        let mut instance = module.instantiate(&context("allow"), &grants).unwrap();
        denied(instance.call_export("step", &[WasmBoundaryValue::I32(1)], &context("revoked-fs"), &policy()));
        assert_eq!(instance.call_export("step", &[WasmBoundaryValue::I32(2)], &context("allow"), &grants).unwrap().results,
            [WasmBoundaryValue::I32(42)]);
    }

    #[test]
    fn passive_binary_data_and_drop_execute_through_the_resolved_import() {
        let module = load(&resolver(STATE_MODULE));
        let ctx = context("allow");
        let grants = policy();
        let mut a = module.instantiate(&ctx, &grants).unwrap();
        let mut b = module.instantiate(&ctx, &grants).unwrap();
        a.call_export("init", &args([16, 0, 3]), &ctx, &grants).unwrap();
        a.call_export("drop", &[], &ctx, &grants).unwrap();
        a.call_export("drop", &[], &ctx, &grants).unwrap();
        assert!(matches!(a.call_export("init", &args([20, 0, 1]), &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::DataSourceOutOfBounds { data_bytes: 0, .. })))));
        b.call_export("init", &args([20, 0, 3]), &ctx, &grants).unwrap();
        assert_eq!(&a.memory_export("m", &ctx, &grants).unwrap().unwrap()[16..19], &[0xff, 0x80, 0xfe]);
        assert_eq!(&b.memory_export("m", &ctx, &grants).unwrap().unwrap()[20..23], &[0xff, 0x80, 0xfe]);
    }

    #[test]
    fn wrong_arity_types_and_export_names_do_not_change_guest_state() {
        let module = load(&resolver(STATE_MODULE));
        let ctx = context("allow");
        let grants = policy();
        let mut instance = module.instantiate(&ctx, &grants).unwrap();
        assert!(matches!(instance.call_export("step", &[], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::ArityMismatch { .. }))));
        assert!(matches!(instance.call_export("step", &[WasmBoundaryValue::I64(2)], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::TypeMismatch { .. }))));
        assert!(matches!(instance.call_export("hidden", &[], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::UnknownExport { .. }))));
        assert_eq!(instance.global_export("g", &ctx, &grants).unwrap(), Some(&WasmBoundaryValue::I32(40)));
    }

    #[test]
    fn limits_apply_to_startup_and_every_later_call() {
        let registry = resolver(STATE_MODULE);
        let ctx = context("allow");
        let grants = policy();
        let module = registry.load_wasm(&request(), &ctx, &grants,
            WasmNumericLimits { max_memory_pages: 0, ..WasmNumericLimits::default() }).unwrap();
        assert!(matches!(module.instantiate(&ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::LimitExceeded { .. })))));
        let module = registry.load_wasm(&request(), &ctx, &grants,
            WasmNumericLimits { max_instructions: 2, ..WasmNumericLimits::default() }).unwrap();
        assert!(matches!(module.instantiate(&ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 2 }))));
        let module = registry.load_wasm(&request(), &ctx, &grants,
            WasmNumericLimits { max_instructions: 3, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = module.instantiate(&ctx, &grants).unwrap();
        for _ in 0..2 {
            assert!(matches!(instance.call_export("step", &[WasmBoundaryValue::I32(1)], &ctx, &grants),
                Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 3 }))));
            assert_eq!(instance.global_export("g", &ctx, &grants).unwrap(), Some(&WasmBoundaryValue::I32(40)));
        }
    }

    #[test]
    fn later_guest_traps_preserve_completed_writes_without_escaping_the_instance() {
        let module = load(&resolver(TRAP_MODULE));
        let ctx = context("allow");
        let grants = policy();
        let mut instance = module.instantiate(&ctx, &grants).unwrap();
        assert!(matches!(instance.call_export("step", &[WasmBoundaryValue::I32(7)], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
        assert_eq!(instance.global_export("g", &ctx, &grants).unwrap(), Some(&WasmBoundaryValue::I32(7)));
        assert_eq!(&instance.memory_export("m", &ctx, &grants).unwrap().unwrap()[..4], &[7, 0, 0, 0]);
        let other = module.instantiate(&ctx, &grants).unwrap();
        assert_eq!(other.global_export("g", &ctx, &grants).unwrap(), Some(&WasmBoundaryValue::I32(0)));
    }

    #[test]
    fn loading_never_synthesizes_an_imported_host_binding() {
        let module = load(&resolver(HOST_MODULE));
        let ctx = context("allow");
        let grants = policy();
        let mut instance = module.instantiate(&ctx, &grants).unwrap();
        assert!(matches!(instance.call_export("call", &[], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::ImportedFunctionUnsupported { module, name, .. }))
                if module == "env" && name == "host"));
    }

    #[test]
    fn require_and_non_wasm_sources_cannot_enter_the_native_route() {
        let registry = resolver(STATE_MODULE);
        let req = ModuleRequest::new("/app/state.wasm", ImportStyle::Require);
        assert!(matches!(registry.load_wasm(&req, &context("allow"), &policy(), WasmNumericLimits::default()),
            Err(WasmNativeLoadError::UnsupportedImportStyle)));
        let mut registry = DeterministicModuleResolver::new("/app");
        registry.register_workspace_module("/app/main.mjs", ModuleDefinition::new(ModuleSyntax::EsModule, "export const n = 1;")).unwrap();
        let req = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
        assert!(matches!(registry.load_wasm(&req, &context("allow"), &policy(), WasmNumericLimits::default()),
            Err(WasmNativeLoadError::UnsupportedSyntax { syntax: ModuleSyntax::EsModule })));
    }

    #[test]
    fn malformed_envelopes_and_size_limits_fail_before_compilation() {
        for payload in ["0", "gg", "FF", "00 0", "é"] {
            let mut registry = registry_with_referrer();
            registry.register_workspace_module("/app/state.wasm", ModuleDefinition::new(
                ModuleSyntax::Wasm, format!("{BINARY_SOURCE_PREFIX}{payload}"),
            )).unwrap();
            assert!(matches!(registry.load_wasm(&request(), &context("allow"), &policy(), WasmNumericLimits::default()),
                Err(WasmNativeLoadError::InvalidBinarySource)));
        }
        let limits = WasmNumericLimits { max_module_bytes: STATE_MODULE.len() - 1, ..WasmNumericLimits::default() };
        assert!(matches!(ModuleDefinition::wasm_binary(STATE_MODULE, &limits),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::ModuleTooLarge { .. }))));
        assert!(matches!(resolver(STATE_MODULE).load_wasm(&request(), &context("allow"), &policy(), limits),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::ModuleTooLarge { .. }))));
    }

    #[test]
    fn tampered_hashes_and_attenuated_contracts_cannot_publish_a_compiled_module() {
        let registry = resolver(STATE_MODULE);
        let ctx = context("allow");
        let grants = policy();
        let original = registry.resolve(&request(), &ctx, &grants).unwrap();
        let mut altered = original.clone();
        altered.module.record.source.push_str("00");
        assert!(matches!(WasmNativeModule::compile(request(), altered, &ctx, &grants, WasmNumericLimits::default()),
            Err(WasmNativeLoadError::ContentHashMismatch)));
        let mut altered = original;
        altered.module.record.required_capabilities.clear();
        altered.module.content_hash = altered.module.record.canonical_hash();
        assert!(matches!(WasmNativeModule::compile(request(), altered, &ctx, &grants, WasmNumericLimits::default()),
            Err(WasmNativeLoadError::InvalidModuleContract)));
    }

    #[test]
    fn loaded_identity_is_pinned_while_new_loads_observe_registry_updates() {
        let mut registry = resolver(STATE_MODULE);
        let old = load(&registry);
        registry.register_workspace_module("/app/state.wasm",
            ModuleDefinition::wasm_binary(TRAP_MODULE, &WasmNumericLimits::default()).unwrap()).unwrap();
        let new = load(&registry);
        assert_ne!(old.resolution().module.content_hash, new.resolution().module.content_hash);
        let ctx = context("allow");
        let grants = policy();
        assert_eq!(old.instantiate(&ctx, &grants).unwrap().call_export("step", &[WasmBoundaryValue::I32(2)], &ctx, &grants).unwrap().results,
            [WasmBoundaryValue::I32(42)]);
        assert!(matches!(new.instantiate(&ctx, &grants).unwrap().call_export("step", &[WasmBoundaryValue::I32(2)], &ctx, &grants),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
    }

    #[test]
    fn fixed_inputs_replay_resolution_and_native_execution_identically() {
        let registry = resolver(STATE_MODULE);
        let a = load(&registry);
        let b = load(&registry);
        assert_eq!(a.resolution().trace_record().to_json_line().unwrap(), b.resolution().trace_record().to_json_line().unwrap());
        assert_eq!(a.resolution().module.content_hash, b.resolution().module.content_hash);
        let ctx = context("allow");
        let grants = policy();
        let first = a.instantiate(&ctx, &grants).unwrap().call_export("step", &[WasmBoundaryValue::I32(2)], &ctx, &grants).unwrap();
        let second = b.instantiate(&ctx, &grants).unwrap().call_export("step", &[WasmBoundaryValue::I32(2)], &ctx, &grants).unwrap();
        assert_eq!(first, second);
    }
}
