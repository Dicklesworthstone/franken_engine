#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use WasmBoundaryValue::{F32Bits, F64Bits, I32, I64};

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend(payload);
}

struct Fixture {
    params: Vec<u8>,
    results: Vec<u8>,
    imports: Vec<(&'static str, &'static str)>,
    code: Vec<u8>,
    start: Option<Vec<u8>>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            params: vec![0x7f, 0x7f], results: vec![0x7f],
            imports: vec![("h", "f")],
            code: vec![0x20, 0, 0x20, 1, 0x10, 0, 0x0b], start: None,
        }
    }
}

impl Fixture {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        let mut types = vec![2, 0x60];
        types.extend(leb(self.params.len())); types.extend(&self.params);
        types.extend(leb(self.results.len())); types.extend(&self.results);
        types.extend([0x60, 0, 0]);
        section(&mut bytes, 1, &types);
        let mut imports = leb(self.imports.len());
        for (module, name) in &self.imports {
            imports.extend(leb(module.len())); imports.extend(module.as_bytes());
            imports.extend(leb(name.len())); imports.extend(name.as_bytes());
            imports.extend([0, 0]);
        }
        section(&mut bytes, 2, &imports);
        section(&mut bytes, 3, if self.start.is_some() { &[2, 0, 1] } else { &[1, 0] });
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
        let mut exports = vec![4, 1, b'f', 0]; exports.extend(leb(self.imports.len()));
        exports.extend([1, b'h', 0, 0, 1, b'g', 3, 0, 1, b't', 1, 0]);
        section(&mut bytes, 7, &exports);
        if self.start.is_some() { section(&mut bytes, 8, &leb(self.imports.len() + 1)); }
        section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
        let mut bodies = leb(1 + usize::from(self.start.is_some()));
        for code in std::iter::once(&self.code).chain(self.start.iter()) {
            bodies.extend(leb(code.len() + 1)); bodies.push(0); bodies.extend(code);
        }
        section(&mut bytes, 10, &bodies);
        bytes
    }

    fn vm(&self) -> WasmNumericVm {
        WasmNumericVm::parse(&self.bytes(), WasmNumericLimits::default()).unwrap()
    }
}

fn grants() -> BTreeSet<RuntimeCapability> {
    [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect()
}

fn signature() -> WasmFunctionSignature {
    WasmFunctionSignature { params: vec![WasmValueType::I32; 2], results: vec![WasmValueType::I32] }
}

fn imports<F>(granted: BTreeSet<RuntimeCapability>, callback: F) -> WasmHostImports
where
    F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue])
            -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync + 'static,
{
    let mut imports = WasmHostImports::new(granted);
    imports.define("h", "f", signature(), [RuntimeCapability::Builtin].into_iter().collect(), 3, callback).unwrap();
    imports
}

fn add(_: &mut WasmHostCaller<'_, '_>, args: &[WasmBoundaryValue]) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> {
    let [I32(a), I32(b)] = args else { panic!("typed arguments"); };
    Ok(vec![I32(a.wrapping_add(*b))])
}

#[test]
fn direct_exported_and_indirect_imports_share_the_typed_host_gate() {
    let vm = Fixture::default().vm();
    let mut instance = vm.instantiate_with_imports(imports(grants(), add)).unwrap();
    let result = instance.call_export("f", &[I32(20), I32(22)]).unwrap();
    assert_eq!(result.results, [I32(42)]);
    assert_eq!(result.instructions_executed, 8); // four opcodes + cost 3 + ABI work 1
    assert_eq!(result.max_call_depth, 2);
    let result = instance.call_export("h", &[I32(-9), I32(3)]).unwrap();
    assert_eq!(result.results, [I32(-6)]);
    assert_eq!(result.instructions_executed, 4);
    assert_eq!(result.max_call_depth, 1);
    let mut fixture = Fixture::default();
    fixture.code = vec![0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x0b];
    let vm = fixture.vm();
    let mut instance = vm.instantiate_with_imports(imports(grants(), add)).unwrap();
    let result = instance.call_export("f", &[I32(20), I32(22)]).unwrap();
    assert_eq!(result.results, [I32(42)]);
    assert_eq!(result.instructions_executed, 10); // includes indirect signature work
}

#[test]
fn default_instantiation_never_acquires_ambient_host_bindings() {
    let vm = Fixture::default().vm();
    for export in ["h", "f"] {
        assert!(matches!(vm.call_export(export, &[I32(20), I32(22)]),
            Err(WasmNumericVmError::ImportedFunctionUnsupported { function_index: 0, .. })));
    }
}

#[test]
fn all_imports_are_linked_before_startup_can_perform_any_host_effects() {
    let mut fixture = Fixture::default();
    fixture.imports.push(("missing", "f"));
    fixture.start = Some(vec![0x41, 20, 0x41, 22, 0x10, 0, 0x24, 0, 0x0b]);
    let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
    let vm = fixture.vm();
    let result = vm.instantiate_with_imports(imports(grants(), move |caller, args| {
        observed.fetch_add(1, Ordering::SeqCst); add(caller, args)
    }));
    assert!(matches!(result, Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { ref module, .. }))) if module == "missing"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_names_and_structural_signatures_are_required_at_link_time() {
    for (module, name) in [("H", "f"), ("h", "F"), ("h.f", "")] {
        let mut bindings = WasmHostImports::new(grants());
        bindings.define(module, name, signature(), [RuntimeCapability::Builtin].into_iter().collect(), 1, add).unwrap();
        assert!(matches!(Fixture::default().vm().instantiate_with_imports(bindings),
            Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { .. })))));
    }
    for signature in [
        WasmFunctionSignature { params: vec![WasmValueType::I64; 2], results: vec![WasmValueType::I32] },
        WasmFunctionSignature { params: vec![WasmValueType::I32; 2], results: vec![] },
    ] {
        let mut bindings = WasmHostImports::new(grants());
        bindings.define("h", "f", signature, [RuntimeCapability::Builtin].into_iter().collect(), 1, add).unwrap();
        assert!(matches!(Fixture::default().vm().instantiate_with_imports(bindings),
            Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::SignatureMismatch { .. })))));
    }
}

#[test]
fn vm_dispatch_and_every_declared_capability_are_required_before_start() {
    for missing in [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin] {
        let mut granted = grants(); granted.remove(&missing);
        let vm = Fixture::default().vm();
        assert!(matches!(vm.instantiate_with_imports(imports(granted, add)),
            Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability, .. }))) if capability == missing));
    }
    let mut bindings = WasmHostImports::new(grants());
    bindings.define("h", "f", signature(), [RuntimeCapability::Builtin, RuntimeCapability::FsRead].into_iter().collect(), 1, add).unwrap();
    assert!(matches!(Fixture::default().vm().instantiate_with_imports(bindings),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: RuntimeCapability::FsRead, .. })))));
}

#[test]
fn revocation_cannot_be_bypassed_by_exported_imports_or_table_dispatch() {
    for indirect in [false, true] {
        let mut fixture = Fixture::default();
        if indirect { fixture.code = vec![0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x0b]; }
        let vm = fixture.vm();
        let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
        let mut instance = vm.instantiate_with_imports(imports(grants(), move |caller, args| {
            observed.fetch_add(1, Ordering::SeqCst); add(caller, args)
        })).unwrap();
        assert_eq!(instance.call_export("f", &[I32(20), I32(22)]).unwrap().results, [I32(42)]);
        assert!(instance.revoke_host_capability(RuntimeCapability::Builtin));
        assert!(!instance.revoke_host_capability(RuntimeCapability::Builtin));
        for export in ["f", "h"] {
            assert!(matches!(instance.call_export(export, &[I32(20), I32(22)]),
                Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: RuntimeCapability::Builtin, .. })))));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn incorrect_arguments_and_host_results_never_enter_later_guest_code() {
    let mut fixture = Fixture::default();
    fixture.code = vec![0x20, 0, 0x20, 1, 0x10, 0, 0x24, 0, 0x23, 0, 0x0b];
    let vm = fixture.vm();
    for results in [vec![], vec![I64(42)], vec![I32(42), I32(9)]] {
        let mut instance = vm.instantiate_with_imports(imports(grants(), move |_, _| Ok(results.clone()))).unwrap();
        assert!(matches!(instance.call_export("f", &[I32(20), I32(22)]),
            Err(WasmNumericVmError::ResultStackMismatch { .. } | WasmNumericVmError::TypeMismatch { .. })));
        assert_eq!(instance.global_export("g"), Some(&I32(0)));
    }
    let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
    let mut instance = vm.instantiate_with_imports(imports(grants(), move |caller, args| {
        observed.fetch_add(1, Ordering::SeqCst); add(caller, args)
    })).unwrap();
    assert!(matches!(instance.call_export("h", &[I32(1)]), Err(WasmNumericVmError::ArityMismatch { .. })));
    assert!(matches!(instance.call_export("h", &[I32(1), I64(2)]), Err(WasmNumericVmError::TypeMismatch { .. })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn callbacks_preserve_exact_multivalue_bits() {
    let mut fixture = Fixture::default();
    fixture.params = vec![0x7d, 0x7e, 0x7c, 0x7f]; fixture.results = fixture.params.clone();
    fixture.code = vec![0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x10, 0, 0x0b];
    let mut bindings = WasmHostImports::new(grants());
    let types = vec![WasmValueType::F32, WasmValueType::I64, WasmValueType::F64, WasmValueType::I32];
    bindings.define("h", "f", WasmFunctionSignature { params: types.clone(), results: types },
        [RuntimeCapability::Builtin].into_iter().collect(), 1, |_, args| Ok(args.to_vec())).unwrap();
    let vm = fixture.vm(); let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    let args = [F32Bits(0x7f80_0001), I64(i64::MIN), F64Bits(0x8000_0000_0000_0000), I32(-9)];
    assert_eq!(instance.call_export("f", &args).unwrap().results, args);
}

#[test]
fn host_startup_runs_once_and_shares_owned_callback_state_with_later_calls() {
    let mut fixture = Fixture::default();
    fixture.start = Some(vec![0x41, 20, 0x41, 22, 0x10, 0, 0x24, 0, 0x0b]);
    let vm = fixture.vm();
    let build = || {
        let mut count = 0;
        imports(grants(), move |_, _| { count += 1; Ok(vec![I32(count)]) })
    };
    let mut first = vm.instantiate_with_imports(build()).unwrap();
    let mut second = vm.instantiate_with_imports(build()).unwrap();
    assert_eq!(first.global_export("g"), Some(&I32(1)));
    assert_eq!(first.start_execution().unwrap().instructions_executed, 9);
    assert_eq!(first.call_export("f", &[I32(0), I32(0)]).unwrap().results, [I32(2)]);
    assert_eq!(first.call_export("h", &[I32(0), I32(0)]).unwrap().results, [I32(3)]);
    assert_eq!(second.call_export("f", &[I32(0), I32(0)]).unwrap().results, [I32(2)]);
    assert_eq!(first.global_export("g"), Some(&I32(1)));
}

#[test]
fn host_budget_is_precharged_and_ignored_provider_refusals_remain_fatal() {
    let fixture = Fixture::default();
    let vm = WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_instructions: 6, ..WasmNumericLimits::default() }).unwrap();
    let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
    let mut instance = vm.instantiate_with_imports(imports(grants(), move |caller, args| {
        observed.fetch_add(1, Ordering::SeqCst); add(caller, args)
    })).unwrap();
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2)]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 6 })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let vm = fixture.vm();
    let mut instance = vm.instantiate_with_imports(imports(grants(), |caller, _| {
        let before = caller.remaining_work();
        assert!(caller.charge_work(u64::MAX).is_err());
        assert_eq!(caller.remaining_work(), before);
        assert!(caller.charge_work(0).is_err());
        Ok(vec![I32(999)]) // provider's attempted refusal suppression
    })).unwrap();
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2)]), Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
    let mut instance = vm.instantiate_with_imports(imports(grants(), |caller, args| {
        caller.charge_work(5)?; add(caller, args)
    })).unwrap();
    assert_eq!(instance.call_export("f", &[I32(1), I32(2)]).unwrap().instructions_executed, 13);
}

#[test]
fn registration_rejects_missing_authority_free_calls_and_duplicate_replacement() {
    let mut bindings = imports(grants(), add);
    assert_eq!(bindings.define("h", "f", signature(), [RuntimeCapability::Builtin].into_iter().collect(), 1, |_, _| Ok(vec![I32(999)])),
        Err(WasmHostError::DuplicateBinding { module: "h".into(), name: "f".into() }));
    assert_eq!(bindings.define("h", "zero", signature(), [RuntimeCapability::Builtin].into_iter().collect(), 0, add), Err(WasmHostError::ZeroCallCost));
    assert_eq!(bindings.define("h", "ambient", signature(), BTreeSet::new(), 1, add), Err(WasmHostError::MissingAuthority));
    let vm = Fixture::default().vm();
    assert_eq!(vm.instantiate_with_imports(bindings).unwrap().call_export("h", &[I32(20), I32(22)]).unwrap().results, [I32(42)]);
}

#[test]
fn host_traps_retain_completed_guest_effects_and_do_not_publish_failed_starts() {
    let mut fixture = Fixture::default();
    fixture.code = vec![0x41, 7, 0x24, 0, 0x20, 0, 0x20, 1, 0x10, 0, 0x0b];
    let vm = fixture.vm();
    let mut instance = vm.instantiate_with_imports(imports(grants(), |_, _| Err(WasmHostError::trap("provider failure").into()))).unwrap();
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2)]), Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. })))));
    assert_eq!(instance.global_export("g"), Some(&I32(7)));
    fixture.start = Some(vec![0x41, 1, 0x41, 2, 0x10, 0, 0x1a, 0x0b]);
    assert!(matches!(fixture.vm().instantiate_with_imports(imports(grants(), |_, _| Err(WasmHostError::trap("startup failure").into()))),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. })))));
}

#[test]
fn imported_start_functions_use_the_same_permission_and_result_contract() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
    section(&mut bytes, 8, &[0]);
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
    let mut bindings = WasmHostImports::new(grants());
    bindings.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
        [RuntimeCapability::Builtin].into_iter().collect(), 3, move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst); Ok(vec![])
        }).unwrap();
    let instance = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 3);
    assert!(matches!(vm.instantiate(), Err(WasmNumericVmError::ImportedFunctionUnsupported { .. })));
}

#[test]
fn cost_overflow_and_call_depth_refuse_before_host_entry() {
    let fixture = Fixture::default();
    let vm = fixture.vm();
    let mut bindings = WasmHostImports::new(grants());
    bindings.define("h", "f", signature(), [RuntimeCapability::Builtin].into_iter().collect(), u64::MAX,
        |_, _| panic!("cost overflow must refuse before entry")).unwrap();
    assert!(matches!(vm.instantiate_with_imports(bindings).unwrap().call_export("h", &[I32(1), I32(2)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
    let vm = WasmNumericVm::parse(&fixture.bytes(), WasmNumericLimits { max_call_depth: 1, ..WasmNumericLimits::default() }).unwrap();
    let mut instance = vm.instantiate_with_imports(imports(grants(), |_, _| panic!("depth refusal before host"))).unwrap();
    assert!(matches!(instance.call_export("f", &[I32(1), I32(2)]), Err(WasmNumericVmError::CallDepthExceeded { max: 1 })));
}

#[test]
fn host_instances_preserve_send_and_sync_embedding_contracts() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<frankenengine_engine::wasm_runtime_lane::numeric::WasmNumericInstance<'static>>();
}
