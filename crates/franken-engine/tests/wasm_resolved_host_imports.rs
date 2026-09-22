#![forbid(unsafe_code)]

use RuntimeCapability::{Builtin, FsRead, ModuleLoad, VmDispatch};
use WasmBoundaryValue::I32;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
    wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmNativeModule, WasmValueType,
};
use std::collections::BTreeSet;
use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn leb(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (n & 127) as u8;
        n >>= 7;
        bytes.push(byte | if n == 0 { 0 } else { 128 });
        if n == 0 {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

fn fixture(start: bool, indirect: bool, missing: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(
        &mut bytes,
        1,
        &[
            3, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0, 0x60, 0, 1, 0x7f,
        ],
    );
    let count = if missing { 2 } else { 1 };
    let mut imports = vec![count, 1, b'h', 1, b'f', 0, 0];
    if missing {
        imports.extend([1, b'h', 1, b'x', 0, 0]);
    }
    section(&mut bytes, 2, &imports);
    section(
        &mut bytes,
        3,
        if start { &[3, 0, 2, 1] } else { &[2, 0, 2] },
    );
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    section(
        &mut bytes,
        7,
        &[
            6,
            1,
            b'f',
            0,
            count,
            1,
            b'h',
            0,
            0,
            1,
            b'p',
            0,
            count + 1,
            1,
            b'm',
            2,
            0,
            1,
            b'g',
            3,
            0,
            1,
            b't',
            1,
            0,
        ],
    );
    if start {
        section(&mut bytes, 8, &[count + 2]);
    }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    // A store BEFORE the host call makes pre-instruction policy denial observable.
    let mut call = vec![0x41, 9, 0x24, 0, 0x20, 0, 0x20, 1];
    if indirect {
        call.extend([0x41, 0, 0x11, 0, 0]);
    } else {
        call.extend([0x10, 0]);
    }
    call.extend([0x24, 0, 0x23, 0, 0x0b]);
    let pure = vec![0x41, 17, 0x0b];
    let startup = vec![0x41, 8, 0x41, 3, 0x10, 0, 0x24, 0, 0x0b];
    let mut bodies = vec![if start { 3 } else { 2 }];
    for code in [&call, &pure]
        .into_iter()
        .chain(if start { Some(&startup) } else { None })
    {
        bodies.extend(leb(code.len() + 1));
        bodies.push(0);
        bodies.extend(code);
    }
    section(&mut bytes, 10, &bodies);
    section(&mut bytes, 11, &[1, 0, 0x41, 8, 0x0b, 3, 255, 128, 254]);
    bytes
}

fn context() -> ResolutionContext {
    ResolutionContext::new(
        "trace-resolved-host",
        "decision-resolved-host",
        "current-policy",
    )
}

fn request() -> ModuleRequest {
    ModuleRequest::new("./host.wasm", ImportStyle::Import).with_referrer("/app/main.mjs")
}

fn policy(services: &[RuntimeCapability]) -> CapabilityPolicyHook {
    let mut caps = wasm_module_required_capabilities();
    caps.extend(services.iter().copied());
    CapabilityPolicyHook::new(caps)
}

fn load(
    bytes: &[u8],
    declared: &[RuntimeCapability],
    policy: &CapabilityPolicyHook,
    limits: WasmNumericLimits,
) -> Result<WasmNativeModule, WasmNativeLoadError> {
    let mut definition =
        ModuleDefinition::wasm_binary(bytes, &WasmNumericLimits::default()).unwrap();
    definition
        .required_capabilities
        .extend(declared.iter().copied());
    let mut resolver = DeterministicModuleResolver::new("/app");
    // Relative imports require a real registered referrer, not just a path.
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './host.wasm';"),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/host.wasm",
            definition.with_provenance("resolved-host-fixture"),
        )
        .unwrap();
    resolver.load_wasm(&request(), &context(), policy, limits)
}

fn signature() -> WasmFunctionSignature {
    WasmFunctionSignature {
        params: vec![WasmValueType::I32; 2],
        results: vec![WasmValueType::I32],
    }
}

fn bindings(
    granted: BTreeSet<RuntimeCapability>,
    required: BTreeSet<RuntimeCapability>,
    calls: Arc<AtomicUsize>,
) -> WasmHostImports {
    let mut imports = WasmHostImports::new(granted);
    imports
        .define("h", "f", signature(), required, 1, move |caller, args| {
            let [I32(address), I32(length)] = args else {
                panic!("validated host ABI");
            };
            let bytes = caller
                .read_memory(*address as u32, *length as u32)?
                .to_vec();
            caller.write_memory(32, &bytes)?;
            Ok(vec![I32((calls.fetch_add(1, Ordering::SeqCst) + 1) as i32)])
        })
        .unwrap();
    imports
}

fn ordinary(calls: Arc<AtomicUsize>) -> WasmHostImports {
    bindings(
        BTreeSet::from([VmDispatch, Builtin]),
        BTreeSet::from([Builtin]),
        calls,
    )
}

fn denied<T: fmt::Debug>(result: Result<T, WasmNativeLoadError>) {
    match result {
        Err(WasmNativeLoadError::Resolution(error)) => {
            assert_eq!(error.code, ResolutionErrorCode::PolicyDenied)
        }
        other => panic!("expected policy denial, got {other:?}"),
    }
}

fn host_denied<T: fmt::Debug>(result: Result<T, WasmNativeLoadError>, expected: RuntimeCapability) {
    assert!(matches!(result,
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { capability, .. }
        )))) if capability == expected));
}

#[test]
fn resolved_imports_execute_real_host_buffers_and_preserve_instance_state() {
    for indirect in [false, true] {
        let grants = policy(&[Builtin]);
        let module = load(
            &fixture(false, indirect, false),
            &[Builtin],
            &grants,
            WasmNumericLimits::default(),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut first = module
            .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
            .unwrap();
        let mut second = module
            .instantiate_with_imports(&context(), &grants, ordinary(Arc::new(AtomicUsize::new(0))))
            .unwrap();
        assert_eq!(
            first
                .call_export("f", &[I32(8), I32(3)], &context(), &grants)
                .unwrap()
                .results,
            [I32(1)]
        );
        assert_eq!(
            first
                .call_export("h", &[I32(8), I32(3)], &context(), &grants)
                .unwrap()
                .results,
            [I32(2)]
        );
        assert_eq!(
            first.global_export("g", &context(), &grants).unwrap(),
            Some(&I32(1))
        );
        assert_eq!(
            &first
                .memory_export("m", &context(), &grants)
                .unwrap()
                .unwrap()[32..35],
            &[255, 128, 254]
        );
        assert_eq!(
            first
                .call_export("p", &[], &context(), &grants)
                .unwrap()
                .results,
            [I32(17)]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            second
                .call_export("f", &[I32(8), I32(3)], &context(), &grants)
                .unwrap()
                .results,
            [I32(1)]
        );
        assert_eq!(
            module.resolution().module.canonical_specifier,
            "/app/host.wasm"
        );
    }
}

#[test]
fn process_policy_and_provider_grants_do_not_supply_undeclared_module_authority() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(true, false, false),
        &[],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    host_denied(
        module.instantiate_with_imports(&context(), &grants, ordinary(calls.clone())),
        Builtin,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn module_and_policy_cannot_manufacture_a_missing_provider_grant() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(true, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    for cap in [VmDispatch, Builtin] {
        let mut provider = BTreeSet::from([VmDispatch, Builtin]);
        provider.remove(&cap);
        let imports = bindings(provider, BTreeSet::from([Builtin]), calls.clone());
        host_denied(
            module.instantiate_with_imports(&context(), &grants, imports),
            cap,
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn current_policy_denies_before_guest_stores_host_calls_and_inspection() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(false, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    instance
        .call_export("f", &[I32(8), I32(3)], &context(), &grants)
        .unwrap();
    let before = instance
        .memory_export("m", &context(), &grants)
        .unwrap()
        .unwrap()
        .to_vec();
    for revoked_cap in [ModuleLoad, VmDispatch, Builtin] {
        let mut revoked = grants.clone();
        revoked.granted_capabilities.remove(&revoked_cap);
        for export in ["f", "h", "p"] {
            denied(instance.call_export(export, &[I32(8), I32(3)], &context(), &revoked));
        }
        denied(instance.memory_export("m", &context(), &revoked));
        denied(instance.global_export("g", &context(), &revoked));
        denied(instance.table_export("t", &context(), &revoked));
        denied(instance.start_execution(&context(), &revoked));
        denied(module.instantiate_with_imports(&context(), &revoked, ordinary(calls.clone())));
        assert_eq!(
            instance.global_export("g", &context(), &grants).unwrap(),
            Some(&I32(1))
        );
        assert_eq!(
            instance
                .memory_export("m", &context(), &grants)
                .unwrap()
                .unwrap(),
            before
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        instance
            .call_export("f", &[I32(8), I32(3)], &context(), &grants)
            .unwrap()
            .results,
        [I32(2)]
    );
}

#[test]
fn request_and_canonical_deny_lists_gate_linking_and_later_host_execution() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(false, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    for specifier in ["./host.wasm", "/app/host.wasm"] {
        let denied_policy = grants.clone().deny_specifier(specifier);
        denied(module.instantiate_with_imports(
            &context(),
            &denied_policy,
            ordinary(calls.clone()),
        ));
        denied(instance.call_export("f", &[I32(8), I32(3)], &context(), &denied_policy));
        denied(instance.call_export("h", &[I32(8), I32(3)], &context(), &denied_policy));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        instance.global_export("g", &context(), &grants).unwrap(),
        Some(&I32(0))
    );
}

#[test]
fn provider_revocation_is_permanent_but_only_stops_host_effects() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(false, true, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    assert!(instance.revoke_host_capability(Builtin));
    assert!(!instance.revoke_host_capability(Builtin));
    host_denied(
        instance.call_export("h", &[I32(8), I32(3)], &context(), &grants),
        Builtin,
    );
    host_denied(
        instance.call_export("f", &[I32(8), I32(3)], &context(), &grants),
        Builtin,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Unlike a module-policy denial, a host-only revocation allows preceding
    // guest instructions. Completed guest stores are not rolled back.
    assert_eq!(
        instance.global_export("g", &context(), &grants).unwrap(),
        Some(&I32(9))
    );
    assert_eq!(
        instance
            .call_export("p", &[], &context(), &grants)
            .unwrap()
            .results,
        [I32(17)]
    );
    assert_eq!(
        &instance
            .memory_export("m", &context(), &grants)
            .unwrap()
            .unwrap()[32..35],
        &[0; 3]
    );
    let mut fresh = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    assert_eq!(
        fresh
            .call_export("f", &[I32(8), I32(3)], &context(), &grants)
            .unwrap()
            .results,
        [I32(1)]
    );
}

#[test]
fn every_binding_and_signature_is_checked_before_startup() {
    let grants = policy(&[Builtin]);
    let calls = Arc::new(AtomicUsize::new(0));
    let module = load(
        &fixture(true, false, true),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        module.instantiate_with_imports(&context(), &grants, ordinary(calls.clone())),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
            WasmStateError::Host(WasmHostError::MissingBinding { .. })
        )))
    ));
    let module = load(
        &fixture(true, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let mut imports = WasmHostImports::new(BTreeSet::from([VmDispatch, Builtin]));
    imports
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![],
                results: vec![],
            },
            BTreeSet::from([Builtin]),
            1,
            |_, _| panic!("ABI-mismatched callback entered"),
        )
        .unwrap();
    assert!(matches!(
        module.instantiate_with_imports(&context(), &grants, imports),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
            WasmStateError::Host(WasmHostError::SignatureMismatch { .. })
        )))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unrelated_registry_bindings_do_not_demand_unused_authority() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(true, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut imports = ordinary(calls.clone());
    imports
        .define(
            "unused",
            "fs",
            signature(),
            BTreeSet::from([FsRead]),
            1,
            |_, _| panic!("undeclared provider must not be called"),
        )
        .unwrap();
    let instance = module
        .instantiate_with_imports(&context(), &grants, imports)
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        instance.global_export("g", &context(), &grants).unwrap(),
        Some(&I32(1))
    );
}

#[test]
fn default_instantiation_still_does_not_install_any_host_service() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(false, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let mut instance = module.instantiate(&context(), &grants).unwrap();
    assert!(matches!(
        instance.call_export("h", &[I32(8), I32(3)], &context(), &grants),
        Err(WasmNativeLoadError::Execution(
            WasmNumericVmError::ImportedFunctionUnsupported { .. }
        ))
    ));
    assert!(!instance.revoke_host_capability(Builtin));
}

#[test]
fn provider_module_and_policy_authority_intersections_cover_all_combinations() {
    let caps = |mask: u8| {
        [Builtin, FsRead]
            .into_iter()
            .enumerate()
            .filter_map(|(bit, cap)| (mask & (1 << bit) != 0).then_some(cap))
            .collect::<Vec<_>>()
    };
    let bytes = fixture(true, false, false);
    for provider in 0..4_u8 {
        for declared in 0..4_u8 {
            for allowed in 0..4_u8 {
                let grants = policy(&caps(allowed));
                let loaded = load(
                    &bytes,
                    &caps(declared),
                    &grants,
                    WasmNumericLimits::default(),
                );
                if declared & !allowed != 0 {
                    denied(loaded);
                    continue;
                }
                let module = loaded.unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let mut envelope: BTreeSet<_> = caps(provider).into_iter().collect();
                envelope.insert(VmDispatch);
                let imports = bindings(envelope, BTreeSet::from([Builtin, FsRead]), calls.clone());
                let result = module.instantiate_with_imports(&context(), &grants, imports);
                let expected = provider == 3 && declared == 3 && allowed == 3;
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "provider={provider}, declared={declared}, policy={allowed}"
                );
                assert_eq!(calls.load(Ordering::SeqCst), usize::from(expected));
            }
        }
    }
}

#[test]
fn linked_callbacks_use_the_module_budget_and_preserve_atomic_buffer_refusal() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(false, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits {
            max_instructions: 3,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    let before = instance
        .memory_export("m", &context(), &grants)
        .unwrap()
        .unwrap()
        .to_vec();
    for _ in 0..2 {
        assert!(matches!(
            instance.call_export("h", &[I32(8), I32(3)], &context(), &grants),
            Err(WasmNativeLoadError::Execution(
                WasmNumericVmError::InstructionBudgetExceeded { max: 3 }
            ))
        ));
        assert_eq!(
            instance
                .memory_export("m", &context(), &grants)
                .unwrap()
                .unwrap(),
            before
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn deterministic_host_provider_replays_start_and_export_metrics_with_pinned_identity() {
    let grants = policy(&[Builtin]);
    let module = load(
        &fixture(true, false, false),
        &[Builtin],
        &grants,
        WasmNumericLimits::default(),
    )
    .unwrap();
    let mut first = module
        .instantiate_with_imports(&context(), &grants, ordinary(Arc::new(AtomicUsize::new(0))))
        .unwrap();
    let mut second = module
        .instantiate_with_imports(&context(), &grants, ordinary(Arc::new(AtomicUsize::new(0))))
        .unwrap();
    assert_eq!(
        first.start_execution(&context(), &grants).unwrap(),
        second.start_execution(&context(), &grants).unwrap()
    );
    assert_eq!(
        first
            .start_execution(&context(), &grants)
            .unwrap()
            .unwrap()
            .instructions_executed,
        9
    );
    for expected in 2..=4 {
        let a = first
            .call_export("f", &[I32(8), I32(3)], &context(), &grants)
            .unwrap();
        let b = second
            .call_export("f", &[I32(8), I32(3)], &context(), &grants)
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.results, [I32(expected)]);
        assert_eq!(a.instructions_executed, 12);
    }
    assert_eq!(
        first.memory_export("m", &context(), &grants).unwrap(),
        second.memory_export("m", &context(), &grants).unwrap()
    );
}

#[test]
fn relative_host_imports_require_a_registered_referrer_before_linking() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/host.wasm",
            ModuleDefinition::wasm_binary(
                &fixture(false, false, false),
                &WasmNumericLimits::default(),
            )
            .unwrap()
            .require_capability(Builtin),
        )
        .unwrap();
    let grants = policy(&[Builtin]);
    assert!(
        matches!(resolver.load_wasm(&request(), &context(), &grants, WasmNumericLimits::default()),
        Err(WasmNativeLoadError::Resolution(error)) if error.code == ResolutionErrorCode::InvalidReferrer)
    );
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import './host.wasm';"),
        )
        .unwrap();
    let module = resolver
        .load_wasm(
            &request(),
            &context(),
            &grants,
            WasmNumericLimits::default(),
        )
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = module
        .instantiate_with_imports(&context(), &grants, ordinary(calls.clone()))
        .unwrap();
    assert_eq!(
        instance
            .call_export("f", &[I32(8), I32(3)], &context(), &grants)
            .unwrap()
            .results,
        [I32(1)]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
