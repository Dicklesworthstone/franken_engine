#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::esm_loader::{EsmModule, ModuleGraph, ModuleStatus};
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleDependency, ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext,
    ResolutionErrorCode, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WASM_MODULE_ROUTE_COMPONENT, WasmBoundaryValue, WasmModuleImportRoute, WasmModuleRouteError,
    WasmValueType,
};

fn context() -> ResolutionContext {
    ResolutionContext::new(
        "trace-wasm-loader",
        "decision-wasm-loader",
        "policy-wasm-loader",
    )
}

fn wasm_fixture(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("test wasm fixture should be utf-8 compatible")
}

fn const_i32_answer_wasm() -> String {
    wasm_fixture(&[
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // type: () -> i32
        0x03, 0x02, 0x01, 0x00, // function: type 0
        0x07, 0x0a, 0x01, 0x06, b'a', b'n', b's', b'w', b'e', b'r', 0x00,
        0x00, // export answer
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b, // body: i32.const 42
    ])
}

fn param_i32_const_wasm() -> String {
    wasm_fixture(&[
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, // type: (i32) -> i32
        0x03, 0x02, 0x01, 0x00, // function: type 0
        0x07, 0x0b, 0x01, 0x07, b'e', b'c', b'h', b'o', b'i', b's', b'h', 0x00,
        0x00, // export echoish
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x07, 0x0b, // body: i32.const 7
    ])
}

fn register_wasm_fixture() -> DeterministicModuleResolver {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "import wasm from './math.wasm';")
                .with_dependency(ModuleDependency::new("./math.wasm", ImportStyle::Import)),
        )
        .unwrap();
    resolver
        .register_workspace_module(
            "/app/math.wasm",
            ModuleDefinition::new(ModuleSyntax::EsModule, const_i32_answer_wasm()),
        )
        .unwrap();
    resolver
}

fn wasm_policy() -> CapabilityPolicyHook {
    CapabilityPolicyHook::new(wasm_module_required_capabilities())
}

#[test]
fn wasm_import_requires_explicit_capabilities() {
    let resolver = register_wasm_fixture();
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let err = resolver
        .resolve_chain(
            &request,
            &context(),
            &CapabilityPolicyHook::new(BTreeSet::new()),
        )
        .expect_err("wasm dependency must fail closed without explicit grants");

    assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
    assert!(err.message.contains("module_load"));
    assert!(err.message.contains("vm_dispatch"));
    assert!(err.message.contains("/app/math.wasm"));
}

#[test]
fn granted_wasm_import_routes_to_wasm_runtime_lane() {
    let resolver = register_wasm_fixture();
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let chain = resolver
        .resolve_chain(&request, &context(), &wasm_policy())
        .expect("explicit wasm grants should allow the dependency chain");

    let wasm = chain
        .iter()
        .find(|outcome| outcome.module.canonical_specifier == "/app/math.wasm")
        .expect("wasm dependency should be present in the chain");
    assert_eq!(wasm.module.record.syntax, ModuleSyntax::Wasm);
    assert_eq!(
        wasm.module.record.required_capabilities,
        BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::VmDispatch])
    );

    let route = WasmModuleImportRoute::from_resolved_module(&wasm.module)
        .expect("wasm module should route");
    assert_eq!(route.canonical_specifier, "/app/math.wasm");
    assert_eq!(route.module_id, "/app/math.wasm");
    assert_eq!(route.content_hash, wasm.module.content_hash);
    assert_eq!(route.route_component, WASM_MODULE_ROUTE_COMPONENT);
    assert_eq!(
        route.required_capabilities,
        wasm_module_required_capabilities()
    );
    let export = route
        .abi
        .function_exports
        .get("answer")
        .expect("answer export should be typed");
    assert_eq!(export.signature.params, Vec::<WasmValueType>::new());
    assert_eq!(export.signature.results, vec![WasmValueType::I32]);
    assert_eq!(export.const_body, Some(vec![WasmBoundaryValue::I32(42)]));
}

#[test]
fn require_of_wasm_fails_closed() {
    let mut resolver = register_wasm_fixture();
    resolver
        .register_workspace_module(
            "/app/main.cjs",
            ModuleDefinition::new(
                ModuleSyntax::CommonJs,
                "module.exports = require('./math.wasm');",
            ),
        )
        .unwrap();

    let request =
        ModuleRequest::new("./math.wasm", ImportStyle::Require).with_referrer("/app/main.cjs");
    let err = resolver
        .resolve(&request, &context(), &wasm_policy())
        .expect_err("CommonJS require of wasm should fail closed");

    assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
    assert!(err.message.contains("WebAssembly module"));
    assert!(err.message.contains("explicit wasm capabilities"));
}

#[test]
fn wasm_import_replay_is_byte_identical() {
    let resolver = register_wasm_fixture();
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);

    let first = resolver
        .resolve_chain(&request, &context(), &wasm_policy())
        .expect("first replay should resolve");
    let second = resolver
        .resolve_chain(&request, &context(), &wasm_policy())
        .expect("second replay should resolve");

    let first_artifacts: Vec<_> = first
        .iter()
        .map(|outcome| {
            (
                outcome.module.canonical_specifier.clone(),
                outcome.module.content_hash,
                outcome.trace_record().to_json_line().unwrap(),
            )
        })
        .collect();
    let second_artifacts: Vec<_> = second
        .iter()
        .map(|outcome| {
            (
                outcome.module.canonical_specifier.clone(),
                outcome.module.content_hash,
                outcome.trace_record().to_json_line().unwrap(),
            )
        })
        .collect();

    assert_eq!(first_artifacts, second_artifacts);
}

#[test]
fn wasm_export_call_returns_deterministic_typed_result() {
    let resolver = register_wasm_fixture();
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let chain = resolver
        .resolve_chain(&request, &context(), &wasm_policy())
        .expect("explicit wasm grants should allow the dependency chain");
    let wasm = chain
        .iter()
        .find(|outcome| outcome.module.canonical_specifier == "/app/math.wasm")
        .expect("wasm dependency should be present in the chain");

    let route = WasmModuleImportRoute::from_resolved_module(&wasm.module)
        .expect("wasm module should route");

    assert_eq!(
        route
            .call_export("answer", &[])
            .expect("answer should be callable"),
        vec![WasmBoundaryValue::I32(42)]
    );
}

#[test]
fn wasm_export_call_rejects_wrong_parameter_type() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/typed.wasm",
            ModuleDefinition::new(ModuleSyntax::Wasm, param_i32_const_wasm()),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/typed.wasm", ImportStyle::Import);
    let resolved = resolver
        .resolve(&request, &context(), &wasm_policy())
        .expect("typed wasm module should resolve");
    let route = WasmModuleImportRoute::from_resolved_module(&resolved.module)
        .expect("typed wasm module should route");

    assert_eq!(
        route
            .call_export("echoish", &[WasmBoundaryValue::I32(9)])
            .expect("i32 argument should pass boundary type check"),
        vec![WasmBoundaryValue::I32(7)]
    );

    let err = route
        .call_export("echoish", &[WasmBoundaryValue::I64(9)])
        .expect_err("i64 argument should fail the i32 boundary contract");
    assert_eq!(
        err,
        WasmModuleRouteError::ParameterTypeMismatch {
            module_id: "/app/typed.wasm".to_string(),
            export_name: "echoish".to_string(),
            parameter_index: 0,
            expected: WasmValueType::I32,
            actual: WasmValueType::I64,
        }
    );
}

#[test]
fn invalid_wasm_module_fails_closed_at_route_boundary() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/bad.wasm",
            ModuleDefinition::new(ModuleSyntax::Wasm, "\0asm deterministic fixture"),
        )
        .unwrap();
    let request = ModuleRequest::new("/app/bad.wasm", ImportStyle::Import);
    let resolved = resolver
        .resolve(&request, &context(), &wasm_policy())
        .expect("resolver should only classify the wasm module");

    let err = WasmModuleImportRoute::from_resolved_module(&resolved.module)
        .expect_err("invalid wasm bytes should fail closed before runtime routing");
    assert_eq!(
        err,
        WasmModuleRouteError::InvalidWasmModule {
            module_id: "/app/bad.wasm".to_string(),
            reason: "unsupported wasm version".to_string(),
        }
    );
}

#[test]
fn non_wasm_module_cannot_route_to_wasm_lane() {
    let resolver = register_wasm_fixture();
    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let entry = resolver
        .resolve(&request, &context(), &wasm_policy())
        .expect("entry module should resolve");

    let err = WasmModuleImportRoute::from_resolved_module(&entry.module)
        .expect_err("ES module should not route to wasm lane");
    assert_eq!(
        err,
        WasmModuleRouteError::UnsupportedSyntax {
            module_id: "/app/main.mjs".to_string(),
            syntax: ModuleSyntax::EsModule,
        }
    );
}

#[test]
fn esm_loader_accepts_wasm_module_record() {
    let mut graph = ModuleGraph::new();
    graph
        .add_module(EsmModule::wasm("/app/math.wasm", const_i32_answer_wasm()))
        .expect("wasm module should enter the ESM graph");

    let linked = graph.link().expect("single wasm module should link");
    let evaluated = graph
        .evaluate()
        .expect("single wasm module should evaluate");
    let module = graph
        .get_module("/app/math.wasm")
        .expect("wasm module should remain addressable");

    assert_eq!(linked.linked_count, 1);
    assert_eq!(evaluated.evaluated_count, 1);
    assert_eq!(module.syntax, ModuleSyntax::Wasm);
    assert_eq!(module.status, ModuleStatus::Evaluated);
}
