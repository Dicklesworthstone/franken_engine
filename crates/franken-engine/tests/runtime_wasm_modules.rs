#![forbid(unsafe_code)]
//! Actual JavaScript source imports execute the shared Rust Wasm VM in both
//! interpreter profiles. The provider supplies captured binary bytes only.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterError, LaneChoice};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
    OrchestratorResult,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, CapabilityPolicyHook, DeterministicModuleResolver, ExecutionModuleResolver,
    ImportStyle, ModuleDefinition, ModulePolicyHook, ModuleRecord, ModuleRequest, ModuleResolver,
    ModuleSyntax, ResolutionContext, ResolutionResult,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::wasm_runtime_lane::numeric::WasmNumericLimits;
use frankenengine_extension_host::host_io::{EnvironmentSnapshotHostIo, HostIoProvider};

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len() as u32));
    module.extend_from_slice(payload);
}

type Function<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);

fn binary(
    functions: &[Function<'_>],
    global: bool,
    memory: Option<u32>,
    start: Option<u32>,
) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    let mut types = leb(functions.len() as u32);
    let mut indices = leb(functions.len() as u32);
    let mut exports = leb(functions.len() as u32);
    let mut bodies = leb(functions.len() as u32);
    for (index, (name, params, results, code)) in functions.iter().enumerate() {
        types.push(0x60);
        types.extend(leb(params.len() as u32));
        types.extend_from_slice(params);
        types.extend(leb(results.len() as u32));
        types.extend_from_slice(results);
        indices.extend(leb(index as u32));
        exports.extend(leb(name.len() as u32));
        exports.extend_from_slice(name.as_bytes());
        exports.push(0);
        exports.extend(leb(index as u32));
        bodies.extend(leb(code.len() as u32 + 1));
        bodies.push(0); // no additional locals
        bodies.extend_from_slice(code);
    }
    section(&mut module, 1, &types);
    section(&mut module, 3, &indices);
    if let Some(pages) = memory {
        let mut limits = vec![1, 1];
        limits.extend(leb(pages));
        limits.extend(leb(pages));
        section(&mut module, 5, &limits);
    }
    if global {
        section(&mut module, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    }
    section(&mut module, 7, &exports);
    if let Some(index) = start {
        section(&mut module, 8, &leb(index));
    }
    section(&mut module, 10, &bodies);
    module
}

fn add_binary() -> Vec<u8> {
    binary(
        &[(
            "add",
            &[0x7f, 0x7f],
            &[0x7f],
            &[0x20, 0, 0x20, 1, 0x6a, 0x0b],
        )],
        false,
        None,
        None,
    )
}

fn run(
    lane: LaneChoice,
    source: &str,
    bytes: &[u8],
    runtime: RuntimeConfig,
    policy: Arc<dyn ModulePolicyHook + Send + Sync>,
    vm_grant: bool,
) -> (Result<OrchestratorResult, OrchestratorError>, Vec<String>) {
    execute(
        lane,
        source,
        bytes,
        RunOptions {
            runtime,
            policy,
            vm_grant,
            host: None,
            cancellation: None,
        },
    )
}

struct RunOptions {
    runtime: RuntimeConfig,
    policy: Arc<dyn ModulePolicyHook + Send + Sync>,
    vm_grant: bool,
    host: Option<Arc<dyn HostIoProvider>>,
    cancellation: Option<CancellationToken>,
}

fn execute(
    lane: LaneChoice,
    source: &str,
    bytes: &[u8],
    options: RunOptions,
) -> (Result<OrchestratorResult, OrchestratorError>, Vec<String>) {
    let mut resolver = DeterministicModuleResolver::new("/wasm-js");
    resolver
        .register_workspace_module(
            "/wasm-js/entry.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, source),
        )
        .unwrap();
    for name in ["math.wasm", "other.wasm"] {
        resolver
            .register_workspace_module(
                format!("/wasm-js/{name}"),
                ModuleDefinition::wasm_binary(bytes, &WasmNumericLimits::default()).unwrap(),
            )
            .unwrap();
    }
    let resolver = Arc::new(resolver);
    let entry = resolver
        .resolve(
            &ModuleRequest::new("/wasm-js/entry.mjs", ImportStyle::Import),
            &ResolutionContext::new("admission", "admission", "admission"),
            &AllowAllPolicy,
        )
        .unwrap();
    let installed = ExecutionModuleResolver::new(&entry.module.record.id, resolver, options.policy);
    let mut capabilities = vec!["module_load".into(), "builtin".into(), "timer".into()];
    if options.vm_grant {
        capabilities.push("vm_dispatch".into());
    }
    if options.host.is_some() {
        capabilities.push("env_read".into());
    }
    let package = ExtensionPackage {
        extension_id: "numeric-wasm-js".into(),
        source: "throw new Error('uncaptured source');".into(),
        source_file: None,
        module_root: None,
        capabilities,
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let mut engine = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Module,
            ..OrchestratorConfig::default()
        },
        options.runtime,
    )
    .unwrap();
    if let Some(host) = options.host {
        engine.set_host_io(host, None);
    }
    if let Some(token) = options.cancellation {
        engine.set_cancellation_token(token);
    }
    let result = engine.execute_resolved_entry_with_resolver(&package, &entry, installed);
    let failed_lines = engine
        .last_failed_console_output()
        .iter()
        .map(|line| line.message.clone())
        .collect();
    (result, failed_lines)
}

fn successful_lines(lane: LaneChoice, source: &str, bytes: &[u8]) -> Vec<String> {
    let (result, _) = run(
        lane,
        source,
        bytes,
        RuntimeConfig::default(),
        Arc::new(AllowAllPolicy),
        true,
    );
    result
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn numeric_exports_are_real_js_callables_with_ordered_reentrant_conversion() {
    let bytes = binary(
        &[
            (
                "add",
                &[0x7f, 0x7f],
                &[0x7f],
                &[0x20, 0, 0x20, 1, 0x6a, 0x0b],
            ),
            ("i64", &[0x7e], &[0x7e], &[0x20, 0, 0x0b]),
            ("f32", &[0x7d], &[0x7d], &[0x20, 0, 0x0b]),
            ("f64", &[0x7c], &[0x7c], &[0x20, 0, 0x0b]),
        ],
        false,
        None,
        None,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            successful_lines(
                lane,
                r#"
import { add, i64, f32, f64 } from './math.wasm';
const detached = add;
console.log(add(20, 22), detached('40.9', true), add(4294967295, 2), add());
console.log(i64(18446744073709551615n) === -1n, Object.is(f32(-0), -0), f64(3.5));
try { i64(1); } catch (error) { console.log(error instanceof TypeError); }
console.log(add({ valueOf() { return add(10, 11); } }, 21));
console.log(add.name, add.length, typeof add);
try { new add(1, 2); } catch (error) { console.log(error instanceof TypeError); }
"#,
                &bytes
            ),
            [
                "42 41 1 0",
                "true true 3.5",
                "true",
                "42",
                "0 2 function",
                "true"
            ]
        );
    }
}

#[test]
fn imports_share_startup_globals_and_memory_and_traps_preserve_prior_writes() {
    let bytes = binary(
        &[
            ("start", &[], &[], &[0x41, 5, 0x24, 0, 0x0b]),
            (
                "add",
                &[0x7f],
                &[0x7f],
                &[0x23, 0, 0x20, 0, 0x6a, 0x24, 0, 0x23, 0, 0x0b],
            ),
            ("read", &[], &[0x7f], &[0x23, 0, 0x0b]),
            ("writeTrap", &[0x7f], &[], &[0x20, 0, 0x24, 0, 0x00, 0x0b]),
            ("store", &[0x7f], &[], &[0x41, 0, 0x20, 0, 0x36, 2, 0, 0x0b]),
            ("load", &[], &[0x7f], &[0x41, 0, 0x28, 2, 0, 0x0b]),
        ],
        true,
        Some(1),
        Some(0),
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            successful_lines(
                lane,
                r#"
import * as first from './math.wasm';
console.log(first.add(2), first.add(3));
const second = await import('./math.wasm');
console.log(first === second, first.add === second.add, second.read());
try { first.writeTrap(29); } catch (error) { console.log(error.message.includes('WebAssembly trap')); }
console.log(second.read());
console.log(first.store(42), second.load());
"#,
                &bytes
            ),
            ["7 10", "true true 10", "true", "29", "undefined 42"]
        );
    }
}

#[derive(Default)]
struct RevokingPolicy {
    wasm_calls: AtomicUsize,
    deny_at: usize,
}

impl ModulePolicyHook for RevokingPolicy {
    fn authorize(
        &self,
        request: &ModuleRequest,
        record: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        let mut policy = CapabilityPolicyHook::new(BTreeSet::from([
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::VmDispatch,
            RuntimeCapability::Builtin,
            RuntimeCapability::Timer,
        ]));
        if record.syntax == ModuleSyntax::Wasm
            && self.wasm_calls.fetch_add(1, Ordering::SeqCst) + 1 >= self.deny_at
        {
            policy.denied_specifiers.insert(request.specifier.clone());
        }
        policy.authorize(request, record, context)
    }
}

#[test]
fn current_policy_is_rechecked_for_detached_calls_and_after_guest_coercion() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (deny_at, expected) in [(3, vec!["before"]), (4, vec!["before", "converted"])] {
            let policy = Arc::new(RevokingPolicy {
                wasm_calls: AtomicUsize::new(0),
                deny_at,
            });
            let (result, lines) = run(
                lane,
                r#"
import { add } from './math.wasm';
const detached = add;
console.log('before');
try { detached({ valueOf() { console.log('converted'); return 20; } }, 22); }
catch (error) { console.log('caught policy denial'); }
console.log('after');
"#,
                &add_binary(),
                RuntimeConfig::default(),
                policy.clone(),
                true,
            );
            let error = result.expect_err("authority refusal must not become a guest exception");
            assert!(error.to_string().contains("refused"), "{lane:?}: {error}");
            assert_eq!(lines, expected);
            assert_eq!(policy.wasm_calls.load(Ordering::SeqCst), deny_at);
        }
    }
}

#[test]
fn startup_traps_are_cached_with_the_same_guest_exception_identity() {
    let bytes = binary(&[("start", &[], &[], &[0, 0x0b])], false, None, Some(0));
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            successful_lines(
                lane,
                r#"
let first;
try { await import('./math.wasm'); } catch (error) { first = error; console.log('trap'); }
try { await import('./math.wasm'); } catch (error) { console.log(first === error); }
"#,
                &bytes
            ),
            ["trap", "true"]
        );
    }
}

#[test]
fn wasm_and_js_share_one_instruction_allowance_across_instances() {
    let mut code = vec![0x01; 1000];
    code.extend([0x41, 7, 0x0b]);
    let bytes = binary(&[("work", &[], &[0x7f], &code)], false, None, None);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut runtime = RuntimeConfig::default();
        runtime.execution.deterministic_budget = 3000;
        runtime.execution.throughput_budget = 3000;
        let (result, lines) = run(
            lane,
            r#"
import { work } from './math.wasm';
import { work as other } from './other.wasm';
console.log(work());
console.log(other());
try { console.log(work()); } catch (error) { console.log('caught budget'); }
"#,
            &bytes,
            runtime,
            Arc::new(AllowAllPolicy),
            true,
        );
        assert!(matches!(
            result.unwrap_err().primary_error(),
            OrchestratorError::Interpreter(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(lines, ["7", "7"]);
    }
}

#[test]
fn missing_vm_authority_and_unadmitted_memory_fail_closed() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (result, lines) = run(
            lane,
            "import { add } from './math.wasm'; console.log(add(1, 2));",
            &add_binary(),
            RuntimeConfig::default(),
            // The orchestrator grants its own JS interpreter VmDispatch.
            // Imported module authority is independently restricted by the
            // installed resolver's current policy.
            Arc::new(CapabilityPolicyHook::new(BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Builtin,
                RuntimeCapability::Timer,
            ]))),
            false,
        );
        assert!(result.unwrap_err().to_string().contains("vm_dispatch"));
        assert!(lines.is_empty());
        let mut runtime = RuntimeConfig::default();
        runtime.execution.max_total_memory_bytes = Some(32 * 1024 * 1024);
        let (small, _) = run(
            lane,
            "import { add } from './math.wasm'; add(20, 22);",
            &add_binary(),
            runtime.clone(),
            Arc::new(AllowAllPolicy),
            true,
        );
        assert_eq!(
            small
                .expect("memoryless activation fits this budget")
                .execution_value,
            "42"
        );
        let bytes = binary(
            &[("read", &[], &[0x7f], &[0x41, 0, 0x0b])],
            false,
            Some(256),
            None,
        );
        let (result, _) = run(
            lane,
            "await import('./math.wasm');",
            &bytes,
            runtime,
            Arc::new(AllowAllPolicy),
            true,
        );
        assert!(matches!(
            result.unwrap_err().primary_error(),
            OrchestratorError::Interpreter(InterpreterError::MemoryBudgetExceeded { .. })
        ));
    }
}

#[test]
fn secret_arguments_and_coercions_taint_persistent_state_even_after_traps() {
    let bytes = binary(
        &[
            ("store", &[0x7f], &[], &[0x20, 0, 0x24, 0, 0x0b]),
            ("writeTrap", &[0x7f], &[], &[0x20, 0, 0x24, 0, 0, 0x0b]),
            ("read", &[], &[0x7f], &[0x23, 0, 0x0b]),
        ],
        true,
        None,
        None,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for mutation in [
            "store(process.env.PRIVATE_NUMBER);",
            "store({ valueOf() { return Number(process.env.PRIVATE_NUMBER); } });",
            "try { writeTrap(process.env.PRIVATE_NUMBER); } catch (error) {}",
        ] {
            let source = format!(
                "import {{ store, writeTrap, read }} from './math.wasm'; {mutation} read();"
            );
            let host = EnvironmentSnapshotHostIo::new(BTreeMap::from([(
                "PRIVATE_NUMBER".into(),
                "29".into(),
            )]))
            .unwrap();
            let (result, _) = execute(
                lane,
                &source,
                &bytes,
                RunOptions {
                    runtime: RuntimeConfig::default(),
                    policy: Arc::new(AllowAllPolicy),
                    vm_grant: true,
                    host: Some(Arc::new(host)),
                    cancellation: None,
                },
            );
            let result = result.unwrap_or_else(|error| panic!("{lane:?}, {mutation}: {error}"));
            assert_eq!(result.execution_value, "29");
            assert_eq!(
                result.completion_label,
                Label::Secret,
                "{lane:?}, {mutation}"
            );
        }
    }
}

struct CancellingPolicy {
    token: CancellationToken,
    wasm_calls: AtomicUsize,
}

impl ModulePolicyHook for CancellingPolicy {
    fn authorize(
        &self,
        request: &ModuleRequest,
        record: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        if record.syntax == ModuleSyntax::Wasm
            && self.wasm_calls.fetch_add(1, Ordering::SeqCst) == 3
        {
            self.token.cancel();
        }
        AllowAllPolicy.authorize(request, record, context)
    }
}

#[test]
fn cancellation_is_observed_at_numeric_entry_and_is_not_a_guest_trap() {
    let bytes = binary(
        &[("spin", &[], &[], &[0x03, 0x40, 0x0c, 0, 0x0b, 0x0b])],
        false,
        None,
        None,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let token = CancellationToken::new();
        let policy = Arc::new(CancellingPolicy {
            token: token.clone(),
            wasm_calls: AtomicUsize::new(0),
        });
        let (result, lines) = execute(
            lane,
            "import { spin } from './math.wasm'; console.log('before'); try { spin(); } catch (error) { console.log('caught cancellation'); }",
            &bytes,
            RunOptions {
                runtime: RuntimeConfig::default(),
                policy,
                vm_grant: true,
                host: None,
                cancellation: Some(token),
            },
        );
        assert!(result.unwrap_err().to_string().contains("cancel"));
        assert_eq!(lines, ["before"]);
    }
}

#[test]
fn host_imports_state_exports_and_multiple_results_are_explicitly_unsupported() {
    let mut imported = b"\0asm\x01\0\0\0".to_vec();
    section(&mut imported, 1, &[1, 0x60, 0, 0]);
    section(
        &mut imported,
        2,
        &[1, 3, b'e', b'n', b'v', 4, b't', b'i', b'c', b'k', 0, 0],
    );
    let mut memory = b"\0asm\x01\0\0\0".to_vec();
    section(&mut memory, 5, &[1, 1, 1, 1]);
    section(
        &mut memory,
        7,
        &[1, 6, b'm', b'e', b'm', b'o', b'r', b'y', 2, 0],
    );
    let multiple = binary(
        &[("pair", &[], &[0x7f, 0x7f], &[0x41, 1, 0x41, 2, 0x0b])],
        false,
        None,
        None,
    );
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for (bytes, reason) in [
            (&imported, "host functions"),
            (&memory, "state exports"),
            (&multiple, "multiple-result"),
        ] {
            let (result, lines) = run(
                lane,
                "await import('./math.wasm'); console.log('unreachable');",
                bytes,
                RuntimeConfig::default(),
                Arc::new(AllowAllPolicy),
                true,
            );
            let error = result.unwrap_err();
            assert!(error.to_string().contains(reason), "{lane:?}: {error}");
            assert!(lines.is_empty());
        }
    }
}

#[test]
fn aliases_of_one_wasm_function_share_identity_and_standard_properties() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 2, 0x7f, 0x7f, 1, 0x7f]);
    section(&mut bytes, 3, &[1, 0]);
    section(
        &mut bytes,
        7,
        &[
            2, 3, b'a', b'd', b'd', 0, 0, 4, b's', b'a', b'm', b'e', 0, 0,
        ],
    );
    section(&mut bytes, 10, &[1, 7, 0, 0x20, 0, 0x20, 1, 0x6a, 0x0b]);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            successful_lines(
                lane,
                "import { add, same } from './math.wasm'; console.log(add === same, same(20, 22), add.name, add.length, Object.prototype.hasOwnProperty.call(add, 'prototype'));",
                &bytes
            ),
            ["true 42 0 2 false"]
        );
    }
}

#[test]
fn compressed_local_declarations_are_charged_before_expansion() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 0]);
    let mut indices = leb(1000);
    indices.extend(std::iter::repeat_n(0, 1000));
    section(&mut bytes, 3, &indices);
    let mut bodies = leb(1000);
    for _ in 0..1000 {
        // Five body bytes retain 4096 local types: source length alone cannot
        // account for the parser's run-length expansion across all functions.
        bodies.extend([5, 1, 0x80, 0x20, 0x7f, 0x0b]);
    }
    section(&mut bytes, 10, &bodies);
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut runtime = RuntimeConfig::default();
        runtime.execution.max_total_memory_bytes = Some(24 * 1024 * 1024);
        let (result, lines) = run(
            lane,
            "await import('./math.wasm'); console.log('unreachable');",
            &bytes,
            runtime,
            Arc::new(AllowAllPolicy),
            true,
        );
        assert!(matches!(
            result.unwrap_err().primary_error(),
            OrchestratorError::Interpreter(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(lines.is_empty());
    }
}
