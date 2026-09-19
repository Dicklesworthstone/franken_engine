#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmNativeModule, WasmValueType,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceLimits, WasmHostTranscript};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WASI_PREVIEW1_MODULE, WasiCommandOutcome, WasiCommandPhase, WasiPreview1Config,
    WasiStdio, WasiStdioLimits, run_command_with_outcome as run_command,
};
use RuntimeCapability::{Builtin, Console, ModuleLoad, VmDispatch};
use WasmBoundaryValue::I32;

// Binary fixtures, also run by Node WASI with returnOnExit=true. They are real
// modules through the production parser, linker, VM and host boundary below.
const EXIT_0: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0c02070041001000000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const EXIT_7: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0c02070041071000000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const EXIT_42: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0c020700412a1000000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const EXIT_2147483648: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a10020b004180808080781000000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const EXIT_4294967295: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0c020700417f1000000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const MARKED_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a13020e0041072400412a1000410924000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const RETURN: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0b020600410724000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const RETURN_START: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000801040908010041000b0200030a15030900230041016a24000b02000b0600410724000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const WRITE_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a21021c00410141004101411810011a41071000410141004101411810011a0b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const WRITE_TRAP: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a13020e00410141004101411810011a000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const START_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000801040908010041000b0200030a2f030d00410141004101411810011a0b02000b1c00410141004101411810011a412a1000410141004101411810011a0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const INDIRECT_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a1602110041072400412a4100110000410924000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const TAIL_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a13020e0041072400412a1200410924000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const TAIL_INDIRECT_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a1602110041072400412a4100130000410924000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const NESTED_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a13020a00410041011102001a0b0600412a10000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const BAD_PARAM: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030302020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000801040908010041000b0200030a150302000b02000b0d00410141004101411810011a0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const BAD_RESULT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030402020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000801040908010041000b0200030a1703040041010b02000b0d00410141004101411810011a0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const MISSING_ENTRY: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030202020404017000020504010101010606017f0141000b071d04056f7468657200020167030004657869740000066d656d6f727902000801040908010041000b0200030a150302000b02000b0d00410141004101411810011a0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const MEMORY_ENTRY: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030202020404017000020504010101010606017f0141000b071e04065f737461727402000167030004657869740000066d656d6f727902000801040908010041000b0200030a150302000b02000b0d00410141004101411810011a0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const TRAP: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a08020300000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const LOOP: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000908010041000b0200030a0c02070003400c000b0b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const LOOP_START: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f777269746500010304030202020404017000020504010101010606017f0141000b071e04065f737461727400020167030004657869740000066d656d6f727902000801040908010041000b0200030a1a030d00410141004101411810011a0b02000b070003400c000b0b0b19020041000b088000000005000000004180010b0568656c6c6f";
const HOOK_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f024f0316776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f77726974650001016804686f6f6b000203030202020404017000020504010101010606017f0141000b071e04065f737461727400030167030004657869740000066d656d6f727902000908010041000b0200040a0d0208001002410710000b02000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const HOOK_START_EXIT: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f024f0316776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f77726974650001016804686f6f6b00020304030202020404017000020504010101010606017f0141000b071e04065f737461727400030167030004657869740000066d656d6f727902000801050908010041000b0200040a100302000b02000b08001002410710000b0b19020041000b088000000005000000004180010b0568656c6c6f";
const NO_MEMORY: &str = "0061736d0100000001180560017f0060047f7f7f7f017f60000060017f006000017f02460216776173695f736e617073686f745f70726576696577310970726f635f65786974000016776173695f736e617073686f745f70726576696577310866645f7772697465000103030202020404017000020606017f0141000b071503065f7374617274000201670300046578697400000908010041000b0200030a0b020600412a10000b02000b";

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
fn vm(hex: &str) -> WasmNumericVm {
    WasmNumericVm::parse(&bytes(hex), WasmNumericLimits::default()).unwrap()
}
fn grants() -> BTreeSet<RuntimeCapability> { BTreeSet::from([Builtin, Console, VmDispatch]) }
fn providers() -> (WasmHostImports, WasiStdio) {
    WasiPreview1Config::default().into_imports_with_stdio(
        grants(), Vec::new(), WasiStdioLimits::default(),
    ).unwrap()
}
fn custom_exit<F>(exit: F) -> WasmHostImports
where
    F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue])
        -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync + 'static,
{
    let mut imports = WasmHostImports::new(grants());
    imports.define(WASI_PREVIEW1_MODULE, "proc_exit", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: Vec::new(),
    }, BTreeSet::from([Builtin]), 1, exit).unwrap();
    imports.define(WASI_PREVIEW1_MODULE, "fd_write", WasmFunctionSignature {
        params: vec![WasmValueType::I32; 4], results: vec![WasmValueType::I32],
    }, BTreeSet::from([Console]), 1, |_, _| Ok(vec![I32(0)])).unwrap();
    imports
}
fn context() -> ResolutionContext { ResolutionContext::new("wasi-command", "command-decision", "command-policy") }
fn policy() -> CapabilityPolicyHook {
    let mut caps = wasm_module_required_capabilities(); caps.extend(grants());
    CapabilityPolicyHook::new(caps)
}
fn resolved(hex: &str, declare_services: bool) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let mut definition = ModuleDefinition::wasm_binary(&bytes(hex), &WasmNumericLimits::default()).unwrap();
    if declare_services { definition.required_capabilities.extend([Builtin, Console]); }
    resolver.register_workspace_module("/app/command.wasm", definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new("/app/command.wasm", ImportStyle::Import),
        &context(), &policy(), WasmNumericLimits::default()).unwrap()
}
fn assert_exit(outcome: WasiCommandOutcome, code: u32, phase: WasiCommandPhase) {
    assert_eq!(outcome.exit_code(), code);
    assert_eq!(outcome, WasiCommandOutcome::Exited { code, phase });
}

#[test]
fn raw_proc_exit_is_typed_and_does_not_execute_the_following_store() {
    let vm = vm(MARKED_EXIT);
    let (imports, _) = providers();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(instance.call_export("_start", &[]), Err(WasmHostError::ProcessExit { code: 42 }.into()));
    assert_eq!(instance.global_export("g"), Some(&I32(7)));
}

#[test]
fn command_exit_preserves_all_u32_bits_including_nonzero_statuses() {
    for (hex, code) in [(EXIT_0, 0), (EXIT_7, 7), (EXIT_42, 42), (EXIT_2147483648, 0x8000_0000), (EXIT_4294967295, u32::MAX)] {
        assert_exit(run_command(&vm(hex), providers().0).unwrap(), code, WasiCommandPhase::Command);
    }
}

#[test]
fn ordinary_return_has_zero_status_and_real_separate_startup_metrics() {
    for hex in [RETURN, RETURN_START] {
        let result = run_command(&vm(hex), providers().0).unwrap();
        assert_eq!(result.exit_code(), 0);
        let WasiCommandOutcome::Returned { startup, execution } = result else { panic!("normal return"); };
        assert!(execution.results.is_empty());
        assert_eq!(execution.instructions_executed, if hex == RETURN { 3 } else { 5 });
        assert_eq!(startup.as_ref().map(|execution| execution.instructions_executed),
            if hex == RETURN { None } else { Some(3) });
    }
}

#[test]
fn startup_exit_does_not_publish_an_instance_or_enter_the_command_export() {
    let (imports, output) = providers();
    assert_exit(run_command(&vm(START_EXIT), imports).unwrap(), 42, WasiCommandPhase::Instantiation);
    assert_eq!(output.take_output().unwrap().stdout, b"hello".to_vec());
}

#[test]
fn exit_unwinds_indirect_and_tail_calls_through_the_existing_host_gate() {
    for hex in [INDIRECT_EXIT, TAIL_EXIT, TAIL_INDIRECT_EXIT, NESTED_EXIT] {
        assert_exit(run_command(&vm(hex), providers().0).unwrap(), 42, WasiCommandPhase::Command);
    }
}

#[test]
fn invalid_command_abi_is_rejected_before_any_binary_start_effect() {
    for hex in [BAD_PARAM, BAD_RESULT, MISSING_ENTRY, MEMORY_ENTRY] {
        let (imports, output) = providers();
        let error = run_command(&vm(hex), imports).unwrap_err();
        assert!(matches!(error, WasmNumericVmError::InvalidModule { .. }
            | WasmNumericVmError::UnknownExport { .. } | WasmNumericVmError::ExportIsNotFunction { .. }));
        assert!(output.take_output().unwrap().stdout.is_empty());
    }
}

#[test]
fn exact_exit_import_abi_is_linked_before_startup() {
    let mut imports = WasmHostImports::new(grants());
    imports.define(WASI_PREVIEW1_MODULE, "proc_exit", WasmFunctionSignature {
        params: vec![WasmValueType::I64], results: Vec::new(),
    }, BTreeSet::from([Builtin]), 1, |_, _| panic!("invalid provider must not execute")).unwrap();
    assert!(matches!(run_command(&vm(START_EXIT), imports),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::SignatureMismatch { .. })))));
}

#[test]
fn exit_work_is_charged_before_it_can_be_classified_as_normal_termination() {
    let exact = WasmNumericVm::parse(&bytes(EXIT_42), WasmNumericLimits {
        max_instructions: 4, ..WasmNumericLimits::default()
    }).unwrap();
    assert_exit(run_command(&exact, providers().0).unwrap(), 42, WasiCommandPhase::Command);
    let tight = WasmNumericVm::parse(&bytes(EXIT_42), WasmNumericLimits {
        max_instructions: 3, ..WasmNumericLimits::default()
    }).unwrap();
    assert_eq!(run_command(&tight, providers().0),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 3 }));
}

#[test]
fn ordinary_traps_are_not_process_statuses_and_keep_completed_output() {
    assert!(matches!(run_command(&vm(TRAP), providers().0), Err(WasmNumericVmError::Unreachable { .. })));
    let (imports, output) = providers();
    assert!(matches!(run_command(&vm(WRITE_TRAP), imports), Err(WasmNumericVmError::Unreachable { .. })));
    assert_eq!(output.take_output().unwrap().stdout, b"hello".to_vec());
    let imports = custom_exit(|_, _| Err(WasmHostError::trap("WASI command exited with status 0").into()));
    assert!(matches!(run_command(&vm(EXIT_0), imports),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. })))));
}

#[test]
fn an_ignored_provider_refusal_cannot_be_laundered_into_exit_zero() {
    let imports = custom_exit(|caller, _| {
        let _ = caller.charge_work(u64::MAX);
        Err(WasmHostError::ProcessExit { code: 0 }.into())
    });
    assert!(matches!(run_command(&vm(EXIT_0), imports), Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
}

#[test]
fn live_cancellation_and_capability_revocation_win_over_a_provider_exit() {
    for revoke in [false, true] {
        let token = CancellationToken::new(); let trigger = token.clone();
        let mut imports = custom_exit(move |_, _| {
            trigger.cancel();
            Err(WasmHostError::ProcessExit { code: 0 }.into())
        });
        if revoke { imports.bind_capability_revocation(Builtin, token, "exit-revocation").unwrap(); }
        else { imports.bind_execution_cancellation(token, "exit-cancellation").unwrap(); }
        assert!(matches!(run_command(&vm(EXIT_0), imports),
            Err(WasmNumericVmError::State(WasmStateError::Host(
                WasmHostError::ExecutionCancelled | WasmHostError::CapabilityDenied { .. }
            )))));
    }
}

#[test]
fn command_output_is_retained_once_after_exit() {
    let (imports, output) = providers();
    assert_exit(run_command(&vm(WRITE_EXIT), imports).unwrap(), 7, WasiCommandPhase::Command);
    assert_eq!(output.take_output().unwrap().stdout, b"hello".to_vec());
    assert!(output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn typed_exit_round_trips_through_the_host_transcript_without_duplicate_io() {
    for (hex, code, phase) in [(WRITE_EXIT, 7, WasiCommandPhase::Command), (START_EXIT, 42, WasiCommandPhase::Instantiation)] {
        let vm = vm(hex); let limits = WasmHostTraceLimits::default();
        let (mut imports, output) = providers();
        let recording = imports.record_calls(limits).unwrap();
        assert_exit(run_command(&vm, imports).unwrap(), code, phase);
        assert_eq!(output.take_output().unwrap().stdout, b"hello".to_vec());
        let tape = recording.snapshot().unwrap(); assert_eq!(tape.call_count(), 2);
        let tape = WasmHostTranscript::from_json(&tape.to_json(limits).unwrap(), limits).unwrap();
        let (mut imports, replay_output) = providers();
        let replay = imports.replay_calls(tape, limits).unwrap();
        assert_exit(run_command(&vm, imports).unwrap(), code, phase);
        replay.verify_complete().unwrap();
        assert!(replay_output.take_output().unwrap().stdout.is_empty());
    }
}

#[test]
fn recording_refusal_is_not_hidden_by_guest_exit() {
    let (mut imports, _) = providers();
    imports.record_calls(WasmHostTraceLimits { max_calls: 0, ..WasmHostTraceLimits::default() }).unwrap();
    assert!(matches!(run_command(&vm(EXIT_0), imports),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trace(_))))));
}

#[test]
fn a_command_requires_neither_process_io_nor_a_memory_export_to_exit() {
    assert_exit(run_command(&vm(NO_MEMORY), providers().0).unwrap(), 42, WasiCommandPhase::Command);
    let machine = vm(RETURN);
    let signature = machine.export_signature("_start").unwrap();
    assert!(signature.params.is_empty() && signature.results.is_empty());
    assert!(matches!(machine.export_signature("memory"), Err(WasmNumericVmError::ExportIsNotFunction { .. })));
}

#[test]
fn every_terminal_command_outcome_releases_owned_providers() {
    struct Released(Arc<AtomicUsize>);
    impl Drop for Released { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
    for hex in [RETURN, EXIT_0, TRAP, BAD_PARAM] {
        let releases = Arc::new(AtomicUsize::new(0)); let guard = Released(releases.clone());
        let imports = custom_exit(move |_, _| {
            let _ = &guard;
            Err(WasmHostError::ProcessExit { code: 0 }.into())
        });
        let _ = run_command(&vm(hex), imports);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn resolved_commands_enforce_manifest_and_current_policy_before_startup() {
    let module = resolved(START_EXIT, false);
    let (imports, output) = providers();
    assert!(matches!(module.run_wasi_command(&context(), &policy(), imports),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { .. }
        ))))));
    assert!(output.take_output().unwrap().stdout.is_empty());
    let module = resolved(START_EXIT, true);
    for denied in [CapabilityPolicyHook::new(BTreeSet::from([ModuleLoad, VmDispatch])),
        policy().deny_specifier("/app/command.wasm")] {
        let (imports, output) = providers();
        assert!(matches!(module.run_wasi_command(&context(), &denied, imports), Err(WasmNativeLoadError::Resolution(_))));
        assert!(output.take_output().unwrap().stdout.is_empty());
    }
    assert_exit(module.run_wasi_command(&context(), &policy(), providers().0).unwrap(),
        42, WasiCommandPhase::Instantiation);
}

#[test]
fn resolved_command_replay_remains_bound_to_the_pinned_module() {
    let module = resolved(WRITE_EXIT, true); let limits = WasmHostTraceLimits::default();
    let (mut imports, _) = providers(); let recording = imports.record_calls(limits).unwrap();
    assert_exit(module.run_wasi_command(&context(), &policy(), imports).unwrap(), 7, WasiCommandPhase::Command);
    let tape = recording.snapshot().unwrap(); assert!(tape.module_hash().is_some());
    let (mut imports, output) = providers(); let replay = imports.replay_calls(tape.clone(), limits).unwrap();
    assert_exit(module.run_wasi_command(&context(), &policy(), imports).unwrap(), 7, WasiCommandPhase::Command);
    replay.verify_complete().unwrap(); assert!(output.take_output().unwrap().stdout.is_empty());
    let (mut imports, _) = providers(); imports.replay_calls(tape, limits).unwrap();
    assert!(resolved(EXIT_0, true).run_wasi_command(&context(), &policy(), imports).is_err());
}

#[test]
fn endless_startup_and_command_loops_keep_the_original_hard_work_limit() {
    for hex in [LOOP, LOOP_START] {
        let vm = WasmNumericVm::parse(&bytes(hex), WasmNumericLimits {
            max_instructions: 17, ..WasmNumericLimits::default()
        }).unwrap();
        let (imports, output) = providers();
        assert_eq!(run_command(&vm, imports),
            Err(WasmNumericVmError::InstructionBudgetExceeded { max: 17 }));
        assert!(output.take_output().unwrap().stdout.is_empty());
    }
}

#[test]
fn a_prior_host_failure_is_not_replaced_by_the_later_requested_exit() {
    for hex in [HOOK_EXIT, HOOK_START_EXIT] {
        let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
        let (mut imports, _) = providers();
        imports.define("h", "hook", WasmFunctionSignature {
            params: Vec::new(), results: Vec::new(),
        }, BTreeSet::from([Builtin]), 1, move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err(WasmHostError::trap("primary service failure").into())
        }).unwrap();
        assert!(matches!(run_command(&vm(hex), imports),
            Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { message })))
                if message == "primary service failure"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
