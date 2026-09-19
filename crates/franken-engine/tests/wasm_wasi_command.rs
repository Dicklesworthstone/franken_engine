#![forbid(unsafe_code)]

mod command_exit {
    use std::collections::BTreeSet;
    use std::num::NonZeroU64;
    use frankenengine_engine::capability::RuntimeCapability::{Builtin, Console, VmDispatch};
    use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
    use frankenengine_engine::wasm_runtime_lane::numeric::{
        WasmCallStep, WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
        WasmNumericVm, WasmNumericVmError, WasmStateError,
    };
    use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceLimits, WasmHostTranscript};
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
        WASI_PREVIEW1_MODULE, WasiPreview1Config, WasiStdio, WasiStdioLimits, run_command,
    };
    use WasmBoundaryValue::I32;

    fn leb(mut n: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop { let low = (n & 127) as u8; n >>= 7; bytes.push(low | if n == 0 { 0 } else { 128 }); if n == 0 { return bytes; } }
    }
    fn signed(mut n: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let low = (n & 127) as u8; n >>= 7;
            let done = (n == 0 && low & 64 == 0) || (n == -1 && low & 64 != 0);
            bytes.push(low | if done { 0 } else { 128 }); if done { return bytes; }
        }
    }
    fn section(bytes: &mut Vec<u8>, id: u8, data: &[u8]) {
        bytes.push(id); bytes.extend(leb(data.len() as u32)); bytes.extend_from_slice(data);
    }
    fn name(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend(leb(value.len() as u32)); bytes.extend_from_slice(value.as_bytes());
    }
    fn exit_code(code: u32, instruction: &[u8]) -> Vec<u8> {
        let mut body = vec![0x41]; body.extend(signed(code as i32)); body.extend_from_slice(instruction); body
    }
    // 0: proc_exit, 1: fd_write, 2: _start, 3: mutate, optional 4: binary start.
    // All declared imports are real WASI providers, even when the body is pure.
    fn binary(body: &[u8], startup: Option<&[u8]>, command_type: u8, export_name: &str) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[4, 0x60, 1, 0x7f, 0, 0x60, 0, 0,
            0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f]);
        let mut imports = vec![2];
        for (function, ty) in [("proc_exit", 0), ("fd_write", 2)] {
            name(&mut imports, WASI_PREVIEW1_MODULE); name(&mut imports, function); imports.extend([0, ty]);
        }
        section(&mut bytes, 2, &imports);
        let declarations = [if startup.is_some() { 3 } else { 2 }, command_type, 1, 1];
        let declaration_length = if startup.is_some() { 4 } else { 3 };
        section(&mut bytes, 3, &declarations[..declaration_length]);
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        section(&mut bytes, 5, &[1, 0, 1]);
        section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
        let mut exports = vec![5];
        for (function, kind, index) in [("proc_exit",0,0), (export_name,0,2), ("mutate",0,3), ("memory",2,0), ("g",3,0)] {
            name(&mut exports, function); exports.extend([kind,index]);
        }
        section(&mut bytes, 7, &exports);
        if startup.is_some() { section(&mut bytes, 8, &[4]); }
        section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
        let mutation: &[u8] = &[0x41, 33, 0x24, 0, 0x0b];
        let mut code = vec![if startup.is_some() { 3 } else { 2 }];
        for body in [body, mutation].into_iter().chain(startup) {
            code.extend(leb(body.len() as u32 + 1)); code.push(0); code.extend_from_slice(body);
        }
        section(&mut bytes, 10, &code);
        let mut data = vec![1, 0, 0x41, 0, 0x0b, 11];
        data.extend(8_u32.to_le_bytes()); data.extend(3_u32.to_le_bytes()); data.extend(b"bye");
        section(&mut bytes, 11, &data);
        bytes
    }
    fn vm(body: &[u8]) -> WasmNumericVm {
        WasmNumericVm::parse(&binary(body, None, 1, "_start"), WasmNumericLimits::default()).unwrap()
    }
    fn providers() -> (WasmHostImports, WasiStdio) {
        WasiPreview1Config::default().into_imports_with_stdio(
            BTreeSet::from([VmDispatch, Builtin, Console]), Vec::new(), WasiStdioLimits::default(),
        ).unwrap()
    }
    fn exited(code: u32) -> WasmNumericVmError { WasmHostError::ProcessExit { code }.into() }
    fn emit() -> Vec<u8> { vec![0x41,1,0x41,0,0x41,1,0x41,16,0x10,1,0x1a] }
    fn custom<F>(callback: F) -> WasmHostImports
    where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync + 'static {
        let mut imports = WasmHostImports::new(BTreeSet::from([VmDispatch, Builtin, Console]));
        imports.define(WASI_PREVIEW1_MODULE, "proc_exit", WasmFunctionSignature {
            params: vec![WasmValueType::I32], results: vec![],
        }, BTreeSet::from([Builtin]), 1, callback).unwrap();
        imports.define(WASI_PREVIEW1_MODULE, "fd_write", WasmFunctionSignature {
            params: vec![WasmValueType::I32; 4], results: vec![WasmValueType::I32],
        }, BTreeSet::from([Console]), 1, |_, _| panic!("unexpected output callback")).unwrap();
        imports
    }

    #[test]
    fn proc_exit_preserves_full_unsigned_status_and_never_returns_to_guest() {
        for code in [0, 7, 255, 256, 0x8000_0000, u32::MAX] {
            let mut body = exit_code(code, &[0x10, 0]); body.extend([0x00, 0x0b]);
            assert_eq!(run_command(&vm(&body), providers().0).unwrap(), code);
        }
    }

    #[test]
    fn indirect_and_tail_exits_use_the_same_terminal_host_boundary() {
        for instruction in [vec![0x41,0,0x11,0,0], vec![0x12,0], vec![0x41,0,0x13,0,0]] {
            let mut body = exit_code(19, &instruction); body.extend([0x00,0x0b]);
            assert_eq!(run_command(&vm(&body), providers().0).unwrap(), 19);
        }
    }

    #[test]
    fn exit_retains_prior_output_and_stores_and_disables_other_exports() {
        let mut body = emit(); body.extend([0x41,7,0x24,0]);
        body.extend(exit_code(23, &[0x10,0])); body.extend([0x41,9,0x24,0,0x0b]);
        let vm = vm(&body); let (imports, output) = providers();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(instance.call_export("_start", &[]), Err(exited(23)));
        assert_eq!(instance.process_exit_status(), Some(23));
        assert_eq!(instance.global_export("g"), Some(&I32(7)));
        assert_eq!(output.take_output().unwrap().stdout, b"bye");
        for export in ["mutate", "_start"] { assert_eq!(instance.call_export(export, &[]), Err(exited(23))); }
        assert_eq!(instance.call_export("proc_exit", &[I32(99)]), Err(exited(23)));
        assert_eq!(instance.global_export("g"), Some(&I32(7)));
        let mut other = vm.instantiate_with_imports(providers().0).unwrap();
        other.call_export("mutate", &[]).unwrap();
        assert_eq!(other.global_export("g"), Some(&I32(33)));
        assert_eq!(other.process_exit_status(), None);
    }

    #[test]
    fn ignored_exit_error_cannot_change_status_write_memory_or_resume_guest() {
        let vm = vm(&[0x41,0,0x10,0,0x41,9,0x24,0,0x0b]);
        let imports = custom(|caller, _| {
            assert_eq!(caller.exit(17), exited(17));
            assert_eq!(caller.exit(99), exited(17));
            assert_eq!(caller.write_memory(0, b"bad"), Err(exited(17)));
            assert_eq!(caller.charge_work(0), Err(exited(17)));
            Ok(vec![])
        });
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(instance.call_export("_start", &[]), Err(exited(17)));
        assert_eq!(&instance.memory_export("memory").unwrap()[..4], &8_u32.to_le_bytes());
        assert_eq!(instance.global_export("g"), Some(&I32(0)));
    }

    #[test]
    fn earlier_latched_buffer_fault_wins_and_does_not_create_a_normal_exit() {
        let vm = vm(&[0x41,0,0x10,0,0x0b]);
        let imports = custom(|caller, _| {
            let fault = caller.write_memory(u32::MAX, b"x").unwrap_err();
            assert_eq!(caller.exit(0), fault);
            Ok(vec![])
        });
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert!(matches!(instance.call_export("_start", &[]), Err(WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))));
        assert_eq!(instance.process_exit_status(), None);
        instance.call_export("mutate", &[]).unwrap();
    }

    #[test]
    fn command_return_is_zero_but_traps_are_not_normal_exit_statuses() {
        assert_eq!(run_command(&vm(&[0x0b]), providers().0).unwrap(), 0);
        assert!(matches!(run_command(&vm(&[0x00,0x0b]), providers().0), Err(WasmNumericVmError::Unreachable { .. })));
        let imports = custom(|_, _| Err(WasmHostError::trap("process exited with status 0").into()));
        assert!(matches!(run_command(&vm(&[0x41,0,0x10,0,0x0b]), imports), Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. })))));
    }

    #[test]
    fn command_contract_is_checked_before_binary_start_has_effects() {
        let mut startup = emit(); startup.push(0x0b);
        for (ty, body, export) in [(0, vec![0x0b], "_start"), (3, vec![0x41,0,0x0b], "_start"), (1, vec![0x0b], "missing")] {
            let vm = WasmNumericVm::parse(&binary(&body, Some(&startup), ty, export), WasmNumericLimits::default()).unwrap();
            let (imports, output) = providers();
            assert!(run_command(&vm, imports).is_err());
            assert!(output.take_output().unwrap().stdout.is_empty());
        }
    }

    #[test]
    fn exit_in_binary_start_ends_command_without_publishing_an_instance() {
        let mut startup = emit(); startup.extend(exit_code(12, &[0x10,0])); startup.extend([0x00,0x0b]);
        let vm = WasmNumericVm::parse(&binary(&[0x00,0x0b], Some(&startup), 1, "_start"), WasmNumericLimits::default()).unwrap();
        let (imports, output) = providers();
        assert_eq!(run_command(&vm, imports).unwrap(), 12);
        assert_eq!(output.take_output().unwrap().stdout, b"bye");
        assert!(matches!(vm.instantiate_with_imports(providers().0), Err(error) if error == exited(12)));
    }

    #[test]
    fn exit_cost_refusal_does_not_mark_instance_terminated() {
        let bytes = binary(&[0x41,5,0x10,0,0x0b], None, 1, "_start");
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_instructions: 3, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = vm.instantiate_with_imports(providers().0).unwrap();
        assert!(matches!(instance.call_export("_start", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 3 })));
        assert_eq!(instance.process_exit_status(), None);
        instance.call_export("mutate", &[]).unwrap();
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits { max_instructions: 4, ..WasmNumericLimits::default() }).unwrap();
        assert_eq!(run_command(&vm, providers().0).unwrap(), 5);
    }

    #[test]
    fn revoked_exit_authority_does_not_turn_denial_into_successful_termination() {
        let vm = vm(&[0x41,0,0x10,0,0x0b]);
        let mut instance = vm.instantiate_with_imports(providers().0).unwrap();
        instance.revoke_host_capability(Builtin);
        assert!(matches!(instance.call_export("_start", &[]), Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: Builtin, .. })))));
        assert_eq!(instance.process_exit_status(), None);
        instance.call_export("mutate", &[]).unwrap();
    }

    #[test]
    fn sliced_exit_consumes_the_continuation_and_never_runs_following_effects() {
        let vm = vm(&[0x41,3,0x10,0,0x41,9,0x24,0,0x0b]);
        let mut instance = vm.instantiate_with_imports(providers().0).unwrap();
        let mut call = instance.begin_call("_start", &[]).unwrap();
        loop {
            match call.resume(NonZeroU64::new(1).unwrap()) {
                Ok(WasmCallStep::Pending(next)) => call = next,
                Err(error) => { assert_eq!(error, exited(3)); break; }
                Ok(WasmCallStep::Complete(_)) => panic!("exit cannot complete normally"),
            }
        }
        assert_eq!(instance.process_exit_status(), Some(3));
        assert_eq!(instance.global_export("g"), Some(&I32(0)));
        let call = instance.begin_call("mutate", &[]).unwrap();
        assert!(matches!(call.resume(NonZeroU64::new(1).unwrap()), Err(error) if error == exited(3)));
    }

    #[test]
    fn recording_and_replay_restore_exit_without_invoking_providers_again() {
        let mut body = emit(); body.extend(exit_code(31, &[0x10,0])); body.extend([0x00,0x0b]);
        let vm = vm(&body); let limits = WasmHostTraceLimits::default();
        let (mut imports, output) = providers(); let recording = imports.record_calls(limits).unwrap();
        let mut original = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(original.call_export("_start", &[]), Err(exited(31)));
        let tape = recording.snapshot().unwrap(); assert_eq!(tape.call_count(), 2);
        let tape = WasmHostTranscript::from_json(&tape.to_json(limits).unwrap(), limits).unwrap();
        let mut imports = custom(|_, _| panic!("exit provider must not run during replay"));
        let replay = imports.replay_calls(tape, limits).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(instance.call_export("_start", &[]), Err(exited(31)));
        assert_eq!(instance.process_exit_status(), Some(31));
        assert_eq!(instance.memory_export("memory"), original.memory_export("memory"));
        assert_eq!(instance.call_export("mutate", &[]), Err(exited(31)));
        replay.verify_complete().unwrap();
        assert_eq!(output.take_output().unwrap().stdout, b"bye");
        assert!(output.take_output().unwrap().stdout.is_empty());
    }

    #[test]
    fn trace_admission_failure_cannot_be_reported_as_exit_zero() {
        let vm = vm(&[0x41,0,0x10,0,0x0b]);
        let (mut imports, _) = providers();
        imports.record_calls(WasmHostTraceLimits { max_calls: 0, ..WasmHostTraceLimits::default() }).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert!(matches!(instance.call_export("_start", &[]), Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trace(_))))));
        assert_eq!(instance.process_exit_status(), None);
    }

    #[test]
    fn cancellation_before_exit_wins_but_later_cancellation_cannot_replace_exit() {
        use frankenengine_engine::checkpoint::CancellationToken;
        for exit_first in [false, true] {
            let vm = vm(&[0x0b]); let token = CancellationToken::new();
            let (mut imports, _) = providers();
            imports.bind_execution_cancellation(token.clone(), "wasi-exit-precedence").unwrap();
            let mut instance = vm.instantiate_with_imports(imports).unwrap();
            if exit_first { assert_eq!(instance.call_export("proc_exit", &[I32(13)]), Err(exited(13))); }
            token.cancel(); token.reset();
            let error = instance.call_export("proc_exit", &[I32(0)]).unwrap_err();
            assert_eq!(error, if exit_first { exited(13) } else { WasmHostError::ExecutionCancelled.into() });
            assert_eq!(instance.process_exit_status(), exit_first.then_some(13));
        }
    }

    #[test]
    fn resolved_execution_keeps_module_policy_checks_and_terminal_guest_state() {
        use frankenengine_engine::module_resolver::{
            CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
            ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
        };
        use frankenengine_engine::wasm_runtime_lane::WasmNativeLoadError;
        let bytes = binary(&[0x41,14,0x10,0,0x41,9,0x24,0,0x0b], None, 1, "_start");
        let mut definition = ModuleDefinition::wasm_binary(&bytes, &WasmNumericLimits::default()).unwrap();
        definition.required_capabilities.extend([Builtin, Console]);
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver.register_workspace_module("/app/command.wasm", definition).unwrap();
        let mut grants = wasm_module_required_capabilities(); grants.extend([Builtin, Console]);
        let policy = CapabilityPolicyHook::new(grants);
        let context = ResolutionContext::new("wasi-exit", "exit-decision", "exit-policy");
        let module = resolver.load_wasm(&ModuleRequest::new("/app/command.wasm", ImportStyle::Import),
            &context, &policy, WasmNumericLimits::default()).unwrap();
        let mut instance = module.instantiate_with_imports(&context, &policy, providers().0).unwrap();
        assert!(matches!(instance.call_export("_start", &[], &context, &policy),
            Err(WasmNativeLoadError::Execution(error)) if error == exited(14)));
        let denied = policy.clone().deny_specifier("/app/command.wasm");
        assert!(matches!(instance.call_export("mutate", &[], &context, &denied), Err(WasmNativeLoadError::Resolution(_))));
        assert!(matches!(instance.call_export("mutate", &[], &context, &policy),
            Err(WasmNativeLoadError::Execution(error)) if error == exited(14)));
        assert_eq!(instance.global_export("g", &context, &policy).unwrap(), Some(&I32(0)));
    }
}