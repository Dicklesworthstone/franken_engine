#![forbid(unsafe_code)]

//! Resolved binary startup through the production future, resolver and host gate.
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use std::task::{Context, Poll, Wake, Waker};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
    wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError,
    WasmNativeModule,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVmError, WasmStateError,
};
use WasmBoundaryValue::I32;
use RuntimeCapability::{Builtin, VmDispatch};

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len() as u32));
    module.extend_from_slice(payload);
}

const LOOP: &[u8] = &[
    0x41, 20, 0x21, 0, 0x02, 0x40, 0x03, 0x40,
    0x20, 0, 0x45, 0x0d, 1,
    0x23, 0, 0x41, 1, 0x6a, 0x24, 0,
    0x20, 0, 0x41, 1, 0x6b, 0x21, 0, 0x0c, 0,
    0x0b, 0x0b, 0x41, 0, 0x23, 0, 0x36, 2, 0, 0x0b,
];
const TWO_HOSTS: &[u8] = &[0x10, 0, 0x41, 9, 0x24, 0, 0x10, 0, 0x0b];

struct Fixture {
    start: bool,
    imported_start: bool,
    hosts: u8,
    locals: u32,
    code: Vec<u8>,
    helper: Option<Vec<u8>>,
    invalid_data: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            start: true, imported_start: false, hosts: 0,
            locals: 1, code: LOOP.to_vec(), helper: None, invalid_data: false,
        }
    }
}

impl Fixture {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[3, 0x60, 0, 0, 0x60, 0, 1, 0x7f, 0x60, 1, 0x7f, 0]);
        if self.hosts != 0 {
            let mut imports = vec![self.hosts];
            for index in 0..self.hosts { imports.extend([1, b'h', 1, b'f' + index, 0, 0]); }
            section(&mut bytes, 2, &imports);
        }
        section(&mut bytes, 3, if self.helper.is_some() { &[3, 1, 0, 2] } else { &[2, 1, 0] });
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        section(&mut bytes, 5, &[1, 1, 1, 2]);
        section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
        section(&mut bytes, 7, &[4, 3, b'g', b'e', b't', 0, self.hosts,
            1, b'g', 3, 0, 1, b'm', 2, 0, 1, b't', 1, 0]);
        if self.start { section(&mut bytes, 8, &[if self.imported_start { 0 } else { self.hosts + 1 }]); }
        section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1,
            if self.helper.is_some() { self.hosts + 2 } else { 0 }]);
        section(&mut bytes, 12, &[2]);
        let mut bodies = vec![if self.helper.is_some() { 3 } else { 2 }, 4, 0, 0x23, 0, 0x0b];
        let mut body = if self.locals == 0 { vec![0] } else {
            let mut locals = vec![1]; locals.extend(leb(self.locals)); locals.push(0x7f); locals
        };
        body.extend_from_slice(&self.code);
        bodies.extend(leb(body.len() as u32)); bodies.extend(body);
        if let Some(helper) = &self.helper {
            bodies.extend(leb(helper.len() as u32 + 1)); bodies.push(0); bodies.extend(helper);
        }
        section(&mut bytes, 10, &bodies);
        let mut data = vec![2, 0, 0x41];
        data.extend(if self.invalid_data { vec![0x80, 0x80, 4] } else { vec![8] });
        data.extend([0x0b, 3, 255, 0, 128, 1, 3, b'X', b'Y', b'Z']);
        section(&mut bytes, 11, &data);
        bytes
    }
}

fn quantum(work: u64) -> NonZeroU64 { NonZeroU64::new(work).unwrap() }
fn context() -> ResolutionContext { ResolutionContext::new("startup-trace", "startup-decision", "current-policy") }
fn policy(services: &[RuntimeCapability]) -> CapabilityPolicyHook {
    let mut grants = wasm_module_required_capabilities();
    grants.extend(services.iter().copied());
    CapabilityPolicyHook::new(grants)
}
fn load(fixture: &Fixture, declared: &[RuntimeCapability], limits: WasmNumericLimits) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/main.mjs", ModuleDefinition::new(
        ModuleSyntax::EsModule, "import './start.wasm';",
    )).unwrap();
    let mut definition = ModuleDefinition::wasm_binary(&fixture.bytes(), &WasmNumericLimits::default()).unwrap();
    definition.required_capabilities.extend(declared.iter().copied());
    resolver.register_workspace_module("/app/start.wasm", definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new("./start.wasm", ImportStyle::Import).with_referrer("/app/main.mjs"),
        &context(), &policy(declared), limits).unwrap()
}
fn reader(
    current: &Arc<Mutex<CapabilityPolicyHook>>, reads: &Arc<AtomicUsize>,
) -> impl FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError> + Send + 'static {
    let current = Arc::clone(current); let reads = Arc::clone(reads);
    move || { reads.fetch_add(1, Ordering::SeqCst); Ok((context(), current.lock().unwrap().clone())) }
}
fn imports<F>(callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue])
    -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync + 'static,
{
    let mut imports = WasmHostImports::new([VmDispatch, Builtin].into());
    imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
        [Builtin].into(), 3, callback).unwrap();
    imports
}
fn counting(calls: &Arc<AtomicUsize>) -> WasmHostImports {
    let calls = Arc::clone(calls);
    imports(move |caller, _| {
        assert_eq!(caller.read_memory(8, 3)?, &[255, 0, 128]);
        let count = calls.fetch_add(1, Ordering::SeqCst) + 1;
        caller.write_memory(0, &(count as u32).to_le_bytes())?;
        Ok(vec![])
    })
}
#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn poll<F: Future>(future: Pin<&mut F>, wake: &Arc<WakeCount>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::clone(wake));
    future.poll(&mut Context::from_waker(&waker))
}
fn drive<F: Future>(mut future: Pin<&mut F>, wake: &Arc<WakeCount>) -> F::Output {
    for _ in 0..1_000_000 {
        if let Poll::Ready(output) = poll(future.as_mut(), wake) { return output; }
    }
    panic!("startup did not terminate within its hard budget");
}
fn denied<T>(result: Result<T, WasmNativeLoadError>) {
    match result {
        Err(WasmNativeLoadError::Resolution(error)) => assert_eq!(error.code, ResolutionErrorCode::PolicyDenied),
        _ => panic!("expected resolution policy denial"),
    }
}
fn host_fixture() -> Fixture { Fixture { hosts: 1, code: TWO_HOSTS.to_vec(), ..Fixture::default() } }

#[test]
fn lazy_resolved_startup_preserves_metrics_state_and_one_wake_per_pending_poll() {
    let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
    let current = Arc::new(Mutex::new(policy(&[Builtin])));
    let baseline = module.instantiate_with_imports(&context(), &policy(&[Builtin]), counting(&Arc::new(AtomicUsize::new(0)))).unwrap();
    for work in [1, 2, 7, u64::MAX] {
        let reads = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let wake = Arc::new(WakeCount::default());
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(
            counting(&calls), quantum(work), reader(&current, &reads),
        ));
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&future);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut instance = drive(future.as_mut(), &wake).unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), wake.0.load(Ordering::SeqCst) + 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(instance.start_execution(&context(), &policy(&[Builtin])).unwrap(), baseline.start_execution(&context(), &policy(&[Builtin])).unwrap());
        assert_eq!(instance.memory_export("m", &context(), &policy(&[Builtin])).unwrap(), baseline.memory_export("m", &context(), &policy(&[Builtin])).unwrap());
        assert_eq!(instance.call_export("get", &[] , &context(), &policy(&[Builtin])).unwrap().results, [I32(9)]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn current_policy_denial_precedes_linking_allocation_and_every_guest_instruction() {
    let fixture = Fixture { hosts: 2, code: TWO_HOSTS.to_vec(), ..Fixture::default() };
    let module = load(&fixture, &[Builtin], WasmNumericLimits { max_memory_pages: 0, ..WasmNumericLimits::default() });
    let current = Arc::new(Mutex::new(policy(&[])));
    let reads = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut future = Box::pin(module.instantiate_cooperatively_with_imports(counting(&calls), quantum(1), reader(&current, &reads)));
    denied(drive(future.as_mut(), &Arc::new(WakeCount::default())));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[test]
fn a_suspended_host_call_cannot_use_the_policy_that_was_valid_before_yield() {
    let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
    let current = Arc::new(Mutex::new(policy(&[Builtin])));
    let reads = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0)); let wake = Arc::new(WakeCount::default());
    let mut future = Box::pin(module.instantiate_cooperatively_with_imports(counting(&calls), quantum(1), reader(&current, &reads)));
    assert!(poll(future.as_mut(), &wake).is_pending()); // after call opcode, before host entry
    *current.lock().unwrap() = policy(&[]);
    denied(drive(future.as_mut(), &wake));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    *current.lock().unwrap() = policy(&[Builtin]);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let _ = poll(future.as_mut(), &wake); })).is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn alias_and_canonical_denials_are_rechecked_while_startup_is_pending() {
    for name in ["./start.wasm", "/app/start.wasm"] {
        let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
        let current = Arc::new(Mutex::new(policy(&[Builtin])));
        let calls = Arc::new(AtomicUsize::new(0)); let wake = Arc::new(WakeCount::default());
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(counting(&calls), quantum(1), reader(&current, &Arc::new(AtomicUsize::new(0)))));
        assert!(poll(future.as_mut(), &wake).is_pending());
        *current.lock().unwrap() = policy(&[Builtin]).deny_specifier(name);
        denied(drive(future.as_mut(), &wake));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn last_callback_policy_changes_are_observed_before_instance_publication() {
    let fixture = Fixture { hosts: 1, code: vec![0x10, 0, 0x0b], ..Fixture::default() };
    let module = load(&fixture, &[Builtin], WasmNumericLimits::default());
    let current = Arc::new(Mutex::new(policy(&[Builtin])));
    let reads = Arc::new(AtomicUsize::new(0)); let calls = Arc::new(AtomicUsize::new(0));
    let revoke = Arc::clone(&current); let observed = Arc::clone(&calls);
    let provider = imports(move |_, _| { observed.fetch_add(1, Ordering::SeqCst); *revoke.lock().unwrap() = policy(&[]); Ok(vec![]) });
    let mut future = Box::pin(module.instantiate_cooperatively_with_imports(provider, quantum(u64::MAX), reader(&current, &reads)));
    denied(drive(future.as_mut(), &Arc::new(WakeCount::default())));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn no_start_modules_still_require_a_current_publication_decision() {
    let module = load(&Fixture { start: false, ..Fixture::default() }, &[], WasmNumericLimits { max_instructions: 0, ..WasmNumericLimits::default() });
    let mut reads = 0;
    let mut future = Box::pin(module.instantiate_cooperatively(quantum(1), move || {
        reads += 1;
        let grants = if reads == 1 { policy(&[]) } else { CapabilityPolicyHook::new(Default::default()) };
        Ok((context(), grants))
    }));
    denied(drive(future.as_mut(), &Arc::new(WakeCount::default())));
    let mut future = Box::pin(module.instantiate_cooperatively(quantum(1), || Ok((context(), policy(&[])))));
    let instance = drive(future.as_mut(), &Arc::new(WakeCount::default())).unwrap();
    assert_eq!(instance.start_execution(&context(), &policy(&[])).unwrap(), None);
}

#[test]
fn policy_reader_failure_is_terminal_and_releases_captured_provider_state() {
    struct Lifetime(Arc<AtomicUsize>);
    impl Drop for Lifetime { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
    let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
    for fail_on in [1, 2] {
        let released = Arc::new(AtomicUsize::new(0)); let lifetime = Lifetime(Arc::clone(&released));
        let provider = imports(move |_, _| { let _keep = &lifetime; Ok(vec![]) });
        let mut reads = 0;
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(provider, quantum(1), move || {
            reads += 1;
            if reads == fail_on { return Err(WasmNumericVmError::from(WasmHostError::trap("policy reader unavailable")).into()); }
            Ok((context(), policy(&[Builtin])))
        }));
        assert!(matches!(drive(future.as_mut(), &Arc::new(WakeCount::default())),
            Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. }))))));
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn original_execution_error_precedes_a_later_policy_reader_failure() {
    let module = load(&Fixture { code: vec![0x00, 0x0b], ..Fixture::default() }, &[], WasmNumericLimits::default());
    let reads = Arc::new(AtomicUsize::new(0)); let observed = Arc::clone(&reads);
    let mut future = Box::pin(module.instantiate_cooperatively(quantum(10), move || {
        if observed.fetch_add(1, Ordering::SeqCst) != 0 { return Err(WasmNumericVmError::from(WasmHostError::trap("later policy failure")).into()); }
        Ok((context(), policy(&[])))
    }));
    assert!(matches!(drive(future.as_mut(), &Arc::new(WakeCount::default())),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_manifest_and_live_policy_all_have_to_authorize_imported_services() {
    for granted in [false, true] { for declared in [false, true] { for authorized in [false, true] {
        let declaration: &[RuntimeCapability] = if declared { &[Builtin] } else { &[] };
        let module = load(&host_fixture(), declaration, WasmNumericLimits::default());
        let mut provider = WasmHostImports::new(if granted { [VmDispatch, Builtin].into() } else { [VmDispatch].into() });
        provider.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] }, [Builtin].into(), 1, |_, _| Ok(vec![])).unwrap();
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(provider, quantum(1), move || Ok((context(), if authorized { policy(&[Builtin]) } else { policy(&[]) }))));
        let result = drive(future.as_mut(), &Arc::new(WakeCount::default()));
        assert_eq!(result.is_ok(), granted && declared && authorized);
        if declared && !authorized { denied(result); }
        else if !granted || !declared {
            assert!(matches!(result, Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { .. }))))));
        }
    } } }
}

#[test]
fn startup_work_slices_cannot_replenish_the_original_hard_budget() {
    let fixture = Fixture::default();
    let module = load(&fixture, &[], WasmNumericLimits { max_instructions: 10, ..WasmNumericLimits::default() });
    let mut future = Box::pin(module.instantiate_cooperatively(quantum(1), || Ok((context(), policy(&[])))));
    let wake = Arc::new(WakeCount::default());
    assert!(matches!(drive(future.as_mut(), &wake), Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 10 }))));
    assert_eq!(wake.0.load(Ordering::SeqCst), 10);
}

#[test]
fn execution_cancellation_and_service_revocation_survive_policy_authorization() {
    for execution in [false, true] {
        let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
        let token = CancellationToken::new(); let calls = Arc::new(AtomicUsize::new(0));
        let mut provider = counting(&calls);
        if execution { provider.bind_execution_cancellation(token.clone(), "resolved-start").unwrap(); }
        else { provider.bind_capability_revocation(Builtin, token.clone(), "resolved-service").unwrap(); }
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(provider, quantum(1), || Ok((context(), policy(&[Builtin])))));
        let wake = Arc::new(WakeCount::default());
        assert!(poll(future.as_mut(), &wake).is_pending());
        token.cancel(); token.reset();
        let error = drive(future.as_mut(), &wake).unwrap_err();
        if execution {
            assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ExecutionCancelled)))));
        } else {
            assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: Builtin, .. })))));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn partially_started_instances_remain_isolated_and_cannot_repeat_completed_effects() {
    let module = load(&host_fixture(), &[Builtin], WasmNumericLimits::default());
    let first = Arc::new(AtomicUsize::new(0)); let second = Arc::new(AtomicUsize::new(0));
    let mut a = Box::pin(module.instantiate_cooperatively_with_imports(counting(&first), quantum(1), || Ok((context(), policy(&[Builtin])))));
    let mut b = Box::pin(module.instantiate_cooperatively_with_imports(counting(&second), quantum(7), || Ok((context(), policy(&[Builtin])))));
    let wake = Arc::new(WakeCount::default());
    assert!(poll(a.as_mut(), &wake).is_pending());
    assert!(poll(a.as_mut(), &wake).is_pending());
    assert_eq!(first.load(Ordering::SeqCst), 1);
    let ready = drive(b.as_mut(), &wake).unwrap();
    assert_eq!(second.load(Ordering::SeqCst), 2);
    drop(a);
    assert_eq!(first.load(Ordering::SeqCst), 1);
    assert_eq!(&ready.memory_export("m", &context(), &policy(&[Builtin])).unwrap().unwrap()[..4], &2_u32.to_le_bytes());
}
