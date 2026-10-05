use super::*;
use crate::host_effect_budget::{HostEffectLimits, HostEffectSnapshot};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};
use frankenengine_extension_host::process_spawn::{
    DenyAllProcessSpawn, ProcessExit, ProcessLaunch, ProcessSignal, ProcessStdio,
};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

const GRANTED: &[ProcessSpawnCapability] = &[ProcessSpawnCapability::Spawn];

fn pool(operations: u64, max_in_flight: usize) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits { operations, max_in_flight })
}

fn launch() -> ProcessLaunch {
    ProcessLaunch {
        executable: "tool".into(),
        argv: vec!["arg".into()],
        env: BTreeMap::new(),
        cwd: None,
        shell: false,
        stdio: ProcessStdio::default(),
    }
}

fn request() -> ProcessSpawnRequest {
    ProcessSpawnRequest::Run { launch: launch(), stdin: vec![1], timeout_millis: Some(1000) }
}

fn success() -> ProcessSpawnOutcome {
    Ok(ProcessSpawnResponse::Run {
        exit: ProcessExit { success: true, code: Some(0), signal: None },
        stdout: vec![1],
        stderr: Vec::new(),
    })
}

fn assert_denied(outcome: ProcessSpawnOutcome, code: &str) {
    assert!(matches!(outcome, Err(ProcessSpawnError::Denied { reason }) if reason == code));
}

#[derive(Debug, Default)]
struct Counting {
    calls: AtomicUsize,
    cleanups: AtomicUsize,
}

impl ProcessSpawnProvider for Counting {
    fn name(&self) -> &str { "counting-process" }

    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
        panic!("live control must never be dropped by the decorator")
    }

    fn perform_controlled(
        &self,
        _: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        assert_eq!(granted, GRANTED);
        control.checkpoint()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        success()
    }

    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

#[derive(Debug, Default)]
struct CountingIo(AtomicUsize);
impl HostIoProvider for CountingIo {
    fn name(&self) -> &str { "counting-io" }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("live I/O control must be forwarded")
    }
    fn perform_controlled(
        &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(HostIoResponse::FsRead { bytes: vec![1] })
    }
}

#[test]
fn process_and_io_aliases_spend_one_nonrenewable_pool() {
    let budget = pool(3, 1);
    let work = ExecutionWorkPool::new(100);
    let process_inner = Arc::new(Counting::default());
    let io_inner = Arc::new(CountingIo::default());
    let process = budget.bind_process_spawn(process_inner.clone(), &work);
    let io = budget.clone().bind_host_io(io_inner.clone(), &work);
    let read = HostIoRequest::FsRead { path: "a".into() };
    process.perform(&request(), GRANTED).unwrap();
    io.perform(&read, &[HostIoCapability::FsRead]).unwrap();
    process.clone().perform(&request(), GRANTED).unwrap();
    assert_denied(process.perform(&request(), GRANTED), "HOST_EFFECT_BUDGET_EXHAUSTED");
    assert!(io.perform(&read, &[HostIoCapability::FsRead]).is_err());
    assert_eq!(process_inner.calls.load(Ordering::SeqCst), 2);
    assert_eq!(io_inner.0.load(Ordering::SeqCst), 1);
    assert_eq!(work.remaining(), 100);
    assert_eq!(budget.snapshot().unwrap(), HostEffectSnapshot {
        remaining_operations: 0, committed_operations: 3, in_flight: 0,
    });
}

#[test]
fn zero_limits_and_missing_capability_never_reach_the_process_provider() {
    for (operations, concurrency) in [(0, 1), (1, 0)] {
        let budget = pool(operations, concurrency);
        let inner = Arc::new(Counting::default());
        let provider = budget.bind_process_spawn(inner.clone(), &ExecutionWorkPool::new(1));
        assert!(provider.perform(&request(), GRANTED).is_err());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
    }
    let budget = pool(1, 1);
    let inner = Arc::new(Counting::default());
    let provider = budget.bind_process_spawn(inner.clone(), &ExecutionWorkPool::new(1));
    assert!(matches!(provider.perform(&request(), &[]), Err(ProcessSpawnError::CapabilityMissing { .. })));
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().remaining_operations, 1);
    assert_eq!(provider.name(), inner.name());
}

#[test]
fn every_guest_process_operation_is_metered_but_cleanup_cannot_be_smuggled() {
    let operations = vec![
        request(),
        ProcessSpawnRequest::Spawn { launch: launch() },
        ProcessSpawnRequest::WriteStdin { handle: "h".into(), data: vec![1] },
        ProcessSpawnRequest::CloseStdin { handle: "h".into() },
        ProcessSpawnRequest::Wait { handle: "h".into(), timeout_millis: None },
        ProcessSpawnRequest::Kill { handle: "h".into(), signal: ProcessSignal::Kill },
    ];
    let budget = pool(operations.len() as u64, 1);
    let inner = Arc::new(Counting::default());
    let provider = budget.bind_process_spawn(inner.clone(), &ExecutionWorkPool::new(1));
    for operation in &operations { provider.perform(operation, GRANTED).unwrap(); }
    assert_eq!(budget.snapshot().unwrap().committed_operations, operations.len() as u64);
    let cleanup = ProcessSpawnRequest::Cleanup { handle: "h".into() };
    assert_denied(provider.perform(&cleanup, GRANTED), "HOST_EFFECT_CLEANUP_REQUIRES_HOST_AUTHORITY");
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 0);
    assert_eq!(inner.calls.load(Ordering::SeqCst), operations.len());
}

#[derive(Debug)]
struct Prepared;
impl ProcessSpawnProvider for Prepared {
    fn name(&self) -> &str { "policy-prepared" }
    fn preflight_request(&self, request: &ProcessSpawnRequest) -> Result<(), ProcessSpawnError> {
        match request {
            ProcessSpawnRequest::Run { stdin, .. } if stdin.len() <= 1 => Ok(()),
            _ => Err(ProcessSpawnError::LimitExceeded { limit: "stdin".into(), actual: 2, maximum: 1 }),
        }
    }
    fn prepare_request(&self, request: &ProcessSpawnRequest) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
        let mut request = request.clone();
        if let ProcessSpawnRequest::Run { launch, .. } = &mut request {
            launch.executable = "/policy/pinned-tool".into();
        }
        Ok(request)
    }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome { success() }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { Err(denied("cleanup failed")) }
}

#[test]
fn preflight_and_canonical_preparation_do_not_consume_or_consult_live_credits() {
    let budget = pool(0, 0);
    let work = ExecutionWorkPool::new(1);
    let provider = budget.bind_process_spawn(Arc::new(Prepared), &work);
    budget.revoke();
    work.revoke();
    provider.preflight_request(&request()).unwrap();
    let canonical = provider.prepare_request(&request()).unwrap();
    assert!(matches!(canonical, ProcessSpawnRequest::Run { launch, .. } if launch.executable == "/policy/pinned-tool"));
    assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
    let oversized = ProcessSpawnRequest::Run { launch: launch(), stdin: vec![1, 2], timeout_millis: None };
    assert!(matches!(provider.preflight_request(&oversized), Err(ProcessSpawnError::LimitExceeded { .. })));
    // The wrapper must never invent successful cleanup, even after revocation.
    assert_denied(provider.cleanup_handle("h"), "cleanup failed");
}

#[test]
fn rejected_preflight_does_not_debit_live_admission() {
    let budget = pool(1, 1);
    let provider = budget.bind_process_spawn(Arc::new(Prepared), &ExecutionWorkPool::new(1));
    let oversized = ProcessSpawnRequest::Run { launch: launch(), stdin: vec![1, 2], timeout_millis: None };
    assert!(matches!(provider.perform(&oversized, GRANTED), Err(ProcessSpawnError::LimitExceeded { .. })));
    assert_eq!(budget.snapshot().unwrap().remaining_operations, 1);
}

#[derive(Debug)]
struct Blocking {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}
impl ProcessSpawnProvider for Blocking {
    fn name(&self) -> &str { "blocking-process" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome { unreachable!() }
    fn perform_controlled(
        &self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability], control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        control.checkpoint()?;
        success()
    }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { Ok(ProcessSpawnResponse::Cleaned { was_present: true }) }
}

#[test]
fn process_in_flight_blocks_io_admission_without_spending_a_second_credit() {
    let budget = pool(3, 1);
    let work = ExecutionWorkPool::new(1);
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let process = budget.bind_process_spawn(Arc::new(Blocking { entered: entered_tx, release: Mutex::new(release_rx) }), &work);
    let worker = std::thread::spawn(move || process.perform(&request(), GRANTED));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let io_inner = Arc::new(CountingIo::default());
    let io = budget.bind_host_io(io_inner.clone(), &work);
    let outcome = io.perform(&HostIoRequest::FsRead { path: "a".into() }, &[HostIoCapability::FsRead]);
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(outcome.is_err());
    assert_eq!(io_inner.0.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[test]
fn active_process_observes_child_and_ancestor_revocation_without_revoking_siblings() {
    let budget = pool(3, 2);
    let root = ExecutionWorkPool::new(20);
    let child = root.partition(10).unwrap();
    let sibling = root.partition(10).unwrap();
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let process = budget.bind_process_spawn(Arc::new(Blocking { entered: entered_tx, release: Mutex::new(release_rx) }), &child);
    let worker = std::thread::spawn(move || process.perform(&request(), GRANTED));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    child.revoke();
    release.send(()).unwrap();
    assert_denied(worker.join().unwrap(), "HOST_EFFECT_SCOPE_REVOKED");
    let inner = Arc::new(Counting::default());
    let peer = budget.bind_process_spawn(inner.clone(), &sibling);
    peer.perform(&request(), GRANTED).unwrap();
    root.revoke();
    assert_denied(peer.perform(&request(), GRANTED), "HOST_EFFECT_SCOPE_REVOKED");
    assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 2);
}

#[derive(Debug)]
struct TerminalFailure;
impl ProcessSpawnProvider for TerminalFailure {
    fn name(&self) -> &str { "terminal-failure" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
        Err(ProcessSpawnError::PartialOutputFailed {
            failure: Box::new(ProcessSpawnError::TimedOut { runtime_millis: 1 }),
            signal: Some(9), partial_stdout: vec![1, 2], partial_stderr: vec![3],
        })
    }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { Ok(ProcessSpawnResponse::Cleaned { was_present: false }) }
}

#[test]
fn native_failures_remain_typed_and_do_not_refund_credits() {
    let budget = pool(1, 1);
    let provider = budget.bind_process_spawn(Arc::new(TerminalFailure), &ExecutionWorkPool::new(1));
    let expected = TerminalFailure.perform(&request(), GRANTED);
    assert_eq!(provider.perform(&request(), GRANTED), expected);
    assert_denied(provider.perform(&request(), GRANTED), "HOST_EFFECT_BUDGET_EXHAUSTED");
    assert_eq!(budget.snapshot().unwrap().in_flight, 0);
}

#[derive(Debug)]
struct Panicking;
impl ProcessSpawnProvider for Panicking {
    fn name(&self) -> &str { "panicking-process" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome { panic!("native unwind") }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { Ok(ProcessSpawnResponse::Cleaned { was_present: true }) }
}

#[test]
fn unwinding_revokes_the_shared_pool_but_cleanup_remains_available() {
    let budget = pool(3, 1);
    let work = ExecutionWorkPool::new(1);
    let provider = budget.bind_process_spawn(Arc::new(Panicking), &work);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provider.perform(&request(), GRANTED))).is_err());
    assert!(budget.is_revoked());
    assert_eq!(budget.snapshot().unwrap(), HostEffectSnapshot { remaining_operations: 2, committed_operations: 1, in_flight: 0 });
    assert_eq!(provider.cleanup_handle("h"), Ok(ProcessSpawnResponse::Cleaned { was_present: true }));
    let io = budget.bind_host_io(Arc::new(CountingIo::default()), &work);
    assert!(io.perform(&HostIoRequest::FsRead { path: "a".into() }, &[HostIoCapability::FsRead]).is_err());
}

#[test]
fn poisoned_admission_still_permits_real_compensating_cleanup() {
    let budget = pool(1, 1);
    let alias = budget.clone();
    assert!(std::panic::catch_unwind(move || {
        let _guard = alias.state.accounting.lock().unwrap();
        panic!("poison accounting");
    }).is_err());
    let inner = Arc::new(Counting::default());
    let provider = budget.bind_process_spawn(inner.clone(), &ExecutionWorkPool::new(1));
    assert!(provider.perform(&request(), GRANTED).is_err());
    provider.cleanup_handle("h").unwrap();
    assert_eq!(inner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 1);
}

#[derive(Debug, Default)]
struct Resettable(AtomicBool);
impl ProcessSpawnControl for Resettable {
    fn checkpoint(&self) -> Result<(), ProcessSpawnError> {
        if self.0.load(Ordering::SeqCst) {
            Err(ProcessSpawnError::Io { operation: "private-operation".into(), detail: "private-secret".into() })
        } else { Ok(()) }
    }
}

#[derive(Debug)]
struct ResetAfterRefusal(Arc<Resettable>);
impl ProcessSpawnProvider for ResetAfterRefusal {
    fn name(&self) -> &str { "reset-after-refusal" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome { unreachable!() }
    fn perform_controlled(
        &self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability], control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        self.0.0.store(true, Ordering::SeqCst);
        assert_denied(control.checkpoint().map(|_| unreachable!()), "HOST_EFFECT_SCOPE_REVOKED");
        self.0.0.store(false, Ordering::SeqCst);
        assert!(control.checkpoint().is_err());
        success()
    }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { unreachable!() }
}

#[test]
fn caller_control_refusal_is_sticky_sanitized_and_operation_local() {
    let budget = pool(2, 1);
    let work = ExecutionWorkPool::new(1);
    let caller = Arc::new(Resettable::default());
    let provider = budget.bind_process_spawn(Arc::new(ResetAfterRefusal(caller.clone())), &work);
    assert_denied(provider.perform_controlled(&request(), GRANTED, caller.clone()), "HOST_EFFECT_SCOPE_REVOKED");
    let next = budget.bind_process_spawn(Arc::new(Counting::default()), &work);
    next.perform_controlled(&request(), GRANTED, caller).unwrap();
    assert!(!budget.is_revoked());
    assert_eq!(budget.snapshot().unwrap().committed_operations, 2);
}

#[derive(Debug)]
struct RacedSpawn { pool: HostEffectWorkPool, cleanups: AtomicUsize }
impl ProcessSpawnProvider for RacedSpawn {
    fn name(&self) -> &str { "raced-spawn" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
        self.pool.revoke();
        Ok(ProcessSpawnResponse::Spawned { handle: "owned-child".into() })
    }
    fn cleanup_handle(&self, handle: &str) -> ProcessSpawnOutcome {
        assert_eq!(handle, "owned-child");
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

#[test]
fn late_revocation_cannot_hide_a_created_handle_or_trigger_unjournaled_cleanup() {
    let budget = pool(2, 1);
    let inner = Arc::new(RacedSpawn { pool: budget.clone(), cleanups: AtomicUsize::new(0) });
    let provider = budget.bind_process_spawn(inner.clone(), &ExecutionWorkPool::new(1));
    let result = provider.perform(&ProcessSpawnRequest::Spawn { launch: launch() }, GRANTED).unwrap();
    let ProcessSpawnResponse::Spawned { handle } = result else { panic!("created handle must be visible to the journal") };
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 0);
    assert_denied(provider.perform(&ProcessSpawnRequest::Wait { handle: handle.clone(), timeout_millis: None }, GRANTED), "HOST_EFFECT_SCOPE_REVOKED");
    provider.cleanup_handle(&handle).unwrap();
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 1);
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
}

#[derive(Debug)]
struct SecretProvider;
impl ProcessSpawnProvider for SecretProvider {
    fn name(&self) -> &str { "private-provider-name" }
    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome { success() }
    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome { unreachable!() }
}

#[test]
fn debug_does_not_expand_providers_and_deny_all_remains_deny_all() {
    let budget = pool(1, 1);
    let work = ExecutionWorkPool::new(1);
    let wrapped = budget.bind_process_spawn(Arc::new(SecretProvider), &work);
    let debug = format!("{wrapped:?}");
    assert!(!debug.contains("SecretProvider"));
    assert!(!debug.contains("private-provider-name"));
    let denied_provider = budget.bind_process_spawn(Arc::new(DenyAllProcessSpawn), &work);
    assert_eq!(denied_provider.name(), "deny-all-process-spawn");
    assert!(matches!(denied_provider.perform(&request(), GRANTED), Err(ProcessSpawnError::Denied { .. })));
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod native {
    use super::*;
    use frankenengine_extension_host::process_spawn::{NativeProcessSpawn, ProcessSpawnPolicy};
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!("franken-core-effect-process-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn cat(scratch: &Scratch) -> (Arc<NativeProcessSpawn>, ProcessLaunch) {
        let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).unwrap();
        policy.limits.max_runtime_millis = 2000;
        let executable = policy.authorize_executable("/bin/cat").unwrap();
        let provider = Arc::new(NativeProcessSpawn::new(policy).unwrap());
        (provider, ProcessLaunch { executable, argv: Vec::new(), ..launch() })
    }

    #[test]
    fn real_native_run_returns_actual_bytes_and_exhaustion_prevents_another_launch() {
        let scratch = Scratch::new();
        let (native, launch) = cat(&scratch);
        let budget = pool(1, 1);
        let provider = budget.bind_process_spawn(native, &ExecutionWorkPool::new(1));
        let request = ProcessSpawnRequest::Run { launch, stdin: b"real bounded process\0\xff".to_vec(), timeout_millis: Some(2000) };
        let response = provider.perform(&request, GRANTED).unwrap();
        let ProcessSpawnResponse::Run { exit, stdout, stderr } = response else { panic!("native run response") };
        assert!(exit.success);
        assert_eq!(stdout, b"real bounded process\0\xff");
        assert!(stderr.is_empty());
        assert_denied(provider.perform(&request, GRANTED), "HOST_EFFECT_BUDGET_EXHAUSTED");
        assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    }

    #[test]
    fn a_real_child_is_reaped_after_budget_exhaustion_and_scope_revocation() {
        let scratch = Scratch::new();
        let (native, launch) = cat(&scratch);
        let budget = pool(1, 1);
        let work = ExecutionWorkPool::new(1);
        let provider = budget.bind_process_spawn(native, &work);
        let ProcessSpawnResponse::Spawned { handle } = provider.perform(&ProcessSpawnRequest::Spawn { launch }, GRANTED).unwrap() else { panic!("native child handle") };
        work.revoke();
        budget.revoke();
        assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: true }));
        assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: false }));
        assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
        assert_eq!(budget.snapshot().unwrap().in_flight, 0);
    }
}
