use super::*;
use crate::execution_work_budget::ExecutionWorkPool;
use crate::host_effect_budget::{HostEffectBudgetError, HostEffectLimits};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
    HostIoResponse,
};
use frankenengine_extension_host::process_spawn::{
    ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnError, ProcessSpawnOutcome,
    ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Barrier, Mutex};

const WAIT: Duration = Duration::from_secs(5);

fn pool(operations: u64, max_in_flight: usize) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits {
        operations,
        max_in_flight,
    })
}

fn read() -> HostIoRequest {
    HostIoRequest::FsRead { path: "a".into() }
}

fn wait_for_revocation(pool: &HostEffectWorkPool) {
    let deadline = Instant::now() + WAIT;
    while !pool.is_revoked() {
        assert!(Instant::now() < deadline, "closer never requested revocation");
        std::thread::yield_now();
    }
}

// These controlled providers exercise boundary interleavings. Real native
// effects are tested separately below; these are not OS containment evidence.
#[derive(Debug)]
struct Parked {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    panic_on_release: bool,
}

fn parked(panic_on_release: bool) -> (Arc<Parked>, Receiver<()>, Sender<()>) {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    (
        Arc::new(Parked {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            panic_on_release,
        }),
        entered,
        release,
    )
}

impl Parked {
    fn park(&self) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        assert!(!self.panic_on_release, "provider unwind after dispatch");
    }
}

impl HostIoProvider for Parked {
    fn name(&self) -> &str {
        "parked-drain-test"
    }

    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("live I/O control must be forwarded")
    }

    fn perform_controlled(
        &self,
        _: &HostIoRequest,
        _: &[HostIoCapability],
        control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.park();
        control.checkpoint()?;
        Ok(HostIoResponse::FsRead { bytes: vec![1] })
    }
}

impl ProcessSpawnProvider for Parked {
    fn name(&self) -> &str {
        "parked-process-drain-test"
    }

    fn perform(&self, _: &ProcessSpawnRequest, _: &[ProcessSpawnCapability]) -> ProcessSpawnOutcome {
        panic!("live process control must be forwarded")
    }

    fn perform_controlled(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        self.park();
        control.checkpoint()?;
        Err(ProcessSpawnError::Denied {
            reason: "test provider has no native child".into(),
        })
    }

    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

#[derive(Debug, Default)]
struct CountingIo(AtomicUsize);

impl HostIoProvider for CountingIo {
    fn name(&self) -> &str {
        "counting-drain-test"
    }

    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(HostIoResponse::FsRead { bytes: vec![1] })
    }
}

#[test]
fn idle_drain_revokes_every_clone_without_consuming_work() {
    for allowance in [0, 5] {
        let budget = pool(allowance, 1);
        let alias = budget.clone();
        let before = budget.snapshot().unwrap();
        assert_eq!(budget.revoke_and_drain(Duration::ZERO), Ok(before));
        assert!(alias.is_revoked());
        assert!(matches!(alias.admit(), Err(HostEffectBudgetError::Revoked)));
        assert_eq!(alias.revoke_and_drain(Duration::ZERO), Ok(before));
    }
}

#[test]
fn zero_timeout_preserves_active_permits_and_nonrefundable_credits() {
    let budget = pool(3, 2);
    let first = budget.admit().unwrap();
    let second = budget.admit().unwrap();
    let before = budget.snapshot().unwrap();
    assert_eq!(
        budget.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::TimedOut { in_flight: 2 })
    );
    assert_eq!(budget.snapshot().unwrap(), before);
    drop(first);
    assert_eq!(
        budget.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::TimedOut { in_flight: 1 })
    );
    drop(second);
    assert_eq!(
        budget.revoke_and_drain(Duration::ZERO),
        Ok(HostEffectSnapshot {
            remaining_operations: 1,
            committed_operations: 2,
            in_flight: 0,
        })
    );
}

#[test]
fn last_permit_wakes_all_closers_and_the_first_completion_is_not_enough() {
    let budget = pool(3, 2);
    let first = budget.admit().unwrap();
    let second = budget.admit().unwrap();
    let start = Arc::new(Barrier::new(9));
    let (done, results) = channel();
    let mut workers = Vec::new();
    for _ in 0..8 {
        let alias = budget.clone();
        let start = start.clone();
        let done = done.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            done.send(alias.revoke_and_drain(WAIT)).unwrap();
        }));
    }
    start.wait();
    wait_for_revocation(&budget);
    drop(first);
    assert!(results.try_recv().is_err());
    drop(second);
    // Without final-permit notification, waiters remain asleep for WAIT.
    for _ in 0..8 {
        let result = results.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        assert_eq!(result.in_flight, 0);
        assert_eq!(result.committed_operations, 2);
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn notifications_neither_complete_active_work_nor_renew_the_wait_deadline() {
    let budget = pool(1, 1);
    let permit = budget.admit().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let notify_budget = budget.clone();
    let notify_stopped = stopped.clone();
    let notifier = std::thread::spawn(move || {
        let end = Instant::now() + WAIT;
        while !notify_stopped.load(Ordering::Acquire) && Instant::now() < end {
            notify_budget.state.idle.notify_all();
            std::thread::yield_now();
        }
    });
    let started = Instant::now();
    let result = budget.revoke_and_drain(Duration::from_millis(30));
    stopped.store(true, Ordering::Release);
    notifier.join().unwrap();
    assert_eq!(result, Err(HostEffectDrainError::TimedOut { in_flight: 1 }));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(budget.snapshot().unwrap().in_flight, 1);
    drop(permit);
}

#[test]
fn an_uncooperative_provider_must_return_before_drain_can_succeed() {
    let budget = pool(2, 1);
    let (inner, entered, release) = parked(false);
    let provider = budget.bind_host_io(inner, &ExecutionWorkPool::new(1));
    let worker = std::thread::spawn(move || provider.perform(&read(), &[HostIoCapability::FsRead]));
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(
        budget.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::TimedOut { in_flight: 1 })
    );
    assert_eq!(budget.snapshot().unwrap().committed_operations, 1);
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    let drained = budget.revoke_and_drain(WAIT).unwrap();
    assert_eq!(drained.in_flight, 0);
    assert_eq!(drained.committed_operations, 1);
}

#[test]
fn one_frontier_drains_both_process_and_io_bindings() {
    let budget = pool(3, 2);
    let work = ExecutionWorkPool::new(1);
    let (io_inner, io_entered, io_release) = parked(false);
    let (process_inner, process_entered, process_release) = parked(false);
    let io = budget.bind_host_io(io_inner, &work);
    let process = budget.bind_process_spawn(process_inner, &work);
    let io_worker = std::thread::spawn(move || io.perform(&read(), &[HostIoCapability::FsRead]));
    let process_worker = std::thread::spawn(move || {
        process.perform(
            &ProcessSpawnRequest::Wait { handle: "test-handle".into(), timeout_millis: None },
            &[ProcessSpawnCapability::Spawn],
        )
    });
    io_entered.recv_timeout(WAIT).unwrap();
    process_entered.recv_timeout(WAIT).unwrap();
    assert_eq!(budget.snapshot().unwrap().in_flight, 2);
    let closer = budget.clone();
    let (done, result) = channel();
    let drain = std::thread::spawn(move || done.send(closer.revoke_and_drain(WAIT)).unwrap());
    wait_for_revocation(&budget);
    io_release.send(()).unwrap();
    assert!(io_worker.join().unwrap().is_err());
    assert_eq!(budget.snapshot().unwrap().in_flight, 1);
    assert!(result.try_recv().is_err());
    process_release.send(()).unwrap();
    assert!(process_worker.join().unwrap().is_err());
    let snapshot = result.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    drain.join().unwrap();
    assert_eq!(snapshot, HostEffectSnapshot {
        remaining_operations: 1, committed_operations: 2, in_flight: 0,
    });
}

#[test]
fn provider_unwind_wakes_drain_without_refunding_or_reactivating_work() {
    let budget = pool(2, 1);
    let (inner, entered, release) = parked(true);
    let provider = budget.bind_host_io(inner, &ExecutionWorkPool::new(1));
    let worker = std::thread::spawn(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            provider.perform(&read(), &[HostIoCapability::FsRead])
        }))
    });
    entered.recv_timeout(WAIT).unwrap();
    let closer = budget.clone();
    let (done, result) = channel();
    let drain = std::thread::spawn(move || done.send(closer.revoke_and_drain(WAIT)).unwrap());
    wait_for_revocation(&budget);
    release.send(()).unwrap();
    assert!(worker.join().unwrap().is_err());
    let snapshot = result.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    drain.join().unwrap();
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(snapshot.committed_operations, 1);
    assert!(matches!(budget.admit(), Err(HostEffectBudgetError::Revoked)));
}

#[test]
fn accounting_poison_never_certifies_idle_even_after_permit_release() {
    let budget = pool(1, 1);
    let permit = budget.admit().unwrap();
    let alias = budget.clone();
    assert!(std::panic::catch_unwind(move || {
        let _guard = alias.state.accounting.lock().unwrap();
        panic!("poison the accounting boundary");
    }).is_err());
    drop(permit);
    assert_eq!(
        budget.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::AccountingPoisoned)
    );
    assert!(budget.is_revoked());
}

#[test]
fn poisoned_accounting_reaches_an_already_admitted_io_control() {
    let budget = pool(2, 1);
    let (inner, entered, release) = parked(false);
    let provider = budget.bind_host_io(inner, &ExecutionWorkPool::new(1));
    let worker = std::thread::spawn(move || provider.perform(&read(), &[HostIoCapability::FsRead]));
    entered.recv_timeout(WAIT).unwrap();
    let alias = budget.clone();
    assert!(std::panic::catch_unwind(move || {
        let _guard = alias.state.accounting.lock().unwrap();
        panic!("poison while native work holds admission");
    }).is_err());
    release.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(HostIoError::Denied { .. })));
    assert_eq!(budget.revoke_and_drain(WAIT), Err(HostEffectDrainError::AccountingPoisoned));
}

#[test]
fn even_an_unrepresentable_wait_revokes_before_returning() {
    let budget = pool(1, 1);
    let result = budget.revoke_and_drain(Duration::MAX);
    // Instant's supported range is platform-dependent. No duration must wrap
    // into a past/fresh deadline, and either outcome must leave admission closed.
    if Instant::now().checked_add(Duration::MAX).is_none() {
        assert_eq!(result, Err(HostEffectDrainError::InvalidTimeout));
    } else {
        assert_eq!(result.unwrap().in_flight, 0);
    }
    assert!(budget.is_revoked());
    assert_eq!(budget.snapshot().unwrap().committed_operations, 0);
}

#[derive(Debug)]
struct ReentrantDrain(HostEffectWorkPool);

impl HostIoProvider for ReentrantDrain {
    fn name(&self) -> &str { "reentrant-drain-test" }
    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        // This would deadlock if a provider ran under the accounting lock.
        assert_eq!(self.0.revoke_and_drain(Duration::ZERO), Err(HostEffectDrainError::TimedOut { in_flight: 1 }));
        Ok(HostIoResponse::FsRead { bytes: vec![1] })
    }
}

#[test]
fn a_provider_cannot_drain_its_own_permit_or_run_under_the_accounting_lock() {
    let budget = pool(2, 1);
    let provider = budget.bind_host_io(Arc::new(ReentrantDrain(budget.clone())), &ExecutionWorkPool::new(1));
    assert!(provider.perform(&read(), &[HostIoCapability::FsRead]).is_err());
    assert_eq!(budget.revoke_and_drain(Duration::ZERO).unwrap().committed_operations, 1);
}

#[test]
fn fresh_bindings_and_scopes_cannot_resurrect_a_drained_pool() {
    let budget = pool(2, 1);
    let snapshot = budget.revoke_and_drain(Duration::ZERO).unwrap();
    let inner = Arc::new(CountingIo::default());
    let provider = budget.clone().bind_host_io(inner.clone(), &ExecutionWorkPool::new(100));
    assert!(provider.perform(&read(), &[HostIoCapability::FsRead]).is_err());
    assert_eq!(inner.0.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot().unwrap(), snapshot);
}

#[test]
fn racing_dispatch_cannot_cross_a_successfully_drained_frontier() {
    for _ in 0..16 {
        let budget = pool(16, 16);
        let inner = Arc::new(CountingIo::default());
        let provider = budget.bind_host_io(inner.clone(), &ExecutionWorkPool::new(1));
        let start = Arc::new(Barrier::new(17));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let provider = provider.clone();
            let start = start.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                provider.perform(&read(), &[HostIoCapability::FsRead])
            }));
        }
        start.wait();
        let snapshot = budget.revoke_and_drain(WAIT).unwrap();
        let completed_calls = inner.0.load(Ordering::SeqCst);
        for worker in workers { let _ = worker.join().unwrap(); }
        assert_eq!(inner.0.load(Ordering::SeqCst), completed_calls);
        assert_eq!(budget.snapshot().unwrap(), snapshot);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.committed_operations + snapshot.remaining_operations, 16);
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use frankenengine_extension_host::host_io::SandboxedHostIo;
    use std::net::TcpListener;
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!("franken-effect-drain-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn real_network_read_drains_while_the_peer_is_still_open() {
        let scratch = Scratch::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (accepted, connected) = channel();
        let (release, peer_release) = channel();
        let peer = std::thread::spawn(move || {
            let deadline = Instant::now() + WAIT;
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "native provider never connected");
                        std::thread::yield_now();
                    }
                    Err(error) => panic!("loopback accept: {error}"),
                }
            };
            accepted.send(()).unwrap();
            peer_release.recv_timeout(WAIT + WAIT).unwrap();
            drop(stream);
        });
        let budget = pool(1, 1);
        let native = SandboxedHostIo::with_root(&scratch.0).unwrap()
            .with_network_timeout(WAIT + WAIT).unwrap();
        let provider = budget.bind_host_io(Arc::new(native), &ExecutionWorkPool::new(1));
        let worker = std::thread::spawn(move || provider.perform(
            &HostIoRequest::NetworkRecv { endpoint: address.to_string(), max_len: 16 },
            &[HostIoCapability::NetworkRecv],
        ));
        connected.recv_timeout(WAIT).unwrap();
        // No data or EOF is supplied to unblock read. The real network provider
        // must observe the forwarded revocation and release its actual permit.
        let drained = budget.revoke_and_drain(WAIT);
        release.send(()).unwrap();
        peer.join().unwrap();
        assert!(worker.join().unwrap().is_err());
        let snapshot = drained.unwrap();
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.committed_operations, 1);
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[test]
    fn dispatch_drain_keeps_real_child_cleanup_available_without_claiming_child_exit() {
        use frankenengine_extension_host::process_spawn::{
            NativeProcessSpawn, ProcessLaunch, ProcessSpawnPolicy, ProcessStdio,
        };
        let scratch = Scratch::new();
        let mut policy = ProcessSpawnPolicy::jailed(&scratch.0).unwrap();
        let executable = policy.authorize_executable("/bin/cat").unwrap();
        policy.limits.max_runtime_millis = 2000;
        let native = Arc::new(NativeProcessSpawn::new(policy).unwrap());
        let budget = pool(1, 1);
        let provider = budget.bind_process_spawn(native, &ExecutionWorkPool::new(1));
        let launch = ProcessLaunch {
            executable, argv: Vec::new(), env: Default::default(), cwd: None,
            shell: false, stdio: ProcessStdio::default(),
        };
        let ProcessSpawnResponse::Spawned { handle } = provider.perform(
            &ProcessSpawnRequest::Spawn { launch }, &[ProcessSpawnCapability::Spawn],
        ).unwrap() else { panic!("real child handle"); };
        // Spawn's provider call ended, but the child resource is still owned.
        let snapshot = budget.revoke_and_drain(Duration::ZERO).unwrap();
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.committed_operations, 1);
        assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: true }));
        assert_eq!(provider.cleanup_handle(&handle), Ok(ProcessSpawnResponse::Cleaned { was_present: false }));
        assert_eq!(budget.snapshot().unwrap(), snapshot);
    }
}
