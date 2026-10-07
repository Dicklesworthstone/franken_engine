//! Boundary interleavings use controlled providers, not simulated OS evidence.

use super::*;
use crate::execution_work_budget::ExecutionWorkPool;
use crate::host_effect_budget::{HostEffectDrainError, HostEffectSnapshot};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};
use frankenengine_extension_host::process_spawn::{
    ProcessExit, ProcessLaunch, ProcessSpawnCapability, ProcessSpawnControl, ProcessSpawnOutcome,
    ProcessSpawnProvider, ProcessSpawnRequest, ProcessSpawnResponse, ProcessStdio,
};
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(5);
const PROCESS: &[ProcessSpawnCapability] = &[ProcessSpawnCapability::Spawn];
const IO: &[HostIoCapability] = &[HostIoCapability::FsRead];

fn limits(operations: u64, max_in_flight: usize) -> HostEffectLimits {
    HostEffectLimits {
        operations,
        max_in_flight,
    }
}

fn read() -> HostIoRequest {
    HostIoRequest::FsRead { path: "a".into() }
}

fn run() -> ProcessSpawnRequest {
    ProcessSpawnRequest::Run {
        launch: ProcessLaunch {
            executable: "controlled-test-provider".into(),
            argv: Vec::new(),
            env: Default::default(),
            cwd: None,
            shell: false,
            stdio: ProcessStdio::default(),
        },
        stdin: Vec::new(),
        timeout_millis: None,
    }
}

fn process_success() -> ProcessSpawnOutcome {
    Ok(ProcessSpawnResponse::Run {
        exit: ProcessExit {
            success: true,
            code: Some(0),
            signal: None,
        },
        stdout: vec![7],
        stderr: Vec::new(),
    })
}

#[derive(Debug, Default)]
struct Observed {
    io_calls: AtomicUsize,
    process_calls: AtomicUsize,
    cleanups: AtomicUsize,
    panic_on_process: AtomicBool,
    io_control: Mutex<Option<Arc<dyn HostIoControl>>>,
    process_control: Mutex<Option<Arc<dyn ProcessSpawnControl>>>,
}

impl HostIoProvider for Observed {
    fn name(&self) -> &str {
        "observed-hierarchy-io"
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
        control.checkpoint()?;
        self.io_calls.fetch_add(1, Ordering::SeqCst);
        *self.io_control.lock().unwrap() = Some(control);
        Ok(HostIoResponse::FsRead { bytes: vec![7] })
    }
}

impl ProcessSpawnProvider for Observed {
    fn name(&self) -> &str {
        "observed-hierarchy-process"
    }

    fn perform(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        panic!("live process control must be forwarded")
    }

    fn perform_controlled(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        control.checkpoint()?;
        self.process_calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.panic_on_process.load(Ordering::SeqCst),
            "native unwind"
        );
        *self.process_control.lock().unwrap() = Some(control);
        process_success()
    }

    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        self.cleanups.fetch_add(1, Ordering::SeqCst);
        Ok(ProcessSpawnResponse::Cleaned { was_present: true })
    }
}

#[test]
fn tenants_spend_prepaid_credits_across_io_and_process_without_double_charging() {
    let root = HostEffectWorkPool::new(limits(4, 2));
    let first = root.partition(limits(2, 1)).unwrap();
    let second = root.partition(limits(2, 1)).unwrap();
    let work = ExecutionWorkPool::new(1);
    let inner = Arc::new(Observed::default());
    assert_eq!(root.snapshot().unwrap().remaining_operations, 0);
    for tenant in [&first, &second] {
        tenant
            .bind_host_io(inner.clone(), &work)
            .perform(&read(), IO)
            .unwrap();
        tenant
            .bind_process_spawn(inner.clone(), &work)
            .perform(&run(), PROCESS)
            .unwrap();
        assert!(matches!(
            tenant.admit(),
            Err(HostEffectBudgetError::Exhausted)
        ));
    }
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 2);
    assert_eq!(inner.process_calls.load(Ordering::SeqCst), 2);
    assert_eq!(root.snapshot().unwrap().committed_operations, 4);
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn exhausted_tenant_cannot_consume_a_siblings_reservation() {
    let root = HostEffectWorkPool::new(limits(3, 1));
    let first = root.partition(limits(1, 1)).unwrap();
    let second = root.partition(limits(2, 1)).unwrap();
    drop(first.admit().unwrap());
    for _ in 0..4 {
        assert!(matches!(
            first.clone().admit(),
            Err(HostEffectBudgetError::Exhausted)
        ));
    }
    assert_eq!(second.snapshot().unwrap().remaining_operations, 2);
    drop(second.admit().unwrap());
    drop(second.admit().unwrap());
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn nested_delegation_and_owner_drop_never_refund_credits() {
    let root = HostEffectWorkPool::new(limits(8, 2));
    let tenant = root.partition(limits(6, 2)).unwrap();
    let cell = tenant.partition(limits(4, 1)).unwrap();
    drop(cell.admit().unwrap());
    assert_eq!(root.snapshot().unwrap().remaining_operations, 2);
    assert_eq!(tenant.snapshot().unwrap().remaining_operations, 2);
    assert_eq!(cell.snapshot().unwrap().remaining_operations, 3);
    drop(cell);
    drop(tenant);
    assert_eq!(root.snapshot().unwrap().remaining_operations, 2);
}

#[test]
fn failed_delegations_do_not_change_parent_accounting() {
    let root = HostEffectWorkPool::new(limits(3, 2));
    let before = root.snapshot().unwrap();
    assert!(matches!(
        root.partition(limits(4, 1)),
        Err(HostEffectBudgetError::Exhausted)
    ));
    assert!(matches!(
        root.partition(limits(1, 3)),
        Err(HostEffectBudgetError::ConcurrencyLimitBroadened)
    ));
    assert_eq!(root.snapshot().unwrap(), before);
    root.revoke();
    assert!(matches!(
        root.partition(limits(0, 0)),
        Err(HostEffectBudgetError::Revoked)
    ));
    assert_eq!(root.snapshot().unwrap(), before);
}

#[test]
fn empty_and_zero_concurrency_children_cannot_dispatch_or_leak_ancestor_permits() {
    let root = HostEffectWorkPool::new(limits(2, 2));
    let empty = root.partition(limits(0, 1)).unwrap();
    let closed = root.partition(limits(1, 0)).unwrap();
    assert!(matches!(
        empty.admit(),
        Err(HostEffectBudgetError::Exhausted)
    ));
    assert!(matches!(
        closed.admit(),
        Err(HostEffectBudgetError::ConcurrencyLimit)
    ));
    for scope in [&root, &empty, &closed] {
        assert_eq!(scope.snapshot().unwrap().in_flight, 0);
    }
    assert_eq!(closed.snapshot().unwrap().remaining_operations, 1);
    drop(root.admit().unwrap());
}

#[test]
fn an_intermediate_cap_rolls_back_provisional_root_admission() {
    let root = HostEffectWorkPool::new(limits(4, 3));
    let tenant = root.partition(limits(4, 1)).unwrap();
    let first = tenant.partition(limits(2, 1)).unwrap();
    let second = tenant.partition(limits(2, 1)).unwrap();
    let permit = first.admit().unwrap();
    let before = second.snapshot().unwrap();
    assert!(matches!(
        second.admit(),
        Err(HostEffectBudgetError::ConcurrencyLimit)
    ));
    assert_eq!(second.snapshot().unwrap(), before);
    assert_eq!(root.snapshot().unwrap().in_flight, 1);
    drop(permit);
    drop(second.admit().unwrap());
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
    assert_eq!(tenant.snapshot().unwrap().in_flight, 0);
}

#[test]
fn dropping_ancestor_owners_does_not_detach_caps_or_revocation() {
    let root = HostEffectWorkPool::new(limits(2, 1));
    let tenant = root.partition(limits(2, 1)).unwrap();
    let cell = tenant.partition(limits(2, 1)).unwrap();
    drop(tenant);
    let first = cell.admit().unwrap();
    assert!(matches!(
        cell.admit(),
        Err(HostEffectBudgetError::ConcurrencyLimit)
    ));
    root.revoke();
    drop(root);
    assert!(cell.is_revoked());
    drop(first);
    assert!(matches!(cell.admit(), Err(HostEffectBudgetError::Revoked)));
}

#[test]
fn explicit_child_revocation_preserves_parent_and_sibling_authority() {
    let root = HostEffectWorkPool::new(limits(4, 2));
    let tenant = root.partition(limits(2, 1)).unwrap();
    let cell = tenant.partition(limits(1, 1)).unwrap();
    let sibling = root.partition(limits(1, 1)).unwrap();
    tenant.revoke();
    assert!(tenant.is_revoked() && cell.is_revoked());
    assert!(!root.is_revoked() && !sibling.is_revoked());
    drop(sibling.admit().unwrap());
    drop(root.admit().unwrap());
    assert!(matches!(cell.admit(), Err(HostEffectBudgetError::Revoked)));
}

#[test]
fn root_drain_counts_descendants_and_child_drain_ignores_siblings() {
    let root = HostEffectWorkPool::new(limits(2, 2));
    let child = root.partition(limits(1, 1)).unwrap();
    let sibling = root.partition(limits(1, 1)).unwrap();
    let child_permit = child.admit().unwrap();
    let sibling_permit = sibling.admit().unwrap();
    assert_eq!(
        child.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::TimedOut { in_flight: 1 })
    );
    drop(child_permit);
    assert_eq!(child.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
    assert!(!root.is_revoked() && !sibling.is_revoked());
    assert_eq!(
        root.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::TimedOut { in_flight: 1 })
    );
    drop(sibling_permit);
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
}

#[test]
fn final_descendant_release_wakes_both_child_and_root_closers() {
    let root = HostEffectWorkPool::new(limits(1, 1));
    let child = root.partition(limits(1, 1)).unwrap();
    let permit = child.admit().unwrap();
    let (done, results) = channel();
    let mut closers = Vec::new();
    for scope in [root.clone(), child.clone()] {
        let done = done.clone();
        closers.push(std::thread::spawn(move || {
            done.send(scope.revoke_and_drain(WAIT)).unwrap()
        }));
    }
    let deadline = Instant::now() + WAIT;
    while !root.state.revoked.load(Ordering::Acquire)
        || !child.state.revoked.load(Ordering::Acquire)
    {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(results.try_recv().is_err());
    drop(permit);
    for _ in 0..2 {
        assert_eq!(
            results
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap()
                .in_flight,
            0
        );
    }
    for closer in closers {
        closer.join().unwrap();
    }
}

#[test]
fn concurrent_partitions_cannot_mint_more_than_the_root_allowance() {
    let root = HostEffectWorkPool::new(limits(16, 1));
    let start = Arc::new(Barrier::new(33));
    let mut workers = Vec::new();
    for _ in 0..32 {
        let root = root.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            root.partition(limits(1, 1))
        }));
    }
    start.wait();
    let children: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap().ok())
        .collect();
    assert_eq!(children.len(), 16);
    assert_eq!(root.snapshot().unwrap().remaining_operations, 0);
    for child in children {
        drop(child.admit().unwrap());
    }
    assert_eq!(root.snapshot().unwrap().in_flight, 0);
}

#[test]
fn maximum_credit_balance_survives_nested_partition_and_spend() {
    let root = HostEffectWorkPool::new(limits(u64::MAX, 1));
    let child = root.partition(limits(u64::MAX, 1)).unwrap();
    let leaf = child.partition(limits(u64::MAX, 1)).unwrap();
    drop(leaf.admit().unwrap());
    assert_eq!(root.snapshot().unwrap().committed_operations, u64::MAX);
    assert_eq!(child.snapshot().unwrap().committed_operations, u64::MAX);
    assert_eq!(leaf.snapshot().unwrap().remaining_operations, u64::MAX - 1);
}

#[test]
fn depth_and_debug_output_are_bounded_even_for_empty_partitions() {
    let mut scope = HostEffectWorkPool::new(limits(0, 1));
    for _ in 0..MAX_HOST_EFFECT_POOL_DEPTH {
        scope = scope.partition(limits(0, 1)).unwrap();
    }
    assert!(format!("{scope:?}").len() < 512);
    assert!(matches!(
        scope.partition(limits(0, 1)),
        Err(HostEffectBudgetError::HierarchyDepthExceeded)
    ));
}

#[test]
fn ancestor_poison_reaches_retained_io_and_process_controls_and_denies_drain() {
    let root = HostEffectWorkPool::new(limits(3, 1));
    let child = root.partition(limits(3, 1)).unwrap();
    let work = ExecutionWorkPool::new(1);
    let inner = Arc::new(Observed::default());
    child
        .bind_host_io(inner.clone(), &work)
        .perform(&read(), IO)
        .unwrap();
    child
        .bind_process_spawn(inner.clone(), &work)
        .perform(&run(), PROCESS)
        .unwrap();
    let alias = root.clone();
    assert!(
        std::panic::catch_unwind(move || {
            let _guard = alias.state.accounting.lock().unwrap();
            panic!("ancestor accounting poison");
        })
        .is_err()
    );
    assert!(
        inner
            .io_control
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .checkpoint()
            .is_err()
    );
    assert!(
        inner
            .process_control
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .checkpoint()
            .is_err()
    );
    assert!(matches!(
        child.admit(),
        Err(HostEffectBudgetError::AccountingPoisoned)
    ));
    assert!(matches!(
        child.partition(limits(1, 1)),
        Err(HostEffectBudgetError::AccountingPoisoned)
    ));
    assert_eq!(
        child.revoke_and_drain(Duration::ZERO),
        Err(HostEffectDrainError::AccountingPoisoned)
    );
    assert_eq!(child.snapshot().unwrap().remaining_operations, 1);
}

#[test]
fn provider_unwind_quarantines_the_family_but_preserves_cleanup() {
    let root = HostEffectWorkPool::new(limits(3, 2));
    let first = root.partition(limits(2, 1)).unwrap();
    let sibling = root.partition(limits(1, 1)).unwrap();
    let inner = Arc::new(Observed::default());
    inner.panic_on_process.store(true, Ordering::SeqCst);
    let work = ExecutionWorkPool::new(1);
    let process = first.bind_process_spawn(inner.clone(), &work);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || process.perform(&run(), PROCESS)
        ))
        .is_err()
    );
    assert!(root.is_revoked() && sibling.is_revoked());
    assert_eq!(first.snapshot().unwrap().remaining_operations, 1);
    assert_eq!(root.revoke_and_drain(Duration::ZERO).unwrap().in_flight, 0);
    assert!(
        sibling
            .bind_host_io(inner.clone(), &work)
            .perform(&read(), IO)
            .is_err()
    );
    process.cleanup_handle("engine-owned-handle").unwrap();
    assert_eq!(inner.cleanups.load(Ordering::SeqCst), 1);
}

#[derive(Debug)]
struct PausedProcess {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}

impl ProcessSpawnProvider for PausedProcess {
    fn name(&self) -> &str {
        "paused-hierarchy-process"
    }

    fn perform(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
    ) -> ProcessSpawnOutcome {
        panic!("controlled dispatch required")
    }

    fn perform_controlled(
        &self,
        _: &ProcessSpawnRequest,
        _: &[ProcessSpawnCapability],
        control: Arc<dyn ProcessSpawnControl>,
    ) -> ProcessSpawnOutcome {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        control.checkpoint()?;
        process_success()
    }

    fn cleanup_handle(&self, _: &str) -> ProcessSpawnOutcome {
        Ok(ProcessSpawnResponse::Cleaned { was_present: false })
    }
}

#[test]
fn a_process_in_one_tenant_blocks_io_in_another_at_the_ancestor_limit() {
    let root = HostEffectWorkPool::new(limits(2, 1));
    let first = root.partition(limits(1, 1)).unwrap();
    let second = root.partition(limits(1, 1)).unwrap();
    let work = ExecutionWorkPool::new(1);
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let process = first.bind_process_spawn(
        Arc::new(PausedProcess {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
        &work,
    );
    let worker = std::thread::spawn(move || process.perform(&run(), PROCESS));
    entered.recv_timeout(WAIT).unwrap();
    let inner = Arc::new(Observed::default());
    let io = second.bind_host_io(inner.clone(), &work);
    let refused = io.perform(&read(), IO);
    let before_release = root.snapshot().unwrap();
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(refused.is_err());
    assert_eq!(inner.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(before_release.in_flight, 1);
    assert_eq!(second.snapshot().unwrap().remaining_operations, 1);
    io.perform(&read(), IO).unwrap();
    assert_eq!(
        root.snapshot().unwrap(),
        HostEffectSnapshot {
            remaining_operations: 0,
            committed_operations: 2,
            in_flight: 0,
        }
    );
}
