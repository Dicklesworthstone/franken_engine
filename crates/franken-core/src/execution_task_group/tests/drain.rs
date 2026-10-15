//! Exercise actual task ownership and production effect accounting. Inner
//! provider callbacks are controlled probes, not operating-system isolation.

use super::*;
use crate::host_effect_budget::{HostEffectDrainError, HostEffectLimits, HostEffectSnapshot};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider, HostIoRequest,
    HostIoResponse,
};

fn effects(operations: u64) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits { operations, max_in_flight: 2 })
}

fn read() -> HostIoRequest {
    HostIoRequest::FsRead { path: "drain-probe".into() }
}

struct HoldingProvider {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
    control: Mutex<Option<Arc<dyn HostIoControl>>>,
}

impl fmt::Debug for HoldingProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HoldingProvider").finish_non_exhaustive()
    }
}

impl HostIoProvider for HoldingProvider {
    fn name(&self) -> &str { "group-drain-probe" }

    fn perform(&self, _: &HostIoRequest, _: &[HostIoCapability]) -> HostIoOutcome {
        panic!("live operation control must be forwarded")
    }

    fn perform_controlled(
        &self, _: &HostIoRequest, _: &[HostIoCapability], control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        control.checkpoint()?;
        *self.control.lock().unwrap() = Some(control.clone());
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        control.checkpoint()?;
        Ok(HostIoResponse::FsRead { bytes: vec![7] })
    }
}

fn hold_effect(
    effects: &HostEffectWorkPool,
    work: &ExecutionWorkPool,
) -> (Arc<HoldingProvider>, Sender<()>, thread::JoinHandle<HostIoOutcome>) {
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let inner = Arc::new(HoldingProvider {
        entered: entered_tx,
        release: Mutex::new(release_rx),
        control: Mutex::new(None),
    });
    let provider = effects.bind_host_io(inner.clone(), work);
    let worker = thread::spawn(move || provider.perform(&read(), &[HostIoCapability::FsRead]));
    entered.recv_timeout(WAIT).unwrap();
    (inner, release, worker)
}

fn denied(outcome: HostIoOutcome) {
    assert!(matches!(outcome, Err(HostIoError::Denied { reason })
        if reason == "HOST_EFFECT_SCOPE_REVOKED"));
}

#[test]
fn native_only_group_cannot_certify_an_unconfigured_provider_frontier() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&parent, 128, 1).unwrap();
    assert_eq!(
        group.close_and_drain(Duration::ZERO),
        Err(ExecutionGroupDrainError::HostEffectsUnconfigured)
    );
    assert!(group.is_closed());
    assert!(!parent.is_revoked());
    assert_eq!(group.remaining_instructions(), 128);
    group.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn idle_group_drains_the_real_scope_without_creating_or_refunding_credits() {
    let parent = ExecutionWorkPool::new(256);
    let effects = effects(7);
    let mut group = ExecutionTaskGroup::new_with_host_effects(
        &parent, 128, 1, effects.clone(),
    ).unwrap();
    let snapshot = group.close_and_drain(Duration::ZERO).unwrap();
    assert_eq!(snapshot, HostEffectSnapshot {
        remaining_operations: 7, committed_operations: 0, in_flight: 0,
    });
    assert_eq!(group.close_and_drain(Duration::ZERO).unwrap(), snapshot);
    assert!(effects.is_revoked());
    assert_eq!(parent.remaining(), 128);
    assert_eq!(group.remaining_instructions(), 128);
    assert!(!parent.is_revoked());
}

#[test]
fn joined_native_worker_does_not_hide_an_independent_live_provider_call() {
    let parent = ExecutionWorkPool::new(512);
    let effects = effects(4);
    let mut group = ExecutionTaskGroup::new_with_host_effects(
        &parent, 256, 1, effects.clone(),
    ).unwrap();
    let id = group.spawn(module("42;"), config(128), "native-first").unwrap();
    wait_for_all(&mut group);
    let (inner, release, worker) = hold_effect(&effects, &parent);
    // The old native-only join is explicitly NOT the combined drain.
    group.close_and_join(Duration::ZERO).unwrap();
    let result = group.close_and_drain(Duration::ZERO);
    let snapshot = effects.snapshot().unwrap();
    let control_denied = inner.control.lock().unwrap().as_ref().unwrap().checkpoint().is_err();
    release.send(()).unwrap();
    denied(worker.join().unwrap());
    assert_eq!(result, Err(ExecutionGroupDrainError::Effects(
        HostEffectDrainError::TimedOut { in_flight: 1 }
    )));
    assert_eq!(snapshot.in_flight, 1);
    assert_eq!(snapshot.committed_operations, 1);
    assert!(control_denied);
    assert_eq!(group.retained(), 1, "timeout must retain the native outcome");
    assert_eq!(group.close_and_drain(WAIT).unwrap().in_flight, 0);
    group.take_result(id).unwrap().unwrap().unwrap();
    assert_eq!(group.remaining_instructions(), 128);
}

#[test]
fn native_timeout_revokes_providers_before_wait_and_keeps_both_frontiers() {
    let parent = ExecutionWorkPool::new(2048);
    let effects = effects(3);
    let mut group = ExecutionTaskGroup::new_with_host_effects(
        &parent, 1024, 1, effects.clone(),
    ).unwrap();
    let (hook, entered, native_release) = parked(false);
    let id = group.spawn_with_hook(
        module("let x = {}; while (true) {}"), config(512), "native-park", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let (inner, effect_release, worker) = hold_effect(&effects, &parent);
    let first = group.close_and_drain(Duration::ZERO);
    assert!(group.task_control(id).unwrap().is_cancelled());
    assert!(inner.control.lock().unwrap().as_ref().unwrap().checkpoint().is_err());
    assert_eq!(group.pending(), 1);
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    native_release.send(()).unwrap();
    group.close_and_join(WAIT).unwrap();
    let second = group.close_and_drain(Duration::ZERO);
    effect_release.send(()).unwrap();
    denied(worker.join().unwrap());
    assert_eq!(first, Err(ExecutionGroupDrainError::Tasks(ExecutionTaskJoinError::TimedOut)));
    assert_eq!(second, Err(ExecutionGroupDrainError::Effects(
        HostEffectDrainError::TimedOut { in_flight: 1 }
    )));
    let final_snapshot = group.close_and_drain(WAIT).unwrap();
    assert_eq!(final_snapshot.in_flight, 0);
    assert_eq!(final_snapshot.committed_operations, 1);
    cancelled(group.take_result(id).unwrap());
    assert_eq!(group.remaining_instructions(), 512);
}

#[test]
fn dedicated_effect_partitions_keep_sibling_groups_and_parent_authority_live() {
    let parent = ExecutionWorkPool::new(512);
    let root_effects = effects(10);
    let child = root_effects.partition(HostEffectLimits { operations: 4, max_in_flight: 1 }).unwrap();
    let peer = root_effects.partition(HostEffectLimits { operations: 4, max_in_flight: 1 }).unwrap();
    let mut first = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 1, child.clone()).unwrap();
    let mut sibling = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 1, peer.clone()).unwrap();
    let control = first.control();
    control.cancel();
    assert!(child.is_revoked());
    assert!(!peer.is_revoked());
    assert!(!root_effects.is_revoked());
    assert!(!parent.is_revoked());
    assert!(!sibling.is_closed());
    let id = sibling.spawn(module("7;"), config(128), "sibling").unwrap();
    collect(&mut sibling, id).unwrap().unwrap();
    assert_eq!(first.close_and_drain(Duration::ZERO).unwrap().committed_operations, 0);
    sibling.close_and_drain(WAIT).unwrap();
    assert_eq!(root_effects.snapshot().unwrap().remaining_operations, 2);
}

#[test]
fn group_effect_frontier_includes_its_descendants() {
    let parent = ExecutionWorkPool::new(128);
    let effects = effects(4);
    let descendant = effects.partition(HostEffectLimits { operations: 2, max_in_flight: 1 }).unwrap();
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 0, effects.clone()).unwrap();
    let (_, release, worker) = hold_effect(&descendant, &parent);
    let result = group.close_and_drain(Duration::ZERO);
    assert!(descendant.is_revoked());
    release.send(()).unwrap();
    denied(worker.join().unwrap());
    assert_eq!(result, Err(ExecutionGroupDrainError::Effects(
        HostEffectDrainError::TimedOut { in_flight: 1 }
    )));
    let snapshot = group.close_and_drain(WAIT).unwrap();
    assert_eq!(snapshot.committed_operations, 2, "delegation is not recharged on dispatch");
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(descendant.snapshot().unwrap().committed_operations, 1);
}

#[test]
fn externally_revoked_effect_scope_refuses_dispatch_before_setup_or_instruction_debit() {
    let parent = ExecutionWorkPool::new(256);
    let effects = effects(1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 1, effects.clone()).unwrap();
    let control = group.control();
    effects.revoke();
    assert!(control.is_cancelled());
    assert!(matches!(
        group.spawn_with_preparation(module("7;"), config(64), "revoked", |_, _| panic!("no setup")),
        Err(ExecutionGroupStartError::Closed)
    ));
    assert_eq!(group.remaining_instructions(), 128);
    group.close_and_drain(Duration::ZERO).unwrap();
}

#[test]
fn effect_revocation_during_preparation_closes_the_actual_native_admission() {
    let parent = ExecutionWorkPool::new(256);
    let effects = effects(1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 1, effects.clone()).unwrap();
    let mut escaped = None;
    let result = group.spawn_with_preparation(module("7;"), config(64), "setup-revoke", |job, _| {
        escaped = Some(job.task_control());
        effects.revoke();
        Ok(None)
    });
    assert!(matches!(result, Err(ExecutionGroupStartError::Worker(
        ExecutionTaskStartError::Admission(WorkBudgetError::Revoked)
    ))));
    assert!(escaped.unwrap().is_cancelled());
    assert_eq!(group.retained(), 0);
    assert_eq!(group.remaining_instructions(), 64);
    assert!(!parent.is_revoked());
    group.close_and_drain(Duration::ZERO).unwrap();
}

#[test]
fn construction_failure_does_not_revoke_the_supplied_effect_scope() {
    let parent = ExecutionWorkPool::new(63);
    let effects = effects(3);
    assert!(matches!(
        ExecutionTaskGroup::new_with_host_effects(&parent, 64, 1, effects.clone()),
        Err(WorkBudgetError::Exhausted { .. })
    ));
    assert!(!effects.is_revoked());
    assert_eq!(effects.snapshot().unwrap().remaining_operations, 3);
    assert_eq!(parent.remaining(), 63);
}

#[test]
fn dropping_group_revokes_effect_aliases_without_certifying_or_refunding_drain() {
    let parent = ExecutionWorkPool::new(256);
    let effects = effects(3);
    let group = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 0, effects.clone()).unwrap();
    let control = group.control();
    let (_, release, worker) = hold_effect(&effects, &parent);
    drop(group);
    assert!(control.is_cancelled());
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    assert_eq!(effects.snapshot().unwrap().remaining_operations, 2);
    release.send(()).unwrap();
    denied(worker.join().unwrap());
    assert_eq!(effects.revoke_and_drain(WAIT).unwrap().in_flight, 0);
    assert!(!parent.is_revoked());
}

#[test]
fn successful_combined_drain_preserves_native_failure_outcomes() {
    let parent = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 256, 1, effects(1)).unwrap();
    let id = group.spawn(module("throw 7;"), config(128), "guest-failure").unwrap();
    wait_for_all(&mut group);
    group.close_and_drain(Duration::ZERO).unwrap();
    assert!(matches!(group.take_result(id).unwrap(), Ok(Err(WorkBudgetError::Interpreter(
        InterpreterError::UncaughtException { .. }
    )))));
    assert_eq!(group.remaining_instructions(), 128);
}

#[test]
fn combined_drain_error_sources_preserve_the_failure_domain() {
    let tasks = ExecutionGroupDrainError::Tasks(ExecutionTaskJoinError::TimedOut);
    let effects = ExecutionGroupDrainError::Effects(HostEffectDrainError::AccountingPoisoned);
    assert!(std::error::Error::source(&tasks).unwrap().is::<ExecutionTaskJoinError>());
    assert!(std::error::Error::source(&effects).unwrap().is::<HostEffectDrainError>());
    assert!(std::error::Error::source(&ExecutionGroupDrainError::HostEffectsUnconfigured).is_none());
}
