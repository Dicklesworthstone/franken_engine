use super::*;
use frankenengine_core::execution_task_group::{
    ExecutionBatchDrainError, ExecutionBatchError, ExecutionGroupDrainError,
};
use frankenengine_core::host_effect_budget::{
    HostEffectDrainError, HostEffectLimits, HostEffectWorkPool,
};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoOutcome, HostIoProvider, HostIoRequest, HostIoResponse,
};

fn observe_one(group: &mut ExecutionTaskGroup) {
    let deadline = Instant::now() + WAIT;
    while group.first_failure().is_none() {
        group.poll();
        assert!(Instant::now() < deadline, "failure was not observed");
        thread::yield_now();
    }
}

#[test]
fn later_failure_cancels_every_sibling_but_retains_the_unfinished_owner() {
    let pool = ExecutionWorkPool::new(1024);
    let mut sibling = ExecutionTaskGroup::new(&pool, 128, 1).unwrap();
    let mut group = ExecutionTaskGroup::new(&pool, 512, 3).unwrap();
    let (hook, entered, mut release) = parked(false);
    let slow = group
        .spawn_with_hook(
            module("let o = {}; while (true) {}"),
            config(),
            "slow",
            Some(hook),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let slow_control = group.task_control(slow).unwrap();
    let failed = group
        .spawn(module("while (true) {}"), config(), "failure")
        .unwrap();
    observe_one(&mut group);
    assert_eq!(group.first_failure(), Some(failed));
    assert!(
        !slow_control.is_cancelled(),
        "ordinary poll must not enable fail-fast"
    );
    let error = group.finish_and_join_fail_fast(Duration::ZERO).unwrap_err();
    assert_eq!(
        error,
        ExecutionBatchError::TaskFailed {
            task: failed,
            join_error: Some(ExecutionTaskJoinError::TimedOut)
        }
    );
    assert!(slow_control.is_cancelled());
    assert!(group.is_closed());
    assert_eq!(group.retained(), 2);
    assert_eq!(group.pending(), 1);
    assert!(group.take_result(failed).unwrap().unwrap().is_err());
    assert_eq!(group.first_failure(), Some(failed));
    assert_eq!(group.remaining_instructions(), 256);
    assert!(!pool.is_revoked());
    sibling
        .spawn(module("42;"), config(), "unaffected")
        .unwrap();
    sibling.finish_and_join_fail_fast(WAIT).unwrap();
    release.open();
    assert_eq!(
        group.finish_and_join_fail_fast(WAIT),
        Err(ExecutionBatchError::TaskFailed {
            task: failed,
            join_error: None
        })
    );
    assert_eq!(group.pending(), 0);
    assert!(group.take_result(slow).unwrap().unwrap().is_err());
    assert_eq!(
        group.finish_and_join_fail_fast(Duration::ZERO),
        Err(ExecutionBatchError::TaskFailed {
            task: failed,
            join_error: None
        })
    );
    assert_eq!(pool.remaining(), 384);
}

#[test]
fn collected_failure_cannot_be_reclassified_as_a_healthy_batch() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 2).unwrap();
    let failed = group
        .spawn(module("while (true) {}"), config(), "failure")
        .unwrap();
    let (id, outcome) = group.join_next(WAIT).unwrap().unwrap();
    assert_eq!(id, failed);
    assert!(outcome.unwrap().is_err());
    assert_eq!(group.retained(), 0);
    assert!(!group.is_cancelled());
    group.spawn(module("42;"), config(), "later").unwrap();
    assert_eq!(
        group.finish_and_join_fail_fast(WAIT),
        Err(ExecutionBatchError::TaskFailed {
            task: failed,
            join_error: None
        })
    );
    assert_eq!(group.first_failure(), Some(failed));
}

#[test]
fn observed_panic_stays_first_after_a_later_execution_failure() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 2).unwrap();
    let (hook, entered, mut release) = parked(true);
    let panic_id = group
        .spawn_with_hook(module("let o = {}; o;"), config(), "panic", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    release.open();
    wait_joined(&mut group);
    let failed = group
        .spawn(module("while (true) {}"), config(), "second")
        .unwrap();
    wait_joined(&mut group);
    assert_eq!(group.first_failure(), Some(panic_id));
    assert_eq!(
        group.finish_and_join_fail_fast(Duration::ZERO),
        Err(ExecutionBatchError::TaskFailed {
            task: panic_id,
            join_error: None
        })
    );
    assert!(matches!(
        group.take_result(panic_id),
        Some(Err(ExecutionTaskJoinError::Panicked))
    ));
    assert!(group.take_result(failed).unwrap().unwrap().is_err());
}

#[test]
fn healthy_timeout_seals_without_cancelling_and_retry_finishes() {
    let pool = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_hook(module("let o = {}; 42;"), config(), "healthy", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(
        group.finish_and_join_fail_fast(Duration::ZERO),
        Err(ExecutionBatchError::Wait(ExecutionTaskJoinError::TimedOut))
    );
    assert!(group.is_closed());
    assert!(!group.is_cancelled());
    assert_eq!(group.first_failure(), None);
    assert!(matches!(
        group.spawn(module("42;"), config(), "sealed"),
        Err(ExecutionGroupStartError::Closed)
    ));
    release.open();
    group.finish_and_join_fail_fast(WAIT).unwrap();
    assert_eq!(
        group.take_result(id).unwrap().unwrap().unwrap().value,
        Value::Int(42)
    );
    assert!(!group.is_cancelled());
}

#[test]
fn invalid_supervision_and_unconfigured_effects_do_not_cancel_live_work() {
    let pool = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_hook(module("let o = {}; 42;"), config(), "preflight", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(
        group.finish_and_join_fail_fast(Duration::MAX),
        Err(ExecutionBatchError::Wait(
            ExecutionTaskJoinError::InvalidTimeout
        ))
    );
    assert_eq!(
        group.finish_and_drain_fail_fast(Duration::MAX),
        Err(ExecutionBatchDrainError::Drain(
            ExecutionGroupDrainError::InvalidTimeout
        ))
    );
    assert_eq!(
        group.finish_and_drain_fail_fast(Duration::ZERO),
        Err(ExecutionBatchDrainError::Drain(
            ExecutionGroupDrainError::HostEffectsUnconfigured
        ))
    );
    assert!(!group.task_control(id).unwrap().is_cancelled());
    assert_eq!(group.pending(), 1);
    release.open();
    group.finish_and_join_fail_fast(WAIT).unwrap();
}

#[derive(Debug)]
struct BlockingIo {
    entered: Sender<()>,
    release: Mutex<Receiver<()>>,
}
impl HostIoProvider for BlockingIo {
    fn name(&self) -> &str {
        "supervision-test-blocked-provider"
    }
    fn perform(&self, _: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        assert!(granted.contains(&HostIoCapability::FsRead));
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv_timeout(WAIT).unwrap();
        Ok(HostIoResponse::FsRead { bytes: vec![42] })
    }
}

#[test]
fn failed_batch_preserves_provider_timeout_and_retries_after_real_dispatch_exits() {
    let pool = ExecutionWorkPool::new(512);
    let parent_effects = HostEffectWorkPool::new(HostEffectLimits {
        operations: 8,
        max_in_flight: 2,
    });
    let effects = parent_effects
        .partition(HostEffectLimits {
            operations: 4,
            max_in_flight: 1,
        })
        .unwrap();
    let mut group =
        ExecutionTaskGroup::new_with_host_effects(&pool, 256, 1, effects.clone()).unwrap();
    let (entered_tx, entered) = channel();
    let (release_tx, release_rx) = channel();
    let mut release = Release(Some(release_tx));
    let provider = Arc::new(BlockingIo {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let mut provider_thread = None;
    let id = group
        .spawn_with_effect_preparation(
            module("while (true) {}"),
            config(),
            "failure",
            |bindings, _| {
                let bound = bindings.bind_host_io(provider);
                provider_thread = Some(thread::spawn(move || {
                    bound.perform(
                        &HostIoRequest::FsRead {
                            path: "bounded".into(),
                        },
                        &[HostIoCapability::FsRead],
                    )
                }));
                entered.recv_timeout(WAIT).unwrap();
                Ok(None)
            },
        )
        .unwrap();
    observe_one(&mut group);
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    assert_eq!(
        group.finish_and_drain_fail_fast(Duration::ZERO),
        Err(ExecutionBatchDrainError::TaskFailed {
            task: id,
            drain_error: Some(ExecutionGroupDrainError::Effects(
                HostEffectDrainError::TimedOut { in_flight: 1 }
            )),
        })
    );
    assert!(group.is_cancelled());
    assert!(effects.is_revoked());
    assert!(!parent_effects.is_revoked());
    assert_eq!(group.pending(), 0);
    assert!(group.take_result(id).unwrap().unwrap().is_err());
    release.open();
    // The real provider finished, but admission-local revocation correctly
    // rejects publishing its late success. Draining still waits for its exit.
    assert!(matches!(
        provider_thread.unwrap().join().unwrap(),
        Err(frankenengine_extension_host::host_io::HostIoError::Denied { reason })
            if reason == "HOST_EFFECT_SCOPE_REVOKED"
    ));
    assert_eq!(
        group.finish_and_drain_fail_fast(WAIT),
        Err(ExecutionBatchDrainError::TaskFailed {
            task: id,
            drain_error: None
        })
    );
    assert_eq!(effects.snapshot().unwrap().in_flight, 0);
    assert_eq!(effects.snapshot().unwrap().remaining_operations, 3);
    assert_eq!(parent_effects.snapshot().unwrap().remaining_operations, 4);
    assert!(!pool.is_revoked());
}

#[test]
fn healthy_drain_keeps_authority_until_worker_join_and_closes_both_scopes_afterwards() {
    let pool = ExecutionWorkPool::new(256);
    let effects = HostEffectWorkPool::new(HostEffectLimits {
        operations: 4,
        max_in_flight: 1,
    });
    let mut group =
        ExecutionTaskGroup::new_with_host_effects(&pool, 256, 1, effects.clone()).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_hook(module("let o = {}; 42;"), config(), "healthy", Some(hook))
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    assert_eq!(
        group.finish_and_drain_fail_fast(Duration::ZERO),
        Err(ExecutionBatchDrainError::Drain(
            ExecutionGroupDrainError::Tasks(ExecutionTaskJoinError::TimedOut)
        ))
    );
    assert!(!effects.is_revoked());
    assert!(!group.is_cancelled());
    release.open();
    let snapshot = group.finish_and_drain_fail_fast(WAIT).unwrap();
    assert_eq!(snapshot.in_flight, 0);
    assert!(effects.is_revoked());
    assert!(group.is_cancelled());
    assert_eq!(
        group.take_result(id).unwrap().unwrap().unwrap().value,
        Value::Int(42)
    );
}

#[test]
fn cancelled_jobs_trigger_batch_failure_without_cancelling_the_parent() {
    let pool = ExecutionWorkPool::new(256);
    let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
    let (hook, entered, mut release) = parked(false);
    let id = group
        .spawn_with_preparation_until(
            module("let o = {}; while (true) {}"),
            config(),
            "deadline",
            Instant::now() + WAIT,
            |_, _| Ok(Some(hook)),
        )
        .unwrap();
    entered.recv_timeout(WAIT).unwrap();
    group.task_control(id).unwrap().cancel();
    release.open();
    assert_eq!(
        group.finish_and_join_fail_fast(WAIT),
        Err(ExecutionBatchError::TaskFailed {
            task: id,
            join_error: None
        })
    );
    assert!(group.take_result(id).unwrap().unwrap().is_err());
    assert!(!pool.is_revoked());
}

#[test]
fn running_supervisor_observes_failure_and_cancels_before_blocked_sibling_is_released() {
    let pool = ExecutionWorkPool::new(512);
    let mut group = ExecutionTaskGroup::new(&pool, 512, 2).unwrap();
    let (slow_hook, slow_entered, mut slow_release) = parked(false);
    let slow_id = group
        .spawn_with_hook(
            module("let o = {}; while (true) {}"),
            config(),
            "slow",
            Some(slow_hook),
        )
        .unwrap();
    slow_entered.recv_timeout(WAIT).unwrap();
    let (fail_hook, fail_entered, mut fail_release) = parked(true);
    let failed = group
        .spawn_with_hook(module("let o = {}; o;"), config(), "panic", Some(fail_hook))
        .unwrap();
    fail_entered.recv_timeout(WAIT).unwrap();
    let control = group.control();
    let release_worker = thread::spawn(move || {
        fail_release.open();
        let deadline = Instant::now() + WAIT;
        while !control.is_cancelled() {
            assert!(
                Instant::now() < deadline,
                "supervisor did not cancel the batch"
            );
            thread::yield_now();
        }
        slow_release.open();
    });
    let result = group.finish_and_join_fail_fast(WAIT);
    release_worker.join().unwrap();
    assert_eq!(
        result,
        Err(ExecutionBatchError::TaskFailed {
            task: failed,
            join_error: None
        })
    );
    assert_eq!(group.pending(), 0);
    assert!(matches!(
        group.take_result(failed),
        Some(Err(ExecutionTaskJoinError::Panicked))
    ));
    assert!(group.take_result(slow_id).unwrap().unwrap().is_err());
    assert!(!pool.is_revoked());
}

struct Contained(HookAction);
impl InterpreterHook for Contained {
    fn pre_property_access(&self, _: &HookContext, _: &ObjectRef, _: &PropertyKey) -> HookAction {
        HookAction::Allow
    }
    fn pre_call(&self, _: &HookContext, _: &FunctionRef, _: &[Value]) -> HookAction {
        HookAction::Allow
    }
    fn pre_import(&self, _: &HookContext, _: &str) -> HookAction {
        HookAction::Allow
    }
    fn pre_allocation(&self, _: &HookContext, _: AllocKind, _: usize) -> HookAction {
        self.0.clone()
    }
}

#[test]
fn containment_results_do_not_count_as_healthy_native_completion() {
    for action in [
        HookAction::Sandbox,
        HookAction::Suspend,
        HookAction::Terminate("stop".into()),
        HookAction::Quarantine("stop".into()),
    ] {
        let pool = ExecutionWorkPool::new(256);
        let mut group = ExecutionTaskGroup::new(&pool, 256, 1).unwrap();
        let id = group
            .spawn_with_hook(
                module("let o = {}; o;"),
                config(),
                "contained",
                Some(Arc::new(Contained(action.clone()))),
            )
            .unwrap();
        assert_eq!(
            group.finish_and_join_fail_fast(WAIT),
            Err(ExecutionBatchError::TaskFailed {
                task: id,
                join_error: None
            }),
            "{action:?}"
        );
        let outcome = group.take_result(id).unwrap().unwrap();
        if let Ok(result) = outcome {
            assert_eq!(result.requested_hook_action, Some(action));
        }
        assert!(group.is_cancelled());
        assert_eq!(group.first_failure(), Some(id));
    }
}
