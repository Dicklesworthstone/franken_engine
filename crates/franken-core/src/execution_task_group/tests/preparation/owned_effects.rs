//! The native hook enters the actual decorators built by the group's borrowed
//! binding context. Inner providers are probes, not process/filesystem proof.

use super::*;
use crate::host_effect_budget::HostEffectDrainError;
use frankenengine_extension_host::host_io::HostIoError;

fn scope(operations: u64, max_in_flight: usize) -> HostEffectWorkPool {
    HostEffectWorkPool::new(HostEffectLimits { operations, max_in_flight })
}

fn read() -> HostIoRequest {
    HostIoRequest::FsRead { path: "owned-binding".into() }
}

fn both(bindings: &ExecutionHostBindings<'_>, providers: Arc<Providers>) -> Arc<dyn InterpreterHook> {
    Arc::new(EffectHook {
        io: Arc::new(bindings.bind_host_io(providers.clone())),
        process: Some(Arc::new(bindings.bind_process_spawn(providers))),
        invoked: AtomicBool::new(false),
        denied: AtomicBool::new(false),
    })
}

#[test]
fn group_owned_bindings_spend_and_drain_one_shared_io_process_frontier() {
    let parent = ExecutionWorkPool::new(512);
    let effects = scope(4, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 512, 1, effects.clone()).unwrap();
    let providers = Arc::new(Providers::default());
    for _ in 0..2 {
        let id = group.spawn_with_effect_preparation(
            module("let x = {}; x;"), config(128), "owned-bindings",
            |bindings, _| Ok(Some(both(bindings, providers.clone()))),
        ).unwrap();
        collect(&mut group, id).unwrap().unwrap();
        assert!(!effects.is_revoked(), "job completion is not whole-group revocation");
        for control in providers.io_controls.lock().unwrap().iter() {
            assert!(control.checkpoint().is_err());
        }
        for control in providers.process_controls.lock().unwrap().iter() {
            assert!(control.checkpoint().is_err());
        }
    }
    let drained = group.close_and_drain(WAIT).unwrap();
    assert_eq!(drained.committed_operations, 4);
    assert_eq!(drained.remaining_operations, 0);
    assert_eq!(drained.in_flight, 0);
    assert_eq!(providers.io_calls.load(Ordering::SeqCst), 2);
    assert_eq!(providers.process_calls.load(Ordering::SeqCst), 2);
    assert_eq!(group.remaining_instructions(), 256);
}

#[test]
fn unconfigured_full_and_closed_groups_never_enter_effect_preparation() {
    let parent = ExecutionWorkPool::new(256);
    let mut unconfigured = ExecutionTaskGroup::new(&parent, 128, 1).unwrap();
    assert!(matches!(unconfigured.spawn_with_effect_preparation(
        module("7;"), config(64), "unconfigured", |_, _| panic!("no setup"),
    ), Err(ExecutionGroupStartError::HostEffectsUnconfigured)));
    assert_eq!(unconfigured.remaining_instructions(), 128);
    let effects = scope(2, 1);
    let mut full = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 0, effects.clone()).unwrap();
    assert!(matches!(full.spawn_with_effect_preparation(
        module("7;"), config(64), "full", |_, _| panic!("no setup"),
    ), Err(ExecutionGroupStartError::Capacity { limit: 0 })));
    full.control().cancel();
    assert!(matches!(full.spawn_with_effect_preparation(
        module("7;"), config(64), "closed", |_, _| panic!("no setup"),
    ), Err(ExecutionGroupStartError::Closed)));
    assert_eq!(full.remaining_instructions(), 128);
    assert_eq!(effects.snapshot().unwrap().committed_operations, 0);
    full.close_and_drain(Duration::ZERO).unwrap();
    unconfigured.close_and_join(Duration::ZERO).unwrap();
}

#[test]
fn preparation_refusal_closes_escaped_bound_provider_without_cancelling_group() {
    let parent = ExecutionWorkPool::new(256);
    let effects = scope(2, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 256, 1, effects.clone()).unwrap();
    let providers = Arc::new(Providers::default());
    let mut escaped = None;
    let result = group.spawn_with_effect_preparation(
        module("7;"), config(128), "refused", |bindings, _| {
            escaped = Some(bindings.bind_host_io(providers.clone()));
            Err(WorkBudgetError::Revoked)
        },
    );
    assert!(matches!(result, Err(ExecutionGroupStartError::Preparation(WorkBudgetError::Revoked))));
    assert!(matches!(escaped.unwrap().perform(&read(), &[HostIoCapability::FsRead]),
        Err(HostIoError::Denied { reason }) if reason == "HOST_EFFECT_SCOPE_REVOKED"));
    assert_eq!(providers.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(effects.snapshot().unwrap().committed_operations, 0);
    assert_eq!(group.remaining_instructions(), 128);
    assert_eq!(group.retained(), 0);
    assert!(!group.is_closed());
    let id = group.spawn_with_effect_preparation(
        module("let x = {}; x;"), config(128), "next", |bindings, _| {
            Ok(Some(both(bindings, providers.clone())))
        },
    ).unwrap();
    collect(&mut group, id).unwrap().unwrap();
    assert_eq!(group.close_and_drain(WAIT).unwrap().committed_operations, 2);
}

#[test]
fn refused_setup_cannot_hide_a_provider_call_already_entered_through_its_bindings() {
    let parent = ExecutionWorkPool::new(256);
    let effects = scope(2, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 256, 1, effects.clone()).unwrap();
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let inner = Arc::new(HoldingIo {
        entered: entered_tx, release: Mutex::new(release_rx), control: Mutex::new(None),
    });
    let mut worker = None;
    let result = group.spawn_with_effect_preparation(
        module("7;"), config(128), "started-during-setup", |bindings, _| {
            let provider = bindings.bind_host_io(inner.clone());
            worker = Some(thread::spawn(move || provider.perform(&read(), &[HostIoCapability::FsRead])));
            entered.recv_timeout(WAIT).unwrap();
            Err(WorkBudgetError::Revoked)
        },
    );
    assert!(matches!(result, Err(ExecutionGroupStartError::Preparation(_))));
    assert_eq!(group.retained(), 0);
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    let drain = group.close_and_drain(Duration::ZERO);
    release.send(()).unwrap();
    assert!(worker.unwrap().join().unwrap().is_err());
    assert_eq!(drain, Err(ExecutionGroupDrainError::Effects(
        HostEffectDrainError::TimedOut { in_flight: 1 }
    )));
    let snapshot = group.close_and_drain(WAIT).unwrap();
    assert_eq!(snapshot.in_flight, 0);
    assert_eq!(snapshot.committed_operations, 1);
    assert_eq!(group.remaining_instructions(), 128);
}

#[test]
fn preparation_unwind_revokes_both_owned_scopes_and_retains_existing_native_worker() {
    let parent = ExecutionWorkPool::new(2048);
    let effects = scope(2, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 1024, 2, effects.clone()).unwrap();
    let (hook, entered, release) = parked(false);
    let running = group.spawn_with_hook(
        module("let x = {}; while (true) {}"), config(512), "before-unwind", Some(hook),
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    let providers = Arc::new(Providers::default());
    let mut escaped = None;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = group.spawn_with_effect_preparation(
            module("7;"), config(128), "unwind", |bindings, _| {
                escaped = Some(bindings.bind_host_io(providers.clone()));
                panic!("trusted setup interrupted");
            },
        );
    }));
    assert!(panic.is_err());
    assert!(effects.is_revoked());
    assert!(group.task_control(running).unwrap().is_cancelled());
    assert_eq!(group.pending(), 1);
    assert!(escaped.unwrap().perform(&read(), &[HostIoCapability::FsRead]).is_err());
    assert!(!parent.is_revoked());
    release.send(()).unwrap();
    group.close_and_drain(WAIT).unwrap();
    cancelled(group.take_result(running).unwrap());
    assert_eq!(group.remaining_instructions(), 384);
}

#[test]
fn cancelling_one_bound_job_preserves_group_credits_and_next_job_progress() {
    let parent = ExecutionWorkPool::new(2048);
    let effects = scope(4, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 1024, 1, effects.clone()).unwrap();
    let (entered_tx, entered) = channel();
    let (release, release_rx) = channel();
    let inner = Arc::new(HoldingIo {
        entered: entered_tx, release: Mutex::new(release_rx), control: Mutex::new(None),
    });
    let id = group.spawn_with_effect_preparation(
        module("let x = {}; while (true) {}"), config(512), "cancel-job", |bindings, _| {
            Ok(Some(Arc::new(EffectHook {
                io: Arc::new(bindings.bind_host_io(inner.clone())), process: None,
                invoked: AtomicBool::new(false), denied: AtomicBool::new(false),
            })))
        },
    ).unwrap();
    entered.recv_timeout(WAIT).unwrap();
    group.task_control(id).unwrap().cancel();
    assert!(!effects.is_revoked());
    assert!(!group.is_closed());
    assert_eq!(effects.snapshot().unwrap().in_flight, 1);
    release.send(()).unwrap();
    cancelled(collect(&mut group, id));
    let providers = Arc::new(Providers::default());
    let next = group.spawn_with_effect_preparation(
        module("let x = {}; x;"), config(128), "next-job",
        |bindings, _| Ok(Some(both(bindings, providers.clone()))),
    ).unwrap();
    collect(&mut group, next).unwrap().unwrap();
    let snapshot = group.close_and_drain(WAIT).unwrap();
    assert_eq!(snapshot.committed_operations, 3);
    assert_eq!(snapshot.remaining_operations, 1);
    assert_eq!(group.remaining_instructions(), 384);
}

#[test]
fn owned_bindings_never_grant_missing_capabilities_or_admit_unauthorized_effects() {
    let parent = ExecutionWorkPool::new(128);
    let effects = scope(2, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 128, 1, effects.clone()).unwrap();
    let providers = Arc::new(Providers::default());
    let id = group.spawn_with_effect_preparation(
        module("7;"), config(128), "capabilities", |bindings, _| {
            assert!(matches!(bindings.bind_host_io(providers.clone()).perform(&read(), &[]),
                Err(HostIoError::CapabilityMissing { .. })));
            Ok(None)
        },
    ).unwrap();
    collect(&mut group, id).unwrap().unwrap();
    assert_eq!(providers.io_calls.load(Ordering::SeqCst), 0);
    assert_eq!(group.close_and_drain(WAIT).unwrap().committed_operations, 0);
}

#[test]
fn owned_binding_preparation_cannot_enlarge_prepaid_instruction_allowance() {
    let parent = ExecutionWorkPool::new(32);
    let effects = scope(1, 1);
    let mut group = ExecutionTaskGroup::new_with_host_effects(&parent, 32, 1, effects).unwrap();
    let id = group.spawn_with_effect_preparation(
        module("while (true) {}"), config(8), "attenuate", |_, current| {
            current.instruction_budget = 1024;
            Ok(None)
        },
    ).unwrap();
    assert!(matches!(collect(&mut group, id), Ok(Err(WorkBudgetError::Interpreter(
        InterpreterError::BudgetExhausted { budget: 8, .. }
    )))));
    assert_eq!(group.remaining_instructions(), 24);
    group.close_and_drain(WAIT).unwrap();
}
