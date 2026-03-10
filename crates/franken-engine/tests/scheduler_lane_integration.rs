#![forbid(unsafe_code)]

//! Integration tests for the `scheduler_lane` module.
//!
//! Tests exercise the public API from outside the crate, covering:
//! - Every public enum variant (construction, Display, serde round-trip)
//! - Every public struct (construction, field access, Default if implemented, serde)
//! - Every public method (happy path, error paths, edge cases)
//! - Lane scheduling and task dispatching
//! - Error variant coverage and Display formatting
//! - Determinism: same inputs produce same outputs
//! - Cross-concern integration scenarios

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;

use frankenengine_engine::scheduler_lane::{
    LaneConfig, LaneError, LaneMetrics, LaneScheduler, ScheduledTask, SchedulerEvent,
    SchedulerLane, TaskId, TaskLabel, TaskType,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cancel_label(trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Cancel,
        task_type: TaskType::CancelCleanup,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn timed_label(trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Timed,
        task_type: TaskType::LeaseRenewal,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn ready_label(trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::ExtensionDispatch,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn cancel_label_typed(tt: TaskType, trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Cancel,
        task_type: tt,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn timed_label_typed(tt: TaskType, trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Timed,
        task_type: tt,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn ready_label_typed(tt: TaskType, trace: &str) -> TaskLabel {
    TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: tt,
        trace_id: trace.to_string(),
        priority_sub_band: 0,
    }
}

fn default_scheduler() -> LaneScheduler {
    LaneScheduler::new(LaneConfig::default())
}

// ===========================================================================
// 1. SchedulerLane enum — construction, Display, ordering, serde
// ===========================================================================

#[test]
fn scheduler_lane_display_cancel() {
    assert_eq!(SchedulerLane::Cancel.to_string(), "cancel");
}

#[test]
fn scheduler_lane_display_timed() {
    assert_eq!(SchedulerLane::Timed.to_string(), "timed");
}

#[test]
fn scheduler_lane_display_ready() {
    assert_eq!(SchedulerLane::Ready.to_string(), "ready");
}

#[test]
fn scheduler_lane_ordering_cancel_lt_timed() {
    assert!(SchedulerLane::Cancel < SchedulerLane::Timed);
}

#[test]
fn scheduler_lane_ordering_timed_lt_ready() {
    assert!(SchedulerLane::Timed < SchedulerLane::Ready);
}

#[test]
fn scheduler_lane_ordering_cancel_lt_ready() {
    assert!(SchedulerLane::Cancel < SchedulerLane::Ready);
}

#[test]
fn scheduler_lane_clone_and_copy() {
    let lane = SchedulerLane::Timed;
    let copied = lane;
    assert_eq!(lane, copied);
}

#[test]
fn scheduler_lane_debug() {
    let debug = format!("{:?}", SchedulerLane::Cancel);
    assert_eq!(debug, "Cancel");
}

#[test]
fn scheduler_lane_serde_round_trip_all_variants() {
    for lane in &[
        SchedulerLane::Cancel,
        SchedulerLane::Timed,
        SchedulerLane::Ready,
    ] {
        let json = serde_json::to_string(lane).expect("serialize");
        let restored: SchedulerLane = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*lane, restored);
    }
}

#[test]
fn scheduler_lane_hash_is_consistent() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(SchedulerLane::Cancel);
    set.insert(SchedulerLane::Timed);
    set.insert(SchedulerLane::Ready);
    set.insert(SchedulerLane::Cancel); // duplicate
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// 2. TaskType enum — construction, Display, required_lane, serde
// ===========================================================================

#[test]
fn task_type_cancel_cleanup_required_lane() {
    assert_eq!(
        TaskType::CancelCleanup.required_lane(),
        SchedulerLane::Cancel
    );
}

#[test]
fn task_type_quarantine_exec_required_lane() {
    assert_eq!(
        TaskType::QuarantineExec.required_lane(),
        SchedulerLane::Cancel
    );
}

#[test]
fn task_type_forced_drain_required_lane() {
    assert_eq!(TaskType::ForcedDrain.required_lane(), SchedulerLane::Cancel);
}

#[test]
fn task_type_lease_renewal_required_lane() {
    assert_eq!(TaskType::LeaseRenewal.required_lane(), SchedulerLane::Timed);
}

#[test]
fn task_type_monitoring_probe_required_lane() {
    assert_eq!(
        TaskType::MonitoringProbe.required_lane(),
        SchedulerLane::Timed
    );
}

#[test]
fn task_type_evidence_flush_required_lane() {
    assert_eq!(
        TaskType::EvidenceFlush.required_lane(),
        SchedulerLane::Timed
    );
}

#[test]
fn task_type_epoch_barrier_timeout_required_lane() {
    assert_eq!(
        TaskType::EpochBarrierTimeout.required_lane(),
        SchedulerLane::Timed
    );
}

#[test]
fn task_type_extension_dispatch_required_lane() {
    assert_eq!(
        TaskType::ExtensionDispatch.required_lane(),
        SchedulerLane::Ready
    );
}

#[test]
fn task_type_gc_cycle_required_lane() {
    assert_eq!(TaskType::GcCycle.required_lane(), SchedulerLane::Ready);
}

#[test]
fn task_type_policy_iteration_required_lane() {
    assert_eq!(
        TaskType::PolicyIteration.required_lane(),
        SchedulerLane::Ready
    );
}

#[test]
fn task_type_remote_sync_required_lane() {
    assert_eq!(TaskType::RemoteSync.required_lane(), SchedulerLane::Ready);
}

#[test]
fn task_type_saga_step_exec_required_lane() {
    assert_eq!(TaskType::SagaStepExec.required_lane(), SchedulerLane::Ready);
}

#[test]
fn task_type_display_all_variants() {
    let expected = [
        (TaskType::CancelCleanup, "cancel_cleanup"),
        (TaskType::QuarantineExec, "quarantine_exec"),
        (TaskType::ForcedDrain, "forced_drain"),
        (TaskType::LeaseRenewal, "lease_renewal"),
        (TaskType::MonitoringProbe, "monitoring_probe"),
        (TaskType::EvidenceFlush, "evidence_flush"),
        (TaskType::EpochBarrierTimeout, "epoch_barrier_timeout"),
        (TaskType::ExtensionDispatch, "extension_dispatch"),
        (TaskType::GcCycle, "gc_cycle"),
        (TaskType::PolicyIteration, "policy_iteration"),
        (TaskType::RemoteSync, "remote_sync"),
        (TaskType::SagaStepExec, "saga_step_exec"),
    ];
    for (tt, expected_str) in expected {
        assert_eq!(tt.to_string(), expected_str);
    }
}

#[test]
fn task_type_serde_round_trip_all_variants() {
    let variants = [
        TaskType::CancelCleanup,
        TaskType::QuarantineExec,
        TaskType::ForcedDrain,
        TaskType::LeaseRenewal,
        TaskType::MonitoringProbe,
        TaskType::EvidenceFlush,
        TaskType::EpochBarrierTimeout,
        TaskType::ExtensionDispatch,
        TaskType::GcCycle,
        TaskType::PolicyIteration,
        TaskType::RemoteSync,
        TaskType::SagaStepExec,
    ];
    for tt in &variants {
        let json = serde_json::to_string(tt).expect("serialize");
        let restored: TaskType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*tt, restored);
    }
}

#[test]
fn task_type_ordering_is_deterministic() {
    assert!(TaskType::CancelCleanup < TaskType::QuarantineExec);
    assert!(TaskType::QuarantineExec < TaskType::ForcedDrain);
}

// ===========================================================================
// 3. TaskLabel struct — construction, field access, serde
// ===========================================================================

#[test]
fn task_label_construction_and_field_access() {
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::GcCycle,
        trace_id: "trace-abc".to_string(),
        priority_sub_band: 42,
    };
    assert_eq!(label.lane, SchedulerLane::Ready);
    assert_eq!(label.task_type, TaskType::GcCycle);
    assert_eq!(label.trace_id, "trace-abc");
    assert_eq!(label.priority_sub_band, 42);
}

#[test]
fn task_label_serde_round_trip() {
    let label = TaskLabel {
        lane: SchedulerLane::Timed,
        task_type: TaskType::MonitoringProbe,
        trace_id: "tr-999".to_string(),
        priority_sub_band: 7,
    };
    let json = serde_json::to_string(&label).expect("serialize");
    let restored: TaskLabel = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(label, restored);
}

#[test]
fn task_label_clone_equality() {
    let label = cancel_label("t1");
    let cloned = label.clone();
    assert_eq!(label, cloned);
}

// ===========================================================================
// 4. TaskId struct — construction, Display, serde
// ===========================================================================

#[test]
fn task_id_construction() {
    let id = TaskId(42);
    assert_eq!(id.0, 42);
}

#[test]
fn task_id_display() {
    assert_eq!(TaskId(1).to_string(), "task:1");
    assert_eq!(TaskId(0).to_string(), "task:0");
    assert_eq!(TaskId(u64::MAX).to_string(), format!("task:{}", u64::MAX));
}

#[test]
fn task_id_serde_round_trip() {
    let id = TaskId(12345);
    let json = serde_json::to_string(&id).expect("serialize");
    let restored: TaskId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, restored);
}

#[test]
fn task_id_ordering() {
    assert!(TaskId(1) < TaskId(2));
    assert!(TaskId(0) < TaskId(u64::MAX));
}

#[test]
fn task_id_clone_copy() {
    let id = TaskId(7);
    let copied = id;
    assert_eq!(id, copied);
}

// ===========================================================================
// 5. ScheduledTask struct — construction, serde
// ===========================================================================

#[test]
fn scheduled_task_construction_and_field_access() {
    let task = ScheduledTask {
        task_id: TaskId(10),
        label: ready_label("trace-10"),
        deadline_tick: 500,
        submitted_at: 100,
        payload_id: "payload-xyz".to_string(),
    };
    assert_eq!(task.task_id, TaskId(10));
    assert_eq!(task.label.lane, SchedulerLane::Ready);
    assert_eq!(task.deadline_tick, 500);
    assert_eq!(task.submitted_at, 100);
    assert_eq!(task.payload_id, "payload-xyz");
}

#[test]
fn scheduled_task_serde_round_trip() {
    let task = ScheduledTask {
        task_id: TaskId(99),
        label: timed_label("serde-test"),
        deadline_tick: 200,
        submitted_at: 50,
        payload_id: "p-serde".to_string(),
    };
    let json = serde_json::to_string(&task).expect("serialize");
    let restored: ScheduledTask = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(task, restored);
}

// ===========================================================================
// 6. LaneMetrics struct — construction, Default, serde
// ===========================================================================

#[test]
fn lane_metrics_default() {
    let m = LaneMetrics::default();
    assert_eq!(m.lane, "");
    assert_eq!(m.queue_depth, 0);
    assert_eq!(m.tasks_submitted, 0);
    assert_eq!(m.tasks_scheduled, 0);
    assert_eq!(m.tasks_completed, 0);
    assert_eq!(m.tasks_timed_out, 0);
}

#[test]
fn lane_metrics_construction_and_field_access() {
    let m = LaneMetrics {
        lane: "cancel".to_string(),
        queue_depth: 5,
        tasks_submitted: 10,
        tasks_scheduled: 8,
        tasks_completed: 7,
        tasks_timed_out: 1,
    };
    assert_eq!(m.lane, "cancel");
    assert_eq!(m.queue_depth, 5);
    assert_eq!(m.tasks_submitted, 10);
    assert_eq!(m.tasks_scheduled, 8);
    assert_eq!(m.tasks_completed, 7);
    assert_eq!(m.tasks_timed_out, 1);
}

#[test]
fn lane_metrics_serde_round_trip() {
    let m = LaneMetrics {
        lane: "timed".to_string(),
        queue_depth: 3,
        tasks_submitted: 100,
        tasks_scheduled: 95,
        tasks_completed: 90,
        tasks_timed_out: 5,
    };
    let json = serde_json::to_string(&m).expect("serialize");
    let restored: LaneMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, restored);
}

// ===========================================================================
// 7. LaneConfig struct — construction, Default, serde
// ===========================================================================

#[test]
fn lane_config_default_values() {
    let cfg = LaneConfig::default();
    assert_eq!(cfg.cancel_max_depth, 256);
    assert_eq!(cfg.timed_max_depth, 1024);
    assert_eq!(cfg.ready_max_depth, 4096);
    assert_eq!(cfg.ready_min_throughput, 1);
}

#[test]
fn lane_config_custom_values() {
    let cfg = LaneConfig {
        cancel_max_depth: 10,
        timed_max_depth: 20,
        ready_max_depth: 30,
        ready_min_throughput: 5,
    };
    assert_eq!(cfg.cancel_max_depth, 10);
    assert_eq!(cfg.timed_max_depth, 20);
    assert_eq!(cfg.ready_max_depth, 30);
    assert_eq!(cfg.ready_min_throughput, 5);
}

#[test]
fn lane_config_serde_round_trip() {
    let cfg = LaneConfig {
        cancel_max_depth: 8,
        timed_max_depth: 16,
        ready_max_depth: 32,
        ready_min_throughput: 3,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let restored: LaneConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cfg, restored);
}

#[test]
fn lane_config_clone_equality() {
    let cfg = LaneConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

// ===========================================================================
// 8. SchedulerEvent struct — construction, serde
// ===========================================================================

#[test]
fn scheduler_event_construction_and_field_access() {
    let ev = SchedulerEvent {
        task_id: 1,
        lane: "cancel".to_string(),
        task_type: "cancel_cleanup".to_string(),
        trace_id: "trace-1".to_string(),
        queue_position: 0,
        event: "submit".to_string(),
    };
    assert_eq!(ev.task_id, 1);
    assert_eq!(ev.lane, "cancel");
    assert_eq!(ev.task_type, "cancel_cleanup");
    assert_eq!(ev.trace_id, "trace-1");
    assert_eq!(ev.queue_position, 0);
    assert_eq!(ev.event, "submit");
}

#[test]
fn scheduler_event_serde_round_trip() {
    let ev = SchedulerEvent {
        task_id: 42,
        lane: "ready".to_string(),
        task_type: "gc_cycle".to_string(),
        trace_id: "trace-42".to_string(),
        queue_position: 5,
        event: "schedule".to_string(),
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let restored: SchedulerEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev, restored);
}

// ===========================================================================
// 9. LaneError enum — construction, Display, serde, std::error::Error
// ===========================================================================

#[test]
fn lane_error_lane_mismatch_display() {
    let err = LaneError::LaneMismatch {
        task_type: "cancel_cleanup".to_string(),
        declared_lane: "ready".to_string(),
        required_lane: "cancel".to_string(),
    };
    let display = err.to_string();
    assert!(display.contains("cancel_cleanup"));
    assert!(display.contains("requires lane cancel"));
    assert!(display.contains("declared ready"));
}

#[test]
fn lane_error_lane_full_display() {
    let err = LaneError::LaneFull {
        lane: "timed".to_string(),
        max_depth: 1024,
    };
    let display = err.to_string();
    assert!(display.contains("timed"));
    assert!(display.contains("full"));
    assert!(display.contains("1024"));
}

#[test]
fn lane_error_task_not_found_display() {
    let err = LaneError::TaskNotFound { task_id: 999 };
    let display = err.to_string();
    assert!(display.contains("999"));
    assert!(display.contains("not found"));
}

#[test]
fn lane_error_empty_trace_id_display() {
    let err = LaneError::EmptyTraceId;
    let display = err.to_string();
    assert!(display.contains("non-empty"));
}

#[test]
fn lane_error_is_std_error() {
    let err = LaneError::EmptyTraceId;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn lane_error_serde_round_trip_all_variants() {
    let errors = vec![
        LaneError::LaneMismatch {
            task_type: "cancel_cleanup".to_string(),
            declared_lane: "ready".to_string(),
            required_lane: "cancel".to_string(),
        },
        LaneError::LaneFull {
            lane: "cancel".to_string(),
            max_depth: 256,
        },
        LaneError::TaskNotFound { task_id: 42 },
        LaneError::EmptyTraceId,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: LaneError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// 10. LaneScheduler::new — initial state
// ===========================================================================

#[test]
fn new_scheduler_has_empty_queues() {
    let sched = default_scheduler();
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
    assert_eq!(sched.total_queue_depth(), 0);
}

#[test]
fn new_scheduler_has_three_lane_metrics() {
    let sched = default_scheduler();
    let metrics = sched.lane_metrics();
    assert_eq!(metrics.len(), 3);
    assert!(metrics.contains_key("cancel"));
    assert!(metrics.contains_key("timed"));
    assert!(metrics.contains_key("ready"));
}

#[test]
fn new_scheduler_metrics_all_zero() {
    let sched = default_scheduler();
    for m in sched.lane_metrics().values() {
        assert_eq!(m.queue_depth, 0);
        assert_eq!(m.tasks_submitted, 0);
        assert_eq!(m.tasks_scheduled, 0);
        assert_eq!(m.tasks_completed, 0);
        assert_eq!(m.tasks_timed_out, 0);
    }
}

#[test]
fn new_scheduler_has_no_events() {
    let mut sched = default_scheduler();
    let events = sched.drain_events();
    assert!(events.is_empty());
}

#[test]
fn new_scheduler_has_empty_event_counts() {
    let sched = default_scheduler();
    assert!(sched.event_counts().is_empty());
}

// ===========================================================================
// 11. LaneScheduler::submit — happy paths
// ===========================================================================

#[test]
fn submit_cancel_task_returns_task_id_1() {
    let mut sched = default_scheduler();
    let id = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    assert_eq!(id, TaskId(1));
}

#[test]
fn submit_increments_task_ids() {
    let mut sched = default_scheduler();
    let id1 = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    let id2 = sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    let id3 = sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
    assert_eq!(id1, TaskId(1));
    assert_eq!(id2, TaskId(2));
    assert_eq!(id3, TaskId(3));
}

#[test]
fn submit_cancel_task_increases_cancel_queue_depth() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
}

#[test]
fn submit_timed_task_increases_timed_queue_depth() {
    let mut sched = default_scheduler();
    sched.submit(timed_label("t1"), 100, "p1", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1);
}

#[test]
fn submit_ready_task_increases_ready_queue_depth() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);
}

#[test]
fn submit_updates_total_queue_depth() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "c1", 0).unwrap();
    sched.submit(timed_label("t2"), 100, "ti1", 0).unwrap();
    sched.submit(ready_label("t3"), 0, "r1", 0).unwrap();
    assert_eq!(sched.total_queue_depth(), 3);
}

#[test]
fn submit_with_all_cancel_task_types() {
    let mut sched = default_scheduler();
    sched
        .submit(
            cancel_label_typed(TaskType::CancelCleanup, "t1"),
            0,
            "p1",
            0,
        )
        .unwrap();
    sched
        .submit(
            cancel_label_typed(TaskType::QuarantineExec, "t2"),
            0,
            "p2",
            0,
        )
        .unwrap();
    sched
        .submit(cancel_label_typed(TaskType::ForcedDrain, "t3"), 0, "p3", 0)
        .unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 3);
}

#[test]
fn submit_with_all_timed_task_types() {
    let mut sched = default_scheduler();
    sched
        .submit(timed_label_typed(TaskType::LeaseRenewal, "t1"), 10, "p1", 0)
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::MonitoringProbe, "t2"),
            20,
            "p2",
            0,
        )
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::EvidenceFlush, "t3"),
            30,
            "p3",
            0,
        )
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::EpochBarrierTimeout, "t4"),
            40,
            "p4",
            0,
        )
        .unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 4);
}

#[test]
fn submit_with_all_ready_task_types() {
    let mut sched = default_scheduler();
    sched
        .submit(
            ready_label_typed(TaskType::ExtensionDispatch, "t1"),
            0,
            "p1",
            0,
        )
        .unwrap();
    sched
        .submit(ready_label_typed(TaskType::GcCycle, "t2"), 0, "p2", 0)
        .unwrap();
    sched
        .submit(
            ready_label_typed(TaskType::PolicyIteration, "t3"),
            0,
            "p3",
            0,
        )
        .unwrap();
    sched
        .submit(ready_label_typed(TaskType::RemoteSync, "t4"), 0, "p4", 0)
        .unwrap();
    sched
        .submit(ready_label_typed(TaskType::SagaStepExec, "t5"), 0, "p5", 0)
        .unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 5);
}

#[test]
fn submit_with_priority_sub_band() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::ExtensionDispatch,
        trace_id: "t-sub".to_string(),
        priority_sub_band: 99,
    };
    sched.submit(label, 0, "p-sub", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);
}

// ===========================================================================
// 12. LaneScheduler::submit — error paths
// ===========================================================================

#[test]
fn submit_rejects_empty_trace_id() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Cancel,
        task_type: TaskType::CancelCleanup,
        trace_id: String::new(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    assert_eq!(err, LaneError::EmptyTraceId);
}

#[test]
fn submit_rejects_lane_mismatch_cancel_in_ready() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::CancelCleanup,
        trace_id: "t1".to_string(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneMismatch { .. }));
}

#[test]
fn submit_rejects_lane_mismatch_ready_in_cancel() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Cancel,
        task_type: TaskType::ExtensionDispatch,
        trace_id: "t1".to_string(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneMismatch { .. }));
}

#[test]
fn submit_rejects_lane_mismatch_timed_in_ready() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::LeaseRenewal,
        trace_id: "t1".to_string(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneMismatch { .. }));
}

#[test]
fn submit_rejects_full_cancel_lane() {
    let cfg = LaneConfig {
        cancel_max_depth: 2,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    let err = sched.submit(cancel_label("t3"), 0, "p3", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneFull { max_depth: 2, .. }));
}

#[test]
fn submit_rejects_full_timed_lane() {
    let cfg = LaneConfig {
        timed_max_depth: 1,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);
    sched.submit(timed_label("t1"), 100, "p1", 0).unwrap();
    let err = sched.submit(timed_label("t2"), 200, "p2", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneFull { .. }));
}

#[test]
fn submit_rejects_full_ready_lane() {
    let cfg = LaneConfig {
        ready_max_depth: 1,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);
    sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    let err = sched.submit(ready_label("t2"), 0, "p2", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneFull { .. }));
}

#[test]
fn submit_lane_mismatch_error_has_correct_fields() {
    let mut sched = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Timed,
        task_type: TaskType::GcCycle,
        trace_id: "t1".to_string(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    if let LaneError::LaneMismatch {
        task_type,
        declared_lane,
        required_lane,
    } = err
    {
        assert_eq!(task_type, "gc_cycle");
        assert_eq!(declared_lane, "timed");
        assert_eq!(required_lane, "ready");
    } else {
        panic!("expected LaneMismatch");
    }
}

// ===========================================================================
// 13. LaneScheduler::schedule_batch — lane priorities
// ===========================================================================

#[test]
fn cancel_tasks_scheduled_first() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "ready-1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "cancel-1", 0).unwrap();
    sched.submit(timed_label("t3"), 100, "timed-1", 0).unwrap();

    let batch = sched.schedule_batch(10, 200);
    assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
}

#[test]
fn timed_tasks_scheduled_before_ready_when_due() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "ready-1", 0).unwrap();
    sched.submit(timed_label("t2"), 50, "timed-1", 0).unwrap();

    let batch = sched.schedule_batch(10, 100);
    let timed_pos = batch
        .iter()
        .position(|t| t.label.lane == SchedulerLane::Timed)
        .expect("timed task present");
    let ready_pos = batch
        .iter()
        .position(|t| t.label.lane == SchedulerLane::Ready)
        .expect("ready task present");
    assert!(timed_pos < ready_pos);
}

#[test]
fn timed_tasks_not_scheduled_if_not_due() {
    let mut sched = default_scheduler();
    sched.submit(timed_label("t1"), 500, "timed-1", 0).unwrap();
    sched.submit(ready_label("t2"), 0, "ready-1", 0).unwrap();

    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].label.lane, SchedulerLane::Ready);
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 1);
}

#[test]
fn priority_order_cancel_then_timed_then_ready() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("r1"), 0, "ready-1", 0).unwrap();
    sched.submit(timed_label("ti1"), 10, "timed-1", 0).unwrap();
    sched.submit(cancel_label("c1"), 0, "cancel-1", 0).unwrap();

    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 3);
    assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    assert_eq!(batch[1].label.lane, SchedulerLane::Timed);
    assert_eq!(batch[2].label.lane, SchedulerLane::Ready);
}

#[test]
fn batch_size_limits_cancel_pulls() {
    let mut sched = default_scheduler();
    for i in 0..5 {
        sched
            .submit(cancel_label(&format!("c{i}")), 0, &format!("pc{i}"), 0)
            .unwrap();
    }
    // batch_size=3 means only 3 cancel tasks pulled (plus anti-starvation ready)
    let batch = sched.schedule_batch(3, 0);
    let cancel_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Cancel)
        .count();
    assert_eq!(cancel_count, 3);
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 2);
}

// ===========================================================================
// 14. LaneScheduler::schedule_batch — timed lane deadline sorting
// ===========================================================================

#[test]
fn timed_lane_sorts_by_deadline() {
    let mut sched = default_scheduler();
    sched.submit(timed_label("t1"), 300, "late", 0).unwrap();
    sched.submit(timed_label("t2"), 100, "early", 0).unwrap();
    sched.submit(timed_label("t3"), 200, "mid", 0).unwrap();

    let batch = sched.schedule_batch(10, 500);
    let timed: Vec<_> = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Timed)
        .collect();
    assert_eq!(timed[0].payload_id, "early");
    assert_eq!(timed[1].payload_id, "mid");
    assert_eq!(timed[2].payload_id, "late");
}

#[test]
fn timed_tasks_with_equal_deadline_are_both_scheduled() {
    let mut sched = default_scheduler();
    sched.submit(timed_label("t1"), 100, "first", 0).unwrap();
    sched.submit(timed_label("t2"), 100, "second", 5).unwrap();

    let batch = sched.schedule_batch(10, 100);
    let timed: Vec<_> = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Timed)
        .collect();
    assert_eq!(timed.len(), 2);
}

// ===========================================================================
// 15. LaneScheduler::schedule_batch — ready lane FIFO
// ===========================================================================

#[test]
fn ready_lane_fifo_ordering() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "first", 0).unwrap();
    sched.submit(ready_label("t2"), 0, "second", 10).unwrap();
    sched.submit(ready_label("t3"), 0, "third", 20).unwrap();

    let batch = sched.schedule_batch(10, 30);
    assert_eq!(batch[0].payload_id, "first");
    assert_eq!(batch[1].payload_id, "second");
    assert_eq!(batch[2].payload_id, "third");
}

// ===========================================================================
// 16. LaneScheduler::schedule_batch — anti-starvation
// ===========================================================================

#[test]
fn anti_starvation_guarantees_ready_progress_when_cancel_fills_batch() {
    let cfg = LaneConfig {
        ready_min_throughput: 2,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);

    for i in 0..5 {
        sched
            .submit(cancel_label(&format!("c{i}")), 0, &format!("cancel-{i}"), 0)
            .unwrap();
    }
    for i in 0..3 {
        sched
            .submit(ready_label(&format!("r{i}")), 0, &format!("ready-{i}"), 0)
            .unwrap();
    }

    let batch = sched.schedule_batch(5, 0);
    let ready_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Ready)
        .count();
    assert!(
        ready_count >= 2,
        "anti-starvation must guarantee >= 2 ready tasks"
    );
}

#[test]
fn anti_starvation_does_not_exceed_available_ready_tasks() {
    let cfg = LaneConfig {
        ready_min_throughput: 10,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);

    for i in 0..5 {
        sched
            .submit(cancel_label(&format!("c{i}")), 0, &format!("cancel-{i}"), 0)
            .unwrap();
    }
    sched.submit(ready_label("r0"), 0, "ready-0", 0).unwrap();

    let batch = sched.schedule_batch(5, 0);
    let ready_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Ready)
        .count();
    // Only 1 ready task available, even though min_throughput is 10.
    assert_eq!(ready_count, 1);
}

#[test]
fn zero_batch_size_schedules_nothing() {
    let cfg = LaneConfig {
        ready_min_throughput: 5,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);
    sched.submit(cancel_label("c1"), 0, "p1", 0).unwrap();
    sched.submit(timed_label("ti1"), 500, "p2", 0).unwrap();
    sched.submit(ready_label("r1"), 0, "p3", 0).unwrap();

    // batch_size=0 schedules nothing. The timed task has a future deadline
    // so it won't be timed out either.
    let batch = sched.schedule_batch(0, 100);
    assert!(batch.is_empty());
    assert_eq!(sched.total_queue_depth(), 3);
}

#[test]
fn anti_starvation_with_remaining_capacity() {
    let cfg = LaneConfig {
        ready_min_throughput: 3,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);

    sched.submit(cancel_label("c1"), 0, "cancel-1", 0).unwrap();
    for i in 0..5 {
        sched
            .submit(ready_label(&format!("r{i}")), 0, &format!("ready-{i}"), 0)
            .unwrap();
    }

    // batch_size=10, 1 cancel + up to 9 remaining, min_throughput=3
    // remaining = 10-1 = 9, max(9, 3) = 9, but only 5 ready tasks
    let batch = sched.schedule_batch(10, 0);
    let cancel_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Cancel)
        .count();
    let ready_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Ready)
        .count();
    assert_eq!(cancel_count, 1);
    assert_eq!(ready_count, 5);
}

// ===========================================================================
// 17. LaneScheduler::schedule_batch — timeout handling
// ===========================================================================

#[test]
fn timed_tasks_past_deadline_not_in_batch_are_timed_out() {
    let mut sched = default_scheduler();
    // Submit two timed tasks; only schedule one via batch_size=1
    sched.submit(timed_label("t1"), 50, "early", 0).unwrap();
    sched
        .submit(timed_label("t2"), 80, "late-expired", 0)
        .unwrap();

    // current_ticks=100. Task with deadline 50 is scheduled. Task with deadline 80
    // is past deadline (80 < 100) but was not pulled in batch. It gets timed out.
    let batch = sched.schedule_batch(1, 100);
    // The early task (deadline 50) is scheduled first.
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload_id, "early");

    // The expired task (deadline 80 < current 100) should be timed out and removed.
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);
    assert_eq!(sched.lane_metrics()["timed"].tasks_timed_out, 1);
}

#[test]
fn timed_tasks_at_exact_deadline_are_not_timed_out() {
    let mut sched = default_scheduler();
    // deadline_tick == current_ticks: this is "due" not "expired"
    sched.submit(timed_label("t1"), 100, "exact", 0).unwrap();

    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload_id, "exact");
    assert_eq!(sched.lane_metrics()["timed"].tasks_timed_out, 0);
}

#[test]
fn timed_tasks_with_zero_deadline_are_never_timed_out() {
    let mut sched = default_scheduler();
    // deadline_tick=0 means no deadline, should not be timed out
    sched
        .submit(timed_label("t1"), 0, "no-deadline", 0)
        .unwrap();

    // Not due (0 <= 100 is true, so it IS scheduled actually)
    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 1);
    assert_eq!(sched.lane_metrics()["timed"].tasks_timed_out, 0);
}

#[test]
fn timeout_emits_events_and_counts() {
    let mut sched = default_scheduler();
    sched
        .submit(timed_label("t1"), 10, "will-expire", 0)
        .unwrap();
    sched.drain_events(); // clear submit event

    // current_ticks=100, deadline=10. Not scheduled because batch_size=0.
    // But with batch_size=0, no tasks are scheduled at all. The timeout
    // logic only runs after scheduling. Let's use a scenario where
    // the task stays in queue past the deadline.
    //
    // Actually, with batch_size=0, ready_slots=0, so the timeout check still runs.
    // But wait: with batch_size=0, the cancel loop doesn't run, timed `if batch.len() < batch_size`
    // is `0 < 0` = false, so timed doesn't run. Then ready_slots=0.
    // Then the timeout check at the end still runs on the timed queue.
    sched.schedule_batch(0, 100);

    // The task with deadline 10 < current 100 should be timed out.
    assert_eq!(sched.lane_metrics()["timed"].tasks_timed_out, 1);
    assert_eq!(sched.queue_depth(SchedulerLane::Timed), 0);

    let events = sched.drain_events();
    assert!(events.iter().any(|e| e.event == "timeout"));
    assert_eq!(sched.event_counts().get("timeout"), Some(&1));
}

// ===========================================================================
// 18. LaneScheduler::complete_task
// ===========================================================================

#[test]
fn complete_task_increments_completed_metric() {
    let mut sched = default_scheduler();
    let id = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.complete_task(id, SchedulerLane::Cancel);

    assert_eq!(sched.lane_metrics()["cancel"].tasks_completed, 1);
}

#[test]
fn complete_task_emits_event() {
    let mut sched = default_scheduler();
    let id = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.drain_events(); // clear submit+schedule events

    sched.complete_task(id, SchedulerLane::Cancel);
    let events = sched.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "complete");
    assert_eq!(events[0].task_id, id.0);
    assert_eq!(events[0].lane, "cancel");
}

#[test]
fn complete_task_updates_event_count() {
    let mut sched = default_scheduler();
    let id = sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.complete_task(id, SchedulerLane::Ready);

    assert_eq!(sched.event_counts().get("complete"), Some(&1));
}

#[test]
fn complete_multiple_tasks() {
    let mut sched = default_scheduler();
    let id1 = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    let id2 = sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.complete_task(id1, SchedulerLane::Cancel);
    sched.complete_task(id2, SchedulerLane::Cancel);

    assert_eq!(sched.lane_metrics()["cancel"].tasks_completed, 2);
    assert_eq!(sched.event_counts().get("complete"), Some(&2));
}

// ===========================================================================
// 19. LaneScheduler::lane_metrics
// ===========================================================================

#[test]
fn metrics_track_submissions_per_lane() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    sched.submit(timed_label("t3"), 100, "p3", 0).unwrap();
    sched.submit(ready_label("t4"), 0, "p4", 0).unwrap();
    sched.submit(ready_label("t5"), 0, "p5", 0).unwrap();
    sched.submit(ready_label("t6"), 0, "p6", 0).unwrap();

    let m = sched.lane_metrics();
    assert_eq!(m["cancel"].tasks_submitted, 2);
    assert_eq!(m["timed"].tasks_submitted, 1);
    assert_eq!(m["ready"].tasks_submitted, 3);
}

#[test]
fn metrics_track_scheduling_per_lane() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(timed_label("t2"), 50, "p2", 0).unwrap();
    sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
    sched.schedule_batch(10, 100);

    let m = sched.lane_metrics();
    assert_eq!(m["cancel"].tasks_scheduled, 1);
    assert_eq!(m["timed"].tasks_scheduled, 1);
    assert_eq!(m["ready"].tasks_scheduled, 1);
}

#[test]
fn metrics_queue_depth_updated_after_schedule() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();

    assert_eq!(sched.lane_metrics()["cancel"].queue_depth, 2);

    sched.schedule_batch(1, 0);
    assert_eq!(sched.lane_metrics()["cancel"].queue_depth, 1);
}

// ===========================================================================
// 20. LaneScheduler::queue_depth / total_queue_depth
// ===========================================================================

#[test]
fn queue_depth_reflects_submit_and_schedule() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 2);

    sched.schedule_batch(1, 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);

    sched.schedule_batch(1, 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
}

#[test]
fn total_queue_depth_across_all_lanes() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("c1"), 0, "p1", 0).unwrap();
    sched.submit(timed_label("ti1"), 100, "p2", 0).unwrap();
    sched.submit(ready_label("r1"), 0, "p3", 0).unwrap();
    sched.submit(ready_label("r2"), 0, "p4", 0).unwrap();
    assert_eq!(sched.total_queue_depth(), 4);
}

// ===========================================================================
// 21. LaneScheduler::drain_events
// ===========================================================================

#[test]
fn drain_events_returns_all_accumulated_events() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();

    let events = sched.drain_events();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.event == "submit"));
}

#[test]
fn drain_events_clears_accumulated_events() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.drain_events();

    let events = sched.drain_events();
    assert!(events.is_empty());
}

#[test]
fn events_include_submit_schedule_and_complete() {
    let mut sched = default_scheduler();
    let id = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.complete_task(id, SchedulerLane::Cancel);

    let events = sched.drain_events();
    let event_types: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert!(event_types.contains(&"submit"));
    assert!(event_types.contains(&"schedule"));
    assert!(event_types.contains(&"complete"));
}

// ===========================================================================
// 22. LaneScheduler::event_counts
// ===========================================================================

#[test]
fn event_counts_accumulate_correctly() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
    sched.schedule_batch(10, 0);

    let counts = sched.event_counts();
    assert_eq!(counts.get("submit"), Some(&3));
    assert_eq!(counts.get("schedule"), Some(&3));
}

#[test]
fn event_counts_persist_across_drain_events() {
    let mut sched = default_scheduler();
    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.drain_events();

    // event_counts should still reflect the submit
    assert_eq!(sched.event_counts().get("submit"), Some(&1));
}

// ===========================================================================
// 23. Determinism: same inputs produce same outputs
// ===========================================================================

#[test]
fn deterministic_scheduling_produces_identical_order() {
    let run = || -> Vec<String> {
        let mut sched = default_scheduler();
        sched.submit(ready_label("t1"), 0, "r1", 0).unwrap();
        sched.submit(cancel_label("t2"), 0, "c1", 0).unwrap();
        sched.submit(timed_label("t3"), 50, "ti1", 0).unwrap();
        sched.submit(ready_label("t4"), 0, "r2", 10).unwrap();
        let batch = sched.schedule_batch(10, 100);
        batch.iter().map(|t| t.payload_id.clone()).collect()
    };

    let order1 = run();
    let order2 = run();
    let order3 = run();
    assert_eq!(order1, order2);
    assert_eq!(order2, order3);
}

#[test]
fn deterministic_task_ids_across_runs() {
    let run = || -> Vec<TaskId> {
        let mut sched = default_scheduler();
        let id1 = sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        let id2 = sched.submit(timed_label("t2"), 50, "p2", 0).unwrap();
        let id3 = sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
        vec![id1, id2, id3]
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_metrics_across_runs() {
    let run = || -> BTreeMap<String, LaneMetrics> {
        let mut sched = default_scheduler();
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.submit(timed_label("t2"), 50, "p2", 0).unwrap();
        sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();
        sched.schedule_batch(10, 100);
        sched.lane_metrics().clone()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_events_across_runs() {
    let run = || -> Vec<SchedulerEvent> {
        let mut sched = default_scheduler();
        sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
        sched.schedule_batch(10, 0);
        sched.drain_events()
    };

    assert_eq!(run(), run());
}

// ===========================================================================
// 24. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn full_lifecycle_submit_schedule_complete() {
    let mut sched = default_scheduler();

    // Submit tasks across all lanes.
    let c1 = sched
        .submit(cancel_label("c1"), 0, "cancel-payload", 0)
        .unwrap();
    let ti1 = sched
        .submit(timed_label("ti1"), 50, "timed-payload", 0)
        .unwrap();
    let r1 = sched
        .submit(ready_label("r1"), 0, "ready-payload", 0)
        .unwrap();

    assert_eq!(sched.total_queue_depth(), 3);

    // Schedule all.
    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 3);
    assert_eq!(sched.total_queue_depth(), 0);

    // Complete all.
    sched.complete_task(c1, SchedulerLane::Cancel);
    sched.complete_task(ti1, SchedulerLane::Timed);
    sched.complete_task(r1, SchedulerLane::Ready);

    let m = sched.lane_metrics();
    assert_eq!(m["cancel"].tasks_submitted, 1);
    assert_eq!(m["cancel"].tasks_scheduled, 1);
    assert_eq!(m["cancel"].tasks_completed, 1);
    assert_eq!(m["timed"].tasks_submitted, 1);
    assert_eq!(m["timed"].tasks_scheduled, 1);
    assert_eq!(m["timed"].tasks_completed, 1);
    assert_eq!(m["ready"].tasks_submitted, 1);
    assert_eq!(m["ready"].tasks_scheduled, 1);
    assert_eq!(m["ready"].tasks_completed, 1);
}

#[test]
fn multiple_rounds_of_scheduling() {
    let mut sched = default_scheduler();

    // Round 1: submit and schedule cancel tasks.
    sched
        .submit(cancel_label("c1"), 0, "c-payload-1", 0)
        .unwrap();
    sched
        .submit(cancel_label("c2"), 0, "c-payload-2", 0)
        .unwrap();
    let batch1 = sched.schedule_batch(10, 0);
    assert_eq!(batch1.len(), 2);

    // Round 2: submit and schedule timed + ready tasks.
    sched
        .submit(timed_label("ti1"), 50, "t-payload-1", 10)
        .unwrap();
    sched
        .submit(ready_label("r1"), 0, "r-payload-1", 10)
        .unwrap();
    let batch2 = sched.schedule_batch(10, 100);
    assert_eq!(batch2.len(), 2);

    // Metrics accumulate across rounds.
    let m = sched.lane_metrics();
    assert_eq!(m["cancel"].tasks_scheduled, 2);
    assert_eq!(m["timed"].tasks_scheduled, 1);
    assert_eq!(m["ready"].tasks_scheduled, 1);
}

#[test]
fn mixed_task_types_per_lane() {
    let mut sched = default_scheduler();

    // All three cancel task types.
    sched
        .submit(
            cancel_label_typed(TaskType::CancelCleanup, "cc"),
            0,
            "p-cc",
            0,
        )
        .unwrap();
    sched
        .submit(
            cancel_label_typed(TaskType::QuarantineExec, "qe"),
            0,
            "p-qe",
            0,
        )
        .unwrap();
    sched
        .submit(
            cancel_label_typed(TaskType::ForcedDrain, "fd"),
            0,
            "p-fd",
            0,
        )
        .unwrap();

    // All four timed task types.
    sched
        .submit(
            timed_label_typed(TaskType::LeaseRenewal, "lr"),
            10,
            "p-lr",
            0,
        )
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::MonitoringProbe, "mp"),
            20,
            "p-mp",
            0,
        )
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::EvidenceFlush, "ef"),
            30,
            "p-ef",
            0,
        )
        .unwrap();
    sched
        .submit(
            timed_label_typed(TaskType::EpochBarrierTimeout, "ebt"),
            40,
            "p-ebt",
            0,
        )
        .unwrap();

    // All five ready task types.
    sched
        .submit(
            ready_label_typed(TaskType::ExtensionDispatch, "ed"),
            0,
            "p-ed",
            0,
        )
        .unwrap();
    sched
        .submit(ready_label_typed(TaskType::GcCycle, "gc"), 0, "p-gc", 0)
        .unwrap();
    sched
        .submit(
            ready_label_typed(TaskType::PolicyIteration, "pi"),
            0,
            "p-pi",
            0,
        )
        .unwrap();
    sched
        .submit(ready_label_typed(TaskType::RemoteSync, "rs"), 0, "p-rs", 0)
        .unwrap();
    sched
        .submit(
            ready_label_typed(TaskType::SagaStepExec, "ss"),
            0,
            "p-ss",
            0,
        )
        .unwrap();

    assert_eq!(sched.total_queue_depth(), 12);
    let batch = sched.schedule_batch(20, 100);
    assert_eq!(batch.len(), 12);
    assert_eq!(sched.total_queue_depth(), 0);
}

#[test]
fn heavy_cancel_load_with_anti_starvation() {
    let cfg = LaneConfig {
        cancel_max_depth: 100,
        ready_min_throughput: 3,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);

    for i in 0..50 {
        sched
            .submit(cancel_label(&format!("c{i}")), 0, &format!("cancel-{i}"), 0)
            .unwrap();
    }
    for i in 0..10 {
        sched
            .submit(ready_label(&format!("r{i}")), 0, &format!("ready-{i}"), 0)
            .unwrap();
    }

    // batch_size=50 takes all 50 cancel tasks, plus anti-starvation guarantees 3 ready.
    let batch = sched.schedule_batch(50, 0);
    let cancel_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Cancel)
        .count();
    let ready_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Ready)
        .count();
    assert_eq!(cancel_count, 50);
    assert!(ready_count >= 3);
}

#[test]
fn scheduled_task_preserves_submitted_at_and_deadline() {
    let mut sched = default_scheduler();
    sched.submit(timed_label("t1"), 999, "p1", 42).unwrap();

    let batch = sched.schedule_batch(10, 1000);
    assert_eq!(batch[0].submitted_at, 42);
    assert_eq!(batch[0].deadline_tick, 999);
}

#[test]
fn scheduled_task_preserves_payload_id() {
    let mut sched = default_scheduler();
    sched
        .submit(ready_label("t1"), 0, "my-unique-payload", 0)
        .unwrap();

    let batch = sched.schedule_batch(10, 0);
    assert_eq!(batch[0].payload_id, "my-unique-payload");
}

#[test]
fn submit_event_has_correct_queue_position() {
    let mut sched = default_scheduler();
    sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(ready_label("t2"), 0, "p2", 0).unwrap();
    sched.submit(ready_label("t3"), 0, "p3", 0).unwrap();

    let events = sched.drain_events();
    assert_eq!(events[0].queue_position, 0);
    assert_eq!(events[1].queue_position, 1);
    assert_eq!(events[2].queue_position, 2);
}

#[test]
fn submit_event_records_trace_id_and_task_type() {
    let mut sched = default_scheduler();
    sched
        .submit(
            timed_label_typed(TaskType::MonitoringProbe, "trace-probe"),
            100,
            "p1",
            0,
        )
        .unwrap();

    let events = sched.drain_events();
    assert_eq!(events[0].trace_id, "trace-probe");
    assert_eq!(events[0].task_type, "monitoring_probe");
    assert_eq!(events[0].lane, "timed");
}

#[test]
fn sequential_batch_scheduling_drains_correctly() {
    let mut sched = default_scheduler();

    for i in 0..10 {
        sched
            .submit(ready_label(&format!("t{i}")), 0, &format!("p{i}"), 0)
            .unwrap();
    }

    // Schedule in batches of 3.
    let batch1 = sched.schedule_batch(3, 0);
    assert_eq!(batch1.len(), 3);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 7);

    let batch2 = sched.schedule_batch(3, 0);
    assert_eq!(batch2.len(), 3);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 4);

    let batch3 = sched.schedule_batch(3, 0);
    assert_eq!(batch3.len(), 3);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 1);

    let batch4 = sched.schedule_batch(3, 0);
    assert_eq!(batch4.len(), 1);
    assert_eq!(sched.queue_depth(SchedulerLane::Ready), 0);
}

#[test]
fn empty_schedule_batch_on_empty_scheduler() {
    let mut sched = default_scheduler();
    let batch = sched.schedule_batch(10, 100);
    assert!(batch.is_empty());
}

#[test]
fn lane_full_then_schedule_then_submit_again() {
    let cfg = LaneConfig {
        cancel_max_depth: 2,
        ..Default::default()
    };
    let mut sched = LaneScheduler::new(cfg);

    sched.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    sched.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    assert!(sched.submit(cancel_label("t3"), 0, "p3", 0).is_err());

    // Schedule one task to free up space.
    sched.schedule_batch(1, 0);
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 1);

    // Now we can submit again.
    sched.submit(cancel_label("t4"), 0, "p4", 0).unwrap();
    assert_eq!(sched.queue_depth(SchedulerLane::Cancel), 2);
}

#[test]
fn trace_id_validation_runs_before_lane_validation() {
    let mut sched = default_scheduler();
    // Both empty trace_id AND lane mismatch — EmptyTraceId should win.
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::CancelCleanup,
        trace_id: String::new(),
        priority_sub_band: 0,
    };
    let err = sched.submit(label, 0, "p", 0).unwrap_err();
    assert_eq!(err, LaneError::EmptyTraceId);
}

#[test]
fn serde_round_trip_of_scheduled_task_from_batch() {
    let mut sched = default_scheduler();
    sched
        .submit(cancel_label("serde-trace"), 0, "serde-payload", 42)
        .unwrap();

    let batch = sched.schedule_batch(10, 50);
    let task = &batch[0];

    let json = serde_json::to_string(task).expect("serialize");
    let restored: ScheduledTask = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*task, restored);
    assert_eq!(restored.label.trace_id, "serde-trace");
    assert_eq!(restored.payload_id, "serde-payload");
    assert_eq!(restored.submitted_at, 42);
}

#[test]
fn event_ordering_submit_then_schedule_then_complete() {
    let mut sched = default_scheduler();
    let id = sched.submit(ready_label("t1"), 0, "p1", 0).unwrap();
    sched.schedule_batch(10, 0);
    sched.complete_task(id, SchedulerLane::Ready);

    let events = sched.drain_events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event, "submit");
    assert_eq!(events[1].event, "schedule");
    assert_eq!(events[2].event, "complete");
}

#[test]
fn custom_config_respects_all_fields() {
    let cfg = LaneConfig {
        cancel_max_depth: 1,
        timed_max_depth: 1,
        ready_max_depth: 1,
        ready_min_throughput: 0,
    };
    let mut sched = LaneScheduler::new(cfg);

    sched.submit(cancel_label("c1"), 0, "p1", 0).unwrap();
    assert!(sched.submit(cancel_label("c2"), 0, "p2", 0).is_err());

    sched.submit(timed_label("ti1"), 50, "p3", 0).unwrap();
    assert!(sched.submit(timed_label("ti2"), 60, "p4", 0).is_err());

    sched.submit(ready_label("r1"), 0, "p5", 0).unwrap();
    assert!(sched.submit(ready_label("r2"), 0, "p6", 0).is_err());
}

#[test]
fn large_batch_stress_test() {
    let cfg = LaneConfig {
        cancel_max_depth: 10000,
        timed_max_depth: 10000,
        ready_max_depth: 10000,
        ready_min_throughput: 1,
    };
    let mut sched = LaneScheduler::new(cfg);

    // Submit many tasks.
    for i in 0..100 {
        sched
            .submit(cancel_label(&format!("c{i}")), 0, &format!("cp{i}"), i)
            .unwrap();
    }
    for i in 0..100 {
        sched
            .submit(timed_label(&format!("ti{i}")), i + 1, &format!("tp{i}"), i)
            .unwrap();
    }
    for i in 0..100 {
        sched
            .submit(ready_label(&format!("r{i}")), 0, &format!("rp{i}"), i)
            .unwrap();
    }

    assert_eq!(sched.total_queue_depth(), 300);

    let batch = sched.schedule_batch(500, 200);
    // All 100 cancel + all 100 timed (all deadlines <= 200) + all 100 ready
    assert_eq!(batch.len(), 300);
    assert_eq!(sched.total_queue_depth(), 0);

    // Verify ordering: cancel first, then timed sorted by deadline, then ready FIFO.
    let first_timed_idx = batch
        .iter()
        .position(|t| t.label.lane == SchedulerLane::Timed)
        .unwrap();
    let first_ready_idx = batch
        .iter()
        .position(|t| t.label.lane == SchedulerLane::Ready)
        .unwrap();
    assert!(first_timed_idx >= 100); // After all cancel tasks
    assert!(first_ready_idx >= 200); // After all timed tasks
}

#[test]
fn timed_task_with_deadline_exactly_equal_to_current_is_scheduled() {
    let mut sched = default_scheduler();
    sched
        .submit(timed_label("t1"), 100, "exact-match", 0)
        .unwrap();

    let batch = sched.schedule_batch(10, 100);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].payload_id, "exact-match");
}

#[test]
fn scheduler_debug_format_exists() {
    let sched = default_scheduler();
    let debug = format!("{:?}", sched);
    assert!(debug.contains("LaneScheduler"));
}
