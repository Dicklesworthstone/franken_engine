//! Enrichment integration tests for `scheduler_lane`.
//!
//! Covers: SchedulerLane Display + serde, TaskType.required_lane correctness,
//! LaneScheduler submit/schedule_batch/complete lifecycle, lane priority
//! ordering, anti-starvation guarantees, queue depth limits, lane mismatch
//! errors, empty trace rejection, timed-lane deadline sorting, task
//! completion metrics, event emission, event count tracking, config
//! defaults, serde roundtrips, and deterministic scheduling replay.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

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

fn default_scheduler() -> LaneScheduler {
    LaneScheduler::new(LaneConfig::default())
}

// =========================================================================
// 1. SchedulerLane — Display + serde
// =========================================================================

#[test]
fn enrichment_scheduler_lane_display() {
    assert_eq!(SchedulerLane::Cancel.to_string(), "cancel");
    assert_eq!(SchedulerLane::Timed.to_string(), "timed");
    assert_eq!(SchedulerLane::Ready.to_string(), "ready");
}

#[test]
fn enrichment_scheduler_lane_serde_all() {
    for lane in &[SchedulerLane::Cancel, SchedulerLane::Timed, SchedulerLane::Ready] {
        let json = serde_json::to_string(lane).unwrap();
        let back: SchedulerLane = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, back);
    }
}

#[test]
fn enrichment_scheduler_lane_ordering_deterministic() {
    let mut lanes = vec![SchedulerLane::Ready, SchedulerLane::Cancel, SchedulerLane::Timed];
    lanes.sort();
    let mut lanes2 = lanes.clone();
    lanes2.sort();
    assert_eq!(lanes, lanes2);
}

// =========================================================================
// 2. TaskType — required_lane mapping
// =========================================================================

#[test]
fn enrichment_task_type_cancel_lane_types() {
    assert_eq!(TaskType::CancelCleanup.required_lane(), SchedulerLane::Cancel);
    assert_eq!(TaskType::QuarantineExec.required_lane(), SchedulerLane::Cancel);
    assert_eq!(TaskType::ForcedDrain.required_lane(), SchedulerLane::Cancel);
}

#[test]
fn enrichment_task_type_timed_lane_types() {
    assert_eq!(TaskType::LeaseRenewal.required_lane(), SchedulerLane::Timed);
    assert_eq!(TaskType::MonitoringProbe.required_lane(), SchedulerLane::Timed);
    assert_eq!(TaskType::EvidenceFlush.required_lane(), SchedulerLane::Timed);
    assert_eq!(
        TaskType::EpochBarrierTimeout.required_lane(),
        SchedulerLane::Timed
    );
}

#[test]
fn enrichment_task_type_ready_lane_types() {
    assert_eq!(
        TaskType::ExtensionDispatch.required_lane(),
        SchedulerLane::Ready
    );
    assert_eq!(TaskType::GcCycle.required_lane(), SchedulerLane::Ready);
    assert_eq!(TaskType::PolicyIteration.required_lane(), SchedulerLane::Ready);
    assert_eq!(TaskType::RemoteSync.required_lane(), SchedulerLane::Ready);
    assert_eq!(TaskType::SagaStepExec.required_lane(), SchedulerLane::Ready);
}

#[test]
fn enrichment_task_type_display_all_non_empty() {
    let types = [
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
    for tt in types {
        assert!(!tt.to_string().is_empty());
    }
}

#[test]
fn enrichment_task_type_serde_roundtrip_all() {
    let types = [
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
    for tt in types {
        let json = serde_json::to_string(&tt).unwrap();
        let back: TaskType = serde_json::from_str(&json).unwrap();
        assert_eq!(tt, back);
    }
}

// =========================================================================
// 3. TaskId — Display
// =========================================================================

#[test]
fn enrichment_task_id_display() {
    let id = TaskId(42);
    assert_eq!(id.to_string(), "task:42");
}

#[test]
fn enrichment_task_id_serde_roundtrip() {
    let id = TaskId(999);
    let json = serde_json::to_string(&id).unwrap();
    let back: TaskId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// =========================================================================
// 4. LaneConfig — defaults
// =========================================================================

#[test]
fn enrichment_lane_config_default_values() {
    let c = LaneConfig::default();
    assert_eq!(c.cancel_max_depth, 256);
    assert_eq!(c.timed_max_depth, 1024);
    assert_eq!(c.ready_max_depth, 4096);
    assert_eq!(c.ready_min_throughput, 1);
}

#[test]
fn enrichment_lane_config_serde_roundtrip() {
    let c = LaneConfig {
        cancel_max_depth: 10,
        timed_max_depth: 20,
        ready_max_depth: 30,
        ready_min_throughput: 5,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: LaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// =========================================================================
// 5. LaneScheduler — submit
// =========================================================================

#[test]
fn enrichment_submit_returns_unique_task_ids() {
    let mut s = default_scheduler();
    let id1 = s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    let id2 = s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    let id3 = s.submit(ready_label("t3"), 0, "p3", 0).unwrap();
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
}

#[test]
fn enrichment_submit_increments_queue_depth() {
    let mut s = default_scheduler();
    assert_eq!(s.queue_depth(SchedulerLane::Cancel), 0);
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    assert_eq!(s.queue_depth(SchedulerLane::Cancel), 1);
    s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    assert_eq!(s.queue_depth(SchedulerLane::Cancel), 2);
}

#[test]
fn enrichment_submit_empty_trace_rejected() {
    let mut s = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Cancel,
        task_type: TaskType::CancelCleanup,
        trace_id: String::new(),
        priority_sub_band: 0,
    };
    let err = s.submit(label, 0, "p", 0).unwrap_err();
    assert!(matches!(err, LaneError::EmptyTraceId));
}

#[test]
fn enrichment_submit_lane_mismatch_rejected() {
    let mut s = default_scheduler();
    let label = TaskLabel {
        lane: SchedulerLane::Ready,
        task_type: TaskType::CancelCleanup, // cancel type in ready lane
        trace_id: "t".into(),
        priority_sub_band: 0,
    };
    let err = s.submit(label, 0, "p", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneMismatch { .. }));
}

#[test]
fn enrichment_submit_queue_full_rejected() {
    let config = LaneConfig {
        cancel_max_depth: 2,
        timed_max_depth: 2,
        ready_max_depth: 2,
        ready_min_throughput: 1,
    };
    let mut s = LaneScheduler::new(config);
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    let err = s.submit(cancel_label("t3"), 0, "p3", 0).unwrap_err();
    assert!(matches!(err, LaneError::LaneFull { .. }));
}

// =========================================================================
// 6. LaneScheduler — schedule_batch priority ordering
// =========================================================================

#[test]
fn enrichment_cancel_tasks_scheduled_before_timed() {
    let mut s = default_scheduler();
    s.submit(timed_label("t-timed"), 10, "p-timed", 0).unwrap();
    s.submit(cancel_label("t-cancel"), 0, "p-cancel", 0).unwrap();
    let batch = s.schedule_batch(10, 100);
    assert!(batch.len() >= 2);
    assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    assert_eq!(batch[1].label.lane, SchedulerLane::Timed);
}

#[test]
fn enrichment_timed_tasks_scheduled_before_ready() {
    let mut s = default_scheduler();
    s.submit(ready_label("t-ready"), 0, "p-ready", 0).unwrap();
    s.submit(timed_label("t-timed"), 10, "p-timed", 0).unwrap();
    let batch = s.schedule_batch(10, 100);
    // timed should be before ready (but after cancel if any)
    let timed_idx = batch.iter().position(|t| t.label.lane == SchedulerLane::Timed);
    let ready_idx = batch.iter().position(|t| t.label.lane == SchedulerLane::Ready);
    assert!(timed_idx.unwrap() < ready_idx.unwrap());
}

#[test]
fn enrichment_cancel_timed_ready_full_priority_order() {
    let mut s = default_scheduler();
    s.submit(ready_label("r1"), 0, "pr", 0).unwrap();
    s.submit(timed_label("t1"), 5, "pt", 0).unwrap();
    s.submit(cancel_label("c1"), 0, "pc", 0).unwrap();
    let batch = s.schedule_batch(10, 100);
    assert_eq!(batch[0].label.lane, SchedulerLane::Cancel);
    assert_eq!(batch[1].label.lane, SchedulerLane::Timed);
    assert_eq!(batch[2].label.lane, SchedulerLane::Ready);
}

// =========================================================================
// 7. Timed lane — deadline sorting
// =========================================================================

#[test]
fn enrichment_timed_tasks_sorted_by_deadline() {
    let mut s = default_scheduler();
    s.submit(timed_label("t-late"), 100, "p-late", 0).unwrap();
    s.submit(timed_label("t-early"), 5, "p-early", 0).unwrap();
    s.submit(timed_label("t-mid"), 50, "p-mid", 0).unwrap();
    let batch = s.schedule_batch(10, 200);
    let timed_tasks: Vec<_> = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Timed)
        .collect();
    assert_eq!(timed_tasks.len(), 3);
    assert!(timed_tasks[0].deadline_tick <= timed_tasks[1].deadline_tick);
    assert!(timed_tasks[1].deadline_tick <= timed_tasks[2].deadline_tick);
}

#[test]
fn enrichment_timed_tasks_not_due_remain_in_queue() {
    let mut s = default_scheduler();
    s.submit(timed_label("t-future"), 1000, "p", 0).unwrap();
    let batch = s.schedule_batch(10, 10); // current_ticks=10, deadline=1000
    let timed_in_batch = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Timed)
        .count();
    assert_eq!(timed_in_batch, 0);
    assert_eq!(s.queue_depth(SchedulerLane::Timed), 1);
}

// =========================================================================
// 8. Anti-starvation guarantee
// =========================================================================

#[test]
fn enrichment_ready_tasks_get_minimum_throughput() {
    let config = LaneConfig {
        cancel_max_depth: 256,
        timed_max_depth: 1024,
        ready_max_depth: 4096,
        ready_min_throughput: 2,
    };
    let mut s = LaneScheduler::new(config);
    // Fill cancel lane
    for i in 0..5 {
        s.submit(cancel_label(&format!("c{i}")), 0, &format!("pc{i}"), 0)
            .unwrap();
    }
    // Add ready tasks
    for i in 0..5 {
        s.submit(ready_label(&format!("r{i}")), 0, &format!("pr{i}"), 0)
            .unwrap();
    }
    // batch_size=5 means 5 cancel consumed, then anti-starvation kicks in
    let batch = s.schedule_batch(5, 0);
    let ready_count = batch
        .iter()
        .filter(|t| t.label.lane == SchedulerLane::Ready)
        .count();
    assert!(ready_count >= 2, "anti-starvation should guarantee at least 2 ready tasks, got {ready_count}");
}

// =========================================================================
// 9. complete_task — metrics
// =========================================================================

#[test]
fn enrichment_complete_task_increments_completed() {
    let mut s = default_scheduler();
    let id = s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.complete_task(id, SchedulerLane::Cancel);
    let metrics = s.lane_metrics();
    assert_eq!(metrics["cancel"].tasks_completed, 1);
}

#[test]
fn enrichment_complete_task_emits_event() {
    let mut s = default_scheduler();
    let id = s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.drain_events(); // clear submit events
    s.complete_task(id, SchedulerLane::Cancel);
    let events = s.drain_events();
    assert!(events.iter().any(|e| e.event == "complete"));
}

// =========================================================================
// 10. LaneMetrics — initial state
// =========================================================================

#[test]
fn enrichment_initial_metrics_all_lanes_zeroed() {
    let s = default_scheduler();
    let metrics = s.lane_metrics();
    for lane in &["cancel", "timed", "ready"] {
        let m = &metrics[*lane];
        assert_eq!(m.queue_depth, 0);
        assert_eq!(m.tasks_submitted, 0);
        assert_eq!(m.tasks_scheduled, 0);
        assert_eq!(m.tasks_completed, 0);
        assert_eq!(m.tasks_timed_out, 0);
    }
}

#[test]
fn enrichment_lane_metrics_serde_roundtrip() {
    let m = LaneMetrics {
        lane: "cancel".into(),
        queue_depth: 5,
        tasks_submitted: 10,
        tasks_scheduled: 8,
        tasks_completed: 7,
        tasks_timed_out: 1,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: LaneMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// =========================================================================
// 11. total_queue_depth
// =========================================================================

#[test]
fn enrichment_total_queue_depth_sum_of_all_lanes() {
    let mut s = default_scheduler();
    s.submit(cancel_label("c1"), 0, "p", 0).unwrap();
    s.submit(timed_label("t1"), 100, "p", 0).unwrap();
    s.submit(ready_label("r1"), 0, "p", 0).unwrap();
    s.submit(ready_label("r2"), 0, "p", 0).unwrap();
    assert_eq!(s.total_queue_depth(), 4);
}

// =========================================================================
// 12. drain_events and event_counts
// =========================================================================

#[test]
fn enrichment_drain_events_clears_buffer() {
    let mut s = default_scheduler();
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    assert!(!s.drain_events().is_empty());
    assert!(s.drain_events().is_empty());
}

#[test]
fn enrichment_event_counts_track_submit_schedule() {
    let mut s = default_scheduler();
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    s.schedule_batch(10, 0);
    let counts = s.event_counts();
    assert_eq!(*counts.get("submit").unwrap_or(&0), 2);
    assert_eq!(*counts.get("schedule").unwrap_or(&0), 2);
}

// =========================================================================
// 13. LaneError — Display and serde
// =========================================================================

#[test]
fn enrichment_lane_error_display_lane_mismatch() {
    let e = LaneError::LaneMismatch {
        task_type: "cancel_cleanup".into(),
        declared_lane: "ready".into(),
        required_lane: "cancel".into(),
    };
    let s = e.to_string();
    assert!(s.contains("cancel_cleanup"));
    assert!(s.contains("ready"));
    assert!(s.contains("cancel"));
}

#[test]
fn enrichment_lane_error_display_lane_full() {
    let e = LaneError::LaneFull {
        lane: "cancel".into(),
        max_depth: 256,
    };
    let s = e.to_string();
    assert!(s.contains("cancel"));
    assert!(s.contains("256"));
}

#[test]
fn enrichment_lane_error_display_empty_trace() {
    let e = LaneError::EmptyTraceId;
    assert!(e.to_string().contains("trace_id"));
}

#[test]
fn enrichment_lane_error_is_std_error() {
    let e = LaneError::EmptyTraceId;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn enrichment_lane_error_serde_roundtrip_all_variants() {
    let errors = [
        LaneError::LaneMismatch {
            task_type: "cancel_cleanup".into(),
            declared_lane: "ready".into(),
            required_lane: "cancel".into(),
        },
        LaneError::LaneFull {
            lane: "timed".into(),
            max_depth: 1024,
        },
        LaneError::TaskNotFound { task_id: 42 },
        LaneError::EmptyTraceId,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: LaneError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// =========================================================================
// 14. SchedulerEvent — serde
// =========================================================================

#[test]
fn enrichment_scheduler_event_serde_roundtrip() {
    let event = SchedulerEvent {
        task_id: 42,
        lane: "cancel".into(),
        task_type: "cancel_cleanup".into(),
        trace_id: "trace-1".into(),
        queue_position: 0,
        event: "submit".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SchedulerEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// =========================================================================
// 15. Batch size zero schedules nothing
// =========================================================================

#[test]
fn enrichment_batch_size_zero_returns_empty() {
    let mut s = default_scheduler();
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.submit(ready_label("t2"), 0, "p2", 0).unwrap();
    let batch = s.schedule_batch(0, 0);
    assert!(batch.is_empty());
}

// =========================================================================
// 16. Deterministic replay
// =========================================================================

#[test]
fn enrichment_deterministic_scheduling() {
    let run = || {
        let mut s = default_scheduler();
        s.submit(cancel_label("c1"), 0, "pc1", 0).unwrap();
        s.submit(timed_label("t1"), 10, "pt1", 0).unwrap();
        s.submit(ready_label("r1"), 0, "pr1", 0).unwrap();
        s.schedule_batch(10, 100)
    };

    let batch1 = run();
    let batch2 = run();
    assert_eq!(batch1.len(), batch2.len());
    for (a, b) in batch1.iter().zip(batch2.iter()) {
        assert_eq!(a.label.lane, b.label.lane);
        assert_eq!(a.label.task_type, b.label.task_type);
        assert_eq!(a.payload_id, b.payload_id);
    }
}

// =========================================================================
// 17. Submit metrics tracking
// =========================================================================

#[test]
fn enrichment_submit_increments_tasks_submitted_metric() {
    let mut s = default_scheduler();
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    let metrics = s.lane_metrics();
    assert_eq!(metrics["cancel"].tasks_submitted, 2);
}

#[test]
fn enrichment_schedule_batch_increments_tasks_scheduled_metric() {
    let mut s = default_scheduler();
    s.submit(cancel_label("t1"), 0, "p1", 0).unwrap();
    s.submit(cancel_label("t2"), 0, "p2", 0).unwrap();
    s.schedule_batch(10, 0);
    let metrics = s.lane_metrics();
    assert_eq!(metrics["cancel"].tasks_scheduled, 2);
}

// =========================================================================
// 18. TaskLabel serde
// =========================================================================

#[test]
fn enrichment_task_label_serde_roundtrip() {
    let label = TaskLabel {
        lane: SchedulerLane::Timed,
        task_type: TaskType::MonitoringProbe,
        trace_id: "trace-99".into(),
        priority_sub_band: 3,
    };
    let json = serde_json::to_string(&label).unwrap();
    let back: TaskLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(label, back);
}

// =========================================================================
// 19. ScheduledTask serde
// =========================================================================

#[test]
fn enrichment_scheduled_task_serde_roundtrip() {
    let task = ScheduledTask {
        task_id: TaskId(7),
        label: ready_label("trace-42"),
        deadline_tick: 100,
        submitted_at: 50,
        payload_id: "payload-x".into(),
    };
    let json = serde_json::to_string(&task).unwrap();
    let back: ScheduledTask = serde_json::from_str(&json).unwrap();
    assert_eq!(task, back);
}
