//! Integration tests for queueing_admission_control module.
//!
//! Bead: bd-1lsy.7.11.2 [RGC-611B]

use frankenengine_engine::queueing_admission_control::*;
use frankenengine_engine::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn default_controller() -> AdmissionController {
    AdmissionController::new(AdmissionControlPolicy::default())
}

fn controller_with_partitions() -> AdmissionController {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 32);
    ctrl.init_partition(ExecutionStage::GcPause, 16);
    ctrl.init_partition(ExecutionStage::ModuleLoad, 8);
    ctrl.init_partition(ExecutionStage::CompileOptimized, 16);
    ctrl
}

fn small_controller() -> AdmissionController {
    let mut policy = AdmissionControlPolicy::default();
    policy.max_queue_depth = 5;
    policy.token_capacity = 10;
    policy.token_refill_rate = 2;
    policy.max_receipts = 10;
    AdmissionController::new(policy)
}

// ---------------------------------------------------------------------------
// E2E admission flow tests
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_admit_process_complete() {
    let mut ctrl = controller_with_partitions();
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_eq!(r.decision, AdmissionDecision::Admit);
    assert_eq!(ctrl.global_queue_depth, 1);
    ctrl.record_completion(ExecutionStage::Parse);
    assert_eq!(ctrl.global_queue_depth, 0);
    let summary = ctrl.summary();
    assert_eq!(summary.total_admitted, 1);
}

#[test]
fn test_e2e_queue_fill_then_shed() {
    let mut ctrl = small_controller();
    // Fill queue to capacity
    for _ in 0..5 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    // Next should be shed (queue full)
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::QueueFull { .. }
        }
    ));
}

#[test]
fn test_e2e_token_exhaustion_and_refill() {
    let mut policy = AdmissionControlPolicy::default();
    policy.max_queue_depth = 1000;
    policy.token_capacity = 3;
    policy.token_refill_rate = 1;
    policy.tokens_per_admission = 1;
    let mut ctrl = AdmissionController::new(policy);

    // Consume all tokens
    for _ in 0..3 {
        let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(!matches!(r.decision, AdmissionDecision::Shed { .. }));
        ctrl.record_completion(ExecutionStage::Parse);
    }

    // Should be shed now (no tokens)
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::TokensExhausted { .. }
        }
    ));

    // Tick refills 1 token
    ctrl.tick();
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(!matches!(r.decision, AdmissionDecision::Shed { .. }));
}

#[test]
fn test_e2e_utilization_shedding_priority_aware() {
    let mut ctrl = controller_with_partitions();
    ctrl.update_utilization(910_000); // 91% — above shed_threshold (90%)

    // Normal should still be admitted
    let r_normal = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(!matches!(r_normal.decision, AdmissionDecision::Shed { .. }));
    ctrl.record_completion(ExecutionStage::Parse);

    // Low should be shed (priority too low for load)
    let r_low = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Low);
    assert!(matches!(
        r_low.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::PriorityShed { .. }
        }
    ));

    // BestEffort should also be shed
    let r_be = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::BestEffort);
    assert!(matches!(
        r_be.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::PriorityShed { .. }
        }
    ));
}

#[test]
fn test_e2e_emergency_sheds_all_except_critical() {
    let mut ctrl = controller_with_partitions();
    ctrl.update_utilization(960_000); // 96% — above emergency (95%)

    // High should be shed
    let r_high = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::High);
    assert!(matches!(
        r_high.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::UtilizationOverload { .. }
        }
    ));

    // Critical should still get through
    let r_crit = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Critical);
    assert!(!matches!(
        r_crit.decision,
        AdmissionDecision::Shed { .. }
    ));
}

#[test]
fn test_e2e_stage_partition_isolation() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::ModuleLoad, 2);
    ctrl.init_partition(ExecutionStage::GcPause, 2);

    // Fill module load partition
    ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);

    // Module load should be shed (stage full)
    let r = ctrl.check_admission(ExecutionStage::ModuleLoad, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));

    // GC should still accept
    let r_gc = ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);
    assert!(!matches!(
        r_gc.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));
}

// ---------------------------------------------------------------------------
// Worker pool sizing
// ---------------------------------------------------------------------------

#[test]
fn test_sizing_light_load() {
    let input = SizingInput {
        arrival_rate_millionths: 10_000, // very low
        mean_service_ns: 1_000_000,      // 1ms
        target_p99_ns: 50_000_000,       // 50ms
        target_utilization_millionths: 800_000,
        max_workers: 16,
    };
    let sizing = compute_worker_pool_sizing(&input);
    assert_eq!(sizing.recommended_workers, 1);
}

#[test]
fn test_sizing_deterministic() {
    let input = SizingInput {
        arrival_rate_millionths: 500_000,
        mean_service_ns: 2_000_000,
        target_p99_ns: 20_000_000,
        target_utilization_millionths: 750_000,
        max_workers: 32,
    };
    let s1 = compute_worker_pool_sizing(&input);
    let s2 = compute_worker_pool_sizing(&input);
    assert_eq!(s1, s2);
}

#[test]
fn test_sizing_max_useful_bounded() {
    let input = SizingInput {
        arrival_rate_millionths: 100_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 64,
    };
    let sizing = compute_worker_pool_sizing(&input);
    assert!(sizing.max_useful_workers <= 64);
    assert!(sizing.max_useful_workers >= 1);
}

// ---------------------------------------------------------------------------
// Receipt audit chain
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_sequence_continuous() {
    let mut ctrl = controller_with_partitions();
    for _ in 0..10 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    let receipts = ctrl.receipts();
    for i in 1..receipts.len() {
        assert_eq!(receipts[i].sequence, receipts[i - 1].sequence + 1);
    }
}

#[test]
fn test_receipt_captures_queue_snapshot() {
    let mut ctrl = default_controller();
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(r.queue_depth_snapshot > 0);
}

#[test]
fn test_receipt_captures_utilization() {
    let mut ctrl = default_controller();
    ctrl.update_utilization(500_000);
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_eq!(r.utilization_snapshot_millionths, 500_000);
}

#[test]
fn test_receipt_has_schema_version() {
    let mut ctrl = default_controller();
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_eq!(r.schema_version, ADMISSION_SCHEMA_VERSION);
}

#[test]
fn test_receipt_unique_hashes() {
    let mut ctrl = default_controller();
    let r1 = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let r2 = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn test_receipts_bounded_eviction() {
    let mut policy = AdmissionControlPolicy::default();
    policy.max_receipts = 5;
    let mut ctrl = AdmissionController::new(policy);
    for _ in 0..20 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    assert_eq!(ctrl.receipts().len(), 5);
    // Should have the most recent receipts
    let last = ctrl.receipts().last().unwrap();
    assert_eq!(last.sequence, 20);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_schema_version() {
    let ctrl = default_controller();
    let manifest = AdmissionControlManifest::from_controller(&ctrl);
    assert_eq!(manifest.schema_version, ADMISSION_SCHEMA_VERSION);
    assert_eq!(manifest.bead_id, ADMISSION_BEAD_ID);
}

#[test]
fn test_manifest_captures_partitions() {
    let ctrl = controller_with_partitions();
    let manifest = AdmissionControlManifest::from_controller(&ctrl);
    assert_eq!(manifest.partitions.len(), 4);
}

#[test]
fn test_manifest_with_sizing() {
    let ctrl = default_controller();
    let sizing = compute_worker_pool_sizing(&SizingInput {
        arrival_rate_millionths: 100_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 8,
    });
    let manifest = AdmissionControlManifest::from_controller(&ctrl).with_sizing(sizing);
    assert!(manifest.sizing.is_some());
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn test_serde_admission_decision() {
    let d = AdmissionDecision::Queue {
        estimated_wait_ns: 5000,
        position: 3,
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn test_serde_shed_reason() {
    let r = ShedReason::PriorityShed {
        item_priority: AdmissionPriority::Low,
        min_admitted_priority: AdmissionPriority::Normal,
    };
    let json = serde_json::to_string(&r).unwrap();
    let restored: ShedReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, restored);
}

#[test]
fn test_serde_controller_roundtrip() {
    let mut ctrl = controller_with_partitions();
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::High);
    let json = serde_json::to_string(&ctrl).unwrap();
    let restored: AdmissionController = serde_json::from_str(&json).unwrap();
    assert_eq!(ctrl.decision_sequence(), restored.decision_sequence());
    assert_eq!(ctrl.global_queue_depth, restored.global_queue_depth);
}

#[test]
fn test_serde_manifest_roundtrip() {
    let mut ctrl = controller_with_partitions();
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let manifest = AdmissionControlManifest::from_controller(&ctrl);
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: AdmissionControlManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn test_serde_priority_roundtrip() {
    for p in [
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let restored: AdmissionPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

#[test]
fn test_summary_mixed_decisions() {
    let mut ctrl = small_controller();
    // Fill queue (5 items)
    for _ in 0..5 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    // Next should be shed
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let summary = ctrl.summary();
    assert!(summary.total_shed > 0);
    assert_eq!(summary.total_checks, summary.total_admitted + summary.total_queued + summary.total_shed);
}

#[test]
fn test_summary_partition_count() {
    let ctrl = controller_with_partitions();
    let summary = ctrl.summary();
    assert_eq!(summary.partition_count, 4);
}

// ---------------------------------------------------------------------------
// Token bucket edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_token_bucket_exact_consume() {
    let mut tb = TokenBucket::new(10, 5);
    assert!(tb.try_consume(10));
    assert_eq!(tb.available, 0);
    assert!(tb.is_empty());
}

#[test]
fn test_token_bucket_multiple_refills() {
    let mut tb = TokenBucket::new(100, 10);
    tb.try_consume(100);
    for _ in 0..10 {
        tb.refill();
    }
    assert_eq!(tb.available, 100); // capped at capacity
}

#[test]
fn test_token_bucket_consumed_tracking() {
    let mut tb = TokenBucket::new(100, 10);
    tb.try_consume(30);
    tb.try_consume(20);
    assert_eq!(tb.total_consumed, 50);
}

// ---------------------------------------------------------------------------
// Queue partition edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_partition_complete_never_underflows() {
    let mut p = QueuePartition::new(ExecutionStage::Parse, 10);
    p.complete(); // complete with 0 depth
    assert_eq!(p.current_depth, 0); // should stay at 0
}

// ---------------------------------------------------------------------------
// Policy configuration
// ---------------------------------------------------------------------------

#[test]
fn test_custom_stage_limits() {
    let mut policy = AdmissionControlPolicy::default();
    policy.stage_max_depths.insert(ExecutionStage::GcPause, 4);
    let mut ctrl = AdmissionController::new(policy);
    ctrl.init_partition(ExecutionStage::GcPause, 4);
    for _ in 0..4 {
        ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);
    }
    let r = ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));
}

#[test]
fn test_policy_slo_percentile() {
    let mut policy = AdmissionControlPolicy::default();
    policy.slo_percentile = LatencyPercentile::P999;
    policy.slo_target_ns = 100_000_000; // 100ms
    let ctrl = AdmissionController::new(policy);
    assert_eq!(ctrl.policy.slo_target_ns, 100_000_000);
}
