//! Integration tests for queueing_admission_control module.
//!
//! Bead: bd-1lsy.7.11.2 [RGC-611B]

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
    let policy = AdmissionControlPolicy {
        max_queue_depth: 5,
        token_capacity: 10,
        token_refill_rate: 2,
        max_receipts: 10,
        ..Default::default()
    };
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
    let policy = AdmissionControlPolicy {
        max_queue_depth: 1000,
        token_capacity: 3,
        token_refill_rate: 1,
        tokens_per_admission: 1,
        ..Default::default()
    };
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
    assert!(!matches!(r_crit.decision, AdmissionDecision::Shed { .. }));
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
    let policy = AdmissionControlPolicy {
        max_receipts: 5,
        ..Default::default()
    };
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
    assert_eq!(
        summary.total_checks,
        summary.total_admitted + summary.total_queued + summary.total_shed
    );
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
    let policy = {
        let mut p = AdmissionControlPolicy::default();
        p.stage_max_depths.insert(ExecutionStage::GcPause, 4);
        p
    };
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
    let policy = AdmissionControlPolicy {
        slo_percentile: LatencyPercentile::P999,
        slo_target_ns: 100_000_000, // 100ms
        ..Default::default()
    };
    let ctrl = AdmissionController::new(policy);
    assert_eq!(ctrl.policy.slo_target_ns, 100_000_000);
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

#[test]
fn test_display_admission_priority_all_variants() {
    assert_eq!(format!("{}", AdmissionPriority::Critical), "critical");
    assert_eq!(format!("{}", AdmissionPriority::High), "high");
    assert_eq!(format!("{}", AdmissionPriority::Normal), "normal");
    assert_eq!(format!("{}", AdmissionPriority::Low), "low");
    assert_eq!(format!("{}", AdmissionPriority::BestEffort), "best_effort");
}

#[test]
fn test_display_admission_decision_all_variants() {
    let admit = AdmissionDecision::Admit;
    assert_eq!(format!("{admit}"), "admit");

    let queue = AdmissionDecision::Queue {
        estimated_wait_ns: 1000,
        position: 7,
    };
    assert_eq!(format!("{queue}"), "queue(pos=7)");

    let shed = AdmissionDecision::Shed {
        reason: ShedReason::QueueFull {
            current_depth: 100,
            max_depth: 100,
        },
    };
    assert!(format!("{shed}").starts_with("shed("));
}

#[test]
fn test_display_shed_reason_all_variants() {
    let queue_full = ShedReason::QueueFull {
        current_depth: 50,
        max_depth: 100,
    };
    assert_eq!(format!("{queue_full}"), "queue_full(50/100)");

    let tokens = ShedReason::TokensExhausted {
        tokens_available: 0,
        tokens_required: 5,
    };
    assert_eq!(format!("{tokens}"), "tokens_exhausted(0/5)");

    let util = ShedReason::UtilizationOverload {
        current_utilization_millionths: 960_000,
        shed_threshold_millionths: 950_000,
    };
    assert_eq!(format!("{util}"), "utilization_overload(960000/1M)");

    let priority = ShedReason::PriorityShed {
        item_priority: AdmissionPriority::Low,
        min_admitted_priority: AdmissionPriority::Normal,
    };
    assert_eq!(format!("{priority}"), "priority_shed(low<normal)");

    let stage = ShedReason::StageBudgetExhausted {
        stage: ExecutionStage::Parse,
        stage_queue_depth: 10,
        stage_max_depth: 10,
    };
    let stage_str = format!("{stage}");
    assert!(stage_str.contains("stage_exhausted"));
    assert!(stage_str.contains("10/10"));
}

#[test]
fn test_display_admission_receipt() {
    let mut ctrl = default_controller();
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let display = format!("{r}");
    assert!(display.starts_with("Receipt(adm-"));
    assert!(display.contains("normal"));
}

// ---------------------------------------------------------------------------
// Priority rank and ordering
// ---------------------------------------------------------------------------

#[test]
fn test_priority_rank_ordering() {
    let priorities = [
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ];
    for i in 0..priorities.len() - 1 {
        assert!(
            priorities[i].rank() < priorities[i + 1].rank(),
            "{:?} should have lower rank than {:?}",
            priorities[i],
            priorities[i + 1]
        );
    }
}

#[test]
fn test_priority_is_unshedable() {
    assert!(AdmissionPriority::Critical.is_unshedable());
    assert!(!AdmissionPriority::High.is_unshedable());
    assert!(!AdmissionPriority::Normal.is_unshedable());
    assert!(!AdmissionPriority::Low.is_unshedable());
    assert!(!AdmissionPriority::BestEffort.is_unshedable());
}

// ---------------------------------------------------------------------------
// Token bucket edge cases (fill ratio, zero capacity)
// ---------------------------------------------------------------------------

#[test]
fn test_token_bucket_fill_ratio_millionths() {
    let tb = TokenBucket::new(100, 10);
    // Full bucket: fill ratio should be 1_000_000
    assert_eq!(tb.fill_ratio_millionths(), 1_000_000);

    let mut tb2 = TokenBucket::new(100, 10);
    tb2.try_consume(50);
    // Half full: 500_000
    assert_eq!(tb2.fill_ratio_millionths(), 500_000);

    let mut tb3 = TokenBucket::new(100, 10);
    tb3.try_consume(100);
    // Empty: 0
    assert_eq!(tb3.fill_ratio_millionths(), 0);
}

#[test]
fn test_token_bucket_zero_capacity() {
    let tb = TokenBucket::new(0, 0);
    assert!(tb.is_empty());
    assert_eq!(tb.fill_ratio_millionths(), 0);
    // Cannot consume anything
    let mut tb2 = TokenBucket::new(0, 5);
    assert!(!tb2.try_consume(1));
    // Refill with zero capacity stays at zero
    tb2.refill();
    assert_eq!(tb2.available, 0);
}

// ---------------------------------------------------------------------------
// Queue partition methods
// ---------------------------------------------------------------------------

#[test]
fn test_queue_partition_is_full_and_utilization() {
    let mut p = QueuePartition::new(ExecutionStage::GcPause, 4);
    assert!(!p.is_full());
    assert_eq!(p.utilization_millionths(), 0);

    p.admit();
    p.admit();
    // 2/4 = 50% = 500_000 millionths
    assert_eq!(p.utilization_millionths(), 500_000);
    assert!(!p.is_full());

    p.admit();
    p.admit();
    // 4/4 = full
    assert!(p.is_full());
    assert_eq!(p.utilization_millionths(), 1_000_000);
    assert_eq!(p.total_admitted, 4);
}

#[test]
fn test_queue_partition_zero_max_depth() {
    let p = QueuePartition::new(ExecutionStage::Parse, 0);
    assert!(p.is_full()); // 0 >= 0
    assert_eq!(p.utilization_millionths(), 0); // division by zero guarded
}

#[test]
fn test_queue_partition_shed_tracking() {
    let mut p = QueuePartition::new(ExecutionStage::ModuleLoad, 2);
    p.admit();
    p.record_shed();
    p.record_shed();
    assert_eq!(p.total_shed, 2);
    assert_eq!(p.total_admitted, 1);
    assert_eq!(p.current_depth, 1);
}

// ---------------------------------------------------------------------------
// Serde round-trips for additional types
// ---------------------------------------------------------------------------

#[test]
fn test_serde_token_bucket_roundtrip() {
    let mut tb = TokenBucket::new(256, 32);
    tb.try_consume(100);
    tb.refill();
    let json = serde_json::to_string(&tb).unwrap();
    let restored: TokenBucket = serde_json::from_str(&json).unwrap();
    assert_eq!(tb, restored);
}

#[test]
fn test_serde_queue_partition_roundtrip() {
    let mut p = QueuePartition::new(ExecutionStage::CompileOptimized, 16);
    p.admit();
    p.admit();
    p.complete();
    p.record_shed();
    let json = serde_json::to_string(&p).unwrap();
    let restored: QueuePartition = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

#[test]
fn test_serde_worker_pool_sizing_roundtrip() {
    let sizing = compute_worker_pool_sizing(&SizingInput {
        arrival_rate_millionths: 200_000,
        mean_service_ns: 2_000_000,
        target_p99_ns: 30_000_000,
        target_utilization_millionths: 750_000,
        max_workers: 16,
    });
    let json = serde_json::to_string(&sizing).unwrap();
    let restored: WorkerPoolSizing = serde_json::from_str(&json).unwrap();
    assert_eq!(sizing, restored);
}

#[test]
fn test_serde_sizing_input_roundtrip() {
    let input = SizingInput {
        arrival_rate_millionths: 500_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 8,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: SizingInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

// ---------------------------------------------------------------------------
// Policy defaults and hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_policy_default_values() {
    let policy = AdmissionControlPolicy::default();
    assert_eq!(policy.max_queue_depth, DEFAULT_MAX_QUEUE_DEPTH);
    assert_eq!(
        policy.target_utilization_millionths,
        DEFAULT_TARGET_UTILIZATION_MILLIONTHS
    );
    assert_eq!(policy.token_capacity, DEFAULT_BURST_CAPACITY);
    assert_eq!(policy.token_refill_rate, DEFAULT_REFILL_RATE);
    assert_eq!(policy.tokens_per_admission, 1);
    assert_eq!(policy.shed_threshold_millionths, 900_000);
    assert_eq!(policy.emergency_threshold_millionths, 950_000);
    assert!(policy.stage_max_depths.is_empty());
}

#[test]
fn test_policy_hash_deterministic() {
    let p1 = AdmissionControlPolicy::default();
    let p2 = AdmissionControlPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn test_policy_hash_sensitive_to_changes() {
    let p1 = AdmissionControlPolicy::default();
    let p2 = AdmissionControlPolicy {
        max_queue_depth: 512,
        ..Default::default()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// Worker pool sizing edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_sizing_zero_arrival_rate() {
    let input = SizingInput {
        arrival_rate_millionths: 0,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 8,
    };
    let sizing = compute_worker_pool_sizing(&input);
    // Zero arrival means minimal workers needed
    assert!(sizing.recommended_workers >= 1);
}

#[test]
fn test_sizing_single_worker_max() {
    let input = SizingInput {
        arrival_rate_millionths: 10_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 50_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 1,
    };
    let sizing = compute_worker_pool_sizing(&input);
    assert_eq!(sizing.recommended_workers, 1);
    assert!(sizing.max_useful_workers >= 1);
    assert!(sizing.min_workers_for_slo >= 1);
}

// ---------------------------------------------------------------------------
// Manifest content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_content_hash_deterministic() {
    let ctrl = default_controller();
    let m1 = AdmissionControlManifest::from_controller(&ctrl);
    let m2 = AdmissionControlManifest::from_controller(&ctrl);
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn test_manifest_content_hash_sensitive() {
    let ctrl1 = default_controller();
    let mut ctrl2 = default_controller();
    ctrl2.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let m1 = AdmissionControlManifest::from_controller(&ctrl1);
    let m2 = AdmissionControlManifest::from_controller(&ctrl2);
    assert_ne!(m1.content_hash, m2.content_hash);
}

// ---------------------------------------------------------------------------
// Summary admission ratio
// ---------------------------------------------------------------------------

#[test]
fn test_summary_admission_ratio_all_admitted() {
    let mut ctrl = default_controller();
    for _ in 0..10 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.record_completion(ExecutionStage::Parse);
    }
    let summary = ctrl.summary();
    // All admitted, none shed: ratio should be 1_000_000
    assert_eq!(summary.admission_ratio_millionths, 1_000_000);
    assert_eq!(summary.total_shed, 0);
}

#[test]
fn test_summary_zero_checks() {
    let ctrl = default_controller();
    let summary = ctrl.summary();
    assert_eq!(summary.total_checks, 0);
    // With zero checks, the ratio defaults to 1_000_000
    assert_eq!(summary.admission_ratio_millionths, 1_000_000);
}

// ---------------------------------------------------------------------------
// Controller clone preserves state
// ---------------------------------------------------------------------------

#[test]
fn test_controller_clone_preserves_state() {
    let mut ctrl = controller_with_partitions();
    ctrl.update_utilization(500_000);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::High);

    let cloned = ctrl.clone();
    assert_eq!(ctrl.global_queue_depth, cloned.global_queue_depth);
    assert_eq!(ctrl.decision_sequence(), cloned.decision_sequence());
    assert_eq!(ctrl.utilization_millionths, cloned.utilization_millionths);
    assert_eq!(ctrl.receipts().len(), cloned.receipts().len());
    assert_eq!(ctrl.partitions.len(), cloned.partitions.len());
    assert_eq!(ctrl.policy_hash(), cloned.policy_hash());
}

// ---------------------------------------------------------------------------
// Critical always admitted under emergency
// ---------------------------------------------------------------------------

#[test]
fn test_critical_queued_under_emergency_with_existing_depth() {
    let mut ctrl = controller_with_partitions();
    ctrl.update_utilization(960_000); // above emergency
    // Put something in the queue first
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Critical);
    assert_eq!(ctrl.global_queue_depth, 1);

    // Second critical: should be queued (not shed) even under emergency
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Critical);
    assert!(matches!(r.decision, AdmissionDecision::Queue { .. }));
    assert_eq!(ctrl.global_queue_depth, 2);
}

// ---------------------------------------------------------------------------
// Multiple ticks refilling tokens
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_ticks_token_recovery() {
    let policy = AdmissionControlPolicy {
        max_queue_depth: 1000,
        token_capacity: 10,
        token_refill_rate: 3,
        tokens_per_admission: 1,
        ..Default::default()
    };
    let mut ctrl = AdmissionController::new(policy);
    // Exhaust all 10 tokens
    for _ in 0..10 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        ctrl.record_completion(ExecutionStage::Parse);
    }
    // Should be shed (no tokens)
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::TokensExhausted { .. }
        }
    ));

    // 2 ticks refill 6 tokens
    ctrl.tick();
    ctrl.tick();
    assert_eq!(ctrl.token_bucket.available, 6);

    // Should be able to admit 6 more
    for _ in 0..6 {
        let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
        assert!(!matches!(r.decision, AdmissionDecision::Shed { .. }));
        ctrl.record_completion(ExecutionStage::Parse);
    }
}
