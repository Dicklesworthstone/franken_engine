//! Enrichment integration tests for `queueing_admission_control`.
//!
//! Covers: enum serde roundtrips, Display uniqueness, struct construction,
//! token bucket lifecycle, queue partition arithmetic, worker pool sizing,
//! admission controller lifecycle, priority-aware shedding, content hash
//! determinism, manifest generation, and edge cases.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::queueing_admission_control::*;
use frankenengine_engine::stage_envelope_certificate::{ExecutionStage, LatencyPercentile};

// ── Helpers ─────────────────────────────────────────────────────────────

fn default_policy() -> AdmissionControlPolicy {
    AdmissionControlPolicy::default()
}

fn controller_with_policy(policy: AdmissionControlPolicy) -> AdmissionController {
    AdmissionController::new(policy)
}

fn default_controller() -> AdmissionController {
    controller_with_policy(default_policy())
}

fn all_priorities() -> Vec<AdmissionPriority> {
    vec![
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ]
}

#[allow(dead_code)]
fn all_stages() -> Vec<ExecutionStage> {
    vec![
        ExecutionStage::Parse,
        ExecutionStage::Lower,
        ExecutionStage::CompileBaseline,
        ExecutionStage::CompileOptimized,
        ExecutionStage::GcPause,
        ExecutionStage::ModuleLoad,
        ExecutionStage::SandboxInit,
        ExecutionStage::ExecutionQuantum,
        ExecutionStage::CacheLookup,
        ExecutionStage::AotLoad,
        ExecutionStage::Custom,
    ]
}

// ── AdmissionPriority serde roundtrips ──────────────────────────────────

#[test]
fn enrichment_serde_admission_priority_roundtrip_all_variants() {
    for p in all_priorities() {
        let json = serde_json::to_string(&p).unwrap();
        let restored: AdmissionPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored, "roundtrip failed for {p:?}");
    }
}

#[test]
fn enrichment_display_admission_priority_unique_strings() {
    let displays: BTreeSet<String> = all_priorities().iter().map(|p| format!("{p}")).collect();
    assert_eq!(
        displays.len(),
        5,
        "each priority must produce a unique Display string"
    );
}

#[test]
fn enrichment_display_admission_priority_exact_values() {
    assert_eq!(format!("{}", AdmissionPriority::Critical), "critical");
    assert_eq!(format!("{}", AdmissionPriority::High), "high");
    assert_eq!(format!("{}", AdmissionPriority::Normal), "normal");
    assert_eq!(format!("{}", AdmissionPriority::Low), "low");
    assert_eq!(format!("{}", AdmissionPriority::BestEffort), "best_effort");
}

#[test]
fn enrichment_ordering_priority_rank_strictly_increasing() {
    let priorities = all_priorities();
    for i in 1..priorities.len() {
        assert!(
            priorities[i - 1].rank() < priorities[i].rank(),
            "rank({:?}) should be < rank({:?})",
            priorities[i - 1],
            priorities[i],
        );
    }
}

#[test]
fn enrichment_logic_only_critical_is_unshedable() {
    for p in all_priorities() {
        if matches!(p, AdmissionPriority::Critical) {
            assert!(p.is_unshedable());
        } else {
            assert!(!p.is_unshedable(), "{p:?} should be shedable");
        }
    }
}

// ── AdmissionDecision serde roundtrips ──────────────────────────────────

#[test]
fn enrichment_serde_admission_decision_admit_roundtrip() {
    let d = AdmissionDecision::Admit;
    let json = serde_json::to_string(&d).unwrap();
    let restored: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn enrichment_serde_admission_decision_queue_roundtrip() {
    let d = AdmissionDecision::Queue {
        estimated_wait_ns: 42_000,
        position: 7,
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn enrichment_serde_admission_decision_shed_roundtrip() {
    let d = AdmissionDecision::Shed {
        reason: ShedReason::QueueFull {
            current_depth: 1024,
            max_depth: 1024,
        },
    };
    let json = serde_json::to_string(&d).unwrap();
    let restored: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, restored);
}

#[test]
fn enrichment_display_admission_decision_all_variants_unique() {
    let variants: Vec<AdmissionDecision> = vec![
        AdmissionDecision::Admit,
        AdmissionDecision::Queue {
            estimated_wait_ns: 100,
            position: 1,
        },
        AdmissionDecision::Shed {
            reason: ShedReason::QueueFull {
                current_depth: 5,
                max_depth: 10,
            },
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

// ── ShedReason serde roundtrips ─────────────────────────────────────────

#[test]
fn enrichment_serde_shed_reason_all_variants_roundtrip() {
    let reasons = vec![
        ShedReason::QueueFull {
            current_depth: 512,
            max_depth: 512,
        },
        ShedReason::TokensExhausted {
            tokens_available: 0,
            tokens_required: 1,
        },
        ShedReason::UtilizationOverload {
            current_utilization_millionths: 960_000,
            shed_threshold_millionths: 950_000,
        },
        ShedReason::PriorityShed {
            item_priority: AdmissionPriority::Low,
            min_admitted_priority: AdmissionPriority::Normal,
        },
        ShedReason::StageBudgetExhausted {
            stage: ExecutionStage::Parse,
            stage_queue_depth: 64,
            stage_max_depth: 64,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: ShedReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored, "roundtrip failed for {r:?}");
    }
}

#[test]
fn enrichment_display_shed_reason_all_variants_unique() {
    let reasons = vec![
        ShedReason::QueueFull {
            current_depth: 10,
            max_depth: 10,
        },
        ShedReason::TokensExhausted {
            tokens_available: 0,
            tokens_required: 5,
        },
        ShedReason::UtilizationOverload {
            current_utilization_millionths: 950_000,
            shed_threshold_millionths: 900_000,
        },
        ShedReason::PriorityShed {
            item_priority: AdmissionPriority::BestEffort,
            min_admitted_priority: AdmissionPriority::Normal,
        },
        ShedReason::StageBudgetExhausted {
            stage: ExecutionStage::GcPause,
            stage_queue_depth: 8,
            stage_max_depth: 8,
        },
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), reasons.len());
}

// ── TokenBucket lifecycle ───────────────────────────────────────────────

#[test]
fn enrichment_lifecycle_token_bucket_full_drain_refill_cycle() {
    let mut tb = TokenBucket::new(DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_RATE);
    assert_eq!(tb.fill_ratio_millionths(), 1_000_000);
    assert!(!tb.is_empty());

    // Drain completely
    let consumed = tb.try_consume(DEFAULT_BURST_CAPACITY);
    assert!(consumed);
    assert!(tb.is_empty());
    assert_eq!(tb.fill_ratio_millionths(), 0);
    assert_eq!(tb.total_consumed, DEFAULT_BURST_CAPACITY);

    // Refill once
    tb.refill();
    assert_eq!(tb.available, DEFAULT_REFILL_RATE);
    assert_eq!(tb.total_refills, 1);
    assert!(!tb.is_empty());

    // Refill until full
    for _ in 0..100 {
        tb.refill();
    }
    assert_eq!(tb.available, DEFAULT_BURST_CAPACITY); // capped
}

#[test]
fn enrichment_edge_token_bucket_zero_capacity_consume_fails() {
    let mut tb = TokenBucket::new(0, 0);
    assert!(!tb.try_consume(1));
    assert!(tb.is_empty());
    assert_eq!(tb.fill_ratio_millionths(), 0);
    tb.refill();
    assert_eq!(tb.available, 0);
}

#[test]
fn enrichment_arithmetic_token_bucket_fill_ratio_half() {
    let mut tb = TokenBucket::new(200, 10);
    tb.try_consume(100);
    assert_eq!(tb.fill_ratio_millionths(), 500_000);
}

#[test]
fn enrichment_arithmetic_token_bucket_fill_ratio_quarter() {
    let mut tb = TokenBucket::new(400, 10);
    tb.try_consume(300);
    assert_eq!(tb.fill_ratio_millionths(), 250_000);
}

#[test]
fn enrichment_edge_token_bucket_consume_exact_capacity() {
    let mut tb = TokenBucket::new(50, 5);
    assert!(tb.try_consume(50));
    assert!(tb.is_empty());
    assert!(!tb.try_consume(1));
}

#[test]
fn enrichment_serde_token_bucket_roundtrip() {
    let mut tb = TokenBucket::new(100, 10);
    tb.try_consume(30);
    tb.refill();
    let json = serde_json::to_string(&tb).unwrap();
    let restored: TokenBucket = serde_json::from_str(&json).unwrap();
    assert_eq!(tb, restored);
}

// ── QueuePartition lifecycle ────────────────────────────────────────────

#[test]
fn enrichment_lifecycle_queue_partition_admit_complete_cycle() {
    let mut p = QueuePartition::new(ExecutionStage::Lower, 10);
    assert_eq!(p.current_depth, 0);
    assert_eq!(p.utilization_millionths(), 0);
    assert!(!p.is_full());

    for _ in 0..10 {
        p.admit();
    }
    assert!(p.is_full());
    assert_eq!(p.total_admitted, 10);
    assert_eq!(p.utilization_millionths(), 1_000_000);

    for _ in 0..5 {
        p.complete();
    }
    assert_eq!(p.current_depth, 5);
    assert_eq!(p.total_completed, 5);
    assert_eq!(p.utilization_millionths(), 500_000);
    assert!(!p.is_full());
}

#[test]
fn enrichment_edge_queue_partition_complete_at_zero_saturates() {
    let mut p = QueuePartition::new(ExecutionStage::Custom, 10);
    p.complete(); // should not underflow
    assert_eq!(p.current_depth, 0);
    assert_eq!(p.total_completed, 1);
}

#[test]
fn enrichment_edge_queue_partition_zero_max_depth() {
    let p = QueuePartition::new(ExecutionStage::AotLoad, 0);
    assert!(p.is_full()); // 0 >= 0
    assert_eq!(p.utilization_millionths(), 0); // special case
}

#[test]
fn enrichment_arithmetic_queue_partition_utilization_incremental() {
    let mut p = QueuePartition::new(ExecutionStage::SandboxInit, 4);
    p.admit();
    assert_eq!(p.utilization_millionths(), 250_000); // 25%
    p.admit();
    assert_eq!(p.utilization_millionths(), 500_000); // 50%
    p.admit();
    assert_eq!(p.utilization_millionths(), 750_000); // 75%
    p.admit();
    assert_eq!(p.utilization_millionths(), 1_000_000); // 100%
}

#[test]
fn enrichment_serde_queue_partition_roundtrip() {
    let mut p = QueuePartition::new(ExecutionStage::CacheLookup, 32);
    p.admit();
    p.admit();
    p.record_shed();
    p.complete();
    let json = serde_json::to_string(&p).unwrap();
    let restored: QueuePartition = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ── AdmissionControlPolicy ─────────────────────────────────────────────

#[test]
fn enrichment_construction_default_policy_constants() {
    let policy = default_policy();
    assert_eq!(policy.max_queue_depth, DEFAULT_MAX_QUEUE_DEPTH);
    assert_eq!(
        policy.target_utilization_millionths,
        DEFAULT_TARGET_UTILIZATION_MILLIONTHS
    );
    assert_eq!(policy.token_capacity, DEFAULT_BURST_CAPACITY);
    assert_eq!(policy.token_refill_rate, DEFAULT_REFILL_RATE);
    assert_eq!(policy.shed_threshold_millionths, 900_000);
    assert_eq!(policy.emergency_threshold_millionths, 950_000);
    assert_eq!(policy.tokens_per_admission, 1);
    assert_eq!(policy.slo_percentile, LatencyPercentile::P99);
    assert_eq!(policy.slo_target_ns, 10_000_000);
    assert_eq!(policy.max_receipts, 1024);
    assert!(policy.stage_max_depths.is_empty());
}

#[test]
fn enrichment_hash_policy_hash_deterministic_across_instances() {
    let h1 = default_policy().policy_hash();
    let h2 = default_policy().policy_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_hash_policy_hash_changes_with_config_diff() {
    let base = default_policy().policy_hash();
    let modified = AdmissionControlPolicy {
        max_queue_depth: 256,
        ..Default::default()
    }
    .policy_hash();
    assert_ne!(base, modified);

    let modified2 = AdmissionControlPolicy {
        shed_threshold_millionths: 850_000,
        ..Default::default()
    }
    .policy_hash();
    assert_ne!(base, modified2);
    assert_ne!(modified, modified2);
}

#[test]
fn enrichment_serde_policy_roundtrip_with_stage_depths() {
    let mut policy = default_policy();
    policy.stage_max_depths.insert(ExecutionStage::Parse, 128);
    policy.stage_max_depths.insert(ExecutionStage::GcPause, 32);
    let json = serde_json::to_string(&policy).unwrap();
    let restored: AdmissionControlPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, restored);
}

// ── AdmissionController lifecycle ───────────────────────────────────────

#[test]
fn enrichment_lifecycle_controller_fresh_state() {
    let ctrl = default_controller();
    assert_eq!(ctrl.global_queue_depth, 0);
    assert_eq!(ctrl.utilization_millionths, 0);
    assert_eq!(ctrl.decision_sequence(), 0);
    assert!(ctrl.receipts().is_empty());
    assert!(ctrl.partitions.is_empty());
    let summary = ctrl.summary();
    assert_eq!(summary.total_checks, 0);
    assert_eq!(summary.total_admitted, 0);
    assert_eq!(summary.total_queued, 0);
    assert_eq!(summary.total_shed, 0);
    assert_eq!(summary.admission_ratio_millionths, 1_000_000); // no checks -> 100%
}

#[test]
fn enrichment_lifecycle_controller_admit_queue_complete_cycle() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 64);

    // First admission -> Admit (queue empty)
    let r1 = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_eq!(r1.decision, AdmissionDecision::Admit);
    assert_eq!(ctrl.global_queue_depth, 1);

    // Second admission -> Queue (queue non-empty)
    let r2 = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(r2.decision, AdmissionDecision::Queue { .. }));
    assert_eq!(ctrl.global_queue_depth, 2);

    // Complete one item
    ctrl.record_completion(ExecutionStage::Parse);
    assert_eq!(ctrl.global_queue_depth, 1);

    // Complete remaining
    ctrl.record_completion(ExecutionStage::Parse);
    assert_eq!(ctrl.global_queue_depth, 0);

    // Next admission is Admit again
    let r3 = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert_eq!(r3.decision, AdmissionDecision::Admit);
}

#[test]
fn enrichment_lifecycle_controller_decision_sequence_monotonic() {
    let mut ctrl = default_controller();
    for _ in 0..10 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    assert_eq!(ctrl.decision_sequence(), 10);
    let receipts = ctrl.receipts();
    for i in 1..receipts.len() {
        assert!(receipts[i].sequence > receipts[i - 1].sequence);
    }
}

#[test]
fn enrichment_edge_controller_receipt_eviction_when_bounded() {
    let mut policy = default_policy();
    policy.max_receipts = 5;
    let mut ctrl = controller_with_policy(policy);

    for _ in 0..20 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    assert_eq!(ctrl.receipts().len(), 5);
    // The oldest receipts should have been evicted; check that the last receipt
    // has the highest sequence number.
    let last = ctrl.receipts().last().unwrap();
    assert_eq!(last.sequence, 20);
}

#[test]
fn enrichment_lifecycle_controller_tick_refills_tokens() {
    let mut policy = default_policy();
    policy.token_capacity = 10;
    policy.token_refill_rate = 3;
    policy.tokens_per_admission = 1;
    let mut ctrl = controller_with_policy(policy);

    // Drain tokens
    for _ in 0..10 {
        ctrl.token_bucket.try_consume(1);
    }
    assert!(ctrl.token_bucket.is_empty());

    ctrl.tick();
    assert_eq!(ctrl.token_bucket.available, 3);

    ctrl.tick();
    assert_eq!(ctrl.token_bucket.available, 6);

    ctrl.tick();
    assert_eq!(ctrl.token_bucket.available, 9);

    ctrl.tick();
    assert_eq!(ctrl.token_bucket.available, 10); // capped
}

// ── Shedding paths ──────────────────────────────────────────────────────

#[test]
fn enrichment_shed_emergency_utilization_sheds_non_critical() {
    let mut ctrl = default_controller();
    ctrl.update_utilization(960_000); // above 95% emergency threshold

    for p in &[
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ] {
        ctrl.record_completion(ExecutionStage::Parse); // keep queue empty
        let r = ctrl.check_admission(ExecutionStage::Parse, *p);
        assert!(
            matches!(
                r.decision,
                AdmissionDecision::Shed {
                    reason: ShedReason::UtilizationOverload { .. }
                }
            ),
            "expected UtilizationOverload shed for {p:?}, got {:?}",
            r.decision,
        );
    }
}

#[test]
fn enrichment_shed_critical_bypasses_emergency_threshold() {
    let mut ctrl = default_controller();
    ctrl.update_utilization(990_000); // 99% utilization
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Critical);
    assert!(
        !matches!(r.decision, AdmissionDecision::Shed { .. }),
        "Critical should never be shed"
    );
}

#[test]
fn enrichment_shed_priority_shedding_at_high_utilization() {
    let mut ctrl = default_controller();
    ctrl.update_utilization(910_000); // above shed threshold (90%), below emergency (95%)

    // Normal and above should pass
    let r_normal = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(!matches!(r_normal.decision, AdmissionDecision::Shed { .. }));

    // Low and BestEffort should be shed by priority
    let r_low = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Low);
    assert!(matches!(
        r_low.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::PriorityShed { .. }
        }
    ));

    let r_best = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::BestEffort);
    assert!(matches!(
        r_best.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::PriorityShed { .. }
        }
    ));
}

#[test]
fn enrichment_shed_tokens_exhausted_path() {
    let mut policy = default_policy();
    policy.token_capacity = 3;
    policy.token_refill_rate = 0;
    policy.tokens_per_admission = 1;
    let mut ctrl = controller_with_policy(policy);

    // Admit 3 items (uses all 3 tokens)
    for _ in 0..3 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    // Drain the queue so it does not trigger QueueFull
    for _ in 0..3 {
        ctrl.record_completion(ExecutionStage::Parse);
    }
    // Fourth admission should fail with TokensExhausted
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::TokensExhausted { .. }
        }
    ));
}

#[test]
fn enrichment_shed_stage_budget_exhausted_path() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::CompileBaseline, 2);

    ctrl.check_admission(ExecutionStage::CompileBaseline, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::CompileBaseline, AdmissionPriority::Normal);
    let r = ctrl.check_admission(ExecutionStage::CompileBaseline, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));
}

#[test]
fn enrichment_shed_global_queue_full_path() {
    let mut policy = default_policy();
    policy.max_queue_depth = 3;
    let mut ctrl = controller_with_policy(policy);

    for _ in 0..3 {
        ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    }
    let r = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::QueueFull { .. }
        }
    ));
}

// ── Summary statistics ──────────────────────────────────────────────────

#[test]
fn enrichment_lifecycle_summary_counts_after_mixed_decisions() {
    let mut policy = default_policy();
    policy.max_queue_depth = 3;
    let mut ctrl = controller_with_policy(policy);

    // 1 admit + 2 queued = 3 items total, then 1 shed
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal); // shed

    let summary = ctrl.summary();
    assert_eq!(summary.total_checks, 4);
    assert_eq!(summary.total_shed, 1);
    assert_eq!(
        summary.total_admitted + summary.total_queued,
        3,
        "3 items should be admitted/queued"
    );
    assert_eq!(summary.current_queue_depth, 3);
    assert_eq!(summary.partition_count, 0); // no partitions initialized
}

#[test]
fn enrichment_arithmetic_summary_admission_ratio() {
    let mut policy = default_policy();
    policy.max_queue_depth = 2;
    let mut ctrl = controller_with_policy(policy);

    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    // 2 admitted/queued, now queue is full
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal); // shed
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal); // shed

    let summary = ctrl.summary();
    assert_eq!(summary.total_checks, 4);
    // admission_ratio = (admitted + queued) / total * 1_000_000 = 2/4 * 1M = 500_000
    assert_eq!(summary.admission_ratio_millionths, 500_000);
}

// ── Worker pool sizing ──────────────────────────────────────────────────

#[test]
fn enrichment_construction_sizing_basic_low_load() {
    let input = SizingInput {
        arrival_rate_millionths: 50_000,
        mean_service_ns: 500_000,
        target_p99_ns: 5_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 8,
    };
    let sizing = compute_worker_pool_sizing(&input);
    assert!(sizing.recommended_workers >= 1);
    assert!(sizing.min_workers_for_slo >= 1);
    assert!(sizing.max_useful_workers >= 1);
    assert_eq!(sizing.arrival_rate_millionths, 50_000);
    assert_eq!(sizing.mean_service_ns, 500_000);
    assert_eq!(sizing.target_p99_ns, 5_000_000);
}

#[test]
fn enrichment_edge_sizing_zero_service_time() {
    let input = SizingInput {
        arrival_rate_millionths: 500_000,
        mean_service_ns: 0,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 16,
    };
    let sizing = compute_worker_pool_sizing(&input);
    // mean_service_ns is clamped to 1 internally
    assert_eq!(sizing.mean_service_ns, 1);
    assert!(sizing.recommended_workers >= 1);
}

#[test]
fn enrichment_edge_sizing_zero_arrival_rate() {
    let input = SizingInput {
        arrival_rate_millionths: 0,
        mean_service_ns: 2_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 32,
    };
    let sizing = compute_worker_pool_sizing(&input);
    assert_eq!(sizing.recommended_workers, 1);
}

#[test]
fn enrichment_serde_sizing_input_roundtrip() {
    let input = SizingInput {
        arrival_rate_millionths: 750_000,
        mean_service_ns: 3_000_000,
        target_p99_ns: 15_000_000,
        target_utilization_millionths: 700_000,
        max_workers: 64,
    };
    let json = serde_json::to_string(&input).unwrap();
    let restored: SizingInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

#[test]
fn enrichment_serde_worker_pool_sizing_roundtrip() {
    let input = SizingInput {
        arrival_rate_millionths: 200_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 16,
    };
    let sizing = compute_worker_pool_sizing(&input);
    let json = serde_json::to_string(&sizing).unwrap();
    let restored: WorkerPoolSizing = serde_json::from_str(&json).unwrap();
    assert_eq!(sizing, restored);
}

// ── Content hash determinism ────────────────────────────────────────────

#[test]
fn enrichment_hash_receipt_content_hash_deterministic() {
    let mut ctrl1 = default_controller();
    let r1 = ctrl1.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);

    let mut ctrl2 = default_controller();
    let r2 = ctrl2.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);

    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_hash_receipt_content_hash_varies_with_stage() {
    let mut ctrl1 = default_controller();
    let r1 = ctrl1.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);

    let mut ctrl2 = default_controller();
    let r2 = ctrl2.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);

    // Different stages produce different content hashes even when same decision
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_hash_receipt_content_hash_varies_with_priority() {
    let mut ctrl1 = default_controller();
    let r1 = ctrl1.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);

    let mut ctrl2 = default_controller();
    let r2 = ctrl2.check_admission(ExecutionStage::Parse, AdmissionPriority::High);

    assert_ne!(r1.content_hash, r2.content_hash);
}

// ── Manifest ────────────────────────────────────────────────────────────

#[test]
fn enrichment_lifecycle_manifest_from_controller_with_partitions() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 32);
    ctrl.init_partition(ExecutionStage::Lower, 16);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Lower, AdmissionPriority::High);

    let manifest = AdmissionControlManifest::from_controller(&ctrl);
    assert_eq!(manifest.schema_version, ADMISSION_SCHEMA_VERSION);
    assert_eq!(manifest.bead_id, ADMISSION_BEAD_ID);
    assert_eq!(manifest.summary.total_checks, 2);
    assert_eq!(manifest.partitions.len(), 2);
    assert!(manifest.sizing.is_none());
}

#[test]
fn enrichment_lifecycle_manifest_with_sizing_attached() {
    let ctrl = default_controller();
    let manifest = AdmissionControlManifest::from_controller(&ctrl);
    assert!(manifest.sizing.is_none());

    let sizing = compute_worker_pool_sizing(&SizingInput {
        arrival_rate_millionths: 100_000,
        mean_service_ns: 1_000_000,
        target_p99_ns: 10_000_000,
        target_utilization_millionths: 800_000,
        max_workers: 8,
    });
    let manifest = manifest.with_sizing(sizing.clone());
    assert!(manifest.sizing.is_some());
    assert_eq!(
        manifest.sizing.unwrap().recommended_workers,
        sizing.recommended_workers
    );
}

#[test]
fn enrichment_serde_manifest_full_roundtrip() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 64);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Low);

    let sizing = compute_worker_pool_sizing(&SizingInput {
        arrival_rate_millionths: 300_000,
        mean_service_ns: 2_000_000,
        target_p99_ns: 20_000_000,
        target_utilization_millionths: 750_000,
        max_workers: 32,
    });

    let manifest = AdmissionControlManifest::from_controller(&ctrl).with_sizing(sizing);
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: AdmissionControlManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

// ── Multi-stage independence ────────────────────────────────────────────

#[test]
fn enrichment_lifecycle_multi_stage_partitions_independent() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 2);
    ctrl.init_partition(ExecutionStage::Lower, 2);
    ctrl.init_partition(ExecutionStage::GcPause, 2);

    // Fill Parse partition
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let r_parse = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    assert!(matches!(
        r_parse.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));

    // Lower and GcPause should still admit
    let r_lower = ctrl.check_admission(ExecutionStage::Lower, AdmissionPriority::Normal);
    assert!(!matches!(
        r_lower.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));

    let r_gc = ctrl.check_admission(ExecutionStage::GcPause, AdmissionPriority::Normal);
    assert!(!matches!(
        r_gc.decision,
        AdmissionDecision::Shed {
            reason: ShedReason::StageBudgetExhausted { .. }
        }
    ));
}

// ── Receipt Display ─────────────────────────────────────────────────────

#[test]
fn enrichment_display_receipt_contains_receipt_id_and_decision() {
    let mut ctrl = default_controller();
    let receipt = ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);
    let display = format!("{receipt}");
    assert!(display.contains("adm-"));
    assert!(display.contains("admit"));
    assert!(display.contains("normal"));
    assert!(display.contains("parse"));
}

// ── Schema constants ────────────────────────────────────────────────────

#[test]
fn enrichment_construction_schema_constants_non_empty() {
    assert!(!ADMISSION_SCHEMA_VERSION.is_empty());
    assert!(ADMISSION_SCHEMA_VERSION.contains("queueing-admission-control"));
    assert!(!ADMISSION_BEAD_ID.is_empty());
    assert!(ADMISSION_BEAD_ID.starts_with("bd-"));
}

// ── Update utilization clamping ─────────────────────────────────────────

#[test]
fn enrichment_edge_update_utilization_clamped_to_million() {
    let mut ctrl = default_controller();
    ctrl.update_utilization(2_000_000); // above 1M
    assert_eq!(ctrl.utilization_millionths, 1_000_000);

    ctrl.update_utilization(500_000);
    assert_eq!(ctrl.utilization_millionths, 500_000);

    ctrl.update_utilization(0);
    assert_eq!(ctrl.utilization_millionths, 0);
}

// ── Record completion without partition ─────────────────────────────────

#[test]
fn enrichment_edge_record_completion_no_partition_is_safe() {
    let mut ctrl = default_controller();
    ctrl.global_queue_depth = 5;
    // Record completion for a stage with no partition -- should not panic
    ctrl.record_completion(ExecutionStage::Custom);
    assert_eq!(ctrl.global_queue_depth, 4);
}

// ── Init partition idempotent ───────────────────────────────────────────

#[test]
fn enrichment_edge_init_partition_does_not_overwrite_existing() {
    let mut ctrl = default_controller();
    ctrl.init_partition(ExecutionStage::Parse, 100);

    // Admit an item
    ctrl.check_admission(ExecutionStage::Parse, AdmissionPriority::Normal);

    // Re-init with different max_depth -- should not overwrite
    ctrl.init_partition(ExecutionStage::Parse, 999);

    let partition = ctrl.partitions.get(&ExecutionStage::Parse).unwrap();
    assert_eq!(partition.max_depth, 100); // original value preserved
    assert_eq!(partition.total_admitted, 1); // state preserved
}
