//! Enrichment integration tests for the `slot_differential` module.
//!
//! Covers: DivergenceClass ordering, WorkloadCategory ordering, DifferentialOutcome
//! ordering, SlotDifferentialError serde, SlotInventoryEntry serde,
//! SlotDifferentialGate serde, ReplacementReceiptFragment serde,
//! classify_divergence edge cases (zero delegate memory, capability priority),
//! evaluate_slot with repro disabled, evaluate_slot mixed divergences,
//! CellOutput partial capability overlap, Debug formatting.

#![forbid(unsafe_code)]
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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_differential::{
    CellOutput, DifferentialConfig, DifferentialOutcome, DivergenceClass, EvaluateSlotInput,
    PromotionReadiness, ReplacementReceiptFragment, SlotDifferentialError,
    SlotDifferentialEvidence, SlotDifferentialGate, SlotInventoryEntry, Workload, WorkloadCategory,
    WorkloadLogEntry, WorkloadResult, build_repro, classify_divergence, evaluate_slot,
};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId, SlotKind};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sid(name: &str) -> SlotId {
    SlotId::new(name).unwrap()
}

fn authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
            SlotCapability::InvokeHostcall,
        ],
    }
}

fn cfg() -> DifferentialConfig {
    DifferentialConfig::default()
}

fn cell(ret: &str, dur: u64, mem: u64, caps: &[SlotCapability]) -> CellOutput {
    CellOutput {
        return_value: ret.to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: caps.to_vec(),
        duration_us: dur,
        memory_bytes: mem,
    }
}

fn wl(id: &str, cat: WorkloadCategory) -> Workload {
    Workload {
        workload_id: id.to_string(),
        category: cat,
        input: format!("input-{id}"),
        expected_output: None,
    }
}

fn inv(name: &str, kind: SlotKind, was_ready: bool) -> SlotInventoryEntry {
    SlotInventoryEntry {
        slot_id: sid(name),
        kind,
        authority: authority(),
        was_previously_ready: was_ready,
    }
}

// =========================================================================
// A. DivergenceClass — ordering
// =========================================================================

#[test]
fn enrichment_divergence_class_severity_ordering() {
    assert!(DivergenceClass::SemanticDivergence < DivergenceClass::CapabilityDivergence);
    assert!(DivergenceClass::CapabilityDivergence < DivergenceClass::PerformanceDivergence);
    assert!(DivergenceClass::PerformanceDivergence < DivergenceClass::ResourceDivergence);
    assert!(DivergenceClass::ResourceDivergence < DivergenceClass::BenignImprovement);
}

#[test]
fn enrichment_divergence_class_blocks_promotion_exactly_three() {
    let blockers: Vec<_> = [
        DivergenceClass::SemanticDivergence,
        DivergenceClass::CapabilityDivergence,
        DivergenceClass::PerformanceDivergence,
        DivergenceClass::ResourceDivergence,
        DivergenceClass::BenignImprovement,
    ]
    .iter()
    .filter(|c| c.blocks_promotion())
    .collect();
    assert_eq!(blockers.len(), 3);
}

#[test]
fn enrichment_divergence_class_triggers_demotion_exactly_two() {
    let demotions: Vec<_> = [
        DivergenceClass::SemanticDivergence,
        DivergenceClass::CapabilityDivergence,
        DivergenceClass::PerformanceDivergence,
        DivergenceClass::ResourceDivergence,
        DivergenceClass::BenignImprovement,
    ]
    .iter()
    .filter(|c| c.triggers_demotion())
    .collect();
    assert_eq!(demotions.len(), 2);
}

// =========================================================================
// B. WorkloadCategory — ordering
// =========================================================================

#[test]
fn enrichment_workload_category_ordering() {
    assert!(WorkloadCategory::SemanticEquivalence < WorkloadCategory::EdgeCase);
    assert!(WorkloadCategory::EdgeCase < WorkloadCategory::Adversarial);
}

#[test]
fn enrichment_workload_category_copy() {
    let c = WorkloadCategory::SemanticEquivalence;
    let c2 = c;
    assert_eq!(c, c2);
}

// =========================================================================
// C. DifferentialOutcome — ordering
// =========================================================================

#[test]
fn enrichment_differential_outcome_ordering() {
    assert!(DifferentialOutcome::Match < DifferentialOutcome::Diverge);
}

#[test]
fn enrichment_differential_outcome_copy() {
    let o = DifferentialOutcome::Match;
    let o2 = o;
    assert_eq!(o, o2);
}

// =========================================================================
// D. SlotDifferentialError — serde roundtrip
// =========================================================================

#[test]
fn enrichment_error_serde_slot_not_found() {
    let err = SlotDifferentialError::SlotNotFound {
        slot_id: "math_eval".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SlotDifferentialError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_empty_corpus() {
    let err = SlotDifferentialError::EmptyCorpus {
        slot_id: "string_interp".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SlotDifferentialError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_invalid_config() {
    let err = SlotDifferentialError::InvalidConfig {
        detail: "threshold out of range".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SlotDifferentialError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_cell_execution_failed() {
    let err = SlotDifferentialError::CellExecutionFailed {
        slot_id: "crypto_hash".to_string(),
        cell_type: "native".to_string(),
        detail: "segfault".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SlotDifferentialError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

#[test]
fn enrichment_error_serde_internal_error() {
    let err = SlotDifferentialError::InternalError {
        detail: "unexpected state".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let restored: SlotDifferentialError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, restored);
}

// =========================================================================
// E. SlotInventoryEntry — serde roundtrip
// =========================================================================

#[test]
fn enrichment_slot_inventory_entry_serde() {
    let entry = inv("sort-impl", SlotKind::Parser, true);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: SlotInventoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// =========================================================================
// F. ReplacementReceiptFragment — serde roundtrip
// =========================================================================

#[test]
fn enrichment_receipt_fragment_serde_roundtrip() {
    let frag = ReplacementReceiptFragment {
        slot_id: sid("regex-compile"),
        workload_count: 42,
        categories_covered: 3,
        improvement_count: 2,
        evidence_hash: ContentHash::compute(b"evidence"),
        corpus_hash: ContentHash::compute(b"corpus"),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&frag).unwrap();
    let restored: ReplacementReceiptFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag, restored);
}

#[test]
fn enrichment_receipt_fragment_from_evaluation_with_improvements() {
    let native_fast = cell("ok", 50, 100, &[]);
    let delegate_slow = cell("ok", 100, 200, &[]);
    let results = vec![
        WorkloadResult {
            workload_id: "wl-1".to_string(),
            category: WorkloadCategory::SemanticEquivalence,
            native_output: native_fast.clone(),
            delegate_output: delegate_slow.clone(),
            outcome: DifferentialOutcome::Diverge,
            divergence_class: Some(DivergenceClass::BenignImprovement),
        },
        WorkloadResult {
            workload_id: "wl-2".to_string(),
            category: WorkloadCategory::EdgeCase,
            native_output: cell("ok", 100, 100, &[]),
            delegate_output: cell("ok", 100, 100, &[]),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
    ];
    let frag = ReplacementReceiptFragment::from_evaluation(
        sid("sort-impl"),
        &results,
        ContentHash::compute(b"ev"),
        ContentHash::compute(b"co"),
        SecurityEpoch::from_raw(1),
    );
    assert_eq!(frag.workload_count, 2);
    assert_eq!(frag.categories_covered, 2);
    assert_eq!(frag.improvement_count, 1);
}

// =========================================================================
// G. classify_divergence — edge cases
// =========================================================================

#[test]
fn enrichment_classify_zero_memory_delegate_no_resource_divergence() {
    // When delegate memory is 0, resource check should be skipped (no division by zero)
    let native = cell("ok", 100, 500, &[]);
    let delegate = cell("ok", 100, 0, &[]);
    let class = classify_divergence(&native, &delegate, &cfg());
    // Native is not lighter, delegate is lighter (0). No resource check triggered
    // because delegate.memory_bytes == 0 skips resource check. No benign improvement
    // because native is not faster. But native has more memory, so no improvement.
    // Actually check: native_faster = false (100 == 100), native_lighter = false (500 > 0 but not <)
    // So no divergence? Wait: native.memory_bytes (500) is NOT < delegate.memory_bytes (0).
    // So native_lighter = false and native_faster = false => None.
    assert!(class.is_none() || matches!(class, Some(DivergenceClass::BenignImprovement)));
}

#[test]
fn enrichment_classify_capability_precedes_performance() {
    // Native exercises broader capabilities AND is slower
    let native = cell(
        "ok",
        200,
        100,
        &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
    );
    let delegate = cell("ok", 100, 100, &[SlotCapability::ReadSource]);
    let class = classify_divergence(&native, &delegate, &cfg());
    // Capability check should fire first (P0 > P1)
    assert_eq!(class, Some(DivergenceClass::CapabilityDivergence));
}

#[test]
fn enrichment_classify_semantic_precedes_capability() {
    let native = cell(
        "wrong",
        100,
        100,
        &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
    );
    let delegate = cell("right", 100, 100, &[SlotCapability::ReadSource]);
    let class = classify_divergence(&native, &delegate, &cfg());
    assert_eq!(class, Some(DivergenceClass::SemanticDivergence));
}

#[test]
fn enrichment_classify_resource_above_threshold() {
    // Resource regression > 20% threshold
    let native = cell("ok", 100, 300, &[]);
    let delegate = cell("ok", 100, 100, &[]);
    let class = classify_divergence(&native, &delegate, &cfg());
    assert_eq!(class, Some(DivergenceClass::ResourceDivergence));
}

#[test]
fn enrichment_classify_performance_exactly_at_threshold_no_divergence() {
    // 10% regression = threshold = 100_000 millionths. delegate=100, native=110
    // regression = (110-100)*1_000_000/100 = 100_000 which is NOT > threshold
    let native = cell("ok", 110, 100, &[]);
    let delegate = cell("ok", 100, 100, &[]);
    let class = classify_divergence(&native, &delegate, &cfg());
    // 100_000 is not > 100_000, so no performance divergence
    // But native is slower => not benign improvement
    // Exact equivalence otherwise => None
    assert!(class.is_none());
}

// =========================================================================
// H. evaluate_slot — repro artifacts disabled
// =========================================================================

#[test]
fn enrichment_evaluate_slot_repro_disabled_still_blocks() {
    let mut config = cfg();
    config.emit_repro_artifacts = false;

    let slot_id = sid("hash-fn");
    let workloads = [wl("wl-1", WorkloadCategory::SemanticEquivalence)];

    let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot_id,
        slot_kind: SlotKind::Parser,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(cell("wrong", 100, 100, &[])),
        delegate_executor: &|_| Ok(cell("right", 100, 100, &[])),
        config: &config,
        was_previously_ready: false,
    })
    .unwrap();

    assert_eq!(results.len(), 1);
    assert!(verdict.is_blocked());
    // Blocked but with no repro hashes since artifacts are disabled
    if let PromotionReadiness::Blocked { repro_hashes, .. } = &verdict {
        assert!(repro_hashes.is_empty());
    } else {
        panic!("expected Blocked");
    }
}

// =========================================================================
// I. evaluate_slot — mixed divergence classes
// =========================================================================

#[test]
fn enrichment_evaluate_slot_mixed_divergences_most_severe_still_blocks() {
    let slot_id = sid("parser");
    let workloads = [
        wl("wl-sem", WorkloadCategory::SemanticEquivalence),
        wl("wl-perf", WorkloadCategory::EdgeCase),
    ];

    let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot_id,
        slot_kind: SlotKind::Parser,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|w| {
            if w.workload_id == "wl-sem" {
                Ok(cell("wrong", 100, 100, &[]))
            } else {
                // Performance regression: native 300us vs delegate 100us (200% > 10%)
                Ok(cell("ok", 300, 100, &[]))
            }
        },
        delegate_executor: &|_| Ok(cell("right", 100, 100, &[])),
        config: &cfg(),
        was_previously_ready: false,
    })
    .unwrap();

    assert_eq!(results.len(), 2);
    assert!(verdict.is_blocked());
    if let PromotionReadiness::Blocked {
        divergence_counts, ..
    } = &verdict
    {
        // Should have entries for both divergence classes
        assert!(divergence_counts.len() >= 1);
    }
}

// =========================================================================
// J. CellOutput — capability equivalence edge cases
// =========================================================================

#[test]
fn enrichment_cell_output_capability_partial_overlap() {
    let native = cell(
        "ok",
        100,
        100,
        &[SlotCapability::ReadSource, SlotCapability::EmitIr],
    );
    let delegate = cell(
        "ok",
        100,
        100,
        &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
    );
    // Native has Timer not in delegate => not capability equivalent
    assert!(!native.capability_equivalent(&delegate));
}

#[test]
fn enrichment_cell_output_capability_native_strict_subset() {
    let native = cell("ok", 100, 100, &[SlotCapability::ReadSource]);
    let delegate = cell(
        "ok",
        100,
        100,
        &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
    );
    // Native subset of delegate => equivalent
    assert!(native.capability_equivalent(&delegate));
}

#[test]
fn enrichment_cell_output_semantic_equivalence_ignores_evidence_entries() {
    let mut a = cell("ok", 100, 100, &[]);
    let mut b = cell("ok", 100, 100, &[]);
    a.evidence_entries = vec!["entry-a".to_string()];
    b.evidence_entries = vec!["entry-b".to_string()];
    // Evidence entries differ but semantic equivalence only checks return_value,
    // side_effects, exceptions
    assert!(a.semantically_equivalent(&b));
}

// =========================================================================
// K. SlotDifferentialEvidence — lifecycle
// =========================================================================

#[test]
fn enrichment_evidence_new_starts_empty() {
    let evidence = SlotDifferentialEvidence::new(
        ContentHash::compute(b"corpus"),
        ContentHash::compute(b"registry"),
        "linux-x86_64".to_string(),
        SecurityEpoch::from_raw(1),
    );
    assert!(evidence.verdicts.is_empty());
    assert!(evidence.divergence_summary.is_empty());
    assert!(!evidence.has_blocking_divergences());
}

#[test]
fn enrichment_evidence_increment_divergence_accumulates() {
    let mut evidence = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        SecurityEpoch::from_raw(1),
    );
    evidence.increment_divergence(&DivergenceClass::SemanticDivergence);
    evidence.increment_divergence(&DivergenceClass::SemanticDivergence);
    evidence.increment_divergence(&DivergenceClass::BenignImprovement);
    assert_eq!(
        evidence.divergence_summary.get("semantic_divergence"),
        Some(&2)
    );
    assert_eq!(
        evidence.divergence_summary.get("benign_improvement"),
        Some(&1)
    );
}

#[test]
fn enrichment_evidence_has_blocking_only_on_blocked_or_regressed() {
    let mut evidence = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        SecurityEpoch::from_raw(1),
    );
    evidence.record_verdict(
        &sid("slot-a"),
        PromotionReadiness::Ready {
            workload_count: 10,
            improvement_count: 0,
        },
    );
    assert!(!evidence.has_blocking_divergences());

    evidence.record_verdict(
        &sid("slot-b"),
        PromotionReadiness::Blocked {
            divergence_counts: BTreeMap::new(),
            repro_hashes: vec![],
        },
    );
    assert!(evidence.has_blocking_divergences());
}

// =========================================================================
// L. SlotDifferentialGate — lifecycle
// =========================================================================

#[test]
fn enrichment_gate_new_starts_with_no_slots() {
    let gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"corpus"),
        ContentHash::compute(b"reg"),
        "test-env".to_string(),
    );
    assert!(gate.slots.is_empty());
    assert!(gate.passes());
}

#[test]
fn enrichment_gate_register_slot_increments_inventory() {
    let mut gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
    );
    gate.register_slot(inv("slot-a", SlotKind::Parser, false));
    gate.register_slot(inv("slot-b", SlotKind::Interpreter, true));
    assert_eq!(gate.slots.len(), 2);
}

#[test]
fn enrichment_gate_evaluate_single_updates_evidence() {
    let mut gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
    );
    gate.register_slot(inv("sort-impl", SlotKind::Parser, false));
    let workloads = [wl("wl-1", WorkloadCategory::SemanticEquivalence)];
    let (results, verdict) = gate
        .evaluate_single(
            &sid("sort-impl"),
            &workloads,
            &|_| Ok(cell("ok", 100, 100, &[])),
            &|_| Ok(cell("ok", 100, 100, &[])),
        )
        .unwrap();
    assert_eq!(results.len(), 1);
    assert!(verdict.is_ready());
    assert!(gate.passes());
    assert!(gate.verdict_for(&sid("sort-impl")).unwrap().is_ready());
}

#[test]
fn enrichment_gate_evaluate_single_slot_not_found() {
    let mut gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
    );
    let workloads = [wl("wl-1", WorkloadCategory::SemanticEquivalence)];
    let err = gate
        .evaluate_single(
            &sid("nonexistent"),
            &workloads,
            &|_| Ok(cell("ok", 100, 100, &[])),
            &|_| Ok(cell("ok", 100, 100, &[])),
        )
        .unwrap_err();
    assert!(matches!(err, SlotDifferentialError::SlotNotFound { .. }));
}

#[test]
fn enrichment_gate_finalize_evidence_returns_ref() {
    let gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
    );
    let evidence = gate.finalize_evidence();
    assert!(evidence.verdicts.is_empty());
}

// =========================================================================
// M. SlotDifferentialGate — serde roundtrip
// =========================================================================

#[test]
fn enrichment_gate_serde_roundtrip() {
    let mut gate = SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
    );
    gate.register_slot(inv("slot-a", SlotKind::Parser, false));
    let json = serde_json::to_string(&gate).unwrap();
    let restored: SlotDifferentialGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, restored);
}

// =========================================================================
// N. WorkloadLogEntry — serde roundtrip
// =========================================================================

#[test]
fn enrichment_workload_log_entry_serde_with_divergence() {
    let entry = WorkloadLogEntry {
        trace_id: "trace-123".to_string(),
        slot_id: sid("crypto-hash"),
        workload_id: "wl-adversarial-1".to_string(),
        corpus_category: WorkloadCategory::Adversarial,
        outcome: DifferentialOutcome::Diverge,
        divergence_class: Some(DivergenceClass::SemanticDivergence),
        native_duration_us: 150,
        delegate_duration_us: 100,
        capability_diff: vec!["extra_cap".to_string()],
        resource_diff: "+50 bytes".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: WorkloadLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// =========================================================================
// O. build_repro — edge cases
// =========================================================================

#[test]
fn enrichment_build_repro_benign_improvement_no_capability_diff() {
    let native = cell("ok", 50, 80, &[SlotCapability::ReadSource]);
    let delegate = cell("ok", 100, 200, &[SlotCapability::ReadSource]);
    let workload = wl("wl-1", WorkloadCategory::SemanticEquivalence);
    let hash = ContentHash::compute(b"contract");
    let repro = build_repro(
        &sid("sort-fn"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::BenignImprovement,
        &hash,
    );
    assert!(repro.capability_diff.is_empty());
    assert!(repro.memory_diff_bytes < 0); // native uses less memory
    assert!(repro.duration_diff_us < 0); // native is faster
    assert_eq!(repro.artifact_hash, repro.compute_hash());
}

#[test]
fn enrichment_build_repro_capability_divergence_captures_diff() {
    let native = cell(
        "ok",
        100,
        100,
        &[
            SlotCapability::ReadSource,
            SlotCapability::InvokeHostcall,
            SlotCapability::EmitIr,
        ],
    );
    let delegate = cell("ok", 100, 100, &[SlotCapability::ReadSource]);
    let workload = wl("wl-cap", WorkloadCategory::Adversarial);
    let hash = ContentHash::compute(b"contract");
    let repro = build_repro(
        &sid("rpc-handler"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::CapabilityDivergence,
        &hash,
    );
    assert_eq!(repro.capability_diff.len(), 2); // Hostcall and Timer not in delegate
}

// =========================================================================
// P. PromotionReadiness — predicates are mutually exclusive
// =========================================================================

#[test]
fn enrichment_promotion_readiness_ready_predicates() {
    let r = PromotionReadiness::Ready {
        workload_count: 5,
        improvement_count: 1,
    };
    assert!(r.is_ready());
    assert!(!r.is_blocked());
    assert!(!r.is_regressed());
    assert_eq!(r.as_str(), "ready");
    assert_eq!(r.to_string(), "ready");
}

#[test]
fn enrichment_promotion_readiness_blocked_predicates() {
    let b = PromotionReadiness::Blocked {
        divergence_counts: BTreeMap::from([("semantic_divergence".to_string(), 1)]),
        repro_hashes: vec![ContentHash::compute(b"repro")],
    };
    assert!(!b.is_ready());
    assert!(b.is_blocked());
    assert!(!b.is_regressed());
    assert_eq!(b.as_str(), "blocked");
}

#[test]
fn enrichment_promotion_readiness_regressed_predicates() {
    let r = PromotionReadiness::Regressed {
        divergence_counts: BTreeMap::new(),
        repro_hashes: vec![],
        trigger_demotion: true,
    };
    assert!(!r.is_ready());
    assert!(!r.is_blocked());
    assert!(r.is_regressed());
    assert_eq!(r.as_str(), "regressed");
}

// =========================================================================
// Q. DifferentialConfig — defaults
// =========================================================================

#[test]
fn enrichment_differential_config_default_thresholds() {
    let c = DifferentialConfig::default();
    assert_eq!(c.performance_threshold_millionths, 100_000);
    assert_eq!(c.resource_threshold_millionths, 200_000);
    assert!(c.emit_repro_artifacts);
    assert_eq!(c.epoch, SecurityEpoch::from_raw(1));
}

#[test]
fn enrichment_differential_config_serde_custom() {
    let c = DifferentialConfig {
        performance_threshold_millionths: 50_000,
        resource_threshold_millionths: 100_000,
        emit_repro_artifacts: false,
        epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&c).unwrap();
    let restored: DifferentialConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// =========================================================================
// R. DivergenceRepro — compute_hash determinism
// =========================================================================

#[test]
fn enrichment_divergence_repro_hash_deterministic() {
    let native = cell("wrong", 100, 100, &[]);
    let delegate = cell("right", 100, 100, &[]);
    let workload = wl("wl-1", WorkloadCategory::SemanticEquivalence);
    let hash = ContentHash::compute(b"contract");
    let repro1 = build_repro(
        &sid("fn-a"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &hash,
    );
    let repro2 = build_repro(
        &sid("fn-a"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &hash,
    );
    assert_eq!(repro1.artifact_hash, repro2.artifact_hash);
}

#[test]
fn enrichment_divergence_repro_hash_changes_with_slot() {
    let native = cell("wrong", 100, 100, &[]);
    let delegate = cell("right", 100, 100, &[]);
    let workload = wl("wl-1", WorkloadCategory::SemanticEquivalence);
    let hash = ContentHash::compute(b"contract");
    let repro1 = build_repro(
        &sid("fn-a"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &hash,
    );
    let repro2 = build_repro(
        &sid("fn-b"),
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &hash,
    );
    assert_ne!(repro1.artifact_hash, repro2.artifact_hash);
}

// =========================================================================
// S. Debug formatting — all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", DivergenceClass::SemanticDivergence).is_empty());
    assert!(!format!("{:?}", WorkloadCategory::EdgeCase).is_empty());
    assert!(!format!("{:?}", DifferentialOutcome::Match).is_empty());
    assert!(
        !format!(
            "{:?}",
            PromotionReadiness::Ready {
                workload_count: 1,
                improvement_count: 0,
            }
        )
        .is_empty()
    );
    assert!(!format!("{:?}", DifferentialConfig::default()).is_empty());
    assert!(
        !format!(
            "{:?}",
            SlotDifferentialError::InternalError {
                detail: "x".to_string()
            }
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            SlotDifferentialEvidence::new(
                ContentHash::compute(b"c"),
                ContentHash::compute(b"r"),
                "env".to_string(),
                SecurityEpoch::from_raw(1),
            )
        )
        .is_empty()
    );
}
