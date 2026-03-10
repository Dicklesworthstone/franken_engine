#![forbid(unsafe_code)]
//! Comprehensive integration tests for the `slot_differential` module.
//!
//! Validates per-slot native-vs-delegate differential gates: divergence
//! classification, cell output comparisons, repro artifact generation,
//! slot evaluation verdicts, aggregate gate logic, evidence tracking,
//! receipt fragment generation, serde round-trips, Display impls, and
//! error variants.
//!
//! Plan reference: Section 10.7 item 7, bd-33z.

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
    CellOutput, DifferentialConfig, DifferentialOutcome, DivergenceClass, DivergenceRepro,
    EvaluateSlotInput, PromotionReadiness, ReplacementReceiptFragment, SlotDifferentialError,
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

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
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

fn cell_with_effects(
    ret: &str,
    effects: &[&str],
    exceptions: &[&str],
    dur: u64,
    mem: u64,
) -> CellOutput {
    CellOutput {
        return_value: ret.to_string(),
        side_effects: effects.iter().map(|s| s.to_string()).collect(),
        exceptions: exceptions.iter().map(|s| s.to_string()).collect(),
        evidence_entries: vec![],
        capabilities_exercised: vec![],
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

fn gate() -> SlotDifferentialGate {
    SlotDifferentialGate::new(
        cfg(),
        ContentHash::compute(b"corpus-hash"),
        ContentHash::compute(b"registry-hash"),
        "integration-test-env".to_string(),
    )
}

// =========================================================================
// 1. classify_divergence
// =========================================================================

#[test]
fn classify_semantic_divergence_return_value_differs() {
    let native = cell("42", 100, 1024, &[]);
    let delegate = cell("43", 100, 1024, &[]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::SemanticDivergence)
    );
}

#[test]
fn classify_semantic_divergence_side_effects_differ() {
    let native = cell_with_effects("ok", &["write:a"], &[], 100, 1024);
    let delegate = cell_with_effects("ok", &["write:b"], &[], 100, 1024);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::SemanticDivergence)
    );
}

#[test]
fn classify_semantic_divergence_exceptions_differ() {
    let native = cell_with_effects("ok", &[], &["TypeError"], 100, 1024);
    let delegate = cell_with_effects("ok", &[], &["RangeError"], 100, 1024);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::SemanticDivergence)
    );
}

#[test]
fn classify_capability_divergence_native_broader() {
    let native = cell(
        "ok",
        100,
        1024,
        &[SlotCapability::ReadSource, SlotCapability::TriggerGc],
    );
    let delegate = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::CapabilityDivergence)
    );
}

#[test]
fn classify_performance_divergence_above_threshold() {
    // Default threshold: 100_000 millionths = 10%.
    // Native 120us vs delegate 100us = 20% regression.
    let native = cell("ok", 120, 1024, &[]);
    let delegate = cell("ok", 100, 1024, &[]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::PerformanceDivergence)
    );
}

#[test]
fn classify_performance_within_threshold_no_divergence() {
    // 5% regression (105 vs 100) is within 10% threshold.
    // native_faster=false, native_lighter=false => None.
    let native = cell("ok", 105, 1024, &[]);
    let delegate = cell("ok", 100, 1024, &[]);
    assert_eq!(classify_divergence(&native, &delegate, &cfg()), None);
}

#[test]
fn classify_resource_divergence_above_threshold() {
    // Default resource threshold: 200_000 millionths = 20%.
    // Native 1300 vs delegate 1000 = 30% more memory.
    let native = cell("ok", 100, 1300, &[]);
    let delegate = cell("ok", 100, 1000, &[]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::ResourceDivergence)
    );
}

#[test]
fn classify_resource_within_threshold_no_divergence() {
    // 15% more memory (1150 vs 1000) is within 20% threshold.
    let native = cell("ok", 100, 1150, &[]);
    let delegate = cell("ok", 100, 1000, &[]);
    assert_eq!(classify_divergence(&native, &delegate, &cfg()), None);
}

#[test]
fn classify_benign_improvement_native_faster() {
    let native = cell("ok", 70, 1024, &[]);
    let delegate = cell("ok", 100, 1024, &[]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::BenignImprovement)
    );
}

#[test]
fn classify_benign_improvement_native_lighter() {
    let native = cell("ok", 100, 700, &[]);
    let delegate = cell("ok", 100, 1024, &[]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::BenignImprovement)
    );
}

#[test]
fn classify_exact_match_no_divergence() {
    let output = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    assert_eq!(classify_divergence(&output, &output, &cfg()), None);
}

#[test]
fn classify_semantic_takes_precedence_over_all() {
    // Both semantic and capability divergence present -- semantic wins.
    let native = cell(
        "wrong",
        200,
        2000,
        &[SlotCapability::ReadSource, SlotCapability::TriggerGc],
    );
    let delegate = cell("right", 100, 1000, &[SlotCapability::ReadSource]);
    assert_eq!(
        classify_divergence(&native, &delegate, &cfg()),
        Some(DivergenceClass::SemanticDivergence)
    );
}

#[test]
fn classify_zero_duration_delegate_no_panic() {
    let native = cell("ok", 100, 1024, &[]);
    let delegate = cell("ok", 0, 1024, &[]);
    // Division by zero guard: delegate duration=0 skips perf check.
    let _ = classify_divergence(&native, &delegate, &cfg());
}

// =========================================================================
// 2. CellOutput
// =========================================================================

#[test]
fn cell_output_semantic_equivalence_ignores_timing() {
    let a = cell_with_effects("result", &["eff1"], &["exc1"], 100, 1024);
    let b = cell_with_effects("result", &["eff1"], &["exc1"], 999, 9999);
    assert!(a.semantically_equivalent(&b));
}

#[test]
fn cell_output_semantic_inequivalence_on_return_value() {
    let a = cell("a", 100, 1024, &[]);
    let b = cell("b", 100, 1024, &[]);
    assert!(!a.semantically_equivalent(&b));
}

#[test]
fn cell_output_capability_equivalent_native_subset() {
    let native = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    let delegate = cell(
        "ok",
        100,
        1024,
        &[SlotCapability::ReadSource, SlotCapability::EmitIr],
    );
    assert!(native.capability_equivalent(&delegate));
}

#[test]
fn cell_output_capability_not_equivalent_native_superset() {
    let native = cell(
        "ok",
        100,
        1024,
        &[SlotCapability::ReadSource, SlotCapability::EmitEvidence],
    );
    let delegate = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    assert!(!native.capability_equivalent(&delegate));
}

#[test]
fn cell_output_capability_equivalent_both_empty() {
    let native = cell("ok", 100, 1024, &[]);
    let delegate = cell("ok", 100, 1024, &[]);
    assert!(native.capability_equivalent(&delegate));
}

// =========================================================================
// 3. build_repro
// =========================================================================

#[test]
fn build_repro_produces_deterministic_hash() {
    let slot = sid("parser");
    let workload = wl("w1", WorkloadCategory::SemanticEquivalence);
    let native = cell("42", 100, 1024, &[]);
    let delegate = cell("43", 100, 1024, &[]);
    let contract = ContentHash::compute(b"contract");
    let r1 = build_repro(
        &slot,
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &contract,
    );
    let r2 = build_repro(
        &slot,
        &workload,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &contract,
    );
    assert_eq!(r1.artifact_hash, r2.artifact_hash);
    assert_eq!(r1.artifact_hash, r1.compute_hash());
}

#[test]
fn build_repro_captures_capability_diff() {
    let slot = sid("interp");
    let workload = wl("w2", WorkloadCategory::Adversarial);
    let native = cell(
        "ok",
        100,
        1024,
        &[SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
    );
    let delegate = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    let contract = ContentHash::compute(b"c");
    let repro = build_repro(
        &slot,
        &workload,
        &native,
        &delegate,
        &DivergenceClass::CapabilityDivergence,
        &contract,
    );
    assert_eq!(repro.capability_diff, vec![SlotCapability::InvokeHostcall]);
}

#[test]
fn build_repro_computes_memory_and_duration_diffs() {
    let slot = sid("builtins");
    let workload = wl("w3", WorkloadCategory::EdgeCase);
    let native = cell("ok", 80, 1200, &[]);
    let delegate = cell("ok", 100, 1000, &[]);
    let contract = ContentHash::compute(b"x");
    let repro = build_repro(
        &slot,
        &workload,
        &native,
        &delegate,
        &DivergenceClass::ResourceDivergence,
        &contract,
    );
    // native.memory_bytes(1200) - delegate.memory_bytes(1000) = 200
    assert_eq!(repro.memory_diff_bytes, 200);
    // native.duration_us(80) - delegate.duration_us(100) = -20
    assert_eq!(repro.duration_diff_us, -20);
}

#[test]
fn build_repro_empty_capability_diff_when_equal() {
    let slot = sid("gc");
    let workload = wl("w4", WorkloadCategory::SemanticEquivalence);
    let native = cell("ok", 200, 2000, &[SlotCapability::ReadSource]);
    let delegate = cell("ok", 100, 1000, &[SlotCapability::ReadSource]);
    let contract = ContentHash::compute(b"y");
    let repro = build_repro(
        &slot,
        &workload,
        &native,
        &delegate,
        &DivergenceClass::PerformanceDivergence,
        &contract,
    );
    assert!(repro.capability_diff.is_empty());
}

// =========================================================================
// 4. evaluate_slot
// =========================================================================

#[test]
fn evaluate_slot_all_matching_yields_ready() {
    let slot = sid("parser");
    let workloads = vec![
        wl("w1", WorkloadCategory::SemanticEquivalence),
        wl("w2", WorkloadCategory::EdgeCase),
        wl("w3", WorkloadCategory::Adversarial),
    ];
    let output = cell("ok", 100, 1024, &[SlotCapability::ReadSource]);
    let output2 = output.clone();

    let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::Parser,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(output.clone()),
        delegate_executor: &|_| Ok(output2.clone()),
        config: &cfg(),
        was_previously_ready: false,
    })
    .unwrap();

    assert_eq!(results.len(), 3);
    assert!(
        results
            .iter()
            .all(|r| r.outcome == DifferentialOutcome::Match)
    );
    assert!(verdict.is_ready());
    if let PromotionReadiness::Ready {
        workload_count,
        improvement_count,
    } = verdict
    {
        assert_eq!(workload_count, 3);
        assert_eq!(improvement_count, 0);
    }
}

#[test]
fn evaluate_slot_semantic_divergence_blocked() {
    let slot = sid("interpreter");
    let workloads = vec![wl("w1", WorkloadCategory::SemanticEquivalence)];

    let (results, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::Interpreter,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(cell("native-val", 100, 1024, &[])),
        delegate_executor: &|_| Ok(cell("delegate-val", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: false,
    })
    .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].outcome, DifferentialOutcome::Diverge);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::SemanticDivergence)
    );
    assert!(verdict.is_blocked());
}

#[test]
fn evaluate_slot_regression_on_previously_ready_triggers_demotion() {
    let slot = sid("object-model");
    let workloads = vec![wl("w1", WorkloadCategory::SemanticEquivalence)];

    let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::ObjectModel,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(cell("a", 100, 1024, &[])),
        delegate_executor: &|_| Ok(cell("b", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: true,
    })
    .unwrap();

    assert!(verdict.is_regressed());
    match verdict {
        PromotionReadiness::Regressed {
            trigger_demotion,
            divergence_counts,
            repro_hashes,
        } => {
            // Semantic divergence triggers demotion.
            assert!(trigger_demotion);
            assert_eq!(
                *divergence_counts.get("semantic_divergence").unwrap_or(&0),
                1
            );
            assert!(!repro_hashes.is_empty());
        }
        _ => panic!("expected Regressed verdict"),
    }
}

#[test]
fn evaluate_slot_performance_regression_on_previously_ready_no_demotion() {
    let slot = sid("scope-model");
    let workloads = vec![wl("w1", WorkloadCategory::SemanticEquivalence)];

    let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::ScopeModel,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(cell("ok", 200, 1024, &[])), // 100% slower
        delegate_executor: &|_| Ok(cell("ok", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: true,
    })
    .unwrap();

    assert!(verdict.is_regressed());
    match verdict {
        PromotionReadiness::Regressed {
            trigger_demotion, ..
        } => {
            // Performance divergence does NOT trigger demotion.
            assert!(!trigger_demotion);
        }
        _ => panic!("expected Regressed verdict"),
    }
}

#[test]
fn evaluate_slot_empty_corpus_returns_error() {
    let slot = sid("gc");
    let result = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::GarbageCollector,
        authority: &authority(),
        workloads: &[],
        native_executor: &|_| Ok(cell("ok", 100, 1024, &[])),
        delegate_executor: &|_| Ok(cell("ok", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: false,
    });

    assert!(result.is_err());
    match result.unwrap_err() {
        SlotDifferentialError::EmptyCorpus { slot_id } => {
            assert_eq!(slot_id, "gc");
        }
        other => panic!("expected EmptyCorpus, got {:?}", other),
    }
}

#[test]
fn evaluate_slot_benign_improvements_counted_in_ready() {
    let slot = sid("async-runtime");
    let workloads = vec![
        wl("w1", WorkloadCategory::SemanticEquivalence),
        wl("w2", WorkloadCategory::EdgeCase),
    ];

    let (_, verdict) = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::AsyncRuntime,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| Ok(cell("ok", 50, 512, &[])), // faster + lighter
        delegate_executor: &|_| Ok(cell("ok", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: false,
    })
    .unwrap();

    match verdict {
        PromotionReadiness::Ready {
            workload_count,
            improvement_count,
        } => {
            assert_eq!(workload_count, 2);
            assert_eq!(improvement_count, 2);
        }
        _ => panic!("expected Ready verdict"),
    }
}

#[test]
fn evaluate_slot_cell_execution_error_propagates() {
    let slot = sid("builtins");
    let workloads = vec![wl("w1", WorkloadCategory::SemanticEquivalence)];

    let result = evaluate_slot(&EvaluateSlotInput {
        slot_id: &slot,
        slot_kind: SlotKind::Builtins,
        authority: &authority(),
        workloads: &workloads,
        native_executor: &|_| {
            Err(SlotDifferentialError::CellExecutionFailed {
                slot_id: "builtins".into(),
                cell_type: "native".into(),
                detail: "oom".into(),
            })
        },
        delegate_executor: &|_| Ok(cell("ok", 100, 1024, &[])),
        config: &cfg(),
        was_previously_ready: false,
    });

    assert!(result.is_err());
    match result.unwrap_err() {
        SlotDifferentialError::CellExecutionFailed { detail, .. } => {
            assert_eq!(detail, "oom");
        }
        other => panic!("expected CellExecutionFailed, got {:?}", other),
    }
}

// =========================================================================
// 5. SlotDifferentialGate
// =========================================================================

#[test]
fn gate_register_and_evaluate_passes() {
    let mut g = gate();
    g.register_slot(inv("parser", SlotKind::Parser, false));

    let s = sid("parser");
    let corpus = vec![wl("w1", WorkloadCategory::SemanticEquivalence)];
    let output = cell("ok", 100, 1024, &[]);
    let out2 = output.clone();

    let (results, verdict) = g
        .evaluate_single(&s, &corpus, &|_| Ok(output.clone()), &|_| Ok(out2.clone()))
        .unwrap();

    assert_eq!(results.len(), 1);
    assert!(verdict.is_ready());
    assert!(g.passes());
}

#[test]
fn gate_fails_when_any_slot_diverges() {
    let mut g = gate();
    g.register_slot(inv("good", SlotKind::Parser, false));
    g.register_slot(inv("bad", SlotKind::Interpreter, false));

    // Good slot: matching.
    let good_id = sid("good");
    let corpus = vec![wl("g1", WorkloadCategory::SemanticEquivalence)];
    let o = cell("ok", 100, 1024, &[]);
    let o2 = o.clone();
    g.evaluate_single(&good_id, &corpus, &|_| Ok(o.clone()), &|_| Ok(o2.clone()))
        .unwrap();

    // Bad slot: semantic divergence.
    let bad_id = sid("bad");
    let corpus = vec![wl("b1", WorkloadCategory::SemanticEquivalence)];
    g.evaluate_single(
        &bad_id,
        &corpus,
        &|_| Ok(cell("native", 100, 1024, &[])),
        &|_| Ok(cell("delegate", 100, 1024, &[])),
    )
    .unwrap();

    assert!(!g.passes());
}

#[test]
fn gate_verdict_for_returns_correct_per_slot() {
    let mut g = gate();
    g.register_slot(inv("slot-a", SlotKind::Parser, false));
    g.register_slot(inv("slot-b", SlotKind::Interpreter, false));

    // Slot A: match.
    let a = sid("slot-a");
    let o = cell("ok", 100, 1024, &[]);
    let o2 = o.clone();
    g.evaluate_single(
        &a,
        &[wl("a1", WorkloadCategory::SemanticEquivalence)],
        &|_| Ok(o.clone()),
        &|_| Ok(o2.clone()),
    )
    .unwrap();

    // Slot B: diverge.
    let b = sid("slot-b");
    g.evaluate_single(
        &b,
        &[wl("b1", WorkloadCategory::SemanticEquivalence)],
        &|_| Ok(cell("x", 100, 1024, &[])),
        &|_| Ok(cell("y", 100, 1024, &[])),
    )
    .unwrap();

    assert!(g.verdict_for(&a).unwrap().is_ready());
    assert!(g.verdict_for(&b).unwrap().is_blocked());
    // Unknown slot returns None.
    assert!(g.verdict_for(&sid("nonexistent")).is_none());
}

#[test]
fn gate_finalize_evidence_returns_complete_evidence() {
    let mut g = gate();
    g.register_slot(inv("s1", SlotKind::Parser, false));
    g.register_slot(inv("s2", SlotKind::Interpreter, false));

    let o = cell("ok", 100, 1024, &[]);
    let o2 = o.clone();

    for name in &["s1", "s2"] {
        let s = sid(name);
        g.evaluate_single(
            &s,
            &[wl(
                &format!("{name}-w1"),
                WorkloadCategory::SemanticEquivalence,
            )],
            &|_| Ok(o.clone()),
            &|_| Ok(o2.clone()),
        )
        .unwrap();
    }

    let evidence = g.finalize_evidence();
    assert_eq!(evidence.verdicts.len(), 2);
    assert_eq!(evidence.environment_fingerprint, "integration-test-env");
    assert_eq!(evidence.epoch, epoch(1));
    assert!(!evidence.has_blocking_divergences());
}

#[test]
fn gate_slot_not_found_error() {
    let mut g = gate();
    let unknown = sid("unknown");
    let result = g.evaluate_single(
        &unknown,
        &[wl("w1", WorkloadCategory::SemanticEquivalence)],
        &|_| Ok(cell("ok", 100, 1024, &[])),
        &|_| Ok(cell("ok", 100, 1024, &[])),
    );
    assert!(matches!(
        result.unwrap_err(),
        SlotDifferentialError::SlotNotFound { .. }
    ));
}

// =========================================================================
// 6. SlotDifferentialEvidence
// =========================================================================

#[test]
fn evidence_increment_divergence_tallies() {
    let mut ev = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        epoch(1),
    );
    ev.increment_divergence(&DivergenceClass::SemanticDivergence);
    ev.increment_divergence(&DivergenceClass::SemanticDivergence);
    ev.increment_divergence(&DivergenceClass::CapabilityDivergence);
    ev.increment_divergence(&DivergenceClass::BenignImprovement);

    assert_eq!(ev.divergence_summary.get("semantic_divergence"), Some(&2));
    assert_eq!(ev.divergence_summary.get("capability_divergence"), Some(&1));
    assert_eq!(ev.divergence_summary.get("benign_improvement"), Some(&1));
    assert_eq!(ev.divergence_summary.get("performance_divergence"), None);
}

#[test]
fn evidence_has_blocking_on_blocked_verdict() {
    let mut ev = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        epoch(1),
    );
    ev.record_verdict(
        &sid("blocked-slot"),
        PromotionReadiness::Blocked {
            divergence_counts: BTreeMap::new(),
            repro_hashes: vec![],
        },
    );
    assert!(ev.has_blocking_divergences());
}

#[test]
fn evidence_has_blocking_on_regressed_verdict() {
    let mut ev = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        epoch(1),
    );
    ev.record_verdict(
        &sid("regressed-slot"),
        PromotionReadiness::Regressed {
            divergence_counts: BTreeMap::new(),
            repro_hashes: vec![],
            trigger_demotion: true,
        },
    );
    assert!(ev.has_blocking_divergences());
}

#[test]
fn evidence_no_blocking_when_all_ready() {
    let mut ev = SlotDifferentialEvidence::new(
        ContentHash::compute(b"c"),
        ContentHash::compute(b"r"),
        "env".to_string(),
        epoch(1),
    );
    ev.record_verdict(
        &sid("ready-slot"),
        PromotionReadiness::Ready {
            workload_count: 10,
            improvement_count: 2,
        },
    );
    assert!(!ev.has_blocking_divergences());
}

// =========================================================================
// 7. ReplacementReceiptFragment
// =========================================================================

#[test]
fn receipt_fragment_correct_counts_and_categories() {
    let results = vec![
        WorkloadResult {
            workload_id: "w1".to_string(),
            category: WorkloadCategory::SemanticEquivalence,
            native_output: cell("ok", 100, 1024, &[]),
            delegate_output: cell("ok", 100, 1024, &[]),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
        WorkloadResult {
            workload_id: "w2".to_string(),
            category: WorkloadCategory::EdgeCase,
            native_output: cell("ok", 100, 1024, &[]),
            delegate_output: cell("ok", 100, 1024, &[]),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
        WorkloadResult {
            workload_id: "w3".to_string(),
            category: WorkloadCategory::Adversarial,
            native_output: cell("ok", 80, 512, &[]),
            delegate_output: cell("ok", 100, 1024, &[]),
            outcome: DifferentialOutcome::Diverge,
            divergence_class: Some(DivergenceClass::BenignImprovement),
        },
    ];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        sid("receipt-slot"),
        &results,
        ContentHash::compute(b"ev"),
        ContentHash::compute(b"corpus"),
        epoch(7),
    );

    assert_eq!(fragment.slot_id, sid("receipt-slot"));
    assert_eq!(fragment.workload_count, 3);
    assert_eq!(fragment.categories_covered, 3); // all 3 categories
    assert_eq!(fragment.improvement_count, 1);
    assert_eq!(fragment.epoch, epoch(7));
}

#[test]
fn receipt_fragment_single_category_no_improvements() {
    let results = vec![WorkloadResult {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::Adversarial,
        native_output: cell("ok", 100, 1024, &[]),
        delegate_output: cell("ok", 100, 1024, &[]),
        outcome: DifferentialOutcome::Match,
        divergence_class: None,
    }];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        sid("single"),
        &results,
        ContentHash::compute(b"ev"),
        ContentHash::compute(b"corpus"),
        epoch(1),
    );

    assert_eq!(fragment.categories_covered, 1);
    assert_eq!(fragment.improvement_count, 0);
    assert_eq!(fragment.workload_count, 1);
}

// =========================================================================
// 8. Serde round-trips
// =========================================================================

#[test]
fn serde_roundtrip_divergence_class() {
    for class in &[
        DivergenceClass::SemanticDivergence,
        DivergenceClass::CapabilityDivergence,
        DivergenceClass::PerformanceDivergence,
        DivergenceClass::ResourceDivergence,
        DivergenceClass::BenignImprovement,
    ] {
        let json = serde_json::to_string(class).unwrap();
        let back: DivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, class);
    }
}

#[test]
fn serde_roundtrip_workload_category() {
    for cat in &[
        WorkloadCategory::SemanticEquivalence,
        WorkloadCategory::EdgeCase,
        WorkloadCategory::Adversarial,
    ] {
        let json = serde_json::to_string(cat).unwrap();
        let back: WorkloadCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, cat);
    }
}

#[test]
fn serde_roundtrip_differential_outcome() {
    for outcome in &[DifferentialOutcome::Match, DifferentialOutcome::Diverge] {
        let json = serde_json::to_string(outcome).unwrap();
        let back: DifferentialOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, outcome);
    }
}

#[test]
fn serde_roundtrip_promotion_readiness_all_variants() {
    let ready = PromotionReadiness::Ready {
        workload_count: 10,
        improvement_count: 3,
    };
    let json = serde_json::to_string(&ready).unwrap();
    let back: PromotionReadiness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ready);

    let mut counts = BTreeMap::new();
    counts.insert("semantic_divergence".to_string(), 2u64);
    let blocked = PromotionReadiness::Blocked {
        divergence_counts: counts.clone(),
        repro_hashes: vec![ContentHash::compute(b"r1")],
    };
    let json = serde_json::to_string(&blocked).unwrap();
    let back: PromotionReadiness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, blocked);

    let regressed = PromotionReadiness::Regressed {
        divergence_counts: counts,
        repro_hashes: vec![],
        trigger_demotion: true,
    };
    let json = serde_json::to_string(&regressed).unwrap();
    let back: PromotionReadiness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, regressed);
}

#[test]
fn serde_roundtrip_differential_config() {
    let config = DifferentialConfig {
        performance_threshold_millionths: 50_000,
        resource_threshold_millionths: 150_000,
        emit_repro_artifacts: false,
        epoch: epoch(42),
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: DifferentialConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

#[test]
fn serde_roundtrip_workload_result() {
    let wr = WorkloadResult {
        workload_id: "wr-1".to_string(),
        category: WorkloadCategory::EdgeCase,
        native_output: cell("ok", 100, 1024, &[SlotCapability::ReadSource]),
        delegate_output: cell("ok", 100, 1024, &[SlotCapability::ReadSource]),
        outcome: DifferentialOutcome::Match,
        divergence_class: None,
    };
    let json = serde_json::to_string(&wr).unwrap();
    let back: WorkloadResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, wr);
}

#[test]
fn serde_roundtrip_slot_differential_evidence() {
    let mut ev = SlotDifferentialEvidence::new(
        ContentHash::compute(b"corpus"),
        ContentHash::compute(b"registry"),
        "test-env".to_string(),
        epoch(5),
    );
    ev.record_verdict(
        &sid("parser"),
        PromotionReadiness::Ready {
            workload_count: 10,
            improvement_count: 2,
        },
    );
    ev.increment_divergence(&DivergenceClass::BenignImprovement);

    let json = serde_json::to_string(&ev).unwrap();
    let back: SlotDifferentialEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ev);
}

#[test]
fn serde_roundtrip_workload_log_entry() {
    let entry = WorkloadLogEntry {
        trace_id: "trace-42".to_string(),
        slot_id: sid("parser"),
        workload_id: "w1".to_string(),
        corpus_category: WorkloadCategory::Adversarial,
        outcome: DifferentialOutcome::Diverge,
        divergence_class: Some(DivergenceClass::SemanticDivergence),
        native_duration_us: 100,
        delegate_duration_us: 120,
        capability_diff: vec!["InvokeHostcall".to_string()],
        resource_diff: "+200 bytes".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: WorkloadLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn serde_roundtrip_divergence_repro() {
    let repro = build_repro(
        &sid("ser-slot"),
        &wl("ser-w1", WorkloadCategory::EdgeCase),
        &cell("a", 100, 1024, &[SlotCapability::ReadSource]),
        &cell("b", 100, 1024, &[]),
        &DivergenceClass::CapabilityDivergence,
        &ContentHash::compute(b"contract"),
    );
    let json = serde_json::to_string(&repro).unwrap();
    let back: DivergenceRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(back, repro);
}

// =========================================================================
// 9. Display traits
// =========================================================================

#[test]
fn display_divergence_class_all_variants() {
    assert_eq!(
        DivergenceClass::SemanticDivergence.to_string(),
        "semantic_divergence"
    );
    assert_eq!(
        DivergenceClass::CapabilityDivergence.to_string(),
        "capability_divergence"
    );
    assert_eq!(
        DivergenceClass::PerformanceDivergence.to_string(),
        "performance_divergence"
    );
    assert_eq!(
        DivergenceClass::ResourceDivergence.to_string(),
        "resource_divergence"
    );
    assert_eq!(
        DivergenceClass::BenignImprovement.to_string(),
        "benign_improvement"
    );
}

#[test]
fn display_workload_category_all_variants() {
    assert_eq!(
        WorkloadCategory::SemanticEquivalence.to_string(),
        "semantic_equivalence"
    );
    assert_eq!(WorkloadCategory::EdgeCase.to_string(), "edge_case");
    assert_eq!(WorkloadCategory::Adversarial.to_string(), "adversarial");
}

#[test]
fn display_differential_outcome_all_variants() {
    assert_eq!(DifferentialOutcome::Match.to_string(), "match");
    assert_eq!(DifferentialOutcome::Diverge.to_string(), "diverge");
}

#[test]
fn display_promotion_readiness_all_variants() {
    let ready = PromotionReadiness::Ready {
        workload_count: 5,
        improvement_count: 1,
    };
    assert_eq!(ready.to_string(), "ready");

    let blocked = PromotionReadiness::Blocked {
        divergence_counts: BTreeMap::new(),
        repro_hashes: vec![],
    };
    assert_eq!(blocked.to_string(), "blocked");

    let regressed = PromotionReadiness::Regressed {
        divergence_counts: BTreeMap::new(),
        repro_hashes: vec![],
        trigger_demotion: false,
    };
    assert_eq!(regressed.to_string(), "regressed");
}

// =========================================================================
// 10. SlotDifferentialError Display
// =========================================================================

#[test]
fn error_display_slot_not_found() {
    let e = SlotDifferentialError::SlotNotFound {
        slot_id: "parser".into(),
    };
    let s = e.to_string();
    assert!(s.contains("slot not found"));
    assert!(s.contains("parser"));
}

#[test]
fn error_display_empty_corpus() {
    let e = SlotDifferentialError::EmptyCorpus {
        slot_id: "gc".into(),
    };
    let s = e.to_string();
    assert!(s.contains("corpus is empty"));
    assert!(s.contains("gc"));
}

#[test]
fn error_display_invalid_config() {
    let e = SlotDifferentialError::InvalidConfig {
        detail: "negative threshold".into(),
    };
    let s = e.to_string();
    assert!(s.contains("invalid differential config"));
    assert!(s.contains("negative threshold"));
}

#[test]
fn error_display_cell_execution_failed() {
    let e = SlotDifferentialError::CellExecutionFailed {
        slot_id: "interpreter".into(),
        cell_type: "delegate".into(),
        detail: "timeout after 5s".into(),
    };
    let s = e.to_string();
    assert!(s.contains("interpreter"));
    assert!(s.contains("delegate"));
    assert!(s.contains("timeout after 5s"));
}

#[test]
fn error_display_internal_error() {
    let e = SlotDifferentialError::InternalError {
        detail: "invariant violated".into(),
    };
    let s = e.to_string();
    assert!(s.contains("internal differential gate error"));
    assert!(s.contains("invariant violated"));
}

// =========================================================================
// Additional: DivergenceClass property tests
// =========================================================================

#[test]
fn divergence_class_blocks_promotion_matches_spec() {
    assert!(DivergenceClass::SemanticDivergence.blocks_promotion());
    assert!(DivergenceClass::CapabilityDivergence.blocks_promotion());
    assert!(DivergenceClass::PerformanceDivergence.blocks_promotion());
    assert!(!DivergenceClass::ResourceDivergence.blocks_promotion());
    assert!(!DivergenceClass::BenignImprovement.blocks_promotion());
}

#[test]
fn divergence_class_triggers_demotion_matches_spec() {
    assert!(DivergenceClass::SemanticDivergence.triggers_demotion());
    assert!(DivergenceClass::CapabilityDivergence.triggers_demotion());
    assert!(!DivergenceClass::PerformanceDivergence.triggers_demotion());
    assert!(!DivergenceClass::ResourceDivergence.triggers_demotion());
    assert!(!DivergenceClass::BenignImprovement.triggers_demotion());
}

#[test]
fn divergence_class_as_str_matches_display() {
    for class in &[
        DivergenceClass::SemanticDivergence,
        DivergenceClass::CapabilityDivergence,
        DivergenceClass::PerformanceDivergence,
        DivergenceClass::ResourceDivergence,
        DivergenceClass::BenignImprovement,
    ] {
        assert_eq!(class.as_str(), &class.to_string());
    }
}

#[test]
fn promotion_readiness_predicates_are_exclusive() {
    let ready = PromotionReadiness::Ready {
        workload_count: 1,
        improvement_count: 0,
    };
    assert!(ready.is_ready());
    assert!(!ready.is_blocked());
    assert!(!ready.is_regressed());

    let blocked = PromotionReadiness::Blocked {
        divergence_counts: BTreeMap::new(),
        repro_hashes: vec![],
    };
    assert!(!blocked.is_ready());
    assert!(blocked.is_blocked());
    assert!(!blocked.is_regressed());

    let regressed = PromotionReadiness::Regressed {
        divergence_counts: BTreeMap::new(),
        repro_hashes: vec![],
        trigger_demotion: false,
    };
    assert!(!regressed.is_ready());
    assert!(!regressed.is_blocked());
    assert!(regressed.is_regressed());
}

#[test]
fn default_config_has_expected_values() {
    let c = DifferentialConfig::default();
    assert_eq!(c.performance_threshold_millionths, 100_000);
    assert_eq!(c.resource_threshold_millionths, 200_000);
    assert!(c.emit_repro_artifacts);
    assert_eq!(c.epoch, epoch(1));
}
