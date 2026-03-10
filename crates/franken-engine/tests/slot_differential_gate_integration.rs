//! Integration tests for the slot_differential module.
//!
//! Validates end-to-end differential gate workflows: slot registration,
//! workload corpus management, divergence classification, promotion readiness
//! verdicts, evidence artifact production, replacement receipt fragment
//! generation, and CI gate logic.
//!
//! bd-33z: Section 10.7 item 7.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::slot_differential::*;
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId, SlotKind};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn slot(name: &str) -> SlotId {
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
        ],
    }
}

fn config() -> DifferentialConfig {
    DifferentialConfig::default()
}

fn matching_output(val: &str) -> CellOutput {
    CellOutput {
        return_value: val.to_string(),
        side_effects: vec!["hostcall:log".to_string()],
        exceptions: vec![],
        evidence_entries: vec!["ev-1".to_string()],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    }
}

fn workload(id: &str, cat: WorkloadCategory) -> Workload {
    Workload {
        workload_id: id.to_string(),
        category: cat,
        input: format!("input-{id}"),
        expected_output: None,
    }
}

fn make_gate() -> SlotDifferentialGate {
    SlotDifferentialGate::new(
        config(),
        ContentHash::compute(b"corpus"),
        ContentHash::compute(b"registry"),
        "integration-test".to_string(),
    )
}

fn inventory_entry(name: &str, kind: SlotKind, was_ready: bool) -> SlotInventoryEntry {
    SlotInventoryEntry {
        slot_id: slot(name),
        kind,
        authority: authority(),
        was_previously_ready: was_ready,
    }
}

fn full_corpus(prefix: &str) -> Vec<Workload> {
    let mut wl = Vec::new();
    for i in 0..50 {
        wl.push(workload(
            &format!("{prefix}-s{i}"),
            WorkloadCategory::SemanticEquivalence,
        ));
    }
    for i in 0..20 {
        wl.push(workload(
            &format!("{prefix}-e{i}"),
            WorkloadCategory::EdgeCase,
        ));
    }
    for i in 0..10 {
        wl.push(workload(
            &format!("{prefix}-a{i}"),
            WorkloadCategory::Adversarial,
        ));
    }
    wl
}

// ---------------------------------------------------------------------------
// E2E: full lifecycle with matching outputs passes gate
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_lifecycle_matching_passes_gate() {
    let mut gate = make_gate();

    // Register 3 slots covering different slot kinds
    gate.register_slot(inventory_entry("parser", SlotKind::Parser, false));
    gate.register_slot(inventory_entry("interpreter", SlotKind::Interpreter, false));
    gate.register_slot(inventory_entry("gc", SlotKind::GarbageCollector, false));

    // Evaluate each slot with matching outputs
    for name in ["parser", "interpreter", "gc"] {
        let sid = slot(name);
        let corpus = full_corpus(name);
        let native_exec = |_w: &Workload| -> Result<CellOutput, SlotDifferentialError> {
            Ok(matching_output("42"))
        };
        let delegate_exec = |_w: &Workload| -> Result<CellOutput, SlotDifferentialError> {
            Ok(matching_output("42"))
        };
        let (results, verdict) = gate
            .evaluate_single(&sid, &corpus, &native_exec, &delegate_exec)
            .unwrap();

        assert_eq!(results.len(), 80); // 50 + 20 + 10
        assert!(verdict.is_ready());
    }

    assert!(gate.passes());
    let evidence = gate.finalize_evidence();
    assert_eq!(evidence.verdicts.len(), 3);
    assert!(!evidence.has_blocking_divergences());
}

// ---------------------------------------------------------------------------
// E2E: semantic divergence in one slot blocks the entire gate
// ---------------------------------------------------------------------------

#[test]
fn e2e_semantic_divergence_blocks_gate() {
    let mut gate = make_gate();

    gate.register_slot(inventory_entry("ok-slot", SlotKind::Parser, false));
    gate.register_slot(inventory_entry("bad-slot", SlotKind::Interpreter, false));

    // OK slot: matching
    let ok_id = slot("ok-slot");
    let ok_corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];
    let (_, ok_verdict) = gate
        .evaluate_single(&ok_id, &ok_corpus, &|_| Ok(matching_output("42")), &|_| {
            Ok(matching_output("42"))
        })
        .unwrap();
    assert!(ok_verdict.is_ready());

    // Bad slot: semantic divergence
    let bad_id = slot("bad-slot");
    let bad_corpus = vec![workload("w2", WorkloadCategory::SemanticEquivalence)];
    let native_diverge =
        |_w: &Workload| -> Result<CellOutput, SlotDifferentialError> { Ok(matching_output("42")) };
    let delegate_diverge =
        |_w: &Workload| -> Result<CellOutput, SlotDifferentialError> { Ok(matching_output("99")) };
    let (results, bad_verdict) = gate
        .evaluate_single(&bad_id, &bad_corpus, &native_diverge, &delegate_diverge)
        .unwrap();

    assert!(bad_verdict.is_blocked());
    assert_eq!(results[0].outcome, DifferentialOutcome::Diverge);
    assert_eq!(
        results[0].divergence_class,
        Some(DivergenceClass::SemanticDivergence)
    );

    // Gate fails overall
    assert!(!gate.passes());
    assert!(gate.finalize_evidence().has_blocking_divergences());
}

// ---------------------------------------------------------------------------
// Capability divergence: native exercises broader capabilities
// ---------------------------------------------------------------------------

#[test]
fn capability_divergence_blocks_promotion() {
    let cfg = config();
    let native = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![
            SlotCapability::ReadSource,
            SlotCapability::InvokeHostcall, // Not in delegate
        ],
        duration_us: 100,
        memory_bytes: 1024,
    };
    let delegate = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    };

    let class = classify_divergence(&native, &delegate, &cfg);
    assert_eq!(class, Some(DivergenceClass::CapabilityDivergence));
    assert!(DivergenceClass::CapabilityDivergence.blocks_promotion());
    assert!(DivergenceClass::CapabilityDivergence.triggers_demotion());
}

// ---------------------------------------------------------------------------
// Performance divergence: native slower than threshold
// ---------------------------------------------------------------------------

#[test]
fn performance_divergence_blocks_promotion() {
    let cfg = config(); // default: 100_000 = 10%
    let native = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 120, // 20% slower
        memory_bytes: 1024,
    };
    let delegate = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    };

    let class = classify_divergence(&native, &delegate, &cfg);
    assert_eq!(class, Some(DivergenceClass::PerformanceDivergence));
    assert!(DivergenceClass::PerformanceDivergence.blocks_promotion());
    // Does NOT trigger demotion
    assert!(!DivergenceClass::PerformanceDivergence.triggers_demotion());
}

// ---------------------------------------------------------------------------
// Resource divergence: native uses more memory (informational)
// ---------------------------------------------------------------------------

#[test]
fn resource_divergence_is_informational() {
    let cfg = config(); // default: 200_000 = 20% memory threshold
    let native = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1300, // 27% more memory
    };
    let delegate = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    };

    let class = classify_divergence(&native, &delegate, &cfg);
    assert_eq!(class, Some(DivergenceClass::ResourceDivergence));
    assert!(!DivergenceClass::ResourceDivergence.blocks_promotion());
    assert!(!DivergenceClass::ResourceDivergence.triggers_demotion());
}

// ---------------------------------------------------------------------------
// Benign improvement: native faster, same semantics
// ---------------------------------------------------------------------------

#[test]
fn benign_improvement_logged_not_blocking() {
    let cfg = config();
    let native = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 50,   // 50% faster
        memory_bytes: 512, // Less memory
    };
    let delegate = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    };

    let class = classify_divergence(&native, &delegate, &cfg);
    assert_eq!(class, Some(DivergenceClass::BenignImprovement));
    assert!(!DivergenceClass::BenignImprovement.blocks_promotion());
}

// ---------------------------------------------------------------------------
// Regression detection: previously ready slot now diverges
// ---------------------------------------------------------------------------

#[test]
fn regression_triggers_demotion_flag() {
    let mut gate = make_gate();

    // Slot was previously ready
    gate.register_slot(inventory_entry(
        "regressed-slot",
        SlotKind::ObjectModel,
        true, // was_previously_ready
    ));

    let sid = slot("regressed-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];

    // Semantic divergence on a previously-ready slot -> Regressed
    let (_, verdict) = gate
        .evaluate_single(&sid, &corpus, &|_| Ok(matching_output("42")), &|_| {
            Ok(matching_output("99"))
        })
        .unwrap();

    match &verdict {
        PromotionReadiness::Regressed {
            trigger_demotion, ..
        } => {
            assert!(*trigger_demotion);
        }
        other => panic!("expected Regressed, got {:?}", other),
    }
    assert!(verdict.is_regressed());
    assert!(!gate.passes());
}

// ---------------------------------------------------------------------------
// Empty corpus returns error
// ---------------------------------------------------------------------------

#[test]
fn empty_corpus_returns_error() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("empty-slot", SlotKind::Parser, false));

    let sid = slot("empty-slot");
    let empty: Vec<Workload> = vec![];
    let result = gate.evaluate_single(&sid, &empty, &|_| Ok(matching_output("42")), &|_| {
        Ok(matching_output("42"))
    });

    match result {
        Err(SlotDifferentialError::EmptyCorpus { .. }) => {}
        other => panic!("expected EmptyCorpus error, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Slot not found in gate
// ---------------------------------------------------------------------------

#[test]
fn slot_not_found_returns_error() {
    let mut gate = make_gate();
    let unknown = slot("unknown-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];
    let result = gate.evaluate_single(&unknown, &corpus, &|_| Ok(matching_output("42")), &|_| {
        Ok(matching_output("42"))
    });

    match result {
        Err(SlotDifferentialError::SlotNotFound { .. }) => {}
        other => panic!("expected SlotNotFound error, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Minimized repro artifact generation
// ---------------------------------------------------------------------------

#[test]
fn divergence_repro_artifact_generated() {
    let sid = slot("repro-slot");
    let wl = workload("repro-w1", WorkloadCategory::Adversarial);
    let native = matching_output("correct");
    let delegate = matching_output("wrong");
    let contract_hash = ContentHash::compute(b"repro-slot:parser");

    let repro = build_repro(
        &sid,
        &wl,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &contract_hash,
    );

    assert_eq!(repro.slot_id.as_str(), "repro-slot");
    assert_eq!(repro.divergence_class, DivergenceClass::SemanticDivergence);
    assert_eq!(repro.minimized_input, "input-repro-w1");
    assert_eq!(repro.native_output.return_value, "correct");
    assert_eq!(repro.delegate_output.return_value, "wrong");
    // Artifact hash is deterministically computed
    let hash2 = repro.compute_hash();
    assert_eq!(repro.artifact_hash, hash2);
}

// ---------------------------------------------------------------------------
// Repro capability diff computed correctly
// ---------------------------------------------------------------------------

#[test]
fn repro_captures_capability_diff() {
    let sid = slot("cap-slot");
    let wl = workload("cap-w1", WorkloadCategory::EdgeCase);
    let native = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource, SlotCapability::InvokeHostcall],
        duration_us: 100,
        memory_bytes: 1024,
    };
    let delegate = CellOutput {
        return_value: "42".to_string(),
        side_effects: vec![],
        exceptions: vec![],
        evidence_entries: vec![],
        capabilities_exercised: vec![SlotCapability::ReadSource],
        duration_us: 100,
        memory_bytes: 1024,
    };
    let contract_hash = ContentHash::compute(b"cap-slot:parser");

    let repro = build_repro(
        &sid,
        &wl,
        &native,
        &delegate,
        &DivergenceClass::CapabilityDivergence,
        &contract_hash,
    );

    assert_eq!(repro.capability_diff, vec![SlotCapability::InvokeHostcall]);
}

// ---------------------------------------------------------------------------
// Replacement receipt fragment from evaluation
// ---------------------------------------------------------------------------

#[test]
fn replacement_receipt_fragment_captures_categories() {
    let results = vec![
        WorkloadResult {
            workload_id: "w1".to_string(),
            category: WorkloadCategory::SemanticEquivalence,
            native_output: matching_output("42"),
            delegate_output: matching_output("42"),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
        WorkloadResult {
            workload_id: "w2".to_string(),
            category: WorkloadCategory::EdgeCase,
            native_output: matching_output("42"),
            delegate_output: matching_output("42"),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
        WorkloadResult {
            workload_id: "w3".to_string(),
            category: WorkloadCategory::Adversarial,
            native_output: matching_output("42"),
            delegate_output: matching_output("42"),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
    ];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        slot("receipt-slot"),
        &results,
        ContentHash::compute(b"evidence"),
        ContentHash::compute(b"corpus"),
        epoch(5),
    );

    assert_eq!(fragment.slot_id.as_str(), "receipt-slot");
    assert_eq!(fragment.workload_count, 3);
    assert_eq!(fragment.categories_covered, 3); // All 3 categories
    assert_eq!(fragment.improvement_count, 0);
    assert_eq!(fragment.epoch, epoch(5));
}

// ---------------------------------------------------------------------------
// Receipt fragment counts benign improvements
// ---------------------------------------------------------------------------

#[test]
fn replacement_receipt_fragment_counts_improvements() {
    let results = vec![
        WorkloadResult {
            workload_id: "w1".to_string(),
            category: WorkloadCategory::SemanticEquivalence,
            native_output: matching_output("42"),
            delegate_output: matching_output("42"),
            outcome: DifferentialOutcome::Diverge,
            divergence_class: Some(DivergenceClass::BenignImprovement),
        },
        WorkloadResult {
            workload_id: "w2".to_string(),
            category: WorkloadCategory::SemanticEquivalence,
            native_output: matching_output("42"),
            delegate_output: matching_output("42"),
            outcome: DifferentialOutcome::Match,
            divergence_class: None,
        },
    ];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        slot("imp-slot"),
        &results,
        ContentHash::compute(b"ev"),
        ContentHash::compute(b"corpus"),
        epoch(5),
    );

    assert_eq!(fragment.improvement_count, 1);
    assert_eq!(fragment.categories_covered, 1); // Only SemanticEquivalence
}

// ---------------------------------------------------------------------------
// Evidence artifact tracks divergence summary
// ---------------------------------------------------------------------------

#[test]
fn evidence_divergence_summary_across_slots() {
    let mut gate = make_gate();

    gate.register_slot(inventory_entry("slot-a", SlotKind::Parser, false));
    gate.register_slot(inventory_entry("slot-b", SlotKind::Interpreter, false));

    let sid_a = slot("slot-a");
    let corpus_a = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];

    // Slot A: semantic divergence
    gate.evaluate_single(&sid_a, &corpus_a, &|_| Ok(matching_output("42")), &|_| {
        Ok(matching_output("99"))
    })
    .unwrap();

    let sid_b = slot("slot-b");
    let corpus_b = vec![workload("w2", WorkloadCategory::SemanticEquivalence)];

    // Slot B: also semantic divergence
    gate.evaluate_single(&sid_b, &corpus_b, &|_| Ok(matching_output("a")), &|_| {
        Ok(matching_output("b"))
    })
    .unwrap();

    let evidence = gate.finalize_evidence();
    assert_eq!(evidence.verdicts.len(), 2);
    assert_eq!(
        *evidence
            .divergence_summary
            .get("semantic_divergence")
            .unwrap(),
        2
    );
    assert!(evidence.has_blocking_divergences());
}

// ---------------------------------------------------------------------------
// Multiple divergence classes in one slot
// ---------------------------------------------------------------------------

#[test]
fn all_divergence_classes_classified_correctly() {
    let cfg = config();

    // Semantic: different return values
    let class = classify_divergence(&matching_output("a"), &matching_output("b"), &cfg);
    assert_eq!(class, Some(DivergenceClass::SemanticDivergence));

    // Side-effect divergence -> semantic
    let native = CellOutput {
        side_effects: vec!["extra".to_string()],
        ..matching_output("42")
    };
    let class = classify_divergence(&native, &matching_output("42"), &cfg);
    assert_eq!(class, Some(DivergenceClass::SemanticDivergence));

    // Exception divergence -> semantic
    let native = CellOutput {
        exceptions: vec!["TypeError".to_string()],
        ..matching_output("42")
    };
    let class = classify_divergence(&native, &matching_output("42"), &cfg);
    assert_eq!(class, Some(DivergenceClass::SemanticDivergence));

    // Capability: native uses cap not in delegate
    let native = CellOutput {
        capabilities_exercised: vec![SlotCapability::ReadSource, SlotCapability::EmitEvidence],
        ..matching_output("42")
    };
    let class = classify_divergence(&native, &matching_output("42"), &cfg);
    assert_eq!(class, Some(DivergenceClass::CapabilityDivergence));
}

// ---------------------------------------------------------------------------
// No divergence when outputs are exactly equal
// ---------------------------------------------------------------------------

#[test]
fn exact_match_yields_no_divergence() {
    let cfg = config();
    let output = matching_output("42");
    let class = classify_divergence(&output, &output, &cfg);
    assert!(class.is_none());
}

// ---------------------------------------------------------------------------
// Gate with mixed verdicts across slots
// ---------------------------------------------------------------------------

#[test]
fn gate_mixed_verdicts_some_ready_some_blocked() {
    let mut gate = make_gate();

    gate.register_slot(inventory_entry("good-slot", SlotKind::ScopeModel, false));
    gate.register_slot(inventory_entry("bad-slot", SlotKind::AsyncRuntime, false));

    // Good slot: all match
    let good_id = slot("good-slot");
    let corpus = vec![
        workload("g1", WorkloadCategory::SemanticEquivalence),
        workload("g2", WorkloadCategory::EdgeCase),
    ];
    let (_, good_verdict) = gate
        .evaluate_single(&good_id, &corpus, &|_| Ok(matching_output("42")), &|_| {
            Ok(matching_output("42"))
        })
        .unwrap();
    assert!(good_verdict.is_ready());

    // Bad slot: diverge
    let bad_id = slot("bad-slot");
    let corpus = vec![workload("b1", WorkloadCategory::Adversarial)];
    let (_, bad_verdict) = gate
        .evaluate_single(&bad_id, &corpus, &|_| Ok(matching_output("42")), &|_| {
            Ok(matching_output("WRONG"))
        })
        .unwrap();
    assert!(bad_verdict.is_blocked());

    // Overall gate fails
    assert!(!gate.passes());

    // But we can inspect individual verdicts
    assert!(gate.verdict_for(&slot("good-slot")).unwrap().is_ready());
    assert!(gate.verdict_for(&slot("bad-slot")).unwrap().is_blocked());
}

// ---------------------------------------------------------------------------
// Evidence artifact serialization round-trip
// ---------------------------------------------------------------------------

#[test]
fn evidence_artifact_serde_round_trip() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("ser-slot", SlotKind::Parser, false));

    let sid = slot("ser-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];
    gate.evaluate_single(&sid, &corpus, &|_| Ok(matching_output("42")), &|_| {
        Ok(matching_output("42"))
    })
    .unwrap();

    let evidence = gate.finalize_evidence();
    let json = serde_json::to_string(evidence).unwrap();
    let back: SlotDifferentialEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(*evidence, back);
}

// ---------------------------------------------------------------------------
// Deterministic serialization
// ---------------------------------------------------------------------------

#[test]
fn evidence_serialization_is_deterministic() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("det-slot", SlotKind::ModuleLoader, false));

    let sid = slot("det-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];
    gate.evaluate_single(&sid, &corpus, &|_| Ok(matching_output("42")), &|_| {
        Ok(matching_output("42"))
    })
    .unwrap();

    let evidence = gate.finalize_evidence();
    let json1 = serde_json::to_string(evidence).unwrap();
    let json2 = serde_json::to_string(evidence).unwrap();
    assert_eq!(json1, json2, "serialization must be deterministic");
}

// ---------------------------------------------------------------------------
// Workload category coverage in receipt fragments
// ---------------------------------------------------------------------------

#[test]
fn receipt_fragment_single_category() {
    let results = vec![WorkloadResult {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::Adversarial,
        native_output: matching_output("42"),
        delegate_output: matching_output("42"),
        outcome: DifferentialOutcome::Match,
        divergence_class: None,
    }];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        slot("single-cat"),
        &results,
        ContentHash::compute(b"ev"),
        ContentHash::compute(b"corpus"),
        epoch(3),
    );

    assert_eq!(fragment.categories_covered, 1);
    assert_eq!(fragment.workload_count, 1);
}

// ---------------------------------------------------------------------------
// DivergenceClass display strings are stable
// ---------------------------------------------------------------------------

#[test]
fn divergence_class_display_strings() {
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

// ---------------------------------------------------------------------------
// WorkloadCategory display strings
// ---------------------------------------------------------------------------

#[test]
fn workload_category_display_strings() {
    assert_eq!(
        WorkloadCategory::SemanticEquivalence.to_string(),
        "semantic_equivalence"
    );
    assert_eq!(WorkloadCategory::EdgeCase.to_string(), "edge_case");
    assert_eq!(WorkloadCategory::Adversarial.to_string(), "adversarial");
}

// ---------------------------------------------------------------------------
// SlotDifferentialError display
// ---------------------------------------------------------------------------

#[test]
fn error_display_messages() {
    let e = SlotDifferentialError::SlotNotFound {
        slot_id: "x".into(),
    };
    assert!(e.to_string().contains("slot not found"));

    let e = SlotDifferentialError::EmptyCorpus {
        slot_id: "x".into(),
    };
    assert!(e.to_string().contains("corpus is empty"));

    let e = SlotDifferentialError::InvalidConfig {
        detail: "bad".into(),
    };
    assert!(e.to_string().contains("bad"));

    let e = SlotDifferentialError::CellExecutionFailed {
        slot_id: "x".into(),
        cell_type: "native".into(),
        detail: "timeout".into(),
    };
    assert!(e.to_string().contains("timeout"));

    let e = SlotDifferentialError::InternalError {
        detail: "oops".into(),
    };
    assert!(e.to_string().contains("oops"));
}

// ---------------------------------------------------------------------------
// Benign improvement counted in Ready verdict
// ---------------------------------------------------------------------------

#[test]
fn benign_improvement_counted_in_ready_verdict() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("imp-slot", SlotKind::Builtins, false));

    let sid = slot("imp-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];

    // Native is faster (benign improvement)
    let (_, verdict) = gate
        .evaluate_single(
            &sid,
            &corpus,
            &|_| {
                Ok(CellOutput {
                    duration_us: 50,
                    memory_bytes: 512,
                    ..matching_output("42")
                })
            },
            &|_| Ok(matching_output("42")),
        )
        .unwrap();

    match verdict {
        PromotionReadiness::Ready {
            improvement_count, ..
        } => assert_eq!(improvement_count, 1),
        other => panic!("expected Ready, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Cell execution failure propagated
// ---------------------------------------------------------------------------

#[test]
fn cell_execution_failure_propagated() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("fail-slot", SlotKind::Parser, false));

    let sid = slot("fail-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];

    let result = gate.evaluate_single(
        &sid,
        &corpus,
        &|_| {
            Err(SlotDifferentialError::CellExecutionFailed {
                slot_id: "fail-slot".into(),
                cell_type: "native".into(),
                detail: "segfault".into(),
            })
        },
        &|_| Ok(matching_output("42")),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        SlotDifferentialError::CellExecutionFailed { detail, .. } => {
            assert_eq!(detail, "segfault");
        }
        other => panic!("expected CellExecutionFailed, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// DivergenceRepro hash is content-addressed
// ---------------------------------------------------------------------------

#[test]
fn repro_hash_deterministic() {
    let sid = slot("hash-slot");
    let wl = workload("hash-w1", WorkloadCategory::EdgeCase);
    let native = matching_output("a");
    let delegate = matching_output("b");
    let contract_hash = ContentHash::compute(b"contract");

    let repro1 = build_repro(
        &sid,
        &wl,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &contract_hash,
    );
    let repro2 = build_repro(
        &sid,
        &wl,
        &native,
        &delegate,
        &DivergenceClass::SemanticDivergence,
        &contract_hash,
    );

    assert_eq!(repro1.artifact_hash, repro2.artifact_hash);
}

// ---------------------------------------------------------------------------
// Multi-slot evaluation with all slot kinds
// ---------------------------------------------------------------------------

#[test]
fn evaluate_all_slot_kinds() {
    let kinds = [
        ("parser", SlotKind::Parser),
        ("ir-lowering", SlotKind::IrLowering),
        ("cap-lowering", SlotKind::CapabilityLowering),
        ("exec-lowering", SlotKind::ExecLowering),
        ("interpreter", SlotKind::Interpreter),
        ("object-model", SlotKind::ObjectModel),
        ("scope-model", SlotKind::ScopeModel),
        ("async-runtime", SlotKind::AsyncRuntime),
        ("gc", SlotKind::GarbageCollector),
        ("module-loader", SlotKind::ModuleLoader),
        ("hostcall-dispatch", SlotKind::HostcallDispatch),
        ("builtins", SlotKind::Builtins),
    ];

    let mut gate = make_gate();

    for (name, kind) in &kinds {
        gate.register_slot(inventory_entry(name, *kind, false));
    }

    for (name, _) in &kinds {
        let sid = slot(name);
        let corpus = vec![workload(
            &format!("{name}-w1"),
            WorkloadCategory::SemanticEquivalence,
        )];
        let (_, verdict) = gate
            .evaluate_single(&sid, &corpus, &|_| Ok(matching_output("42")), &|_| {
                Ok(matching_output("42"))
            })
            .unwrap();
        assert!(verdict.is_ready());
    }

    assert!(gate.passes());
    assert_eq!(gate.finalize_evidence().verdicts.len(), 12);
}

// ---------------------------------------------------------------------------
// Workload result serde round trip
// ---------------------------------------------------------------------------

#[test]
fn workload_result_serde_round_trip() {
    let result = WorkloadResult {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::Adversarial,
        native_output: matching_output("42"),
        delegate_output: matching_output("42"),
        outcome: DifferentialOutcome::Match,
        divergence_class: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let back: WorkloadResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// DivergenceRepro serde round trip
// ---------------------------------------------------------------------------

#[test]
fn divergence_repro_serde_round_trip() {
    let repro = build_repro(
        &slot("ser-slot"),
        &workload("ser-w1", WorkloadCategory::EdgeCase),
        &matching_output("a"),
        &matching_output("b"),
        &DivergenceClass::SemanticDivergence,
        &ContentHash::compute(b"contract"),
    );

    let json = serde_json::to_string(&repro).unwrap();
    let back: DivergenceRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(repro, back);
}

// ---------------------------------------------------------------------------
// DifferentialConfig serde round trip
// ---------------------------------------------------------------------------

#[test]
fn differential_config_serde_round_trip() {
    let cfg = DifferentialConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: DifferentialConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// Enrichment: double evaluation, gate reset, receipt fragment serde, config
// ---------------------------------------------------------------------------

#[test]
fn double_evaluation_of_same_slot_updates_verdict() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry("re-eval-slot", SlotKind::Parser, false));

    let sid = slot("re-eval-slot");

    // First evaluation: diverge
    let (_, v1) = gate
        .evaluate_single(
            &sid,
            &[workload("w1", WorkloadCategory::SemanticEquivalence)],
            &|_| Ok(matching_output("42")),
            &|_| Ok(matching_output("99")),
        )
        .unwrap();
    assert!(v1.is_blocked());
    assert!(!gate.passes());

    // Second evaluation: matching (re-evaluate same slot)
    let (_, v2) = gate
        .evaluate_single(
            &sid,
            &[workload("w2", WorkloadCategory::SemanticEquivalence)],
            &|_| Ok(matching_output("42")),
            &|_| Ok(matching_output("42")),
        )
        .unwrap();
    assert!(v2.is_ready());
    // Gate should now pass since the latest verdict is Ready
    assert!(gate.passes());
}

#[test]
fn replacement_receipt_fragment_serde_roundtrip() {
    let results = vec![WorkloadResult {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::SemanticEquivalence,
        native_output: matching_output("42"),
        delegate_output: matching_output("42"),
        outcome: DifferentialOutcome::Match,
        divergence_class: None,
    }];

    let fragment = ReplacementReceiptFragment::from_evaluation(
        slot("serde-frag"),
        &results,
        ContentHash::compute(b"evidence"),
        ContentHash::compute(b"corpus"),
        epoch(7),
    );

    let json = serde_json::to_string(&fragment).unwrap();
    let back: ReplacementReceiptFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(fragment, back);
}

#[test]
fn slot_inventory_entry_serde_roundtrip() {
    let entry = inventory_entry("inv-serde", SlotKind::Parser, true);
    let json = serde_json::to_string(&entry).unwrap();
    let back: SlotInventoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn differential_config_default_has_positive_thresholds() {
    let cfg = DifferentialConfig::default();
    assert!(
        cfg.performance_threshold_millionths > 0,
        "performance threshold should be positive"
    );
    assert!(
        cfg.resource_threshold_millionths > 0,
        "memory threshold should be positive"
    );
}

#[test]
fn evidence_with_only_informational_divergences_passes_gate() {
    let mut gate = make_gate();
    gate.register_slot(inventory_entry(
        "resource-slot",
        SlotKind::GarbageCollector,
        false,
    ));

    let sid = slot("resource-slot");
    let corpus = vec![workload("w1", WorkloadCategory::SemanticEquivalence)];

    // Native uses more memory but same semantics (resource divergence = informational)
    let (results, _verdict) = gate
        .evaluate_single(
            &sid,
            &corpus,
            &|_| {
                Ok(CellOutput {
                    return_value: "42".to_string(),
                    side_effects: vec![],
                    exceptions: vec![],
                    evidence_entries: vec![],
                    capabilities_exercised: vec![SlotCapability::ReadSource],
                    duration_us: 100,
                    memory_bytes: 2048, // much more memory
                })
            },
            &|_| Ok(matching_output("42")),
        )
        .unwrap();

    // Resource divergence is informational, should not block
    assert!(
        results[0].divergence_class == Some(DivergenceClass::ResourceDivergence)
            || results[0].divergence_class == Some(DivergenceClass::BenignImprovement)
            || results[0].divergence_class.is_none(),
        "divergence: {:?}",
        results[0].divergence_class
    );
    // Gate passes because resource divergence is informational
    assert!(gate.passes());
}
