#![forbid(unsafe_code)]
//! Integration tests for the `frir_schema` module.
//!
//! Exercises FrirLoweringPipeline construction, PassWitness recording,
//! WitnessChain verification, EquivalenceWitness, FrirArtifact, PipelineConfig,
//! invariant and obligation tracking, fallback triggers, and serde round-trips.

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

use std::collections::BTreeSet;

use frankenengine_engine::frir_schema::{
    AssumptionRef, ChainVerification, EffectAnnotation, EquivalenceKind, EquivalenceWitness,
    FRIR_SCHEMA_VERSION, FallbackReason, FrirArtifact, FrirLoweringPipeline, FrirPipelineError,
    FrirPipelineEvent, FrirPipelineEventKind, FrirVersion, InvariantCheck, InvariantKind,
    LaneTarget, ObligationRef, PassKind, PassWitness, PipelineConfig, WitnessChain, WitnessVerdict,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::EffectBoundary;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

fn make_invariant(kind: InvariantKind, passed: bool) -> InvariantCheck {
    InvariantCheck {
        kind,
        passed,
        description: format!("{kind:?} check"),
        evidence_hash: Some(make_hash(b"evidence")),
    }
}

fn make_obligation(id: &str, discharged: bool) -> ObligationRef {
    ObligationRef {
        id: id.into(),
        description: format!("obligation {id}"),
        discharged,
        discharge_evidence: if discharged {
            Some(make_hash(b"discharge"))
        } else {
            None
        },
    }
}

fn make_assumption(id: &str, validated: bool) -> AssumptionRef {
    AssumptionRef {
        id: id.into(),
        description: format!("assumption {id}"),
        validated,
        established_by_pass: if validated { Some(0) } else { None },
    }
}

fn make_witness(index: usize, kind: PassKind, input: &[u8], output: &[u8]) -> PassWitness {
    PassWitness {
        pass_index: index,
        pass_kind: kind,
        input_hash: make_hash(input),
        output_hash: make_hash(output),
        invariants_checked: vec![make_invariant(InvariantKind::TypeSafety, true)],
        obligations_touched: vec![make_obligation("obl-1", true)],
        assumptions: vec![make_assumption("asm-1", true)],
        effect_annotations: vec![EffectAnnotation::pure_annotation()],
        target_lane: LaneTarget::Js,
        computed_offline: false,
        computation_cost_millionths: 50_000,
        witness_hash: make_hash(&[input, output].concat()),
    }
}

fn make_chained_witnesses() -> (PassWitness, PassWitness) {
    let w1 = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let w2 = PassWitness {
        pass_index: 1,
        pass_kind: PassKind::ScopeResolve,
        input_hash: w1.output_hash.clone(),
        output_hash: make_hash(b"resolved"),
        invariants_checked: vec![make_invariant(InvariantKind::SemanticEquivalence, true)],
        obligations_touched: vec![],
        assumptions: vec![],
        effect_annotations: vec![],
        target_lane: LaneTarget::Js,
        computed_offline: false,
        computation_cost_millionths: 30_000,
        witness_hash: make_hash(b"w2-hash"),
    };
    (w1, w2)
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn frir_schema_version() {
    assert!(FRIR_SCHEMA_VERSION.contains("frir-schema"));
}

// ===========================================================================
// 2. FrirVersion
// ===========================================================================

#[test]
fn frir_version_current() {
    let v = FrirVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
    assert_eq!(v.patch, 0);
}

#[test]
fn frir_version_can_read_same() {
    let v = FrirVersion::CURRENT;
    assert!(v.can_read(&v));
}

#[test]
fn frir_version_display() {
    let v = FrirVersion::CURRENT;
    assert_eq!(v.to_string(), "0.1.0");
}

#[test]
fn frir_version_serde() {
    let v = FrirVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let back: FrirVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 3. LaneTarget
// ===========================================================================

#[test]
fn lane_target_display() {
    assert!(!LaneTarget::Js.to_string().is_empty());
    assert!(!LaneTarget::Wasm.to_string().is_empty());
    assert!(!LaneTarget::Baseline.to_string().is_empty());
}

#[test]
fn lane_target_serde() {
    for t in [LaneTarget::Js, LaneTarget::Wasm, LaneTarget::Baseline] {
        let json = serde_json::to_string(&t).unwrap();
        let back: LaneTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}

// ===========================================================================
// 4. PassKind
// ===========================================================================

#[test]
fn pass_kind_all_variants_serde() {
    let kinds = [
        PassKind::Parse,
        PassKind::ScopeResolve,
        PassKind::CapabilityAnnotate,
        PassKind::EffectAnalysis,
        PassKind::HookSlotValidation,
        PassKind::DependencyGraph,
        PassKind::DeadCodeElimination,
        PassKind::MemoizationBoundary,
        PassKind::SignalGraphExtraction,
        PassKind::DomUpdatePlanning,
        PassKind::EGraphOptimization,
        PassKind::PartialEvaluation,
        PassKind::Incrementalization,
        PassKind::CodeGeneration,
        PassKind::Custom,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: PassKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
}

// ===========================================================================
// 5. InvariantKind
// ===========================================================================

#[test]
fn invariant_kind_serde() {
    let kinds = [
        InvariantKind::SemanticEquivalence,
        InvariantKind::TypeSafety,
        InvariantKind::EffectContainment,
        InvariantKind::HookOrdering,
        InvariantKind::CapabilityMonotonicity,
        InvariantKind::Determinism,
        InvariantKind::ResourceBound,
        InvariantKind::Custom,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: InvariantKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
}

// ===========================================================================
// 6. WitnessVerdict
// ===========================================================================

#[test]
fn witness_verdict_allows_optimized() {
    assert!(WitnessVerdict::Valid.allows_optimized_path());
    assert!(!WitnessVerdict::Invalid.allows_optimized_path());
    assert!(!WitnessVerdict::Missing.allows_optimized_path());
    assert!(!WitnessVerdict::Stale.allows_optimized_path());
    assert!(!WitnessVerdict::TimedOut.allows_optimized_path());
}

#[test]
fn witness_verdict_serde() {
    for v in [
        WitnessVerdict::Valid,
        WitnessVerdict::Invalid,
        WitnessVerdict::Missing,
        WitnessVerdict::Stale,
        WitnessVerdict::TimedOut,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: WitnessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ===========================================================================
// 7. EquivalenceKind
// ===========================================================================

#[test]
fn equivalence_kind_serde() {
    for k in [
        EquivalenceKind::Observational,
        EquivalenceKind::Trace,
        EquivalenceKind::Effect,
        EquivalenceKind::Output,
        EquivalenceKind::Approximate,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: EquivalenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// 8. PassWitness
// ===========================================================================

#[test]
fn pass_witness_all_invariants_hold() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    assert!(w.all_invariants_hold());
}

#[test]
fn pass_witness_failed_invariant() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.invariants_checked
        .push(make_invariant(InvariantKind::Determinism, false));
    assert!(!w.all_invariants_hold());
    assert_eq!(w.failed_invariant_count(), 1);
}

#[test]
fn pass_witness_all_obligations_discharged() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    assert!(w.all_obligations_discharged());
}

#[test]
fn pass_witness_undischarged_obligation() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.obligations_touched.push(make_obligation("obl-2", false));
    assert!(!w.all_obligations_discharged());
    assert_eq!(w.undischarged_obligation_count(), 1);
}

#[test]
fn pass_witness_chain_links() {
    let (w1, w2) = make_chained_witnesses();
    assert!(w2.chain_links_to(&w1.output_hash));
}

#[test]
fn pass_witness_verdict_valid() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    assert_eq!(w.verdict(), WitnessVerdict::Valid);
}

#[test]
fn pass_witness_serde() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    let json = serde_json::to_string(&w).unwrap();
    let back: PassWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
}

// ===========================================================================
// 9. EffectAnnotation
// ===========================================================================

#[test]
fn pure_annotation_compatible_with_all() {
    let ann = EffectAnnotation::pure_annotation();
    assert!(ann.is_compatible(LaneTarget::Js));
    assert!(ann.is_compatible(LaneTarget::Wasm));
    assert!(ann.is_compatible(LaneTarget::Baseline));
}

#[test]
fn effect_annotation_serde() {
    let ann = EffectAnnotation::pure_annotation();
    let json = serde_json::to_string(&ann).unwrap();
    let back: EffectAnnotation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ann);
}

// ===========================================================================
// 10. EquivalenceWitness
// ===========================================================================

#[test]
fn equivalence_witness_proven() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Observational,
        test_input_count: 1000,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![InvariantKind::SemanticEquivalence],
        witness_hash: make_hash(b"equiv"),
    };
    assert!(w.is_proven());
}

#[test]
fn equivalence_witness_not_proven() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Observational,
        test_input_count: 1000,
        all_outputs_matched: false,
        counterexample_hash: Some(make_hash(b"counterexample")),
        preserved_invariants: vec![],
        witness_hash: make_hash(b"equiv"),
    };
    assert!(!w.is_proven());
}

#[test]
fn equivalence_witness_serde() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Trace,
        test_input_count: 100,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![InvariantKind::TypeSafety],
        witness_hash: make_hash(b"w"),
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: EquivalenceWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
}

// ===========================================================================
// 11. PipelineConfig
// ===========================================================================

#[test]
fn pipeline_config_production() {
    let config = PipelineConfig::production();
    assert!(config.budget_ms > 0);
    assert!(config.max_passes > 0);
}

#[test]
fn pipeline_config_offline_analysis() {
    let config = PipelineConfig::offline_analysis();
    assert!(config.enable_offline_witnesses);
    assert!(config.enable_equivalence_witnesses);
}

#[test]
fn pipeline_config_default_is_production() {
    let default = PipelineConfig::default();
    let production = PipelineConfig::production();
    assert_eq!(default.budget_ms, production.budget_ms);
    assert_eq!(default.max_passes, production.max_passes);
}

#[test]
fn pipeline_config_serde() {
    let config = PipelineConfig::production();
    let json = serde_json::to_string(&config).unwrap();
    let back: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 12. FrirLoweringPipeline — construction
// ===========================================================================

#[test]
fn pipeline_new_empty() {
    let pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    assert_eq!(pipeline.pass_count(), 0);
    assert!(!pipeline.has_fallen_back());
    assert!(pipeline.fallback_reasons().is_empty());
}

#[test]
fn pipeline_default() {
    let pipeline = FrirLoweringPipeline::default();
    assert_eq!(pipeline.pass_count(), 0);
}

// ===========================================================================
// 13. FrirLoweringPipeline — record_pass
// ===========================================================================

#[test]
fn pipeline_record_pass() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    pipeline.record_pass(w).unwrap();
    assert_eq!(pipeline.pass_count(), 1);
}

#[test]
fn pipeline_record_chained_passes() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let (w1, w2) = make_chained_witnesses();
    pipeline.record_pass(w1).unwrap();
    pipeline.record_pass(w2).unwrap();
    assert_eq!(pipeline.pass_count(), 2);
}

#[test]
fn pipeline_duplicate_pass_index_fails() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w1 = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let w2 = make_witness(0, PassKind::ScopeResolve, b"parsed", b"resolved");
    pipeline.record_pass(w1).unwrap();
    let result = pipeline.record_pass(w2);
    assert!(result.is_err());
}

// ===========================================================================
// 14. FrirLoweringPipeline — fallback
// ===========================================================================

#[test]
fn pipeline_trigger_fallback() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    pipeline.trigger_fallback(FallbackReason::ExplicitOptOut {
        reason: "testing".into(),
    });
    assert!(pipeline.has_fallen_back());
    assert_eq!(pipeline.fallback_reasons().len(), 1);
}

#[test]
fn pipeline_fallback_missing_witness() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    pipeline.trigger_fallback(FallbackReason::MissingWitness {
        pass_index: 0,
        pass_kind: PassKind::Parse,
    });
    assert!(pipeline.has_fallen_back());
}

// ===========================================================================
// 15. FrirLoweringPipeline — obligations and assumptions
// ===========================================================================

#[test]
fn pipeline_tracks_obligations() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    pipeline.record_pass(w).unwrap();
    assert!(!pipeline.obligations().is_empty());
    assert!(pipeline.all_obligations_discharged());
}

#[test]
fn pipeline_undischarged_obligations() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.obligations_touched = vec![make_obligation("obl-pending", false)];
    pipeline.record_pass(w).unwrap();
    assert!(!pipeline.all_obligations_discharged());
    assert!(!pipeline.undischarged_obligations().is_empty());
}

// ===========================================================================
// 16. FrirLoweringPipeline — finalize
// ===========================================================================

#[test]
fn pipeline_finalize_single_pass() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    pipeline.record_pass(w).unwrap();

    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();
    assert!(artifact.is_valid());
    assert_eq!(artifact.target_lane, LaneTarget::Js);
}

#[test]
fn pipeline_finalize_chained_passes() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let (w1, w2) = make_chained_witnesses();
    pipeline.record_pass(w1).unwrap();
    pipeline.record_pass(w2).unwrap();

    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();
    assert!(artifact.is_valid());
}

#[test]
fn pipeline_finalize_with_equivalence_witness() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::offline_analysis());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    pipeline.record_pass(w).unwrap();

    let equiv = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Observational,
        test_input_count: 500,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![InvariantKind::SemanticEquivalence],
        witness_hash: make_hash(b"equiv"),
    };
    pipeline.record_equivalence_witness(equiv);

    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();
    assert!(artifact.all_equivalences_proven());
    assert_eq!(artifact.equivalence_witnesses.len(), 1);
}

// ===========================================================================
// 17. FrirLoweringPipeline — events
// ===========================================================================

#[test]
fn pipeline_emits_events() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    pipeline.record_pass(w).unwrap();
    assert!(!pipeline.events().is_empty());
}

// ===========================================================================
// 18. WitnessChain
// ===========================================================================

#[test]
fn witness_chain_verify_valid() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let (w1, w2) = make_chained_witnesses();
    pipeline.record_pass(w1).unwrap();
    pipeline.record_pass(w2).unwrap();
    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();

    let verification = artifact.witness_chain.verify();
    assert!(verification.valid, "errors: {:?}", verification.errors);
}

#[test]
fn witness_chain_total_cost() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let (w1, w2) = make_chained_witnesses();
    pipeline.record_pass(w1).unwrap();
    pipeline.record_pass(w2).unwrap();
    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();

    assert!(artifact.witness_chain.total_cost_millionths() > 0);
}

// ===========================================================================
// 19. FrirArtifact
// ===========================================================================

#[test]
fn frir_artifact_serde_round_trip() {
    let mut pipeline = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    pipeline.record_pass(w).unwrap();
    let artifact = pipeline.finalize(make_hash(b"source")).unwrap();

    let json = serde_json::to_string(&artifact).unwrap();
    let back: FrirArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ===========================================================================
// 20. FallbackReason
// ===========================================================================

#[test]
fn fallback_reason_display() {
    let reasons = [
        FallbackReason::MissingWitness {
            pass_index: 0,
            pass_kind: PassKind::Parse,
        },
        FallbackReason::InvalidWitness {
            pass_index: 1,
            pass_kind: PassKind::ScopeResolve,
            detail: "bad hash".into(),
        },
        FallbackReason::StaleWitness {
            pass_index: 2,
            pass_kind: PassKind::EffectAnalysis,
        },
        FallbackReason::VerificationBudgetExceeded {
            elapsed_ms: 100,
            budget_ms: 50,
        },
        FallbackReason::ExplicitOptOut {
            reason: "testing".into(),
        },
    ];
    for r in &reasons {
        assert!(!r.to_string().is_empty());
    }
}

#[test]
fn fallback_reason_serde() {
    let reason = FallbackReason::ExplicitOptOut {
        reason: "test".into(),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: FallbackReason = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reason);
}

// ===========================================================================
// 21. FrirPipelineError
// ===========================================================================

#[test]
fn pipeline_error_display() {
    let errors = [
        FrirPipelineError::PassLimitExceeded {
            count: 100,
            max: 50,
        },
        FrirPipelineError::DuplicatePassIndex(3),
        FrirPipelineError::BudgetExceeded {
            elapsed_ms: 200,
            budget_ms: 100,
        },
    ];
    for e in &errors {
        assert!(!e.to_string().is_empty());
    }
}

// ===========================================================================
// 22. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_multi_pass_pipeline() {
    let config = PipelineConfig::offline_analysis();
    let mut pipeline = FrirLoweringPipeline::new(config);

    // Stage 1: Parse
    let w1 = make_witness(0, PassKind::Parse, b"source-code", b"ast");
    pipeline.record_pass(w1).unwrap();

    // Stage 2: Scope resolution (chained)
    let w2 = PassWitness {
        pass_index: 1,
        pass_kind: PassKind::ScopeResolve,
        input_hash: make_hash(b"ast"),
        output_hash: make_hash(b"scoped-ast"),
        invariants_checked: vec![
            make_invariant(InvariantKind::SemanticEquivalence, true),
            make_invariant(InvariantKind::TypeSafety, true),
        ],
        obligations_touched: vec![make_obligation("scope-obl", true)],
        assumptions: vec![],
        effect_annotations: vec![EffectAnnotation::pure_annotation()],
        target_lane: LaneTarget::Js,
        computed_offline: true,
        computation_cost_millionths: 200_000,
        witness_hash: make_hash(b"w2"),
    };
    pipeline.record_pass(w2).unwrap();

    // Stage 3: Capability annotation (chained)
    let w3 = PassWitness {
        pass_index: 2,
        pass_kind: PassKind::CapabilityAnnotate,
        input_hash: make_hash(b"scoped-ast"),
        output_hash: make_hash(b"annotated-ast"),
        invariants_checked: vec![make_invariant(InvariantKind::CapabilityMonotonicity, true)],
        obligations_touched: vec![],
        assumptions: vec![],
        effect_annotations: vec![],
        target_lane: LaneTarget::Js,
        computed_offline: true,
        computation_cost_millionths: 100_000,
        witness_hash: make_hash(b"w3"),
    };
    pipeline.record_pass(w3).unwrap();

    // Add equivalence witness
    let equiv = EquivalenceWitness {
        reference_hash: make_hash(b"baseline-output"),
        optimized_hash: make_hash(b"annotated-ast"),
        equivalence_kind: EquivalenceKind::Observational,
        test_input_count: 1000,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![
            InvariantKind::SemanticEquivalence,
            InvariantKind::EffectContainment,
        ],
        witness_hash: make_hash(b"equiv-w"),
    };
    pipeline.record_equivalence_witness(equiv);

    // Finalize
    let artifact = pipeline.finalize(make_hash(b"source-code")).unwrap();

    // Verify
    assert!(artifact.is_valid());
    assert!(artifact.all_equivalences_proven());
    assert_eq!(artifact.witness_chain.passes.len(), 3);
    assert!(artifact.witness_chain.total_cost_millionths() > 0);
    assert_eq!(artifact.witness_chain.offline_pass_count(), 2);
    assert_eq!(artifact.witness_chain.online_pass_count(), 1);

    // Serde round-trip
    let json = serde_json::to_string(&artifact).unwrap();
    let back: FrirArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ===========================================================================
// 23. Enrichment: PearlTower 2026-03-12
// ===========================================================================

// ---------------------------------------------------------------------------
// FrirVersion — can_read edge cases
// ---------------------------------------------------------------------------

#[test]
fn frir_version_can_read_older_minor_higher_patch() {
    let reader = FrirVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    let artifact = FrirVersion {
        major: 0,
        minor: 1,
        patch: 99,
    };
    assert!(reader.can_read(&artifact));
}

#[test]
fn frir_version_cannot_read_newer_minor() {
    let reader = FrirVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let artifact = FrirVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    assert!(!reader.can_read(&artifact));
}

#[test]
fn frir_version_cannot_read_different_major_even_if_minor_ok() {
    let reader = FrirVersion {
        major: 1,
        minor: 5,
        patch: 0,
    };
    let artifact = FrirVersion {
        major: 2,
        minor: 0,
        patch: 0,
    };
    assert!(!reader.can_read(&artifact));
}

#[test]
fn frir_version_major_zero_cannot_read_major_one() {
    let v0 = FrirVersion {
        major: 0,
        minor: 10,
        patch: 0,
    };
    let v1 = FrirVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(!v0.can_read(&v1));
    assert!(!v1.can_read(&v0));
}

#[test]
fn frir_version_display_large_numbers() {
    let v = FrirVersion {
        major: 999,
        minor: 888,
        patch: 777,
    };
    assert_eq!(v.to_string(), "999.888.777");
}

#[test]
fn frir_version_ord_ordering() {
    let v010 = FrirVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let v020 = FrirVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    let v100 = FrirVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(v010 < v020);
    assert!(v020 < v100);
}

#[test]
fn frir_version_clone_eq() {
    let v = FrirVersion {
        major: 3,
        minor: 4,
        patch: 5,
    };
    let cloned = v;
    assert_eq!(v, cloned);
}

#[test]
fn frir_version_serde_custom() {
    let v = FrirVersion {
        major: 10,
        minor: 20,
        patch: 30,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: FrirVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// LaneTarget — ordering and enum exhaustiveness
// ---------------------------------------------------------------------------

#[test]
fn lane_target_ord_is_deterministic() {
    let mut lanes = vec![LaneTarget::Baseline, LaneTarget::Js, LaneTarget::Wasm];
    lanes.sort();
    // Js < Wasm < Baseline based on derive ordering
    assert_eq!(lanes[0], LaneTarget::Js);
    assert_eq!(lanes[1], LaneTarget::Wasm);
    assert_eq!(lanes[2], LaneTarget::Baseline);
}

#[test]
fn lane_target_clone_copy_semantics() {
    let original = LaneTarget::Wasm;
    let copied = original;
    let cloned = original.clone();
    assert_eq!(original, copied);
    assert_eq!(original, cloned);
}

// ---------------------------------------------------------------------------
// PassKind — ordering, additional display coverage
// ---------------------------------------------------------------------------

#[test]
fn pass_kind_ord_deterministic() {
    let mut kinds = vec![PassKind::Custom, PassKind::Parse, PassKind::CodeGeneration];
    kinds.sort();
    // Parse is first in enum declaration, Custom is last
    assert_eq!(kinds[0], PassKind::Parse);
    assert!(kinds[2] == PassKind::Custom);
}

#[test]
fn pass_kind_display_all_15_non_empty() {
    let all = [
        PassKind::Parse,
        PassKind::ScopeResolve,
        PassKind::CapabilityAnnotate,
        PassKind::EffectAnalysis,
        PassKind::HookSlotValidation,
        PassKind::DependencyGraph,
        PassKind::DeadCodeElimination,
        PassKind::MemoizationBoundary,
        PassKind::SignalGraphExtraction,
        PassKind::DomUpdatePlanning,
        PassKind::EGraphOptimization,
        PassKind::PartialEvaluation,
        PassKind::Incrementalization,
        PassKind::CodeGeneration,
        PassKind::Custom,
    ];
    let mut set = BTreeSet::new();
    for k in &all {
        let s = k.to_string();
        assert!(!s.is_empty());
        set.insert(s);
    }
    assert_eq!(set.len(), 15);
}

// ---------------------------------------------------------------------------
// WitnessVerdict — allows_optimized_path exhaustive
// ---------------------------------------------------------------------------

#[test]
fn witness_verdict_only_valid_allows_optimized() {
    let verdicts = [
        (WitnessVerdict::Valid, true),
        (WitnessVerdict::Invalid, false),
        (WitnessVerdict::Missing, false),
        (WitnessVerdict::Stale, false),
        (WitnessVerdict::TimedOut, false),
    ];
    for (v, expected) in &verdicts {
        assert_eq!(v.allows_optimized_path(), *expected, "verdict: {v}");
    }
}

#[test]
fn witness_verdict_ord_deterministic() {
    let mut verdicts = vec![
        WitnessVerdict::TimedOut,
        WitnessVerdict::Valid,
        WitnessVerdict::Missing,
        WitnessVerdict::Invalid,
        WitnessVerdict::Stale,
    ];
    verdicts.sort();
    assert_eq!(verdicts[0], WitnessVerdict::Valid);
}

// ---------------------------------------------------------------------------
// InvariantKind — Ord and all 8 variants
// ---------------------------------------------------------------------------

#[test]
fn invariant_kind_all_8_distinct_debug() {
    let all = [
        InvariantKind::SemanticEquivalence,
        InvariantKind::TypeSafety,
        InvariantKind::EffectContainment,
        InvariantKind::HookOrdering,
        InvariantKind::CapabilityMonotonicity,
        InvariantKind::Determinism,
        InvariantKind::ResourceBound,
        InvariantKind::Custom,
    ];
    let set: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(set.len(), 8);
}

#[test]
fn invariant_kind_display_resource_bound_exact() {
    assert_eq!(InvariantKind::ResourceBound.to_string(), "resource_bound");
}

#[test]
fn invariant_kind_display_custom_exact() {
    assert_eq!(InvariantKind::Custom.to_string(), "custom");
}

// ---------------------------------------------------------------------------
// InvariantCheck — construction and serde
// ---------------------------------------------------------------------------

#[test]
fn invariant_check_passed_with_evidence() {
    let ic = InvariantCheck {
        kind: InvariantKind::TypeSafety,
        passed: true,
        description: "type check ok".into(),
        evidence_hash: Some(make_hash(b"type-evidence")),
    };
    assert!(ic.passed);
    assert!(ic.evidence_hash.is_some());
}

#[test]
fn invariant_check_failed_no_evidence() {
    let ic = InvariantCheck {
        kind: InvariantKind::Determinism,
        passed: false,
        description: "nondeterministic output".into(),
        evidence_hash: None,
    };
    assert!(!ic.passed);
    assert!(ic.evidence_hash.is_none());
}

#[test]
fn invariant_check_serde_with_none_evidence() {
    let ic = InvariantCheck {
        kind: InvariantKind::EffectContainment,
        passed: true,
        description: "contained".into(),
        evidence_hash: None,
    };
    let json = serde_json::to_string(&ic).unwrap();
    let back: InvariantCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(ic, back);
    assert!(json.contains("null") || !json.contains("evidence_hash"));
}

#[test]
fn invariant_check_serde_with_some_evidence() {
    let ic = make_invariant(InvariantKind::HookOrdering, true);
    let json = serde_json::to_string(&ic).unwrap();
    let back: InvariantCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(ic, back);
}

// ---------------------------------------------------------------------------
// ObligationRef — field access and serde
// ---------------------------------------------------------------------------

#[test]
fn obligation_ref_discharged_has_evidence() {
    let ob = make_obligation("ob-discharged", true);
    assert!(ob.discharged);
    assert!(ob.discharge_evidence.is_some());
}

#[test]
fn obligation_ref_undischarged_no_evidence() {
    let ob = make_obligation("ob-pending", false);
    assert!(!ob.discharged);
    assert!(ob.discharge_evidence.is_none());
}

#[test]
fn obligation_ref_serde_undischarged() {
    let ob = make_obligation("ob-pending", false);
    let json = serde_json::to_string(&ob).unwrap();
    let back: ObligationRef = serde_json::from_str(&json).unwrap();
    assert_eq!(ob, back);
}

#[test]
fn obligation_ref_ord_by_id() {
    let ob_a = ObligationRef {
        id: "aaa".into(),
        description: "".into(),
        discharged: false,
        discharge_evidence: None,
    };
    let ob_b = ObligationRef {
        id: "bbb".into(),
        description: "".into(),
        discharged: false,
        discharge_evidence: None,
    };
    assert!(ob_a < ob_b);
}

// ---------------------------------------------------------------------------
// AssumptionRef — field access and serde
// ---------------------------------------------------------------------------

#[test]
fn assumption_ref_validated_with_pass() {
    let a = AssumptionRef {
        id: "asm-1".into(),
        description: "scope assumption".into(),
        validated: true,
        established_by_pass: Some(2),
    };
    assert!(a.validated);
    assert_eq!(a.established_by_pass, Some(2));
}

#[test]
fn assumption_ref_not_validated_no_pass() {
    let a = make_assumption("asm-pending", false);
    assert!(!a.validated);
    assert!(a.established_by_pass.is_none());
}

#[test]
fn assumption_ref_serde_with_established_by() {
    let a = AssumptionRef {
        id: "asm-2".into(),
        description: "assumed pure".into(),
        validated: true,
        established_by_pass: Some(5),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: AssumptionRef = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn assumption_ref_ord_by_id() {
    let a1 = AssumptionRef {
        id: "aaa".into(),
        description: "".into(),
        validated: false,
        established_by_pass: None,
    };
    let a2 = AssumptionRef {
        id: "zzz".into(),
        description: "".into(),
        validated: false,
        established_by_pass: None,
    };
    assert!(a1 < a2);
}

// ---------------------------------------------------------------------------
// EffectAnnotation — DOM-only, custom capabilities, incompatible lanes
// ---------------------------------------------------------------------------

#[test]
fn effect_annotation_dom_only_js_compatible() {
    let ann = EffectAnnotation {
        boundary: EffectBoundary::WriteEffect,
        required_capabilities: {
            let mut s = BTreeSet::new();
            s.insert("dom".to_string());
            s
        },
        compatible_lanes: {
            let mut s = BTreeSet::new();
            s.insert(LaneTarget::Js);
            s
        },
        wasm_safe: false,
        requires_dom: true,
    };
    assert!(ann.is_compatible(LaneTarget::Js));
    assert!(!ann.is_compatible(LaneTarget::Wasm));
    assert!(!ann.is_compatible(LaneTarget::Baseline));
    assert!(ann.requires_dom);
    assert!(!ann.wasm_safe);
}

#[test]
fn effect_annotation_empty_lanes_compatible_with_none() {
    let ann = EffectAnnotation {
        boundary: EffectBoundary::NetworkEffect,
        required_capabilities: BTreeSet::new(),
        compatible_lanes: BTreeSet::new(),
        wasm_safe: false,
        requires_dom: false,
    };
    assert!(!ann.is_compatible(LaneTarget::Js));
    assert!(!ann.is_compatible(LaneTarget::Wasm));
    assert!(!ann.is_compatible(LaneTarget::Baseline));
}

#[test]
fn effect_annotation_with_capabilities_serde() {
    let mut caps = BTreeSet::new();
    caps.insert("network".to_string());
    caps.insert("fs".to_string());
    let mut lanes = BTreeSet::new();
    lanes.insert(LaneTarget::Js);
    lanes.insert(LaneTarget::Baseline);
    let ann = EffectAnnotation {
        boundary: EffectBoundary::FsEffect,
        required_capabilities: caps,
        compatible_lanes: lanes,
        wasm_safe: false,
        requires_dom: false,
    };
    let json = serde_json::to_string(&ann).unwrap();
    let back: EffectAnnotation = serde_json::from_str(&json).unwrap();
    assert_eq!(ann, back);
    assert_eq!(back.required_capabilities.len(), 2);
}

#[test]
fn pure_annotation_boundary_is_pure() {
    let ann = EffectAnnotation::pure_annotation();
    assert_eq!(ann.boundary, EffectBoundary::Pure);
}

#[test]
fn pure_annotation_no_required_capabilities() {
    let ann = EffectAnnotation::pure_annotation();
    assert!(ann.required_capabilities.is_empty());
}

#[test]
fn pure_annotation_three_compatible_lanes() {
    let ann = EffectAnnotation::pure_annotation();
    assert_eq!(ann.compatible_lanes.len(), 3);
}

// ---------------------------------------------------------------------------
// PassWitness — verdict logic, chain_links_to, multiple failed invariants
// ---------------------------------------------------------------------------

#[test]
fn pass_witness_verdict_invalid_both_invariant_and_obligation_fail() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.invariants_checked
        .push(make_invariant(InvariantKind::Determinism, false));
    w.obligations_touched
        .push(make_obligation("obl-bad", false));
    assert_eq!(w.verdict(), WitnessVerdict::Invalid);
    assert_eq!(w.failed_invariant_count(), 1);
    assert_eq!(w.undischarged_obligation_count(), 1);
}

#[test]
fn pass_witness_multiple_failed_invariants() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.invariants_checked
        .push(make_invariant(InvariantKind::Determinism, false));
    w.invariants_checked
        .push(make_invariant(InvariantKind::EffectContainment, false));
    w.invariants_checked
        .push(make_invariant(InvariantKind::CapabilityMonotonicity, false));
    assert_eq!(w.failed_invariant_count(), 3);
    assert!(!w.all_invariants_hold());
}

#[test]
fn pass_witness_chain_links_to_wrong_hash_is_false() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    let wrong_hash = make_hash(b"completely-wrong");
    assert!(!w.chain_links_to(&wrong_hash));
}

#[test]
fn pass_witness_chain_links_to_correct_hash_is_true() {
    let (w1, w2) = make_chained_witnesses();
    assert!(w2.chain_links_to(&w1.output_hash));
}

#[test]
fn pass_witness_empty_invariants_all_hold() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.invariants_checked.clear();
    assert!(w.all_invariants_hold());
    assert_eq!(w.failed_invariant_count(), 0);
}

#[test]
fn pass_witness_empty_obligations_all_discharged() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    w.obligations_touched.clear();
    assert!(w.all_obligations_discharged());
    assert_eq!(w.undischarged_obligation_count(), 0);
}

#[test]
fn pass_witness_computed_offline_flag() {
    let mut w = make_witness(0, PassKind::Parse, b"in", b"out");
    assert!(!w.computed_offline);
    w.computed_offline = true;
    assert!(w.computed_offline);
}

// ---------------------------------------------------------------------------
// WitnessChain — direct construction and verify
// ---------------------------------------------------------------------------

#[test]
fn witness_chain_verify_empty_is_invalid() {
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: Vec::new(),
        source_hash: make_hash(b"src"),
        final_output_hash: make_hash(b"out"),
        target_lane: LaneTarget::Js,
        complete: false,
        chain_hash: make_hash(b"chain"),
    };
    let v = chain.verify();
    assert!(!v.valid);
    assert!(!v.errors.is_empty());
    assert!(v.pass_verdicts.is_empty());
}

#[test]
fn witness_chain_verify_source_hash_mismatch() {
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w.clone()],
        source_hash: make_hash(b"wrong-source"),
        final_output_hash: w.output_hash,
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    let v = chain.verify();
    assert!(!v.valid);
    assert!(v.errors.iter().any(|e| e.contains("source hash")));
}

#[test]
fn witness_chain_verify_final_output_mismatch() {
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w.clone()],
        source_hash: w.input_hash,
        final_output_hash: make_hash(b"wrong-final"),
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    let v = chain.verify();
    assert!(!v.valid);
    assert!(v.errors.iter().any(|e| e.contains("final output hash")));
}

#[test]
fn witness_chain_verify_broken_link_between_passes() {
    let w0 = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let w1 = make_witness(1, PassKind::ScopeResolve, b"wrong-input", b"resolved");
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w0.clone(), w1.clone()],
        source_hash: w0.input_hash,
        final_output_hash: w1.output_hash,
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    let v = chain.verify();
    assert!(!v.valid);
}

#[test]
fn witness_chain_verify_pass_with_invalid_verdict() {
    let mut w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    w.invariants_checked
        .push(make_invariant(InvariantKind::Determinism, false));
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w.clone()],
        source_hash: w.input_hash,
        final_output_hash: w.output_hash,
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    let v = chain.verify();
    assert!(!v.valid);
    assert_eq!(v.pass_verdicts.len(), 1);
    assert_eq!(v.pass_verdicts[0], WitnessVerdict::Invalid);
}

#[test]
fn witness_chain_total_cost_single_pass() {
    let w = make_witness(0, PassKind::Parse, b"in", b"out");
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w.clone()],
        source_hash: w.input_hash,
        final_output_hash: w.output_hash,
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    assert_eq!(chain.total_cost_millionths(), 50_000);
}

#[test]
fn witness_chain_offline_online_split() {
    let mut w0 = make_witness(0, PassKind::Parse, b"source", b"parsed");
    w0.computed_offline = true;
    let mut w1 = make_witness(1, PassKind::ScopeResolve, b"parsed", b"resolved");
    w1.input_hash = w0.output_hash;
    w1.computed_offline = false;
    let mut w2 = make_witness(2, PassKind::EffectAnalysis, b"resolved", b"analyzed");
    w2.input_hash = w1.output_hash;
    w2.computed_offline = true;
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w0, w1, w2],
        source_hash: make_hash(b"source"),
        final_output_hash: make_hash(b"analyzed"),
        target_lane: LaneTarget::Js,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    assert_eq!(chain.offline_pass_count(), 2);
    assert_eq!(chain.online_pass_count(), 1);
}

#[test]
fn witness_chain_serde_roundtrip() {
    let (w1, w2) = make_chained_witnesses();
    let chain = WitnessChain {
        schema_version: FRIR_SCHEMA_VERSION.to_string(),
        frir_version: FrirVersion::CURRENT,
        passes: vec![w1.clone(), w2.clone()],
        source_hash: w1.input_hash,
        final_output_hash: w2.output_hash,
        target_lane: LaneTarget::Wasm,
        complete: true,
        chain_hash: make_hash(b"chain"),
    };
    let json = serde_json::to_string(&chain).unwrap();
    let back: WitnessChain = serde_json::from_str(&json).unwrap();
    assert_eq!(chain, back);
}

// ---------------------------------------------------------------------------
// ChainVerification — serde and fields
// ---------------------------------------------------------------------------

#[test]
fn chain_verification_valid_serde() {
    let cv = ChainVerification {
        valid: true,
        errors: Vec::new(),
        pass_verdicts: vec![WitnessVerdict::Valid, WitnessVerdict::Valid],
    };
    let json = serde_json::to_string(&cv).unwrap();
    let back: ChainVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(cv, back);
}

#[test]
fn chain_verification_invalid_serde() {
    let cv = ChainVerification {
        valid: false,
        errors: vec![
            "broken chain at pass 1".to_string(),
            "source mismatch".to_string(),
        ],
        pass_verdicts: vec![WitnessVerdict::Valid, WitnessVerdict::Invalid],
    };
    let json = serde_json::to_string(&cv).unwrap();
    let back: ChainVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(cv, back);
    assert_eq!(back.errors.len(), 2);
}

// ---------------------------------------------------------------------------
// EquivalenceWitness — edge cases
// ---------------------------------------------------------------------------

#[test]
fn equivalence_witness_matched_but_with_counterexample_not_proven() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Output,
        test_input_count: 500,
        all_outputs_matched: true,
        counterexample_hash: Some(make_hash(b"spurious")),
        preserved_invariants: vec![],
        witness_hash: make_hash(b"w"),
    };
    // counterexample_hash is Some => not proven even if all_outputs_matched
    assert!(!w.is_proven());
}

#[test]
fn equivalence_witness_not_matched_no_counterexample_not_proven() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Trace,
        test_input_count: 0,
        all_outputs_matched: false,
        counterexample_hash: None,
        preserved_invariants: vec![],
        witness_hash: make_hash(b"w"),
    };
    assert!(!w.is_proven());
}

#[test]
fn equivalence_witness_all_kinds_serde() {
    for kind in [
        EquivalenceKind::Observational,
        EquivalenceKind::Trace,
        EquivalenceKind::Effect,
        EquivalenceKind::Output,
        EquivalenceKind::Approximate,
    ] {
        let w = EquivalenceWitness {
            reference_hash: make_hash(b"ref"),
            optimized_hash: make_hash(b"opt"),
            equivalence_kind: kind,
            test_input_count: 100,
            all_outputs_matched: true,
            counterexample_hash: None,
            preserved_invariants: vec![InvariantKind::SemanticEquivalence],
            witness_hash: make_hash(b"eq"),
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: EquivalenceWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}

// ---------------------------------------------------------------------------
// FallbackReason — Display exact format for all 6 variants
// ---------------------------------------------------------------------------

#[test]
fn fallback_reason_display_exact_missing_witness() {
    let r = FallbackReason::MissingWitness {
        pass_index: 5,
        pass_kind: PassKind::CodeGeneration,
    };
    assert_eq!(r.to_string(), "missing witness at pass 5 (code_generation)");
}

#[test]
fn fallback_reason_display_exact_invalid_witness() {
    let r = FallbackReason::InvalidWitness {
        pass_index: 3,
        pass_kind: PassKind::HookSlotValidation,
        detail: "hook order violated".into(),
    };
    assert_eq!(
        r.to_string(),
        "invalid witness at pass 3 (hook_slot_validation): hook order violated"
    );
}

#[test]
fn fallback_reason_display_exact_stale_witness() {
    let r = FallbackReason::StaleWitness {
        pass_index: 7,
        pass_kind: PassKind::Incrementalization,
    };
    assert_eq!(
        r.to_string(),
        "stale witness at pass 7 (incrementalization)"
    );
}

#[test]
fn fallback_reason_display_exact_budget_exceeded() {
    let r = FallbackReason::VerificationBudgetExceeded {
        elapsed_ms: 12345,
        budget_ms: 5000,
    };
    assert_eq!(
        r.to_string(),
        "verification budget exceeded: 12345ms > 5000ms"
    );
}

#[test]
fn fallback_reason_display_exact_unfulfilled_obligation() {
    let r = FallbackReason::UnfulfilledObligation {
        obligation_id: "scope-check".into(),
        pass_index: 2,
    };
    assert_eq!(
        r.to_string(),
        "unfulfilled obligation scope-check at pass 2"
    );
}

#[test]
fn fallback_reason_display_exact_explicit_opt_out() {
    let r = FallbackReason::ExplicitOptOut {
        reason: "debug mode".into(),
    };
    assert_eq!(r.to_string(), "explicit opt-out: debug mode");
}

#[test]
fn fallback_reason_serde_all_6_variants() {
    let variants = vec![
        FallbackReason::MissingWitness {
            pass_index: 0,
            pass_kind: PassKind::Parse,
        },
        FallbackReason::InvalidWitness {
            pass_index: 1,
            pass_kind: PassKind::ScopeResolve,
            detail: "bad".into(),
        },
        FallbackReason::StaleWitness {
            pass_index: 2,
            pass_kind: PassKind::EffectAnalysis,
        },
        FallbackReason::VerificationBudgetExceeded {
            elapsed_ms: 100,
            budget_ms: 50,
        },
        FallbackReason::UnfulfilledObligation {
            obligation_id: "ob-1".into(),
            pass_index: 4,
        },
        FallbackReason::ExplicitOptOut {
            reason: "test".into(),
        },
    ];
    for r in &variants {
        let json = serde_json::to_string(r).unwrap();
        let back: FallbackReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, &back);
    }
}

// ---------------------------------------------------------------------------
// FrirPipelineError — Display exact for all 7 variants, serde
// ---------------------------------------------------------------------------

#[test]
fn pipeline_error_display_exact_obligation_limit() {
    let e = FrirPipelineError::ObligationLimitExceeded {
        count: 600,
        max: 512,
    };
    assert_eq!(e.to_string(), "obligation limit exceeded: 600 > 512");
}

#[test]
fn pipeline_error_display_exact_assumption_limit() {
    let e = FrirPipelineError::AssumptionLimitExceeded {
        count: 300,
        max: 256,
    };
    assert_eq!(e.to_string(), "assumption limit exceeded: 300 > 256");
}

#[test]
fn pipeline_error_display_exact_broken_chain() {
    let e = FrirPipelineError::BrokenChain {
        pass_index: 4,
        detail: "mismatch".into(),
    };
    assert_eq!(e.to_string(), "broken chain at pass 4: mismatch");
}

#[test]
fn pipeline_error_display_exact_invariant_failed() {
    let e = FrirPipelineError::InvariantFailed {
        kind: InvariantKind::HookOrdering,
        pass_index: 1,
        detail: "hook order".into(),
    };
    assert_eq!(
        e.to_string(),
        "invariant hook_ordering failed at pass 1: hook order"
    );
}

#[test]
fn pipeline_error_serde_all_7_variants() {
    let variants: Vec<FrirPipelineError> = vec![
        FrirPipelineError::PassLimitExceeded { count: 65, max: 64 },
        FrirPipelineError::ObligationLimitExceeded {
            count: 600,
            max: 512,
        },
        FrirPipelineError::AssumptionLimitExceeded {
            count: 300,
            max: 256,
        },
        FrirPipelineError::BrokenChain {
            pass_index: 1,
            detail: "x".into(),
        },
        FrirPipelineError::InvariantFailed {
            kind: InvariantKind::Determinism,
            pass_index: 0,
            detail: "y".into(),
        },
        FrirPipelineError::BudgetExceeded {
            elapsed_ms: 99,
            budget_ms: 50,
        },
        FrirPipelineError::DuplicatePassIndex(9),
    ];
    for e in &variants {
        let json = serde_json::to_string(e).unwrap();
        let back: FrirPipelineError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &back);
    }
}

// ---------------------------------------------------------------------------
// FrirPipelineEventKind — serde all 7 variants
// ---------------------------------------------------------------------------

#[test]
fn pipeline_event_kind_serde_all_7() {
    let kinds = [
        FrirPipelineEventKind::PipelineStarted,
        FrirPipelineEventKind::PassExecuted,
        FrirPipelineEventKind::WitnessProduced,
        FrirPipelineEventKind::WitnessVerified,
        FrirPipelineEventKind::FallbackTriggered,
        FrirPipelineEventKind::EquivalenceWitnessProduced,
        FrirPipelineEventKind::PipelineCompleted,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let back: FrirPipelineEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, &back);
    }
    assert_eq!(kinds.len(), 7);
}

#[test]
fn pipeline_event_kind_display_all_7_distinct() {
    let kinds = [
        FrirPipelineEventKind::PipelineStarted,
        FrirPipelineEventKind::PassExecuted,
        FrirPipelineEventKind::WitnessProduced,
        FrirPipelineEventKind::WitnessVerified,
        FrirPipelineEventKind::FallbackTriggered,
        FrirPipelineEventKind::EquivalenceWitnessProduced,
        FrirPipelineEventKind::PipelineCompleted,
    ];
    let set: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(set.len(), 7);
}

// ---------------------------------------------------------------------------
// FrirPipelineEvent — serde
// ---------------------------------------------------------------------------

#[test]
fn pipeline_event_serde_with_pass_index() {
    let event = FrirPipelineEvent {
        seq: 10,
        kind: FrirPipelineEventKind::PassExecuted,
        pass_index: Some(3),
        detail: "scope_resolve".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: FrirPipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn pipeline_event_serde_without_pass_index() {
    let event = FrirPipelineEvent {
        seq: 0,
        kind: FrirPipelineEventKind::PipelineStarted,
        pass_index: None,
        detail: "".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: FrirPipelineEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(back.pass_index.is_none());
}

// ---------------------------------------------------------------------------
// PipelineConfig — offline_analysis invariants exact check
// ---------------------------------------------------------------------------

#[test]
fn pipeline_config_offline_has_all_7_invariant_kinds() {
    let c = PipelineConfig::offline_analysis();
    assert!(
        c.required_invariants
            .contains(&InvariantKind::SemanticEquivalence)
    );
    assert!(c.required_invariants.contains(&InvariantKind::TypeSafety));
    assert!(
        c.required_invariants
            .contains(&InvariantKind::EffectContainment)
    );
    assert!(c.required_invariants.contains(&InvariantKind::HookOrdering));
    assert!(
        c.required_invariants
            .contains(&InvariantKind::CapabilityMonotonicity)
    );
    assert!(c.required_invariants.contains(&InvariantKind::Determinism));
    assert!(
        c.required_invariants
            .contains(&InvariantKind::ResourceBound)
    );
}

#[test]
fn pipeline_config_offline_max_passes_64() {
    let c = PipelineConfig::offline_analysis();
    assert_eq!(c.max_passes, 64);
}

#[test]
fn pipeline_config_offline_serde() {
    let c = PipelineConfig::offline_analysis();
    let json = serde_json::to_string(&c).unwrap();
    let back: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn pipeline_config_production_does_not_contain_type_safety() {
    let c = PipelineConfig::production();
    assert!(!c.required_invariants.contains(&InvariantKind::TypeSafety));
}

// ---------------------------------------------------------------------------
// FrirLoweringPipeline — broken chain, budget exceeded, assumption tracking
// ---------------------------------------------------------------------------

#[test]
fn pipeline_broken_chain_error() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w0 = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w0).unwrap();
    // Second witness with mismatched input hash
    let w1 = make_witness(1, PassKind::ScopeResolve, b"wrong-input", b"resolved");
    let err = p.record_pass(w1).unwrap_err();
    assert!(matches!(err, FrirPipelineError::BrokenChain { .. }));
}

#[test]
fn pipeline_budget_exceeded_triggers_fallback() {
    let mut config = PipelineConfig::production();
    config.budget_ms = 0;
    let mut p = FrirLoweringPipeline::new(config);
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    let err = p.record_pass(w).unwrap_err();
    assert!(matches!(err, FrirPipelineError::BudgetExceeded { .. }));
    assert!(p.has_fallen_back());
    assert!(!p.fallback_reasons().is_empty());
}

#[test]
fn pipeline_assumptions_accumulated() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    assert!(!p.assumptions().is_empty());
}

#[test]
fn pipeline_multiple_fallback_reasons() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    p.trigger_fallback(FallbackReason::ExplicitOptOut {
        reason: "first".into(),
    });
    p.trigger_fallback(FallbackReason::ExplicitOptOut {
        reason: "second".into(),
    });
    assert!(p.has_fallen_back());
    assert_eq!(p.fallback_reasons().len(), 2);
}

#[test]
fn pipeline_events_include_fallback() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    p.trigger_fallback(FallbackReason::ExplicitOptOut {
        reason: "test".into(),
    });
    assert!(
        p.events()
            .iter()
            .any(|e| e.kind == FrirPipelineEventKind::FallbackTriggered)
    );
}

#[test]
fn pipeline_events_monotone_seq() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    p.finalize(make_hash(b"source")).unwrap();
    let events = p.events();
    for window in events.windows(2) {
        assert!(
            window[0].seq < window[1].seq,
            "events must have monotonically increasing seq"
        );
    }
}

#[test]
fn pipeline_serde_roundtrip_after_pass() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    let back: FrirLoweringPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn pipeline_default_config_is_production() {
    let p = FrirLoweringPipeline::default();
    assert_eq!(p.config, PipelineConfig::production());
}

// ---------------------------------------------------------------------------
// FrirArtifact — all_equivalences_proven, is_valid edge cases
// ---------------------------------------------------------------------------

#[test]
fn frir_artifact_no_equivalences_is_all_proven() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    // Empty equivalence list => all_equivalences_proven() is vacuously true
    assert!(artifact.all_equivalences_proven());
    assert!(artifact.equivalence_witnesses.is_empty());
}

#[test]
fn frir_artifact_disproven_equivalence() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::offline_analysis());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let disproven = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Observational,
        test_input_count: 50,
        all_outputs_matched: false,
        counterexample_hash: Some(make_hash(b"counter")),
        preserved_invariants: vec![],
        witness_hash: make_hash(b"eq-disproven"),
    };
    p.record_equivalence_witness(disproven);
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    assert!(!artifact.all_equivalences_proven());
}

#[test]
fn frir_artifact_schema_version_matches_constant() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    assert_eq!(artifact.schema_version, FRIR_SCHEMA_VERSION);
}

#[test]
fn frir_artifact_frir_version_matches_current() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    assert_eq!(artifact.frir_version, FrirVersion::CURRENT);
}

#[test]
fn frir_artifact_aggregated_effects_from_passes() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    // The make_witness helper adds one pure annotation per pass
    assert_eq!(artifact.aggregated_effects.len(), 1);
}

#[test]
fn frir_artifact_required_capabilities_empty_for_pure() {
    let mut p = FrirLoweringPipeline::new(PipelineConfig::production());
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    // Pure annotations have no required capabilities
    assert!(artifact.required_capabilities.is_empty());
}

#[test]
fn frir_artifact_target_lane_from_config() {
    let mut config = PipelineConfig::production();
    config.target_lane = LaneTarget::Wasm;
    let mut p = FrirLoweringPipeline::new(config);
    let w = make_witness(0, PassKind::Parse, b"source", b"parsed");
    p.record_pass(w).unwrap();
    let artifact = p.finalize(make_hash(b"source")).unwrap();
    assert_eq!(artifact.target_lane, LaneTarget::Wasm);
}

// ---------------------------------------------------------------------------
// JSON field name stability
// ---------------------------------------------------------------------------

#[test]
fn json_field_names_frir_version() {
    let v = FrirVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"major\""));
    assert!(json.contains("\"minor\""));
    assert!(json.contains("\"patch\""));
}

#[test]
fn json_field_names_pipeline_config() {
    let c = PipelineConfig::production();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"target_lane\""));
    assert!(json.contains("\"budget_ms\""));
    assert!(json.contains("\"enable_offline_witnesses\""));
    assert!(json.contains("\"enable_equivalence_witnesses\""));
    assert!(json.contains("\"required_invariants\""));
    assert!(json.contains("\"max_passes\""));
}

#[test]
fn json_field_names_obligation_ref() {
    let ob = make_obligation("ob-1", true);
    let json = serde_json::to_string(&ob).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"discharged\""));
    assert!(json.contains("\"discharge_evidence\""));
}

#[test]
fn json_field_names_assumption_ref() {
    let a = make_assumption("asm-1", true);
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"validated\""));
    assert!(json.contains("\"established_by_pass\""));
}

#[test]
fn json_field_names_invariant_check() {
    let ic = make_invariant(InvariantKind::TypeSafety, true);
    let json = serde_json::to_string(&ic).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"passed\""));
    assert!(json.contains("\"description\""));
    assert!(json.contains("\"evidence_hash\""));
}

#[test]
fn json_field_names_effect_annotation() {
    let ann = EffectAnnotation::pure_annotation();
    let json = serde_json::to_string(&ann).unwrap();
    assert!(json.contains("\"boundary\""));
    assert!(json.contains("\"required_capabilities\""));
    assert!(json.contains("\"compatible_lanes\""));
    assert!(json.contains("\"wasm_safe\""));
    assert!(json.contains("\"requires_dom\""));
}

#[test]
fn json_field_names_equivalence_witness() {
    let w = EquivalenceWitness {
        reference_hash: make_hash(b"ref"),
        optimized_hash: make_hash(b"opt"),
        equivalence_kind: EquivalenceKind::Output,
        test_input_count: 1,
        all_outputs_matched: true,
        counterexample_hash: None,
        preserved_invariants: vec![],
        witness_hash: make_hash(b"eq"),
    };
    let json = serde_json::to_string(&w).unwrap();
    assert!(json.contains("\"reference_hash\""));
    assert!(json.contains("\"optimized_hash\""));
    assert!(json.contains("\"equivalence_kind\""));
    assert!(json.contains("\"test_input_count\""));
    assert!(json.contains("\"all_outputs_matched\""));
    assert!(json.contains("\"counterexample_hash\""));
    assert!(json.contains("\"preserved_invariants\""));
    assert!(json.contains("\"witness_hash\""));
}
