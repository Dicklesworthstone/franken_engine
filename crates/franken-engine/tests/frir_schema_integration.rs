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

use frankenengine_engine::frir_schema::{
    AssumptionRef, EffectAnnotation, EquivalenceKind, EquivalenceWitness, FRIR_SCHEMA_VERSION,
    FallbackReason, FrirArtifact, FrirLoweringPipeline, FrirPipelineError, FrirVersion,
    InvariantCheck, InvariantKind, LaneTarget, ObligationRef, PassKind, PassWitness,
    PipelineConfig, WitnessVerdict,
};
use frankenengine_engine::hash_tiers::ContentHash;

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
