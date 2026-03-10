#![forbid(unsafe_code)]
//! Enrichment integration tests for `frir_schema`.
//!
//! Adds Display exactness, Debug distinctness, serde roundtrips,
//! JSON field-name stability, config defaults, factory functions,
//! and initial-state checks beyond the existing 48 integration tests.

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
    EffectAnnotation, EquivalenceKind, FRIR_SCHEMA_VERSION, FallbackReason, FrirLoweringPipeline,
    FrirPipelineError, FrirPipelineEventKind, FrirVersion, InvariantKind, LaneTarget, PassKind,
    PipelineConfig, WitnessVerdict,
};

// ===========================================================================
// 1) Constants — exact values
// ===========================================================================

#[test]
fn frir_schema_version_exact() {
    assert_eq!(FRIR_SCHEMA_VERSION, "franken-engine.frir-schema.v1");
}

#[test]
fn frir_version_current() {
    let v = FrirVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
    assert_eq!(v.patch, 0);
}

// ===========================================================================
// 2) FrirVersion — Display
// ===========================================================================

#[test]
fn frir_version_display() {
    assert_eq!(FrirVersion::CURRENT.to_string(), "0.1.0");
}

// ===========================================================================
// 3) LaneTarget — Display exact values
// ===========================================================================

#[test]
fn lane_target_display_js() {
    assert_eq!(LaneTarget::Js.to_string(), "js");
}

#[test]
fn lane_target_display_wasm() {
    assert_eq!(LaneTarget::Wasm.to_string(), "wasm");
}

#[test]
fn lane_target_display_baseline() {
    assert_eq!(LaneTarget::Baseline.to_string(), "baseline");
}

// ===========================================================================
// 4) LaneTarget — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_lane_target() {
    let variants = [
        format!("{:?}", LaneTarget::Js),
        format!("{:?}", LaneTarget::Wasm),
        format!("{:?}", LaneTarget::Baseline),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 5) PassKind — Display exact values (all 15)
// ===========================================================================

#[test]
fn pass_kind_display_parse() {
    assert_eq!(PassKind::Parse.to_string(), "parse");
}

#[test]
fn pass_kind_display_scope_resolve() {
    assert_eq!(PassKind::ScopeResolve.to_string(), "scope_resolve");
}

#[test]
fn pass_kind_display_capability_annotate() {
    assert_eq!(
        PassKind::CapabilityAnnotate.to_string(),
        "capability_annotate"
    );
}

#[test]
fn pass_kind_display_effect_analysis() {
    assert_eq!(PassKind::EffectAnalysis.to_string(), "effect_analysis");
}

#[test]
fn pass_kind_display_hook_slot_validation() {
    assert_eq!(
        PassKind::HookSlotValidation.to_string(),
        "hook_slot_validation"
    );
}

#[test]
fn pass_kind_display_dependency_graph() {
    assert_eq!(PassKind::DependencyGraph.to_string(), "dependency_graph");
}

#[test]
fn pass_kind_display_dead_code_elimination() {
    assert_eq!(
        PassKind::DeadCodeElimination.to_string(),
        "dead_code_elimination"
    );
}

#[test]
fn pass_kind_display_memoization_boundary() {
    assert_eq!(
        PassKind::MemoizationBoundary.to_string(),
        "memoization_boundary"
    );
}

#[test]
fn pass_kind_display_signal_graph_extraction() {
    assert_eq!(
        PassKind::SignalGraphExtraction.to_string(),
        "signal_graph_extraction"
    );
}

#[test]
fn pass_kind_display_dom_update_planning() {
    assert_eq!(
        PassKind::DomUpdatePlanning.to_string(),
        "dom_update_planning"
    );
}

#[test]
fn pass_kind_display_egraph_optimization() {
    assert_eq!(
        PassKind::EGraphOptimization.to_string(),
        "egraph_optimization"
    );
}

#[test]
fn pass_kind_display_partial_evaluation() {
    assert_eq!(
        PassKind::PartialEvaluation.to_string(),
        "partial_evaluation"
    );
}

#[test]
fn pass_kind_display_incrementalization() {
    assert_eq!(
        PassKind::Incrementalization.to_string(),
        "incrementalization"
    );
}

#[test]
fn pass_kind_display_code_generation() {
    assert_eq!(PassKind::CodeGeneration.to_string(), "code_generation");
}

#[test]
fn pass_kind_display_custom() {
    assert_eq!(PassKind::Custom.to_string(), "custom");
}

// ===========================================================================
// 6) PassKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_pass_kind() {
    let variants = [
        format!("{:?}", PassKind::Parse),
        format!("{:?}", PassKind::ScopeResolve),
        format!("{:?}", PassKind::CapabilityAnnotate),
        format!("{:?}", PassKind::EffectAnalysis),
        format!("{:?}", PassKind::HookSlotValidation),
        format!("{:?}", PassKind::DependencyGraph),
        format!("{:?}", PassKind::DeadCodeElimination),
        format!("{:?}", PassKind::MemoizationBoundary),
        format!("{:?}", PassKind::SignalGraphExtraction),
        format!("{:?}", PassKind::DomUpdatePlanning),
        format!("{:?}", PassKind::EGraphOptimization),
        format!("{:?}", PassKind::PartialEvaluation),
        format!("{:?}", PassKind::Incrementalization),
        format!("{:?}", PassKind::CodeGeneration),
        format!("{:?}", PassKind::Custom),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 15);
}

// ===========================================================================
// 7) WitnessVerdict — Display exact values
// ===========================================================================

#[test]
fn witness_verdict_display_valid() {
    assert_eq!(WitnessVerdict::Valid.to_string(), "valid");
}

#[test]
fn witness_verdict_display_invalid() {
    assert_eq!(WitnessVerdict::Invalid.to_string(), "invalid");
}

#[test]
fn witness_verdict_display_missing() {
    assert_eq!(WitnessVerdict::Missing.to_string(), "missing");
}

#[test]
fn witness_verdict_display_stale() {
    assert_eq!(WitnessVerdict::Stale.to_string(), "stale");
}

#[test]
fn witness_verdict_display_timed_out() {
    assert_eq!(WitnessVerdict::TimedOut.to_string(), "timed_out");
}

// ===========================================================================
// 8) WitnessVerdict — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_witness_verdict() {
    let variants = [
        format!("{:?}", WitnessVerdict::Valid),
        format!("{:?}", WitnessVerdict::Invalid),
        format!("{:?}", WitnessVerdict::Missing),
        format!("{:?}", WitnessVerdict::Stale),
        format!("{:?}", WitnessVerdict::TimedOut),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 9) InvariantKind — Display exact values
// ===========================================================================

#[test]
fn invariant_kind_display_semantic_equivalence() {
    assert_eq!(
        InvariantKind::SemanticEquivalence.to_string(),
        "semantic_equivalence"
    );
}

#[test]
fn invariant_kind_display_type_safety() {
    assert_eq!(InvariantKind::TypeSafety.to_string(), "type_safety");
}

#[test]
fn invariant_kind_display_effect_containment() {
    assert_eq!(
        InvariantKind::EffectContainment.to_string(),
        "effect_containment"
    );
}

#[test]
fn invariant_kind_display_hook_ordering() {
    assert_eq!(InvariantKind::HookOrdering.to_string(), "hook_ordering");
}

#[test]
fn invariant_kind_display_capability_monotonicity() {
    assert_eq!(
        InvariantKind::CapabilityMonotonicity.to_string(),
        "capability_monotonicity"
    );
}

#[test]
fn invariant_kind_display_determinism() {
    assert_eq!(InvariantKind::Determinism.to_string(), "determinism");
}

#[test]
fn invariant_kind_display_resource_bound() {
    assert_eq!(InvariantKind::ResourceBound.to_string(), "resource_bound");
}

#[test]
fn invariant_kind_display_custom() {
    assert_eq!(InvariantKind::Custom.to_string(), "custom");
}

// ===========================================================================
// 10) InvariantKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_invariant_kind() {
    let variants = [
        format!("{:?}", InvariantKind::SemanticEquivalence),
        format!("{:?}", InvariantKind::TypeSafety),
        format!("{:?}", InvariantKind::EffectContainment),
        format!("{:?}", InvariantKind::HookOrdering),
        format!("{:?}", InvariantKind::CapabilityMonotonicity),
        format!("{:?}", InvariantKind::Determinism),
        format!("{:?}", InvariantKind::ResourceBound),
        format!("{:?}", InvariantKind::Custom),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 8);
}

// ===========================================================================
// 11) EquivalenceKind — Display exact values
// ===========================================================================

#[test]
fn equivalence_kind_display_observational() {
    assert_eq!(EquivalenceKind::Observational.to_string(), "observational");
}

#[test]
fn equivalence_kind_display_trace() {
    assert_eq!(EquivalenceKind::Trace.to_string(), "trace");
}

#[test]
fn equivalence_kind_display_effect() {
    assert_eq!(EquivalenceKind::Effect.to_string(), "effect");
}

#[test]
fn equivalence_kind_display_output() {
    assert_eq!(EquivalenceKind::Output.to_string(), "output");
}

#[test]
fn equivalence_kind_display_approximate() {
    assert_eq!(EquivalenceKind::Approximate.to_string(), "approximate");
}

// ===========================================================================
// 12) EquivalenceKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_equivalence_kind() {
    let variants = [
        format!("{:?}", EquivalenceKind::Observational),
        format!("{:?}", EquivalenceKind::Trace),
        format!("{:?}", EquivalenceKind::Effect),
        format!("{:?}", EquivalenceKind::Output),
        format!("{:?}", EquivalenceKind::Approximate),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 13) FallbackReason — Display exact values
// ===========================================================================

#[test]
fn fallback_reason_display_missing_witness() {
    let r = FallbackReason::MissingWitness {
        pass_index: 3,
        pass_kind: PassKind::Parse,
    };
    let s = r.to_string();
    assert!(s.contains("missing witness"), "{s}");
    assert!(s.contains("3"), "{s}");
    assert!(s.contains("parse"), "{s}");
}

#[test]
fn fallback_reason_display_invalid_witness() {
    let r = FallbackReason::InvalidWitness {
        pass_index: 2,
        pass_kind: PassKind::CodeGeneration,
        detail: "bad".into(),
    };
    let s = r.to_string();
    assert!(s.contains("invalid witness"), "{s}");
    assert!(s.contains("bad"), "{s}");
}

#[test]
fn fallback_reason_display_stale_witness() {
    let r = FallbackReason::StaleWitness {
        pass_index: 1,
        pass_kind: PassKind::ScopeResolve,
    };
    let s = r.to_string();
    assert!(s.contains("stale witness"), "{s}");
}

#[test]
fn fallback_reason_display_budget_exceeded() {
    let r = FallbackReason::VerificationBudgetExceeded {
        elapsed_ms: 6000,
        budget_ms: 5000,
    };
    let s = r.to_string();
    assert!(s.contains("6000"), "{s}");
    assert!(s.contains("5000"), "{s}");
}

#[test]
fn fallback_reason_display_unfulfilled_obligation() {
    let r = FallbackReason::UnfulfilledObligation {
        obligation_id: "ob-1".into(),
        pass_index: 0,
    };
    let s = r.to_string();
    assert!(s.contains("ob-1"), "{s}");
}

#[test]
fn fallback_reason_display_explicit_opt_out() {
    let r = FallbackReason::ExplicitOptOut {
        reason: "testing".into(),
    };
    let s = r.to_string();
    assert!(s.contains("testing"), "{s}");
}

// ===========================================================================
// 14) FrirPipelineError — Display exact values
// ===========================================================================

#[test]
fn pipeline_error_display_pass_limit() {
    let e = FrirPipelineError::PassLimitExceeded { count: 65, max: 64 };
    let s = e.to_string();
    assert!(s.contains("65"), "{s}");
    assert!(s.contains("64"), "{s}");
}

#[test]
fn pipeline_error_display_broken_chain() {
    let e = FrirPipelineError::BrokenChain {
        pass_index: 2,
        detail: "hash mismatch".into(),
    };
    let s = e.to_string();
    assert!(s.contains("2"), "{s}");
    assert!(s.contains("hash mismatch"), "{s}");
}

#[test]
fn pipeline_error_display_invariant_failed() {
    let e = FrirPipelineError::InvariantFailed {
        kind: InvariantKind::Determinism,
        pass_index: 1,
        detail: "non-det".into(),
    };
    let s = e.to_string();
    assert!(s.contains("determinism"), "{s}");
    assert!(s.contains("non-det"), "{s}");
}

#[test]
fn pipeline_error_display_budget_exceeded() {
    let e = FrirPipelineError::BudgetExceeded {
        elapsed_ms: 10000,
        budget_ms: 5000,
    };
    let s = e.to_string();
    assert!(s.contains("10000"), "{s}");
    assert!(s.contains("5000"), "{s}");
}

#[test]
fn pipeline_error_display_duplicate_pass_index() {
    let e = FrirPipelineError::DuplicatePassIndex(3);
    let s = e.to_string();
    assert!(s.contains("3"), "{s}");
}

// ===========================================================================
// 15) FrirPipelineEventKind — Display exact values
// ===========================================================================

#[test]
fn event_kind_display_pipeline_started() {
    assert_eq!(
        FrirPipelineEventKind::PipelineStarted.to_string(),
        "pipeline_started"
    );
}

#[test]
fn event_kind_display_pass_executed() {
    assert_eq!(
        FrirPipelineEventKind::PassExecuted.to_string(),
        "pass_executed"
    );
}

#[test]
fn event_kind_display_witness_produced() {
    assert_eq!(
        FrirPipelineEventKind::WitnessProduced.to_string(),
        "witness_produced"
    );
}

#[test]
fn event_kind_display_witness_verified() {
    assert_eq!(
        FrirPipelineEventKind::WitnessVerified.to_string(),
        "witness_verified"
    );
}

#[test]
fn event_kind_display_fallback_triggered() {
    assert_eq!(
        FrirPipelineEventKind::FallbackTriggered.to_string(),
        "fallback_triggered"
    );
}

#[test]
fn event_kind_display_equivalence_witness_produced() {
    assert_eq!(
        FrirPipelineEventKind::EquivalenceWitnessProduced.to_string(),
        "equivalence_witness_produced"
    );
}

#[test]
fn event_kind_display_pipeline_completed() {
    assert_eq!(
        FrirPipelineEventKind::PipelineCompleted.to_string(),
        "pipeline_completed"
    );
}

// ===========================================================================
// 16) FrirPipelineEventKind — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_pipeline_event_kind() {
    let variants = [
        format!("{:?}", FrirPipelineEventKind::PipelineStarted),
        format!("{:?}", FrirPipelineEventKind::PassExecuted),
        format!("{:?}", FrirPipelineEventKind::WitnessProduced),
        format!("{:?}", FrirPipelineEventKind::WitnessVerified),
        format!("{:?}", FrirPipelineEventKind::FallbackTriggered),
        format!("{:?}", FrirPipelineEventKind::EquivalenceWitnessProduced),
        format!("{:?}", FrirPipelineEventKind::PipelineCompleted),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

// ===========================================================================
// 17) PipelineConfig::production — default exact values
// ===========================================================================

#[test]
fn pipeline_config_production_target_lane() {
    let c = PipelineConfig::production();
    assert_eq!(c.target_lane, LaneTarget::Js);
}

#[test]
fn pipeline_config_production_budget_ms() {
    let c = PipelineConfig::production();
    assert_eq!(c.budget_ms, 5_000);
}

#[test]
fn pipeline_config_production_no_offline_witnesses() {
    let c = PipelineConfig::production();
    assert!(!c.enable_offline_witnesses);
}

#[test]
fn pipeline_config_production_no_equivalence_witnesses() {
    let c = PipelineConfig::production();
    assert!(!c.enable_equivalence_witnesses);
}

#[test]
fn pipeline_config_production_three_required_invariants() {
    let c = PipelineConfig::production();
    assert_eq!(c.required_invariants.len(), 3);
    assert!(
        c.required_invariants
            .contains(&InvariantKind::SemanticEquivalence)
    );
    assert!(c.required_invariants.contains(&InvariantKind::HookOrdering));
    assert!(c.required_invariants.contains(&InvariantKind::Determinism));
}

#[test]
fn pipeline_config_production_max_passes_64() {
    let c = PipelineConfig::production();
    assert_eq!(c.max_passes, 64);
}

// ===========================================================================
// 18) PipelineConfig::offline_analysis
// ===========================================================================

#[test]
fn pipeline_config_offline_seven_invariants() {
    let c = PipelineConfig::offline_analysis();
    assert_eq!(c.required_invariants.len(), 7);
}

#[test]
fn pipeline_config_offline_budget_300s() {
    let c = PipelineConfig::offline_analysis();
    assert_eq!(c.budget_ms, 300_000);
}

#[test]
fn pipeline_config_offline_both_witness_types_enabled() {
    let c = PipelineConfig::offline_analysis();
    assert!(c.enable_offline_witnesses);
    assert!(c.enable_equivalence_witnesses);
}

// ===========================================================================
// 19) PipelineConfig::default is production
// ===========================================================================

#[test]
fn pipeline_config_default_equals_production() {
    let default = PipelineConfig::default();
    let production = PipelineConfig::production();
    assert_eq!(default, production);
}

// ===========================================================================
// 20) EffectAnnotation::pure_annotation
// ===========================================================================

#[test]
fn pure_annotation_all_lanes_compatible() {
    let a = EffectAnnotation::pure_annotation();
    assert!(a.is_compatible(LaneTarget::Js));
    assert!(a.is_compatible(LaneTarget::Wasm));
    assert!(a.is_compatible(LaneTarget::Baseline));
}

#[test]
fn pure_annotation_wasm_safe() {
    let a = EffectAnnotation::pure_annotation();
    assert!(a.wasm_safe);
}

#[test]
fn pure_annotation_no_dom() {
    let a = EffectAnnotation::pure_annotation();
    assert!(!a.requires_dom);
}

// ===========================================================================
// 21) FrirLoweringPipeline — initial state
// ===========================================================================

#[test]
fn pipeline_initial_no_passes() {
    let p = FrirLoweringPipeline::new(PipelineConfig::default());
    assert_eq!(p.pass_count(), 0);
}

#[test]
fn pipeline_initial_not_fallen_back() {
    let p = FrirLoweringPipeline::new(PipelineConfig::default());
    assert!(!p.has_fallen_back());
}

#[test]
fn pipeline_initial_no_fallback_reasons() {
    let p = FrirLoweringPipeline::new(PipelineConfig::default());
    assert!(p.fallback_reasons().is_empty());
}

#[test]
fn pipeline_initial_has_pipeline_started_event() {
    let p = FrirLoweringPipeline::new(PipelineConfig::default());
    assert_eq!(p.events().len(), 1);
    assert_eq!(p.events()[0].kind, FrirPipelineEventKind::PipelineStarted);
}

#[test]
fn pipeline_initial_all_obligations_discharged() {
    let p = FrirLoweringPipeline::new(PipelineConfig::default());
    assert!(p.all_obligations_discharged());
}

// ===========================================================================
// 22) Serde roundtrips — enums
// ===========================================================================

#[test]
fn serde_roundtrip_lane_target_all() {
    for t in [LaneTarget::Js, LaneTarget::Wasm, LaneTarget::Baseline] {
        let json = serde_json::to_string(&t).unwrap();
        let rt: LaneTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(t, rt);
    }
}

#[test]
fn serde_roundtrip_witness_verdict_all() {
    for v in [
        WitnessVerdict::Valid,
        WitnessVerdict::Invalid,
        WitnessVerdict::Missing,
        WitnessVerdict::Stale,
        WitnessVerdict::TimedOut,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let rt: WitnessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, rt);
    }
}

#[test]
fn serde_roundtrip_invariant_kind_all() {
    for k in [
        InvariantKind::SemanticEquivalence,
        InvariantKind::TypeSafety,
        InvariantKind::EffectContainment,
        InvariantKind::HookOrdering,
        InvariantKind::CapabilityMonotonicity,
        InvariantKind::Determinism,
        InvariantKind::ResourceBound,
        InvariantKind::Custom,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: InvariantKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_equivalence_kind_all() {
    for k in [
        EquivalenceKind::Observational,
        EquivalenceKind::Trace,
        EquivalenceKind::Effect,
        EquivalenceKind::Output,
        EquivalenceKind::Approximate,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: EquivalenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

// ===========================================================================
// 23) Serde roundtrips — structs
// ===========================================================================

#[test]
fn serde_roundtrip_pipeline_config() {
    let c = PipelineConfig::production();
    let json = serde_json::to_string(&c).unwrap();
    let rt: PipelineConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

#[test]
fn serde_roundtrip_frir_version() {
    let v = FrirVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let rt: FrirVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

#[test]
fn serde_roundtrip_fallback_reason() {
    let r = FallbackReason::MissingWitness {
        pass_index: 1,
        pass_kind: PassKind::Parse,
    };
    let json = serde_json::to_string(&r).unwrap();
    let rt: FallbackReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, rt);
}

#[test]
fn serde_roundtrip_pipeline_error() {
    let e = FrirPipelineError::BrokenChain {
        pass_index: 2,
        detail: "hash".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: FrirPipelineError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 24) FrirVersion::can_read
// ===========================================================================

#[test]
fn frir_version_can_read_same() {
    let v = FrirVersion::CURRENT;
    assert!(v.can_read(&v));
}
