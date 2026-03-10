//! Integration tests for the `cut_line_automation` module.
//!
//! Exercises the public API from outside the crate boundary:
//! CutLine, InputValidity, GateCategory, GateRequirement, CutLineSpec,
//! GateInput, GateEvaluationInput, GateEvaluation, PromotionRecord,
//! CutLineEvaluator, PromotionSummary, GateHistory.

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

use frankenengine_engine::cut_line_automation::{
    CutLine, CutLineEvaluator, CutLineSpec, GateCategory, GateEvaluation, GateEvaluationInput,
    GateHistory, GateInput, GateRequirement, InputValidity, PromotionRecord, PromotionSummary,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{GateVerdict, RiskLevel};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn now_ns() -> u64 {
    1_000_000_000 // 1 second
}

fn make_passing_input(category: GateCategory, ts: u64) -> GateInput {
    GateInput {
        category,
        score_millionths: Some(1_000_000),
        passed: true,
        evidence_hash: ContentHash::compute(category.as_str().as_bytes()),
        evidence_refs: vec![format!("{}_evidence", category)],
        collected_at_ns: ts,
        schema_major: 1,
        metadata: BTreeMap::new(),
    }
}

fn make_failing_input(category: GateCategory, ts: u64) -> GateInput {
    GateInput {
        category,
        score_millionths: Some(500_000),
        passed: false,
        evidence_hash: ContentHash::compute(b"fail"),
        evidence_refs: vec![format!("{}_fail", category)],
        collected_at_ns: ts,
        schema_major: 1,
        metadata: BTreeMap::new(),
    }
}

fn make_c0_inputs(ts: u64) -> Vec<GateInput> {
    vec![
        make_passing_input(GateCategory::SemanticContract, ts),
        make_passing_input(GateCategory::GovernanceCompliance, ts),
    ]
}

fn make_c1_inputs(ts: u64) -> Vec<GateInput> {
    fn with_c1_metadata(mut input: GateInput) -> GateInput {
        match input.category {
            GateCategory::CompilerCorrectness => {
                input.metadata.insert(
                    "frx20_1_unit_taxonomy_ref".to_string(),
                    "docs/FRX_UNIT_TEST_TAXONOMY_V1.md".to_string(),
                );
            }
            GateCategory::RuntimeParity => {
                input.metadata.insert(
                    "frx20_3_e2e_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "known_gap_ledger_ref".to_string(),
                    "artifacts/frx_known_gap_ledger/latest/known_gaps.jsonl".to_string(),
                );
                if !input.passed {
                    input.metadata.insert(
                        "divergence_replay_manifest_ref".to_string(),
                        "artifacts/frx_divergence_replay/latest/run_manifest.json".to_string(),
                    );
                }
            }
            GateCategory::DeterministicReplay => {
                input.metadata.insert(
                    "replay_manifest_ref".to_string(),
                    "artifacts/frx_replay/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::ObservabilityIntegrity => {
                input.metadata.insert(
                    "log_schema_ref".to_string(),
                    "docs/frx_test_logging_schema_v1.json".to_string(),
                );
                input.metadata.insert(
                    "frx20_4_logging_schema_ref".to_string(),
                    "docs/FRX_TEST_LOGGING_SCHEMA_V1.md".to_string(),
                );
            }
            _ => {}
        }
        input
    }

    vec![
        with_c1_metadata(make_passing_input(GateCategory::CompilerCorrectness, ts)),
        with_c1_metadata(make_passing_input(GateCategory::RuntimeParity, ts)),
        with_c1_metadata(make_passing_input(GateCategory::DeterministicReplay, ts)),
        with_c1_metadata(make_passing_input(GateCategory::ObservabilityIntegrity, ts)),
        with_c1_metadata(make_passing_input(GateCategory::FlakeBurden, ts)),
    ]
}

fn make_c2_inputs(ts: u64) -> Vec<GateInput> {
    fn with_c2_metadata(mut input: GateInput) -> GateInput {
        match input.category {
            GateCategory::HandoffReadiness => {
                input.metadata.insert(
                    "route_adoption_control_ref".to_string(),
                    "docs/FRX_ROUTE_ADOPTION_CONTROL_V1.md".to_string(),
                );
            }
            GateCategory::RuntimeParity => {
                input.metadata.insert(
                    "frx20_3_e2e_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "frx20_3_chaos_matrix_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/chaos_manifest.json"
                        .to_string(),
                );
            }
            GateCategory::DeterministicReplay => {
                input.metadata.insert(
                    "incident_replay_manifest_ref".to_string(),
                    "artifacts/frx_route_scale_incident_replay/latest/run_manifest.json"
                        .to_string(),
                );
                input.metadata.insert(
                    "divergence_replay_manifest_ref".to_string(),
                    "artifacts/frx_divergence_replay/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::SecuritySurvival => {
                input.metadata.insert(
                    "rollback_drill_report_ref".to_string(),
                    "artifacts/frx_route_scale_rollback_drills/latest/report.json".to_string(),
                );
                input.metadata.insert(
                    "safe_fallback_policy_ref".to_string(),
                    "docs/FRX_SAFE_FALLBACK_POLICY_V1.md".to_string(),
                );
            }
            GateCategory::FlakeBurden => {
                input.metadata.insert(
                    "frx20_5_flake_report_ref".to_string(),
                    "artifacts/frx_flake_detection/latest/flake_report.json".to_string(),
                );
            }
            _ => {}
        }
        input
    }

    vec![
        with_c2_metadata(make_passing_input(GateCategory::HandoffReadiness, ts)),
        with_c2_metadata(make_passing_input(GateCategory::RuntimeParity, ts)),
        with_c2_metadata(make_passing_input(GateCategory::DeterministicReplay, ts)),
        with_c2_metadata(make_passing_input(GateCategory::SecuritySurvival, ts)),
        with_c2_metadata(make_passing_input(GateCategory::FlakeBurden, ts)),
    ]
}

fn make_c3_inputs(ts: u64) -> Vec<GateInput> {
    fn with_c3_metadata(mut input: GateInput) -> GateInput {
        match input.category {
            GateCategory::RuntimeParity => {
                input.metadata.insert(
                    "wasm_parity_manifest_ref".to_string(),
                    "artifacts/frx_hybrid_router_wasm_parity/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "frx20_3_e2e_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::SecuritySurvival => {
                input.metadata.insert(
                    "hybrid_router_calibration_report_ref".to_string(),
                    "artifacts/frx_hybrid_router_calibration/latest/calibration_report.json"
                        .to_string(),
                );
                input.metadata.insert(
                    "router_regime_shift_manifest_ref".to_string(),
                    "artifacts/frx_hybrid_router_regime_shift/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "safe_fallback_policy_ref".to_string(),
                    "docs/FRX_SAFE_FALLBACK_POLICY_V1.md".to_string(),
                );
            }
            GateCategory::ObservabilityIntegrity => {
                input.metadata.insert(
                    "evidence_ledger_manifest_ref".to_string(),
                    "artifacts/frx_evidence_ledger/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "lane_explainability_report_ref".to_string(),
                    "artifacts/frx_hybrid_lane_explainability/latest/explainability_report.json"
                        .to_string(),
                );
                input.metadata.insert(
                    "frx20_4_logging_correlation_ref".to_string(),
                    "artifacts/frx_logging_correlation/latest/correlation_manifest.json"
                        .to_string(),
                );
            }
            GateCategory::FlakeBurden => {
                input.metadata.insert(
                    "frx20_5_flake_report_ref".to_string(),
                    "artifacts/frx_flake_detection/latest/flake_report.json".to_string(),
                );
            }
            GateCategory::GovernanceCompliance => {
                input.metadata.insert(
                    "frx20_6_test_evidence_integrator_manifest_ref".to_string(),
                    "artifacts/frx_milestone_release_test_evidence_integrator/latest/run_manifest.json".to_string(),
                );
            }
            _ => {}
        }
        input
    }

    vec![
        with_c3_metadata(make_passing_input(GateCategory::RuntimeParity, ts)),
        with_c3_metadata(make_passing_input(GateCategory::SecuritySurvival, ts)),
        with_c3_metadata(make_passing_input(GateCategory::ObservabilityIntegrity, ts)),
        with_c3_metadata(make_passing_input(GateCategory::FlakeBurden, ts)),
        with_c3_metadata(make_passing_input(GateCategory::GovernanceCompliance, ts)),
    ]
}

fn make_c4_inputs(ts: u64) -> Vec<GateInput> {
    fn with_c4_metadata(mut input: GateInput) -> GateInput {
        match input.category {
            GateCategory::RuntimeParity => {
                input.metadata.insert(
                    "claim_repro_bundle_manifest_ref".to_string(),
                    "artifacts/frx_claim_repro_bundle/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "frx20_3_e2e_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::PerformanceBenchmark => {
                input.metadata.insert(
                    "latency_memory_budget_report_ref".to_string(),
                    "artifacts/frx_ga_latency_memory_budget/latest/budget_report.json".to_string(),
                );
            }
            GateCategory::SecuritySurvival => {
                input.metadata.insert(
                    "incident_rollback_drill_report_ref".to_string(),
                    "artifacts/frx_ga_incident_rollback_drills/latest/report.json".to_string(),
                );
                input.metadata.insert(
                    "catastrophic_tail_tournament_manifest_ref".to_string(),
                    "artifacts/frx_catastrophic_tail_tournament/latest/run_manifest.json"
                        .to_string(),
                );
            }
            GateCategory::DeterministicReplay => {
                input.metadata.insert(
                    "semantic_twin_rollback_synthesis_manifest_ref".to_string(),
                    "artifacts/frx_semantic_twin_rollback_synthesis/latest/run_manifest.json"
                        .to_string(),
                );
            }
            GateCategory::ObservabilityIntegrity => {
                input.metadata.insert(
                    "observability_quality_sentinel_report_ref".to_string(),
                    "artifacts/frx_observability_quality_sentinel/latest/report.json".to_string(),
                );
            }
            GateCategory::GovernanceCompliance => {
                input.metadata.insert(
                    "proof_carrying_ci_gate_manifest_ref".to_string(),
                    "artifacts/frx_ci_proof_gate/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "frx20_6_test_evidence_integrator_manifest_ref".to_string(),
                    "artifacts/frx_milestone_release_test_evidence_integrator/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "public_claim_registry_ref".to_string(),
                    "artifacts/frx_public_claim_registry/latest/claims.json".to_string(),
                );
            }
            _ => {}
        }
        input
    }

    vec![
        with_c4_metadata(make_passing_input(GateCategory::RuntimeParity, ts)),
        with_c4_metadata(make_passing_input(GateCategory::PerformanceBenchmark, ts)),
        with_c4_metadata(make_passing_input(GateCategory::SecuritySurvival, ts)),
        with_c4_metadata(make_passing_input(GateCategory::DeterministicReplay, ts)),
        with_c4_metadata(make_passing_input(GateCategory::ObservabilityIntegrity, ts)),
        with_c4_metadata(make_passing_input(GateCategory::GovernanceCompliance, ts)),
    ]
}

fn make_c5_inputs(ts: u64) -> Vec<GateInput> {
    fn with_c5_metadata(mut input: GateInput) -> GateInput {
        match input.category {
            GateCategory::HandoffReadiness => {
                input.metadata.insert(
                    "browser_embedding_boundary_manifest_ref".to_string(),
                    "artifacts/frx_browser_embedding_boundaries/latest/run_manifest.json"
                        .to_string(),
                );
                input.metadata.insert(
                    "sidecar_to_subsystem_migration_plan_ref".to_string(),
                    "docs/FRX_BROWSER_SIDECAR_TO_SUBSYSTEM_MIGRATION_PLAN_V1.md".to_string(),
                );
            }
            GateCategory::RuntimeParity => {
                input.metadata.insert(
                    "scheduler_embedding_compatibility_manifest_ref".to_string(),
                    "artifacts/frx_browser_scheduler_embedding_compat/latest/run_manifest.json"
                        .to_string(),
                );
                input.metadata.insert(
                    "frx20_3_e2e_manifest_ref".to_string(),
                    "artifacts/frx_end_to_end_scenario_matrix/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::SecuritySurvival => {
                input.metadata.insert(
                    "browser_security_boundary_report_ref".to_string(),
                    "artifacts/frx_browser_security_boundaries/latest/report.json".to_string(),
                );
                input.metadata.insert(
                    "browser_rollback_drill_report_ref".to_string(),
                    "artifacts/frx_browser_integration_rollback_drills/latest/report.json"
                        .to_string(),
                );
            }
            GateCategory::DeterministicReplay => {
                input.metadata.insert(
                    "browser_runtime_replay_manifest_ref".to_string(),
                    "artifacts/frx_browser_runtime_replay/latest/run_manifest.json".to_string(),
                );
            }
            GateCategory::ObservabilityIntegrity => {
                input.metadata.insert(
                    "browser_embedded_logging_correlation_ref".to_string(),
                    "artifacts/frx_browser_embedded_logging_correlation/latest/correlation_manifest.json".to_string(),
                );
            }
            GateCategory::GovernanceCompliance => {
                input.metadata.insert(
                    "frx20_6_test_evidence_integrator_manifest_ref".to_string(),
                    "artifacts/frx_milestone_release_test_evidence_integrator/latest/run_manifest.json".to_string(),
                );
                input.metadata.insert(
                    "proof_carrying_ci_gate_manifest_ref".to_string(),
                    "artifacts/frx_ci_proof_gate/latest/run_manifest.json".to_string(),
                );
            }
            _ => {}
        }
        input
    }

    vec![
        with_c5_metadata(make_passing_input(GateCategory::HandoffReadiness, ts)),
        with_c5_metadata(make_passing_input(GateCategory::RuntimeParity, ts)),
        with_c5_metadata(make_passing_input(GateCategory::SecuritySurvival, ts)),
        with_c5_metadata(make_passing_input(GateCategory::DeterministicReplay, ts)),
        with_c5_metadata(make_passing_input(GateCategory::ObservabilityIntegrity, ts)),
        with_c5_metadata(make_passing_input(GateCategory::GovernanceCompliance, ts)),
    ]
}

// =========================================================================
// CutLine enum
// =========================================================================

#[test]
fn cut_line_as_str_all() {
    assert_eq!(CutLine::C0.as_str(), "C0");
    assert_eq!(CutLine::C1.as_str(), "C1");
    assert_eq!(CutLine::C2.as_str(), "C2");
    assert_eq!(CutLine::C3.as_str(), "C3");
    assert_eq!(CutLine::C4.as_str(), "C4");
    assert_eq!(CutLine::C5.as_str(), "C5");
}

#[test]
fn cut_line_display_matches_as_str() {
    for cl in CutLine::all() {
        assert_eq!(cl.to_string(), cl.as_str());
    }
}

#[test]
fn cut_line_all_returns_six() {
    assert_eq!(CutLine::all().len(), 6);
}

#[test]
fn cut_line_predecessor_chain() {
    assert_eq!(CutLine::C0.predecessor(), None);
    assert_eq!(CutLine::C1.predecessor(), Some(CutLine::C0));
    assert_eq!(CutLine::C2.predecessor(), Some(CutLine::C1));
    assert_eq!(CutLine::C3.predecessor(), Some(CutLine::C2));
    assert_eq!(CutLine::C4.predecessor(), Some(CutLine::C3));
    assert_eq!(CutLine::C5.predecessor(), Some(CutLine::C4));
}

#[test]
fn cut_line_ordering() {
    assert!(CutLine::C0 < CutLine::C1);
    assert!(CutLine::C1 < CutLine::C2);
    assert!(CutLine::C4 < CutLine::C5);
}

#[test]
fn cut_line_serde_roundtrip() {
    for cl in CutLine::all() {
        let json = serde_json::to_string(cl).unwrap();
        let restored: CutLine = serde_json::from_str(&json).unwrap();
        assert_eq!(*cl, restored);
    }
}

// =========================================================================
// InputValidity
// =========================================================================

#[test]
fn input_validity_valid() {
    let v = InputValidity::Valid;
    assert!(v.is_valid());
    assert_eq!(v.to_string(), "valid");
}

#[test]
fn input_validity_stale() {
    let v = InputValidity::Stale {
        age_ns: 100,
        max_age_ns: 50,
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("stale"));
    assert!(v.to_string().contains("100"));
}

#[test]
fn input_validity_missing() {
    let v = InputValidity::Missing {
        field: "test_field".into(),
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("test_field"));
}

#[test]
fn input_validity_incompatible() {
    let v = InputValidity::Incompatible {
        reason: "bad schema".into(),
    };
    assert!(!v.is_valid());
    assert!(v.to_string().contains("bad schema"));
}

#[test]
fn input_validity_serde_roundtrip() {
    let variants = vec![
        InputValidity::Valid,
        InputValidity::Stale {
            age_ns: 10,
            max_age_ns: 5,
        },
        InputValidity::Missing { field: "x".into() },
        InputValidity::Incompatible { reason: "y".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: InputValidity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

// =========================================================================
// GateCategory
// =========================================================================

#[test]
fn gate_category_as_str() {
    assert_eq!(GateCategory::SemanticContract.as_str(), "semantic_contract");
    assert_eq!(
        GateCategory::CompilerCorrectness.as_str(),
        "compiler_correctness"
    );
    assert_eq!(GateCategory::HandoffReadiness.as_str(), "handoff_readiness");
}

#[test]
fn gate_category_display_matches_as_str() {
    let cats = [
        GateCategory::SemanticContract,
        GateCategory::CompilerCorrectness,
        GateCategory::RuntimeParity,
        GateCategory::PerformanceBenchmark,
        GateCategory::SecuritySurvival,
        GateCategory::DeterministicReplay,
        GateCategory::ObservabilityIntegrity,
        GateCategory::FlakeBurden,
        GateCategory::GovernanceCompliance,
        GateCategory::HandoffReadiness,
    ];
    for c in &cats {
        assert_eq!(c.to_string(), c.as_str());
    }
}

#[test]
fn gate_category_serde_roundtrip() {
    let cat = GateCategory::SecuritySurvival;
    let json = serde_json::to_string(&cat).unwrap();
    let restored: GateCategory = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, restored);
}

// =========================================================================
// GateRequirement
// =========================================================================

#[test]
fn gate_requirement_serde_roundtrip() {
    let req = GateRequirement {
        category: GateCategory::PerformanceBenchmark,
        mandatory: true,
        description: "P99 latency below 10ms".into(),
        min_score_millionths: Some(900_000),
    };
    let json = serde_json::to_string(&req).unwrap();
    let restored: GateRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, restored);
}

// =========================================================================
// CutLineSpec
// =========================================================================

#[test]
fn default_c0_spec_properties() {
    let spec = CutLineSpec::default_c0();
    assert_eq!(spec.cut_line, CutLine::C0);
    assert!(!spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 2);
    assert_eq!(spec.mandatory_count(), 2);
    assert_eq!(spec.min_schema_major, 1);
}

#[test]
fn default_c1_spec_properties() {
    let spec = CutLineSpec::default_c1();
    assert_eq!(spec.cut_line, CutLine::C1);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 5);
    assert_eq!(spec.mandatory_count(), 5);
}

#[test]
fn default_c2_spec_properties() {
    let spec = CutLineSpec::default_c2();
    assert_eq!(spec.cut_line, CutLine::C2);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 5);
    assert_eq!(spec.mandatory_count(), 5);
}

#[test]
fn default_c3_spec_properties() {
    let spec = CutLineSpec::default_c3();
    assert_eq!(spec.cut_line, CutLine::C3);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 5);
    assert_eq!(spec.mandatory_count(), 5);
}

#[test]
fn default_c4_spec_properties() {
    let spec = CutLineSpec::default_c4();
    assert_eq!(spec.cut_line, CutLine::C4);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 6);
    assert_eq!(spec.mandatory_count(), 6);
}

#[test]
fn default_c5_spec_properties() {
    let spec = CutLineSpec::default_c5();
    assert_eq!(spec.cut_line, CutLine::C5);
    assert!(spec.requires_predecessor);
    assert_eq!(spec.requirements.len(), 6);
    assert_eq!(spec.mandatory_count(), 6);
}

#[test]
fn cut_line_spec_serde_roundtrip() {
    let spec = CutLineSpec::default_c0();
    let json = serde_json::to_string(&spec).unwrap();
    let restored: CutLineSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, restored);
}

// =========================================================================
// GateInput
// =========================================================================

#[test]
fn gate_input_serde_roundtrip() {
    let input = make_passing_input(GateCategory::SemanticContract, now_ns());
    let json = serde_json::to_string(&input).unwrap();
    let restored: GateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, restored);
}

// =========================================================================
// GateEvaluationInput
// =========================================================================

#[test]
fn gate_evaluation_input_serde_roundtrip() {
    let gei = GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "test-zone".into(),
    };
    let json = serde_json::to_string(&gei).unwrap();
    let restored: GateEvaluationInput = serde_json::from_str(&json).unwrap();
    assert_eq!(gei, restored);
}

// =========================================================================
// GateEvaluation
// =========================================================================

#[test]
fn gate_evaluation_to_gate_result() {
    let eval = GateEvaluation {
        category: GateCategory::SemanticContract,
        mandatory: true,
        passed: true,
        score_millionths: Some(1_000_000),
        evidence_refs: vec!["ref-1".into()],
        summary: "passed".into(),
        input_validity: InputValidity::Valid,
    };
    let result = eval.to_gate_result();
    assert!(result.passed);
    assert_eq!(result.gate_name, "semantic_contract");
    assert_eq!(result.evidence_refs, vec!["ref-1".to_string()]);
}

#[test]
fn gate_evaluation_serde_roundtrip() {
    let eval = GateEvaluation {
        category: GateCategory::FlakeBurden,
        mandatory: false,
        passed: false,
        score_millionths: Some(500_000),
        evidence_refs: vec!["flake-evidence".into()],
        summary: "flake rate too high".into(),
        input_validity: InputValidity::Valid,
    };
    let json = serde_json::to_string(&eval).unwrap();
    let restored: GateEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
}

// =========================================================================
// CutLineEvaluator — basic construction
// =========================================================================

#[test]
fn evaluator_new_empty() {
    let eval = CutLineEvaluator::new(vec![]);
    assert!(!eval.is_promoted(CutLine::C0));
    assert_eq!(eval.history_len(), 0);
}

#[test]
fn evaluator_with_defaults() {
    let eval = CutLineEvaluator::with_defaults();
    assert!(!eval.is_promoted(CutLine::C0));
    assert!(!eval.is_promoted(CutLine::C1));
    assert!(!eval.is_promoted(CutLine::C2));
    assert!(!eval.is_promoted(CutLine::C3));
    assert!(!eval.is_promoted(CutLine::C4));
    assert!(!eval.is_promoted(CutLine::C5));
    assert_eq!(eval.history_len(), 0);
}

#[test]
fn evaluator_register_spec() {
    let mut eval = CutLineEvaluator::new(vec![]);
    eval.register_spec(CutLineSpec::default_c0());
    // Verify by evaluating C0
    let result = eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "z".into(),
    });
    assert!(result.is_some());
}

// =========================================================================
// CutLineEvaluator — evaluate C0
// =========================================================================

#[test]
fn evaluate_c0_all_pass() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.cut_line, CutLine::C0);
    assert_eq!(record.verdict, GateVerdict::Approved);
    assert_eq!(record.risk_level, RiskLevel::Low);
    assert!(eval.is_promoted(CutLine::C0));
    assert!(eval.promotion_hash(CutLine::C0).is_some());
    assert_eq!(eval.history_len(), 1);
}

#[test]
fn evaluate_c0_missing_evidence_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Submit only SemanticContract, missing GovernanceCompliance
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![make_passing_input(GateCategory::SemanticContract, now_ns())],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert!(!eval.is_promoted(CutLine::C0));
}

#[test]
fn evaluate_c0_failing_evidence_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![
                make_failing_input(GateCategory::SemanticContract, now_ns()),
                make_passing_input(GateCategory::GovernanceCompliance, now_ns()),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert!(!eval.is_promoted(CutLine::C0));
}

#[test]
fn evaluate_c0_stale_input_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // C0 max staleness is 86_400_000_000_000 (24h).
    // Set collected_at_ns to 0, now_ns to 100_000_000_000_000 (way past 24h).
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: 100_000_000_000_000,
            epoch: epoch(),
            inputs: vec![
                make_passing_input(GateCategory::SemanticContract, 0),
                make_passing_input(GateCategory::GovernanceCompliance, 0),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    // Evaluation should have Stale input_validity
    let stale_eval = record
        .evaluations
        .iter()
        .find(|e| matches!(e.input_validity, InputValidity::Stale { .. }));
    assert!(stale_eval.is_some());
}

#[test]
fn evaluate_c0_schema_incompatible_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let mut input = make_passing_input(GateCategory::SemanticContract, now_ns());
    input.schema_major = 0; // Below min_schema_major (1)
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: vec![
                input,
                make_passing_input(GateCategory::GovernanceCompliance, now_ns()),
            ],
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let incompat = record
        .evaluations
        .iter()
        .find(|e| matches!(e.input_validity, InputValidity::Incompatible { .. }));
    assert!(incompat.is_some());
}

#[test]
fn evaluate_unregistered_cut_line_returns_none() {
    let mut eval = CutLineEvaluator::new(vec![CutLineSpec::default_c0()]);
    let result = eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: vec![],
        predecessor_promoted: false,
        zone: "z".into(),
    });
    assert!(result.is_none());
}

// =========================================================================
// CutLineEvaluator — evaluate C1 (requires predecessor)
// =========================================================================

#[test]
fn evaluate_c1_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // C0 not promoted, try C1
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
    assert!(!eval.is_promoted(CutLine::C1));
}

#[test]
fn evaluate_c1_with_predecessor_flag_passes() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Even without promoting C0 internally, the predecessor_promoted flag
    // in the input overrides.
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: true,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C1));
}

#[test]
fn evaluate_c1_after_c0_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    // First promote C0
    let c0_record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();
    assert_eq!(c0_record.verdict, GateVerdict::Approved);

    // Now C1 should pass (predecessor promoted internally)
    let c1_record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();
    assert_eq!(c1_record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C1));
    // C1 record should link to C0 predecessor hash
    assert!(c1_record.predecessor_hash.is_some());
}

#[test]
fn evaluate_c1_score_below_threshold_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    // Promote C0 first
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    // C1 CompilerCorrectness requires 1_000_000, give 999_999
    let mut c1_inputs = make_c1_inputs(now_ns());
    c1_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::CompilerCorrectness)
        .expect("compiler correctness input must exist")
        .score_millionths = Some(999_999);

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c1_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
}

#[test]
fn evaluate_c1_missing_known_gap_metadata_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c1_inputs = make_c1_inputs(now_ns());
    c1_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::RuntimeParity)
        .expect("runtime parity input must exist")
        .metadata
        .remove("known_gap_ledger_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c1_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let runtime_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::RuntimeParity)
        .expect("runtime parity evaluation must exist");
    assert!(matches!(
        runtime_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

#[test]
fn evaluate_c1_divergence_without_replay_manifest_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c1_inputs = make_c1_inputs(now_ns());
    let runtime = c1_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::RuntimeParity)
        .expect("runtime parity input must exist");
    runtime.passed = false;
    runtime.metadata.remove("divergence_replay_manifest_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c1_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let runtime_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::RuntimeParity)
        .expect("runtime parity evaluation must exist");
    assert!(matches!(
        runtime_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

#[test]
fn evaluate_c2_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C2,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c2_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
}

#[test]
fn evaluate_c2_after_c1_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C2,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c2_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C2));
}

#[test]
fn evaluate_c2_missing_route_adoption_metadata_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c2_inputs = make_c2_inputs(now_ns());
    c2_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::HandoffReadiness)
        .expect("handoff readiness input must exist")
        .metadata
        .remove("route_adoption_control_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C2,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c2_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let handoff_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::HandoffReadiness)
        .expect("handoff readiness evaluation must exist");
    assert!(matches!(
        handoff_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

#[test]
fn evaluate_c3_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C3,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c3_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
}

#[test]
fn evaluate_c3_after_c2_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C3,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c3_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C3));
}

#[test]
fn evaluate_c3_missing_wasm_parity_metadata_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c3_inputs = make_c3_inputs(now_ns());
    c3_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::RuntimeParity)
        .expect("runtime parity input must exist")
        .metadata
        .remove("wasm_parity_manifest_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C3,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c3_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let runtime_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::RuntimeParity)
        .expect("runtime parity evaluation must exist");
    assert!(matches!(
        runtime_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

#[test]
fn evaluate_c4_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C4,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c4_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
}

#[test]
fn evaluate_c4_after_c3_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c3_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C4,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c4_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C4));
}

#[test]
fn evaluate_c4_missing_proof_ci_gate_metadata_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c3_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c4_inputs = make_c4_inputs(now_ns());
    c4_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::GovernanceCompliance)
        .expect("governance compliance input must exist")
        .metadata
        .remove("proof_carrying_ci_gate_manifest_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C4,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c4_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let governance_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::GovernanceCompliance)
        .expect("governance compliance evaluation must exist");
    assert!(matches!(
        governance_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

#[test]
fn evaluate_c5_without_predecessor_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C5,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c5_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    assert_eq!(record.risk_level, RiskLevel::Critical);
}

#[test]
fn evaluate_c5_after_c4_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c3_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C4,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c4_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C5,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c5_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Approved);
    assert!(eval.is_promoted(CutLine::C5));
}

#[test]
fn evaluate_c5_missing_embedding_boundary_metadata_denied() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C1,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c1_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C2,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c2_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C3,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c3_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C4,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c4_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut c5_inputs = make_c5_inputs(now_ns());
    c5_inputs
        .iter_mut()
        .find(|input| input.category == GateCategory::HandoffReadiness)
        .expect("handoff readiness input must exist")
        .metadata
        .remove("browser_embedding_boundary_manifest_ref");

    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C5,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: c5_inputs,
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    assert_eq!(record.verdict, GateVerdict::Denied);
    let handoff_eval = record
        .evaluations
        .iter()
        .find(|evaluation| evaluation.category == GateCategory::HandoffReadiness)
        .expect("handoff readiness evaluation must exist");
    assert!(matches!(
        handoff_eval.input_validity,
        InputValidity::Incompatible { .. }
    ));
}

// =========================================================================
// PromotionRecord
// =========================================================================

#[test]
fn promotion_record_hash_deterministic() {
    let mut eval1 = CutLineEvaluator::with_defaults();
    let mut eval2 = CutLineEvaluator::with_defaults();

    let input = GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    };

    let r1 = eval1.evaluate(input.clone()).unwrap();
    let r2 = eval2.evaluate(input).unwrap();
    assert_eq!(r1.record_hash, r2.record_hash);
}

#[test]
fn promotion_record_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    let record = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "prod".into(),
        })
        .unwrap();

    let json = serde_json::to_string(&record).unwrap();
    let restored: PromotionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, restored);
}

// =========================================================================
// PromotionSummary
// =========================================================================

#[test]
fn promotion_summary_initial() {
    let eval = CutLineEvaluator::with_defaults();
    let summary = eval.promotion_summary();
    assert!(summary.promoted_lines.is_empty());
    assert_eq!(summary.next_line, Some(CutLine::C0));
    assert_eq!(summary.total_evaluations, 0);
    assert_eq!(summary.approved_count, 0);
    assert_eq!(summary.denied_count, 0);
    assert!(!summary.all_promoted());
    assert_eq!(summary.progress_millionths(), 0);
}

#[test]
fn promotion_summary_after_c0_promoted() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let summary = eval.promotion_summary();
    assert_eq!(summary.promoted_lines, vec![CutLine::C0]);
    assert_eq!(summary.next_line, Some(CutLine::C1));
    assert_eq!(summary.total_evaluations, 1);
    assert_eq!(summary.approved_count, 1);
    assert_eq!(summary.denied_count, 0);
    // 1 of 6 promoted = 166_666 millionths
    assert_eq!(summary.progress_millionths(), 166_666);
}

#[test]
fn promotion_summary_serde_roundtrip() {
    let summary = PromotionSummary {
        promoted_lines: vec![CutLine::C0, CutLine::C1],
        next_line: Some(CutLine::C2),
        total_evaluations: 5,
        approved_count: 2,
        denied_count: 3,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: PromotionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// CutLineEvaluator — revoke promotion
// =========================================================================

#[test]
fn revoke_promotion() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });
    assert!(eval.is_promoted(CutLine::C0));
    assert!(eval.revoke_promotion(CutLine::C0));
    assert!(!eval.is_promoted(CutLine::C0));
    // Revoking again returns false
    assert!(!eval.revoke_promotion(CutLine::C0));
}

// =========================================================================
// GateHistory
// =========================================================================

#[test]
fn gate_history_empty() {
    let eval = CutLineEvaluator::with_defaults();
    let history = GateHistory::from_evaluator(&eval);
    assert!(history.records.is_empty());
    assert!(history.verify());
}

#[test]
fn gate_history_with_records() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let history = GateHistory::from_evaluator(&eval);
    assert_eq!(history.records.len(), 1);
    assert!(history.verify());
}

#[test]
fn gate_history_tampered_fails_verify() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let mut history = GateHistory::from_evaluator(&eval);
    // Tamper with the hash
    history.history_hash = ContentHash::compute(b"tampered");
    assert!(!history.verify());
}

#[test]
fn gate_history_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let history = GateHistory::from_evaluator(&eval);
    let json = serde_json::to_string(&history).unwrap();
    let restored: GateHistory = serde_json::from_str(&json).unwrap();
    assert_eq!(history, restored);
    assert!(restored.verify());
}

// =========================================================================
// CutLineEvaluator — serde roundtrip
// =========================================================================

#[test]
fn evaluator_serde_roundtrip() {
    let mut eval = CutLineEvaluator::with_defaults();
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "prod".into(),
    });

    let json = serde_json::to_string(&eval).unwrap();
    let restored: CutLineEvaluator = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, restored);
    assert!(restored.is_promoted(CutLine::C0));
}

// =========================================================================
// Full lifecycle: C0 → C1 → denied C1 with advisory failure
// =========================================================================

#[test]
fn full_lifecycle_c0_then_c1() {
    let mut eval = CutLineEvaluator::with_defaults();

    // Promote C0
    let c0 = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "staging".into(),
        })
        .unwrap();
    assert_eq!(c0.verdict, GateVerdict::Approved);
    assert_eq!(c0.zone, "staging");

    // Promote C1
    let c1 = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C1,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c1_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "staging".into(),
        })
        .unwrap();
    assert_eq!(c1.verdict, GateVerdict::Approved);

    // Summary
    let summary = eval.promotion_summary();
    assert_eq!(summary.promoted_lines.len(), 2);
    assert_eq!(summary.next_line, Some(CutLine::C2));
    assert_eq!(summary.approved_count, 2);
    assert_eq!(eval.history_len(), 2);

    // History integrity
    let history = GateHistory::from_evaluator(&eval);
    assert!(history.verify());
}

#[test]
fn risk_level_varies_with_failures() {
    let mut eval = CutLineEvaluator::with_defaults();

    // All pass → Low risk
    let r = eval
        .evaluate(GateEvaluationInput {
            cut_line: CutLine::C0,
            now_ns: now_ns(),
            epoch: epoch(),
            inputs: make_c0_inputs(now_ns()),
            predecessor_promoted: false,
            zone: "z".into(),
        })
        .unwrap();
    assert_eq!(r.risk_level, RiskLevel::Low);
}

// =========================================================================
// Multiple evaluations accumulate history
// =========================================================================

#[test]
fn multiple_evaluations_accumulate() {
    let mut eval = CutLineEvaluator::with_defaults();

    // Attempt 1: denied (missing evidence)
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: vec![],
        predecessor_promoted: false,
        zone: "z".into(),
    });

    // Attempt 2: approved
    eval.evaluate(GateEvaluationInput {
        cut_line: CutLine::C0,
        now_ns: now_ns(),
        epoch: epoch(),
        inputs: make_c0_inputs(now_ns()),
        predecessor_promoted: false,
        zone: "z".into(),
    });

    assert_eq!(eval.history_len(), 2);
    let summary = eval.promotion_summary();
    assert_eq!(summary.total_evaluations, 2);
    assert_eq!(summary.approved_count, 1);
    assert_eq!(summary.denied_count, 1);
}
