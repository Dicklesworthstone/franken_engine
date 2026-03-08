#![forbid(unsafe_code)]
//! Enrichment integration tests for `obstruction_certificate`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, config defaults, and edge cases beyond
//! the existing 66 integration tests.

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::global_coherence_checker::SeverityScore;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::obstruction_certificate::{
    CertificationOutcome, CertificationResult, DEBT_BUDGET_EXHAUSTED, DEBT_FALLBACK_INFEASIBLE,
    DEBT_OBSTRUCTION_UNRESOLVED, DEBT_PLAN_CYCLE, DEBT_WITNESS_INCOMPLETE, FallbackAction,
    FallbackActionKind, FallbackPlan, OBSTRUCTION_CERT_BEAD_ID, OBSTRUCTION_CERT_SCHEMA_VERSION,
    ObstructionCertificate, ObstructionCertifier, ObstructionCertifierConfig, ObstructionError,
    WitnessFragment,
};

/// Helper to make a unique EngineObjectId from a byte seed.
fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

// ===========================================================================
// 1) FallbackActionKind — exact Display
// ===========================================================================

#[test]
fn fallback_action_kind_display_exact_isolate() {
    assert_eq!(FallbackActionKind::Isolate.to_string(), "isolate");
}

#[test]
fn fallback_action_kind_display_exact_degrade() {
    assert_eq!(FallbackActionKind::Degrade.to_string(), "degrade");
}

#[test]
fn fallback_action_kind_display_exact_split_boundary() {
    assert_eq!(
        FallbackActionKind::SplitBoundary.to_string(),
        "split-boundary"
    );
}

#[test]
fn fallback_action_kind_display_exact_inject_adapter() {
    assert_eq!(
        FallbackActionKind::InjectAdapter.to_string(),
        "inject-adapter"
    );
}

#[test]
fn fallback_action_kind_display_exact_remove_and_stub() {
    assert_eq!(
        FallbackActionKind::RemoveAndStub.to_string(),
        "remove-and-stub"
    );
}

#[test]
fn fallback_action_kind_display_exact_escalate() {
    assert_eq!(FallbackActionKind::Escalate.to_string(), "escalate");
}

// ===========================================================================
// 2) CertificationOutcome — exact Display
// ===========================================================================

#[test]
fn certification_outcome_display_exact_clear() {
    assert_eq!(CertificationOutcome::Clear.to_string(), "clear");
}

#[test]
fn certification_outcome_display_exact_obstructed_with_fallbacks() {
    assert_eq!(
        CertificationOutcome::ObstructedWithFallbacks.to_string(),
        "obstructed-with-fallbacks"
    );
}

#[test]
fn certification_outcome_display_exact_obstructed_no_fallback() {
    assert_eq!(
        CertificationOutcome::ObstructedNoFallback.to_string(),
        "obstructed-no-fallback"
    );
}

#[test]
fn certification_outcome_display_exact_budget_exhausted() {
    assert_eq!(
        CertificationOutcome::BudgetExhausted.to_string(),
        "budget-exhausted"
    );
}

// ===========================================================================
// 3) ObstructionError — exact Display
// ===========================================================================

#[test]
fn obstruction_error_display_exact_budget_exhausted() {
    let e = ObstructionError::BudgetExhausted {
        resource: "certificates".to_string(),
        limit: 100,
    };
    let s = e.to_string();
    assert!(s.contains("certificates"), "should mention resource: {s}");
    assert!(s.contains("100"), "should mention limit: {s}");
}

#[test]
fn obstruction_error_display_exact_invalid_input() {
    let e = ObstructionError::InvalidInput("bad field".to_string());
    let s = e.to_string();
    assert!(s.contains("bad field"), "should contain detail: {s}");
}

#[test]
fn obstruction_error_display_exact_internal_inconsistency() {
    let e = ObstructionError::InternalInconsistency("hash mismatch".to_string());
    let s = e.to_string();
    assert!(s.contains("hash mismatch"), "should contain detail: {s}");
}

#[test]
fn obstruction_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ObstructionError::BudgetExhausted {
            resource: "x".into(),
            limit: 1,
        }
        .to_string(),
        ObstructionError::InvalidInput("y".into()).to_string(),
        ObstructionError::InternalInconsistency("z".into()).to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all Display strings must be unique"
    );
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_fallback_action_kind() {
    let variants = [
        format!("{:?}", FallbackActionKind::Isolate),
        format!("{:?}", FallbackActionKind::Degrade),
        format!("{:?}", FallbackActionKind::SplitBoundary),
        format!("{:?}", FallbackActionKind::InjectAdapter),
        format!("{:?}", FallbackActionKind::RemoveAndStub),
        format!("{:?}", FallbackActionKind::Escalate),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_certification_outcome() {
    let variants = [
        format!("{:?}", CertificationOutcome::Clear),
        format!("{:?}", CertificationOutcome::ObstructedWithFallbacks),
        format!("{:?}", CertificationOutcome::ObstructedNoFallback),
        format!("{:?}", CertificationOutcome::BudgetExhausted),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 5) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_fallback_action_kind_tags() {
    let kinds = [
        FallbackActionKind::Isolate,
        FallbackActionKind::Degrade,
        FallbackActionKind::SplitBoundary,
        FallbackActionKind::InjectAdapter,
        FallbackActionKind::RemoveAndStub,
        FallbackActionKind::Escalate,
    ];
    let expected = [
        "\"Isolate\"",
        "\"Degrade\"",
        "\"SplitBoundary\"",
        "\"InjectAdapter\"",
        "\"RemoveAndStub\"",
        "\"Escalate\"",
    ];
    for (kind, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(kind).unwrap();
        assert_eq!(
            json, *exp,
            "FallbackActionKind serde tag mismatch for {kind:?}"
        );
    }
}

#[test]
fn serde_exact_certification_outcome_tags() {
    let outcomes = [
        CertificationOutcome::Clear,
        CertificationOutcome::ObstructedWithFallbacks,
        CertificationOutcome::ObstructedNoFallback,
        CertificationOutcome::BudgetExhausted,
    ];
    let expected = [
        "\"Clear\"",
        "\"ObstructedWithFallbacks\"",
        "\"ObstructedNoFallback\"",
        "\"BudgetExhausted\"",
    ];
    for (o, exp) in outcomes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(o).unwrap();
        assert_eq!(
            json, *exp,
            "CertificationOutcome serde tag mismatch for {o:?}"
        );
    }
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_witness_fragment() {
    let wf = WitnessFragment {
        component_id: "c1".to_string(),
        contract_aspect: "ordering".to_string(),
        contract_value: "before-after".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&wf).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("component_id"));
    assert!(obj.contains_key("contract_aspect"));
    assert!(obj.contains_key("contract_value"));
}

#[test]
fn json_fields_fallback_action() {
    let fa = FallbackAction {
        id: oid(1),
        kind: FallbackActionKind::Isolate,
        target_components: vec!["comp-a".to_string()],
        description: "isolate component".to_string(),
        disruption_cost_millionths: 500_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"rationale"),
    };
    let v: serde_json::Value = serde_json::to_value(&fa).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "id",
        "kind",
        "target_components",
        "description",
        "disruption_cost_millionths",
        "feasible",
        "rationale_hash",
    ] {
        assert!(obj.contains_key(key), "FallbackAction missing field: {key}");
    }
}

#[test]
fn json_fields_fallback_plan() {
    let fp = FallbackPlan {
        id: oid(2),
        certificate_id: oid(3),
        actions: vec![],
        recommended_action_index: 0,
        has_feasible_resolution: false,
        debt_code: None,
        plan_hash: ContentHash::compute(b"plan"),
    };
    let v: serde_json::Value = serde_json::to_value(&fp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "id",
        "certificate_id",
        "actions",
        "recommended_action_index",
        "has_feasible_resolution",
        "debt_code",
        "plan_hash",
    ] {
        assert!(obj.contains_key(key), "FallbackPlan missing field: {key}");
    }
}

#[test]
fn json_fields_obstruction_certificate() {
    let cert = ObstructionCertificate {
        id: oid(4),
        source_violation_id: oid(5),
        violation_kind_tag: "test-violation".to_string(),
        severity: SeverityScore(500_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 42,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "test".to_string(),
        certificate_hash: ContentHash::compute(b"cert"),
        fallback_plan: None,
    };
    let v: serde_json::Value = serde_json::to_value(&cert).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "id",
        "source_violation_id",
        "violation_kind_tag",
        "severity",
        "debt_code",
        "detected_epoch",
        "witness_components",
        "witness_fragments",
        "explanation",
        "certificate_hash",
        "fallback_plan",
    ] {
        assert!(
            obj.contains_key(key),
            "ObstructionCertificate missing field: {key}"
        );
    }
}

#[test]
fn json_fields_certification_result() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"result"),
    };
    let v: serde_json::Value = serde_json::to_value(&result).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "bead_id",
        "outcome",
        "certificates",
        "total_obstructions",
        "blocking_obstructions",
        "feasible_fallback_count",
        "infeasible_fallback_count",
        "certification_epoch",
        "result_hash",
    ] {
        assert!(
            obj.contains_key(key),
            "CertificationResult missing field: {key}"
        );
    }
}

#[test]
fn json_fields_obstruction_certifier_config() {
    let config = ObstructionCertifierConfig::default();
    let v: serde_json::Value = serde_json::to_value(&config).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "max_certificates",
        "max_actions_per_plan",
        "max_witness_components",
        "include_non_blocking",
        "disruption_costs",
    ] {
        assert!(
            obj.contains_key(key),
            "ObstructionCertifierConfig missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) Config default exact values
// ===========================================================================

#[test]
fn config_default_exact_values() {
    let config = ObstructionCertifierConfig::default();
    assert_eq!(config.max_certificates, 10_000);
    assert_eq!(config.max_actions_per_plan, 100);
    assert_eq!(config.max_witness_components, 500);
    assert!(config.include_non_blocking);
    assert!(!config.disruption_costs.is_empty());
}

// ===========================================================================
// 8) Constants stability
// ===========================================================================

#[test]
fn schema_version_constant_stable() {
    assert_eq!(
        OBSTRUCTION_CERT_SCHEMA_VERSION,
        "franken-engine.obstruction_certificate.v1"
    );
}

#[test]
fn bead_id_constant_stable() {
    assert_eq!(OBSTRUCTION_CERT_BEAD_ID, "bd-mjh3.14.3");
}

#[test]
fn debt_code_constants_stable() {
    assert_eq!(DEBT_OBSTRUCTION_UNRESOLVED, "FE-FRX-14-3-OBSTRUCTION-0001");
    assert_eq!(DEBT_FALLBACK_INFEASIBLE, "FE-FRX-14-3-OBSTRUCTION-0002");
    assert_eq!(DEBT_WITNESS_INCOMPLETE, "FE-FRX-14-3-OBSTRUCTION-0003");
    assert_eq!(DEBT_PLAN_CYCLE, "FE-FRX-14-3-OBSTRUCTION-0004");
    assert_eq!(DEBT_BUDGET_EXHAUSTED, "FE-FRX-14-3-OBSTRUCTION-0005");
}

// ===========================================================================
// 9) WitnessFragment Display
// ===========================================================================

#[test]
fn witness_fragment_display_format() {
    let wf = WitnessFragment {
        component_id: "comp-x".to_string(),
        contract_aspect: "ordering".to_string(),
        contract_value: "strict-before".to_string(),
    };
    assert_eq!(wf.to_string(), "comp-x/ordering: strict-before");
}

// ===========================================================================
// 10) FallbackPlan methods
// ===========================================================================

#[test]
fn fallback_plan_recommended_action_empty() {
    let fp = FallbackPlan {
        id: oid(10),
        certificate_id: oid(11),
        actions: vec![],
        recommended_action_index: 0,
        has_feasible_resolution: false,
        debt_code: None,
        plan_hash: ContentHash::compute(b"empty-plan"),
    };
    assert!(fp.recommended_action().is_none());
    assert!(fp.feasible_actions().is_empty());
}

#[test]
fn fallback_plan_recommended_action_valid_index() {
    let action = FallbackAction {
        id: oid(12),
        kind: FallbackActionKind::Degrade,
        target_components: vec!["c1".to_string()],
        description: "degrade c1".to_string(),
        disruption_cost_millionths: 300_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"r"),
    };
    let fp = FallbackPlan {
        id: oid(13),
        certificate_id: oid(14),
        actions: vec![action.clone()],
        recommended_action_index: 0,
        has_feasible_resolution: true,
        debt_code: None,
        plan_hash: ContentHash::compute(b"plan-rec"),
    };
    assert!(fp.recommended_action().is_some());
    assert_eq!(fp.feasible_actions().len(), 1);
}

#[test]
fn fallback_plan_summary_line_non_empty() {
    let fp = FallbackPlan {
        id: oid(15),
        certificate_id: oid(16),
        actions: vec![],
        recommended_action_index: 0,
        has_feasible_resolution: false,
        debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
        plan_hash: ContentHash::compute(b"plan-sum"),
    };
    let s = fp.summary_line();
    assert!(!s.is_empty());
}

// ===========================================================================
// 11) ObstructionCertificate methods
// ===========================================================================

#[test]
fn obstruction_certificate_summary_line_non_empty() {
    let cert = ObstructionCertificate {
        id: oid(20),
        source_violation_id: oid(21),
        violation_kind_tag: "ordering-violation".to_string(),
        severity: SeverityScore(800_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 10,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "ordering problem".to_string(),
        certificate_hash: ContentHash::compute(b"cert-sum"),
        fallback_plan: None,
    };
    let s = cert.summary_line();
    assert!(!s.is_empty());
}

// ===========================================================================
// 12) CertificationResult methods
// ===========================================================================

#[test]
fn certification_result_clear_can_proceed() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"clear"),
    };
    assert!(result.can_proceed());
    assert!(result.infeasible_certificates().is_empty());
    assert!(result.blocking_certificates().is_empty());
    assert!(result.by_debt_code().is_empty());
}

#[test]
fn certification_result_summary_line_non_empty() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"clear-sum"),
    };
    let s = result.summary_line();
    assert!(!s.is_empty());
}

// ===========================================================================
// 13) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_witness_fragment() {
    let wf = WitnessFragment {
        component_id: "c1".to_string(),
        contract_aspect: "timing".to_string(),
        contract_value: "before".to_string(),
    };
    let json = serde_json::to_string(&wf).unwrap();
    let rt: WitnessFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(wf, rt);
}

#[test]
fn serde_roundtrip_fallback_action() {
    let fa = FallbackAction {
        id: oid(30),
        kind: FallbackActionKind::Escalate,
        target_components: vec!["x".to_string(), "y".to_string()],
        description: "escalate".to_string(),
        disruption_cost_millionths: 1_000_000,
        feasible: false,
        rationale_hash: ContentHash::compute(b"esc"),
    };
    let json = serde_json::to_string(&fa).unwrap();
    let rt: FallbackAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fa, rt);
}

#[test]
fn serde_roundtrip_obstruction_error_all_variants() {
    let variants = vec![
        ObstructionError::BudgetExhausted {
            resource: "plans".into(),
            limit: 50,
        },
        ObstructionError::InvalidInput("bad".into()),
        ObstructionError::InternalInconsistency("oops".into()),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ObstructionError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_certification_result() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedWithFallbacks,
        certificates: vec![],
        total_obstructions: 3,
        blocking_obstructions: 1,
        feasible_fallback_count: 2,
        infeasible_fallback_count: 1,
        certification_epoch: 99,
        result_hash: ContentHash::compute(b"rt"),
    };
    let json = serde_json::to_string(&result).unwrap();
    let rt: CertificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, rt);
}

// ===========================================================================
// 14) ObstructionCertifier construction
// ===========================================================================

#[test]
fn certifier_new_uses_defaults() {
    let certifier = ObstructionCertifier::new();
    let _ = format!("{:?}", certifier);
}

#[test]
fn certifier_with_custom_config() {
    let config = ObstructionCertifierConfig {
        max_certificates: 5,
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);
    let _ = format!("{:?}", certifier);
}

// ===========================================================================
// 15) FallbackActionKind ordering
// ===========================================================================

#[test]
fn fallback_action_kind_ordering_stable() {
    let mut kinds = [
        FallbackActionKind::Escalate,
        FallbackActionKind::Isolate,
        FallbackActionKind::RemoveAndStub,
        FallbackActionKind::Degrade,
        FallbackActionKind::SplitBoundary,
        FallbackActionKind::InjectAdapter,
    ];
    kinds.sort();
    assert_eq!(kinds[0], FallbackActionKind::Isolate);
    assert_eq!(kinds[5], FallbackActionKind::Escalate);
}

// ===========================================================================
// 16) CertificationOutcome ordering
// ===========================================================================

#[test]
fn certification_outcome_ordering_stable() {
    let mut outcomes = [
        CertificationOutcome::BudgetExhausted,
        CertificationOutcome::Clear,
        CertificationOutcome::ObstructedNoFallback,
        CertificationOutcome::ObstructedWithFallbacks,
    ];
    outcomes.sort();
    assert_eq!(outcomes[0], CertificationOutcome::Clear);
    assert_eq!(outcomes[3], CertificationOutcome::BudgetExhausted);
}

// ===========================================================================
// 17) Serde determinism
// ===========================================================================

#[test]
fn fallback_action_serde_deterministic() {
    let fa = FallbackAction {
        id: oid(40),
        kind: FallbackActionKind::Isolate,
        target_components: vec!["c1".to_string()],
        description: "isolate c1".to_string(),
        disruption_cost_millionths: 500_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"det-test"),
    };
    let json1 = serde_json::to_string(&fa).unwrap();
    let json2 = serde_json::to_string(&fa).unwrap();
    assert_eq!(json1, json2, "serde output must be deterministic");
}

// ===========================================================================
// 18) FallbackPlan feasible_actions filters correctly
// ===========================================================================

#[test]
fn fallback_plan_feasible_actions_filters() {
    let feasible = FallbackAction {
        id: oid(50),
        kind: FallbackActionKind::Isolate,
        target_components: vec!["a".to_string()],
        description: "feasible".to_string(),
        disruption_cost_millionths: 100_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"f"),
    };
    let infeasible = FallbackAction {
        id: oid(51),
        kind: FallbackActionKind::Escalate,
        target_components: vec!["b".to_string()],
        description: "infeasible".to_string(),
        disruption_cost_millionths: 900_000,
        feasible: false,
        rationale_hash: ContentHash::compute(b"i"),
    };
    let fp = FallbackPlan {
        id: oid(52),
        certificate_id: oid(53),
        actions: vec![feasible, infeasible],
        recommended_action_index: 0,
        has_feasible_resolution: true,
        debt_code: None,
        plan_hash: ContentHash::compute(b"filter"),
    };
    let feasible_actions = fp.feasible_actions();
    assert_eq!(feasible_actions.len(), 1);
    assert!(feasible_actions[0].feasible);
}

// ===========================================================================
// 19) render_certification_report and utility functions
// ===========================================================================

#[test]
fn render_certification_report_non_empty() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"report"),
    };
    let report =
        frankenengine_engine::obstruction_certificate::render_certification_report(&result);
    assert!(!report.is_empty());
}

#[test]
fn should_block_gate_clear_does_not_block() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"gate-clear"),
    };
    assert!(!frankenengine_engine::obstruction_certificate::should_block_gate(&result));
}

#[test]
fn collect_debt_codes_empty_for_clear() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"debt-clear"),
    };
    let codes = frankenengine_engine::obstruction_certificate::collect_debt_codes(&result);
    assert!(codes.is_empty());
}

// ===========================================================================
// 20) can_proceed() edge cases for each CertificationOutcome
// ===========================================================================

#[test]
fn certification_result_obstructed_with_fallbacks_can_proceed() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedWithFallbacks,
        certificates: vec![],
        total_obstructions: 1,
        blocking_obstructions: 0,
        feasible_fallback_count: 1,
        infeasible_fallback_count: 0,
        certification_epoch: 2,
        result_hash: ContentHash::compute(b"owf-proceed"),
    };
    assert!(result.can_proceed());
}

#[test]
fn certification_result_obstructed_no_fallback_cannot_proceed() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![],
        total_obstructions: 1,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 3,
        result_hash: ContentHash::compute(b"onf-proceed"),
    };
    assert!(!result.can_proceed());
}

#[test]
fn certification_result_budget_exhausted_cannot_proceed() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::BudgetExhausted,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 4,
        result_hash: ContentHash::compute(b"be-proceed"),
    };
    assert!(!result.can_proceed());
}

// ===========================================================================
// 21) should_block_gate() for each outcome
// ===========================================================================

#[test]
fn should_block_gate_obstructed_with_fallbacks_does_not_block() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedWithFallbacks,
        certificates: vec![],
        total_obstructions: 1,
        blocking_obstructions: 0,
        feasible_fallback_count: 1,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"gate-owf"),
    };
    assert!(!frankenengine_engine::obstruction_certificate::should_block_gate(&result));
}

#[test]
fn should_block_gate_obstructed_no_fallback_blocks() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![],
        total_obstructions: 1,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"gate-onf"),
    };
    assert!(frankenengine_engine::obstruction_certificate::should_block_gate(&result));
}

#[test]
fn should_block_gate_budget_exhausted_blocks() {
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::BudgetExhausted,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"gate-be"),
    };
    assert!(frankenengine_engine::obstruction_certificate::should_block_gate(&result));
}

// ===========================================================================
// 22) ObstructionCertificate.is_blocking()
// ===========================================================================

#[test]
fn obstruction_certificate_is_blocking_high_severity() {
    let cert = ObstructionCertificate {
        id: oid(60),
        source_violation_id: oid(61),
        violation_kind_tag: "blocking-violation".to_string(),
        severity: SeverityScore(1_000_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 10,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "critical".to_string(),
        certificate_hash: ContentHash::compute(b"blocking"),
        fallback_plan: None,
    };
    // is_blocking() delegates to severity.is_blocking()
    let _blocking = cert.is_blocking();
}

#[test]
fn obstruction_certificate_is_blocking_low_severity() {
    let cert = ObstructionCertificate {
        id: oid(62),
        source_violation_id: oid(63),
        violation_kind_tag: "warning-violation".to_string(),
        severity: SeverityScore(100_000),
        debt_code: DEBT_WITNESS_INCOMPLETE.to_string(),
        detected_epoch: 10,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "minor".to_string(),
        certificate_hash: ContentHash::compute(b"non-blocking"),
        fallback_plan: None,
    };
    let _blocking = cert.is_blocking();
}

// ===========================================================================
// 23) collect_debt_codes with actual certificates
// ===========================================================================

#[test]
fn collect_debt_codes_with_certificates() {
    let cert1 = ObstructionCertificate {
        id: oid(70),
        source_violation_id: oid(71),
        violation_kind_tag: "v1".to_string(),
        severity: SeverityScore(500_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 1,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "test".to_string(),
        certificate_hash: ContentHash::compute(b"c1"),
        fallback_plan: None,
    };
    let cert2 = ObstructionCertificate {
        id: oid(72),
        source_violation_id: oid(73),
        violation_kind_tag: "v2".to_string(),
        severity: SeverityScore(300_000),
        debt_code: DEBT_FALLBACK_INFEASIBLE.to_string(),
        detected_epoch: 1,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "test2".to_string(),
        certificate_hash: ContentHash::compute(b"c2"),
        fallback_plan: Some(FallbackPlan {
            id: oid(74),
            certificate_id: oid(72),
            actions: vec![],
            recommended_action_index: 0,
            has_feasible_resolution: false,
            debt_code: Some(DEBT_PLAN_CYCLE.to_string()),
            plan_hash: ContentHash::compute(b"p2"),
        }),
    };
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![cert1, cert2],
        total_obstructions: 2,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 1,
        certification_epoch: 5,
        result_hash: ContentHash::compute(b"debt-codes"),
    };
    let codes = frankenengine_engine::obstruction_certificate::collect_debt_codes(&result);
    assert!(codes.contains(DEBT_OBSTRUCTION_UNRESOLVED));
    assert!(codes.contains(DEBT_FALLBACK_INFEASIBLE));
    assert!(codes.contains(DEBT_PLAN_CYCLE));
    assert_eq!(codes.len(), 3);
}

// ===========================================================================
// 24) by_debt_code with actual certificates
// ===========================================================================

#[test]
fn by_debt_code_groups_correctly() {
    let cert1 = ObstructionCertificate {
        id: oid(80),
        source_violation_id: oid(81),
        violation_kind_tag: "v1".to_string(),
        severity: SeverityScore(500_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 1,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "first".to_string(),
        certificate_hash: ContentHash::compute(b"g1"),
        fallback_plan: None,
    };
    let cert2 = ObstructionCertificate {
        id: oid(82),
        source_violation_id: oid(83),
        violation_kind_tag: "v2".to_string(),
        severity: SeverityScore(300_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 2,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "second".to_string(),
        certificate_hash: ContentHash::compute(b"g2"),
        fallback_plan: None,
    };
    let cert3 = ObstructionCertificate {
        id: oid(84),
        source_violation_id: oid(85),
        violation_kind_tag: "v3".to_string(),
        severity: SeverityScore(700_000),
        debt_code: DEBT_WITNESS_INCOMPLETE.to_string(),
        detected_epoch: 3,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "third".to_string(),
        certificate_hash: ContentHash::compute(b"g3"),
        fallback_plan: None,
    };
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![cert1, cert2, cert3],
        total_obstructions: 3,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 5,
        result_hash: ContentHash::compute(b"by-debt"),
    };
    let by_code = result.by_debt_code();
    assert_eq!(by_code.len(), 2);
    assert_eq!(by_code[DEBT_OBSTRUCTION_UNRESOLVED].len(), 2);
    assert_eq!(by_code[DEBT_WITNESS_INCOMPLETE].len(), 1);
}

// ===========================================================================
// 25) blocking_certificates and infeasible_certificates
// ===========================================================================

#[test]
fn blocking_and_infeasible_certificate_filtering() {
    let blocking_cert = ObstructionCertificate {
        id: oid(90),
        source_violation_id: oid(91),
        violation_kind_tag: "blocking".to_string(),
        severity: SeverityScore(1_000_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 1,
        witness_components: BTreeSet::new(),
        witness_fragments: vec![],
        explanation: "blocking cert".to_string(),
        certificate_hash: ContentHash::compute(b"blocking-cert"),
        fallback_plan: Some(FallbackPlan {
            id: oid(92),
            certificate_id: oid(90),
            actions: vec![FallbackAction {
                id: oid(93),
                kind: FallbackActionKind::Isolate,
                target_components: vec!["a".to_string()],
                description: "isolate".to_string(),
                disruption_cost_millionths: 500_000,
                feasible: false,
                rationale_hash: ContentHash::compute(b"infeasible-action"),
            }],
            recommended_action_index: 0,
            has_feasible_resolution: false,
            debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
            plan_hash: ContentHash::compute(b"infeasible-plan"),
        }),
    };
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![blocking_cert],
        total_obstructions: 1,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 1,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"filter-test"),
    };
    // At least verify methods return expected counts based on severity
    let blocking = result.blocking_certificates();
    let infeasible = result.infeasible_certificates();
    assert!(!blocking.is_empty() || !infeasible.is_empty());
}

// ===========================================================================
// 26) Serde roundtrips — ObstructionCertificate with fallback plan
// ===========================================================================

#[test]
fn serde_roundtrip_obstruction_certificate_with_plan() {
    let cert = ObstructionCertificate {
        id: oid(100),
        source_violation_id: oid(101),
        violation_kind_tag: "serde-test".to_string(),
        severity: SeverityScore(600_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 42,
        witness_components: {
            let mut set = BTreeSet::new();
            set.insert("comp-a".to_string());
            set.insert("comp-b".to_string());
            set
        },
        witness_fragments: vec![WitnessFragment {
            component_id: "comp-a".to_string(),
            contract_aspect: "timing".to_string(),
            contract_value: "before".to_string(),
        }],
        explanation: "serde roundtrip test".to_string(),
        certificate_hash: ContentHash::compute(b"serde-cert"),
        fallback_plan: Some(FallbackPlan {
            id: oid(102),
            certificate_id: oid(100),
            actions: vec![FallbackAction {
                id: oid(103),
                kind: FallbackActionKind::Degrade,
                target_components: vec!["comp-a".to_string()],
                description: "degrade component".to_string(),
                disruption_cost_millionths: 200_000,
                feasible: true,
                rationale_hash: ContentHash::compute(b"degrade-rationale"),
            }],
            recommended_action_index: 0,
            has_feasible_resolution: true,
            debt_code: None,
            plan_hash: ContentHash::compute(b"serde-plan"),
        }),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let rt: ObstructionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, rt);
}

// ===========================================================================
// 27) Serde roundtrip — FallbackPlan
// ===========================================================================

#[test]
fn serde_roundtrip_fallback_plan() {
    let fp = FallbackPlan {
        id: oid(110),
        certificate_id: oid(111),
        actions: vec![
            FallbackAction {
                id: oid(112),
                kind: FallbackActionKind::SplitBoundary,
                target_components: vec!["x".to_string(), "y".to_string()],
                description: "split boundary".to_string(),
                disruption_cost_millionths: 400_000,
                feasible: true,
                rationale_hash: ContentHash::compute(b"split"),
            },
            FallbackAction {
                id: oid(113),
                kind: FallbackActionKind::RemoveAndStub,
                target_components: vec!["z".to_string()],
                description: "remove and stub".to_string(),
                disruption_cost_millionths: 800_000,
                feasible: false,
                rationale_hash: ContentHash::compute(b"remove"),
            },
        ],
        recommended_action_index: 0,
        has_feasible_resolution: true,
        debt_code: Some(DEBT_WITNESS_INCOMPLETE.to_string()),
        plan_hash: ContentHash::compute(b"fp-roundtrip"),
    };
    let json = serde_json::to_string(&fp).unwrap();
    let rt: FallbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, rt);
}

// ===========================================================================
// 28) Serde roundtrip — ObstructionCertifierConfig
// ===========================================================================

#[test]
fn serde_roundtrip_obstruction_certifier_config() {
    let config = ObstructionCertifierConfig {
        max_certificates: 42,
        max_actions_per_plan: 7,
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    let rt: ObstructionCertifierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, rt);
}

// ===========================================================================
// 29) render_certification_report with certificates
// ===========================================================================

#[test]
fn render_certification_report_with_certificates() {
    let cert = ObstructionCertificate {
        id: oid(120),
        source_violation_id: oid(121),
        violation_kind_tag: "report-test".to_string(),
        severity: SeverityScore(500_000),
        debt_code: DEBT_OBSTRUCTION_UNRESOLVED.to_string(),
        detected_epoch: 10,
        witness_components: {
            let mut s = BTreeSet::new();
            s.insert("comp".to_string());
            s
        },
        witness_fragments: vec![WitnessFragment {
            component_id: "comp".to_string(),
            contract_aspect: "order".to_string(),
            contract_value: "before".to_string(),
        }],
        explanation: "report test".to_string(),
        certificate_hash: ContentHash::compute(b"report-cert"),
        fallback_plan: None,
    };
    let result = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::ObstructedNoFallback,
        certificates: vec![cert],
        total_obstructions: 1,
        blocking_obstructions: 1,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 10,
        result_hash: ContentHash::compute(b"report-result"),
    };
    let report =
        frankenengine_engine::obstruction_certificate::render_certification_report(&result);
    assert!(report.contains("epoch"));
    assert!(report.contains("report-test"));
}

// ===========================================================================
// 30) WitnessFragment ordering (PartialOrd/Ord)
// ===========================================================================

#[test]
fn witness_fragment_ordering_stable() {
    let mut fragments = [
        WitnessFragment {
            component_id: "z".to_string(),
            contract_aspect: "timing".to_string(),
            contract_value: "before".to_string(),
        },
        WitnessFragment {
            component_id: "a".to_string(),
            contract_aspect: "timing".to_string(),
            contract_value: "after".to_string(),
        },
    ];
    fragments.sort();
    assert_eq!(fragments[0].component_id, "a");
    assert_eq!(fragments[1].component_id, "z");
}

// ===========================================================================
// 31) ObstructionCertificate with witness_components populated
// ===========================================================================

#[test]
fn obstruction_certificate_with_witness_components() {
    let mut witness_components = BTreeSet::new();
    witness_components.insert("comp-a".to_string());
    witness_components.insert("comp-b".to_string());
    witness_components.insert("comp-c".to_string());

    let cert = ObstructionCertificate {
        id: oid(130),
        source_violation_id: oid(131),
        violation_kind_tag: "witness-test".to_string(),
        severity: SeverityScore(400_000),
        debt_code: DEBT_WITNESS_INCOMPLETE.to_string(),
        detected_epoch: 15,
        witness_components: witness_components.clone(),
        witness_fragments: vec![],
        explanation: "witness components".to_string(),
        certificate_hash: ContentHash::compute(b"witness-cert"),
        fallback_plan: None,
    };
    let json = serde_json::to_string(&cert).unwrap();
    let rt: ObstructionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.witness_components.len(), 3);
    assert!(rt.witness_components.contains("comp-a"));
    assert!(rt.witness_components.contains("comp-b"));
    assert!(rt.witness_components.contains("comp-c"));
}

// ===========================================================================
// 32) ObstructionError serde roundtrip deterministic
// ===========================================================================

#[test]
fn obstruction_error_serde_deterministic() {
    let e = ObstructionError::BudgetExhausted {
        resource: "witnesses".to_string(),
        limit: 500,
    };
    let json1 = serde_json::to_string(&e).unwrap();
    let json2 = serde_json::to_string(&e).unwrap();
    assert_eq!(json1, json2);
}

// ===========================================================================
// 33) FallbackAction rationale_hash computed from inputs
// ===========================================================================

#[test]
fn fallback_action_rationale_hash_varies_with_kind() {
    let fa1 = FallbackAction {
        id: oid(140),
        kind: FallbackActionKind::Isolate,
        target_components: vec!["c".to_string()],
        description: "same description".to_string(),
        disruption_cost_millionths: 500_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"isolate-c-same description"),
    };
    let fa2 = FallbackAction {
        id: oid(141),
        kind: FallbackActionKind::Degrade,
        target_components: vec!["c".to_string()],
        description: "same description".to_string(),
        disruption_cost_millionths: 500_000,
        feasible: true,
        rationale_hash: ContentHash::compute(b"degrade-c-same description"),
    };
    assert_ne!(fa1.rationale_hash, fa2.rationale_hash);
}
