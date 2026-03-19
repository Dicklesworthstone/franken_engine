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
    clippy::identity_op
)]

//! Enrichment integration tests (batch 2) for the `proof_obligations` module.

use std::collections::BTreeSet;

use frankenengine_engine::proof_obligations::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ===========================================================================
// ObligationCategory Display uniqueness
// ===========================================================================

#[test]
fn enrichment_category_display_all_unique() {
    let displays: BTreeSet<String> = ObligationCategory::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), 5);
}

// ===========================================================================
// ObligationSeverity Display uniqueness
// ===========================================================================

#[test]
fn enrichment_severity_display_all_unique() {
    let severities = [
        ObligationSeverity::Info,
        ObligationSeverity::Warning,
        ObligationSeverity::Error,
        ObligationSeverity::Fatal,
    ];
    let displays: BTreeSet<String> = severities.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// ===========================================================================
// ObligationStatus Display uniqueness
// ===========================================================================

#[test]
fn enrichment_status_display_all_unique() {
    let statuses = [
        ObligationStatus::Pending,
        ObligationStatus::InProgress,
        ObligationStatus::Satisfied,
        ObligationStatus::Violated,
        ObligationStatus::Waived,
        ObligationStatus::InsufficientEvidence,
    ];
    let displays: BTreeSet<String> = statuses.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

// ===========================================================================
// ObligationId ordering
// ===========================================================================

#[test]
fn enrichment_obligation_id_ord_is_lexicographic() {
    let a = ObligationId("obl-10".into());
    let b = ObligationId("obl-2".into());
    // Lexicographic: "obl-10" < "obl-2" because '1' < '2'
    assert!(a < b);
}

// ===========================================================================
// PassId ordering
// ===========================================================================

#[test]
fn enrichment_pass_id_ord_is_lexicographic() {
    let a = PassId("alpha".into());
    let b = PassId("beta".into());
    assert!(a < b);
}

// ===========================================================================
// Registry: bind returns incrementing obligation IDs
// ===========================================================================

#[test]
fn enrichment_registry_bind_returns_sequential_ids() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let id1 = reg
        .bind(PassId("p1".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let id2 = reg
        .bind(PassId("p2".into()), "behavioral/render_output_stability")
        .unwrap();
    let id3 = reg
        .bind(PassId("p3".into()), "safety/ifc_label_propagation")
        .unwrap();
    assert_eq!(id1.0, "obl-1");
    assert_eq!(id2.0, "obl-2");
    assert_eq!(id3.0, "obl-3");
}

// ===========================================================================
// Registry: auto_evaluate CVaR boundary
// ===========================================================================

#[test]
fn enrichment_auto_evaluate_cvar_exact_boundary() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();
    // max_cvar = 50_000_000, observed = exactly that
    let status = reg.auto_evaluate(&obl_id, 50_000_000, 100).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn enrichment_auto_evaluate_cvar_just_over() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 50_000_001, 100).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

// ===========================================================================
// Registry: auto_evaluate differential test boundary
// ===========================================================================

#[test]
fn enrichment_auto_evaluate_differential_exact_boundary() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    // min_pass_rate = 999_000, min_test_count = 1000
    let status = reg.auto_evaluate(&obl_id, 999_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn enrichment_auto_evaluate_differential_just_below() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 998_999, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

#[test]
fn enrichment_auto_evaluate_differential_insufficient_samples() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 1_000_000, 999).unwrap();
    assert_eq!(status, ObligationStatus::InsufficientEvidence);
}

// ===========================================================================
// Registry: auto_evaluate calibration coverage
// ===========================================================================

#[test]
fn enrichment_auto_evaluate_calibration_coverage_satisfied() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cal".into()), "calibration/conformal_coverage")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 950_000, 100).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn enrichment_auto_evaluate_calibration_coverage_violated() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cal".into()), "calibration/conformal_coverage")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 500_000, 100).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

// ===========================================================================
// Registry: waive waivable and non-waivable
// ===========================================================================

#[test]
fn enrichment_waive_waivable_succeeds_and_shows_in_report() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
        .unwrap();
    assert!(reg.waive(&obl_id, "operator approved"));
    let report = reg.report();
    assert_eq!(report.waived_count, 1);
    assert!(report.gate_pass);
}

#[test]
fn enrichment_waive_non_waivable_fails() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("safety".into()), "safety/ifc_label_propagation")
        .unwrap();
    assert!(!reg.waive(&obl_id, "trying to waive"));
}

// ===========================================================================
// Report: InProgress counts as pending
// ===========================================================================

#[test]
fn enrichment_report_in_progress_counts_as_pending() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "test".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Error,
        status: ObligationStatus::InProgress,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "in progress".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert_eq!(report.pending_count, 1);
    assert!(!report.gate_pass);
}

// ===========================================================================
// Report: insufficient_evidence alone passes gate
// ===========================================================================

#[test]
fn enrichment_report_insufficient_evidence_alone_passes() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t1".into(),
        category: ObligationCategory::BehavioralPreservation,
        severity: ObligationSeverity::Fatal,
        status: ObligationStatus::InsufficientEvidence,
        epoch: epoch(1),
        observed_value: None,
        required_value: Some(999_000),
        reason: "not enough data".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert_eq!(report.insufficient_count, 1);
    assert!(report.gate_pass);
}

// ===========================================================================
// Report: fatal violation blocks gate
// ===========================================================================

#[test]
fn enrichment_report_fatal_violation_blocks_gate() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t1".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Fatal,
        status: ObligationStatus::Violated,
        epoch: epoch(1),
        observed_value: Some(0),
        required_value: Some(999_000),
        reason: "failed".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
    assert_eq!(report.violated_count, 1);
}

// ===========================================================================
// Report serde roundtrip
// ===========================================================================

#[test]
fn enrichment_report_serde_roundtrip_empty() {
    let report = ObligationReport::from_evaluations(epoch(1), vec![]);
    let json = serde_json::to_string(&report).unwrap();
    let back: ObligationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Registry: empty vs new
// ===========================================================================

#[test]
fn enrichment_registry_empty_has_no_templates() {
    let reg = ObligationRegistry::empty(epoch(1));
    assert_eq!(reg.template_count(), 0);
    assert_eq!(reg.binding_count(), 0);
}

#[test]
fn enrichment_registry_new_has_builtin_templates() {
    let reg = ObligationRegistry::new(epoch(1));
    assert!(reg.template_count() >= 15);
}

// ===========================================================================
// Registry: custom template bind and auto_evaluate
// ===========================================================================

#[test]
fn enrichment_custom_template_auto_evaluate_operator_review() {
    let mut reg = ObligationRegistry::empty(epoch(1));
    reg.register_template(ObligationTemplate {
        template_id: "custom/operator_check".into(),
        category: ObligationCategory::TailRisk,
        severity: ObligationSeverity::Warning,
        description: "custom check".into(),
        evidence: EvidenceRequirement::OperatorReview,
        waivable: true,
    });
    let obl_id = reg
        .bind(PassId("custom_pass".into()), "custom/operator_check")
        .unwrap();
    // OperatorReview falls into the catch-all branch -> Pending
    let status = reg.auto_evaluate(&obl_id, 1_000_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

// ===========================================================================
// Determinism: same operations produce same report
// ===========================================================================

#[test]
fn enrichment_deterministic_report_across_runs() {
    let run = || {
        let mut reg = ObligationRegistry::new(epoch(1));
        let obl1 = reg
            .bind(PassId("p1".into()), "behavioral/ir_transform_equivalence")
            .unwrap();
        let obl2 = reg
            .bind(PassId("p2".into()), "safety/hash_chain_integrity")
            .unwrap();
        reg.auto_evaluate(&obl1, 999_500, 2000);
        reg.evaluate(&obl2, ObligationStatus::Satisfied, None, "verified");
        reg.report()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

// ===========================================================================
// ObligationBinding denormalized fields match template
// ===========================================================================

#[test]
fn enrichment_binding_denormalized_fields_match_template() {
    let mut reg = ObligationRegistry::new(epoch(1));
    reg.bind(PassId("pass".into()), "behavioral/ir_transform_equivalence");
    let template = reg.template("behavioral/ir_transform_equivalence").unwrap();
    let bindings = reg.bindings_for_pass(&PassId("pass".into()));
    assert_eq!(bindings.len(), 1);
    let b = &bindings[0];
    assert_eq!(b.category, template.category);
    assert_eq!(b.severity, template.severity);
    assert_eq!(b.evidence, template.evidence);
}

// ===========================================================================
// ObligationEvaluation serde roundtrip
// ===========================================================================

#[test]
fn enrichment_obligation_evaluation_serde_roundtrip() {
    let eval = ObligationEvaluation {
        obligation_id: ObligationId("obl-99".into()),
        template_id: "test/template".into(),
        category: ObligationCategory::TailRisk,
        severity: ObligationSeverity::Warning,
        status: ObligationStatus::InsufficientEvidence,
        epoch: epoch(42),
        observed_value: None,
        required_value: Some(999_000),
        reason: "not enough data".into(),
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ObligationEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// auto_evaluate for e-process guardrail returns Pending
// ===========================================================================

#[test]
fn enrichment_auto_evaluate_eprocess_guardrail_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("ep".into()), "calibration/eprocess_integrity")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 1_000_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

// ===========================================================================
// auto_evaluate for PLAS witness returns Pending
// ===========================================================================

#[test]
fn enrichment_auto_evaluate_plas_witness_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cap".into()), "safety/capability_authority_bound")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 1_000_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

// ===========================================================================
// ObligationReport serde roundtrip with multiple evaluations
// ===========================================================================

#[test]
fn enrichment_report_serde_roundtrip_mixed() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Satisfied,
            epoch: epoch(1),
            observed_value: Some(1_000_000),
            required_value: Some(999_000),
            reason: "ok".into(),
        },
        ObligationEvaluation {
            obligation_id: ObligationId("obl-2".into()),
            template_id: "t2".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Warning,
            status: ObligationStatus::Waived,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "waived".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    let json = serde_json::to_string(&report).unwrap();
    let back: ObligationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Registry: evaluation_count tracks correctly
// ===========================================================================

#[test]
fn enrichment_registry_evaluation_count() {
    let mut reg = ObligationRegistry::new(epoch(1));
    assert_eq!(reg.evaluation_count(), 0);
    let obl1 = reg
        .bind(PassId("p1".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    reg.auto_evaluate(&obl1, 999_500, 2000);
    assert_eq!(reg.evaluation_count(), 1);
    let obl2 = reg
        .bind(PassId("p2".into()), "safety/hash_chain_integrity")
        .unwrap();
    reg.evaluate(&obl2, ObligationStatus::Satisfied, None, "verified");
    assert_eq!(reg.evaluation_count(), 2);
}

// ===========================================================================
// ObligationCategory serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_category_serde_roundtrip_all() {
    for cat in &ObligationCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ObligationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}
