#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the `proof_obligations` module.

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
// ObligationId enrichment
// ===========================================================================

#[test]
fn obligation_id_display() {
    let id = ObligationId("obl-42".into());
    assert_eq!(id.to_string(), "obl-42");
}

#[test]
fn obligation_id_ordering() {
    let a = ObligationId("obl-1".into());
    let b = ObligationId("obl-2".into());
    assert!(a < b);
}

#[test]
fn obligation_id_clone_eq() {
    let a = ObligationId("test".into());
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn obligation_id_serde_roundtrip() {
    let id = ObligationId("obl-test".into());
    let json = serde_json::to_string(&id).expect("serialize");
    let restored: ObligationId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, restored);
}

// ===========================================================================
// PassId enrichment
// ===========================================================================

#[test]
fn pass_id_display() {
    let id = PassId("lowering-pass".into());
    assert_eq!(id.to_string(), "lowering-pass");
}

#[test]
fn pass_id_ordering() {
    assert!(PassId("a".into()) < PassId("b".into()));
}

#[test]
fn pass_id_serde_roundtrip() {
    let id = PassId("pass-1".into());
    let json = serde_json::to_string(&id).expect("serialize");
    let restored: PassId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, restored);
}

// ===========================================================================
// ObligationCategory enrichment
// ===========================================================================

#[test]
fn category_all_contains_five() {
    assert_eq!(ObligationCategory::ALL.len(), 5);
}

#[test]
fn category_all_distinct_display() {
    let displays: BTreeSet<String> = ObligationCategory::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn category_display_values() {
    assert_eq!(ObligationCategory::BehavioralPreservation.to_string(), "behavioral_preservation");
    assert_eq!(ObligationCategory::Safety.to_string(), "safety");
    assert_eq!(ObligationCategory::Liveness.to_string(), "liveness");
    assert_eq!(ObligationCategory::CalibrationValidity.to_string(), "calibration_validity");
    assert_eq!(ObligationCategory::TailRisk.to_string(), "tail_risk");
}

#[test]
fn category_serde_all_roundtrip() {
    for cat in &ObligationCategory::ALL {
        let json = serde_json::to_string(cat).expect("serialize");
        let restored: ObligationCategory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*cat, restored);
    }
}

// ===========================================================================
// ObligationSeverity enrichment
// ===========================================================================

#[test]
fn severity_display_all() {
    assert_eq!(ObligationSeverity::Info.to_string(), "info");
    assert_eq!(ObligationSeverity::Warning.to_string(), "warning");
    assert_eq!(ObligationSeverity::Error.to_string(), "error");
    assert_eq!(ObligationSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn severity_ordering() {
    assert!(ObligationSeverity::Info < ObligationSeverity::Warning);
    assert!(ObligationSeverity::Warning < ObligationSeverity::Error);
    assert!(ObligationSeverity::Error < ObligationSeverity::Fatal);
}

#[test]
fn severity_serde_all_roundtrip() {
    for sev in [ObligationSeverity::Info, ObligationSeverity::Warning, ObligationSeverity::Error, ObligationSeverity::Fatal] {
        let json = serde_json::to_string(&sev).expect("serialize");
        let restored: ObligationSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sev, restored);
    }
}

// ===========================================================================
// ObligationStatus enrichment
// ===========================================================================

#[test]
fn status_display_all() {
    assert_eq!(ObligationStatus::Pending.to_string(), "pending");
    assert_eq!(ObligationStatus::InProgress.to_string(), "in_progress");
    assert_eq!(ObligationStatus::Satisfied.to_string(), "satisfied");
    assert_eq!(ObligationStatus::Violated.to_string(), "violated");
    assert_eq!(ObligationStatus::Waived.to_string(), "waived");
    assert_eq!(ObligationStatus::InsufficientEvidence.to_string(), "insufficient_evidence");
}

#[test]
fn status_all_distinct_display() {
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

#[test]
fn status_serde_all_roundtrip() {
    for status in [
        ObligationStatus::Pending,
        ObligationStatus::InProgress,
        ObligationStatus::Satisfied,
        ObligationStatus::Violated,
        ObligationStatus::Waived,
        ObligationStatus::InsufficientEvidence,
    ] {
        let json = serde_json::to_string(&status).expect("serialize");
        let restored: ObligationStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, restored);
    }
}

// ===========================================================================
// EvidenceRequirement enrichment
// ===========================================================================

#[test]
fn evidence_requirement_all_variants_serde() {
    let variants = vec![
        EvidenceRequirement::DifferentialTest { min_pass_rate_millionths: 990_000, min_test_count: 100 },
        EvidenceRequirement::StatisticalTest { confidence_level_millionths: 950_000, min_samples: 500 },
        EvidenceRequirement::FormalProof { proof_system: "coq".into() },
        EvidenceRequirement::HashLinkage,
        EvidenceRequirement::PlasWitness,
        EvidenceRequirement::EProcessGuardrail { guardrail_id: "g1".into() },
        EvidenceRequirement::CvarBound { max_cvar_millionths: 50_000_000, alpha_millionths: 950_000 },
        EvidenceRequirement::CalibrationCoverage { min_coverage_millionths: 900_000 },
        EvidenceRequirement::OperatorReview,
    ];
    for ev in &variants {
        let json = serde_json::to_string(ev).expect("serialize");
        let restored: EvidenceRequirement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*ev, restored);
    }
}

// ===========================================================================
// ObligationTemplate enrichment
// ===========================================================================

#[test]
fn obligation_template_serde_roundtrip() {
    let t = ObligationTemplate {
        template_id: "test/template".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Error,
        description: "test template".into(),
        evidence: EvidenceRequirement::HashLinkage,
        waivable: true,
    };
    let json = serde_json::to_string(&t).expect("serialize");
    let restored: ObligationTemplate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(t, restored);
}

// ===========================================================================
// builtin_templates enrichment
// ===========================================================================

#[test]
fn builtin_templates_not_empty() {
    let templates = builtin_templates();
    assert!(!templates.is_empty());
}

#[test]
fn builtin_templates_cover_all_categories() {
    let templates = builtin_templates();
    let cats: BTreeSet<ObligationCategory> = templates.iter().map(|t| t.category).collect();
    for cat in &ObligationCategory::ALL {
        assert!(cats.contains(cat), "missing category: {cat}");
    }
}

#[test]
fn builtin_templates_unique_ids() {
    let templates = builtin_templates();
    let ids: BTreeSet<&str> = templates.iter().map(|t| t.template_id.as_str()).collect();
    assert_eq!(ids.len(), templates.len());
}

#[test]
fn builtin_templates_all_have_descriptions() {
    for t in builtin_templates() {
        assert!(!t.description.is_empty(), "template {} has empty description", t.template_id);
    }
}

// ===========================================================================
// ObligationBinding enrichment
// ===========================================================================

#[test]
fn obligation_binding_serde_roundtrip() {
    let b = ObligationBinding {
        pass_id: PassId("pass-1".into()),
        obligation_id: ObligationId("obl-1".into()),
        template_id: "safety/ifc_label_propagation".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Fatal,
        evidence: EvidenceRequirement::FormalProof { proof_system: "flow_lattice".into() },
    };
    let json = serde_json::to_string(&b).expect("serialize");
    let restored: ObligationBinding = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(b, restored);
}

// ===========================================================================
// ObligationEvaluation enrichment
// ===========================================================================

#[test]
fn obligation_evaluation_serde_roundtrip() {
    let e = ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "test/t".into(),
        category: ObligationCategory::Liveness,
        severity: ObligationSeverity::Warning,
        status: ObligationStatus::Satisfied,
        epoch: epoch(1),
        observed_value: Some(999_000),
        required_value: Some(990_000),
        reason: "pass rate met".into(),
    };
    let json = serde_json::to_string(&e).expect("serialize");
    let restored: ObligationEvaluation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(e, restored);
}

// ===========================================================================
// ObligationReport enrichment
// ===========================================================================

#[test]
fn report_from_empty_evaluations() {
    let report = ObligationReport::from_evaluations(epoch(1), vec![]);
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 0);
    assert_eq!(report.violated_count, 0);
    assert_eq!(report.pending_count, 0);
}

#[test]
fn report_gate_pass_with_all_satisfied() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("o1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Satisfied,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "ok".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 1);
}

#[test]
fn report_gate_fails_on_fatal_violation() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("o1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Violated,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "failed".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
    assert_eq!(report.violated_count, 1);
}

#[test]
fn report_gate_fails_on_any_violation() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("o1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Warning, // non-fatal
            status: ObligationStatus::Violated,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "failed".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
}

#[test]
fn report_gate_fails_with_pending() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("o1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Info,
            status: ObligationStatus::Pending,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "pending".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
    assert_eq!(report.pending_count, 1);
}

#[test]
fn report_waived_counts() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("o1".into()),
            template_id: "t1".into(),
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
    assert!(report.gate_pass);
    assert_eq!(report.waived_count, 1);
}

// ===========================================================================
// ObligationRegistry enrichment
// ===========================================================================

#[test]
fn registry_new_has_builtin_templates() {
    let reg = ObligationRegistry::new(epoch(1));
    assert!(reg.template_count() > 0);
    assert_eq!(reg.binding_count(), 0);
    assert_eq!(reg.evaluation_count(), 0);
}

#[test]
fn registry_empty_has_no_templates() {
    let reg = ObligationRegistry::empty(epoch(1));
    assert_eq!(reg.template_count(), 0);
}

#[test]
fn registry_register_custom_template() {
    let mut reg = ObligationRegistry::empty(epoch(1));
    reg.register_template(ObligationTemplate {
        template_id: "custom/t".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Error,
        description: "custom".into(),
        evidence: EvidenceRequirement::HashLinkage,
        waivable: true,
    });
    assert_eq!(reg.template_count(), 1);
    assert!(reg.template("custom/t").is_some());
}

#[test]
fn registry_bind_returns_id() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("pass-1".into()), "safety/ifc_label_propagation");
    assert!(obl_id.is_some());
    assert_eq!(reg.binding_count(), 1);
}

#[test]
fn registry_bind_unknown_template_returns_none() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("pass-1".into()), "nonexistent/template");
    assert!(obl_id.is_none());
}

#[test]
fn registry_evaluate_unknown_binding_returns_false() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let result = reg.evaluate(&ObligationId("nonexistent".into()), ObligationStatus::Satisfied, None, "ok");
    assert!(!result);
}

#[test]
fn registry_evaluate_records_result() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "safety/ifc_label_propagation").unwrap();
    assert!(reg.evaluate(&obl_id, ObligationStatus::Satisfied, None, "ok"));
    assert_eq!(reg.evaluation_count(), 1);
}

#[test]
fn registry_auto_evaluate_differential_test_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "behavioral/ir_transform_equivalence").unwrap();
    let status = reg.auto_evaluate(&obl_id, 999_500, 2000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn registry_auto_evaluate_differential_test_fail() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "behavioral/ir_transform_equivalence").unwrap();
    let status = reg.auto_evaluate(&obl_id, 900_000, 2000).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

#[test]
fn registry_auto_evaluate_insufficient_samples() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "behavioral/ir_transform_equivalence").unwrap();
    let status = reg.auto_evaluate(&obl_id, 999_500, 50).unwrap(); // needs 1000
    assert_eq!(status, ObligationStatus::InsufficientEvidence);
}

#[test]
fn registry_auto_evaluate_cvar_bound_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "tail_risk/cvar_latency_bound").unwrap();
    let status = reg.auto_evaluate(&obl_id, 40_000_000, 1000).unwrap(); // within bound
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn registry_auto_evaluate_cvar_bound_fail() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "tail_risk/cvar_latency_bound").unwrap();
    let status = reg.auto_evaluate(&obl_id, 60_000_000, 1000).unwrap(); // exceeds bound
    assert_eq!(status, ObligationStatus::Violated);
}

#[test]
fn registry_waive_waivable_succeeds() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "behavioral/effect_timing_contract").unwrap(); // waivable=true
    assert!(reg.waive(&obl_id, "operator approved"));
}

#[test]
fn registry_waive_non_waivable_fails() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "safety/ifc_label_propagation").unwrap(); // waivable=false
    assert!(!reg.waive(&obl_id, "try waive"));
}

#[test]
fn registry_report_includes_unevaluated_as_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    reg.bind(PassId("p".into()), "safety/ifc_label_propagation").unwrap();
    let report = reg.report();
    assert_eq!(report.evaluations.len(), 1);
    assert_eq!(report.evaluations[0].status, ObligationStatus::Pending);
    assert!(!report.gate_pass);
}

#[test]
fn registry_report_all_satisfied_gate_passes() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "safety/hash_chain_integrity").unwrap();
    reg.evaluate(&obl_id, ObligationStatus::Satisfied, None, "ok");
    let report = reg.report();
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 1);
}

#[test]
fn registry_bindings_for_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let pass_a = PassId("pass-a".into());
    let pass_b = PassId("pass-b".into());
    reg.bind(pass_a.clone(), "safety/ifc_label_propagation");
    reg.bind(pass_a.clone(), "safety/hash_chain_integrity");
    reg.bind(pass_b.clone(), "liveness/scheduler_progress");
    assert_eq!(reg.bindings_for_pass(&pass_a).len(), 2);
    assert_eq!(reg.bindings_for_pass(&pass_b).len(), 1);
}

#[test]
fn registry_bindings_in_category() {
    let mut reg = ObligationRegistry::new(epoch(1));
    reg.bind(PassId("p1".into()), "safety/ifc_label_propagation");
    reg.bind(PassId("p2".into()), "safety/hash_chain_integrity");
    reg.bind(PassId("p3".into()), "liveness/scheduler_progress");
    let safety = reg.bindings_in_category(ObligationCategory::Safety);
    assert_eq!(safety.len(), 2);
    let liveness = reg.bindings_in_category(ObligationCategory::Liveness);
    assert_eq!(liveness.len(), 1);
}

#[test]
fn registry_template_lookup() {
    let reg = ObligationRegistry::new(epoch(1));
    let t = reg.template("safety/ifc_label_propagation");
    assert!(t.is_some());
    assert_eq!(t.unwrap().category, ObligationCategory::Safety);
}

#[test]
fn registry_template_lookup_missing() {
    let reg = ObligationRegistry::new(epoch(1));
    assert!(reg.template("nonexistent").is_none());
}

// ===========================================================================
// Serde enrichment
// ===========================================================================

#[test]
fn obligation_report_serde_roundtrip() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "safety/hash_chain_integrity").unwrap();
    reg.evaluate(&obl_id, ObligationStatus::Satisfied, None, "ok");
    let report = reg.report();
    let json = serde_json::to_string(&report).expect("serialize");
    let restored: ObligationReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, restored);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn registry_deterministic_obligation_ids() {
    let run = || {
        let mut reg = ObligationRegistry::new(epoch(1));
        let id1 = reg.bind(PassId("p1".into()), "safety/ifc_label_propagation").unwrap();
        let id2 = reg.bind(PassId("p2".into()), "safety/hash_chain_integrity").unwrap();
        (id1, id2)
    };
    let (a1, a2) = run();
    let (b1, b2) = run();
    assert_eq!(a1, b1);
    assert_eq!(a2, b2);
}

#[test]
fn auto_evaluate_calibration_coverage_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "calibration/conformal_coverage").unwrap();
    let status = reg.auto_evaluate(&obl_id, 950_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_calibration_coverage_fail() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg.bind(PassId("p".into()), "calibration/conformal_coverage").unwrap();
    let status = reg.auto_evaluate(&obl_id, 800_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}
