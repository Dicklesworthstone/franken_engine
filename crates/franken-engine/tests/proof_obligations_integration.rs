#![forbid(unsafe_code)]
//! Integration tests for the `proof_obligations` module.
//!
//! Exercises the public API of the proof obligations library and contract
//! compiler from outside the crate boundary, covering:
//!   - ObligationId, PassId constructors, Display, Ord, serde
//!   - ObligationCategory enum (ALL, Display, Ord, serde)
//!   - ObligationSeverity enum (Display, Ord, serde)
//!   - ObligationStatus enum (Display, Ord, serde)
//!   - EvidenceRequirement all nine variants (serde roundtrips)
//!   - ObligationTemplate struct + serde
//!   - builtin_templates() factory
//!   - ObligationBinding struct + serde
//!   - ObligationEvaluation struct + serde
//!   - ObligationReport::from_evaluations() logic (gate_pass, counts)
//!   - ObligationRegistry: new, empty, register_template, bind, evaluate,
//!     auto_evaluate, waive, report, bindings_for_pass, bindings_in_category,
//!     template_count, binding_count, evaluation_count, template()

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

use frankenengine_engine::proof_obligations::{
    EvidenceRequirement, ObligationBinding, ObligationCategory, ObligationEvaluation, ObligationId,
    ObligationRegistry, ObligationReport, ObligationSeverity, ObligationStatus, ObligationTemplate,
    PassId, builtin_templates,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_custom_template(id: &str, cat: ObligationCategory, waivable: bool) -> ObligationTemplate {
    ObligationTemplate {
        template_id: id.into(),
        category: cat,
        severity: ObligationSeverity::Error,
        description: format!("Custom template {id}"),
        evidence: EvidenceRequirement::OperatorReview,
        waivable,
    }
}

// ===========================================================================
// 1. ObligationId
// ===========================================================================

#[test]
fn obligation_id_display() {
    let id = ObligationId("obl-42".into());
    assert_eq!(format!("{id}"), "obl-42");
}

#[test]
fn obligation_id_clone_eq() {
    let a = ObligationId("obl-1".into());
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn obligation_id_ord_is_lexicographic() {
    let a = ObligationId("obl-10".into());
    let b = ObligationId("obl-2".into());
    // lexicographic: '1' < '2' so "obl-10" < "obl-2"
    assert!(a < b);
}

#[test]
fn obligation_id_serde_roundtrip() {
    let id = ObligationId("obl-99".into());
    let json = serde_json::to_string(&id).unwrap();
    let back: ObligationId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn obligation_id_hash_consistency() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(ObligationId("a".into()));
    set.insert(ObligationId("b".into()));
    set.insert(ObligationId("a".into())); // duplicate
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// 2. PassId
// ===========================================================================

#[test]
fn pass_id_display() {
    let p = PassId("ir_lowering".into());
    assert_eq!(p.to_string(), "ir_lowering");
}

#[test]
fn pass_id_serde_roundtrip() {
    let p = PassId("scheduler_pass".into());
    let json = serde_json::to_string(&p).unwrap();
    let back: PassId = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn pass_id_ord() {
    let a = PassId("alpha".into());
    let b = PassId("beta".into());
    assert!(a < b);
}

// ===========================================================================
// 3. ObligationCategory
// ===========================================================================

#[test]
fn category_all_has_five_elements() {
    assert_eq!(ObligationCategory::ALL.len(), 5);
}

#[test]
fn category_all_display_values() {
    let expected = [
        "behavioral_preservation",
        "safety",
        "liveness",
        "calibration_validity",
        "tail_risk",
    ];
    for (cat, exp) in ObligationCategory::ALL.iter().zip(expected.iter()) {
        assert_eq!(cat.to_string(), *exp);
    }
}

#[test]
fn category_display_unique() {
    let mut displays = BTreeSet::new();
    for cat in &ObligationCategory::ALL {
        assert!(displays.insert(cat.to_string()));
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn category_serde_roundtrip() {
    for cat in &ObligationCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ObligationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn category_ordering_chain() {
    assert!(ObligationCategory::BehavioralPreservation < ObligationCategory::Safety);
    assert!(ObligationCategory::Safety < ObligationCategory::Liveness);
    assert!(ObligationCategory::Liveness < ObligationCategory::CalibrationValidity);
    assert!(ObligationCategory::CalibrationValidity < ObligationCategory::TailRisk);
}

// ===========================================================================
// 4. ObligationSeverity
// ===========================================================================

#[test]
fn severity_display_values() {
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
fn severity_serde_roundtrip() {
    let variants = [
        ObligationSeverity::Info,
        ObligationSeverity::Warning,
        ObligationSeverity::Error,
        ObligationSeverity::Fatal,
    ];
    for s in &variants {
        let json = serde_json::to_string(s).unwrap();
        let back: ObligationSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ===========================================================================
// 5. ObligationStatus
// ===========================================================================

#[test]
fn status_display_all_six() {
    let expected = [
        (ObligationStatus::Pending, "pending"),
        (ObligationStatus::InProgress, "in_progress"),
        (ObligationStatus::Satisfied, "satisfied"),
        (ObligationStatus::Violated, "violated"),
        (ObligationStatus::Waived, "waived"),
        (
            ObligationStatus::InsufficientEvidence,
            "insufficient_evidence",
        ),
    ];
    for (status, exp) in &expected {
        assert_eq!(status.to_string(), *exp);
    }
}

#[test]
fn status_display_unique() {
    let statuses = [
        ObligationStatus::Pending,
        ObligationStatus::InProgress,
        ObligationStatus::Satisfied,
        ObligationStatus::Violated,
        ObligationStatus::Waived,
        ObligationStatus::InsufficientEvidence,
    ];
    let mut displays = BTreeSet::new();
    for s in &statuses {
        displays.insert(s.to_string());
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn status_serde_roundtrip() {
    let statuses = [
        ObligationStatus::Pending,
        ObligationStatus::InProgress,
        ObligationStatus::Satisfied,
        ObligationStatus::Violated,
        ObligationStatus::Waived,
        ObligationStatus::InsufficientEvidence,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: ObligationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn status_ordering_pending_before_satisfied() {
    assert!(ObligationStatus::Pending < ObligationStatus::Satisfied);
}

// ===========================================================================
// 6. EvidenceRequirement -- all nine variants
// ===========================================================================

#[test]
fn evidence_requirement_all_variants_serde() {
    let variants = vec![
        EvidenceRequirement::DifferentialTest {
            min_pass_rate_millionths: 999_000,
            min_test_count: 1000,
        },
        EvidenceRequirement::StatisticalTest {
            confidence_level_millionths: 950_000,
            min_samples: 100,
        },
        EvidenceRequirement::FormalProof {
            proof_system: "lean4".into(),
        },
        EvidenceRequirement::HashLinkage,
        EvidenceRequirement::PlasWitness,
        EvidenceRequirement::EProcessGuardrail {
            guardrail_id: "grd-7".into(),
        },
        EvidenceRequirement::CvarBound {
            max_cvar_millionths: 50 * MILLION,
            alpha_millionths: 950_000,
        },
        EvidenceRequirement::CalibrationCoverage {
            min_coverage_millionths: 900_000,
        },
        EvidenceRequirement::OperatorReview,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EvidenceRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// 7. ObligationTemplate
// ===========================================================================

#[test]
fn obligation_template_serde_roundtrip() {
    let t = ObligationTemplate {
        template_id: "custom/integ".into(),
        category: ObligationCategory::Liveness,
        severity: ObligationSeverity::Warning,
        description: "Integration test template".into(),
        evidence: EvidenceRequirement::StatisticalTest {
            confidence_level_millionths: 990_000,
            min_samples: 500,
        },
        waivable: true,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ObligationTemplate = serde_json::from_str(&json).unwrap();
    assert_eq!(t.template_id, back.template_id);
    assert_eq!(t.category, back.category);
    assert_eq!(t.severity, back.severity);
    assert_eq!(t.waivable, back.waivable);
    assert_eq!(t.evidence, back.evidence);
}

// ===========================================================================
// 8. builtin_templates()
// ===========================================================================

#[test]
fn builtin_templates_at_least_fifteen() {
    let templates = builtin_templates();
    assert!(templates.len() >= 15);
}

#[test]
fn builtin_templates_cover_all_five_categories() {
    let templates = builtin_templates();
    for cat in &ObligationCategory::ALL {
        let count = templates.iter().filter(|t| t.category == *cat).count();
        assert!(count >= 2, "category {} has only {} templates", cat, count);
    }
}

#[test]
fn builtin_templates_unique_ids() {
    let templates = builtin_templates();
    let mut seen = BTreeSet::new();
    for t in &templates {
        assert!(
            seen.insert(t.template_id.clone()),
            "duplicate template_id: {}",
            t.template_id
        );
    }
}

#[test]
fn builtin_templates_serde_roundtrip() {
    let templates = builtin_templates();
    let json = serde_json::to_string(&templates).unwrap();
    let back: Vec<ObligationTemplate> = serde_json::from_str(&json).unwrap();
    assert_eq!(templates.len(), back.len());
}

#[test]
fn builtin_templates_no_waivable_fatal_safety() {
    // Fatal safety obligations should NOT be waivable
    let templates = builtin_templates();
    for t in &templates {
        if t.severity == ObligationSeverity::Fatal && t.category == ObligationCategory::Safety {
            assert!(
                !t.waivable,
                "Fatal safety template '{}' should not be waivable",
                t.template_id
            );
        }
    }
}

// ===========================================================================
// 9. ObligationBinding
// ===========================================================================

#[test]
fn obligation_binding_serde_roundtrip() {
    let binding = ObligationBinding {
        pass_id: PassId("ir_transform".into()),
        obligation_id: ObligationId("obl-1".into()),
        template_id: "behavioral/ir_transform_equivalence".into(),
        category: ObligationCategory::BehavioralPreservation,
        severity: ObligationSeverity::Fatal,
        evidence: EvidenceRequirement::DifferentialTest {
            min_pass_rate_millionths: 999_000,
            min_test_count: 1000,
        },
    };
    let json = serde_json::to_string(&binding).unwrap();
    let back: ObligationBinding = serde_json::from_str(&json).unwrap();
    assert_eq!(binding, back);
}

// ===========================================================================
// 10. ObligationEvaluation
// ===========================================================================

#[test]
fn obligation_evaluation_serde_roundtrip() {
    let eval = ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "safety/test".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Fatal,
        status: ObligationStatus::Violated,
        epoch: epoch(42),
        observed_value: Some(500_000),
        required_value: Some(999_000),
        reason: "insufficient pass rate".into(),
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ObligationEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

#[test]
fn obligation_evaluation_with_none_values() {
    let eval = ObligationEvaluation {
        obligation_id: ObligationId("obl-2".into()),
        template_id: "liveness/test".into(),
        category: ObligationCategory::Liveness,
        severity: ObligationSeverity::Warning,
        status: ObligationStatus::Pending,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "not yet evaluated".into(),
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ObligationEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ===========================================================================
// 11. ObligationReport::from_evaluations
// ===========================================================================

#[test]
fn report_empty_evaluations_gate_passes() {
    let report = ObligationReport::from_evaluations(epoch(1), vec![]);
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 0);
    assert_eq!(report.violated_count, 0);
    assert_eq!(report.pending_count, 0);
    assert_eq!(report.waived_count, 0);
    assert_eq!(report.insufficient_count, 0);
}

#[test]
fn report_all_satisfied_gate_passes() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "t".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Satisfied,
            epoch: epoch(1),
            observed_value: Some(MILLION),
            required_value: Some(999_000),
            reason: "ok".into(),
        },
        ObligationEvaluation {
            obligation_id: ObligationId("obl-2".into()),
            template_id: "t2".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Error,
            status: ObligationStatus::Satisfied,
            epoch: epoch(1),
            observed_value: Some(995_000),
            required_value: Some(990_000),
            reason: "ok".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 2);
}

#[test]
fn report_fatal_violation_blocks_gate() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
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

#[test]
fn report_non_fatal_violation_still_blocks_gate() {
    // Any violated_count > 0 blocks the gate, not just fatal
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::Liveness,
        severity: ObligationSeverity::Warning,
        status: ObligationStatus::Violated,
        epoch: epoch(1),
        observed_value: Some(0),
        required_value: Some(990_000),
        reason: "failed".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
}

#[test]
fn report_pending_blocks_gate() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Info,
        status: ObligationStatus::Pending,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "not yet".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(!report.gate_pass);
    assert_eq!(report.pending_count, 1);
}

#[test]
fn report_in_progress_counts_as_pending() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Error,
        status: ObligationStatus::InProgress,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "running".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert_eq!(report.pending_count, 1);
    assert!(!report.gate_pass);
}

#[test]
fn report_waived_does_not_block_gate() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::TailRisk,
        severity: ObligationSeverity::Warning,
        status: ObligationStatus::Waived,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "operator approved".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(report.gate_pass);
    assert_eq!(report.waived_count, 1);
}

#[test]
fn report_insufficient_evidence_does_not_block_gate() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::CalibrationValidity,
        severity: ObligationSeverity::Error,
        status: ObligationStatus::InsufficientEvidence,
        epoch: epoch(1),
        observed_value: None,
        required_value: None,
        reason: "not enough data".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(report.gate_pass);
    assert_eq!(report.insufficient_count, 1);
}

#[test]
fn report_mixed_statuses_counts() {
    let evals = vec![
        ObligationEvaluation {
            obligation_id: ObligationId("obl-1".into()),
            template_id: "t1".into(),
            category: ObligationCategory::Safety,
            severity: ObligationSeverity::Fatal,
            status: ObligationStatus::Satisfied,
            epoch: epoch(1),
            observed_value: Some(MILLION),
            required_value: Some(999_000),
            reason: "ok".into(),
        },
        ObligationEvaluation {
            obligation_id: ObligationId("obl-2".into()),
            template_id: "t2".into(),
            category: ObligationCategory::Liveness,
            severity: ObligationSeverity::Error,
            status: ObligationStatus::Waived,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "waived".into(),
        },
        ObligationEvaluation {
            obligation_id: ObligationId("obl-3".into()),
            template_id: "t3".into(),
            category: ObligationCategory::TailRisk,
            severity: ObligationSeverity::Warning,
            status: ObligationStatus::InsufficientEvidence,
            epoch: epoch(1),
            observed_value: None,
            required_value: None,
            reason: "not enough data".into(),
        },
    ];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 1);
    assert_eq!(report.waived_count, 1);
    assert_eq!(report.insufficient_count, 1);
    assert_eq!(report.violated_count, 0);
    assert_eq!(report.pending_count, 0);
}

#[test]
fn report_serde_roundtrip() {
    let evals = vec![ObligationEvaluation {
        obligation_id: ObligationId("obl-1".into()),
        template_id: "t".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Fatal,
        status: ObligationStatus::Satisfied,
        epoch: epoch(1),
        observed_value: Some(MILLION),
        required_value: Some(999_000),
        reason: "ok".into(),
    }];
    let report = ObligationReport::from_evaluations(epoch(1), evals);
    let json = serde_json::to_string(&report).unwrap();
    let back: ObligationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// 12. ObligationRegistry::new / empty
// ===========================================================================

#[test]
fn registry_new_has_builtin_templates() {
    let reg = ObligationRegistry::new(epoch(1));
    assert!(reg.template_count() >= 15);
    assert_eq!(reg.binding_count(), 0);
    assert_eq!(reg.evaluation_count(), 0);
}

#[test]
fn registry_empty_has_no_templates() {
    let reg = ObligationRegistry::empty(epoch(1));
    assert_eq!(reg.template_count(), 0);
    assert_eq!(reg.binding_count(), 0);
}

// ===========================================================================
// 13. register_template
// ===========================================================================

#[test]
fn registry_register_custom_template() {
    let mut reg = ObligationRegistry::empty(epoch(1));
    let t = make_custom_template("custom/test", ObligationCategory::Safety, true);
    reg.register_template(t);
    assert_eq!(reg.template_count(), 1);
    assert!(reg.template("custom/test").is_some());
}

#[test]
fn registry_register_replaces_existing() {
    let mut reg = ObligationRegistry::empty(epoch(1));
    let t1 = make_custom_template("custom/x", ObligationCategory::Safety, false);
    reg.register_template(t1);
    let t2 = make_custom_template("custom/x", ObligationCategory::Liveness, true);
    reg.register_template(t2);
    assert_eq!(reg.template_count(), 1);
    let fetched = reg.template("custom/x").unwrap();
    assert_eq!(fetched.category, ObligationCategory::Liveness);
}

// ===========================================================================
// 14. bind
// ===========================================================================

#[test]
fn registry_bind_creates_obligation_with_sequential_ids() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let id1 = reg
        .bind(PassId("p1".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let id2 = reg
        .bind(PassId("p2".into()), "behavioral/render_output_stability")
        .unwrap();
    assert_eq!(id1.0, "obl-1");
    assert_eq!(id2.0, "obl-2");
    assert_eq!(reg.binding_count(), 2);
}

#[test]
fn registry_bind_unknown_template_returns_none() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let result = reg.bind(PassId("p".into()), "nonexistent/template");
    assert!(result.is_none());
    assert_eq!(reg.binding_count(), 0);
}

#[test]
fn registry_bind_denormalized_fields_match_template() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let _obl_id = reg
        .bind(PassId("pass".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let template = reg.template("behavioral/ir_transform_equivalence").unwrap();
    let bindings = reg.bindings_for_pass(&PassId("pass".into()));
    assert_eq!(bindings.len(), 1);
    let b = &bindings[0];
    assert_eq!(b.category, template.category);
    assert_eq!(b.severity, template.severity);
    assert_eq!(b.evidence, template.evidence);
    assert_eq!(b.template_id, template.template_id);
}

#[test]
fn registry_multiple_bindings_per_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let pass = PassId("compiler".into());
    reg.bind(pass.clone(), "behavioral/ir_transform_equivalence");
    reg.bind(pass.clone(), "safety/hash_chain_integrity");
    reg.bind(pass.clone(), "liveness/scheduler_progress");
    let bindings = reg.bindings_for_pass(&pass);
    assert_eq!(bindings.len(), 3);
}

// ===========================================================================
// 15. evaluate (manual)
// ===========================================================================

#[test]
fn registry_evaluate_manual_satisfied() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("p".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let ok = reg.evaluate(
        &obl_id,
        ObligationStatus::Satisfied,
        Some(999_500),
        "all tests pass",
    );
    assert!(ok);
    assert_eq!(reg.evaluation_count(), 1);
}

#[test]
fn registry_evaluate_nonexistent_returns_false() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let ok = reg.evaluate(
        &ObligationId("nonexistent".into()),
        ObligationStatus::Satisfied,
        None,
        "test",
    );
    assert!(!ok);
    assert_eq!(reg.evaluation_count(), 0);
}

// ===========================================================================
// 16. auto_evaluate -- DifferentialTest
// ===========================================================================

#[test]
fn auto_evaluate_differential_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("t".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 999_500, 2000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_differential_exact_boundary() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("t".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    // min_pass_rate_millionths = 999_000, min_test_count = 1000
    let status = reg.auto_evaluate(&obl_id, 999_000, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_differential_just_below() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("t".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 998_999, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

#[test]
fn auto_evaluate_differential_insufficient_samples() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("t".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, MILLION, 999).unwrap();
    assert_eq!(status, ObligationStatus::InsufficientEvidence);
}

// ===========================================================================
// 17. auto_evaluate -- StatisticalTest
// ===========================================================================

#[test]
fn auto_evaluate_statistical_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("sched".into()), "liveness/scheduler_progress")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 995_000, 2000).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_statistical_insufficient() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("sched".into()), "liveness/scheduler_progress")
        .unwrap();
    // min_samples = 1000 for scheduler_progress
    let status = reg.auto_evaluate(&obl_id, 995_000, 5).unwrap();
    assert_eq!(status, ObligationStatus::InsufficientEvidence);
}

#[test]
fn auto_evaluate_statistical_violated() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("sched".into()), "liveness/scheduler_progress")
        .unwrap();
    // confidence_level_millionths = 990_000
    let status = reg.auto_evaluate(&obl_id, 500_000, 2000).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

// ===========================================================================
// 18. auto_evaluate -- CvarBound
// ===========================================================================

#[test]
fn auto_evaluate_cvar_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 30 * MILLION, 100).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_cvar_exact_boundary() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();
    // max_cvar_millionths = 50 * MILLION
    let status = reg.auto_evaluate(&obl_id, 50 * MILLION, 100).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_cvar_violated() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 100 * MILLION, 100).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

// ===========================================================================
// 19. auto_evaluate -- CalibrationCoverage
// ===========================================================================

#[test]
fn auto_evaluate_calibration_pass() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cal".into()), "calibration/conformal_coverage")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, 950_000, 100).unwrap();
    assert_eq!(status, ObligationStatus::Satisfied);
}

#[test]
fn auto_evaluate_calibration_violated() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cal".into()), "calibration/conformal_coverage")
        .unwrap();
    // min_coverage_millionths = 900_000
    let status = reg.auto_evaluate(&obl_id, 800_000, 100).unwrap();
    assert_eq!(status, ObligationStatus::Violated);
}

// ===========================================================================
// 20. auto_evaluate -- unsupported evidence types => Pending
// ===========================================================================

#[test]
fn auto_evaluate_hash_linkage_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("prover".into()), "safety/hash_chain_integrity")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, MILLION, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

#[test]
fn auto_evaluate_formal_proof_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("prover".into()), "safety/ifc_label_propagation")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, MILLION, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

#[test]
fn auto_evaluate_plas_witness_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("cap".into()), "safety/capability_authority_bound")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, MILLION, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

#[test]
fn auto_evaluate_eprocess_guardrail_returns_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("ep".into()), "calibration/eprocess_integrity")
        .unwrap();
    let status = reg.auto_evaluate(&obl_id, MILLION, 1000).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}

#[test]
fn auto_evaluate_nonexistent_returns_none() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let result = reg.auto_evaluate(&ObligationId("nope".into()), 0, 0);
    assert!(result.is_none());
}

// ===========================================================================
// 21. waive
// ===========================================================================

#[test]
fn waive_waivable_obligation_succeeds() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
        .unwrap();
    assert!(reg.waive(&obl_id, "operator approved"));
    assert_eq!(reg.evaluation_count(), 1);
}

#[test]
fn waive_non_waivable_obligation_fails() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("safety".into()), "safety/ifc_label_propagation")
        .unwrap();
    assert!(!reg.waive(&obl_id, "trying to waive"));
    assert_eq!(reg.evaluation_count(), 0);
}

#[test]
fn waive_nonexistent_obligation_returns_false() {
    let mut reg = ObligationRegistry::new(epoch(1));
    assert!(!reg.waive(&ObligationId("nope".into()), "test"));
}

// ===========================================================================
// 22. report (via registry)
// ===========================================================================

#[test]
fn report_empty_registry_gate_passes() {
    let reg = ObligationRegistry::new(epoch(1));
    let report = reg.report();
    assert!(report.gate_pass);
    assert_eq!(report.evaluations.len(), 0);
}

#[test]
fn report_unevaluated_binding_is_pending() {
    let mut reg = ObligationRegistry::new(epoch(1));
    reg.bind(PassId("p".into()), "behavioral/ir_transform_equivalence");
    let report = reg.report();
    assert!(!report.gate_pass);
    assert_eq!(report.pending_count, 1);
    assert_eq!(report.evaluations.len(), 1);
    assert_eq!(report.evaluations[0].status, ObligationStatus::Pending);
}

#[test]
fn report_all_satisfied_gate_passes_via_registry() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("p".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    reg.auto_evaluate(&obl_id, 999_500, 2000);
    let report = reg.report();
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 1);
}

#[test]
fn report_waived_via_registry() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
        .unwrap();
    reg.waive(&obl_id, "approved");
    let report = reg.report();
    assert!(report.gate_pass);
    assert_eq!(report.waived_count, 1);
}

// ===========================================================================
// 23. bindings_for_pass / bindings_in_category
// ===========================================================================

#[test]
fn bindings_for_pass_returns_empty_for_unknown() {
    let reg = ObligationRegistry::new(epoch(1));
    let b = reg.bindings_for_pass(&PassId("unknown".into()));
    assert!(b.is_empty());
}

#[test]
fn bindings_in_category_filters_correctly() {
    let mut reg = ObligationRegistry::new(epoch(1));
    reg.bind(PassId("a".into()), "behavioral/ir_transform_equivalence");
    reg.bind(PassId("b".into()), "behavioral/render_output_stability");
    reg.bind(PassId("c".into()), "safety/ifc_label_propagation");
    let behavioral = reg.bindings_in_category(ObligationCategory::BehavioralPreservation);
    assert_eq!(behavioral.len(), 2);
    let safety = reg.bindings_in_category(ObligationCategory::Safety);
    assert_eq!(safety.len(), 1);
    let liveness = reg.bindings_in_category(ObligationCategory::Liveness);
    assert!(liveness.is_empty());
}

// ===========================================================================
// 24. template()
// ===========================================================================

#[test]
fn template_returns_none_for_unknown() {
    let reg = ObligationRegistry::new(epoch(1));
    assert!(reg.template("nonexistent/template").is_none());
}

#[test]
fn template_returns_some_for_builtin() {
    let reg = ObligationRegistry::new(epoch(1));
    let t = reg.template("behavioral/ir_transform_equivalence");
    assert!(t.is_some());
    let t = t.unwrap();
    assert_eq!(t.category, ObligationCategory::BehavioralPreservation);
    assert_eq!(t.severity, ObligationSeverity::Fatal);
}

// ===========================================================================
// 25. Registry serde roundtrip
// ===========================================================================

#[test]
fn registry_serde_roundtrip() {
    let mut reg = ObligationRegistry::new(epoch(1));
    let obl_id = reg
        .bind(PassId("p".into()), "behavioral/ir_transform_equivalence")
        .unwrap();
    reg.auto_evaluate(&obl_id, MILLION, 10_000);
    let json = serde_json::to_string(&reg).unwrap();
    let back: ObligationRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.template_count(), reg.template_count());
    assert_eq!(back.binding_count(), reg.binding_count());
    assert_eq!(back.evaluation_count(), reg.evaluation_count());
}

// ===========================================================================
// 26. End-to-end scenario: multi-pass pipeline
// ===========================================================================

#[test]
fn e2e_multi_pass_pipeline() {
    let mut reg = ObligationRegistry::new(epoch(5));

    // Bind multiple passes to obligations
    let ir_obl = reg
        .bind(
            PassId("ir_transform".into()),
            "behavioral/ir_transform_equivalence",
        )
        .unwrap();
    let render_obl = reg
        .bind(
            PassId("renderer".into()),
            "behavioral/render_output_stability",
        )
        .unwrap();
    let safety_obl = reg
        .bind(PassId("prover".into()), "safety/ifc_label_propagation")
        .unwrap();
    let liveness_obl = reg
        .bind(PassId("scheduler".into()), "liveness/scheduler_progress")
        .unwrap();
    let cvar_obl = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();

    assert_eq!(reg.binding_count(), 5);

    // Auto-evaluate quantitative obligations
    assert_eq!(
        reg.auto_evaluate(&ir_obl, 999_500, 2000).unwrap(),
        ObligationStatus::Satisfied
    );
    assert_eq!(
        reg.auto_evaluate(&render_obl, MILLION, 200).unwrap(),
        ObligationStatus::Satisfied
    );
    assert_eq!(
        reg.auto_evaluate(&liveness_obl, 995_000, 2000).unwrap(),
        ObligationStatus::Satisfied
    );
    assert_eq!(
        reg.auto_evaluate(&cvar_obl, 30 * MILLION, 100).unwrap(),
        ObligationStatus::Satisfied
    );

    // Formal proof: manual evaluation
    reg.evaluate(
        &safety_obl,
        ObligationStatus::Satisfied,
        None,
        "formal proof verified in flow_lattice",
    );

    let report = reg.report();
    assert!(report.gate_pass);
    assert_eq!(report.satisfied_count, 5);
    assert_eq!(report.violated_count, 0);
    assert_eq!(report.pending_count, 0);
    assert_eq!(report.epoch, epoch(5));
}

#[test]
fn e2e_mixed_outcome_pipeline() {
    let mut reg = ObligationRegistry::new(epoch(10));

    let ir_obl = reg
        .bind(
            PassId("ir_transform".into()),
            "behavioral/ir_transform_equivalence",
        )
        .unwrap();
    let timing_obl = reg
        .bind(PassId("timing".into()), "behavioral/effect_timing_contract")
        .unwrap();
    let cvar_obl = reg
        .bind(PassId("router".into()), "tail_risk/cvar_latency_bound")
        .unwrap();

    // IR transform passes
    reg.auto_evaluate(&ir_obl, 999_500, 2000);
    // Timing waived by operator
    reg.waive(&timing_obl, "known flaky, operator approved");
    // CVaR violated
    reg.auto_evaluate(&cvar_obl, 100 * MILLION, 500);

    let report = reg.report();
    assert!(!report.gate_pass);
    assert_eq!(report.satisfied_count, 1);
    assert_eq!(report.waived_count, 1);
    assert_eq!(report.violated_count, 1);
}

// ===========================================================================
// 27. Custom template with operator review
// ===========================================================================

#[test]
fn custom_template_operator_review_auto_evaluate_pending() {
    let mut reg = ObligationRegistry::empty(epoch(1));
    reg.register_template(ObligationTemplate {
        template_id: "custom/review".into(),
        category: ObligationCategory::Safety,
        severity: ObligationSeverity::Warning,
        description: "Requires operator review".into(),
        evidence: EvidenceRequirement::OperatorReview,
        waivable: true,
    });
    let obl_id = reg.bind(PassId("review".into()), "custom/review").unwrap();
    let status = reg.auto_evaluate(&obl_id, 0, 0).unwrap();
    assert_eq!(status, ObligationStatus::Pending);
}
