//! Enrichment integration tests for `security_conformance`.
//!
//! Supplements base tests with deeper coverage of: Clopper-Pearson boundary
//! conditions, gate failure reason specificity, latency p95 edge cases,
//! default_observation_from_label for all outcomes, error Display coverage,
//! evaluation with mixed outcomes, observation validation edges, and
//! SecurityConformanceSummary field verification.

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
use std::path::PathBuf;

use frankenengine_engine::security_conformance::{
    BinomialConfidenceInterval, SecurityAttackTaxonomy, SecurityConformanceError,
    SecurityConformanceThresholds, SecurityCorpus, SecurityOutcome, SecurityWorkloadLabel,
    SecurityWorkloadLabelRecord, SecurityWorkloadObservation, clopper_pearson_interval,
    corpus_manifest_hash, default_observation_from_label, evaluate_security_conformance,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn benign_label(id: &str) -> SecurityWorkloadLabel {
    SecurityWorkloadLabel {
        workload_id: id.into(),
        corpus: SecurityCorpus::Benign,
        attack_taxonomy: None,
        expected_outcome: SecurityOutcome::Allow,
        expected_detection_latency_bound_ms: 10,
        hostcall_sequence_hash: hex64('a'),
        semantic_domain: "security/benign".into(),
    }
}

fn malicious_label(id: &str, taxonomy: SecurityAttackTaxonomy) -> SecurityWorkloadLabel {
    SecurityWorkloadLabel {
        workload_id: id.into(),
        corpus: SecurityCorpus::Malicious,
        attack_taxonomy: Some(taxonomy),
        expected_outcome: SecurityOutcome::Contain,
        expected_detection_latency_bound_ms: 50,
        hostcall_sequence_hash: hex64('b'),
        semantic_domain: "security/malicious".into(),
    }
}

fn malicious_label_outcome(
    id: &str,
    taxonomy: SecurityAttackTaxonomy,
    outcome: SecurityOutcome,
) -> SecurityWorkloadLabel {
    SecurityWorkloadLabel {
        workload_id: id.into(),
        corpus: SecurityCorpus::Malicious,
        attack_taxonomy: Some(taxonomy),
        expected_outcome: outcome,
        expected_detection_latency_bound_ms: 50,
        hostcall_sequence_hash: hex64('b'),
        semantic_domain: "security/malicious".into(),
    }
}

fn label_record(label: SecurityWorkloadLabel) -> SecurityWorkloadLabelRecord {
    SecurityWorkloadLabelRecord {
        label_hash: hex64('c'),
        label_path: PathBuf::from(format!("{}/workload_label.toml", label.workload_id)),
        label,
    }
}

fn benign_observation(id: &str) -> SecurityWorkloadObservation {
    SecurityWorkloadObservation {
        workload_id: id.into(),
        actual_outcome: SecurityOutcome::Allow,
        detection_latency_us: 5_000,
        sentinel_posterior: 0.05,
        policy_action: "allow".into(),
        containment_action: "none".into(),
        error_code: None,
    }
}

fn malicious_observation(id: &str) -> SecurityWorkloadObservation {
    SecurityWorkloadObservation {
        workload_id: id.into(),
        actual_outcome: SecurityOutcome::Contain,
        detection_latency_us: 20_000,
        sentinel_posterior: 0.99,
        policy_action: "contain".into(),
        containment_action: "sandbox".into(),
        error_code: None,
    }
}

fn relaxed_thresholds() -> SecurityConformanceThresholds {
    SecurityConformanceThresholds {
        tpr_min: "0.100000".into(),
        fpr_max: "0.900000".into(),
        ..SecurityConformanceThresholds::default()
    }
}

// ===========================================================================
// A. Clopper-Pearson boundary conditions (6 tests)
// ===========================================================================

#[test]
fn enrichment_clopper_pearson_single_success_single_total() {
    let ci = clopper_pearson_interval(1, 1, 0.95).unwrap();
    assert_eq!(ci.upper_millionths, 1_000_000);
    assert!(ci.lower_millionths > 0, "lower should be > 0 with 1/1");
}

#[test]
fn enrichment_clopper_pearson_confidence_90_vs_95() {
    let ci_90 = clopper_pearson_interval(50, 100, 0.90).unwrap();
    let ci_95 = clopper_pearson_interval(50, 100, 0.95).unwrap();
    assert!(ci_95.lower_millionths <= ci_90.lower_millionths);
    assert!(ci_95.upper_millionths >= ci_90.upper_millionths);
}

#[test]
fn enrichment_clopper_pearson_invalid_confidence_fails() {
    let result = clopper_pearson_interval(5, 10, 1.0);
    assert!(result.is_err());
}

#[test]
fn enrichment_clopper_pearson_negative_confidence_fails() {
    let result = clopper_pearson_interval(5, 10, -0.1);
    assert!(result.is_err());
}

#[test]
fn enrichment_clopper_pearson_large_sample_tight_ci() {
    let ci = clopper_pearson_interval(950, 1000, 0.95).unwrap();
    assert!(
        ci.lower_millionths > 920_000,
        "lower={}",
        ci.lower_millionths
    );
    assert!(
        ci.upper_millionths < 980_000,
        "upper={}",
        ci.upper_millionths
    );
}

#[test]
fn enrichment_clopper_pearson_interval_lower_le_upper() {
    for successes in [0, 1, 5, 10, 50, 99, 100] {
        let ci = clopper_pearson_interval(successes, 100, 0.95).unwrap();
        assert!(ci.lower_millionths <= ci.upper_millionths);
    }
}

// ===========================================================================
// B. Gate failure reason specificity (5 tests)
// ===========================================================================

#[test]
fn enrichment_gate_failure_mentions_tpr() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        SecurityWorkloadObservation {
            workload_id: "m-1".into(),
            actual_outcome: SecurityOutcome::Allow,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.05,
            policy_action: "allow".into(),
            containment_action: "none".into(),
            error_code: None,
        },
    ];
    let eval = evaluate_security_conformance(
        &records,
        &observations,
        &SecurityConformanceThresholds::default(),
    )
    .unwrap();
    assert!(!eval.summary.gate_pass);
    assert!(
        eval.summary
            .gate_failure_reasons
            .iter()
            .any(|r| r.contains("TPR"))
    );
}

#[test]
fn enrichment_gate_failure_mentions_fpr() {
    let mut records = Vec::new();
    let mut observations = Vec::new();
    for i in 0..100 {
        let id = format!("b-{i}");
        records.push(label_record(benign_label(&id)));
        observations.push(SecurityWorkloadObservation {
            workload_id: id,
            actual_outcome: SecurityOutcome::Contain,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.7,
            policy_action: "contain".into(),
            containment_action: "sandbox".into(),
            error_code: None,
        });
    }
    let mid = "m-0".to_string();
    records.push(label_record(malicious_label(
        &mid,
        SecurityAttackTaxonomy::Dos,
    )));
    observations.push(malicious_observation(&mid));

    let thresholds = SecurityConformanceThresholds {
        tpr_min: "0.000001".into(),
        ..SecurityConformanceThresholds::default()
    };
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert!(!eval.summary.gate_pass);
    assert!(
        eval.summary
            .gate_failure_reasons
            .iter()
            .any(|r| r.contains("FPR"))
    );
}

#[test]
fn enrichment_gate_failure_mentions_latency() {
    let mut records = Vec::new();
    let mut observations = Vec::new();
    for i in 0..100 {
        let bid = format!("b-{i}");
        records.push(label_record(benign_label(&bid)));
        observations.push(benign_observation(&bid));
    }
    for i in 0..100 {
        let mid = format!("m-{i}");
        records.push(label_record(malicious_label(
            &mid,
            SecurityAttackTaxonomy::Dos,
        )));
        observations.push(SecurityWorkloadObservation {
            workload_id: mid,
            actual_outcome: SecurityOutcome::Contain,
            detection_latency_us: 1_000_000,
            sentinel_posterior: 0.99,
            policy_action: "contain".into(),
            containment_action: "sandbox".into(),
            error_code: None,
        });
    }
    let eval = evaluate_security_conformance(
        &records,
        &observations,
        &SecurityConformanceThresholds::default(),
    )
    .unwrap();
    assert!(!eval.summary.gate_pass);
    assert!(
        eval.summary
            .gate_failure_reasons
            .iter()
            .any(|r| r.contains("latency"))
    );
}

#[test]
fn enrichment_gate_pass_no_failure_reasons() {
    let mut records = Vec::new();
    let mut observations = Vec::new();
    for i in 0..500 {
        let bid = format!("b-{i}");
        records.push(label_record(benign_label(&bid)));
        observations.push(benign_observation(&bid));
    }
    for i in 0..500 {
        let mid = format!("m-{i}");
        let tax = match i % 6 {
            0 => SecurityAttackTaxonomy::Exfil,
            1 => SecurityAttackTaxonomy::Escalation,
            2 => SecurityAttackTaxonomy::Evasion,
            3 => SecurityAttackTaxonomy::Dos,
            4 => SecurityAttackTaxonomy::SideChannel,
            _ => SecurityAttackTaxonomy::Staging,
        };
        records.push(label_record(malicious_label(&mid, tax)));
        observations.push(malicious_observation(&mid));
    }
    let eval = evaluate_security_conformance(
        &records,
        &observations,
        &SecurityConformanceThresholds::default(),
    )
    .unwrap();
    assert!(eval.summary.gate_pass);
    assert!(eval.summary.gate_failure_reasons.is_empty());
}

#[test]
fn enrichment_gate_multiple_failures_accumulated() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![
        SecurityWorkloadObservation {
            workload_id: "b-1".into(),
            actual_outcome: SecurityOutcome::Contain,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.7,
            policy_action: "contain".into(),
            containment_action: "sandbox".into(),
            error_code: None,
        },
        SecurityWorkloadObservation {
            workload_id: "m-1".into(),
            actual_outcome: SecurityOutcome::Allow,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.05,
            policy_action: "allow".into(),
            containment_action: "none".into(),
            error_code: None,
        },
    ];
    let eval = evaluate_security_conformance(
        &records,
        &observations,
        &SecurityConformanceThresholds::default(),
    )
    .unwrap();
    assert!(!eval.summary.gate_pass);
    assert!(eval.summary.gate_failure_reasons.len() >= 2);
}

// ===========================================================================
// C. default_observation_from_label for all outcomes (4 tests)
// ===========================================================================

#[test]
fn enrichment_default_observation_quarantine() {
    let label = malicious_label_outcome(
        "m-1",
        SecurityAttackTaxonomy::Evasion,
        SecurityOutcome::Quarantine,
    );
    let obs = default_observation_from_label(&label);
    assert_eq!(obs.actual_outcome, SecurityOutcome::Quarantine);
    assert_eq!(obs.policy_action, "quarantine");
}

#[test]
fn enrichment_default_observation_terminate() {
    let label = malicious_label_outcome(
        "m-1",
        SecurityAttackTaxonomy::Dos,
        SecurityOutcome::Terminate,
    );
    let obs = default_observation_from_label(&label);
    assert_eq!(obs.actual_outcome, SecurityOutcome::Terminate);
    assert_eq!(obs.policy_action, "terminate");
}

#[test]
fn enrichment_default_observation_latency_under_bound() {
    let label = benign_label("b-1");
    let obs = default_observation_from_label(&label);
    assert!(obs.detection_latency_us < label.expected_detection_latency_bound_ms * 1000);
}

#[test]
fn enrichment_default_observation_validates() {
    let label = benign_label("b-1");
    assert!(default_observation_from_label(&label).validate().is_ok());
    let mlabel = malicious_label("m-1", SecurityAttackTaxonomy::Exfil);
    assert!(default_observation_from_label(&mlabel).validate().is_ok());
}

// ===========================================================================
// D. Error Display coverage (6 tests)
// ===========================================================================

#[test]
fn enrichment_error_display_invalid_label_field() {
    let err = SecurityConformanceError::InvalidLabelField {
        field: "workload_id",
        detail: "must not be empty".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("workload_id"));
}

#[test]
fn enrichment_error_display_invalid_observation_field() {
    let err = SecurityConformanceError::InvalidObservationField {
        field: "policy_action",
        detail: "must not be empty".into(),
    };
    assert!(format!("{err}").contains("policy_action"));
}

#[test]
fn enrichment_error_display_missing_observation() {
    let err = SecurityConformanceError::MissingObservation {
        workload_id: "w-1".into(),
    };
    assert!(format!("{err}").contains("w-1"));
}

#[test]
fn enrichment_error_display_invalid_ratio_config() {
    let err = SecurityConformanceError::InvalidRatioConfig {
        field: "tpr_min",
        value: "bad".into(),
    };
    assert!(format!("{err}").contains("tpr_min"));
}

#[test]
fn enrichment_error_display_binomial_unavailable() {
    let err = SecurityConformanceError::BinomialIntervalUnavailable {
        successes: 10,
        total: 0,
    };
    assert!(format!("{err}").contains("binomial"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err = SecurityConformanceError::EmptyDataset;
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// E. Observation validation edges (4 tests)
// ===========================================================================

#[test]
fn enrichment_observation_posterior_at_zero_valid() {
    let mut obs = benign_observation("b-1");
    obs.sentinel_posterior = 0.0;
    assert!(obs.validate().is_ok());
}

#[test]
fn enrichment_observation_posterior_at_one_valid() {
    let mut obs = benign_observation("b-1");
    obs.sentinel_posterior = 1.0;
    assert!(obs.validate().is_ok());
}

#[test]
fn enrichment_observation_whitespace_policy_action_fails() {
    let mut obs = benign_observation("b-1");
    obs.policy_action = "   ".into();
    assert!(obs.validate().is_err());
}

#[test]
fn enrichment_observation_whitespace_containment_action_fails() {
    let mut obs = benign_observation("b-1");
    obs.containment_action = "  \t  ".into();
    assert!(obs.validate().is_err());
}

// ===========================================================================
// F. Label validation edges (4 tests)
// ===========================================================================

#[test]
fn enrichment_label_whitespace_workload_id_fails() {
    let mut label = benign_label("  ");
    label.workload_id = "  ".into();
    assert!(label.validate().is_err());
}

#[test]
fn enrichment_label_all_taxonomy_variants_valid() {
    for tax in [
        SecurityAttackTaxonomy::Exfil,
        SecurityAttackTaxonomy::Escalation,
        SecurityAttackTaxonomy::Evasion,
        SecurityAttackTaxonomy::Dos,
        SecurityAttackTaxonomy::SideChannel,
        SecurityAttackTaxonomy::Staging,
    ] {
        assert!(malicious_label("m-test", tax).validate().is_ok());
    }
}

#[test]
fn enrichment_label_malicious_all_non_allow_outcomes_valid() {
    for outcome in [
        SecurityOutcome::Contain,
        SecurityOutcome::Quarantine,
        SecurityOutcome::Terminate,
    ] {
        assert!(
            malicious_label_outcome("m-test", SecurityAttackTaxonomy::Dos, outcome)
                .validate()
                .is_ok()
        );
    }
}

#[test]
fn enrichment_label_serde_malicious_roundtrip() {
    let label = malicious_label("m-1", SecurityAttackTaxonomy::SideChannel);
    let json = serde_json::to_string(&label).unwrap();
    let back: SecurityWorkloadLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back.attack_taxonomy,
        Some(SecurityAttackTaxonomy::SideChannel)
    );
}

// ===========================================================================
// G. Evaluation metric correctness (5 tests)
// ===========================================================================

#[test]
fn enrichment_evaluate_tpr_millionths_correct() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
        label_record(malicious_label("m-2", SecurityAttackTaxonomy::Dos)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        malicious_observation("m-1"),
        SecurityWorkloadObservation {
            workload_id: "m-2".into(),
            actual_outcome: SecurityOutcome::Allow,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.05,
            policy_action: "allow".into(),
            containment_action: "none".into(),
            error_code: None,
        },
    ];
    let eval =
        evaluate_security_conformance(&records, &observations, &relaxed_thresholds()).unwrap();
    assert_eq!(eval.summary.tpr_millionths, 500_000);
}

#[test]
fn enrichment_evaluate_fpr_millionths_correct() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(benign_label("b-2")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![
        SecurityWorkloadObservation {
            workload_id: "b-1".into(),
            actual_outcome: SecurityOutcome::Contain,
            detection_latency_us: 5_000,
            sentinel_posterior: 0.7,
            policy_action: "contain".into(),
            containment_action: "sandbox".into(),
            error_code: None,
        },
        benign_observation("b-2"),
        malicious_observation("m-1"),
    ];
    let eval =
        evaluate_security_conformance(&records, &observations, &relaxed_thresholds()).unwrap();
    assert_eq!(eval.summary.fpr_millionths, 500_000);
}

#[test]
fn enrichment_evaluate_corpus_manifest_hash_populated() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![benign_observation("b-1"), malicious_observation("m-1")];
    let eval =
        evaluate_security_conformance(&records, &observations, &relaxed_thresholds()).unwrap();
    assert_eq!(
        eval.summary.corpus_manifest_hash,
        corpus_manifest_hash(&records)
    );
}

#[test]
fn enrichment_evaluate_latency_p95_max_from_thresholds() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![benign_observation("b-1"), malicious_observation("m-1")];
    let thresholds = SecurityConformanceThresholds {
        malicious_latency_p95_max_ms: 500,
        ..relaxed_thresholds()
    };
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert_eq!(eval.summary.malicious_latency_p95_max_us, 500_000);
}

#[test]
fn enrichment_evaluate_observations_by_workload_complete() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(benign_label("b-2")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Staging)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        benign_observation("b-2"),
        malicious_observation("m-1"),
    ];
    let eval =
        evaluate_security_conformance(&records, &observations, &relaxed_thresholds()).unwrap();
    assert_eq!(eval.observations_by_workload.len(), 3);
}

// ===========================================================================
// H. Enum as_str coverage (2 tests)
// ===========================================================================

#[test]
fn enrichment_taxonomy_as_str_all_distinct() {
    let mut strs = BTreeSet::new();
    for tax in [
        SecurityAttackTaxonomy::Exfil,
        SecurityAttackTaxonomy::Escalation,
        SecurityAttackTaxonomy::Evasion,
        SecurityAttackTaxonomy::Dos,
        SecurityAttackTaxonomy::SideChannel,
        SecurityAttackTaxonomy::Staging,
    ] {
        strs.insert(tax.as_str());
    }
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_outcome_as_str_all_distinct() {
    let mut strs = BTreeSet::new();
    for outcome in [
        SecurityOutcome::Allow,
        SecurityOutcome::Contain,
        SecurityOutcome::Quarantine,
        SecurityOutcome::Terminate,
    ] {
        strs.insert(outcome.as_str());
    }
    assert_eq!(strs.len(), 4);
}

// ===========================================================================
// I. BinomialConfidenceInterval helpers (3 tests)
// ===========================================================================

#[test]
fn enrichment_binomial_ci_lower_upper_f64() {
    let ci = BinomialConfidenceInterval {
        lower_millionths: 500_000,
        upper_millionths: 750_000,
    };
    assert!((ci.lower_f64().unwrap() - 0.5).abs() < 0.001);
    assert!((ci.upper_f64().unwrap() - 0.75).abs() < 0.001);
}

#[test]
fn enrichment_binomial_ci_zero_values() {
    let ci = BinomialConfidenceInterval {
        lower_millionths: 0,
        upper_millionths: 0,
    };
    assert!(ci.lower_f64().unwrap().abs() < 0.001);
}

#[test]
fn enrichment_binomial_ci_serde_preserves_values() {
    let ci = BinomialConfidenceInterval {
        lower_millionths: 123_456,
        upper_millionths: 987_654,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: BinomialConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(back.lower_millionths, 123_456);
    assert_eq!(back.upper_millionths, 987_654);
}
