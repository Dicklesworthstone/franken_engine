#![forbid(unsafe_code)]
//! Integration tests for the `security_conformance` module.
//!
//! Exercises the security conformance pipeline from outside the crate
//! boundary: label validation, observation validation, thresholds,
//! Clopper-Pearson confidence intervals, conformance evaluation,
//! corpus manifest operations, and serde round-trips.

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

use std::path::PathBuf;

use frankenengine_engine::security_conformance::{
    BinomialConfidenceInterval, SECURITY_ATTACK_TAXONOMIES, SECURITY_CONFORMANCE_SCHEMA_VERSION,
    SECURITY_CORPUS_MANIFEST_FILE_NAME, SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
    SECURITY_LABEL_FILE_NAME, SecurityAttackTaxonomy, SecurityConformanceError,
    SecurityConformanceSummary, SecurityConformanceThresholds, SecurityCorpus, SecurityOutcome,
    SecurityWorkloadLabel, SecurityWorkloadLabelRecord, SecurityWorkloadObservation,
    clopper_pearson_interval, corpus_manifest_hash, default_observation_from_label,
    evaluate_security_conformance,
};

// ===========================================================================
// Helpers
// ===========================================================================

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

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn label_file_name_constant() {
    assert_eq!(SECURITY_LABEL_FILE_NAME, "workload_label.toml");
}

#[test]
fn corpus_manifest_file_name_constant() {
    assert_eq!(SECURITY_CORPUS_MANIFEST_FILE_NAME, "corpus_manifest.toml");
}

#[test]
fn schema_version_constants_nonempty() {
    assert!(!SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!SECURITY_CONFORMANCE_SCHEMA_VERSION.is_empty());
}

#[test]
fn attack_taxonomies_has_six_entries() {
    assert_eq!(SECURITY_ATTACK_TAXONOMIES.len(), 6);
}

// ===========================================================================
// 2. SecurityCorpus serde
// ===========================================================================

#[test]
fn security_corpus_serde_round_trip() {
    for corpus in [SecurityCorpus::Benign, SecurityCorpus::Malicious] {
        let json = serde_json::to_string(&corpus).unwrap();
        let back: SecurityCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, corpus);
    }
}

#[test]
fn security_corpus_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&SecurityCorpus::Benign).unwrap(),
        "\"benign\""
    );
    assert_eq!(
        serde_json::to_string(&SecurityCorpus::Malicious).unwrap(),
        "\"malicious\""
    );
}

// ===========================================================================
// 3. SecurityAttackTaxonomy serde
// ===========================================================================

#[test]
fn attack_taxonomy_serde_round_trip() {
    for tax in [
        SecurityAttackTaxonomy::Exfil,
        SecurityAttackTaxonomy::Escalation,
        SecurityAttackTaxonomy::Evasion,
        SecurityAttackTaxonomy::Dos,
        SecurityAttackTaxonomy::SideChannel,
        SecurityAttackTaxonomy::Staging,
    ] {
        let json = serde_json::to_string(&tax).unwrap();
        let back: SecurityAttackTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tax);
    }
}

#[test]
fn attack_taxonomy_as_str() {
    assert_eq!(SecurityAttackTaxonomy::Exfil.as_str(), "exfil");
    assert_eq!(SecurityAttackTaxonomy::SideChannel.as_str(), "side_channel");
}

// ===========================================================================
// 4. SecurityOutcome serde
// ===========================================================================

#[test]
fn security_outcome_serde_round_trip() {
    for outcome in [
        SecurityOutcome::Allow,
        SecurityOutcome::Contain,
        SecurityOutcome::Quarantine,
        SecurityOutcome::Terminate,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: SecurityOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }
}

#[test]
fn security_outcome_as_str() {
    assert_eq!(SecurityOutcome::Allow.as_str(), "allow");
    assert_eq!(SecurityOutcome::Contain.as_str(), "contain");
    assert_eq!(SecurityOutcome::Quarantine.as_str(), "quarantine");
    assert_eq!(SecurityOutcome::Terminate.as_str(), "terminate");
}

// ===========================================================================
// 5. SecurityWorkloadLabel validation
// ===========================================================================

#[test]
fn benign_label_valid() {
    assert!(benign_label("b-1").validate().is_ok());
}

#[test]
fn malicious_label_valid() {
    assert!(
        malicious_label("m-1", SecurityAttackTaxonomy::Exfil)
            .validate()
            .is_ok()
    );
}

#[test]
fn label_empty_workload_id_fails() {
    let mut label = benign_label("");
    label.workload_id = String::new();
    assert!(label.validate().is_err());
}

#[test]
fn label_empty_semantic_domain_fails() {
    let mut label = benign_label("b-1");
    label.semantic_domain = String::new();
    assert!(label.validate().is_err());
}

#[test]
fn label_zero_latency_bound_fails() {
    let mut label = benign_label("b-1");
    label.expected_detection_latency_bound_ms = 0;
    assert!(label.validate().is_err());
}

#[test]
fn label_bad_hostcall_hash_length_fails() {
    let mut label = benign_label("b-1");
    label.hostcall_sequence_hash = "abcd".into();
    assert!(label.validate().is_err());
}

#[test]
fn label_bad_hostcall_hash_uppercase_fails() {
    let mut label = benign_label("b-1");
    label.hostcall_sequence_hash = hex64('A');
    assert!(label.validate().is_err());
}

#[test]
fn benign_label_with_taxonomy_fails() {
    let mut label = benign_label("b-1");
    label.attack_taxonomy = Some(SecurityAttackTaxonomy::Dos);
    assert!(label.validate().is_err());
}

#[test]
fn benign_label_with_non_allow_outcome_fails() {
    let mut label = benign_label("b-1");
    label.expected_outcome = SecurityOutcome::Contain;
    assert!(label.validate().is_err());
}

#[test]
fn malicious_label_without_taxonomy_fails() {
    let mut label = malicious_label("m-1", SecurityAttackTaxonomy::Exfil);
    label.attack_taxonomy = None;
    assert!(label.validate().is_err());
}

#[test]
fn malicious_label_with_allow_outcome_fails() {
    let mut label = malicious_label("m-1", SecurityAttackTaxonomy::Exfil);
    label.expected_outcome = SecurityOutcome::Allow;
    assert!(label.validate().is_err());
}

#[test]
fn label_serde_round_trip() {
    let label = benign_label("b-1");
    let json = serde_json::to_string(&label).unwrap();
    let back: SecurityWorkloadLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(back.workload_id, "b-1");
    assert_eq!(back.corpus, SecurityCorpus::Benign);
}

// ===========================================================================
// 6. SecurityWorkloadObservation validation
// ===========================================================================

#[test]
fn benign_observation_valid() {
    assert!(benign_observation("b-1").validate().is_ok());
}

#[test]
fn malicious_observation_valid() {
    assert!(malicious_observation("m-1").validate().is_ok());
}

#[test]
fn observation_empty_workload_id_fails() {
    let mut obs = benign_observation("b-1");
    obs.workload_id = String::new();
    assert!(obs.validate().is_err());
}

#[test]
fn observation_empty_policy_action_fails() {
    let mut obs = benign_observation("b-1");
    obs.policy_action = String::new();
    assert!(obs.validate().is_err());
}

#[test]
fn observation_empty_containment_action_fails() {
    let mut obs = benign_observation("b-1");
    obs.containment_action = String::new();
    assert!(obs.validate().is_err());
}

#[test]
fn observation_posterior_below_zero_fails() {
    let mut obs = benign_observation("b-1");
    obs.sentinel_posterior = -0.1;
    assert!(obs.validate().is_err());
}

#[test]
fn observation_posterior_above_one_fails() {
    let mut obs = benign_observation("b-1");
    obs.sentinel_posterior = 1.1;
    assert!(obs.validate().is_err());
}

#[test]
fn observation_serde_round_trip() {
    let obs = malicious_observation("m-1");
    let json = serde_json::to_string(&obs).unwrap();
    let back: SecurityWorkloadObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.workload_id, "m-1");
    assert_eq!(back.actual_outcome, SecurityOutcome::Contain);
}

// ===========================================================================
// 7. SecurityConformanceThresholds
// ===========================================================================

#[test]
fn thresholds_default() {
    let t = SecurityConformanceThresholds::default();
    assert_eq!(t.malicious_latency_p95_max_ms, 250);
    assert_eq!(t.confidence_level_millionths, 950_000);
}

#[test]
fn thresholds_serde_round_trip() {
    let t = SecurityConformanceThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: SecurityConformanceThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 8. BinomialConfidenceInterval
// ===========================================================================

#[test]
fn binomial_ci_serde_round_trip() {
    let ci = BinomialConfidenceInterval {
        lower_millionths: 900_000,
        upper_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: BinomialConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(back.lower_millionths, 900_000);
    assert_eq!(back.upper_millionths, 1_000_000);
}

// ===========================================================================
// 9. Clopper-Pearson interval
// ===========================================================================

#[test]
fn clopper_pearson_all_successes() {
    let ci = clopper_pearson_interval(100, 100, 0.95).unwrap();
    assert_eq!(ci.upper_millionths, 1_000_000);
    assert!(ci.lower_millionths > 900_000);
}

#[test]
fn clopper_pearson_no_successes() {
    let ci = clopper_pearson_interval(0, 100, 0.95).unwrap();
    assert_eq!(ci.lower_millionths, 0);
    assert!(ci.upper_millionths < 100_000);
}

#[test]
fn clopper_pearson_half() {
    let ci = clopper_pearson_interval(50, 100, 0.95).unwrap();
    assert!(ci.lower_millionths > 300_000);
    assert!(ci.upper_millionths < 700_000);
    assert!(ci.lower_millionths < 500_000);
    assert!(ci.upper_millionths > 500_000);
}

#[test]
fn clopper_pearson_zero_total_fails() {
    let result = clopper_pearson_interval(0, 0, 0.95);
    assert!(result.is_err());
}

#[test]
fn clopper_pearson_successes_exceeds_total_fails() {
    let result = clopper_pearson_interval(10, 5, 0.95);
    assert!(result.is_err());
}

// ===========================================================================
// 10. default_observation_from_label
// ===========================================================================

#[test]
fn default_observation_benign() {
    let label = benign_label("b-1");
    let obs = default_observation_from_label(&label);
    assert_eq!(obs.workload_id, "b-1");
    assert_eq!(obs.actual_outcome, SecurityOutcome::Allow);
    assert!(obs.sentinel_posterior < 0.5);
    assert!(obs.error_code.is_none());
}

#[test]
fn default_observation_malicious() {
    let label = malicious_label("m-1", SecurityAttackTaxonomy::Exfil);
    let obs = default_observation_from_label(&label);
    assert_eq!(obs.workload_id, "m-1");
    assert_eq!(obs.actual_outcome, SecurityOutcome::Contain);
    assert!(obs.sentinel_posterior > 0.5);
}

// ===========================================================================
// 11. corpus_manifest_hash
// ===========================================================================

#[test]
fn manifest_hash_deterministic() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Dos)),
    ];
    let h1 = corpus_manifest_hash(&records);
    let h2 = corpus_manifest_hash(&records);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn manifest_hash_empty_records() {
    let hash = corpus_manifest_hash(&[]);
    assert_eq!(hash.len(), 64);
}

#[test]
fn manifest_hash_different_records_different_hash() {
    let r1 = vec![label_record(benign_label("b-1"))];
    let r2 = vec![label_record(benign_label("b-2"))];
    assert_ne!(corpus_manifest_hash(&r1), corpus_manifest_hash(&r2));
}

// ===========================================================================
// 12. evaluate_security_conformance: all correct
// ===========================================================================

#[test]
fn evaluate_all_correct_passes_gate() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(benign_label("b-2")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
        label_record(malicious_label("m-2", SecurityAttackTaxonomy::Dos)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        benign_observation("b-2"),
        malicious_observation("m-1"),
        malicious_observation("m-2"),
    ];
    // Use relaxed thresholds: with only 2 malicious samples the Clopper-Pearson
    // CI lower bound is wide (~0.158 at 95%) so the default tpr_min=0.99 fails.
    let thresholds = SecurityConformanceThresholds {
        tpr_min: "0.100000".into(),
        fpr_max: "0.900000".into(),
        ..SecurityConformanceThresholds::default()
    };
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert!(
        eval.summary.gate_pass,
        "gate_failure_reasons: {:?}",
        eval.summary.gate_failure_reasons
    );
    assert_eq!(eval.summary.true_positive_count, 2);
    assert_eq!(eval.summary.false_positive_count, 0);
    assert_eq!(eval.summary.false_negative_count, 0);
    assert_eq!(eval.summary.benign_total, 2);
    assert_eq!(eval.summary.malicious_total, 2);
}

// ===========================================================================
// 13. evaluate: false positive (benign detected as malicious)
// ===========================================================================

#[test]
fn evaluate_false_positive() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![
        SecurityWorkloadObservation {
            workload_id: "b-1".into(),
            actual_outcome: SecurityOutcome::Contain, // FP: benign classified as contain
            detection_latency_us: 5_000,
            sentinel_posterior: 0.7,
            policy_action: "contain".into(),
            containment_action: "sandbox".into(),
            error_code: Some("FE-FP".into()),
        },
        malicious_observation("m-1"),
    ];
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert_eq!(eval.summary.false_positive_count, 1);
}

// ===========================================================================
// 14. evaluate: false negative (malicious not detected)
// ===========================================================================

#[test]
fn evaluate_false_negative() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Escalation)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        SecurityWorkloadObservation {
            workload_id: "m-1".into(),
            actual_outcome: SecurityOutcome::Allow, // FN: malicious classified as allow
            detection_latency_us: 5_000,
            sentinel_posterior: 0.1,
            policy_action: "allow".into(),
            containment_action: "none".into(),
            error_code: Some("FE-FN".into()),
        },
    ];
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert_eq!(eval.summary.false_negative_count, 1);
    assert_eq!(eval.summary.true_positive_count, 0);
}

// ===========================================================================
// 15. evaluate: gate failure reasons
// ===========================================================================

#[test]
fn evaluate_gate_failure_tpr_too_low() {
    // 1 malicious, 0 detected → TPR = 0
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Evasion)),
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
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert!(!eval.summary.gate_pass);
    assert!(!eval.summary.gate_failure_reasons.is_empty());
}

// ===========================================================================
// 16. evaluate: empty dataset error
// ===========================================================================

#[test]
fn evaluate_empty_records_fails() {
    let thresholds = SecurityConformanceThresholds::default();
    let result = evaluate_security_conformance(&[], &[], &thresholds);
    assert!(result.is_err());
}

// ===========================================================================
// 17. evaluate: missing observation error
// ===========================================================================

#[test]
fn evaluate_missing_observation_fails() {
    let records = vec![label_record(benign_label("b-1"))];
    let observations: Vec<SecurityWorkloadObservation> = vec![];
    let thresholds = SecurityConformanceThresholds::default();
    let result = evaluate_security_conformance(&records, &observations, &thresholds);
    assert!(result.is_err());
}

// ===========================================================================
// 18. evaluate: duplicate observation error
// ===========================================================================

#[test]
fn evaluate_duplicate_observation_fails() {
    let records = vec![label_record(benign_label("b-1"))];
    let observations = vec![benign_observation("b-1"), benign_observation("b-1")];
    let thresholds = SecurityConformanceThresholds::default();
    let result = evaluate_security_conformance(&records, &observations, &thresholds);
    assert!(result.is_err());
}

// ===========================================================================
// 19. SecurityConformanceSummary serde
// ===========================================================================

#[test]
fn conformance_summary_serde_round_trip() {
    let summary = SecurityConformanceSummary {
        corpus_manifest_hash: hex64('a'),
        benign_total: 10,
        malicious_total: 5,
        true_positive_count: 5,
        false_positive_count: 0,
        false_negative_count: 0,
        tpr_millionths: 1_000_000,
        fpr_millionths: 0,
        tpr_ci: BinomialConfidenceInterval {
            lower_millionths: 500_000,
            upper_millionths: 1_000_000,
        },
        fpr_ci: BinomialConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 100_000,
        },
        malicious_latency_p95_us: 20_000,
        malicious_latency_p95_max_us: 250_000,
        gate_pass: true,
        gate_failure_reasons: vec![],
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SecurityConformanceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.benign_total, 10);
    assert_eq!(back.true_positive_count, 5);
    assert!(back.gate_pass);
}

// ===========================================================================
// 20. SecurityConformanceError display
// ===========================================================================

#[test]
fn error_display_nonempty() {
    let err = SecurityConformanceError::EmptyDataset;
    let msg = format!("{err}");
    assert!(!msg.is_empty());
}

#[test]
fn error_display_duplicate_observation() {
    let err = SecurityConformanceError::DuplicateObservation {
        workload_id: "dup-1".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("dup-1"));
}

// ===========================================================================
// 21. File-based: load_security_labels and validate_corpus_manifest
// ===========================================================================

#[test]
fn load_security_labels_missing_root_fails() {
    use frankenengine_engine::security_conformance::load_security_labels;
    let result = load_security_labels(std::path::Path::new("/nonexistent/path/12345"));
    assert!(result.is_err());
}

#[test]
fn load_security_labels_empty_dir_fails() {
    use frankenengine_engine::security_conformance::load_security_labels;
    let dir =
        std::env::temp_dir().join(format!("security_conformance_empty_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let result = load_security_labels(&dir);
    assert!(result.is_err()); // NoLabelsFound
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_security_labels_valid_label() {
    use frankenengine_engine::security_conformance::load_security_labels;
    let dir =
        std::env::temp_dir().join(format!("security_conformance_valid_{}", std::process::id()));
    let label_dir = dir.join("benign").join("case1");
    std::fs::create_dir_all(&label_dir).unwrap();

    let label_toml = r#"
workload_id = "benign-case1"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "security/benign"
"#;
    std::fs::write(label_dir.join("workload_label.toml"), label_toml).unwrap();

    let records = load_security_labels(&dir).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].label.workload_id, "benign-case1");
    assert_eq!(records[0].label.corpus, SecurityCorpus::Benign);

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// 22. evaluate: large corpus
// ===========================================================================

#[test]
fn evaluate_large_corpus_gate_pass() {
    let mut records = vec![];
    let mut observations = vec![];

    // 500 benign workloads — large enough for tight CIs
    for i in 0..500 {
        let id = format!("b-{i}");
        records.push(label_record(benign_label(&id)));
        observations.push(benign_observation(&id));
    }

    // 500 malicious workloads — all detected correctly
    for i in 0..500 {
        let id = format!("m-{i}");
        let tax = match i % 6 {
            0 => SecurityAttackTaxonomy::Exfil,
            1 => SecurityAttackTaxonomy::Escalation,
            2 => SecurityAttackTaxonomy::Evasion,
            3 => SecurityAttackTaxonomy::Dos,
            4 => SecurityAttackTaxonomy::SideChannel,
            _ => SecurityAttackTaxonomy::Staging,
        };
        records.push(label_record(malicious_label(&id, tax)));
        observations.push(malicious_observation(&id));
    }

    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert!(
        eval.summary.gate_pass,
        "gate_failure_reasons: {:?}",
        eval.summary.gate_failure_reasons
    );
    assert_eq!(eval.summary.true_positive_count, 500);
    assert_eq!(eval.summary.false_positive_count, 0);
    assert_eq!(eval.summary.false_negative_count, 0);
    assert_eq!(eval.observations_by_workload.len(), 1000);
}

// ===========================================================================
// 23. evaluate: observations by workload map
// ===========================================================================

#[test]
fn evaluate_returns_observations_by_workload() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Dos)),
    ];
    let observations = vec![benign_observation("b-1"), malicious_observation("m-1")];
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert!(eval.observations_by_workload.contains_key("b-1"));
    assert!(eval.observations_by_workload.contains_key("m-1"));
    assert_eq!(
        eval.observations_by_workload["b-1"].actual_outcome,
        SecurityOutcome::Allow
    );
}

// ===========================================================================
// 24. Malicious with different outcomes
// ===========================================================================

#[test]
fn malicious_quarantine_counted_as_tp() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Staging)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        SecurityWorkloadObservation {
            workload_id: "m-1".into(),
            actual_outcome: SecurityOutcome::Quarantine,
            detection_latency_us: 10_000,
            sentinel_posterior: 0.98,
            policy_action: "quarantine".into(),
            containment_action: "isolate".into(),
            error_code: None,
        },
    ];
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert_eq!(eval.summary.true_positive_count, 1);
}

#[test]
fn malicious_terminate_counted_as_tp() {
    let records = vec![
        label_record(benign_label("b-1")),
        label_record(malicious_label("m-1", SecurityAttackTaxonomy::Exfil)),
    ];
    let observations = vec![
        benign_observation("b-1"),
        SecurityWorkloadObservation {
            workload_id: "m-1".into(),
            actual_outcome: SecurityOutcome::Terminate,
            detection_latency_us: 8_000,
            sentinel_posterior: 0.999,
            policy_action: "terminate".into(),
            containment_action: "kill".into(),
            error_code: None,
        },
    ];
    let thresholds = SecurityConformanceThresholds::default();
    let eval = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    assert_eq!(eval.summary.true_positive_count, 1);
}

// ===========================================================================
// 25. Label serde with attack taxonomy
// ===========================================================================

#[test]
fn malicious_label_serde_round_trip() {
    let label = malicious_label("m-1", SecurityAttackTaxonomy::SideChannel);
    let json = serde_json::to_string(&label).unwrap();
    let back: SecurityWorkloadLabel = serde_json::from_str(&json).unwrap();
    assert_eq!(back.corpus, SecurityCorpus::Malicious);
    assert_eq!(
        back.attack_taxonomy,
        Some(SecurityAttackTaxonomy::SideChannel)
    );
    assert_eq!(back.expected_outcome, SecurityOutcome::Contain);
}

// ===========================================================================
// 26. Determinism meta-test
// ===========================================================================

#[test]
fn evaluate_repeated_runs_are_deterministic_within_latency_tolerance() {
    let mut records = vec![];
    let mut observations = vec![];

    for i in 0..500 {
        let id = format!("b-{i}");
        records.push(label_record(benign_label(&id)));
        observations.push(benign_observation(&id));
    }

    for i in 0..500 {
        let id = format!("m-{i}");
        let taxonomy = match i % 6 {
            0 => SecurityAttackTaxonomy::Exfil,
            1 => SecurityAttackTaxonomy::Escalation,
            2 => SecurityAttackTaxonomy::Evasion,
            3 => SecurityAttackTaxonomy::Dos,
            4 => SecurityAttackTaxonomy::SideChannel,
            _ => SecurityAttackTaxonomy::Staging,
        };
        records.push(label_record(malicious_label(&id, taxonomy)));
        observations.push(malicious_observation(&id));
    }

    let thresholds = SecurityConformanceThresholds::default();
    let baseline = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
    let baseline_p95 = baseline.summary.malicious_latency_p95_us;

    for _ in 0..5 {
        let rerun = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
        assert_eq!(baseline.summary, rerun.summary);
        assert_eq!(
            baseline.observations_by_workload,
            rerun.observations_by_workload
        );
        assert!(
            rerun
                .summary
                .malicious_latency_p95_us
                .abs_diff(baseline_p95)
                <= 1_000
        );
    }
}

// ===========================================================================
// 27. Latency bound meta-test
// ===========================================================================

#[test]
fn evaluate_gate_fails_when_malicious_latency_p95_exceeds_threshold() {
    let mut records = vec![];
    let mut observations = vec![];

    for i in 0..500 {
        let id = format!("b-{i}");
        records.push(label_record(benign_label(&id)));
        observations.push(benign_observation(&id));
    }

    for i in 0..500 {
        let id = format!("m-{i}");
        let taxonomy = match i % 6 {
            0 => SecurityAttackTaxonomy::Exfil,
            1 => SecurityAttackTaxonomy::Escalation,
            2 => SecurityAttackTaxonomy::Evasion,
            3 => SecurityAttackTaxonomy::Dos,
            4 => SecurityAttackTaxonomy::SideChannel,
            _ => SecurityAttackTaxonomy::Staging,
        };
        records.push(label_record(malicious_label(&id, taxonomy)));

        let mut obs = malicious_observation(&id);
        obs.detection_latency_us = 300_000;
        observations.push(obs);
    }

    let thresholds = SecurityConformanceThresholds::default();
    let evaluation = evaluate_security_conformance(&records, &observations, &thresholds).unwrap();

    assert!(!evaluation.summary.gate_pass);
    assert!(
        evaluation
            .summary
            .gate_failure_reasons
            .iter()
            .any(|reason| reason.contains("malicious latency p95")),
        "gate_failure_reasons={:?}",
        evaluation.summary.gate_failure_reasons
    );
    assert!(
        !evaluation
            .summary
            .gate_failure_reasons
            .iter()
            .any(|reason| reason.contains("TPR lower CI bound")),
        "unexpected TPR gate failure: {:?}",
        evaluation.summary.gate_failure_reasons
    );
    assert!(
        !evaluation
            .summary
            .gate_failure_reasons
            .iter()
            .any(|reason| reason.contains("FPR upper CI bound")),
        "unexpected FPR gate failure: {:?}",
        evaluation.summary.gate_failure_reasons
    );
}
