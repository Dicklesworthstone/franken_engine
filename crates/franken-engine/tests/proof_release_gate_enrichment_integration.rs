//! Enrichment integration tests for proof_release_gate.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_release_gate::{
    GateFailureCode, GateFinding, OptimizationProofArtifact, PromotionDecisionArtifact,
    ProofChainBundle, ProofGateLogEvent, ReleaseGateInput, ReleaseGateThresholds,
    TestEvidenceBundle, evaluate_release_gate,
};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hash(label: &str) -> [u8; 32] {
    *ContentHash::compute(label.as_bytes()).as_bytes()
}

fn ok_artifact(pass_name: &str) -> OptimizationProofArtifact {
    OptimizationProofArtifact {
        optimization_pass: pass_name.to_string(),
        optimization_applied: true,
        pre_ir_hash: hash("pre"),
        post_ir_hash: hash("post"),
        ir_diff_size_bytes: 48,
        proof_hash: hash("proof"),
        verifier_version: "verifier-v1".to_string(),
        proof_generation_time_ns: 1_000,
        verification_time_ns: 2_000,
        independent_replay_verified: true,
        replay_command: format!("verify --pass {pass_name}"),
        proof_verified: true,
        fallback_triggered: false,
        fallback_receipt_id: None,
    }
}

fn good_test_evidence() -> TestEvidenceBundle {
    TestEvidenceBundle {
        unit_coverage_millionths: 940_000,
        mutation_score_millionths: 900_000,
        required_failure_mode_tests: 12,
        executed_failure_mode_tests: 12,
        required_e2e_scenarios: 9,
        executed_e2e_scenarios: 9,
        logging_artifact_count: 18,
        logging_artifact_max_age_ns: 600_000_000_000,
        trace_correlated_logging: true,
    }
}

fn base_input() -> ReleaseGateInput {
    let mut expected = BTreeSet::new();
    expected.insert("inline".to_string());
    expected.insert("dce".to_string());
    ReleaseGateInput {
        trace_id: "trace-gate-1".to_string(),
        policy_id: "policy-opt-gate".to_string(),
        expected_optimization_passes: expected,
        bundle: ProofChainBundle {
            candidate_version: "candidate-2026-02-20".to_string(),
            compilation_id: "compile-0001".to_string(),
            original_compile_time_ns: 50_000_000,
            replay_time_ns: 200_000_000,
            archive_root: hash("archive-root"),
            archive_uri: "cas://proof-chain/compile-0001".to_string(),
            artifacts: vec![ok_artifact("inline"), ok_artifact("dce")],
        },
        test_evidence: Some(good_test_evidence()),
    }
}

// ---------------------------------------------------------------------------
// Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_failure_code_copy() {
    let a = GateFailureCode::MissingProofArtifact;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Clone independence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_clone_independence() {
    let a = ok_artifact("inline");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_bundle_clone_independence() {
    let input = base_input();
    let a = input.bundle.clone();
    assert_eq!(input.bundle, a);
}

#[test]
fn enrichment_test_evidence_clone_independence() {
    let a = good_test_evidence();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_input_clone_independence() {
    let a = base_input();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_thresholds_clone_independence() {
    let a = ReleaseGateThresholds::default();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_finding_clone_independence() {
    let a = GateFinding {
        code: GateFailureCode::MissingProofArtifact,
        optimization_pass: Some("inline".to_string()),
        detail: "test detail".to_string(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_decision_clone_independence() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let cloned = decision.clone();
    assert_eq!(decision, cloned);
}

// ---------------------------------------------------------------------------
// BTreeSet ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_failure_code_btreeset() {
    let codes = [
        GateFailureCode::MissingProofArtifact,
        GateFailureCode::MissingBundleField,
        GateFailureCode::ProofVerificationFailed,
        GateFailureCode::FallbackPathInvalid,
        GateFailureCode::IndependentReplayFailed,
        GateFailureCode::ReplayMultiplierExceeded,
        GateFailureCode::ArchiveNotContentAddressed,
        GateFailureCode::MissingTestEvidence,
        GateFailureCode::TestEvidenceBelowThreshold,
        GateFailureCode::LoggingArtifactsMissing,
        GateFailureCode::LoggingArtifactsStale,
        GateFailureCode::LoggingArtifactsUncorrelated,
    ];
    let set: BTreeSet<GateFailureCode> = codes.iter().copied().collect();
    assert_eq!(set.len(), 12);
}

// ---------------------------------------------------------------------------
// Debug nonempty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_failure_code_debug() {
    assert!(!format!("{:?}", GateFailureCode::MissingProofArtifact).is_empty());
    assert!(!format!("{:?}", GateFailureCode::LoggingArtifactsUncorrelated).is_empty());
}

#[test]
fn enrichment_artifact_debug() {
    assert!(!format!("{:?}", ok_artifact("inline")).is_empty());
}

#[test]
fn enrichment_bundle_debug() {
    assert!(!format!("{:?}", base_input().bundle).is_empty());
}

#[test]
fn enrichment_test_evidence_debug() {
    assert!(!format!("{:?}", good_test_evidence()).is_empty());
}

#[test]
fn enrichment_input_debug() {
    assert!(!format!("{:?}", base_input()).is_empty());
}

#[test]
fn enrichment_thresholds_debug() {
    assert!(!format!("{:?}", ReleaseGateThresholds::default()).is_empty());
}

#[test]
fn enrichment_finding_debug() {
    let f = GateFinding {
        code: GateFailureCode::MissingBundleField,
        optimization_pass: None,
        detail: "test".to_string(),
    };
    assert!(!format!("{:?}", f).is_empty());
}

#[test]
fn enrichment_decision_debug() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(!format!("{:?}", d).is_empty());
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_failure_code_display_all_unique() {
    let codes = [
        GateFailureCode::MissingProofArtifact,
        GateFailureCode::MissingBundleField,
        GateFailureCode::ProofVerificationFailed,
        GateFailureCode::FallbackPathInvalid,
        GateFailureCode::IndependentReplayFailed,
        GateFailureCode::ReplayMultiplierExceeded,
        GateFailureCode::ArchiveNotContentAddressed,
        GateFailureCode::MissingTestEvidence,
        GateFailureCode::TestEvidenceBelowThreshold,
        GateFailureCode::LoggingArtifactsMissing,
        GateFailureCode::LoggingArtifactsStale,
        GateFailureCode::LoggingArtifactsUncorrelated,
    ];
    let displays: BTreeSet<String> = codes.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 12);
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thresholds_default_values() {
    let t = ReleaseGateThresholds::default();
    assert_eq!(t.max_replay_multiplier_millionths, 5_000_000);
    assert_eq!(t.min_unit_coverage_millionths, 900_000);
    assert_eq!(t.min_mutation_score_millionths, 850_000);
    assert_eq!(t.max_logging_artifact_age_ns, 3_600_000_000_000);
    assert!(t.require_trace_correlated_logging);
}

// ---------------------------------------------------------------------------
// JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_json_fields() {
    let a = ok_artifact("inline");
    let json = serde_json::to_string(&a).unwrap();
    for field in [
        "optimization_pass",
        "optimization_applied",
        "pre_ir_hash",
        "post_ir_hash",
        "ir_diff_size_bytes",
        "proof_hash",
        "verifier_version",
        "proof_generation_time_ns",
        "verification_time_ns",
        "independent_replay_verified",
        "replay_command",
        "proof_verified",
        "fallback_triggered",
        "fallback_receipt_id",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_bundle_json_fields() {
    let b = base_input().bundle;
    let json = serde_json::to_string(&b).unwrap();
    for field in [
        "candidate_version",
        "compilation_id",
        "original_compile_time_ns",
        "replay_time_ns",
        "archive_root",
        "archive_uri",
        "artifacts",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_test_evidence_json_fields() {
    let e = good_test_evidence();
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "unit_coverage_millionths",
        "mutation_score_millionths",
        "required_failure_mode_tests",
        "executed_failure_mode_tests",
        "required_e2e_scenarios",
        "executed_e2e_scenarios",
        "logging_artifact_count",
        "logging_artifact_max_age_ns",
        "trace_correlated_logging",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_input_json_fields() {
    let i = base_input();
    let json = serde_json::to_string(&i).unwrap();
    for field in [
        "trace_id",
        "policy_id",
        "expected_optimization_passes",
        "bundle",
        "test_evidence",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_thresholds_json_fields() {
    let t = ReleaseGateThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    for field in [
        "max_replay_multiplier_millionths",
        "min_unit_coverage_millionths",
        "min_mutation_score_millionths",
        "max_logging_artifact_age_ns",
        "require_trace_correlated_logging",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_finding_json_fields() {
    let f = GateFinding {
        code: GateFailureCode::MissingProofArtifact,
        optimization_pass: Some("dce".to_string()),
        detail: "missing".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    for field in ["code", "optimization_pass", "detail"] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

#[test]
fn enrichment_decision_json_fields() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let json = serde_json::to_string(&d).unwrap();
    for field in [
        "decision_id",
        "candidate_version",
        "pass",
        "replay_multiplier_millionths",
        "rollback_token",
        "findings",
        "logs",
    ] {
        assert!(json.contains(field), "missing field: {}", field);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_serde_roundtrip() {
    let a = ok_artifact("inline");
    let json = serde_json::to_string(&a).unwrap();
    let back: OptimizationProofArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn enrichment_bundle_serde_roundtrip() {
    let b = base_input().bundle;
    let json = serde_json::to_string(&b).unwrap();
    let back: ProofChainBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_test_evidence_serde_roundtrip() {
    let e = good_test_evidence();
    let json = serde_json::to_string(&e).unwrap();
    let back: TestEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn enrichment_input_serde_roundtrip() {
    let i = base_input();
    let json = serde_json::to_string(&i).unwrap();
    let back: ReleaseGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(i, back);
}

#[test]
fn enrichment_thresholds_serde_roundtrip() {
    let t = ReleaseGateThresholds {
        max_replay_multiplier_millionths: 3_000_000,
        min_unit_coverage_millionths: 910_000,
        min_mutation_score_millionths: 870_000,
        max_logging_artifact_age_ns: 1_200_000_000_000,
        require_trace_correlated_logging: false,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: ReleaseGateThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_finding_serde_roundtrip() {
    let f = GateFinding {
        code: GateFailureCode::FallbackPathInvalid,
        optimization_pass: Some("dce".to_string()),
        detail: "test fallback".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: GateFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn enrichment_gate_failure_code_serde_all() {
    let codes = [
        GateFailureCode::MissingProofArtifact,
        GateFailureCode::MissingBundleField,
        GateFailureCode::ProofVerificationFailed,
        GateFailureCode::FallbackPathInvalid,
        GateFailureCode::IndependentReplayFailed,
        GateFailureCode::ReplayMultiplierExceeded,
        GateFailureCode::ArchiveNotContentAddressed,
        GateFailureCode::MissingTestEvidence,
        GateFailureCode::TestEvidenceBelowThreshold,
        GateFailureCode::LoggingArtifactsMissing,
        GateFailureCode::LoggingArtifactsStale,
        GateFailureCode::LoggingArtifactsUncorrelated,
    ];
    for code in codes {
        let json = serde_json::to_string(&code).unwrap();
        let back: GateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(code, back);
    }
}

#[test]
fn enrichment_decision_serde_roundtrip() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let json = serde_json::to_string(&d).unwrap();
    let back: PromotionDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_determinism_20_runs() {
    let input = base_input();
    let thresholds = ReleaseGateThresholds::default();
    let first = evaluate_release_gate(&input, &thresholds);
    for _ in 1..20 {
        let r = evaluate_release_gate(&input, &thresholds);
        assert_eq!(first, r);
    }
}

#[test]
fn enrichment_decision_id_deterministic() {
    let input = base_input();
    let thresholds = ReleaseGateThresholds::default();
    let a = evaluate_release_gate(&input, &thresholds);
    let b = evaluate_release_gate(&input, &thresholds);
    assert_eq!(a.decision_id, b.decision_id);
}

// ---------------------------------------------------------------------------
// evaluate_release_gate: pass scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_passes_complete_pipeline() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(d.pass);
    assert!(d.findings.is_empty());
    assert_eq!(d.replay_multiplier_millionths, 4_000_000);
}

#[test]
fn enrichment_gate_pass_has_logs() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    // 2 artifact logs + 1 decision log
    assert_eq!(d.logs.len(), 3);
}

#[test]
fn enrichment_gate_pass_has_rollback_token() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(d.rollback_token.starts_with("rollback-"));
}

#[test]
fn enrichment_gate_pass_candidate_version() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert_eq!(d.candidate_version, "candidate-2026-02-20");
}

// ---------------------------------------------------------------------------
// evaluate_release_gate: failure scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gate_fails_missing_artifact() {
    let mut input = base_input();
    input.bundle.artifacts = vec![ok_artifact("inline")]; // missing "dce"
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingProofArtifact)
    );
}

#[test]
fn enrichment_gate_fails_proof_not_verified_but_applied() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = true;
    input.bundle.artifacts[0].fallback_triggered = false;
    input.bundle.artifacts[0].fallback_receipt_id = None;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
    );
}

#[test]
fn enrichment_gate_fails_invalid_fallback() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = false;
    input.bundle.artifacts[0].fallback_receipt_id = None;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
    );
}

#[test]
fn enrichment_gate_fails_replay_not_verified() {
    let mut input = base_input();
    input.bundle.artifacts[0].independent_replay_verified = false;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::IndependentReplayFailed)
    );
}

#[test]
fn enrichment_gate_fails_replay_multiplier_exceeded() {
    let mut input = base_input();
    input.bundle.replay_time_ns = 700_000_000; // 14x > 5x threshold
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
    );
}

#[test]
fn enrichment_gate_fails_not_content_addressed() {
    let mut input = base_input();
    input.bundle.archive_uri = "https://not-cas".to_string();
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
    );
}

#[test]
fn enrichment_gate_fails_missing_test_evidence() {
    let mut input = base_input();
    input.test_evidence = None;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingTestEvidence)
    );
}

#[test]
fn enrichment_gate_fails_low_unit_coverage() {
    let mut input = base_input();
    input
        .test_evidence
        .as_mut()
        .unwrap()
        .unit_coverage_millionths = 500_000;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold)
    );
}

#[test]
fn enrichment_gate_fails_low_mutation_score() {
    let mut input = base_input();
    input
        .test_evidence
        .as_mut()
        .unwrap()
        .mutation_score_millionths = 500_000;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold)
    );
}

#[test]
fn enrichment_gate_fails_missing_failure_mode_tests() {
    let mut input = base_input();
    input
        .test_evidence
        .as_mut()
        .unwrap()
        .executed_failure_mode_tests = 5;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
}

#[test]
fn enrichment_gate_fails_missing_e2e_scenarios() {
    let mut input = base_input();
    input.test_evidence.as_mut().unwrap().executed_e2e_scenarios = 3;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
}

#[test]
fn enrichment_gate_fails_no_logging_artifacts() {
    let mut input = base_input();
    input.test_evidence.as_mut().unwrap().logging_artifact_count = 0;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::LoggingArtifactsMissing)
    );
}

#[test]
fn enrichment_gate_fails_stale_logging() {
    let mut input = base_input();
    input
        .test_evidence
        .as_mut()
        .unwrap()
        .logging_artifact_max_age_ns = 10_000_000_000_000;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::LoggingArtifactsStale)
    );
}

#[test]
fn enrichment_gate_fails_uncorrelated_logging() {
    let mut input = base_input();
    input
        .test_evidence
        .as_mut()
        .unwrap()
        .trace_correlated_logging = false;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::LoggingArtifactsUncorrelated)
    );
}

#[test]
fn enrichment_gate_fails_missing_bundle_field() {
    let mut input = base_input();
    input.bundle.artifacts[0].optimization_pass = "  ".to_string();
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn enrichment_gate_fails_zero_proof_hash() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_hash = [0u8; 32];
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

// ---------------------------------------------------------------------------
// Valid fallback path
// ---------------------------------------------------------------------------

#[test]
fn enrichment_valid_fallback_no_fallback_finding() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-001".to_string());
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(
        !d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
    );
    assert!(
        !d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ProofVerificationFailed)
    );
}

// ---------------------------------------------------------------------------
// Log event structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_log_events_trace_id() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    for log in &d.logs {
        assert_eq!(log.trace_id, "trace-gate-1");
    }
}

#[test]
fn enrichment_log_events_decision_id_consistent() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    for log in &d.logs {
        assert_eq!(log.decision_id, d.decision_id);
    }
}

#[test]
fn enrichment_log_events_policy_id() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    for log in &d.logs {
        assert_eq!(log.policy_id, "policy-opt-gate");
    }
}

#[test]
fn enrichment_log_final_event_is_decision() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let last = d.logs.last().unwrap();
    assert_eq!(last.event, "release_gate_decision");
    assert_eq!(last.outcome, "pass");
}

#[test]
fn enrichment_log_artifact_events_have_proof_hash() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    // First N-1 logs are artifact events
    for log in &d.logs[..d.logs.len() - 1] {
        assert!(log.proof_hash.is_some());
        assert!(log.optimization_pass.is_some());
    }
}

// ---------------------------------------------------------------------------
// Custom thresholds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_custom_thresholds_stricter() {
    let thresholds = ReleaseGateThresholds {
        max_replay_multiplier_millionths: 2_000_000, // 2x
        min_unit_coverage_millionths: 950_000,
        min_mutation_score_millionths: 920_000,
        max_logging_artifact_age_ns: 300_000_000_000,
        require_trace_correlated_logging: true,
    };
    let d = evaluate_release_gate(&base_input(), &thresholds);
    // Base input has 4x replay and 940k coverage — should fail stricter thresholds
    assert!(!d.pass);
}

#[test]
fn enrichment_custom_thresholds_lenient() {
    let thresholds = ReleaseGateThresholds {
        max_replay_multiplier_millionths: 20_000_000, // 20x
        min_unit_coverage_millionths: 500_000,
        min_mutation_score_millionths: 500_000,
        max_logging_artifact_age_ns: 10_000_000_000_000,
        require_trace_correlated_logging: false,
    };
    let d = evaluate_release_gate(&base_input(), &thresholds);
    assert!(d.pass);
}

// ---------------------------------------------------------------------------
// ProofGateLogEvent serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_log_event_serde_roundtrip() {
    let d = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    for log in &d.logs {
        let json = serde_json::to_string(log).unwrap();
        let back: ProofGateLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(*log, back);
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_artifacts_fails() {
    let mut input = base_input();
    input.bundle.artifacts.clear();
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingProofArtifact)
    );
}

#[test]
fn enrichment_zero_compile_time_max_multiplier() {
    let mut input = base_input();
    input.bundle.original_compile_time_ns = 0;
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
    );
}

#[test]
fn enrichment_archive_zero_root_fails() {
    let mut input = base_input();
    input.bundle.archive_root = [0u8; 32];
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(
        d.findings
            .iter()
            .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
    );
}

#[test]
fn enrichment_multiple_findings_accumulated() {
    let mut input = base_input();
    input.test_evidence = None;
    input.bundle.archive_uri = "https://bad".to_string();
    let d = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!d.pass);
    assert!(d.findings.len() >= 2);
}
