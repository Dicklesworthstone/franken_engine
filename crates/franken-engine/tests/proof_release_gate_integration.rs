//! Integration tests for proof_release_gate module.
//!
//! Covers all public types, trait impls, and the evaluate_release_gate
//! function across pass, failure-code, and edge-case scenarios.

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

use frankenengine_engine::proof_release_gate::{
    GateFailureCode, GateFinding, OptimizationProofArtifact, PromotionDecisionArtifact,
    ProofChainBundle, ReleaseGateInput, ReleaseGateThresholds, TestEvidenceBundle,
    evaluate_release_gate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn nonzero_hash(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn ok_artifact(pass_name: &str) -> OptimizationProofArtifact {
    OptimizationProofArtifact {
        optimization_pass: pass_name.to_string(),
        optimization_applied: true,
        pre_ir_hash: nonzero_hash(1),
        post_ir_hash: nonzero_hash(2),
        ir_diff_size_bytes: 48,
        proof_hash: nonzero_hash(3),
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
            replay_time_ns: 200_000_000, // 4x
            archive_root: nonzero_hash(10),
            archive_uri: "cas://proof-chain/compile-0001".to_string(),
            artifacts: vec![ok_artifact("inline"), ok_artifact("dce")],
        },
        test_evidence: Some(TestEvidenceBundle {
            unit_coverage_millionths: 940_000,
            mutation_score_millionths: 900_000,
            required_failure_mode_tests: 12,
            executed_failure_mode_tests: 12,
            required_e2e_scenarios: 9,
            executed_e2e_scenarios: 9,
            logging_artifact_count: 18,
            logging_artifact_max_age_ns: 600_000_000_000,
            trace_correlated_logging: true,
        }),
    }
}

// ===========================================================================
// GateFailureCode — Display
// ===========================================================================

#[test]
fn failure_code_display_missing_proof_artifact() {
    assert_eq!(
        GateFailureCode::MissingProofArtifact.to_string(),
        "missing_proof_artifact"
    );
}

#[test]
fn failure_code_display_missing_bundle_field() {
    assert_eq!(
        GateFailureCode::MissingBundleField.to_string(),
        "missing_bundle_field"
    );
}

#[test]
fn failure_code_display_proof_verification_failed() {
    assert_eq!(
        GateFailureCode::ProofVerificationFailed.to_string(),
        "proof_verification_failed"
    );
}

#[test]
fn failure_code_display_fallback_path_invalid() {
    assert_eq!(
        GateFailureCode::FallbackPathInvalid.to_string(),
        "fallback_path_invalid"
    );
}

#[test]
fn failure_code_display_independent_replay_failed() {
    assert_eq!(
        GateFailureCode::IndependentReplayFailed.to_string(),
        "independent_replay_failed"
    );
}

#[test]
fn failure_code_display_replay_multiplier_exceeded() {
    assert_eq!(
        GateFailureCode::ReplayMultiplierExceeded.to_string(),
        "replay_multiplier_exceeded"
    );
}

#[test]
fn failure_code_display_archive_not_content_addressed() {
    assert_eq!(
        GateFailureCode::ArchiveNotContentAddressed.to_string(),
        "archive_not_content_addressed"
    );
}

#[test]
fn failure_code_display_missing_test_evidence() {
    assert_eq!(
        GateFailureCode::MissingTestEvidence.to_string(),
        "missing_test_evidence"
    );
}

#[test]
fn failure_code_display_test_evidence_below_threshold() {
    assert_eq!(
        GateFailureCode::TestEvidenceBelowThreshold.to_string(),
        "test_evidence_below_threshold"
    );
}

#[test]
fn failure_code_display_logging_artifacts_missing() {
    assert_eq!(
        GateFailureCode::LoggingArtifactsMissing.to_string(),
        "logging_artifacts_missing"
    );
}

#[test]
fn failure_code_display_logging_artifacts_stale() {
    assert_eq!(
        GateFailureCode::LoggingArtifactsStale.to_string(),
        "logging_artifacts_stale"
    );
}

#[test]
fn failure_code_display_logging_artifacts_uncorrelated() {
    assert_eq!(
        GateFailureCode::LoggingArtifactsUncorrelated.to_string(),
        "logging_artifacts_uncorrelated"
    );
}

// ===========================================================================
// Serde round-trips
// ===========================================================================

#[test]
fn serde_round_trip_gate_failure_code() {
    for variant in [
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
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: GateFailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[test]
fn serde_round_trip_optimization_proof_artifact() {
    let artifact = ok_artifact("inline");
    let json = serde_json::to_string(&artifact).unwrap();
    let parsed: OptimizationProofArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, parsed);
}

#[test]
fn serde_round_trip_proof_chain_bundle() {
    let bundle = base_input().bundle;
    let json = serde_json::to_string(&bundle).unwrap();
    let parsed: ProofChainBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, parsed);
}

#[test]
fn serde_round_trip_test_evidence_bundle() {
    let evidence = base_input().test_evidence.expect("test evidence");
    let json = serde_json::to_string(&evidence).unwrap();
    let parsed: TestEvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, parsed);
}

#[test]
fn serde_round_trip_release_gate_input() {
    let input = base_input();
    let json = serde_json::to_string(&input).unwrap();
    let parsed: ReleaseGateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, parsed);
}

#[test]
fn serde_round_trip_release_gate_thresholds() {
    let thresholds = ReleaseGateThresholds::default();
    let json = serde_json::to_string(&thresholds).unwrap();
    let parsed: ReleaseGateThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(thresholds, parsed);
}

#[test]
fn serde_round_trip_gate_finding() {
    let finding = GateFinding {
        code: GateFailureCode::MissingProofArtifact,
        optimization_pass: Some("inline".to_string()),
        detail: "expected optimization pass has no proof artifact".to_string(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let parsed: GateFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, parsed);
}

#[test]
fn serde_round_trip_promotion_decision_artifact() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let json = serde_json::to_string(&decision).unwrap();
    let parsed: PromotionDecisionArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, parsed);
}

// ===========================================================================
// ReleaseGateThresholds — Default
// ===========================================================================

#[test]
fn default_thresholds_replay_multiplier() {
    let thresholds = ReleaseGateThresholds::default();
    assert_eq!(thresholds.max_replay_multiplier_millionths, 5_000_000);
    assert_eq!(thresholds.min_unit_coverage_millionths, 900_000);
    assert_eq!(thresholds.min_mutation_score_millionths, 850_000);
    assert_eq!(thresholds.max_logging_artifact_age_ns, 3_600_000_000_000);
    assert!(thresholds.require_trace_correlated_logging);
}

// ===========================================================================
// evaluate_release_gate — pass scenario
// ===========================================================================

#[test]
fn gate_passes_for_complete_replayable_pipeline() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(decision.pass);
    assert!(decision.findings.is_empty());
}

#[test]
fn gate_pass_has_correct_candidate_version() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert_eq!(decision.candidate_version, "candidate-2026-02-20");
}

#[test]
fn gate_pass_replay_multiplier_computed_correctly() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    // 200_000_000 / 50_000_000 = 4x = 4_000_000 ppm
    assert_eq!(decision.replay_multiplier_millionths, 4_000_000);
}

#[test]
fn gate_pass_rollback_token_derived_from_decision_id() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(decision.rollback_token.starts_with("rollback-"));
    assert!(
        decision
            .decision_id
            .starts_with(&decision.rollback_token["rollback-".len()..])
    );
}

// ===========================================================================
// evaluate_release_gate — logs
// ===========================================================================

#[test]
fn gate_pass_emits_three_logs() {
    // 2 artifacts + 1 summary decision log
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert_eq!(decision.logs.len(), 3);
}

#[test]
fn gate_pass_last_log_is_decision_event() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    let last = decision.logs.last().unwrap();
    assert_eq!(last.event, "release_gate_decision");
    assert_eq!(last.outcome, "pass");
    assert!(last.error_code.is_none());
    assert!(last.optimization_pass.is_none());
    assert_eq!(last.component, "proof_release_gate");
}

#[test]
fn gate_pass_artifact_logs_carry_proof_data() {
    let input = base_input();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    for log in &decision.logs[..2] {
        assert_eq!(log.event, "optimization_proof_evaluated");
        assert_eq!(log.outcome, "verified");
        assert_eq!(log.trace_id, "trace-gate-1");
        assert_eq!(log.policy_id, "policy-opt-gate");
        assert_eq!(log.component, "proof_release_gate");
        assert!(log.optimization_pass.is_some());
        assert!(log.proof_hash.is_some());
        assert!(log.proof_status.as_deref() == Some("verified"));
        assert_eq!(log.fallback_triggered, Some(false));
        assert!(log.verification_time_ns.is_some());
        assert!(log.ir_diff_size_bytes.is_some());
    }
}

// ===========================================================================
// evaluate_release_gate — decision_id determinism
// ===========================================================================

#[test]
fn decision_id_is_deterministic() {
    let input = base_input();
    let thresholds = ReleaseGateThresholds::default();
    let d1 = evaluate_release_gate(&input, &thresholds);
    let d2 = evaluate_release_gate(&input, &thresholds);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_changes_with_different_trace() {
    let mut input_a = base_input();
    input_a.trace_id = "trace-A".to_string();
    let mut input_b = base_input();
    input_b.trace_id = "trace-B".to_string();
    let thresholds = ReleaseGateThresholds::default();
    let d1 = evaluate_release_gate(&input_a, &thresholds);
    let d2 = evaluate_release_gate(&input_b, &thresholds);
    assert_ne!(d1.decision_id, d2.decision_id);
}

#[test]
fn decision_id_is_hex_string() {
    let decision = evaluate_release_gate(&base_input(), &ReleaseGateThresholds::default());
    assert!(
        decision.decision_id.chars().all(|c| c.is_ascii_hexdigit()),
        "decision_id should be hex: {}",
        decision.decision_id
    );
}

// ===========================================================================
// evaluate — failure: MissingProofArtifact
// ===========================================================================

#[test]
fn gate_fails_missing_proof_artifact() {
    let mut input = base_input();
    input.bundle.artifacts = vec![ok_artifact("inline")]; // missing "dce"
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == GateFailureCode::MissingProofArtifact
            && f.optimization_pass.as_deref() == Some("dce")
    }));
}

#[test]
fn gate_fails_missing_all_proof_artifacts() {
    let mut input = base_input();
    input.bundle.artifacts.clear();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    let missing: Vec<_> = decision
        .findings
        .iter()
        .filter(|f| f.code == GateFailureCode::MissingProofArtifact)
        .collect();
    assert_eq!(missing.len(), 2);
}

// ===========================================================================
// evaluate — failure: MissingBundleField
// ===========================================================================

#[test]
fn gate_fails_empty_optimization_pass_name() {
    let mut input = base_input();
    input.bundle.artifacts[0].optimization_pass = "".to_string();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_proof_hash() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_hash = [0u8; 32];
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_pre_ir_hash() {
    let mut input = base_input();
    input.bundle.artifacts[0].pre_ir_hash = [0u8; 32];
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_post_ir_hash() {
    let mut input = base_input();
    input.bundle.artifacts[0].post_ir_hash = [0u8; 32];
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_ir_diff_size() {
    let mut input = base_input();
    input.bundle.artifacts[0].ir_diff_size_bytes = 0;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_proof_generation_time() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_generation_time_ns = 0;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_zero_verification_time() {
    let mut input = base_input();
    input.bundle.artifacts[0].verification_time_ns = 0;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_empty_verifier_version() {
    let mut input = base_input();
    input.bundle.artifacts[0].verifier_version = "".to_string();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

#[test]
fn gate_fails_empty_replay_command() {
    let mut input = base_input();
    input.bundle.artifacts[0].replay_command = "  ".to_string();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingBundleField)
    );
}

// ===========================================================================
// evaluate — failure: ProofVerificationFailed
// ===========================================================================

#[test]
fn gate_fails_proof_not_verified_but_optimization_applied() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = true;
    // Also set valid fallback so we isolate this specific check
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-1".to_string());
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == GateFailureCode::ProofVerificationFailed
            && f.optimization_pass.as_deref() == Some("inline")
    }));
}

// ===========================================================================
// evaluate — failure: FallbackPathInvalid
// ===========================================================================

#[test]
fn gate_fails_fallback_not_triggered_on_failed_proof() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = false;
    input.bundle.artifacts[0].fallback_receipt_id = None;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
    );
}

#[test]
fn gate_fails_fallback_triggered_but_no_receipt() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = None;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
    );
}

#[test]
fn gate_fails_fallback_receipt_is_whitespace() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = Some("  ".to_string());
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::FallbackPathInvalid)
    );
}

#[test]
fn gate_passes_when_fallback_path_is_valid() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = Some("receipt-001".to_string());
    input.bundle.artifacts[0].independent_replay_verified = false;
    // With valid fallback, FallbackPathInvalid should NOT appear
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    let has_fallback_invalid = decision
        .findings
        .iter()
        .any(|f| f.code == GateFailureCode::FallbackPathInvalid);
    assert!(
        !has_fallback_invalid,
        "valid fallback should not produce FallbackPathInvalid"
    );
}

// ===========================================================================
// evaluate — failure: IndependentReplayFailed
// ===========================================================================

#[test]
fn gate_fails_independent_replay_not_verified() {
    let mut input = base_input();
    input.bundle.artifacts[0].independent_replay_verified = false;
    // proof_verified is true, so IndependentReplayFailed applies
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(decision.findings.iter().any(|f| {
        f.code == GateFailureCode::IndependentReplayFailed
            && f.optimization_pass.as_deref() == Some("inline")
    }));
}

// ===========================================================================
// evaluate — failure: ReplayMultiplierExceeded
// ===========================================================================

#[test]
fn gate_fails_replay_multiplier_exceeds_default_threshold() {
    let mut input = base_input();
    // 6x = 6_000_000 ppm > 5_000_000
    input.bundle.replay_time_ns = 300_000_000;
    input.bundle.original_compile_time_ns = 50_000_000;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
    );
    assert_eq!(decision.replay_multiplier_millionths, 6_000_000);
}

#[test]
fn gate_passes_replay_multiplier_at_exactly_threshold() {
    let mut input = base_input();
    // 5x = 5_000_000 ppm = 5_000_000 (not > threshold)
    input.bundle.replay_time_ns = 250_000_000;
    input.bundle.original_compile_time_ns = 50_000_000;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    let has_replay_exceeded = decision
        .findings
        .iter()
        .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded);
    assert!(
        !has_replay_exceeded,
        "exactly at threshold should not produce ReplayMultiplierExceeded"
    );
}

#[test]
fn gate_fails_zero_compile_time_gives_max_multiplier() {
    let mut input = base_input();
    input.bundle.original_compile_time_ns = 0;
    input.bundle.replay_time_ns = 1;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded)
    );
    assert_eq!(decision.replay_multiplier_millionths, u64::MAX);
}

#[test]
fn gate_passes_with_custom_relaxed_threshold() {
    let mut input = base_input();
    input.bundle.replay_time_ns = 300_000_000; // 6x
    let thresholds = ReleaseGateThresholds {
        max_replay_multiplier_millionths: 10_000_000, // 10x
        ..ReleaseGateThresholds::default()
    };
    let decision = evaluate_release_gate(&input, &thresholds);
    let has_replay_exceeded = decision
        .findings
        .iter()
        .any(|f| f.code == GateFailureCode::ReplayMultiplierExceeded);
    assert!(!has_replay_exceeded);
}

// ===========================================================================
// evaluate — failure: ArchiveNotContentAddressed
// ===========================================================================

#[test]
fn gate_fails_non_cas_archive_uri() {
    let mut input = base_input();
    input.bundle.archive_uri = "https://storage.example.com/archive".to_string();
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
    );
}

#[test]
fn gate_fails_cas_uri_with_zero_root() {
    let mut input = base_input();
    input.bundle.archive_root = [0u8; 32];
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::ArchiveNotContentAddressed)
    );
}

// ===========================================================================
// evaluate — fail-closed test/e2e/logging evidence policy
// ===========================================================================

#[test]
fn gate_fails_when_test_evidence_bundle_missing() {
    let mut input = base_input();
    input.test_evidence = None;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::MissingTestEvidence)
    );
}

#[test]
fn gate_fails_when_unit_coverage_below_threshold() {
    let mut input = base_input();
    let evidence = input.test_evidence.as_mut().expect("test evidence");
    evidence.unit_coverage_millionths = 200_000;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::TestEvidenceBelowThreshold)
    );
}

#[test]
fn gate_fails_when_logging_artifacts_stale() {
    let mut input = base_input();
    let evidence = input.test_evidence.as_mut().expect("test evidence");
    evidence.logging_artifact_max_age_ns = 10_000_000_000_000;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::LoggingArtifactsStale)
    );
}

#[test]
fn gate_fails_when_logging_not_trace_correlated() {
    let mut input = base_input();
    let evidence = input.test_evidence.as_mut().expect("test evidence");
    evidence.trace_correlated_logging = false;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    assert!(
        decision
            .findings
            .iter()
            .any(|f| f.code == GateFailureCode::LoggingArtifactsUncorrelated)
    );
}

// ===========================================================================
// evaluate — multiple failures accumulate
// ===========================================================================

#[test]
fn gate_accumulates_multiple_failure_codes() {
    let mut input = base_input();
    // Remove one artifact → MissingProofArtifact
    input.bundle.artifacts = vec![ok_artifact("inline")];
    // Bad archive → ArchiveNotContentAddressed
    input.bundle.archive_uri = "s3://bucket/archive".to_string();
    // Excessive replay → ReplayMultiplierExceeded
    input.bundle.replay_time_ns = 500_000_000; // 10x
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    let codes: BTreeSet<_> = decision.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&GateFailureCode::MissingProofArtifact));
    assert!(codes.contains(&GateFailureCode::ArchiveNotContentAddressed));
    assert!(codes.contains(&GateFailureCode::ReplayMultiplierExceeded));
}

// ===========================================================================
// evaluate — fail decision log
// ===========================================================================

#[test]
fn gate_fail_decision_log_has_error_code() {
    let mut input = base_input();
    input.bundle.artifacts[0].independent_replay_verified = false;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(!decision.pass);
    let last = decision.logs.last().unwrap();
    assert_eq!(last.event, "release_gate_decision");
    assert_eq!(last.outcome, "fail");
    assert!(last.error_code.is_some());
}

#[test]
fn gate_fail_artifact_log_carries_failed_status() {
    let mut input = base_input();
    input.bundle.artifacts[0].proof_verified = false;
    input.bundle.artifacts[0].optimization_applied = false;
    input.bundle.artifacts[0].fallback_triggered = true;
    input.bundle.artifacts[0].fallback_receipt_id = Some("r-1".to_string());
    input.bundle.artifacts[0].independent_replay_verified = false;
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    let inline_log = decision
        .logs
        .iter()
        .find(|l| l.optimization_pass.as_deref() == Some("inline"))
        .unwrap();
    assert_eq!(inline_log.outcome, "failed");
    assert_eq!(
        inline_log.error_code.as_deref(),
        Some("proof_verification_failed")
    );
    assert_eq!(inline_log.proof_status.as_deref(), Some("failed"));
}

// ===========================================================================
// GateFailureCode — Ord
// ===========================================================================

#[test]
fn failure_code_ord_follows_declaration_order() {
    let mut v = [
        GateFailureCode::ArchiveNotContentAddressed,
        GateFailureCode::MissingProofArtifact,
        GateFailureCode::ReplayMultiplierExceeded,
        GateFailureCode::FallbackPathInvalid,
        GateFailureCode::ProofVerificationFailed,
        GateFailureCode::IndependentReplayFailed,
        GateFailureCode::MissingBundleField,
    ];
    v.sort();
    assert_eq!(v[0], GateFailureCode::MissingProofArtifact);
    assert_eq!(v[1], GateFailureCode::MissingBundleField);
    assert_eq!(v[2], GateFailureCode::ProofVerificationFailed);
    assert_eq!(v[3], GateFailureCode::FallbackPathInvalid);
    assert_eq!(v[4], GateFailureCode::IndependentReplayFailed);
    assert_eq!(v[5], GateFailureCode::ReplayMultiplierExceeded);
    assert_eq!(v[6], GateFailureCode::ArchiveNotContentAddressed);
}

// ===========================================================================
// evaluate — single-artifact pipeline pass
// ===========================================================================

#[test]
fn gate_passes_single_artifact_pipeline() {
    let mut input = base_input();
    input.expected_optimization_passes = BTreeSet::from(["inline".to_string()]);
    input.bundle.artifacts = vec![ok_artifact("inline")];
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(decision.pass);
    assert!(decision.findings.is_empty());
    assert_eq!(decision.logs.len(), 2); // 1 artifact + 1 decision
}

// ===========================================================================
// evaluate — extra artifact does not cause failure
// ===========================================================================

#[test]
fn gate_passes_with_extra_artifact_beyond_expected() {
    let mut input = base_input();
    input.bundle.artifacts.push(ok_artifact("loop_unroll"));
    let decision = evaluate_release_gate(&input, &ReleaseGateThresholds::default());
    assert!(decision.pass);
    assert!(decision.findings.is_empty());
    assert_eq!(decision.logs.len(), 4); // 3 artifacts + 1 decision
}
