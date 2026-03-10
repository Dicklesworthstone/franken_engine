#![forbid(unsafe_code)]

//! Integration tests for FRX-20.6 milestone/release test-evidence integrator.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::cut_line_automation::{CutLine, GateCategory};
use frankenengine_engine::milestone_release_test_evidence_integrator::*;
use frankenengine_engine::release_checklist_gate::{
    ChecklistCategory, ChecklistItem, ChecklistItemStatus, ReleaseChecklist,
};

// ── Helpers ──────────────────────────────────────────────────────────────

fn signed_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
    EvidenceArtifactLink {
        artifact_id: format!("{prefix}-artifact"),
        path: format!("artifacts/{prefix}/run_manifest.json"),
        sha256: format!("{prefix}abcdef1234567890"),
        signature_status: SignatureStatus::Signed,
        signer: Some("maintainer@franken.engine".to_string()),
        signature_ref: Some(format!("sig:{prefix}")),
        generated_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
    }
}

fn unsigned_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
    EvidenceArtifactLink {
        artifact_id: format!("{prefix}-artifact"),
        path: format!("artifacts/{prefix}/run_manifest.json"),
        sha256: format!("{prefix}abcdef1234567890"),
        signature_status: SignatureStatus::Unsigned,
        signer: None,
        signature_ref: None,
        generated_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
    }
}

fn baseline_signal(source: EvidenceSource, score: i64, now_ns: u64) -> EvidenceSignal {
    let mut metadata = BTreeMap::new();
    if source == EvidenceSource::FlakeQuarantineWorkflow {
        metadata.insert("flake_burden_millionths".to_string(), "90000".to_string());
    }
    EvidenceSignal {
        source,
        passed: true,
        score_millionths: score,
        collected_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
        evidence_refs: vec![format!("docs/{}.json", source.as_str())],
        artifact_links: vec![signed_artifact(source.as_str(), now_ns)],
        metadata,
    }
}

fn all_signals(score: i64, now_ns: u64) -> Vec<EvidenceSignal> {
    EvidenceSource::REQUIRED
        .iter()
        .map(|s| baseline_signal(*s, score, now_ns))
        .collect()
}

fn baseline_input(now_ns: u64) -> TestEvidenceIntegratorInput {
    TestEvidenceIntegratorInput {
        cut_line: CutLine::C4,
        release_tag: "v0.9.0-rc1".to_string(),
        now_ns,
        trace_id: "trace-integration".to_string(),
        decision_id: "decision-integration".to_string(),
        policy_id: "policy-integration-v1".to_string(),
        signals: all_signals(980_000, now_ns),
        previous_summary: None,
    }
}

fn empty_checklist() -> ReleaseChecklist {
    ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc1".to_string(),
        generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
        trace_id: "trace-integration".to_string(),
        decision_id: "decision-integration".to_string(),
        policy_id: "policy-integration-v1".to_string(),
        items: Vec::new(),
    }
}

// ── Section 1: Constants ─────────────────────────────────────────────────

#[test]
fn constants_component_name() {
    assert_eq!(
        TEST_EVIDENCE_INTEGRATOR_COMPONENT,
        "frx_milestone_release_test_evidence_integrator"
    );
}

#[test]
fn constants_contract_schema_version() {
    assert_eq!(
        TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION,
        "frx.milestone-release-test-evidence-integrator.contract.v1"
    );
}

#[test]
fn constants_event_schema_version() {
    assert_eq!(
        TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION,
        "frx.milestone-release-test-evidence-integrator.event.v1"
    );
}

#[test]
fn constants_failure_code() {
    assert_eq!(
        TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE,
        "FE-FRX-20-6-TEST-EVIDENCE-INTEGRATOR-0001"
    );
}

// ── Section 2: EvidenceSource enum ───────────────────────────────────────

#[test]
fn evidence_source_required_contains_all_five_variants() {
    assert_eq!(EvidenceSource::REQUIRED.len(), 5);
    let set: BTreeSet<EvidenceSource> = EvidenceSource::REQUIRED.iter().copied().collect();
    assert!(set.contains(&EvidenceSource::UnitDepthGate));
    assert!(set.contains(&EvidenceSource::EndToEndScenarioMatrix));
    assert!(set.contains(&EvidenceSource::TestLoggingSchema));
    assert!(set.contains(&EvidenceSource::FlakeQuarantineWorkflow));
    assert!(set.contains(&EvidenceSource::ProofCarryingArtifactGate));
}

#[test]
fn evidence_source_as_str_all_variants() {
    assert_eq!(EvidenceSource::UnitDepthGate.as_str(), "unit_depth_gate");
    assert_eq!(
        EvidenceSource::EndToEndScenarioMatrix.as_str(),
        "end_to_end_scenario_matrix"
    );
    assert_eq!(
        EvidenceSource::TestLoggingSchema.as_str(),
        "test_logging_schema"
    );
    assert_eq!(
        EvidenceSource::FlakeQuarantineWorkflow.as_str(),
        "flake_quarantine_workflow"
    );
    assert_eq!(
        EvidenceSource::ProofCarryingArtifactGate.as_str(),
        "proof_carrying_artifact_gate"
    );
}

#[test]
fn evidence_source_gate_categories_unit_depth() {
    let cats = EvidenceSource::UnitDepthGate.gate_categories();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0], GateCategory::CompilerCorrectness);
}

#[test]
fn evidence_source_gate_categories_e2e_two_categories() {
    let cats = EvidenceSource::EndToEndScenarioMatrix.gate_categories();
    assert_eq!(cats.len(), 2);
    assert_eq!(cats[0], GateCategory::RuntimeParity);
    assert_eq!(cats[1], GateCategory::DeterministicReplay);
}

#[test]
fn evidence_source_gate_categories_logging() {
    let cats = EvidenceSource::TestLoggingSchema.gate_categories();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0], GateCategory::ObservabilityIntegrity);
}

#[test]
fn evidence_source_gate_categories_flake() {
    let cats = EvidenceSource::FlakeQuarantineWorkflow.gate_categories();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0], GateCategory::FlakeBurden);
}

#[test]
fn evidence_source_gate_categories_proof_carrying() {
    let cats = EvidenceSource::ProofCarryingArtifactGate.gate_categories();
    assert_eq!(cats.len(), 2);
    assert_eq!(cats[0], GateCategory::GovernanceCompliance);
    assert_eq!(cats[1], GateCategory::HandoffReadiness);
}

#[test]
fn evidence_source_release_checklist_bindings_all() {
    let cases: Vec<(EvidenceSource, &str, ChecklistCategory)> = vec![
        (
            EvidenceSource::UnitDepthGate,
            "security.conformance_suite",
            ChecklistCategory::Security,
        ),
        (
            EvidenceSource::EndToEndScenarioMatrix,
            "operational.diagnostics_cli_test",
            ChecklistCategory::Operational,
        ),
        (
            EvidenceSource::TestLoggingSchema,
            "operational.evidence_export_test",
            ChecklistCategory::Operational,
        ),
        (
            EvidenceSource::FlakeQuarantineWorkflow,
            "security.adversarial_corpus",
            ChecklistCategory::Security,
        ),
        (
            EvidenceSource::ProofCarryingArtifactGate,
            "reproducibility.manifest_json",
            ChecklistCategory::Reproducibility,
        ),
    ];
    for (source, expected_id, expected_cat) in cases {
        let (id, cat) = source.release_checklist_binding();
        assert_eq!(id, expected_id, "binding for {:?}", source);
        assert_eq!(cat, expected_cat, "category for {:?}", source);
    }
}

#[test]
fn evidence_source_serde_roundtrip_all_variants() {
    for source in EvidenceSource::REQUIRED {
        let json = serde_json::to_string(&source).unwrap();
        let back: EvidenceSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, source);
    }
}

#[test]
fn evidence_source_serde_uses_snake_case() {
    let json = serde_json::to_string(&EvidenceSource::UnitDepthGate).unwrap();
    assert_eq!(json, "\"unit_depth_gate\"");
    let json = serde_json::to_string(&EvidenceSource::EndToEndScenarioMatrix).unwrap();
    assert_eq!(json, "\"end_to_end_scenario_matrix\"");
}

// ── Section 3: SignatureStatus serde ─────────────────────────────────────

#[test]
fn signature_status_serde_roundtrip() {
    for status in [
        SignatureStatus::Signed,
        SignatureStatus::Unsigned,
        SignatureStatus::Invalid,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: SignatureStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }
}

#[test]
fn signature_status_debug_format() {
    assert_eq!(format!("{:?}", SignatureStatus::Signed), "Signed");
    assert_eq!(format!("{:?}", SignatureStatus::Unsigned), "Unsigned");
    assert_eq!(format!("{:?}", SignatureStatus::Invalid), "Invalid");
}

// ── Section 4: EvidenceArtifactLink serde ────────────────────────────────

#[test]
fn evidence_artifact_link_serde_roundtrip() {
    let link = signed_artifact("test", 10_000);
    let json = serde_json::to_string(&link).unwrap();
    let back: EvidenceArtifactLink = serde_json::from_str(&json).unwrap();
    assert_eq!(back, link);
}

#[test]
fn evidence_artifact_link_serde_with_none_fields() {
    let link = unsigned_artifact("test", 10_000);
    let json = serde_json::to_string(&link).unwrap();
    let back: EvidenceArtifactLink = serde_json::from_str(&json).unwrap();
    assert_eq!(back.signer, None);
    assert_eq!(back.signature_ref, None);
}

// ── Section 5: EvidenceSignal serde ──────────────────────────────────────

#[test]
fn evidence_signal_serde_roundtrip() {
    let sig = baseline_signal(EvidenceSource::UnitDepthGate, 950_000, 10_000);
    let json = serde_json::to_string(&sig).unwrap();
    let back: EvidenceSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back, sig);
}

#[test]
fn evidence_signal_with_metadata_serde_roundtrip() {
    let sig = baseline_signal(EvidenceSource::FlakeQuarantineWorkflow, 950_000, 10_000);
    assert!(sig.metadata.contains_key("flake_burden_millionths"));
    let json = serde_json::to_string(&sig).unwrap();
    let back: EvidenceSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(back.metadata, sig.metadata);
}

// ── Section 6: IntegratorPolicy ──────────────────────────────────────────

#[test]
fn integrator_policy_default_values() {
    let p = IntegratorPolicy::default();
    assert_eq!(p.max_signal_age_ns, 3_600_000_000_000);
    assert_eq!(p.min_schema_major, 1);
    assert!(p.require_signed_artifacts);
    assert_eq!(p.max_flake_burden_millionths, 120_000);
    assert_eq!(p.minimum_cut_line_scores_millionths.len(), 6);
}

#[test]
fn integrator_policy_threshold_for_all_known_cut_lines() {
    let p = IntegratorPolicy::default();
    assert_eq!(p.threshold_for_cut_line(CutLine::C0), 900_000);
    assert_eq!(p.threshold_for_cut_line(CutLine::C1), 930_000);
    assert_eq!(p.threshold_for_cut_line(CutLine::C2), 940_000);
    assert_eq!(p.threshold_for_cut_line(CutLine::C3), 950_000);
    assert_eq!(p.threshold_for_cut_line(CutLine::C4), 965_000);
    assert_eq!(p.threshold_for_cut_line(CutLine::C5), 975_000);
}

#[test]
fn integrator_policy_threshold_unknown_cut_line_defaults_to_930k() {
    // Clear the map so no cut line matches
    let mut p = IntegratorPolicy::default();
    p.minimum_cut_line_scores_millionths.clear();
    // Every cut line should now return the fallback of 930_000
    assert_eq!(p.threshold_for_cut_line(CutLine::C4), 930_000);
}

#[test]
fn integrator_policy_serde_roundtrip() {
    let p = IntegratorPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: IntegratorPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

// ── Section 7: integrate — happy path ────────────────────────────────────

#[test]
fn integrate_allows_with_complete_signed_inputs() {
    let input = baseline_input(10_000);
    let policy = IntegratorPolicy::default();
    let decision = integrate_milestone_release_test_evidence(&input, &policy);

    assert!(decision.allows_promotion());
    assert_eq!(decision.outcome, "allow");
    assert_eq!(decision.error_code, None);
    assert_eq!(
        decision.schema_version,
        TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(decision.component, TEST_EVIDENCE_INTEGRATOR_COMPONENT);
    assert_eq!(decision.trace_id, "trace-integration");
    assert_eq!(decision.release_tag, "v0.9.0-rc1");
}

#[test]
fn integrate_happy_path_signed_evidence_links_non_empty() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.signed_evidence_links.is_empty());
    // Each source with signed artifacts should produce links for each gate category
    // 5 sources: UnitDepth=1, E2E=2, Logging=1, Flake=1, ProofCarrying=2 => 7 total
    assert_eq!(decision.signed_evidence_links.len(), 7);
}

#[test]
fn integrate_happy_path_quality_summary_aggregate_score() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    // All scores 980k => aggregate = (980k*30 + 980k*30 + 980k*20 + 980k*10 + 980k*10)/100 = 980k
    assert_eq!(decision.quality_summary.aggregate_score_millionths, 980_000);
    assert_eq!(
        decision.quality_summary.unit_depth_score_millionths,
        980_000
    );
    assert_eq!(
        decision.quality_summary.e2e_stability_score_millionths,
        980_000
    );
    assert_eq!(
        decision.quality_summary.logging_integrity_score_millionths,
        980_000
    );
    assert_eq!(
        decision.quality_summary.flake_resilience_score_millionths,
        980_000
    );
    assert_eq!(
        decision.quality_summary.artifact_integrity_score_millionths,
        980_000
    );
}

#[test]
fn integrate_happy_path_queue_risk_millionths() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    // queue_risk = clamp(1_000_000 - 980_000) = 20_000
    assert_eq!(decision.queue_risk_millionths, 20_000);
}

#[test]
fn integrate_happy_path_no_blockers() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(decision.blockers.is_empty());
}

// ── Section 8: integrate — missing signals ───────────────────────────────

#[test]
fn integrate_fails_closed_when_one_source_missing() {
    let mut input = baseline_input(20_000);
    input
        .signals
        .retain(|s| s.source != EvidenceSource::TestLoggingSchema);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert_eq!(decision.outcome, "deny");
    assert_eq!(
        decision.error_code,
        Some(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string())
    );
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing required signal"))
    );
}

#[test]
fn integrate_fails_closed_when_all_sources_missing() {
    let mut input = baseline_input(20_000);
    input.signals.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    // Should have at least 5 missing-required blockers + 1 aggregate-below threshold
    assert!(decision.blockers.len() >= 6);
}

#[test]
fn integrate_fails_on_duplicate_signal() {
    let mut input = baseline_input(20_000);
    // Add a duplicate UnitDepthGate signal
    input.signals.push(baseline_signal(
        EvidenceSource::UnitDepthGate,
        980_000,
        20_000,
    ));
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("duplicate evidence signal"))
    );
}

// ── Section 9: integrate — validation failures ───────────────────────────

#[test]
fn integrate_rejects_negative_score() {
    let mut input = baseline_input(30_000);
    input.signals[0].score_millionths = -1;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("out of range"))
    );
}

#[test]
fn integrate_rejects_score_over_million() {
    let mut input = baseline_input(30_000);
    input.signals[0].score_millionths = 1_000_001;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("out of range"))
    );
}

#[test]
fn integrate_rejects_empty_evidence_refs() {
    let mut input = baseline_input(30_000);
    input.signals[0].evidence_refs.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing evidence_refs"))
    );
}

#[test]
fn integrate_rejects_empty_artifact_links() {
    let mut input = baseline_input(30_000);
    input.signals[0].artifact_links.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing artifact links"))
    );
}

#[test]
fn integrate_rejects_old_schema_major() {
    let input = baseline_input(30_000);
    let policy = IntegratorPolicy {
        min_schema_major: 2,
        ..IntegratorPolicy::default()
    };
    // All signals have schema_major=1
    let decision = integrate_milestone_release_test_evidence(&input, &policy);

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("schema_major"))
    );
}

#[test]
fn integrate_rejects_future_collected_at() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].collected_at_ns = now_ns + 1000;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("in the future"))
    );
}

#[test]
fn integrate_rejects_stale_signal() {
    let now_ns = 100_000_000_000_000u64;
    let mut input = baseline_input(now_ns);
    // Make the first signal very old
    input.signals[0].collected_at_ns = 1;
    input.signals[0].artifact_links[0].generated_at_ns = 1;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("signal stale"))
    );
}

#[test]
fn integrate_rejects_unsigned_artifact_when_policy_requires_signed() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links = vec![unsigned_artifact("test", now_ns)];
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("not signed"))
    );
}

#[test]
fn integrate_allows_unsigned_when_policy_does_not_require() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    // Replace all artifacts with unsigned
    for sig in &mut input.signals {
        sig.artifact_links = vec![unsigned_artifact(sig.source.as_str(), now_ns)];
    }
    let policy = IntegratorPolicy {
        require_signed_artifacts: false,
        ..IntegratorPolicy::default()
    };
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    // Should still allow since all pass and scores meet threshold
    assert!(decision.allows_promotion());
}

#[test]
fn integrate_rejects_artifact_missing_signer() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].signer = None;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing signer"))
    );
}

#[test]
fn integrate_rejects_artifact_missing_signature_ref() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].signature_ref = None;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing signature_ref"))
    );
}

#[test]
fn integrate_rejects_artifact_empty_artifact_id() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].artifact_id = "  ".to_string();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing artifact_id"))
    );
}

#[test]
fn integrate_rejects_artifact_empty_path() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].path = "".to_string();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing path"))
    );
}

#[test]
fn integrate_rejects_artifact_empty_sha256() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].sha256 = "".to_string();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("missing sha256"))
    );
}

#[test]
fn integrate_rejects_artifact_future_generated_at() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].generated_at_ns = now_ns + 5000;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("generated_at_ns is in the future"))
    );
}

#[test]
fn integrate_rejects_stale_artifact() {
    let now_ns = 100_000_000_000_000u64;
    let mut input = baseline_input(now_ns);
    input.signals[0].artifact_links[0].generated_at_ns = 1;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("artifact") && f.message.contains("stale"))
    );
}

#[test]
fn integrate_rejects_artifact_old_schema_major() {
    let now_ns = 30_000u64;
    let input = baseline_input(now_ns);
    let policy = IntegratorPolicy {
        min_schema_major: 2,
        ..IntegratorPolicy::default()
    };
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    assert!(!decision.allows_promotion());
    // Both signal and artifact have schema_major=1 < min=2
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("schema_major"))
    );
}

// ── Section 10: Flake burden validation ──────────────────────────────────

#[test]
fn integrate_rejects_excessive_flake_burden() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    // Find the flake signal and set a high burden
    for sig in &mut input.signals {
        if sig.source == EvidenceSource::FlakeQuarantineWorkflow {
            sig.metadata
                .insert("flake_burden_millionths".to_string(), "200000".to_string());
        }
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("flake burden"))
    );
}

#[test]
fn integrate_rejects_invalid_flake_burden_value() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        if sig.source == EvidenceSource::FlakeQuarantineWorkflow {
            sig.metadata.insert(
                "flake_burden_millionths".to_string(),
                "not_a_number".to_string(),
            );
        }
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("invalid flake_burden_millionths"))
    );
}

#[test]
fn integrate_accepts_flake_burden_at_max() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        if sig.source == EvidenceSource::FlakeQuarantineWorkflow {
            sig.metadata
                .insert("flake_burden_millionths".to_string(), "120000".to_string());
        }
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    // At exactly the max, no flake burden finding
    assert!(
        !decision
            .blockers
            .iter()
            .any(|f| f.message.contains("flake burden")),
        "flake burden at max should not trigger blocker"
    );
}

// ── Section 11: Aggregate threshold failures ─────────────────────────────

#[test]
fn integrate_denies_when_aggregate_below_cut_line_threshold() {
    // C4 threshold = 965_000. Set all scores to 900_000 => aggregate = 900_000 < 965_000
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        sig.score_millionths = 900_000;
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|f| f.message.contains("aggregate_score_millionths")
                && f.message.contains("below cut-line"))
    );
}

#[test]
fn integrate_weighted_aggregate_calculation() {
    // unit_depth=1M, e2e=0, logging=1M, flake=1M, artifact=1M
    // aggregate = (1M*30 + 0*30 + 1M*20 + 1M*10 + 1M*10)/100 = 700_000
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        if sig.source == EvidenceSource::EndToEndScenarioMatrix {
            sig.score_millionths = 0;
        } else {
            sig.score_millionths = 1_000_000;
        }
    }
    // Use C0 threshold (900k) — 700k < 900k => deny
    input.cut_line = CutLine::C0;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert_eq!(decision.quality_summary.aggregate_score_millionths, 700_000);
    assert!(!decision.allows_promotion());
}

// ── Section 12: Previous summary deltas ──────────────────────────────────

#[test]
fn integrate_computes_deltas_from_previous_summary() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    input.previous_summary = Some(MilestoneQualitySummary {
        cut_line: CutLine::C3,
        aggregate_score_millionths: 970_000,
        unit_depth_score_millionths: 960_000,
        e2e_stability_score_millionths: 970_000,
        logging_integrity_score_millionths: 975_000,
        flake_resilience_score_millionths: 950_000,
        artifact_integrity_score_millionths: 955_000,
        delta_from_previous_millionths: BTreeMap::new(),
    });

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let deltas = &decision.quality_summary.delta_from_previous_millionths;

    assert!(deltas.contains_key("aggregate"));
    assert!(deltas.contains_key("unit_depth"));
    assert!(deltas.contains_key("e2e_stability"));
    assert!(deltas.contains_key("logging_integrity"));
    assert!(deltas.contains_key("flake_resilience"));
    assert!(deltas.contains_key("artifact_integrity"));

    // All signals at 980k
    assert_eq!(deltas["unit_depth"], 980_000 - 960_000);
    assert_eq!(deltas["e2e_stability"], 980_000 - 970_000);
    assert_eq!(deltas["flake_resilience"], 980_000 - 950_000);
}

#[test]
fn integrate_no_deltas_when_no_previous_summary() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(
        decision
            .quality_summary
            .delta_from_previous_millionths
            .is_empty()
    );
}

// ── Section 13: TestEvidenceIntegrationDecision ──────────────────────────

#[test]
fn decision_allows_promotion_true_for_allow() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(decision.allows_promotion());
}

#[test]
fn decision_allows_promotion_false_for_deny() {
    let mut input = baseline_input(10_000);
    input.signals.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(!decision.allows_promotion());
}

#[test]
fn decision_serde_roundtrip() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let json = serde_json::to_string(&decision).unwrap();
    let back: TestEvidenceIntegrationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

// ── Section 14: emit_integration_events ──────────────────────────────────

#[test]
fn emit_events_produces_one_event() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    assert_eq!(events.len(), 1);
}

#[test]
fn emit_events_mirrors_decision_fields() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    let ev = &events[0];

    assert_eq!(
        ev.schema_version,
        TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION
    );
    assert_eq!(ev.trace_id, decision.trace_id);
    assert_eq!(ev.decision_id, decision.decision_id);
    assert_eq!(ev.policy_id, decision.policy_id);
    assert_eq!(ev.component, TEST_EVIDENCE_INTEGRATOR_COMPONENT);
    assert_eq!(ev.event, "integration_completed");
    assert_eq!(ev.outcome, decision.outcome);
    assert_eq!(ev.error_code, decision.error_code);
    assert_eq!(ev.cut_line, decision.cut_line.as_str());
    assert_eq!(ev.release_tag, decision.release_tag);
    assert_eq!(ev.blocker_count, decision.blockers.len());
    assert_eq!(
        ev.aggregate_score_millionths,
        decision.quality_summary.aggregate_score_millionths
    );
    assert_eq!(ev.queue_risk_millionths, decision.queue_risk_millionths);
}

#[test]
fn emit_events_for_denied_decision() {
    let mut input = baseline_input(10_000);
    input.signals.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    let ev = &events[0];

    assert_eq!(ev.outcome, "deny");
    assert_eq!(
        ev.error_code,
        Some(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string())
    );
    assert!(ev.blocker_count > 0);
}

#[test]
fn event_serde_roundtrip() {
    let input = baseline_input(10_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let events = emit_integration_events(&decision);
    let json = serde_json::to_string(&events[0]).unwrap();
    let back: TestEvidenceIntegratorEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, events[0]);
}

// ── Section 15: to_cut_line_gate_inputs ──────────────────────────────────

#[test]
fn cut_line_gate_inputs_include_all_expected_categories() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);

    let categories: BTreeSet<GateCategory> = gates.iter().map(|g| g.category).collect();
    assert!(categories.contains(&GateCategory::CompilerCorrectness));
    assert!(categories.contains(&GateCategory::RuntimeParity));
    assert!(categories.contains(&GateCategory::DeterministicReplay));
    assert!(categories.contains(&GateCategory::ObservabilityIntegrity));
    assert!(categories.contains(&GateCategory::FlakeBurden));
    assert!(categories.contains(&GateCategory::GovernanceCompliance));
    assert!(categories.contains(&GateCategory::HandoffReadiness));
}

#[test]
fn cut_line_gate_inputs_count_matches_total_gate_categories() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);

    // UnitDepth=1, E2E=2, Logging=1, Flake=1, ProofCarrying=2 => 7
    assert_eq!(gates.len(), 7);
}

#[test]
fn cut_line_gate_inputs_passed_false_when_blocked() {
    let mut input = baseline_input(30_000);
    // Make unit depth signal have a negative score to trigger a blocker
    input.signals[0].score_millionths = -1;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);

    let unit_gate = gates
        .iter()
        .find(|g| g.category == GateCategory::CompilerCorrectness)
        .unwrap();
    assert!(
        !unit_gate.passed,
        "blocked signal should mark gate as not passed"
    );
}

#[test]
fn cut_line_gate_inputs_metadata_includes_source() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);

    for gate in &gates {
        assert!(
            gate.metadata.contains_key("source"),
            "gate input should have source in metadata"
        );
    }
}

#[test]
fn cut_line_gate_inputs_evidence_refs_deduplicated() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    // Add an evidence_ref that matches an artifact path
    let artifact_path = input.signals[0].artifact_links[0].path.clone();
    input.signals[0].evidence_refs.push(artifact_path);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);

    let unit_gate = gates
        .iter()
        .find(|g| g.category == GateCategory::CompilerCorrectness)
        .unwrap();
    // Check no duplicates in evidence_refs
    let set: BTreeSet<_> = unit_gate.evidence_refs.iter().collect();
    assert_eq!(
        set.len(),
        unit_gate.evidence_refs.len(),
        "evidence refs should be deduplicated"
    );
}

// ── Section 16: apply_to_release_checklist ───────────────────────────────

#[test]
fn apply_checklist_marks_all_five_items_pass() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    assert_eq!(checklist.items.len(), 5);
    for item in &checklist.items {
        assert_eq!(item.status, ChecklistItemStatus::Pass);
        assert!(item.required);
        assert!(item.waiver.is_none());
        assert!(!item.artifact_refs.is_empty());
    }
}

#[test]
fn apply_checklist_items_sorted_by_id() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let ids: Vec<&str> = checklist.items.iter().map(|i| i.item_id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

#[test]
fn apply_checklist_marks_fail_when_source_blocked() {
    let mut input = baseline_input(40_000);
    // Remove UnitDepthGate signal => blocker
    input
        .signals
        .retain(|s| s.source != EvidenceSource::UnitDepthGate);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let security_item = checklist
        .items
        .iter()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap();
    assert_eq!(security_item.status, ChecklistItemStatus::Fail);
}

#[test]
fn apply_checklist_updates_existing_items() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    // Pre-populate with a stale item
    checklist.items.push(ChecklistItem {
        item_id: "security.conformance_suite".to_string(),
        category: ChecklistCategory::Performance, // wrong, should be updated
        required: false,
        status: ChecklistItemStatus::NotRun,
        artifact_refs: Vec::new(),
        waiver: None,
    });

    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let item = checklist
        .items
        .iter()
        .find(|i| i.item_id == "security.conformance_suite")
        .unwrap();
    assert_eq!(item.category, ChecklistCategory::Security);
    assert!(item.required);
    assert_eq!(item.status, ChecklistItemStatus::Pass);
}

#[test]
fn apply_checklist_artifact_refs_include_signed_links() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    // The reproducibility.manifest_json item should have artifact refs including signed links
    let repro = checklist
        .items
        .iter()
        .find(|i| i.item_id == "reproducibility.manifest_json")
        .unwrap();
    // Should have refs from both signal artifacts and signed evidence links
    assert!(repro.artifact_refs.len() >= 2);
}

// ── Section 17: Input serde ──────────────────────────────────────────────

#[test]
fn input_serde_roundtrip() {
    let input = baseline_input(10_000);
    let json = serde_json::to_string(&input).unwrap();
    let back: TestEvidenceIntegratorInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
}

// ── Section 18: IntegrationFinding / SignedEvidenceLink serde ────────────

#[test]
fn integration_finding_serde_roundtrip() {
    let f = IntegrationFinding {
        source: Some(EvidenceSource::UnitDepthGate),
        error_code: "TEST-001".to_string(),
        message: "something went wrong".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: IntegrationFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

#[test]
fn integration_finding_with_none_source() {
    let f = IntegrationFinding {
        source: None,
        error_code: "TEST-002".to_string(),
        message: "aggregate too low".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: IntegrationFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source, None);
}

#[test]
fn signed_evidence_link_serde_roundtrip() {
    let link = SignedEvidenceLink {
        evidence_source: EvidenceSource::ProofCarryingArtifactGate,
        gate_category: "governance_compliance".to_string(),
        artifact_id: "art-1".to_string(),
        artifact_sha256: "abcd1234".to_string(),
        signer: "signer@example.com".to_string(),
        signature_ref: "sig:ref:1".to_string(),
    };
    let json = serde_json::to_string(&link).unwrap();
    let back: SignedEvidenceLink = serde_json::from_str(&json).unwrap();
    assert_eq!(back, link);
}

// ── Section 19: MilestoneQualitySummary serde ────────────────────────────

#[test]
fn quality_summary_serde_roundtrip() {
    let mut deltas = BTreeMap::new();
    deltas.insert("aggregate".to_string(), 5000);
    let summary = MilestoneQualitySummary {
        cut_line: CutLine::C3,
        aggregate_score_millionths: 970_000,
        unit_depth_score_millionths: 960_000,
        e2e_stability_score_millionths: 970_000,
        logging_integrity_score_millionths: 975_000,
        flake_resilience_score_millionths: 950_000,
        artifact_integrity_score_millionths: 955_000,
        delta_from_previous_millionths: deltas,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: MilestoneQualitySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ── Section 20: Edge cases and combined scenarios ────────────────────────

#[test]
fn integrate_all_scores_zero_still_produces_decision() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        sig.score_millionths = 0;
    }
    input.cut_line = CutLine::C0;
    let mut policy = IntegratorPolicy::default();
    policy
        .minimum_cut_line_scores_millionths
        .insert("C0".to_string(), 0);
    let decision = integrate_milestone_release_test_evidence(&input, &policy);

    // aggregate = 0, threshold = 0, so 0 >= 0 does not trigger blocker
    assert_eq!(decision.quality_summary.aggregate_score_millionths, 0);
    // queue_risk = clamp(1_000_000 - 0) = 1_000_000
    assert_eq!(decision.queue_risk_millionths, 1_000_000);
    assert!(decision.allows_promotion());
}

#[test]
fn integrate_all_scores_million_max() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        sig.score_millionths = 1_000_000;
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert_eq!(
        decision.quality_summary.aggregate_score_millionths,
        1_000_000
    );
    assert_eq!(decision.queue_risk_millionths, 0);
    assert!(decision.allows_promotion());
}

#[test]
fn integrate_c0_lower_threshold_allows_lower_scores() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    for sig in &mut input.signals {
        sig.score_millionths = 910_000;
    }
    input.cut_line = CutLine::C0;
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    // 910_000 >= 900_000 (C0 threshold) => no threshold blocker
    assert!(decision.allows_promotion());
}

#[test]
fn integrate_multiple_artifact_links_per_signal() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    // Add a second artifact to the first signal
    let mut second = signed_artifact("extra", now_ns);
    second.artifact_id = "extra-artifact-2".to_string();
    input.signals[0].artifact_links.push(second);

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(decision.allows_promotion());
}

#[test]
fn apply_checklist_with_signal_not_passed_marks_fail() {
    let now_ns = 40_000u64;
    let mut input = baseline_input(now_ns);
    // Mark the logging schema signal as not passed
    for sig in &mut input.signals {
        if sig.source == EvidenceSource::TestLoggingSchema {
            sig.passed = false;
        }
    }
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = empty_checklist();
    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let logging_item = checklist
        .items
        .iter()
        .find(|i| i.item_id == "operational.evidence_export_test")
        .unwrap();
    assert_eq!(logging_item.status, ChecklistItemStatus::Fail);
}

#[test]
fn cut_line_gate_inputs_with_no_signals_empty() {
    let mut input = baseline_input(30_000);
    input.signals.clear();
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gates = to_cut_line_gate_inputs(&decision, &input.signals);
    assert!(gates.is_empty());
}

#[test]
fn signed_evidence_links_omitted_when_no_signed_artifact() {
    let now_ns = 30_000u64;
    let mut input = baseline_input(now_ns);
    // Replace all artifacts with unsigned
    for sig in &mut input.signals {
        sig.artifact_links = vec![unsigned_artifact(sig.source.as_str(), now_ns)];
    }
    let policy = IntegratorPolicy {
        require_signed_artifacts: false,
        ..IntegratorPolicy::default()
    };
    let decision = integrate_milestone_release_test_evidence(&input, &policy);
    assert!(
        decision.signed_evidence_links.is_empty(),
        "no signed artifacts => no signed evidence links"
    );
}
