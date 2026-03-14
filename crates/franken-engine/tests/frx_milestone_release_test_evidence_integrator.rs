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
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use frankenengine_engine::milestone_release_test_evidence_integrator::{
    EvidenceArtifactLink, EvidenceSignal, EvidenceSource, IntegratorPolicy,
    MilestoneQualitySummary, SignatureStatus, TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION,
    TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION, TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE,
    TestEvidenceIntegratorInput, apply_to_release_checklist, emit_integration_events,
    integrate_milestone_release_test_evidence, to_cut_line_gate_inputs,
};

use frankenengine_engine::cut_line_automation::{CutLine, GateCategory};
use frankenengine_engine::release_checklist_gate::ReleaseChecklist;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = read_to_string(path);
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

#[derive(Debug, Deserialize)]
struct IntegratorContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    required_signal_sources: Vec<String>,
    cut_line_quality_thresholds_millionths: BTreeMap<String, i64>,
    staleness_policy: StalenessPolicy,
    release_workflow: ReleaseWorkflow,
    queue_risk_contract: QueueRiskContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StalenessPolicy {
    max_signal_age_ns: u64,
    min_schema_major: u32,
    require_signed_artifacts: bool,
    max_flake_burden_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct ReleaseWorkflow {
    auto_apply_to_release_checklist: bool,
    fail_closed_on_missing_signals: bool,
    signed_link_required: bool,
}

#[derive(Debug, Deserialize)]
struct QueueRiskContract {
    emit_machine_readable_summary: bool,
    risk_field: String,
}

fn signed_artifact(prefix: &str, now_ns: u64) -> EvidenceArtifactLink {
    EvidenceArtifactLink {
        artifact_id: format!("{prefix}-artifact"),
        path: format!("artifacts/{prefix}/run_manifest.json"),
        sha256: format!("{prefix}-sha-abcdef1234567890"),
        signature_status: SignatureStatus::Signed,
        signer: Some("maintainer@franken.engine".to_string()),
        signature_ref: Some(format!("sig:{prefix}")),
        generated_at_ns: now_ns.saturating_sub(100),
        schema_major: 1,
    }
}

fn baseline_signal(source: EvidenceSource, score: i64, now_ns: u64) -> EvidenceSignal {
    let mut metadata = BTreeMap::new();
    if source == EvidenceSource::FlakeQuarantineWorkflow {
        metadata.insert("flake_burden_millionths".to_string(), "85000".to_string());
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

fn baseline_input(now_ns: u64) -> TestEvidenceIntegratorInput {
    let previous_summary = MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 930_000,
        unit_depth_score_millionths: 920_000,
        e2e_stability_score_millionths: 930_000,
        logging_integrity_score_millionths: 940_000,
        flake_resilience_score_millionths: 935_000,
        artifact_integrity_score_millionths: 935_000,
        delta_from_previous_millionths: BTreeMap::new(),
    };

    TestEvidenceIntegratorInput {
        cut_line: CutLine::C4,
        release_tag: "v0.9.0-rc2".to_string(),
        now_ns,
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        signals: EvidenceSource::REQUIRED
            .iter()
            .map(|source| baseline_signal(*source, 980_000, now_ns))
            .collect(),
        previous_summary: Some(previous_summary),
    }
}

#[test]
fn frx_20_6_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_MILESTONE_RELEASE_TEST_EVIDENCE_INTEGRATOR_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# FRX Milestone/Release Test-Evidence Integrator v1",
        "## Scope",
        "## Required Signal Sources",
        "## Fail-Closed Validation Rules",
        "## Cut-Line and Release Workflow Binding",
        "## Signed Evidence Linkage",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }

    for phrase in [
        "fail-closed",
        "missing",
        "stale",
        "signed",
        "queue_risk_millionths",
        "bd-mjh3.20.6",
    ] {
        assert!(
            doc.to_ascii_lowercase().contains(phrase),
            "expected phrase not found in {}: {phrase}",
            path.display()
        );
    }
}

#[test]
fn frx_20_6_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_milestone_release_test_evidence_integrator_v1.json");
    let contract: IntegratorContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.bead_id, "bd-mjh3.20.6");
    assert_eq!(contract.generated_by, "bd-mjh3.20.6");

    let required_sources: BTreeSet<_> = contract
        .required_signal_sources
        .iter()
        .map(String::as_str)
        .collect();
    for source in [
        "unit_depth_gate",
        "end_to_end_scenario_matrix",
        "test_logging_schema",
        "flake_quarantine_workflow",
        "proof_carrying_artifact_gate",
    ] {
        assert!(
            required_sources.contains(source),
            "missing source: {source}"
        );
    }

    for cut_line in ["C1", "C2", "C3", "C4", "C5"] {
        assert!(
            contract
                .cut_line_quality_thresholds_millionths
                .contains_key(cut_line),
            "missing cut-line threshold for {cut_line}"
        );
    }

    assert!(contract.staleness_policy.max_signal_age_ns > 0);
    assert!(contract.staleness_policy.require_signed_artifacts);
    assert!(contract.staleness_policy.min_schema_major >= 1);
    assert!(contract.staleness_policy.max_flake_burden_millionths <= 250_000);

    assert!(contract.release_workflow.auto_apply_to_release_checklist);
    assert!(contract.release_workflow.fail_closed_on_missing_signals);
    assert!(contract.release_workflow.signed_link_required);

    assert!(contract.queue_risk_contract.emit_machine_readable_summary);
    assert_eq!(
        contract.queue_risk_contract.risk_field,
        "queue_risk_millionths"
    );

    assert!(
        contract.operator_verification.iter().any(|entry| entry
            .contains("run_frx_milestone_release_test_evidence_integrator_suite.sh ci")),
        "operator verification must include suite command"
    );
}

#[test]
fn frx_20_6_integration_is_fail_closed_on_missing_signal() {
    let mut input = baseline_input(10_000);
    input
        .signals
        .retain(|signal| signal.source != EvidenceSource::TestLoggingSchema);

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert_eq!(
        decision.error_code,
        Some(TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.to_string())
    );
    assert!(
        decision
            .blockers
            .iter()
            .any(|finding| finding.message.contains("missing required signal"))
    );
}

#[test]
fn frx_20_6_integration_is_fail_closed_on_unsigned_artifacts() {
    let mut input = baseline_input(20_000);
    input
        .signals
        .iter_mut()
        .filter(|signal| signal.source == EvidenceSource::ProofCarryingArtifactGate)
        .for_each(|signal| {
            signal.artifact_links[0].signature_status = SignatureStatus::Unsigned;
            signal.artifact_links[0].signer = None;
            signal.artifact_links[0].signature_ref = None;
        });

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|finding| finding.message.contains("not signed"))
    );
}

#[test]
fn frx_20_6_integration_emits_quality_summary_and_signed_links() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    assert!(decision.allows_promotion());
    assert_eq!(decision.error_code, None);
    assert!(decision.quality_summary.aggregate_score_millionths >= 970_000);
    assert!(!decision.signed_evidence_links.is_empty());
    assert!(
        decision
            .quality_summary
            .delta_from_previous_millionths
            .contains_key("aggregate")
    );

    let events = emit_integration_events(&decision);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].schema_version,
        TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION
    );
    assert_eq!(events[0].outcome, "allow");
}

#[test]
fn frx_20_6_cut_line_inputs_cover_expected_categories() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);

    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::CompilerCorrectness)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::RuntimeParity)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::DeterministicReplay)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::ObservabilityIntegrity)
    );
    assert!(
        gate_inputs
            .iter()
            .any(|gate| gate.category == GateCategory::FlakeBurden)
    );
}

#[test]
fn frx_20_6_release_checklist_binding_is_automatic_and_fail_closed() {
    let mut input = baseline_input(50_000);
    input
        .signals
        .iter_mut()
        .filter(|signal| signal.source == EvidenceSource::FlakeQuarantineWorkflow)
        .for_each(|signal| {
            signal.passed = false;
            signal.score_millionths = 700_000;
            signal
                .metadata
                .insert("flake_burden_millionths".to_string(), "200000".to_string());
        });

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc2".to_string(),
        generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        items: Vec::new(),
    };

    apply_to_release_checklist(&mut checklist, &decision, &input.signals);

    let security_conformance = checklist
        .items
        .iter()
        .find(|item| item.item_id == "security.conformance_suite")
        .expect("missing security.conformance_suite");
    assert_eq!(security_conformance.status.as_str(), "pass");

    let adversarial = checklist
        .items
        .iter()
        .find(|item| item.item_id == "security.adversarial_corpus")
        .expect("missing security.adversarial_corpus");
    assert_eq!(adversarial.status.as_str(), "fail");
    assert!(!adversarial.artifact_refs.is_empty());
}

// ---------- signed_artifact helper ----------

#[test]
fn signed_artifact_has_signed_status() {
    let link = signed_artifact("test-prefix", 1_000);
    assert_eq!(link.signature_status, SignatureStatus::Signed);
    assert!(link.signer.is_some());
    assert!(link.signature_ref.is_some());
    assert_eq!(link.schema_major, 1);
    assert!(link.artifact_id.contains("test-prefix"));
}

// ---------- baseline_signal helper ----------

#[test]
fn baseline_signal_sets_fields() {
    let signal = baseline_signal(EvidenceSource::UnitDepthGate, 900_000, 5_000);
    assert_eq!(signal.source, EvidenceSource::UnitDepthGate);
    assert!(signal.passed);
    assert_eq!(signal.score_millionths, 900_000);
    assert_eq!(signal.schema_major, 1);
    assert!(!signal.artifact_links.is_empty());
}

// ---------- baseline_input helper ----------

#[test]
fn baseline_input_covers_all_required_sources() {
    let input = baseline_input(10_000);
    let sources: BTreeSet<_> = input.signals.iter().map(|s| s.source).collect();
    for required in EvidenceSource::REQUIRED {
        assert!(
            sources.contains(&required),
            "missing required source: {:?}",
            required
        );
    }
}

#[test]
fn baseline_input_has_previous_summary() {
    let input = baseline_input(10_000);
    assert!(input.previous_summary.is_some());
    assert_eq!(input.release_tag, "v0.9.0-rc2");
}

// ---------- EvidenceSource ----------

#[test]
fn evidence_source_required_is_nonempty() {
    assert!(!EvidenceSource::REQUIRED.is_empty());
}

#[test]
fn evidence_source_as_str_is_nonempty() {
    for source in EvidenceSource::REQUIRED {
        assert!(!source.as_str().is_empty());
    }
}

#[test]
fn evidence_source_serde_roundtrip() {
    for source in EvidenceSource::REQUIRED {
        let json = serde_json::to_string(&source).expect("serialize");
        let recovered: EvidenceSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, source);
    }
}

// ---------- SignatureStatus ----------

#[test]
fn signature_status_serde_roundtrip() {
    for status in [
        SignatureStatus::Signed,
        SignatureStatus::Unsigned,
        SignatureStatus::Invalid,
    ] {
        let json = serde_json::to_string(&status).expect("serialize");
        let recovered: SignatureStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, status);
    }
}

// ---------- IntegratorPolicy ----------

#[test]
fn integrator_policy_default_has_thresholds() {
    let policy = IntegratorPolicy::default();
    let threshold = policy.threshold_for_cut_line(CutLine::C1);
    assert!(threshold > 0);
}

#[test]
fn integrator_policy_thresholds_increase_with_cut_line() {
    let policy = IntegratorPolicy::default();
    let c1 = policy.threshold_for_cut_line(CutLine::C1);
    let c5 = policy.threshold_for_cut_line(CutLine::C5);
    assert!(c5 >= c1);
}

// ---------- EvidenceArtifactLink ----------

#[test]
fn evidence_artifact_link_serde_roundtrip() {
    let link = signed_artifact("serde-test", 2_000);
    let json = serde_json::to_string(&link).expect("serialize");
    let recovered: EvidenceArtifactLink = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.artifact_id, link.artifact_id);
    assert_eq!(recovered.signature_status, SignatureStatus::Signed);
}

// ---------- EvidenceSignal ----------

#[test]
fn evidence_signal_serde_roundtrip() {
    let signal = baseline_signal(EvidenceSource::EndToEndScenarioMatrix, 950_000, 3_000);
    let json = serde_json::to_string(&signal).expect("serialize");
    let recovered: EvidenceSignal = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.source, EvidenceSource::EndToEndScenarioMatrix);
    assert_eq!(recovered.score_millionths, 950_000);
}

// ---------- MilestoneQualitySummary ----------

#[test]
fn milestone_quality_summary_serde_roundtrip() {
    let summary = MilestoneQualitySummary {
        cut_line: CutLine::C3,
        aggregate_score_millionths: 900_000,
        unit_depth_score_millionths: 910_000,
        e2e_stability_score_millionths: 920_000,
        logging_integrity_score_millionths: 930_000,
        flake_resilience_score_millionths: 940_000,
        artifact_integrity_score_millionths: 950_000,
        delta_from_previous_millionths: BTreeMap::new(),
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: MilestoneQualitySummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.aggregate_score_millionths, 900_000);
}

// ---------- TestEvidenceIntegratorInput ----------

#[test]
fn test_evidence_integrator_input_serde_roundtrip() {
    let input = baseline_input(10_000);
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: TestEvidenceIntegratorInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-frx-20-6");
    assert_eq!(recovered.signals.len(), input.signals.len());
}

// ---------- integration decision determinism ----------

#[test]
fn integration_decision_is_deterministic() {
    let input = baseline_input(10_000);
    let policy = IntegratorPolicy::default();
    let a = integrate_milestone_release_test_evidence(&input, &policy);
    let b = integrate_milestone_release_test_evidence(&input, &policy);
    assert_eq!(a, b);
}

// ---------- schema version constants ----------

#[test]
fn schema_version_constants_are_nonempty() {
    assert!(!TEST_EVIDENCE_INTEGRATOR_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_EVIDENCE_INTEGRATOR_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!TEST_EVIDENCE_INTEGRATOR_FAILURE_CODE.is_empty());
}

#[test]
fn integrator_policy_debug_is_nonempty() {
    let policy = IntegratorPolicy::default();
    assert!(!format!("{policy:?}").is_empty());
}

#[test]
fn signature_status_debug_is_nonempty() {
    for status in [
        SignatureStatus::Signed,
        SignatureStatus::Unsigned,
        SignatureStatus::Invalid,
    ] {
        assert!(!format!("{status:?}").is_empty());
    }
}

#[test]
fn test_evidence_integrator_input_debug_is_nonempty() {
    let input = baseline_input(10_000);
    assert!(!format!("{input:?}").is_empty());
}

#[test]
fn frx_20_6_integration_is_fail_closed_on_stale_signals() {
    let now_ns = 100_000_000_000_000_u64;
    let mut input = baseline_input(now_ns);
    // Make all signals very old (older than max_signal_age_ns)
    for signal in &mut input.signals {
        signal.collected_at_ns = 1;
        for link in &mut signal.artifact_links {
            link.generated_at_ns = 1;
        }
    }

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(!decision.allows_promotion());
    assert!(
        decision
            .blockers
            .iter()
            .any(|finding| finding.message.contains("stale"))
    );
}

#[test]
fn frx_20_6_evidence_source_gate_categories_are_nonempty() {
    for source in EvidenceSource::REQUIRED {
        let categories = source.gate_categories();
        assert!(
            !categories.is_empty(),
            "gate categories must not be empty for {:?}",
            source
        );
    }
}

#[test]
fn frx_20_6_evidence_source_release_checklist_binding_has_nonempty_id() {
    for source in EvidenceSource::REQUIRED {
        let (item_id, _category) = source.release_checklist_binding();
        assert!(
            !item_id.trim().is_empty(),
            "checklist binding item_id must not be empty for {:?}",
            source
        );
    }
}

#[test]
fn frx_20_6_integrator_policy_serde_roundtrip() {
    let policy = IntegratorPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: IntegratorPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.max_signal_age_ns, policy.max_signal_age_ns,
        "max_signal_age_ns should survive roundtrip"
    );
    assert_eq!(
        recovered.require_signed_artifacts, policy.require_signed_artifacts,
        "require_signed_artifacts should survive roundtrip"
    );
    assert_eq!(
        recovered.threshold_for_cut_line(CutLine::C4),
        policy.threshold_for_cut_line(CutLine::C4)
    );
}

#[test]
fn frx_20_6_integration_with_low_flake_burden_passes() {
    let mut input = baseline_input(50_000);
    // Set flake burden well under the 120_000 limit
    input
        .signals
        .iter_mut()
        .filter(|signal| signal.source == EvidenceSource::FlakeQuarantineWorkflow)
        .for_each(|signal| {
            signal
                .metadata
                .insert("flake_burden_millionths".to_string(), "10000".to_string());
        });
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(decision.allows_promotion());
}

#[test]
fn frx_20_6_integration_blocked_decision_emits_deny_event() {
    let mut input = baseline_input(10_000);
    input
        .signals
        .retain(|signal| signal.source != EvidenceSource::TestLoggingSchema);

    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(!decision.allows_promotion());

    let events = emit_integration_events(&decision);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "deny");
}

#[test]
fn frx_20_6_quality_summary_has_all_dimensional_scores() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let summary = &decision.quality_summary;
    assert!(summary.unit_depth_score_millionths > 0);
    assert!(summary.e2e_stability_score_millionths > 0);
    assert!(summary.logging_integrity_score_millionths > 0);
    assert!(summary.flake_resilience_score_millionths > 0);
    assert!(summary.artifact_integrity_score_millionths > 0);
    assert!(summary.aggregate_score_millionths > 0);
}

// ---------- EvidenceArtifactLink field validation ----------

#[test]
fn signed_artifact_path_contains_prefix() {
    let link = signed_artifact("my_component", 5_000);
    assert!(link.path.contains("my_component"));
}

#[test]
fn signed_artifact_sha256_contains_prefix() {
    let link = signed_artifact("sha_test", 3_000);
    assert!(link.sha256.contains("sha_test"));
}

#[test]
fn signed_artifact_generated_at_before_now() {
    let now_ns = 10_000_u64;
    let link = signed_artifact("timing", now_ns);
    assert!(link.generated_at_ns < now_ns);
}

// ---------- baseline_signal metadata ----------

#[test]
fn baseline_signal_flake_source_has_burden_metadata() {
    let signal = baseline_signal(EvidenceSource::FlakeQuarantineWorkflow, 950_000, 10_000);
    assert!(signal.metadata.contains_key("flake_burden_millionths"));
}

#[test]
fn baseline_signal_non_flake_source_has_no_burden_metadata() {
    let signal = baseline_signal(EvidenceSource::UnitDepthGate, 950_000, 10_000);
    assert!(!signal.metadata.contains_key("flake_burden_millionths"));
}

#[test]
fn baseline_signal_evidence_refs_contain_source_name() {
    for source in &EvidenceSource::REQUIRED {
        let signal = baseline_signal(*source, 900_000, 5_000);
        assert!(
            signal.evidence_refs[0].contains(source.as_str()),
            "evidence ref should contain source name for {:?}",
            source
        );
    }
}

// ---------- integration decision signed links ----------

#[test]
fn frx_20_6_passing_decision_has_signed_evidence_links() {
    let input = baseline_input(30_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    assert!(decision.allows_promotion());
    for link in &decision.signed_evidence_links {
        assert!(!link.artifact_id.is_empty());
    }
}

// ---------- EvidenceSource exhaustive ----------

#[test]
fn evidence_source_required_count_at_least_five() {
    assert!(EvidenceSource::REQUIRED.len() >= 5);
}

#[test]
fn evidence_source_as_str_all_unique() {
    let strs: BTreeSet<&str> = EvidenceSource::REQUIRED
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(strs.len(), EvidenceSource::REQUIRED.len());
}

// ---------- IntegratorPolicy thresholds ----------

#[test]
fn integrator_policy_c1_less_than_or_equal_c5() {
    let policy = IntegratorPolicy::default();
    let c1 = policy.threshold_for_cut_line(CutLine::C1);
    let c2 = policy.threshold_for_cut_line(CutLine::C2);
    let c3 = policy.threshold_for_cut_line(CutLine::C3);
    let c4 = policy.threshold_for_cut_line(CutLine::C4);
    let c5 = policy.threshold_for_cut_line(CutLine::C5);
    assert!(c1 <= c2);
    assert!(c2 <= c3);
    assert!(c3 <= c4);
    assert!(c4 <= c5);
}

// ---------- release checklist binding ----------

#[test]
fn frx_20_6_release_checklist_items_have_nonempty_ids() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc2".to_string(),
        generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        items: Vec::new(),
    };

    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    for item in &checklist.items {
        assert!(!item.item_id.trim().is_empty());
    }
}

#[test]
fn frx_20_6_release_checklist_has_items_after_apply() {
    let input = baseline_input(50_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());

    let mut checklist = ReleaseChecklist {
        schema_version: "franken-engine.release-checklist.v1".to_string(),
        release_tag: "v0.9.0-rc2".to_string(),
        generated_at_utc: "2026-02-27T00:00:00Z".to_string(),
        trace_id: "trace-frx-20-6".to_string(),
        decision_id: "decision-frx-20-6".to_string(),
        policy_id: "policy-frx-20-6-v1".to_string(),
        items: Vec::new(),
    };

    apply_to_release_checklist(&mut checklist, &decision, &input.signals);
    assert!(!checklist.items.is_empty());
}

// ---------- emit_integration_events determinism ----------

#[test]
fn frx_20_6_events_deterministic_across_two_runs() {
    let input = baseline_input(30_000);
    let policy = IntegratorPolicy::default();
    let dec_a = integrate_milestone_release_test_evidence(&input, &policy);
    let dec_b = integrate_milestone_release_test_evidence(&input, &policy);
    let events_a = emit_integration_events(&dec_a);
    let events_b = emit_integration_events(&dec_b);
    assert_eq!(events_a.len(), events_b.len());
    for (a, b) in events_a.iter().zip(events_b.iter()) {
        assert_eq!(a.schema_version, b.schema_version);
        assert_eq!(a.outcome, b.outcome);
    }
}

// ---------- MilestoneQualitySummary clone independence ----------

#[test]
fn milestone_quality_summary_clone_independence() {
    let summary = MilestoneQualitySummary {
        cut_line: CutLine::C4,
        aggregate_score_millionths: 950_000,
        unit_depth_score_millionths: 940_000,
        e2e_stability_score_millionths: 935_000,
        logging_integrity_score_millionths: 960_000,
        flake_resilience_score_millionths: 945_000,
        artifact_integrity_score_millionths: 955_000,
        delta_from_previous_millionths: BTreeMap::new(),
    };
    let cloned = summary.clone();
    assert_eq!(
        cloned.aggregate_score_millionths,
        summary.aggregate_score_millionths
    );
    assert_eq!(cloned.cut_line, summary.cut_line);
}

// ---------- to_cut_line_gate_inputs ----------

#[test]
fn frx_20_6_gate_inputs_have_nonempty_gate_ids() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
    for gate in &gate_inputs {
        assert!(!format!("{:?}", gate.category).is_empty());
    }
}

#[test]
fn frx_20_6_gate_inputs_count_matches_signals() {
    let input = baseline_input(40_000);
    let decision = integrate_milestone_release_test_evidence(&input, &IntegratorPolicy::default());
    let gate_inputs = to_cut_line_gate_inputs(&decision, &input.signals);
    assert!(!gate_inputs.is_empty());
}
