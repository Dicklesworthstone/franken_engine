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

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct GatingPolicy {
    minimum_passed_verifiers: u32,
    max_open_risk_score_millionths: u64,
    fail_on_evidence_statuses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EvidenceArtifact {
    evidence_id: String,
    status: String,
    required: bool,
    manifest_path: String,
    replay_command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EvidenceStatus {
    Pass,
    InProgress,
    Fail,
    Missing,
}

impl EvidenceStatus {
    fn parse(raw: &str) -> Self {
        match raw {
            "pass" => Self::Pass,
            "in_progress" => Self::InProgress,
            "fail" => Self::Fail,
            "missing" => Self::Missing,
            other => panic!("unknown evidence status: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    fn parse(raw: &str) -> Self {
        match raw {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            other => panic!("unknown severity: {other}"),
        }
    }

    fn weight(self) -> u64 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResidualRisk {
    risk_id: String,
    severity: String,
    likelihood_millionths: u32,
    impact_millionths: u32,
    owner: String,
    mitigation: String,
    trigger_threshold: String,
    rollback_trigger_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct RollbackTrigger {
    trigger_id: String,
    metric: String,
    comparison: String,
    threshold_millionths: u32,
    recovery_command: String,
    blast_radius_assumption: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationOutcome {
    Pass,
    Hold,
    Fail,
}

impl VerificationOutcome {
    fn parse(raw: &str) -> Self {
        match raw {
            "pass" => Self::Pass,
            "hold" => Self::Hold,
            "fail" => Self::Fail,
            other => panic!("unknown verification outcome: {other}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct IndependentVerification {
    verifier_id: String,
    outcome: String,
    manifest_path: String,
    replay_command: String,
    signed_off: bool,
}

#[derive(Debug, Deserialize)]
struct ClaimReplayCommand {
    claim_id: String,
    replay_command: String,
    expected_outcome: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_fail_reasons: Vec<String>,
    expected_hold_reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ParserFinalReadinessDossierFixture {
    schema_version: String,
    dossier_version: String,
    log_schema_version: String,
    dossier_id: String,
    bead_id: String,
    required_log_keys: Vec<String>,
    blocked_dependency_ids: Vec<String>,
    gating_policy: GatingPolicy,
    evidence_artifacts: Vec<EvidenceArtifact>,
    residual_risks: Vec<ResidualRisk>,
    rollback_triggers: Vec<RollbackTrigger>,
    independent_verification: Vec<IndependentVerification>,
    claim_replay_commands: Vec<ClaimReplayCommand>,
    expected_gate: ExpectedGate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RankedRisk {
    risk_id: String,
    score_millionths: u64,
    severity_weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    fail_reasons: Vec<String>,
    hold_reasons: Vec<String>,
    passed_verifiers: usize,
    ranked_open_risks: Vec<RankedRisk>,
    risk_register_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReadinessEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    dossier_id: String,
    risk_register_hash: String,
    replay_command: String,
    blocked_dependency_count: usize,
    hold_reason_count: usize,
    fail_reason_count: usize,
}

fn load_fixture() -> ParserFinalReadinessDossierFixture {
    let path = Path::new("tests/fixtures/parser_final_readiness_dossier_v1.json");
    let bytes = fs::read(path).expect("read parser final readiness dossier fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser final readiness dossier fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_FINAL_READINESS_DOSSIER.md");
    fs::read_to_string(path).expect("read parser final readiness dossier doc")
}

fn comparison_matches(raw: &str) -> bool {
    matches!(raw, ">" | ">=" | "<" | "<=")
}

fn open_risk_score_millionths(risk: &ResidualRisk) -> u64 {
    let likelihood = u64::from(risk.likelihood_millionths);
    let impact = u64::from(risk.impact_millionths);
    likelihood.saturating_mul(impact) / 1_000_000_u64
}

fn rank_open_risks(risks: &[ResidualRisk]) -> Vec<RankedRisk> {
    let mut ranked = risks
        .iter()
        .filter(|risk| risk.status == "open")
        .map(|risk| {
            let severity = Severity::parse(risk.severity.as_str());
            RankedRisk {
                risk_id: risk.risk_id.clone(),
                score_millionths: open_risk_score_millionths(risk),
                severity_weight: severity.weight(),
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by_key(|entry| {
        (
            Reverse(entry.score_millionths),
            Reverse(entry.severity_weight),
            entry.risk_id.clone(),
        )
    });
    ranked
}

fn compute_risk_register_hash(risks: &[ResidualRisk]) -> String {
    #[derive(Serialize)]
    struct RiskHashRow<'a> {
        risk_id: &'a str,
        severity: &'a str,
        likelihood_millionths: u32,
        impact_millionths: u32,
        owner: &'a str,
        status: &'a str,
        rollback_trigger_id: &'a str,
        trigger_threshold: &'a str,
    }

    let mut rows = risks
        .iter()
        .map(|risk| RiskHashRow {
            risk_id: risk.risk_id.as_str(),
            severity: risk.severity.as_str(),
            likelihood_millionths: risk.likelihood_millionths,
            impact_millionths: risk.impact_millionths,
            owner: risk.owner.as_str(),
            status: risk.status.as_str(),
            rollback_trigger_id: risk.rollback_trigger_id.as_str(),
            trigger_threshold: risk.trigger_threshold.as_str(),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| a.risk_id.cmp(b.risk_id));

    let canonical = serde_json::to_vec(&rows).expect("serialize canonical risk hash rows");
    let digest = Sha256::digest(canonical);
    format!("sha256:{digest:x}")
}

fn evaluate_dossier(fixture: &ParserFinalReadinessDossierFixture) -> GateEvaluation {
    let fail_statuses = fixture
        .gating_policy
        .fail_on_evidence_statuses
        .iter()
        .map(|status| EvidenceStatus::parse(status))
        .collect::<BTreeSet<_>>();

    let trigger_by_id = fixture
        .rollback_triggers
        .iter()
        .map(|trigger| (trigger.trigger_id.as_str(), trigger))
        .collect::<BTreeMap<_, _>>();

    let mut fail_reasons = BTreeSet::new();
    let mut hold_reasons = BTreeSet::new();

    for evidence in &fixture.evidence_artifacts {
        let status = EvidenceStatus::parse(evidence.status.as_str());

        if evidence.required {
            if fail_statuses.contains(&status) {
                fail_reasons.insert(format!("required_evidence_failed:{}", evidence.evidence_id));
            }

            if status == EvidenceStatus::InProgress {
                hold_reasons.insert(format!("evidence_in_progress:{}", evidence.evidence_id));
            }
        }

        if evidence.manifest_path.trim().is_empty() {
            fail_reasons.insert(format!(
                "evidence_manifest_missing:{}",
                evidence.evidence_id
            ));
        }
        if evidence.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("evidence_replay_missing:{}", evidence.evidence_id));
        }
    }

    let ranked_open_risks = rank_open_risks(&fixture.residual_risks);
    let max_open_risk_score = ranked_open_risks
        .first()
        .map(|risk| risk.score_millionths)
        .unwrap_or(0);

    if max_open_risk_score > fixture.gating_policy.max_open_risk_score_millionths {
        hold_reasons.insert(format!(
            "open_risk_score_above_threshold:{}>{}",
            max_open_risk_score, fixture.gating_policy.max_open_risk_score_millionths
        ));
    }

    for risk in &fixture.residual_risks {
        if risk.owner.trim().is_empty() {
            fail_reasons.insert(format!("risk_owner_missing:{}", risk.risk_id));
        }
        if risk.mitigation.trim().is_empty() {
            fail_reasons.insert(format!("risk_mitigation_missing:{}", risk.risk_id));
        }
        if risk.trigger_threshold.trim().is_empty() {
            fail_reasons.insert(format!("risk_trigger_threshold_missing:{}", risk.risk_id));
        }

        if risk.status == "open" && !trigger_by_id.contains_key(risk.rollback_trigger_id.as_str()) {
            fail_reasons.insert(format!(
                "rollback_trigger_missing_for_open_risk:{}:{}",
                risk.risk_id, risk.rollback_trigger_id
            ));
        }
    }

    for trigger in &fixture.rollback_triggers {
        if trigger.metric.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_metric_missing:{}",
                trigger.trigger_id
            ));
        }
        if !comparison_matches(trigger.comparison.as_str()) {
            fail_reasons.insert(format!(
                "rollback_trigger_comparison_invalid:{}:{}",
                trigger.trigger_id, trigger.comparison
            ));
        }
        if trigger.recovery_command.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_command_missing:{}",
                trigger.trigger_id
            ));
        }
        if trigger.blast_radius_assumption.trim().is_empty() {
            fail_reasons.insert(format!(
                "rollback_trigger_blast_radius_missing:{}",
                trigger.trigger_id
            ));
        }

        // Trigger thresholds must stay within millionths contract bounds.
        if trigger.threshold_millionths > 1_000_000 {
            fail_reasons.insert(format!(
                "rollback_trigger_threshold_out_of_bounds:{}:{}",
                trigger.trigger_id, trigger.threshold_millionths
            ));
        }
    }

    let mut seen_claim_ids = BTreeSet::new();
    let mut seen_replay_commands = BTreeSet::new();
    for claim in &fixture.claim_replay_commands {
        if !seen_claim_ids.insert(claim.claim_id.clone()) {
            fail_reasons.insert(format!("duplicate_claim_id:{}", claim.claim_id));
        }
        if claim.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("claim_replay_missing:{}", claim.claim_id));
        }
        if !seen_replay_commands.insert(claim.replay_command.clone()) {
            fail_reasons.insert(format!("duplicate_claim_replay:{}", claim.replay_command));
        }
        if claim.expected_outcome.trim().is_empty() {
            fail_reasons.insert(format!("claim_expected_outcome_missing:{}", claim.claim_id));
        }
    }

    let mut passed_verifiers = 0usize;
    for verifier in &fixture.independent_verification {
        let outcome = VerificationOutcome::parse(verifier.outcome.as_str());
        if verifier.manifest_path.trim().is_empty() {
            fail_reasons.insert(format!(
                "verifier_manifest_missing:{}",
                verifier.verifier_id
            ));
        }
        if verifier.replay_command.trim().is_empty() {
            fail_reasons.insert(format!("verifier_replay_missing:{}", verifier.verifier_id));
        }

        if outcome == VerificationOutcome::Fail {
            fail_reasons.insert(format!(
                "independent_verification_failed:{}",
                verifier.verifier_id
            ));
        }

        if verifier.signed_off && outcome == VerificationOutcome::Pass {
            passed_verifiers = passed_verifiers.saturating_add(1);
        }
    }

    if passed_verifiers < fixture.gating_policy.minimum_passed_verifiers as usize {
        hold_reasons.insert(format!(
            "independent_verifier_floor_not_met:{}<{}",
            passed_verifiers, fixture.gating_policy.minimum_passed_verifiers
        ));
    }

    let outcome = if fail_reasons.is_empty() {
        if hold_reasons.is_empty() {
            "pass"
        } else {
            "hold"
        }
    } else {
        "fail"
    }
    .to_string();

    GateEvaluation {
        outcome,
        fail_reasons: fail_reasons.into_iter().collect::<Vec<_>>(),
        hold_reasons: hold_reasons.into_iter().collect::<Vec<_>>(),
        passed_verifiers,
        ranked_open_risks,
        risk_register_hash: compute_risk_register_hash(&fixture.residual_risks),
    }
}

fn emit_structured_event(
    fixture: &ParserFinalReadinessDossierFixture,
    evaluation: &GateEvaluation,
) -> ReadinessEvent {
    ReadinessEvent {
        schema_version: fixture.log_schema_version.clone(),
        trace_id: format!("trace-{}", fixture.dossier_id),
        decision_id: format!("decision-{}", fixture.dossier_id),
        policy_id: "policy-parser-final-readiness-dossier-v1".to_string(),
        component: "parser_final_readiness_dossier_gate".to_string(),
        event: "final_readiness_dossier_evaluated".to_string(),
        outcome: evaluation.outcome.clone(),
        error_code: if evaluation.outcome == "fail" {
            Some("FE-PARSER-FINAL-DOSSIER-0001".to_string())
        } else {
            None
        },
        dossier_id: fixture.dossier_id.clone(),
        risk_register_hash: evaluation.risk_register_hash.clone(),
        replay_command: "./scripts/run_parser_final_readiness_dossier.sh ci".to_string(),
        blocked_dependency_count: fixture.blocked_dependency_ids.len(),
        hold_reason_count: evaluation.hold_reasons.len(),
        fail_reason_count: evaluation.fail_reasons.len(),
    }
}

#[test]
fn parser_final_readiness_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Final Readiness Dossier (`bd-2mds.1.8.4`)",
        "## Required Evidence Linkage",
        "## Risk Register Contract",
        "## Rollback Posture Contract",
        "## Independent Verification Contract",
        "## Structured Log Contract",
        "risk_register_hash is computed deterministically as `sha256`",
        "step_logs/step_*.log",
        "./scripts/run_parser_final_readiness_dossier.sh ci",
    ] {
        assert!(
            doc.contains(section),
            "required section missing from final readiness dossier doc: {section}"
        );
    }
}

#[test]
fn parser_final_readiness_fixture_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-final-readiness-dossier.v1"
    );
    assert_eq!(fixture.dossier_version, "0.1.0");
    assert_eq!(
        fixture.log_schema_version,
        "franken-engine.parser-log-event.v1"
    );
    assert_eq!(fixture.bead_id, "bd-2mds.1.8.4");

    for dep in [
        "bd-2mds.1.8.2",
        "bd-2mds.1.8.3",
        "bd-2mds.1.7.4",
        "bd-2mds.1.10.4",
    ] {
        assert!(
            fixture.blocked_dependency_ids.iter().any(|id| id == dep),
            "missing blocked dependency id: {dep}"
        );
    }

    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "dossier_id",
        "risk_register_hash",
        "replay_command",
    ] {
        assert!(
            fixture
                .required_log_keys
                .iter()
                .any(|required| required == key),
            "required log key missing: {key}"
        );
    }

    assert!(!fixture.evidence_artifacts.is_empty());
    let mut evidence_ids = BTreeSet::new();
    for evidence in &fixture.evidence_artifacts {
        assert!(!evidence.evidence_id.trim().is_empty());
        assert!(
            evidence_ids.insert(evidence.evidence_id.clone()),
            "duplicate evidence_id in fixture: {}",
            evidence.evidence_id
        );
        let _status = EvidenceStatus::parse(evidence.status.as_str());
        assert!(!evidence.manifest_path.trim().is_empty());
        assert!(!evidence.replay_command.trim().is_empty());
    }

    assert!(!fixture.residual_risks.is_empty());
    for risk in &fixture.residual_risks {
        let _severity = Severity::parse(risk.severity.as_str());
        assert!(!risk.owner.trim().is_empty());
        assert!(!risk.mitigation.trim().is_empty());
        assert!(!risk.trigger_threshold.trim().is_empty());
        assert!(risk.likelihood_millionths <= 1_000_000);
        assert!(risk.impact_millionths <= 1_000_000);
    }

    assert!(!fixture.rollback_triggers.is_empty());
    for trigger in &fixture.rollback_triggers {
        assert!(!trigger.trigger_id.trim().is_empty());
        assert!(comparison_matches(trigger.comparison.as_str()));
        assert!(!trigger.recovery_command.trim().is_empty());
        assert!(!trigger.blast_radius_assumption.trim().is_empty());
        assert!(trigger.threshold_millionths <= 1_000_000);
    }

    let mut claim_ids = BTreeSet::new();
    let mut replay_commands = BTreeSet::new();
    for claim in &fixture.claim_replay_commands {
        assert!(claim_ids.insert(claim.claim_id.clone()));
        assert!(!claim.replay_command.trim().is_empty());
        assert!(replay_commands.insert(claim.replay_command.clone()));
        assert!(!claim.expected_outcome.trim().is_empty());
    }
}

#[test]
fn parser_final_readiness_evaluator_matches_expected_hold_contract() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(
        evaluation.fail_reasons,
        fixture.expected_gate.expected_fail_reasons
    );
    assert_eq!(
        evaluation.hold_reasons,
        fixture.expected_gate.expected_hold_reasons
    );

    assert_eq!(evaluation.passed_verifiers, 1);
    assert!(evaluation.fail_reasons.is_empty());
    assert!(!evaluation.hold_reasons.is_empty());
}

#[test]
fn parser_final_readiness_risk_ranking_is_deterministic() {
    let fixture = load_fixture();
    let first = rank_open_risks(&fixture.residual_risks);
    let second = rank_open_risks(&fixture.residual_risks);

    assert_eq!(first, second, "open-risk ranking must be deterministic");
    assert!(!first.is_empty(), "fixture must include open risks");

    for window in first.windows(2) {
        let a = &window[0];
        let b = &window[1];
        assert!(
            a.score_millionths >= b.score_millionths,
            "risk scores must be sorted descending"
        );
    }
}

#[test]
fn parser_final_readiness_structured_event_has_required_keys() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    let value = serde_json::to_value(event).expect("serialize readiness event");
    let object = value.as_object().expect("event json object");

    for key in &fixture.required_log_keys {
        assert!(
            object.contains_key(key),
            "readiness event missing required key `{key}`"
        );

        let field = object
            .get(key)
            .expect("required key should exist in event object");

        if key == "error_code" {
            assert!(
                field.is_null() || field.as_str().is_some(),
                "error_code must be null or string"
            );
        } else {
            let text = field.as_str().unwrap_or_default();
            assert!(
                !text.trim().is_empty(),
                "required key `{key}` must be non-empty"
            );
        }
    }

    assert_eq!(
        object
            .get("blocked_dependency_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        fixture.blocked_dependency_ids.len() as u64
    );
    assert!(
        object
            .get("risk_register_hash")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .starts_with("sha256:"),
        "risk register hash must be deterministic sha256 fingerprint"
    );
}

// ---------- load_fixture helper ----------

#[test]
fn load_fixture_returns_valid_fixture() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.is_empty());
    assert!(!fixture.dossier_id.is_empty());
    assert!(!fixture.evidence_artifacts.is_empty());
}

// ---------- load_doc helper ----------

#[test]
fn load_doc_returns_nonempty_string() {
    let doc = load_doc();
    assert!(!doc.is_empty());
    assert!(doc.contains("Readiness"));
}

// ---------- comparison_matches ----------

#[test]
fn comparison_matches_valid_operators() {
    assert!(comparison_matches(">"));
    assert!(comparison_matches(">="));
    assert!(comparison_matches("<"));
    assert!(comparison_matches("<="));
}

#[test]
fn comparison_matches_rejects_invalid() {
    assert!(!comparison_matches("=="));
    assert!(!comparison_matches("!="));
    assert!(!comparison_matches(""));
}

// ---------- EvidenceStatus ----------

#[test]
fn evidence_status_parse_all_variants() {
    assert_eq!(EvidenceStatus::parse("pass"), EvidenceStatus::Pass);
    assert_eq!(
        EvidenceStatus::parse("in_progress"),
        EvidenceStatus::InProgress
    );
    assert_eq!(EvidenceStatus::parse("fail"), EvidenceStatus::Fail);
    assert_eq!(EvidenceStatus::parse("missing"), EvidenceStatus::Missing);
}

#[test]
#[should_panic(expected = "unknown evidence status")]
fn evidence_status_parse_panics_on_unknown() {
    EvidenceStatus::parse("invalid");
}

// ---------- Severity ----------

#[test]
fn severity_weight_is_ordered() {
    assert!(Severity::Critical.weight() > Severity::High.weight());
    assert!(Severity::High.weight() > Severity::Medium.weight());
    assert!(Severity::Medium.weight() > Severity::Low.weight());
}

#[test]
fn severity_parse_all_variants() {
    assert_eq!(Severity::parse("critical"), Severity::Critical);
    assert_eq!(Severity::parse("high"), Severity::High);
    assert_eq!(Severity::parse("medium"), Severity::Medium);
    assert_eq!(Severity::parse("low"), Severity::Low);
}

// ---------- VerificationOutcome ----------

#[test]
fn verification_outcome_parse_all_variants() {
    assert_eq!(
        VerificationOutcome::parse("pass"),
        VerificationOutcome::Pass
    );
    assert_eq!(
        VerificationOutcome::parse("hold"),
        VerificationOutcome::Hold
    );
    assert_eq!(
        VerificationOutcome::parse("fail"),
        VerificationOutcome::Fail
    );
}

// ---------- compute_risk_register_hash ----------

#[test]
fn risk_register_hash_is_deterministic() {
    let fixture = load_fixture();
    let a = compute_risk_register_hash(&fixture.residual_risks);
    let b = compute_risk_register_hash(&fixture.residual_risks);
    assert_eq!(a, b);
    assert!(a.starts_with("sha256:"));
}

// ---------- evaluate_dossier ----------

#[test]
fn evaluate_dossier_is_deterministic() {
    let fixture = load_fixture();
    let a = evaluate_dossier(&fixture);
    let b = evaluate_dossier(&fixture);
    assert_eq!(a, b);
}

// ---------- emit_structured_event ----------

#[test]
fn emit_structured_event_has_correct_component() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    assert_eq!(event.component, "parser_final_readiness_dossier_gate");
    assert_eq!(event.event, "final_readiness_dossier_evaluated");
    assert_eq!(event.dossier_id, fixture.dossier_id);
}

#[test]
fn readiness_event_has_nonempty_trace_id() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    assert!(!event.trace_id.trim().is_empty());
}

#[test]
fn severity_critical_has_highest_weight() {
    assert!(Severity::Critical.weight() > 0);
    assert!(Severity::Critical.weight() > Severity::Low.weight());
}

#[test]
fn risk_register_hash_starts_with_sha256_prefix() {
    let fixture = load_fixture();
    let hash = compute_risk_register_hash(&fixture.residual_risks);
    assert!(hash.starts_with("sha256:"), "hash must have sha256 prefix");
}

#[test]
fn readiness_fixture_has_nonempty_dossier_id() {
    let fixture = load_fixture();
    assert!(!fixture.dossier_id.trim().is_empty());
}

#[test]
fn readiness_fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.dossier_id, b.dossier_id);
    assert_eq!(a.schema_version, b.schema_version);
}

#[test]
fn risk_register_hash_deterministic_for_same_risks() {
    let fixture = load_fixture();
    let a = compute_risk_register_hash(&fixture.residual_risks);
    let b = compute_risk_register_hash(&fixture.residual_risks);
    assert_eq!(a, b);
}

#[test]
fn rank_open_risks_empty_input_returns_empty() {
    let ranked = rank_open_risks(&[]);
    assert!(
        ranked.is_empty(),
        "empty risk slice should yield empty ranking"
    );
}

#[test]
fn open_risk_score_millionths_boundary_values() {
    // Maximum likelihood and impact (both 1_000_000) should produce score = 1_000_000
    let max_risk = ResidualRisk {
        risk_id: "r-max".into(),
        severity: "critical".into(),
        likelihood_millionths: 1_000_000,
        impact_millionths: 1_000_000,
        owner: "owner".into(),
        mitigation: "mitigate".into(),
        trigger_threshold: "threshold".into(),
        rollback_trigger_id: "t-1".into(),
        status: "open".into(),
    };
    assert_eq!(open_risk_score_millionths(&max_risk), 1_000_000);

    // Zero likelihood should produce zero score
    let zero_risk = ResidualRisk {
        risk_id: "r-zero".into(),
        severity: "low".into(),
        likelihood_millionths: 0,
        impact_millionths: 1_000_000,
        owner: "owner".into(),
        mitigation: "mitigate".into(),
        trigger_threshold: "threshold".into(),
        rollback_trigger_id: "t-2".into(),
        status: "open".into(),
    };
    assert_eq!(open_risk_score_millionths(&zero_risk), 0);
}

#[test]
fn structured_event_error_code_null_for_hold_outcome() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    if evaluation.outcome == "hold" {
        assert!(
            event.error_code.is_none(),
            "error_code should be None for hold outcome"
        );
    }
}

#[test]
fn residual_risk_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for risk in &fixture.residual_risks {
        assert!(
            seen.insert(&risk.risk_id),
            "duplicate risk_id: {}",
            risk.risk_id
        );
    }
}

#[test]
fn rollback_trigger_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for trigger in &fixture.rollback_triggers {
        assert!(
            seen.insert(&trigger.trigger_id),
            "duplicate trigger_id: {}",
            trigger.trigger_id
        );
    }
}

#[test]
fn evidence_status_ordering_fail_after_pass() {
    // EvidenceStatus derives Ord — verify that the ordering is sensible
    assert!(EvidenceStatus::Pass < EvidenceStatus::Fail);
    assert!(EvidenceStatus::InProgress < EvidenceStatus::Fail);
}

#[test]
fn severity_parse_roundtrip_weight_consistency() {
    for (label, expected_weight) in [("critical", 4), ("high", 3), ("medium", 2), ("low", 1)] {
        let severity = Severity::parse(label);
        assert_eq!(
            severity.weight(),
            expected_weight,
            "weight mismatch for {label}"
        );
    }
}

#[test]
fn rank_open_risks_excludes_mitigated_risks() {
    let risks = vec![
        ResidualRisk {
            risk_id: "r-open".into(),
            severity: "high".into(),
            likelihood_millionths: 500_000,
            impact_millionths: 400_000,
            owner: "owner-a".into(),
            mitigation: "m1".into(),
            trigger_threshold: "t1".into(),
            rollback_trigger_id: "trig-1".into(),
            status: "open".into(),
        },
        ResidualRisk {
            risk_id: "r-mitigated".into(),
            severity: "critical".into(),
            likelihood_millionths: 900_000,
            impact_millionths: 900_000,
            owner: "owner-b".into(),
            mitigation: "m2".into(),
            trigger_threshold: "t2".into(),
            rollback_trigger_id: "trig-2".into(),
            status: "mitigated".into(),
        },
    ];
    let ranked = rank_open_risks(&risks);
    assert_eq!(ranked.len(), 1, "only open risks should be ranked");
    assert_eq!(ranked[0].risk_id, "r-open");
}

#[test]
fn compute_risk_register_hash_empty_slice_is_deterministic() {
    let a = compute_risk_register_hash(&[]);
    let b = compute_risk_register_hash(&[]);
    assert_eq!(a, b);
    assert!(a.starts_with("sha256:"));
    // Empty slice should still produce a valid hash (of `[]`)
    assert!(a.len() > "sha256:".len());
}

#[test]
fn readiness_event_serde_roundtrip_preserves_all_fields() {
    let fixture = load_fixture();
    let evaluation = evaluate_dossier(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);
    let json = serde_json::to_string(&event).expect("serialize event");
    let map: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&json).expect("deserialize event as map");
    // Verify key fields survive roundtrip
    assert_eq!(
        map["schema_version"].as_str().unwrap(),
        event.schema_version
    );
    assert_eq!(map["trace_id"].as_str().unwrap(), event.trace_id);
    assert_eq!(map["component"].as_str().unwrap(), event.component);
    assert_eq!(map["outcome"].as_str().unwrap(), event.outcome);
    assert_eq!(
        map["blocked_dependency_count"].as_u64().unwrap(),
        event.blocked_dependency_count as u64
    );
    assert_eq!(
        map["hold_reason_count"].as_u64().unwrap(),
        event.hold_reason_count as u64
    );
    assert_eq!(
        map["fail_reason_count"].as_u64().unwrap(),
        event.fail_reason_count as u64
    );
}

#[test]
#[should_panic(expected = "unknown verification outcome")]
fn verification_outcome_parse_panics_on_unknown() {
    VerificationOutcome::parse("bogus");
}

#[test]
fn risk_register_hash_changes_when_risk_data_changes() {
    let fixture = load_fixture();
    let original_hash = compute_risk_register_hash(&fixture.residual_risks);

    // Create a modified copy with a different likelihood value
    let mut modified_risks: Vec<ResidualRisk> = Vec::new();
    for (i, risk) in fixture.residual_risks.iter().enumerate() {
        modified_risks.push(ResidualRisk {
            risk_id: risk.risk_id.clone(),
            severity: risk.severity.clone(),
            likelihood_millionths: if i == 0 {
                risk.likelihood_millionths.wrapping_add(1).min(1_000_000)
            } else {
                risk.likelihood_millionths
            },
            impact_millionths: risk.impact_millionths,
            owner: risk.owner.clone(),
            mitigation: risk.mitigation.clone(),
            trigger_threshold: risk.trigger_threshold.clone(),
            rollback_trigger_id: risk.rollback_trigger_id.clone(),
            status: risk.status.clone(),
        });
    }
    let modified_hash = compute_risk_register_hash(&modified_risks);
    assert_ne!(
        original_hash, modified_hash,
        "hash must change when risk data changes"
    );
}
