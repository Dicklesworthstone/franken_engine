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
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct WaiverRecord {
    waiver_id: String,
    approved_by: String,
    remediation_due_utc: String,
    rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct DriftRecord {
    drift_id: String,
    fixture_id: String,
    severity: String,
    status: String,
    owner: String,
    detected_at_utc: String,
    replay_command: String,
    waiver: Option<WaiverRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct EvidenceVector {
    lane_id: String,
    status: String,
    artifact_manifest: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_unresolved_high_count: usize,
    expected_waiver_count: usize,
    expected_blockers: Vec<String>,
    expected_failing_fixture_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct ParserCorrectnessPromotionGateFixture {
    schema_version: String,
    gate_version: String,
    high_severity_levels: Vec<String>,
    required_evidence_lanes: Vec<String>,
    structured_log_required_keys: Vec<String>,
    drift_records: Vec<DriftRecord>,
    evidence_vectors: Vec<EvidenceVector>,
    expected_gate: ExpectedGate,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    unresolved_high_count: usize,
    waiver_count: usize,
    blockers: Vec<String>,
    failing_fixture_ids: Vec<String>,
}

fn load_fixture() -> ParserCorrectnessPromotionGateFixture {
    let path = Path::new("tests/fixtures/parser_correctness_promotion_gate_v1.json");
    let bytes = fs::read(path).expect("read parser correctness promotion gate fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser correctness promotion gate fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_CORRECTNESS_PROMOTION_GATE.md");
    fs::read_to_string(path).expect("read parser correctness promotion gate doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_correctness_promotion_gate.sh");
    fs::read_to_string(path).expect("read parser correctness promotion gate script")
}

fn unresolved_high_drifts(fixture: &ParserCorrectnessPromotionGateFixture) -> Vec<&DriftRecord> {
    let high_set = fixture
        .high_severity_levels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    fixture
        .drift_records
        .iter()
        .filter(|drift| {
            high_set.contains(drift.severity.as_str())
                && drift.status != "resolved"
                && drift.status != "waived"
        })
        .collect()
}

fn count_waivers(fixture: &ParserCorrectnessPromotionGateFixture) -> usize {
    fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
        .count()
}

fn collect_waiver_issues(fixture: &ParserCorrectnessPromotionGateFixture) -> Vec<String> {
    let mut issues = Vec::new();

    for drift in fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
    {
        let Some(waiver) = drift.waiver.as_ref() else {
            issues.push(format!("invalid_waiver:{}:missing_record", drift.drift_id));
            continue;
        };

        if waiver.waiver_id.trim().is_empty()
            || waiver.approved_by.trim().is_empty()
            || waiver.rationale.trim().is_empty()
        {
            issues.push(format!("invalid_waiver:{}:missing_fields", drift.drift_id));
        }

        if waiver.remediation_due_utc <= drift.detected_at_utc {
            issues.push(format!(
                "invalid_waiver:{}:invalid_due_date",
                drift.drift_id
            ));
        }
    }

    issues
}

fn evaluate_gate(fixture: &ParserCorrectnessPromotionGateFixture) -> GateEvaluation {
    let unresolved = unresolved_high_drifts(fixture);
    let waiver_count = count_waivers(fixture);
    let waiver_issues = collect_waiver_issues(fixture);

    let evidence_by_lane = fixture
        .evidence_vectors
        .iter()
        .map(|vector| (vector.lane_id.as_str(), vector.status.as_str()))
        .collect::<BTreeMap<_, _>>();

    let mut blockers = Vec::new();
    for drift in &unresolved {
        blockers.push(format!("unresolved_high_drift:{}", drift.drift_id));
    }

    for lane in &fixture.required_evidence_lanes {
        match evidence_by_lane.get(lane.as_str()) {
            None => blockers.push(format!("evidence_missing:{lane}")),
            Some(status) if *status != "pass" => {
                blockers.push(format!("evidence_not_green:{lane}:{status}"));
            }
            Some(_) => {}
        }
    }

    blockers.extend(waiver_issues);
    blockers.sort();
    blockers.dedup();

    let mut failing_fixture_ids = unresolved
        .iter()
        .map(|drift| drift.fixture_id.clone())
        .collect::<Vec<_>>();
    failing_fixture_ids.sort();
    failing_fixture_ids.dedup();

    let outcome = if blockers.is_empty() {
        "promote"
    } else {
        "hold"
    };

    GateEvaluation {
        outcome: outcome.to_string(),
        unresolved_high_count: unresolved.len(),
        waiver_count,
        blockers,
        failing_fixture_ids,
    }
}

fn emit_structured_event(
    fixture: &ParserCorrectnessPromotionGateFixture,
    evaluation: &GateEvaluation,
) -> serde_json::Value {
    let drift_inventory = fixture
        .drift_records
        .iter()
        .map(|drift| drift.drift_id.clone())
        .collect::<Vec<_>>();
    let waiver_inventory = fixture
        .drift_records
        .iter()
        .filter(|drift| drift.status == "waived")
        .filter_map(|drift| drift.waiver.as_ref().map(|waiver| waiver.waiver_id.clone()))
        .collect::<Vec<_>>();

    let replay_pointers = fixture
        .drift_records
        .iter()
        .map(|drift| drift.replay_command.clone())
        .chain(
            fixture
                .evidence_vectors
                .iter()
                .map(|vector| vector.replay_command.clone()),
        )
        .chain(
            fixture
                .replay_scenarios
                .iter()
                .map(|scenario| scenario.replay_command.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    serde_json::json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-correctness-promotion-gate-v1",
        "decision_id": "decision-parser-correctness-promotion-gate-v1",
        "policy_id": "policy-parser-correctness-promotion-gate-v1",
        "component": "parser_correctness_promotion_gate",
        "event": "correctness_gate_evaluated",
        "outcome": evaluation.outcome,
        "error_code": if evaluation.outcome == "promote" {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("FE-PARSER-CORRECTNESS-GATE-0001".to_string())
        },
        "drift_inventory": drift_inventory,
        "waiver_inventory": waiver_inventory,
        "failing_fixture_ids": evaluation.failing_fixture_ids,
        "replay_pointers": replay_pointers,
        "blockers": evaluation.blockers,
    })
}

#[test]
fn parser_correctness_doc_has_required_sections() {
    let doc = load_doc();

    for section in [
        "# Parser Correctness Promotion Gate (`bd-2mds.1.8.2`)",
        "## Promotion Policy",
        "## Evidence Requirements",
        "## Drift and Waiver Semantics",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
    ] {
        assert!(doc.contains(section), "missing section: {section}");
    }

    for command in [
        "./scripts/run_parser_correctness_promotion_gate.sh ci",
        "./scripts/e2e/parser_correctness_promotion_gate_replay.sh",
    ] {
        assert!(
            doc.contains(command),
            "missing command reference: {command}"
        );
    }
}

#[test]
fn parser_correctness_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-correctness-promotion-gate.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");

    let high_levels = fixture
        .high_severity_levels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(high_levels.contains("high"));
    assert!(high_levels.contains("critical"));

    let required_lanes = fixture
        .required_evidence_lanes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert!(required_lanes.contains("parser_oracle"));
    assert!(required_lanes.contains("event_ast_equivalence"));
    assert!(required_lanes.contains("parallel_fallback_parity"));
    assert!(required_lanes.contains("differential_harness"));

    for drift in &fixture.drift_records {
        assert!(!drift.drift_id.trim().is_empty());
        assert!(!drift.fixture_id.trim().is_empty());
        assert!(!drift.owner.trim().is_empty());
        assert!(
            ["open", "resolved", "waived"].contains(&drift.status.as_str()),
            "unexpected drift status: {}",
            drift.status
        );
        assert!(
            ["critical", "high", "medium", "low"].contains(&drift.severity.as_str()),
            "unexpected drift severity: {}",
            drift.severity
        );
    }

    for vector in &fixture.evidence_vectors {
        assert!(!vector.lane_id.trim().is_empty());
        assert!(!vector.artifact_manifest.trim().is_empty());
        assert!(
            ["pass", "fail", "missing"].contains(&vector.status.as_str()),
            "unexpected evidence status: {}",
            vector.status
        );
    }

    assert!(!fixture.replay_scenarios.is_empty());
}

#[test]
fn parser_correctness_unresolved_high_and_waiver_counts_match_expected() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(
        evaluation.unresolved_high_count,
        fixture.expected_gate.expected_unresolved_high_count
    );
    assert_eq!(
        evaluation.waiver_count,
        fixture.expected_gate.expected_waiver_count
    );

    let waiver_issues = collect_waiver_issues(&fixture);
    assert!(waiver_issues.is_empty(), "waiver issues: {waiver_issues:?}");
}

#[test]
fn parser_correctness_gate_evaluation_matches_expected_fixture() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(evaluation.blockers, fixture.expected_gate.expected_blockers);
    assert_eq!(
        evaluation.failing_fixture_ids,
        fixture.expected_gate.expected_failing_fixture_ids
    );
}

#[test]
fn parser_correctness_structured_event_has_required_fields() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);

    for key in &fixture.structured_log_required_keys {
        assert!(
            event.get(key).is_some(),
            "missing structured log key in emitted event: {key}"
        );
    }

    assert_eq!(
        event
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .expect("outcome string"),
        fixture.expected_gate.expected_outcome
    );

    assert_eq!(
        event
            .get("failing_fixture_ids")
            .and_then(serde_json::Value::as_array)
            .expect("failing_fixture_ids array")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>(),
        fixture
            .expected_gate
            .expected_failing_fixture_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
}

#[test]
fn parser_correctness_replay_scenarios_reference_wrapper_commands() {
    let fixture = load_fixture();

    for scenario in &fixture.replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(scenario.replay_command.starts_with("./scripts/e2e/"));
        assert!(scenario.replay_command.ends_with(".sh"));
        assert!(
            ["hold", "promote"].contains(&scenario.expected_outcome.as_str()),
            "unexpected expected_outcome: {}",
            scenario.expected_outcome
        );
    }
}

#[test]
fn parser_correctness_evidence_vectors_reference_manifests_and_wrappers() {
    let fixture = load_fixture();
    for vector in &fixture.evidence_vectors {
        assert!(
            vector.artifact_manifest.ends_with("/run_manifest.json"),
            "artifact manifest should end with run_manifest.json: {}",
            vector.artifact_manifest
        );
        assert!(
            vector.replay_command.starts_with("./scripts/e2e/"),
            "replay command should use e2e wrapper path: {}",
            vector.replay_command
        );
    }
}

#[test]
fn parser_correctness_gate_script_contains_fail_closed_rch_markers() {
    let script = load_script();
    let required_markers = [
        "policy-parser-correctness-promotion-gate-v1",
        "rch_last_remote_exit_code",
        "rch_has_recoverable_artifact_timeout",
        "rch_reject_artifact_retrieval_failure",
        "running locally",
        "RCH-E326",
        "rsync error: .*code 23",
        "parser_frontier_emit_manifest_environment_fields",
        "./scripts/e2e/parser_correctness_promotion_gate_replay.sh",
    ];

    for marker in required_markers {
        assert!(
            script.contains(marker),
            "correctness gate script missing marker: {marker}"
        );
    }
}

// ---------- unresolved_high_drifts ----------

fn make_drift(
    drift_id: &str,
    severity: &str,
    status: &str,
    waiver: Option<WaiverRecord>,
) -> DriftRecord {
    DriftRecord {
        drift_id: drift_id.to_string(),
        fixture_id: format!("fixture-{drift_id}"),
        severity: severity.to_string(),
        status: status.to_string(),
        owner: "owner-a".to_string(),
        detected_at_utc: "2026-01-01T00:00:00Z".to_string(),
        replay_command: "./scripts/e2e/replay.sh".to_string(),
        waiver,
    }
}

fn make_fixture(drifts: Vec<DriftRecord>) -> ParserCorrectnessPromotionGateFixture {
    ParserCorrectnessPromotionGateFixture {
        schema_version: "franken-engine.parser-correctness-promotion-gate.v1".to_string(),
        gate_version: "1.0.0".to_string(),
        high_severity_levels: vec!["high".to_string(), "critical".to_string()],
        required_evidence_lanes: vec![],
        structured_log_required_keys: vec![],
        drift_records: drifts,
        evidence_vectors: vec![],
        expected_gate: ExpectedGate {
            expected_outcome: String::new(),
            expected_blockers: vec![],
            expected_unresolved_high_count: 0,
            expected_waiver_count: 0,
            expected_failing_fixture_ids: vec![],
        },
        replay_scenarios: vec![],
    }
}

#[test]
fn unresolved_high_drifts_finds_open_critical() {
    let fixture = make_fixture(vec![make_drift("d1", "critical", "open", None)]);
    let unresolved = unresolved_high_drifts(&fixture);
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].drift_id, "d1");
}

#[test]
fn unresolved_high_drifts_skips_resolved() {
    let fixture = make_fixture(vec![make_drift("d1", "critical", "resolved", None)]);
    assert!(unresolved_high_drifts(&fixture).is_empty());
}

#[test]
fn unresolved_high_drifts_skips_waived() {
    let fixture = make_fixture(vec![make_drift("d1", "high", "waived", None)]);
    assert!(unresolved_high_drifts(&fixture).is_empty());
}

#[test]
fn unresolved_high_drifts_skips_low_severity() {
    let fixture = make_fixture(vec![make_drift("d1", "low", "open", None)]);
    assert!(unresolved_high_drifts(&fixture).is_empty());
}

#[test]
fn unresolved_high_drifts_skips_medium_severity() {
    let fixture = make_fixture(vec![make_drift("d1", "medium", "open", None)]);
    assert!(unresolved_high_drifts(&fixture).is_empty());
}

// ---------- count_waivers ----------

#[test]
fn count_waivers_counts_waived_status() {
    let fixture = make_fixture(vec![
        make_drift("d1", "high", "waived", None),
        make_drift("d2", "critical", "open", None),
        make_drift("d3", "low", "waived", None),
    ]);
    assert_eq!(count_waivers(&fixture), 2);
}

#[test]
fn count_waivers_zero_when_none_waived() {
    let fixture = make_fixture(vec![make_drift("d1", "high", "open", None)]);
    assert_eq!(count_waivers(&fixture), 0);
}

// ---------- collect_waiver_issues ----------

#[test]
fn collect_waiver_issues_missing_waiver_record() {
    let fixture = make_fixture(vec![make_drift("d1", "high", "waived", None)]);
    let issues = collect_waiver_issues(&fixture);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("missing_record"));
}

#[test]
fn collect_waiver_issues_empty_fields() {
    let waiver = WaiverRecord {
        waiver_id: "".to_string(),
        approved_by: "admin".to_string(),
        remediation_due_utc: "2027-01-01T00:00:00Z".to_string(),
        rationale: "reason".to_string(),
    };
    let fixture = make_fixture(vec![make_drift("d1", "high", "waived", Some(waiver))]);
    let issues = collect_waiver_issues(&fixture);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("missing_fields"));
}

#[test]
fn collect_waiver_issues_invalid_due_date() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        approved_by: "admin".to_string(),
        remediation_due_utc: "2025-12-31T00:00:00Z".to_string(),
        rationale: "reason".to_string(),
    };
    let fixture = make_fixture(vec![make_drift("d1", "high", "waived", Some(waiver))]);
    let issues = collect_waiver_issues(&fixture);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].contains("invalid_due_date"));
}

#[test]
fn collect_waiver_issues_valid_waiver_no_issues() {
    let waiver = WaiverRecord {
        waiver_id: "w1".to_string(),
        approved_by: "admin".to_string(),
        remediation_due_utc: "2027-01-01T00:00:00Z".to_string(),
        rationale: "reason".to_string(),
    };
    let fixture = make_fixture(vec![make_drift("d1", "high", "waived", Some(waiver))]);
    let issues = collect_waiver_issues(&fixture);
    assert!(issues.is_empty());
}

// ---------- evaluate_gate synthetic ----------

#[test]
fn evaluate_gate_promotes_with_no_drifts() {
    let fixture = make_fixture(vec![]);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "promote");
    assert!(eval.blockers.is_empty());
}

#[test]
fn evaluate_gate_holds_with_unresolved_critical() {
    let fixture = make_fixture(vec![make_drift("d1", "critical", "open", None)]);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blockers
            .iter()
            .any(|b| b.contains("unresolved_high_drift:d1"))
    );
    assert!(eval.failing_fixture_ids.contains(&"fixture-d1".to_string()));
}

#[test]
fn evaluate_gate_holds_on_missing_evidence_lane() {
    let mut fixture = make_fixture(vec![]);
    fixture.required_evidence_lanes = vec!["lane_x".to_string()];
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blockers
            .iter()
            .any(|b| b.contains("evidence_missing:lane_x"))
    );
}

#[test]
fn evaluate_gate_holds_on_failed_evidence_lane() {
    let mut fixture = make_fixture(vec![]);
    fixture.required_evidence_lanes = vec!["lane_y".to_string()];
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_y".to_string(),
        status: "fail".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/replay.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blockers
            .iter()
            .any(|b| b.contains("evidence_not_green:lane_y:fail"))
    );
}

// ---------- emit_structured_event ----------

#[test]
fn emit_structured_event_promote_null_error_code() {
    let fixture = make_fixture(vec![]);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert!(event.get("error_code").unwrap().is_null());
}

#[test]
fn emit_structured_event_hold_has_error_code() {
    let fixture = make_fixture(vec![make_drift("d1", "critical", "open", None)]);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert_eq!(
        event.get("error_code").unwrap().as_str().unwrap(),
        "FE-PARSER-CORRECTNESS-GATE-0001"
    );
}

// ---------- evaluate_gate determinism ----------

#[test]
fn evaluate_gate_deterministic() {
    let fixture = load_fixture();
    let eval1 = evaluate_gate(&fixture);
    let eval2 = evaluate_gate(&fixture);
    assert_eq!(eval1, eval2);
}

// ---------- additional edge-case coverage ----------

#[test]
fn evaluate_gate_blockers_are_sorted_and_deduped() {
    let mut fixture = make_fixture(vec![
        make_drift("d2", "critical", "open", None),
        make_drift("d1", "high", "open", None),
        make_drift("d1_dup", "high", "open", None),
    ]);
    fixture.required_evidence_lanes = vec!["lane_z".to_string(), "lane_a".to_string()];
    let eval = evaluate_gate(&fixture);

    // Blockers must be sorted lexicographically
    let sorted = {
        let mut s = eval.blockers.clone();
        s.sort();
        s.dedup();
        s
    };
    assert_eq!(eval.blockers, sorted, "blockers must be sorted and deduped");
}

#[test]
fn collect_waiver_issues_accumulates_multiple_independent_issues() {
    let bad_waiver_missing_fields = WaiverRecord {
        waiver_id: "".to_string(),
        approved_by: "".to_string(),
        remediation_due_utc: "2027-06-01T00:00:00Z".to_string(),
        rationale: "".to_string(),
    };
    let bad_waiver_invalid_date = WaiverRecord {
        waiver_id: "w2".to_string(),
        approved_by: "admin".to_string(),
        remediation_due_utc: "2020-01-01T00:00:00Z".to_string(),
        rationale: "reason".to_string(),
    };
    let fixture = make_fixture(vec![
        make_drift("d1", "high", "waived", Some(bad_waiver_missing_fields)),
        make_drift("d2", "low", "waived", Some(bad_waiver_invalid_date)),
        make_drift("d3", "medium", "waived", None),
    ]);
    let issues = collect_waiver_issues(&fixture);
    assert_eq!(issues.len(), 3);
    assert!(
        issues
            .iter()
            .any(|i| i.contains("d1") && i.contains("missing_fields"))
    );
    assert!(
        issues
            .iter()
            .any(|i| i.contains("d2") && i.contains("invalid_due_date"))
    );
    assert!(
        issues
            .iter()
            .any(|i| i.contains("d3") && i.contains("missing_record"))
    );
}

#[test]
fn evaluate_gate_failing_fixture_ids_are_sorted_and_deduped() {
    let fixture = make_fixture(vec![
        make_drift("d2", "critical", "open", None),
        make_drift("d1", "high", "open", None),
    ]);
    let eval = evaluate_gate(&fixture);

    let sorted = {
        let mut s = eval.failing_fixture_ids.clone();
        s.sort();
        s.dedup();
        s
    };
    assert_eq!(
        eval.failing_fixture_ids, sorted,
        "failing_fixture_ids must be sorted and deduped"
    );
}

#[test]
fn emit_structured_event_replay_pointers_are_deduplicated() {
    let mut fixture = make_fixture(vec![
        make_drift("d1", "low", "resolved", None),
        make_drift("d2", "low", "resolved", None),
    ]);
    // Both drifts share the same replay_command from make_drift
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_a".to_string(),
        status: "pass".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/replay.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    let pointers = event
        .get("replay_pointers")
        .and_then(serde_json::Value::as_array)
        .expect("replay_pointers must be array");

    // All three share "./scripts/e2e/replay.sh" so dedup via BTreeSet should yield 1
    let unique: BTreeSet<&str> = pointers
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert_eq!(
        pointers.len(),
        unique.len(),
        "replay_pointers must already be deduplicated"
    );
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_waiver_record_clone_preserves_all_fields() {
    let waiver = WaiverRecord {
        waiver_id: "w-clone-test".to_string(),
        approved_by: "team-security".to_string(),
        remediation_due_utc: "2027-06-15T12:00:00Z".to_string(),
        rationale: "accepted risk during migration window".to_string(),
    };
    let cloned = waiver.clone();
    assert_eq!(cloned.waiver_id, waiver.waiver_id);
    assert_eq!(cloned.approved_by, waiver.approved_by);
    assert_eq!(cloned.remediation_due_utc, waiver.remediation_due_utc);
    assert_eq!(cloned.rationale, waiver.rationale);
    assert_eq!(cloned, waiver);
}

#[test]
fn enrichment_drift_record_clone_and_debug_roundtrip() {
    let waiver = WaiverRecord {
        waiver_id: "w-debug".to_string(),
        approved_by: "sec-lead".to_string(),
        remediation_due_utc: "2028-01-01T00:00:00Z".to_string(),
        rationale: "mitigated by separate control".to_string(),
    };
    let drift = make_drift("d-debug", "high", "waived", Some(waiver));
    let cloned = drift.clone();
    assert_eq!(cloned, drift);
    let debug_str = format!("{drift:?}");
    assert!(debug_str.contains("d-debug"));
    assert!(debug_str.contains("high"));
    assert!(debug_str.contains("waived"));
}

#[test]
fn enrichment_gate_evaluation_clone_preserves_equality() {
    let fixture = make_fixture(vec![
        make_drift("d1", "critical", "open", None),
        make_drift("d2", "high", "open", None),
    ]);
    let eval = evaluate_gate(&fixture);
    let cloned = eval.clone();
    assert_eq!(eval.outcome, cloned.outcome);
    assert_eq!(eval.unresolved_high_count, cloned.unresolved_high_count);
    assert_eq!(eval.waiver_count, cloned.waiver_count);
    assert_eq!(eval.blockers, cloned.blockers);
    assert_eq!(eval.failing_fixture_ids, cloned.failing_fixture_ids);
    assert_eq!(eval, cloned);
}

#[test]
fn enrichment_gate_evaluation_debug_contains_outcome_and_counts() {
    let fixture = make_fixture(vec![make_drift("d1", "high", "open", None)]);
    let eval = evaluate_gate(&fixture);
    let debug_str = format!("{eval:?}");
    assert!(debug_str.contains("hold"));
    assert!(debug_str.contains("unresolved_high_count"));
    assert!(debug_str.contains("waiver_count"));
}

#[test]
fn enrichment_serde_roundtrip_waiver_record() {
    let waiver = WaiverRecord {
        waiver_id: "w-serde-1".to_string(),
        approved_by: "approver-x".to_string(),
        remediation_due_utc: "2027-03-15T08:00:00Z".to_string(),
        rationale: "low exposure during freeze".to_string(),
    };
    let json = serde_json::to_string(&waiver).expect("serialize WaiverRecord");
    let decoded: WaiverRecord = serde_json::from_str(&json).expect("deserialize WaiverRecord");
    assert_eq!(decoded, waiver);
}

#[test]
fn enrichment_serde_roundtrip_drift_record_with_waiver() {
    let waiver = WaiverRecord {
        waiver_id: "w-rt".to_string(),
        approved_by: "eng-director".to_string(),
        remediation_due_utc: "2027-09-01T00:00:00Z".to_string(),
        rationale: "accepted by risk board".to_string(),
    };
    let drift = make_drift("d-rt", "critical", "waived", Some(waiver));
    let json = serde_json::to_string(&drift).expect("serialize DriftRecord");
    let decoded: DriftRecord = serde_json::from_str(&json).expect("deserialize DriftRecord");
    assert_eq!(decoded, drift);
}

#[test]
fn enrichment_serde_roundtrip_drift_record_no_waiver() {
    let drift = make_drift("d-no-waiver", "high", "open", None);
    let json = serde_json::to_string(&drift).expect("serialize DriftRecord");
    let decoded: DriftRecord = serde_json::from_str(&json).expect("deserialize DriftRecord");
    assert_eq!(decoded, drift);
    assert!(decoded.waiver.is_none());
}

#[test]
fn enrichment_evaluate_gate_deterministic_with_multiple_drifts_and_lanes() {
    let mut fixture = make_fixture(vec![
        make_drift("d3", "critical", "open", None),
        make_drift("d1", "high", "open", None),
        make_drift("d2", "medium", "open", None),
    ]);
    fixture.required_evidence_lanes = vec!["lane_b".to_string(), "lane_a".to_string()];
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_a".to_string(),
        status: "pass".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/lane_a.sh".to_string(),
    });
    let eval1 = evaluate_gate(&fixture);
    let eval2 = evaluate_gate(&fixture);
    assert_eq!(eval1, eval2, "gate evaluation must be fully deterministic");
    assert_eq!(eval1.outcome, "hold");
}

#[test]
fn enrichment_evaluate_gate_only_high_and_critical_cause_unresolved_blocker() {
    let fixture = make_fixture(vec![
        make_drift("d-low", "low", "open", None),
        make_drift("d-med", "medium", "open", None),
        make_drift("d-high", "high", "open", None),
        make_drift("d-crit", "critical", "open", None),
    ]);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.unresolved_high_count, 2);
    assert!(eval.blockers.iter().any(|b| b.contains("d-high")));
    assert!(eval.blockers.iter().any(|b| b.contains("d-crit")));
    assert!(!eval.blockers.iter().any(|b| b.contains("d-low")));
    assert!(!eval.blockers.iter().any(|b| b.contains("d-med")));
}

#[test]
fn enrichment_evaluate_gate_all_resolved_and_waived_promote() {
    let waiver = WaiverRecord {
        waiver_id: "w-ok".to_string(),
        approved_by: "sec-team".to_string(),
        remediation_due_utc: "2027-06-01T00:00:00Z".to_string(),
        rationale: "full remediation planned".to_string(),
    };
    let fixture = make_fixture(vec![
        make_drift("d1", "critical", "resolved", None),
        make_drift("d2", "high", "waived", Some(waiver)),
        make_drift("d3", "low", "open", None),
    ]);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "promote");
    assert!(eval.blockers.is_empty());
    assert_eq!(eval.unresolved_high_count, 0);
    assert_eq!(eval.waiver_count, 1);
}

#[test]
fn enrichment_evaluate_gate_evidence_missing_status_is_specific_lane() {
    let mut fixture = make_fixture(vec![]);
    fixture.required_evidence_lanes = vec!["lane_present".to_string(), "lane_absent".to_string()];
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_present".to_string(),
        status: "pass".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/present.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    let missing_blockers: Vec<&String> = eval
        .blockers
        .iter()
        .filter(|b| b.contains("evidence_missing"))
        .collect();
    assert_eq!(missing_blockers.len(), 1);
    assert!(missing_blockers[0].contains("lane_absent"));
    assert!(!eval.blockers.iter().any(|b| b.contains("lane_present")));
}

#[test]
fn enrichment_emit_structured_event_drift_inventory_contains_all_drift_ids() {
    let fixture = make_fixture(vec![
        make_drift("d-alpha", "high", "open", None),
        make_drift("d-beta", "low", "resolved", None),
        make_drift("d-gamma", "critical", "open", None),
    ]);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    let inventory = event
        .get("drift_inventory")
        .and_then(serde_json::Value::as_array)
        .expect("drift_inventory must be array");
    let ids: BTreeSet<&str> = inventory
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(ids.contains("d-alpha"));
    assert!(ids.contains("d-beta"));
    assert!(ids.contains("d-gamma"));
    assert_eq!(ids.len(), 3);
}

#[test]
fn enrichment_emit_structured_event_waiver_inventory_only_waived_drifts() {
    let waiver_a = WaiverRecord {
        waiver_id: "w-inv-a".to_string(),
        approved_by: "admin".to_string(),
        remediation_due_utc: "2027-01-01T00:00:00Z".to_string(),
        rationale: "scheduled".to_string(),
    };
    let waiver_b = WaiverRecord {
        waiver_id: "w-inv-b".to_string(),
        approved_by: "director".to_string(),
        remediation_due_utc: "2028-06-01T00:00:00Z".to_string(),
        rationale: "risk accepted".to_string(),
    };
    let fixture = make_fixture(vec![
        make_drift("d1", "high", "waived", Some(waiver_a)),
        make_drift("d2", "critical", "open", None),
        make_drift("d3", "low", "waived", Some(waiver_b)),
    ]);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    let waiver_inv = event
        .get("waiver_inventory")
        .and_then(serde_json::Value::as_array)
        .expect("waiver_inventory must be array");
    let waiver_ids: BTreeSet<&str> = waiver_inv
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(waiver_ids.contains("w-inv-a"));
    assert!(waiver_ids.contains("w-inv-b"));
    assert_eq!(waiver_ids.len(), 2);
}

#[test]
fn enrichment_collect_waiver_issues_both_missing_fields_and_invalid_date_on_same_drift() {
    // A waiver with empty fields AND a remediation_due_utc before detected_at_utc triggers both issues
    let waiver_both_bad = WaiverRecord {
        waiver_id: "".to_string(),
        approved_by: "".to_string(),
        remediation_due_utc: "2025-06-01T00:00:00Z".to_string(), // before detected_at_utc "2026-01-01T00:00:00Z"
        rationale: "".to_string(),
    };
    let fixture = make_fixture(vec![make_drift(
        "d-both",
        "high",
        "waived",
        Some(waiver_both_bad),
    )]);
    let issues = collect_waiver_issues(&fixture);
    // Both missing_fields and invalid_due_date should be reported
    assert!(issues.iter().any(|i| i.contains("missing_fields")));
    assert!(issues.iter().any(|i| i.contains("invalid_due_date")));
}

#[test]
fn enrichment_gate_evaluation_no_failing_fixture_ids_when_all_resolved() {
    let fixture = make_fixture(vec![
        make_drift("d1", "critical", "resolved", None),
        make_drift("d2", "high", "resolved", None),
    ]);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "promote");
    assert!(eval.failing_fixture_ids.is_empty());
    assert!(eval.blockers.is_empty());
}

#[test]
fn enrichment_fixture_serde_roundtrip_schema_version_preserved() {
    let fixture = make_fixture(vec![]);
    let json = serde_json::to_string(&fixture).expect("serialize fixture");
    let decoded: ParserCorrectnessPromotionGateFixture =
        serde_json::from_str(&json).expect("deserialize fixture");
    assert_eq!(decoded.schema_version, fixture.schema_version);
    assert_eq!(decoded.gate_version, fixture.gate_version);
    assert_eq!(decoded.high_severity_levels, fixture.high_severity_levels);
}

#[test]
fn enrichment_evidence_vector_missing_status_produces_evidence_not_green_blocker() {
    let mut fixture = make_fixture(vec![]);
    fixture.required_evidence_lanes = vec!["lane_q".to_string()];
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_q".to_string(),
        status: "missing".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/missing.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blockers
            .iter()
            .any(|b| b.contains("evidence_not_green:lane_q:missing"))
    );
}

#[test]
fn enrichment_multiple_calls_to_emit_structured_event_are_identical() {
    let fixture = make_fixture(vec![make_drift("d1", "high", "open", None)]);
    let eval = evaluate_gate(&fixture);
    let event1 = emit_structured_event(&fixture, &eval);
    let event2 = emit_structured_event(&fixture, &eval);
    assert_eq!(
        event1.to_string(),
        event2.to_string(),
        "structured event output must be deterministic across repeated calls"
    );
}
