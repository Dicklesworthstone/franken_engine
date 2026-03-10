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

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct BenchmarkRow {
    workload_id: String,
    corpus_id: String,
    peer_id: String,
    quantile: String,
    franken_score_millionths: i64,
    peer_score_millionths: i64,
    sample_count: u64,
    confidence_low_delta_millionths: i64,
    confidence_high_delta_millionths: i64,
    protocol_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceVector {
    lane_id: String,
    status: String,
    artifact_manifest: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TelemetryArtifact {
    artifact_id: String,
    manifest_path: String,
    protocol_hash: String,
    reproducible: bool,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_blocked_pairs: Vec<String>,
    expected_failing_workload_ids: Vec<String>,
    expected_verified_pairs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserPerformancePromotionGateFixture {
    schema_version: String,
    gate_version: String,
    protocol_version: String,
    protocol_hash: String,
    required_peers: Vec<String>,
    required_quantiles: Vec<String>,
    minimum_delta_millionths_by_quantile: BTreeMap<String, i64>,
    required_evidence_lanes: Vec<String>,
    required_structured_log_keys: Vec<String>,
    evidence_vectors: Vec<EvidenceVector>,
    telemetry_artifacts: Vec<TelemetryArtifact>,
    benchmark_rows: Vec<BenchmarkRow>,
    expected_gate: ExpectedGate,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    blocked_pairs: Vec<String>,
    failing_workload_ids: Vec<String>,
    verified_pairs: usize,
}

fn load_fixture() -> ParserPerformancePromotionGateFixture {
    let path = Path::new("tests/fixtures/parser_performance_promotion_gate_v1.json");
    let bytes = fs::read(path).expect("read parser performance promotion fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser performance promotion fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_PERFORMANCE_PROMOTION_GATE.md");
    fs::read_to_string(path).expect("read parser performance promotion gate doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_performance_promotion_gate.sh");
    fs::read_to_string(path).expect("read parser performance promotion gate script")
}

fn pair_key(peer_id: &str, quantile: &str) -> (String, String) {
    (peer_id.to_string(), quantile.to_string())
}

fn pair_blocker(peer_id: &str, quantile: &str, reason: &str) -> String {
    format!("{peer_id}:{quantile}:{reason}")
}

fn evaluate_gate(fixture: &ParserPerformancePromotionGateFixture) -> GateEvaluation {
    let mut blockers = BTreeSet::new();
    let mut failing_workloads = BTreeSet::new();

    let evidence_by_lane = fixture
        .evidence_vectors
        .iter()
        .map(|lane| (lane.lane_id.as_str(), lane.status.as_str()))
        .collect::<BTreeMap<_, _>>();

    for required_lane in &fixture.required_evidence_lanes {
        match evidence_by_lane.get(required_lane.as_str()) {
            Some(status) if *status == "pass" => {}
            Some(status) => {
                blockers.insert(format!("evidence_not_green:{required_lane}:{status}"));
            }
            None => {
                blockers.insert(format!("evidence_missing:{required_lane}"));
            }
        }
    }

    for artifact in &fixture.telemetry_artifacts {
        if artifact.protocol_hash != fixture.protocol_hash {
            blockers.insert(format!("telemetry_protocol_drift:{}", artifact.artifact_id));
        }
        if !artifact.reproducible {
            blockers.insert(format!(
                "telemetry_not_reproducible:{}",
                artifact.artifact_id
            ));
        }
    }

    let mut rows_by_pair = BTreeMap::<(String, String), Vec<&BenchmarkRow>>::new();
    for row in &fixture.benchmark_rows {
        rows_by_pair
            .entry(pair_key(row.peer_id.as_str(), row.quantile.as_str()))
            .or_default()
            .push(row);

        if row.protocol_hash != fixture.protocol_hash {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "protocol_drift",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }

        if row.sample_count == 0 {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "sample_count_zero",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }

        if row.confidence_low_delta_millionths > row.confidence_high_delta_millionths {
            blockers.insert(pair_blocker(
                row.peer_id.as_str(),
                row.quantile.as_str(),
                "invalid_confidence_interval",
            ));
            failing_workloads.insert(row.workload_id.clone());
        }
    }

    let mut verified_pairs = 0usize;
    for peer in &fixture.required_peers {
        for quantile in &fixture.required_quantiles {
            let pair = pair_key(peer.as_str(), quantile.as_str());
            let rows = rows_by_pair.get(&pair);
            let threshold = fixture
                .minimum_delta_millionths_by_quantile
                .get(quantile)
                .copied()
                .unwrap_or(0);

            let Some(rows) = rows else {
                blockers.insert(pair_blocker(peer, quantile, "missing_pair"));
                continue;
            };

            if rows.len() != 1 {
                blockers.insert(pair_blocker(peer, quantile, "duplicate_pair_rows"));
            }

            let row = rows[0];
            let delta = row
                .franken_score_millionths
                .saturating_sub(row.peer_score_millionths);

            if delta < threshold {
                blockers.insert(pair_blocker(peer, quantile, "delta_below_threshold"));
                failing_workloads.insert(row.workload_id.clone());
            }

            if row.confidence_low_delta_millionths <= 0 {
                blockers.insert(pair_blocker(peer, quantile, "non_reproducible_win"));
                failing_workloads.insert(row.workload_id.clone());
            }

            if row.sample_count > 0
                && row.confidence_low_delta_millionths <= row.confidence_high_delta_millionths
                && row.protocol_hash == fixture.protocol_hash
                && delta >= threshold
                && row.confidence_low_delta_millionths > 0
            {
                verified_pairs = verified_pairs.saturating_add(1);
            }
        }
    }

    let blocked_pairs = blockers.into_iter().collect::<Vec<_>>();
    let failing_workload_ids = failing_workloads.into_iter().collect::<Vec<_>>();

    let outcome = if blocked_pairs.is_empty() {
        "promote"
    } else {
        "hold"
    }
    .to_string();

    GateEvaluation {
        outcome,
        blocked_pairs,
        failing_workload_ids,
        verified_pairs,
    }
}

fn emit_structured_event(
    fixture: &ParserPerformancePromotionGateFixture,
    evaluation: &GateEvaluation,
) -> serde_json::Value {
    let corpus_inventory = fixture
        .benchmark_rows
        .iter()
        .map(|row| row.corpus_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let quantile_inventory = fixture.required_quantiles.to_vec();

    let replay_pointers = fixture
        .evidence_vectors
        .iter()
        .map(|lane| lane.replay_command.clone())
        .chain(
            fixture
                .telemetry_artifacts
                .iter()
                .map(|artifact| artifact.replay_command.clone()),
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
        "trace_id": "trace-parser-performance-promotion-gate-v1",
        "decision_id": "decision-parser-performance-promotion-gate-v1",
        "policy_id": "policy-parser-performance-promotion-gate-v1",
        "component": "parser_performance_promotion_gate",
        "event": "performance_gate_evaluated",
        "outcome": evaluation.outcome,
        "error_code": if evaluation.outcome == "promote" {
            serde_json::Value::Null
        } else {
            serde_json::Value::String("FE-PARSER-PERF-GATE-0001".to_string())
        },
        "blocked_pairs": evaluation.blocked_pairs,
        "failing_workload_ids": evaluation.failing_workload_ids,
        "corpus_inventory": corpus_inventory,
        "quantile_inventory": quantile_inventory,
        "replay_pointers": replay_pointers,
        "protocol_version": fixture.protocol_version,
        "protocol_hash": fixture.protocol_hash,
        "verified_pairs": evaluation.verified_pairs,
        "telemetry_manifest_paths": fixture
            .telemetry_artifacts
            .iter()
            .map(|artifact| artifact.manifest_path.clone())
            .collect::<Vec<_>>(),
        "evidence_manifests": fixture
            .evidence_vectors
            .iter()
            .map(|lane| lane.artifact_manifest.clone())
            .collect::<Vec<_>>()
    })
}

#[test]
fn parser_performance_doc_has_required_sections() {
    let doc = load_doc();

    for section in [
        "# Parser Performance Promotion Gate (`bd-2mds.1.8.3`)",
        "## Promotion Policy",
        "## Benchmark Protocol Requirements",
        "## Reproducibility and Confidence Semantics",
        "## Evidence Requirements",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
    ] {
        assert!(doc.contains(section), "missing section: {section}");
    }

    for command in [
        "./scripts/run_parser_performance_promotion_gate.sh ci",
        "./scripts/e2e/parser_performance_promotion_gate_replay.sh",
    ] {
        assert!(
            doc.contains(command),
            "missing command reference: {command}"
        );
    }
}

#[test]
fn parser_performance_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-performance-promotion-gate.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");
    assert!(!fixture.protocol_version.trim().is_empty());
    assert!(fixture.protocol_hash.starts_with("sha256:"));

    assert!(!fixture.required_peers.is_empty());
    assert!(!fixture.required_quantiles.is_empty());

    for quantile in &fixture.required_quantiles {
        assert!(
            fixture
                .minimum_delta_millionths_by_quantile
                .contains_key(quantile),
            "missing threshold for quantile: {quantile}"
        );
    }

    for row in &fixture.benchmark_rows {
        assert!(
            fixture.required_peers.contains(&row.peer_id),
            "benchmark row peer is undeclared: {}",
            row.peer_id
        );
        assert!(
            fixture.required_quantiles.contains(&row.quantile),
            "benchmark row quantile is undeclared: {}",
            row.quantile
        );
        assert!(row.sample_count > 0, "sample count must be > 0");
        assert!(
            row.confidence_low_delta_millionths <= row.confidence_high_delta_millionths,
            "invalid confidence interval for {}:{}",
            row.peer_id,
            row.quantile
        );
        assert_eq!(
            row.protocol_hash, fixture.protocol_hash,
            "row protocol hash drift for {}:{}",
            row.peer_id, row.quantile
        );
    }

    let pair_count = fixture.required_peers.len() * fixture.required_quantiles.len();
    assert_eq!(
        fixture.benchmark_rows.len(),
        pair_count,
        "fixture must declare one row per required peer/quantile pair"
    );
}

#[test]
fn parser_performance_gate_evaluation_matches_expected_contract() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    assert_eq!(evaluation.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(
        evaluation.blocked_pairs,
        fixture.expected_gate.expected_blocked_pairs
    );
    assert_eq!(
        evaluation.failing_workload_ids,
        fixture.expected_gate.expected_failing_workload_ids
    );
    assert_eq!(
        evaluation.verified_pairs,
        fixture.expected_gate.expected_verified_pairs
    );
}

#[test]
fn parser_performance_structured_event_has_required_keys() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &evaluation);

    let object = event
        .as_object()
        .expect("structured event should serialize to object");

    for required_key in &fixture.required_structured_log_keys {
        assert!(
            object.contains_key(required_key),
            "missing structured log key: {required_key}"
        );
    }

    assert_eq!(
        object
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .expect("outcome string"),
        fixture.expected_gate.expected_outcome
    );
}

#[test]
fn parser_performance_replay_scenarios_align_with_gate_outcome() {
    let fixture = load_fixture();
    let evaluation = evaluate_gate(&fixture);

    for scenario in &fixture.replay_scenarios {
        assert!(
            scenario
                .replay_command
                .contains("parser_performance_promotion_gate_replay.sh"),
            "replay scenario must use one-command replay wrapper: {}",
            scenario.scenario_id
        );

        assert!(
            scenario.expected_pass,
            "scenario should expect runnable replay"
        );
        assert_eq!(scenario.expected_outcome, evaluation.outcome);
    }
}

#[test]
fn parser_performance_evidence_vectors_and_telemetry_paths_are_contract_shaped() {
    let fixture = load_fixture();

    for vector in &fixture.evidence_vectors {
        assert!(
            vector.artifact_manifest.ends_with("/run_manifest.json"),
            "evidence manifest should end with run_manifest.json: {}",
            vector.artifact_manifest
        );
        assert!(
            vector.replay_command.starts_with("./scripts/e2e/"),
            "evidence replay command should use e2e wrapper path: {}",
            vector.replay_command
        );
    }

    for artifact in &fixture.telemetry_artifacts {
        assert!(
            artifact.manifest_path.ends_with("/run_manifest.json"),
            "telemetry manifest should end with run_manifest.json: {}",
            artifact.manifest_path
        );
        assert!(
            artifact.replay_command.starts_with("./scripts/e2e/"),
            "telemetry replay command should use e2e wrapper path: {}",
            artifact.replay_command
        );
    }
}

#[test]
fn parser_performance_gate_script_contains_fail_closed_rch_markers() {
    let script = load_script();
    let required_markers = [
        "policy-parser-performance-promotion-gate-v1",
        "rch_last_remote_exit_code",
        "rch_has_recoverable_artifact_timeout",
        "rch_reject_artifact_retrieval_failure",
        "running locally",
        "RCH-E326",
        "rsync error: .*code 23",
        "parser_frontier_emit_manifest_environment_fields",
        "./scripts/e2e/parser_performance_promotion_gate_replay.sh",
    ];

    for marker in required_markers {
        assert!(
            script.contains(marker),
            "performance gate script missing marker: {marker}"
        );
    }
}

// ---------- pair_key ----------

#[test]
fn pair_key_returns_owned_tuple() {
    let (peer, quantile) = pair_key("v8", "p99");
    assert_eq!(peer, "v8");
    assert_eq!(quantile, "p99");
}

// ---------- pair_blocker ----------

#[test]
fn pair_blocker_formats_three_segments() {
    let blocker = pair_blocker("v8", "p99", "protocol_drift");
    assert_eq!(blocker, "v8:p99:protocol_drift");
}

#[test]
fn pair_blocker_empty_fields_still_format() {
    let blocker = pair_blocker("", "", "");
    assert_eq!(blocker, "::");
}

// ---------- evaluate_gate with synthetic data ----------

fn minimal_fixture(
    franken: i64,
    peer: i64,
    sample_count: u64,
    ci_low: i64,
    ci_high: i64,
    threshold: i64,
) -> ParserPerformancePromotionGateFixture {
    let protocol_hash = "sha256:abc123".to_string();
    ParserPerformancePromotionGateFixture {
        schema_version: "franken-engine.parser-performance-promotion-gate.v1".to_string(),
        gate_version: "1.0.0".to_string(),
        protocol_version: "1.0".to_string(),
        protocol_hash: protocol_hash.clone(),
        required_peers: vec!["peer-a".to_string()],
        required_quantiles: vec!["p50".to_string()],
        minimum_delta_millionths_by_quantile: {
            let mut m = BTreeMap::new();
            m.insert("p50".to_string(), threshold);
            m
        },
        required_evidence_lanes: vec![],
        required_structured_log_keys: vec![],
        evidence_vectors: vec![],
        telemetry_artifacts: vec![],
        benchmark_rows: vec![BenchmarkRow {
            workload_id: "wl-1".to_string(),
            corpus_id: "corpus-1".to_string(),
            peer_id: "peer-a".to_string(),
            quantile: "p50".to_string(),
            franken_score_millionths: franken,
            peer_score_millionths: peer,
            sample_count,
            confidence_low_delta_millionths: ci_low,
            confidence_high_delta_millionths: ci_high,
            protocol_hash,
        }],
        expected_gate: ExpectedGate {
            expected_outcome: String::new(),
            expected_blocked_pairs: vec![],
            expected_failing_workload_ids: vec![],
            expected_verified_pairs: 0,
        },
        replay_scenarios: vec![],
    }
}

#[test]
fn evaluate_gate_promotes_when_all_conditions_pass() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "promote");
    assert!(eval.blocked_pairs.is_empty());
    assert_eq!(eval.verified_pairs, 1);
}

#[test]
fn evaluate_gate_holds_when_delta_below_threshold() {
    let fixture = minimal_fixture(1_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("delta_below_threshold"))
    );
}

#[test]
fn evaluate_gate_holds_when_sample_count_zero() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 0, 500_000, 1_500_000, 0);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("sample_count_zero"))
    );
}

#[test]
fn evaluate_gate_holds_when_invalid_confidence_interval() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 1_500_000, 500_000, 0);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("invalid_confidence_interval"))
    );
}

#[test]
fn evaluate_gate_holds_when_ci_low_not_positive() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 0, 1_500_000, 0);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("non_reproducible_win"))
    );
}

#[test]
fn evaluate_gate_protocol_drift_in_row_blocks() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 0);
    fixture.benchmark_rows[0].protocol_hash = "sha256:different".to_string();
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("protocol_drift"))
    );
    assert!(eval.failing_workload_ids.contains(&"wl-1".to_string()));
}

#[test]
fn evaluate_gate_missing_evidence_lane_blocks() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    fixture.required_evidence_lanes = vec!["lane_missing".to_string()];
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("evidence_missing:lane_missing"))
    );
}

#[test]
fn evaluate_gate_non_reproducible_telemetry_blocks() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    fixture.telemetry_artifacts.push(TelemetryArtifact {
        artifact_id: "art-1".to_string(),
        manifest_path: "path/run_manifest.json".to_string(),
        protocol_hash: fixture.protocol_hash.clone(),
        reproducible: false,
        replay_command: "./scripts/e2e/replay.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("telemetry_not_reproducible:art-1"))
    );
}

// ---------- emit_structured_event ----------

#[test]
fn emit_structured_event_promote_has_null_error_code() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert!(event.get("error_code").unwrap().is_null());
    assert_eq!(event.get("outcome").unwrap().as_str().unwrap(), "promote");
}

#[test]
fn emit_structured_event_hold_has_error_code() {
    let fixture = minimal_fixture(1_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert_eq!(
        event.get("error_code").unwrap().as_str().unwrap(),
        "FE-PARSER-PERF-GATE-0001"
    );
}

#[test]
fn emit_structured_event_contains_schema_version() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert_eq!(
        event.get("schema_version").unwrap().as_str().unwrap(),
        "franken-engine.parser-log-event.v1"
    );
}

// ---------- evaluate_gate determinism ----------

#[test]
fn evaluate_gate_deterministic_across_runs() {
    let fixture = load_fixture();
    let eval1 = evaluate_gate(&fixture);
    let eval2 = evaluate_gate(&fixture);
    assert_eq!(eval1, eval2);
}

#[test]
fn load_fixture_has_nonempty_gate_version() {
    let fixture = load_fixture();
    assert!(!fixture.gate_version.trim().is_empty());
}

#[test]
fn load_fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn load_doc_has_more_than_50_lines() {
    let doc = load_doc();
    assert!(doc.lines().count() > 50);
}

// ---------- evaluate_gate edge cases ----------

#[test]
fn evaluate_gate_negative_delta_blocks_even_with_zero_threshold() {
    // franken slower than peer: delta = 500_000 - 1_000_000 = -500_000 < 0
    let fixture = minimal_fixture(500_000, 1_000_000, 100, 1, 1_500_000, 0);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("delta_below_threshold")),
        "negative delta should trigger delta_below_threshold"
    );
    assert_eq!(eval.verified_pairs, 0);
}

#[test]
fn evaluate_gate_evidence_lane_with_non_pass_status_blocks() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    fixture.required_evidence_lanes = vec!["lane_a".to_string()];
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_a".to_string(),
        status: "fail".to_string(),
        artifact_manifest: "path/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/replay.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("evidence_not_green:lane_a:fail")),
        "evidence lane with fail status should block"
    );
}

#[test]
fn evaluate_gate_telemetry_protocol_drift_blocks() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    fixture.telemetry_artifacts.push(TelemetryArtifact {
        artifact_id: "art-drift".to_string(),
        manifest_path: "path/run_manifest.json".to_string(),
        protocol_hash: "sha256:different_hash".to_string(),
        reproducible: true,
        replay_command: "./scripts/e2e/replay.sh".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "hold");
    assert!(
        eval.blocked_pairs
            .iter()
            .any(|b| b.contains("telemetry_protocol_drift:art-drift")),
        "telemetry with mismatched protocol hash should block"
    );
}

// ---------- emit_structured_event field coverage ----------

#[test]
fn emit_structured_event_contains_corpus_and_quantile_inventories() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);

    let corpus_inv = event["corpus_inventory"]
        .as_array()
        .expect("corpus_inventory should be an array");
    assert!(
        corpus_inv.iter().any(|v| v == "corpus-1"),
        "corpus inventory must contain rows' corpus_id"
    );

    let quantile_inv = event["quantile_inventory"]
        .as_array()
        .expect("quantile_inventory should be an array");
    assert!(
        quantile_inv.iter().any(|v| v == "p50"),
        "quantile inventory must reflect required_quantiles"
    );
}

// ---------- fixture benchmark rows deterministic ordering ----------

#[test]
fn evaluate_gate_deterministic_blocker_ordering_for_multiple_pairs() {
    let protocol_hash = "sha256:abc123".to_string();
    let fixture = ParserPerformancePromotionGateFixture {
        schema_version: "franken-engine.parser-performance-promotion-gate.v1".to_string(),
        gate_version: "1.0.0".to_string(),
        protocol_version: "1.0".to_string(),
        protocol_hash: protocol_hash.clone(),
        required_peers: vec!["peer-a".to_string(), "peer-b".to_string()],
        required_quantiles: vec!["p50".to_string(), "p99".to_string()],
        minimum_delta_millionths_by_quantile: {
            let mut m = BTreeMap::new();
            m.insert("p50".to_string(), 0);
            m.insert("p99".to_string(), 0);
            m
        },
        required_evidence_lanes: vec![],
        required_structured_log_keys: vec![],
        evidence_vectors: vec![],
        telemetry_artifacts: vec![],
        benchmark_rows: vec![],
        expected_gate: ExpectedGate {
            expected_outcome: String::new(),
            expected_blocked_pairs: vec![],
            expected_failing_workload_ids: vec![],
            expected_verified_pairs: 0,
        },
        replay_scenarios: vec![],
    };
    let eval1 = evaluate_gate(&fixture);
    let eval2 = evaluate_gate(&fixture);
    assert_eq!(
        eval1.blocked_pairs, eval2.blocked_pairs,
        "blocker ordering must be deterministic across runs"
    );
    // All pairs are missing, so we should see 4 missing_pair blockers
    assert_eq!(eval1.blocked_pairs.len(), 4);
    assert!(
        eval1
            .blocked_pairs
            .iter()
            .all(|b| b.contains("missing_pair")),
        "all blockers should be missing_pair for empty rows"
    );
}

#[test]
fn emit_structured_event_verified_pairs_field_matches_evaluation() {
    let fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    assert_eq!(
        event["verified_pairs"].as_u64().unwrap(),
        eval.verified_pairs as u64
    );
}

#[test]
fn emit_structured_event_replay_pointers_are_deduped_and_sorted() {
    let mut fixture = minimal_fixture(2_000_000, 1_000_000, 100, 500_000, 1_500_000, 500_000);
    fixture.evidence_vectors.push(EvidenceVector {
        lane_id: "lane_dup".to_string(),
        status: "pass".to_string(),
        artifact_manifest: "p/run_manifest.json".to_string(),
        replay_command: "./scripts/e2e/replay_a.sh".to_string(),
    });
    fixture.replay_scenarios.push(ReplayScenario {
        scenario_id: "sc-dup".to_string(),
        replay_command: "./scripts/e2e/replay_a.sh".to_string(),
        expected_pass: true,
        expected_outcome: "promote".to_string(),
    });
    let eval = evaluate_gate(&fixture);
    let event = emit_structured_event(&fixture, &eval);
    let pointers = event["replay_pointers"]
        .as_array()
        .expect("replay_pointers array");
    // The duplicate replay command should appear only once (BTreeSet dedup)
    let replay_strs: Vec<&str> = pointers.iter().map(|v| v.as_str().unwrap()).collect();
    let unique: BTreeSet<&str> = replay_strs.iter().copied().collect();
    assert_eq!(
        replay_strs.len(),
        unique.len(),
        "replay pointers must be deduplicated"
    );
    // Also must be sorted
    let mut sorted = replay_strs.clone();
    sorted.sort();
    assert_eq!(replay_strs, sorted, "replay pointers must be sorted");
}

#[test]
fn evaluate_gate_exactly_at_threshold_promotes() {
    // delta = 2_000_000 - 1_500_000 = 500_000, threshold = 500_000
    let fixture = minimal_fixture(2_000_000, 1_500_000, 100, 1, 1_500_000, 500_000);
    let eval = evaluate_gate(&fixture);
    assert_eq!(eval.outcome, "promote", "delta == threshold should promote");
    assert_eq!(eval.verified_pairs, 1);
}

#[test]
fn pair_blocker_format_is_colon_separated() {
    let b = pair_blocker("peer-x", "p99.9", "reason_y");
    let parts: Vec<&str> = b.split(':').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "peer-x");
    assert_eq!(parts[1], "p99.9");
    assert_eq!(parts[2], "reason_y");
}

#[test]
fn evaluate_gate_fixture_double_evaluation_is_stable() {
    let fixture = load_fixture();
    let first = evaluate_gate(&fixture);
    let second = evaluate_gate(&fixture);
    assert_eq!(first.outcome, second.outcome);
    assert_eq!(first.blocked_pairs, second.blocked_pairs);
    assert_eq!(first.failing_workload_ids, second.failing_workload_ids);
    assert_eq!(first.verified_pairs, second.verified_pairs);
}
