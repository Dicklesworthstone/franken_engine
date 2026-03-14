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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetricDirection {
    HigherIsBetter,
    LowerIsBetter,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MetricDefinition {
    metric_id: String,
    direction: MetricDirection,
    weight_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HistoryEntry {
    commit: String,
    run_id: String,
    generated_at_utc: String,
    metrics: BTreeMap<String, u64>,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedBisect {
    first_bad_commit: String,
    search_path: Vec<String>,
    classification: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ScoreboardExpectations {
    top_improvement_commit: String,
    worst_regression_commit: String,
    regression_alert_commits: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct IncidentReplayDrill {
    drill_id: String,
    replay_command: String,
    expected_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserRegressionScoreboardFixture {
    schema_version: String,
    scoreboard_version: String,
    metric_schema_version: String,
    max_allowed_regression_millionths: u32,
    metric_definitions: Vec<MetricDefinition>,
    required_log_keys: Vec<String>,
    history: Vec<HistoryEntry>,
    baseline_commit: String,
    candidate_commit: String,
    expected_bisect: ExpectedBisect,
    scoreboard_expectations: ScoreboardExpectations,
    incident_replay_drills: Vec<IncidentReplayDrill>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitScore {
    commit: String,
    run_id: String,
    generated_at_utc: String,
    composite_score_millionths: u64,
    delta_from_baseline_millionths: i64,
    regression: bool,
    replay_command: String,
    artifact_manifest: String,
    artifact_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BisectOutcome {
    classification: String,
    first_bad_commit: Option<String>,
    search_path: Vec<String>,
}

fn load_fixture() -> ParserRegressionScoreboardFixture {
    let path = Path::new("tests/fixtures/parser_regression_bisector_scoreboard_v1.json");
    let bytes = fs::read(path).expect("read parser regression fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser regression fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_REGRESSION_BISECTOR_SCOREBOARD.md");
    fs::read_to_string(path).expect("read parser regression bisector doc")
}

fn metric_score_millionths(definition: &MetricDefinition, baseline: u64, current: u64) -> u64 {
    let baseline_nonzero = u128::from(baseline.max(1));
    let current_nonzero = u128::from(current.max(1));
    let million = 1_000_000_u128;

    let ratio = match definition.direction {
        MetricDirection::HigherIsBetter => {
            current_nonzero.saturating_mul(million) / baseline_nonzero
        }
        MetricDirection::LowerIsBetter => {
            baseline_nonzero.saturating_mul(million) / current_nonzero
        }
    };
    ratio.min(u128::from(u64::MAX)) as u64
}

fn baseline_index(fixture: &ParserRegressionScoreboardFixture) -> usize {
    fixture
        .history
        .iter()
        .position(|entry| entry.commit == fixture.baseline_commit)
        .unwrap_or_else(|| panic!("missing baseline commit `{}`", fixture.baseline_commit))
}

fn candidate_index(fixture: &ParserRegressionScoreboardFixture) -> usize {
    fixture
        .history
        .iter()
        .position(|entry| entry.commit == fixture.candidate_commit)
        .unwrap_or_else(|| panic!("missing candidate commit `{}`", fixture.candidate_commit))
}

fn composite_score_millionths(
    fixture: &ParserRegressionScoreboardFixture,
    baseline: &HistoryEntry,
    current: &HistoryEntry,
) -> u64 {
    let mut numerator = 0_u128;
    for definition in &fixture.metric_definitions {
        let baseline_metric = baseline
            .metrics
            .get(&definition.metric_id)
            .unwrap_or_else(|| panic!("baseline missing metric `{}`", definition.metric_id));
        let current_metric = current
            .metrics
            .get(&definition.metric_id)
            .unwrap_or_else(|| panic!("current missing metric `{}`", definition.metric_id));
        let score = metric_score_millionths(definition, *baseline_metric, *current_metric);
        numerator = numerator.saturating_add(
            u128::from(score).saturating_mul(u128::from(definition.weight_millionths)),
        );
    }
    (numerator / 1_000_000_u128) as u64
}

fn is_regression(delta: i64, threshold_millionths: u32) -> bool {
    delta < -(i64::from(threshold_millionths))
}

fn build_commit_scores(fixture: &ParserRegressionScoreboardFixture) -> Vec<CommitScore> {
    let base_idx = baseline_index(fixture);
    let baseline = &fixture.history[base_idx];
    let baseline_score = composite_score_millionths(fixture, baseline, baseline);

    fixture
        .history
        .iter()
        .map(|entry| {
            let composite = composite_score_millionths(fixture, baseline, entry);
            let delta = composite as i64 - baseline_score as i64;
            CommitScore {
                commit: entry.commit.clone(),
                run_id: entry.run_id.clone(),
                generated_at_utc: entry.generated_at_utc.clone(),
                composite_score_millionths: composite,
                delta_from_baseline_millionths: delta,
                regression: is_regression(delta, fixture.max_allowed_regression_millionths),
                replay_command: entry.replay_command.clone(),
                artifact_manifest: entry.artifact_manifest.clone(),
                artifact_report: entry.artifact_report.clone(),
            }
        })
        .collect()
}

fn run_bisect(fixture: &ParserRegressionScoreboardFixture) -> BisectOutcome {
    let base_idx = baseline_index(fixture);
    let candidate_idx = candidate_index(fixture);
    assert!(
        candidate_idx > base_idx,
        "candidate must be newer than baseline"
    );

    let scores = build_commit_scores(fixture);
    if !scores[candidate_idx].regression {
        return BisectOutcome {
            classification: "no_regression_detected".to_string(),
            first_bad_commit: None,
            search_path: Vec::new(),
        };
    }

    let mut low = base_idx + 1;
    let mut high = candidate_idx;
    let mut path = Vec::new();

    while low < high {
        let mid = low + ((high - low) / 2);
        path.push(scores[mid].commit.clone());
        if scores[mid].regression {
            high = mid;
        } else {
            low = mid + 1;
        }
    }

    BisectOutcome {
        classification: "regression_detected".to_string(),
        first_bad_commit: Some(scores[low].commit.clone()),
        search_path: path,
    }
}

fn top_improvement_commit(scores: &[CommitScore]) -> String {
    scores
        .iter()
        .max_by(|left, right| {
            left.delta_from_baseline_millionths
                .cmp(&right.delta_from_baseline_millionths)
                .then_with(|| right.commit.cmp(&left.commit))
        })
        .expect("non-empty scores")
        .commit
        .clone()
}

fn worst_regression_commit(scores: &[CommitScore]) -> String {
    scores
        .iter()
        .min_by(|left, right| {
            left.delta_from_baseline_millionths
                .cmp(&right.delta_from_baseline_millionths)
                .then_with(|| left.commit.cmp(&right.commit))
        })
        .expect("non-empty scores")
        .commit
        .clone()
}

fn regression_alert_commits(scores: &[CommitScore]) -> Vec<String> {
    scores
        .iter()
        .filter(|score| score.regression)
        .map(|score| score.commit.clone())
        .collect()
}

fn emit_structured_events(
    fixture: &ParserRegressionScoreboardFixture,
    scores: &[CommitScore],
    bisect: &BisectOutcome,
) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for score in scores {
        events.push(serde_json::json!({
            "trace_id": "trace-parser-regression-bisector-v1",
            "decision_id": format!("decision-{}", score.commit),
            "policy_id": "policy-parser-regression-bisector-v1",
            "component": "parser_regression_bisector_scoreboard",
            "event": "scoreboard_row",
            "outcome": if score.regression { "regression" } else { "within_budget" },
            "error_code": if score.regression {
                serde_json::Value::String("FE-PARSER-REGRESSION-0001".to_string())
            } else {
                serde_json::Value::Null
            },
            "commit": score.commit,
            "delta_from_baseline_millionths": score.delta_from_baseline_millionths
        }));
    }

    events.push(serde_json::json!({
        "trace_id": "trace-parser-regression-bisector-v1",
        "decision_id": "decision-parser-regression-bisect",
        "policy_id": "policy-parser-regression-bisector-v1",
        "component": "parser_regression_bisector_scoreboard",
        "event": "bisect_completed",
        "outcome": bisect.classification,
        "error_code": serde_json::Value::Null,
        "first_bad_commit": bisect.first_bad_commit,
        "search_path": bisect.search_path,
        "required_key_count": fixture.required_log_keys.len()
    }));

    events
}

#[test]
fn parser_regression_doc_has_required_sections() {
    let doc = load_doc();
    for section in [
        "# Parser Regression Bisector and Scoreboard Contract (`bd-2mds.1.6.4`)",
        "## Bisector Determinism Contract",
        "## Scoreboard Publication Contract",
        "## Structured Log Contract",
        "./scripts/run_parser_regression_bisector_scoreboard.sh ci",
        "./scripts/e2e/parser_regression_bisector_scoreboard_replay.sh",
    ] {
        assert!(
            doc.contains(section),
            "required doc section missing: {section}"
        );
    }
}

#[test]
fn parser_regression_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-regression-bisector-scoreboard.v1"
    );
    assert_eq!(fixture.scoreboard_version, "1.0.0");
    assert_eq!(
        fixture.metric_schema_version,
        "franken-engine.parser-telemetry.v1"
    );

    assert!(
        fixture.max_allowed_regression_millionths <= 200_000,
        "regression threshold budget unexpectedly large"
    );

    let mut metric_ids = BTreeSet::new();
    let mut total_weight = 0_u64;
    for metric in &fixture.metric_definitions {
        assert!(metric_ids.insert(metric.metric_id.clone()));
        total_weight = total_weight.saturating_add(u64::from(metric.weight_millionths));
    }
    assert_eq!(total_weight, 1_000_000);

    for required_metric in [
        "throughput_sources_per_second_millionths",
        "latency_ns_p95",
        "ns_per_token_millionths",
        "allocs_per_token_millionths",
    ] {
        assert!(
            metric_ids.contains(required_metric),
            "missing required metric definition: {required_metric}"
        );
    }

    let required_keys: BTreeSet<&str> = fixture
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_keys.contains(key),
            "missing required log key `{key}`"
        );
    }

    assert!(!fixture.history.is_empty(), "history must not be empty");
    for entry in &fixture.history {
        assert!(!entry.run_id.trim().is_empty());
        assert!(!entry.generated_at_utc.trim().is_empty());
        assert!(!entry.replay_command.trim().is_empty());
        assert!(!entry.artifact_manifest.trim().is_empty());
        assert!(!entry.artifact_report.trim().is_empty());
        for metric in &fixture.metric_definitions {
            assert!(
                entry.metrics.contains_key(&metric.metric_id),
                "entry `{}` missing metric `{}`",
                entry.commit,
                metric.metric_id
            );
        }
    }

    assert!(!fixture.incident_replay_drills.is_empty());
    for drill in &fixture.incident_replay_drills {
        assert!(!drill.drill_id.trim().is_empty());
        assert!(!drill.replay_command.trim().is_empty());
    }
}

#[test]
fn regression_bisector_matches_expected_path() {
    let fixture = load_fixture();
    let first = run_bisect(&fixture);
    let second = run_bisect(&fixture);
    assert_eq!(first, second, "bisect output must be deterministic");

    assert_eq!(first.classification, fixture.expected_bisect.classification);
    assert_eq!(
        first.first_bad_commit,
        Some(fixture.expected_bisect.first_bad_commit.clone())
    );
    assert_eq!(first.search_path, fixture.expected_bisect.search_path);
}

#[test]
fn scoreboard_publication_matches_expected_rankings() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);

    let top = top_improvement_commit(&scores);
    assert_eq!(
        top, fixture.scoreboard_expectations.top_improvement_commit,
        "top improvement commit mismatch"
    );

    let worst = worst_regression_commit(&scores);
    assert_eq!(
        worst, fixture.scoreboard_expectations.worst_regression_commit,
        "worst regression commit mismatch"
    );

    let alerts = regression_alert_commits(&scores);
    assert_eq!(
        alerts,
        fixture.scoreboard_expectations.regression_alert_commits
    );

    let baseline_idx = baseline_index(&fixture);
    let candidate_idx = candidate_index(&fixture);
    assert_eq!(scores[baseline_idx].delta_from_baseline_millionths, 0);
    assert!(scores[candidate_idx].regression);

    let near_threshold_commit = scores
        .iter()
        .find(|score| score.commit == "c004")
        .expect("commit c004 should exist");
    assert!(
        !near_threshold_commit.regression,
        "c004 should remain within regression budget"
    );
}

#[test]
fn structured_log_contract_and_replay_drills_are_complete() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);

    for drill in &fixture.incident_replay_drills {
        assert!(
            drill.expected_pass,
            "replay drill `{}` must be expected to pass in fixture",
            drill.drill_id
        );
    }

    for event in &events {
        let object = event.as_object().expect("structured event must be object");
        for required in &fixture.required_log_keys {
            assert!(
                object.contains_key(required),
                "structured event missing key `{required}`"
            );
            if required == "error_code" {
                continue;
            }
            if let Some(value) = object.get(required).and_then(|raw| raw.as_str()) {
                assert!(
                    !value.trim().is_empty(),
                    "event key `{required}` must not be empty"
                );
            }
        }
    }
}

// ---------- load_fixture helper ----------

#[test]
fn load_fixture_returns_valid_fixture() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.is_empty());
    assert!(!fixture.history.is_empty());
    assert!(!fixture.metric_definitions.is_empty());
}

// ---------- load_doc helper ----------

#[test]
fn load_doc_returns_nonempty_string() {
    let doc = load_doc();
    assert!(!doc.is_empty());
    assert!(doc.contains("Bisector"));
}

// ---------- metric_score_millionths ----------

#[test]
fn metric_score_higher_is_better_above_baseline() {
    let def = MetricDefinition {
        metric_id: "x".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 500_000,
    };
    // candidate 200, baseline 100 → 2_000_000
    let score = metric_score_millionths(&def, 100, 200);
    assert_eq!(score, 2_000_000);
}

#[test]
fn metric_score_lower_is_better_below_baseline() {
    let def = MetricDefinition {
        metric_id: "y".to_string(),
        direction: MetricDirection::LowerIsBetter,
        weight_millionths: 500_000,
    };
    // baseline 200, current 100 → 2_000_000
    let score = metric_score_millionths(&def, 200, 100);
    assert_eq!(score, 2_000_000);
}

#[test]
fn metric_score_equal_values_returns_million() {
    let def = MetricDefinition {
        metric_id: "z".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 250_000,
    };
    let score = metric_score_millionths(&def, 100, 100);
    assert_eq!(score, 1_000_000);
}

// ---------- is_regression ----------

#[test]
fn is_regression_below_threshold() {
    assert!(is_regression(-100_001, 100_000));
    assert!(!is_regression(-100_000, 100_000));
    assert!(!is_regression(0, 100_000));
    assert!(!is_regression(500_000, 100_000));
}

// ---------- build_commit_scores ----------

#[test]
fn build_commit_scores_baseline_delta_is_zero() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let base_idx = baseline_index(&fixture);
    assert_eq!(scores[base_idx].delta_from_baseline_millionths, 0);
}

#[test]
fn build_commit_scores_is_deterministic() {
    let fixture = load_fixture();
    let a = build_commit_scores(&fixture);
    let b = build_commit_scores(&fixture);
    assert_eq!(a, b);
}

// ---------- run_bisect ----------

#[test]
fn run_bisect_is_deterministic() {
    let fixture = load_fixture();
    let a = run_bisect(&fixture);
    let b = run_bisect(&fixture);
    assert_eq!(a, b);
}

// ---------- top_improvement_commit / worst_regression_commit ----------

#[test]
fn top_and_worst_commits_are_different() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let top = top_improvement_commit(&scores);
    let worst = worst_regression_commit(&scores);
    // Top and worst should differ when there are both improvements and regressions
    assert_ne!(top, worst);
}

// ---------- regression_alert_commits ----------

#[test]
fn regression_alert_commits_only_contains_regressions() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let alerts = regression_alert_commits(&scores);
    for commit in &alerts {
        let score = scores.iter().find(|s| &s.commit == commit).expect("score");
        assert!(score.regression);
    }
}

// ---------- emit_structured_events ----------

#[test]
fn emit_structured_events_includes_bisect_event() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);
    // Last event is bisect_completed
    let last = events.last().expect("at least one event");
    assert_eq!(last["event"], "bisect_completed");
    assert_eq!(last["component"], "parser_regression_bisector_scoreboard");
}

#[test]
fn fixture_metric_definitions_have_unique_ids() {
    let fixture = load_fixture();
    let mut ids = BTreeSet::new();
    for metric in &fixture.metric_definitions {
        assert!(
            ids.insert(&metric.metric_id),
            "duplicate metric id: {}",
            metric.metric_id
        );
    }
}

#[test]
fn fixture_history_commits_are_nonempty() {
    let fixture = load_fixture();
    for entry in &fixture.history {
        assert!(
            !entry.commit.trim().is_empty(),
            "history commit must not be empty"
        );
    }
}

#[test]
fn emit_structured_events_count_matches_scores_plus_one() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);
    assert_eq!(
        events.len(),
        scores.len() + 1,
        "events = score rows + bisect event"
    );
}

#[test]
fn fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.history.len(), b.history.len());
}

#[test]
fn build_commit_scores_deterministic() {
    let fixture = load_fixture();
    let a = build_commit_scores(&fixture);
    let b = build_commit_scores(&fixture);
    assert_eq!(a.len(), b.len());
}

// ---------- metric_score_millionths edge cases ----------

#[test]
fn metric_score_higher_is_better_below_baseline_returns_fraction() {
    let def = MetricDefinition {
        metric_id: "regressed".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 500_000,
    };
    // candidate 50, baseline 100 → 500_000 (0.5x)
    let score = metric_score_millionths(&def, 100, 50);
    assert_eq!(score, 500_000);
}

#[test]
fn metric_score_lower_is_better_above_baseline_returns_fraction() {
    let def = MetricDefinition {
        metric_id: "latency_regressed".to_string(),
        direction: MetricDirection::LowerIsBetter,
        weight_millionths: 500_000,
    };
    // baseline 100, current 200 → 100/200 * 1_000_000 = 500_000
    let score = metric_score_millionths(&def, 100, 200);
    assert_eq!(score, 500_000);
}

#[test]
fn metric_score_zero_baseline_clamps_to_one() {
    let def = MetricDefinition {
        metric_id: "zero_base".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 1_000_000,
    };
    // baseline 0 → clamped to 1; current 100 → 100_000_000
    let score = metric_score_millionths(&def, 0, 100);
    assert_eq!(score, 100_000_000);
}

// ---------- bisect search_path is ordered ----------

#[test]
fn bisect_search_path_entries_are_valid_commits() {
    let fixture = load_fixture();
    let bisect = run_bisect(&fixture);
    let all_commits: BTreeSet<_> = fixture.history.iter().map(|e| e.commit.as_str()).collect();
    for path_commit in &bisect.search_path {
        assert!(
            all_commits.contains(path_commit.as_str()),
            "search path commit `{path_commit}` not found in history"
        );
    }
}

// ---------- commit scores carry provenance ----------

#[test]
fn commit_scores_carry_replay_command_and_artifact_provenance() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    for score in &scores {
        assert!(
            !score.replay_command.trim().is_empty(),
            "commit {} missing replay_command",
            score.commit
        );
        assert!(
            !score.artifact_manifest.trim().is_empty(),
            "commit {} missing artifact_manifest",
            score.commit
        );
        assert!(
            !score.artifact_report.trim().is_empty(),
            "commit {} missing artifact_report",
            score.commit
        );
    }
}

// ---------- structured events carry error_code for regressions ----------

#[test]
fn structured_events_regression_rows_have_error_code() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);
    for event in &events {
        if event.get("event").and_then(|v| v.as_str()) == Some("scoreboard_row") {
            if event.get("outcome").and_then(|v| v.as_str()) == Some("regression") {
                assert_eq!(
                    event["error_code"].as_str(),
                    Some("FE-PARSER-REGRESSION-0001"),
                    "regression row must carry error_code"
                );
            } else {
                assert!(
                    event["error_code"].is_null(),
                    "within_budget row must have null error_code"
                );
            }
        }
    }
}

// ---------- incident replay drill ids are unique ----------

#[test]
fn incident_replay_drill_ids_are_unique() {
    let fixture = load_fixture();
    let mut ids = BTreeSet::new();
    for drill in &fixture.incident_replay_drills {
        assert!(
            ids.insert(&drill.drill_id),
            "duplicate incident drill id: {}",
            drill.drill_id
        );
    }
}

// ---------- enrichment: MetricDirection serde roundtrip ----------

#[test]
fn metric_direction_higher_is_better_deserializes() {
    let recovered: MetricDirection =
        serde_json::from_str("\"higher_is_better\"").expect("deserialize");
    assert_eq!(recovered, MetricDirection::HigherIsBetter);
}

#[test]
fn metric_direction_lower_is_better_deserializes() {
    let recovered: MetricDirection =
        serde_json::from_str("\"lower_is_better\"").expect("deserialize");
    assert_eq!(recovered, MetricDirection::LowerIsBetter);
}

// ---------- enrichment: MetricDefinition ----------

#[test]
fn metric_definition_clone_equals_original() {
    let def = MetricDefinition {
        metric_id: "throughput".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 500_000,
    };
    let cloned = def.clone();
    assert_eq!(def, cloned);
}

#[test]
fn metric_definition_debug_contains_id() {
    let def = MetricDefinition {
        metric_id: "latency_ns".to_string(),
        direction: MetricDirection::LowerIsBetter,
        weight_millionths: 300_000,
    };
    let debug = format!("{def:?}");
    assert!(debug.contains("latency_ns"));
    assert!(debug.contains("LowerIsBetter"));
}

// ---------- enrichment: HistoryEntry ----------

#[test]
fn history_entry_clone_equals_original() {
    let mut metrics = BTreeMap::new();
    metrics.insert("throughput".to_string(), 1000);
    let entry = HistoryEntry {
        commit: "abc123".to_string(),
        run_id: "run-001".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        metrics,
        replay_command: "cargo test".to_string(),
        artifact_manifest: "manifest.json".to_string(),
        artifact_report: "report.json".to_string(),
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ---------- enrichment: CommitScore ----------

#[test]
fn commit_score_debug_contains_commit() {
    let score = CommitScore {
        commit: "abc123".to_string(),
        run_id: "run-001".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        composite_score_millionths: 1_000_000,
        delta_from_baseline_millionths: 0,
        regression: false,
        replay_command: "cargo test".to_string(),
        artifact_manifest: "manifest.json".to_string(),
        artifact_report: "report.json".to_string(),
    };
    let debug = format!("{score:?}");
    assert!(debug.contains("abc123"));
    assert!(debug.contains("CommitScore"));
}

#[test]
fn commit_score_clone_equals_original() {
    let score = CommitScore {
        commit: "def456".to_string(),
        run_id: "run-002".to_string(),
        generated_at_utc: "2026-01-02T00:00:00Z".to_string(),
        composite_score_millionths: 900_000,
        delta_from_baseline_millionths: -100_000,
        regression: false,
        replay_command: "cargo test".to_string(),
        artifact_manifest: "manifest.json".to_string(),
        artifact_report: "report.json".to_string(),
    };
    let cloned = score.clone();
    assert_eq!(score, cloned);
}

// ---------- enrichment: BisectOutcome ----------

#[test]
fn bisect_outcome_no_regression_has_none_first_bad() {
    let outcome = BisectOutcome {
        classification: "no_regression_detected".to_string(),
        first_bad_commit: None,
        search_path: Vec::new(),
    };
    assert!(outcome.first_bad_commit.is_none());
    assert!(outcome.search_path.is_empty());
}

#[test]
fn bisect_outcome_regression_detected_has_some_first_bad() {
    let fixture = load_fixture();
    let bisect = run_bisect(&fixture);
    assert_eq!(bisect.classification, "regression_detected");
    assert!(bisect.first_bad_commit.is_some());
}

#[test]
fn bisect_outcome_debug_contains_classification() {
    let outcome = BisectOutcome {
        classification: "regression_detected".to_string(),
        first_bad_commit: Some("c005".to_string()),
        search_path: vec!["c003".to_string(), "c004".to_string()],
    };
    let debug = format!("{outcome:?}");
    assert!(debug.contains("regression_detected"));
    assert!(debug.contains("c005"));
}

// ---------- enrichment: fixture structural properties ----------

#[test]
fn fixture_history_commits_are_unique() {
    let fixture = load_fixture();
    let mut commits = BTreeSet::new();
    for entry in &fixture.history {
        assert!(
            commits.insert(entry.commit.as_str()),
            "duplicate commit: {}",
            entry.commit
        );
    }
}

#[test]
fn fixture_baseline_commit_exists_in_history() {
    let fixture = load_fixture();
    assert!(
        fixture
            .history
            .iter()
            .any(|e| e.commit == fixture.baseline_commit),
        "baseline commit {} not in history",
        fixture.baseline_commit
    );
}

#[test]
fn fixture_candidate_commit_exists_in_history() {
    let fixture = load_fixture();
    assert!(
        fixture
            .history
            .iter()
            .any(|e| e.commit == fixture.candidate_commit),
        "candidate commit {} not in history",
        fixture.candidate_commit
    );
}

#[test]
fn fixture_candidate_is_after_baseline() {
    let fixture = load_fixture();
    let base_idx = baseline_index(&fixture);
    let cand_idx = candidate_index(&fixture);
    assert!(
        cand_idx > base_idx,
        "candidate must be after baseline in history"
    );
}

#[test]
fn fixture_metric_weights_sum_to_one_million() {
    let fixture = load_fixture();
    let total: u64 = fixture
        .metric_definitions
        .iter()
        .map(|m| u64::from(m.weight_millionths))
        .sum();
    assert_eq!(total, 1_000_000);
}

// ---------- enrichment: metric edge cases ----------

#[test]
fn metric_score_both_zero_clamps_to_million() {
    let def = MetricDefinition {
        metric_id: "both_zero".to_string(),
        direction: MetricDirection::HigherIsBetter,
        weight_millionths: 1_000_000,
    };
    // Both zero → clamped to 1/1 → 1_000_000
    let score = metric_score_millionths(&def, 0, 0);
    assert_eq!(score, 1_000_000);
}

#[test]
fn metric_score_lower_is_better_zero_current_clamps() {
    let def = MetricDefinition {
        metric_id: "zero_current".to_string(),
        direction: MetricDirection::LowerIsBetter,
        weight_millionths: 1_000_000,
    };
    // baseline 100, current 0 → clamped to 1 → 100/1 * 1_000_000 = 100_000_000
    let score = metric_score_millionths(&def, 100, 0);
    assert_eq!(score, 100_000_000);
}

// ---------- enrichment: structured events ----------

#[test]
fn structured_events_all_have_trace_id() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);
    for event in &events {
        assert!(
            event.get("trace_id").is_some(),
            "event missing trace_id: {event}"
        );
    }
}

#[test]
fn structured_events_scoreboard_rows_match_history_count() {
    let fixture = load_fixture();
    let scores = build_commit_scores(&fixture);
    let bisect = run_bisect(&fixture);
    let events = emit_structured_events(&fixture, &scores, &bisect);
    let row_count = events
        .iter()
        .filter(|e| e.get("event").and_then(|v| v.as_str()) == Some("scoreboard_row"))
        .count();
    assert_eq!(row_count, fixture.history.len());
}
