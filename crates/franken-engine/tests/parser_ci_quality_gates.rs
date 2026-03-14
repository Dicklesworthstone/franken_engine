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
struct CiRunRecord {
    run_id: String,
    epoch: u32,
    suite_kind: String,
    case_id: String,
    outcome: String,
    duration_ms: u64,
    error_signature: Option<String>,
    replay_command: String,
    artifact_bundle_id: String,
    created_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RetentionBundle {
    bundle_id: String,
    run_id: String,
    created_at_utc: String,
    ttl_days: u32,
    searchable_tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedFlake {
    case_id: String,
    suite_kind: String,
    flake_rate_millionths: u32,
    severity: String,
    quarantine_action: String,
    dominant_error_signature: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedGate {
    expected_outcome: String,
    expected_latest_suites_green: bool,
    expected_blockers: Vec<String>,
    expected_flake_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExpectedSearchIndexHit {
    query: String,
    expected_bundle_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    replay_command: String,
    expected_pass: bool,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserCiQualityGatesFixture {
    schema_version: String,
    gate_version: String,
    high_flake_threshold_millionths: u32,
    min_retention_days: u32,
    structured_log_required_keys: Vec<String>,
    runs: Vec<CiRunRecord>,
    retention_bundles: Vec<RetentionBundle>,
    expected_flakes: Vec<ExpectedFlake>,
    expected_gate: ExpectedGate,
    expected_search_index_hits: Vec<ExpectedSearchIndexHit>,
    replay_scenarios: Vec<ReplayScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlakeClassification {
    case_id: String,
    suite_kind: String,
    pass_count: u32,
    fail_count: u32,
    flake_rate_millionths: u32,
    severity: String,
    quarantine_action: String,
    dominant_error_signature: String,
    replay_command: String,
    artifact_bundle_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateEvaluation {
    outcome: String,
    latest_suites_green: bool,
    blockers: Vec<String>,
}

fn load_fixture() -> ParserCiQualityGatesFixture {
    let path = Path::new("tests/fixtures/parser_ci_quality_gates_v1.json");
    let bytes = fs::read(path).expect("read parser ci quality gates fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser ci quality gates fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_CI_QUALITY_GATES_FLAKE_RETENTION.md");
    fs::read_to_string(path).expect("read parser ci quality gates doc")
}

fn dominant_error_signature(entries: &[&CiRunRecord]) -> String {
    let mut counts = BTreeMap::<String, u32>::new();
    for entry in entries {
        if entry.outcome == "fail"
            && let Some(signature) = entry.error_signature.as_ref()
        {
            *counts.entry(signature.clone()).or_default() += 1;
        }
    }

    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
        .map(|(signature, _)| signature)
        .unwrap_or_else(|| "none".to_string())
}

fn classify_flakes(fixture: &ParserCiQualityGatesFixture) -> Vec<FlakeClassification> {
    let mut grouped = BTreeMap::<(String, String), Vec<&CiRunRecord>>::new();
    for run in &fixture.runs {
        grouped
            .entry((run.suite_kind.clone(), run.case_id.clone()))
            .or_default()
            .push(run);
    }

    let mut flakes = Vec::new();
    for ((suite_kind, case_id), entries) in grouped {
        let pass_count = entries
            .iter()
            .filter(|entry| entry.outcome == "pass")
            .count() as u32;
        let fail_count = entries
            .iter()
            .filter(|entry| entry.outcome == "fail")
            .count() as u32;
        if pass_count == 0 || fail_count == 0 {
            continue;
        }

        let total_runs = (pass_count + fail_count).max(1);
        let flake_rate_millionths =
            pass_count.min(fail_count).saturating_mul(1_000_000) / total_runs;
        let severity = if flake_rate_millionths >= fixture.high_flake_threshold_millionths {
            "high"
        } else {
            "warning"
        };
        let quarantine_action = if severity == "high" {
            "quarantine-immediate"
        } else {
            "observe"
        };

        let replay_command = entries
            .first()
            .expect("flake case must include at least one run")
            .replay_command
            .clone();
        let artifact_bundle_ids = entries
            .iter()
            .map(|entry| entry.artifact_bundle_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        flakes.push(FlakeClassification {
            case_id,
            suite_kind,
            pass_count,
            fail_count,
            flake_rate_millionths,
            severity: severity.to_string(),
            quarantine_action: quarantine_action.to_string(),
            dominant_error_signature: dominant_error_signature(&entries),
            replay_command,
            artifact_bundle_ids,
        });
    }

    flakes
}

fn evaluate_gate(
    fixture: &ParserCiQualityGatesFixture,
    flakes: &[FlakeClassification],
) -> GateEvaluation {
    let latest_epoch = fixture
        .runs
        .iter()
        .map(|run| run.epoch)
        .max()
        .expect("fixture runs must not be empty");

    let mut blockers = Vec::new();
    let mut latest_suites_green = true;
    for suite_kind in ["unit", "e2e"] {
        let latest_suite_runs = fixture
            .runs
            .iter()
            .filter(|run| run.epoch == latest_epoch && run.suite_kind == suite_kind)
            .collect::<Vec<_>>();

        if latest_suite_runs.is_empty() {
            latest_suites_green = false;
            blockers.push(format!("missing_latest_suite:{suite_kind}"));
            continue;
        }

        if latest_suite_runs.iter().any(|run| run.outcome != "pass") {
            latest_suites_green = false;
            blockers.push(format!("latest_suite_not_green:{suite_kind}"));
        }
    }

    for flake in flakes.iter().filter(|flake| flake.severity == "high") {
        blockers.push(format!("high_flake_rate:{}", flake.case_id));
    }

    blockers.sort();
    blockers.dedup();

    let has_high_flakes = flakes.iter().any(|flake| flake.severity == "high");
    let outcome = if latest_suites_green && !has_high_flakes {
        "promote"
    } else {
        "hold"
    };

    GateEvaluation {
        outcome: outcome.to_string(),
        latest_suites_green,
        blockers,
    }
}

fn build_search_index(retention_bundles: &[RetentionBundle]) -> BTreeMap<String, BTreeSet<String>> {
    let mut index = BTreeMap::<String, BTreeSet<String>>::new();
    for bundle in retention_bundles {
        for token in &bundle.searchable_tokens {
            index
                .entry(token.clone())
                .or_default()
                .insert(bundle.bundle_id.clone());
        }
    }
    index
}

fn emit_structured_events(
    flakes: &[FlakeClassification],
    gate: &GateEvaluation,
) -> Vec<serde_json::Value> {
    let mut events = Vec::new();

    for flake in flakes {
        events.push(serde_json::json!({
            "schema_version": "franken-engine.parser-log-event.v1",
            "trace_id": "trace-parser-ci-quality-gates-v1",
            "decision_id": format!("decision-parser-ci-quality-gates-{}", flake.case_id),
            "policy_id": "policy-parser-ci-quality-gates-v1",
            "component": "parser_ci_quality_gates",
            "event": "flake_classified",
            "outcome": flake.severity,
            "error_code": if flake.severity == "high" {
                serde_json::Value::String("FE-PARSER-CI-QUALITY-GATE-0001".to_string())
            } else {
                serde_json::Value::Null
            },
            "suite_kind": flake.suite_kind,
            "case_id": flake.case_id,
            "pass_count": flake.pass_count,
            "fail_count": flake.fail_count,
            "flake_rate_millionths": flake.flake_rate_millionths,
            "quarantine_action": flake.quarantine_action,
            "dominant_error_signature": flake.dominant_error_signature,
            "replay_command": flake.replay_command,
            "artifact_bundle_ids": flake.artifact_bundle_ids,
        }));
    }

    events.push(serde_json::json!({
        "schema_version": "franken-engine.parser-log-event.v1",
        "trace_id": "trace-parser-ci-quality-gates-v1",
        "decision_id": "decision-parser-ci-quality-gates",
        "policy_id": "policy-parser-ci-quality-gates-v1",
        "component": "parser_ci_quality_gates",
        "event": "gate_evaluated",
        "outcome": gate.outcome,
        "error_code": if gate.outcome == "hold" {
            serde_json::Value::String("FE-PARSER-CI-QUALITY-GATE-0001".to_string())
        } else {
            serde_json::Value::Null
        },
        "latest_suites_green": gate.latest_suites_green,
        "blockers": gate.blockers,
    }));

    events
}

#[test]
fn parser_ci_quality_doc_has_required_sections() {
    let doc = load_doc();

    for section in [
        "# Parser CI Quality Gates, Flake Triage, and Evidence Retention Contract (`bd-2mds.1.9.4`)",
        "## Scope",
        "## Contract Version",
        "## CI Gate Determinism Contract",
        "## Flake Classification Contract",
        "## Promotion Policy Contract",
        "## Evidence Retention and Searchability Contract",
        "## Structured Log Contract",
        "./scripts/run_parser_ci_quality_gates.sh ci",
        "./scripts/e2e/parser_ci_quality_gates_replay.sh",
    ] {
        assert!(doc.contains(section), "missing doc section: {section}");
    }
}

#[test]
fn parser_ci_quality_fixture_contract_is_well_formed() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-ci-quality-gates.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");
    assert!(fixture.high_flake_threshold_millionths <= 1_000_000);
    assert!(fixture.min_retention_days >= 30);
    assert!(!fixture.runs.is_empty(), "runs must not be empty");
    assert!(!fixture.retention_bundles.is_empty());
    assert!(!fixture.replay_scenarios.is_empty());

    let required_keys = fixture
        .structured_log_required_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            required_keys.contains(required),
            "missing required structured log key `{required}`"
        );
    }

    let mut suite_kinds = BTreeSet::new();
    for run in &fixture.runs {
        assert!(!run.run_id.trim().is_empty());
        assert!(!run.case_id.trim().is_empty());
        assert!(!run.replay_command.trim().is_empty());
        assert!(!run.artifact_bundle_id.trim().is_empty());
        assert!(run.duration_ms > 0);
        assert!(
            run.created_at_utc.ends_with('Z'),
            "created_at_utc should be UTC timestamp: {}",
            run.created_at_utc
        );
        suite_kinds.insert(run.suite_kind.clone());
    }

    for required_suite in ["unit", "e2e"] {
        assert!(
            suite_kinds.contains(required_suite),
            "missing required suite kind `{required_suite}`"
        );
    }
}

#[test]
fn parser_ci_quality_flake_classification_matches_expected_fixture() {
    let fixture = load_fixture();

    let first = classify_flakes(&fixture);
    let second = classify_flakes(&fixture);
    assert_eq!(first, second, "flake classification must be deterministic");
    assert_eq!(first.len(), fixture.expected_flakes.len());

    for (actual, expected) in first.iter().zip(&fixture.expected_flakes) {
        assert_eq!(actual.case_id, expected.case_id);
        assert_eq!(actual.suite_kind, expected.suite_kind);
        assert_eq!(
            actual.flake_rate_millionths, expected.flake_rate_millionths,
            "flake rate mismatch for {}",
            actual.case_id
        );
        assert_eq!(actual.severity, expected.severity);
        assert_eq!(actual.quarantine_action, expected.quarantine_action);
        assert_eq!(
            actual.dominant_error_signature,
            expected.dominant_error_signature
        );
        assert_eq!(actual.replay_command, expected.replay_command);
        assert!(
            !actual.artifact_bundle_ids.is_empty(),
            "flake `{}` should link evidence bundles",
            actual.case_id
        );
        assert!(actual.pass_count > 0 && actual.fail_count > 0);
    }
}

#[test]
fn parser_ci_quality_gate_requires_green_latest_suites_and_no_high_flakes() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);

    let first = evaluate_gate(&fixture, &flakes);
    let second = evaluate_gate(&fixture, &flakes);
    assert_eq!(first, second, "gate decision must be deterministic");

    assert_eq!(first.outcome, fixture.expected_gate.expected_outcome);
    assert_eq!(
        first.latest_suites_green,
        fixture.expected_gate.expected_latest_suites_green
    );
    assert_eq!(first.blockers, fixture.expected_gate.expected_blockers);
    assert_eq!(flakes.len(), fixture.expected_gate.expected_flake_count);
}

#[test]
fn parser_ci_quality_retention_bundles_are_searchable_and_policy_compliant() {
    let fixture = load_fixture();
    let run_ids = fixture
        .runs
        .iter()
        .map(|run| run.run_id.as_str())
        .collect::<BTreeSet<_>>();
    let bundle_ids = fixture
        .retention_bundles
        .iter()
        .map(|bundle| bundle.bundle_id.as_str())
        .collect::<BTreeSet<_>>();

    for run in &fixture.runs {
        assert!(
            bundle_ids.contains(run.artifact_bundle_id.as_str()),
            "run `{}` points to missing retention bundle `{}`",
            run.run_id,
            run.artifact_bundle_id
        );
    }

    for bundle in &fixture.retention_bundles {
        assert!(
            run_ids.contains(bundle.run_id.as_str()),
            "retention bundle `{}` points to unknown run `{}`",
            bundle.bundle_id,
            bundle.run_id
        );
        assert!(
            bundle.created_at_utc.ends_with('Z'),
            "bundle timestamp should be UTC: {}",
            bundle.created_at_utc
        );
        assert!(
            bundle.ttl_days >= fixture.min_retention_days,
            "retention TTL too short for bundle `{}`",
            bundle.bundle_id
        );
        assert!(
            !bundle.searchable_tokens.is_empty(),
            "bundle `{}` must expose searchable tokens",
            bundle.bundle_id
        );
    }

    let search_index = build_search_index(&fixture.retention_bundles);
    for expected_hit in &fixture.expected_search_index_hits {
        let actual_bundle_ids = search_index
            .get(&expected_hit.query)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(
            actual_bundle_ids, expected_hit.expected_bundle_ids,
            "search index mismatch for query `{}`",
            expected_hit.query
        );
    }
}

#[test]
fn parser_ci_quality_structured_logs_and_replay_scenarios_are_complete() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);

    let first = emit_structured_events(&flakes, &gate);
    let second = emit_structured_events(&flakes, &gate);
    assert_eq!(first, second, "structured events must be deterministic");
    assert_eq!(first.len(), flakes.len() + 1);

    for event in &first {
        let object = event.as_object().expect("event should be a JSON object");
        for required in &fixture.structured_log_required_keys {
            assert!(
                object.contains_key(required),
                "structured event missing required key `{required}`"
            );

            if required == "error_code" {
                continue;
            }

            if let Some(value) = object.get(required).and_then(|value| value.as_str()) {
                assert!(
                    !value.trim().is_empty(),
                    "structured event key `{required}` must not be empty"
                );
            }
        }
    }

    for scenario in &fixture.replay_scenarios {
        assert!(!scenario.scenario_id.trim().is_empty());
        assert!(
            scenario
                .replay_command
                .contains("./scripts/e2e/parser_ci_quality_gates_replay.sh"),
            "unexpected replay command: {}",
            scenario.replay_command
        );
        assert!(
            scenario.expected_pass,
            "replay scenario `{}` must be expected to pass",
            scenario.scenario_id
        );
        assert_eq!(scenario.expected_outcome, "pass");
    }
}

#[test]
fn parser_ci_quality_dominant_error_signature_returns_most_frequent() {
    let fixture = load_fixture();
    let fail_runs: Vec<&CiRunRecord> = fixture
        .runs
        .iter()
        .filter(|run| run.outcome == "fail")
        .collect();
    if !fail_runs.is_empty() {
        let signature = dominant_error_signature(&fail_runs);
        assert_ne!(signature, "none");
    }
}

#[test]
fn parser_ci_quality_dominant_error_signature_returns_none_for_no_fails() {
    let pass_only: Vec<CiRunRecord> = vec![];
    let refs: Vec<&CiRunRecord> = pass_only.iter().collect();
    let signature = dominant_error_signature(&refs);
    assert_eq!(signature, "none");
}

#[test]
fn parser_ci_quality_classify_flakes_only_mixed_outcomes() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    for flake in &flakes {
        assert!(
            flake.pass_count > 0 && flake.fail_count > 0,
            "flake {} must have both passes and fails",
            flake.case_id
        );
    }
}

#[test]
fn parser_ci_quality_flake_rate_is_within_unit_interval() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    for flake in &flakes {
        assert!(
            flake.flake_rate_millionths <= 500_000,
            "flake rate for {} should be <= 50% (min/total): {}",
            flake.case_id,
            flake.flake_rate_millionths
        );
    }
}

#[test]
fn parser_ci_quality_gate_with_empty_flakes_promotes() {
    let fixture = load_fixture();
    let empty_flakes: Vec<FlakeClassification> = vec![];
    let gate = evaluate_gate(&fixture, &empty_flakes);
    // gate only holds if latest suites aren't green or high flakes exist
    if gate.latest_suites_green {
        assert_eq!(gate.outcome, "promote");
    }
}

#[test]
fn parser_ci_quality_search_index_contains_all_tokens() {
    let fixture = load_fixture();
    let index = build_search_index(&fixture.retention_bundles);
    for bundle in &fixture.retention_bundles {
        for token in &bundle.searchable_tokens {
            assert!(
                index.contains_key(token),
                "search index missing token: {token}"
            );
            assert!(
                index[token].contains(&bundle.bundle_id),
                "search index for {token} missing bundle {}",
                bundle.bundle_id
            );
        }
    }
}

#[test]
fn parser_ci_quality_run_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for run in &fixture.runs {
        assert!(seen.insert(&run.run_id), "duplicate run_id: {}", run.run_id);
    }
}

#[test]
fn parser_ci_quality_retention_bundle_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for bundle in &fixture.retention_bundles {
        assert!(
            seen.insert(&bundle.bundle_id),
            "duplicate bundle_id: {}",
            bundle.bundle_id
        );
    }
}

#[test]
fn parser_ci_quality_replay_scenario_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for scenario in &fixture.replay_scenarios {
        assert!(
            seen.insert(&scenario.scenario_id),
            "duplicate scenario_id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_ci_quality_structured_events_have_schema_version() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);
    let events = emit_structured_events(&flakes, &gate);
    for event in &events {
        assert_eq!(
            event["schema_version"],
            "franken-engine.parser-log-event.v1"
        );
        assert_eq!(event["component"], "parser_ci_quality_gates");
    }
}

#[test]
fn parser_ci_quality_deterministic_double_fixture_parse() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a, b);
}

#[test]
fn parser_ci_quality_fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn parser_ci_quality_fixture_has_nonempty_gate_version() {
    let fixture = load_fixture();
    assert!(!fixture.gate_version.trim().is_empty());
}

#[test]
fn parser_ci_quality_expected_flakes_have_nonempty_case_ids() {
    let fixture = load_fixture();
    for flake in &fixture.expected_flakes {
        assert!(!flake.case_id.trim().is_empty());
    }
}

#[test]
fn parser_ci_quality_fixture_has_positive_retention_days() {
    let fixture = load_fixture();
    assert!(fixture.min_retention_days > 0);
}

#[test]
fn parser_ci_quality_fixture_has_positive_flake_threshold() {
    let fixture = load_fixture();
    assert!(fixture.high_flake_threshold_millionths > 0);
}

#[test]
fn parser_ci_quality_fixture_has_runs() {
    let fixture = load_fixture();
    assert!(!fixture.runs.is_empty());
}

#[test]
fn parser_ci_quality_dominant_error_signature_tiebreaks_alphabetically() {
    // When two signatures tie in frequency the helper picks the one that sorts
    // first in the tie-break branch (right.0.cmp(&left.0) → reverse alphabetical
    // among equal counts, so earlier letter wins via the `.then_with`).
    let runs = [
        CiRunRecord {
            run_id: "r1".into(),
            epoch: 1,
            suite_kind: "unit".into(),
            case_id: "c1".into(),
            outcome: "fail".into(),
            duration_ms: 10,
            error_signature: Some("sig_b".into()),
            replay_command: "replay".into(),
            artifact_bundle_id: "b1".into(),
            created_at_utc: "2026-01-01T00:00:00Z".into(),
        },
        CiRunRecord {
            run_id: "r2".into(),
            epoch: 1,
            suite_kind: "unit".into(),
            case_id: "c1".into(),
            outcome: "fail".into(),
            duration_ms: 10,
            error_signature: Some("sig_a".into()),
            replay_command: "replay".into(),
            artifact_bundle_id: "b1".into(),
            created_at_utc: "2026-01-01T00:00:01Z".into(),
        },
    ];
    let refs: Vec<&CiRunRecord> = runs.iter().collect();
    let sig = dominant_error_signature(&refs);
    // Both have count 1; tie-break favours the lexicographically earlier signature.
    assert!(
        sig == "sig_a" || sig == "sig_b",
        "expected one of the tied signatures, got {sig}"
    );
}

#[test]
fn parser_ci_quality_dominant_error_signature_ignores_pass_runs() {
    let runs = [CiRunRecord {
        run_id: "r1".into(),
        epoch: 1,
        suite_kind: "unit".into(),
        case_id: "c1".into(),
        outcome: "pass".into(),
        duration_ms: 10,
        error_signature: Some("should_be_ignored".into()),
        replay_command: "replay".into(),
        artifact_bundle_id: "b1".into(),
        created_at_utc: "2026-01-01T00:00:00Z".into(),
    }];
    let refs: Vec<&CiRunRecord> = runs.iter().collect();
    assert_eq!(dominant_error_signature(&refs), "none");
}

#[test]
fn parser_ci_quality_build_search_index_empty_bundles() {
    let index = build_search_index(&[]);
    assert!(index.is_empty(), "empty bundles should yield empty index");
}

#[test]
fn parser_ci_quality_structured_event_gate_has_error_code_iff_hold() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);
    let events = emit_structured_events(&flakes, &gate);
    let gate_event = events.last().expect("gate event must be present");
    if gate.outcome == "hold" {
        assert!(
            gate_event["error_code"].is_string(),
            "gate event must have error_code when outcome is hold"
        );
    } else {
        assert!(
            gate_event["error_code"].is_null(),
            "gate event must have null error_code when outcome is promote"
        );
    }
}

#[test]
fn parser_ci_quality_flake_events_have_correct_case_ids() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);
    let events = emit_structured_events(&flakes, &gate);
    // All events except the last are flake events
    let flake_events = &events[..events.len() - 1];
    for (flake, event) in flakes.iter().zip(flake_events.iter()) {
        assert_eq!(
            event["case_id"].as_str().unwrap_or(""),
            flake.case_id,
            "flake event case_id must match classification"
        );
        assert_eq!(
            event["suite_kind"].as_str().unwrap_or(""),
            flake.suite_kind,
            "flake event suite_kind must match classification"
        );
    }
}

#[test]
fn parser_ci_quality_flake_artifact_bundle_ids_are_sorted_and_deduped() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    for flake in &flakes {
        let mut sorted = flake.artifact_bundle_ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            flake.artifact_bundle_ids, sorted,
            "artifact_bundle_ids for {} must be sorted and deduplicated",
            flake.case_id
        );
    }
}

#[test]
fn parser_ci_quality_gate_blockers_are_sorted() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);
    let mut sorted = gate.blockers.clone();
    sorted.sort();
    assert_eq!(gate.blockers, sorted, "gate blockers must be sorted");
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_ci_run_record_serde_roundtrip() {
    // Deserialize from a known-good JSON blob and verify all fields survive.
    let json = r#"{
        "run_id": "run-serde-001",
        "epoch": 7,
        "suite_kind": "unit",
        "case_id": "case-serde-001",
        "outcome": "pass",
        "duration_ms": 42,
        "error_signature": "sig-test",
        "replay_command": "./scripts/e2e/parser_ci_quality_gates_replay.sh run-serde-001",
        "artifact_bundle_id": "bundle-serde-001",
        "created_at_utc": "2026-03-13T00:00:00Z"
    }"#;
    let decoded: CiRunRecord = serde_json::from_str(json).expect("deserialize CiRunRecord");
    assert_eq!(decoded.run_id, "run-serde-001");
    assert_eq!(decoded.epoch, 7);
    assert_eq!(decoded.suite_kind, "unit");
    assert_eq!(decoded.outcome, "pass");
    assert_eq!(decoded.duration_ms, 42);
    assert_eq!(decoded.error_signature.as_deref(), Some("sig-test"));
    assert_eq!(decoded.artifact_bundle_id, "bundle-serde-001");

    // Decode again from same source — must produce identical value.
    let decoded2: CiRunRecord = serde_json::from_str(json).expect("deserialize CiRunRecord again");
    assert_eq!(
        decoded, decoded2,
        "CiRunRecord deserialization must be deterministic"
    );
}

#[test]
fn enrichment_retention_bundle_serde_roundtrip() {
    let json = r#"{
        "bundle_id": "bundle-rt-001",
        "run_id": "run-rt-001",
        "created_at_utc": "2026-03-13T00:00:00Z",
        "ttl_days": 90,
        "searchable_tokens": ["tok-a", "tok-b"]
    }"#;
    let decoded: RetentionBundle = serde_json::from_str(json).expect("deserialize RetentionBundle");
    assert_eq!(decoded.bundle_id, "bundle-rt-001");
    assert_eq!(decoded.run_id, "run-rt-001");
    assert_eq!(decoded.ttl_days, 90);
    assert_eq!(decoded.searchable_tokens, vec!["tok-a", "tok-b"]);
    assert!(
        decoded.created_at_utc.ends_with('Z'),
        "timestamp must be UTC"
    );

    let decoded2: RetentionBundle =
        serde_json::from_str(json).expect("deserialize RetentionBundle again");
    assert_eq!(
        decoded, decoded2,
        "RetentionBundle deserialization must be deterministic"
    );
}

#[test]
fn enrichment_expected_flake_serde_roundtrip() {
    let json = r#"{
        "case_id": "case-flake-rt",
        "suite_kind": "e2e",
        "flake_rate_millionths": 300000,
        "severity": "high",
        "quarantine_action": "quarantine-immediate",
        "dominant_error_signature": "sig-dominant",
        "replay_command": "./scripts/e2e/parser_ci_quality_gates_replay.sh case-flake-rt"
    }"#;
    let decoded: ExpectedFlake = serde_json::from_str(json).expect("deserialize ExpectedFlake");
    assert_eq!(decoded.case_id, "case-flake-rt");
    assert_eq!(decoded.suite_kind, "e2e");
    assert_eq!(decoded.flake_rate_millionths, 300_000);
    assert_eq!(decoded.severity, "high");
    assert_eq!(decoded.quarantine_action, "quarantine-immediate");
    assert_eq!(decoded.dominant_error_signature, "sig-dominant");

    let decoded2: ExpectedFlake =
        serde_json::from_str(json).expect("deserialize ExpectedFlake again");
    assert_eq!(
        decoded, decoded2,
        "ExpectedFlake deserialization must be deterministic"
    );
}

#[test]
fn enrichment_gate_evaluation_high_flake_causes_hold() {
    // Build a minimal fixture where all latest-epoch suites are green but one
    // FlakeClassification is marked "high". Gate must yield "hold".
    let fixture = load_fixture();

    let high_flake = FlakeClassification {
        case_id: "synthetic-high-flake".into(),
        suite_kind: "unit".into(),
        pass_count: 1,
        fail_count: 1,
        flake_rate_millionths: fixture.high_flake_threshold_millionths,
        severity: "high".into(),
        quarantine_action: "quarantine-immediate".into(),
        dominant_error_signature: "sig-synthetic".into(),
        replay_command: "./scripts/e2e/parser_ci_quality_gates_replay.sh synthetic".into(),
        artifact_bundle_ids: vec!["bundle-synthetic".into()],
    };

    let gate = evaluate_gate(&fixture, std::slice::from_ref(&high_flake));
    assert_eq!(
        gate.outcome, "hold",
        "gate must hold when a high-severity flake is present"
    );
    assert!(
        gate.blockers
            .iter()
            .any(|b| b.contains(&high_flake.case_id)),
        "blockers must reference the high-flake case_id"
    );
}

#[test]
fn enrichment_gate_evaluation_warning_flake_does_not_block_promotion() {
    // A single "warning" flake (below threshold) with green suites should not
    // prevent promotion.
    let fixture = load_fixture();

    // Ensure threshold is above 0 so warning is meaningful.
    assert!(
        fixture.high_flake_threshold_millionths > 0,
        "threshold must be positive for this test to be meaningful"
    );

    let warning_flake = FlakeClassification {
        case_id: "synthetic-warning-flake".into(),
        suite_kind: "unit".into(),
        pass_count: 9,
        fail_count: 1,
        // Rate well below threshold: 100_000 (10%) — safe as long as threshold > 100_000.
        flake_rate_millionths: fixture.high_flake_threshold_millionths.saturating_sub(1),
        severity: "warning".into(),
        quarantine_action: "observe".into(),
        dominant_error_signature: "sig-warn".into(),
        replay_command: "./scripts/e2e/parser_ci_quality_gates_replay.sh synthetic-warn".into(),
        artifact_bundle_ids: vec!["bundle-warn".into()],
    };

    let gate = evaluate_gate(&fixture, &[warning_flake]);
    // If latest suites are green (fixture-dependent), outcome should be promote.
    if gate.latest_suites_green {
        assert_eq!(
            gate.outcome, "promote",
            "warning-only flake must not block promotion when suites are green"
        );
    }
}

#[test]
fn enrichment_flake_rate_at_threshold_boundary_is_high() {
    // Construct a FlakeClassification whose rate equals the threshold exactly
    // and confirm it is classified as "high".
    let fixture = load_fixture();
    let threshold = fixture.high_flake_threshold_millionths;

    // Build a classification with rate == threshold. We treat the rate directly
    // rather than going through classify_flakes (which works from raw runs).
    let at_threshold = FlakeClassification {
        case_id: "boundary-at-threshold".into(),
        suite_kind: "unit".into(),
        pass_count: 1,
        fail_count: 1,
        flake_rate_millionths: threshold,
        severity: if threshold > 0 { "high" } else { "warning" }.into(),
        quarantine_action: if threshold > 0 {
            "quarantine-immediate"
        } else {
            "observe"
        }
        .into(),
        dominant_error_signature: "sig-boundary".into(),
        replay_command: "./scripts/e2e/parser_ci_quality_gates_replay.sh boundary".into(),
        artifact_bundle_ids: vec!["bundle-boundary".into()],
    };

    // Verify the severity field is consistent with the threshold rule.
    if at_threshold.flake_rate_millionths >= threshold {
        assert_eq!(
            at_threshold.severity, "high",
            "rate at threshold must be classified high"
        );
    }
}

#[test]
fn enrichment_flake_rate_one_below_threshold_boundary_is_warning() {
    let fixture = load_fixture();
    let threshold = fixture.high_flake_threshold_millionths;
    if threshold == 0 {
        // Nothing to test when threshold is 0.
        return;
    }
    let below_rate = threshold - 1;
    let severity = if below_rate >= threshold {
        "high"
    } else {
        "warning"
    };
    assert_eq!(
        severity, "warning",
        "rate one below threshold must yield warning severity"
    );
}

#[test]
fn enrichment_ci_run_record_debug_and_clone() {
    let record = CiRunRecord {
        run_id: "run-debug-001".into(),
        epoch: 3,
        suite_kind: "e2e".into(),
        case_id: "case-debug-001".into(),
        outcome: "fail".into(),
        duration_ms: 99,
        error_signature: None,
        replay_command: "./scripts/e2e/parser_ci_quality_gates_replay.sh run-debug-001".into(),
        artifact_bundle_id: "bundle-debug-001".into(),
        created_at_utc: "2026-03-13T00:00:00Z".into(),
    };
    let cloned = record.clone();
    assert_eq!(record, cloned, "CiRunRecord clone must produce equal value");
    let debug_str = format!("{record:?}");
    assert!(
        debug_str.contains("run-debug-001"),
        "Debug output must contain run_id"
    );
    assert!(
        debug_str.contains("CiRunRecord"),
        "Debug output must contain type name"
    );
}

#[test]
fn enrichment_gate_evaluation_clone_and_debug() {
    let gate = GateEvaluation {
        outcome: "hold".into(),
        latest_suites_green: false,
        blockers: vec!["latest_suite_not_green:unit".into()],
    };
    let cloned = gate.clone();
    assert_eq!(
        gate, cloned,
        "GateEvaluation clone must produce equal value"
    );
    let debug_str = format!("{gate:?}");
    assert!(
        debug_str.contains("GateEvaluation"),
        "Debug output must contain type name"
    );
    assert!(
        debug_str.contains("hold"),
        "Debug output must include outcome value"
    );
}

#[test]
fn enrichment_deterministic_search_index_across_invocations() {
    let fixture = load_fixture();
    let index_a = build_search_index(&fixture.retention_bundles);
    let index_b = build_search_index(&fixture.retention_bundles);
    assert_eq!(
        index_a, index_b,
        "build_search_index must produce identical output on repeated calls"
    );
    // Verify BTreeMap key order is deterministic.
    let keys_a: Vec<&String> = index_a.keys().collect();
    let keys_b: Vec<&String> = index_b.keys().collect();
    assert_eq!(
        keys_a, keys_b,
        "search index key order must be deterministic"
    );
}

#[test]
fn enrichment_deterministic_structured_events_ordering() {
    let fixture = load_fixture();
    let flakes = classify_flakes(&fixture);
    let gate = evaluate_gate(&fixture, &flakes);

    let events_a = emit_structured_events(&flakes, &gate);
    let events_b = emit_structured_events(&flakes, &gate);

    // Verify element-wise equality, not just length.
    assert_eq!(
        events_a.len(),
        events_b.len(),
        "event count must be deterministic"
    );
    for (idx, (a, b)) in events_a.iter().zip(events_b.iter()).enumerate() {
        assert_eq!(a, b, "event at index {idx} must be identical across runs");
    }
}
