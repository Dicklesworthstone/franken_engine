#![forbid(unsafe_code)]
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
use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserCrossArchReproMatrixFixture {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    required_log_keys: Vec<String>,
    architecture_targets: Vec<String>,
    required_lanes: Vec<RequiredLane>,
    delta_classes: Vec<DeltaClass>,
    matrix_input_statuses: Vec<String>,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RequiredLane {
    lane_id: String,
    manifest_schema_version: String,
    replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DeltaClass {
    class_id: String,
    severity: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneRunSummary {
    lane_id: String,
    arch_profile: String,
    outcome: String,
    error_code: Option<String>,
    witness_digest: String,
    toolchain_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeltaExplanation {
    class_id: String,
    severity: String,
    reason: String,
}

fn load_fixture() -> ParserCrossArchReproMatrixFixture {
    let path = Path::new("tests/fixtures/parser_cross_arch_repro_matrix_v1.json");
    let bytes = fs::read(path).expect("read parser cross-arch reproducibility matrix fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser cross-arch reproducibility fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_CROSS_ARCH_REPRO_MATRIX.md");
    fs::read_to_string(path).expect("read parser cross-arch reproducibility contract doc")
}

fn load_runner_script() -> String {
    let path = Path::new("../../scripts/run_parser_cross_arch_repro_matrix.sh");
    fs::read_to_string(path).expect("read parser cross-arch reproducibility runner script")
}

fn load_replay_wrapper() -> String {
    let path = Path::new("../../scripts/e2e/parser_cross_arch_repro_matrix_replay.sh");
    fs::read_to_string(path).expect("read parser cross-arch reproducibility replay wrapper")
}

fn explain_delta(
    x86_run: &LaneRunSummary,
    arm64_run: &LaneRunSummary,
    allow_missing: bool,
) -> DeltaExplanation {
    if allow_missing
        && (x86_run.witness_digest == "missing-input"
            || arm64_run.witness_digest == "missing-input")
    {
        return DeltaExplanation {
            class_id: "missing_input".to_string(),
            severity: "critical".to_string(),
            reason: "required manifest input missing for one or more architecture lanes"
                .to_string(),
        };
    }

    if x86_run.outcome != arm64_run.outcome || x86_run.error_code != arm64_run.error_code {
        return DeltaExplanation {
            class_id: "upstream_lane_regression".to_string(),
            severity: "critical".to_string(),
            reason: "outcome or error_code diverged across architectures".to_string(),
        };
    }

    if x86_run.witness_digest == arm64_run.witness_digest {
        return DeltaExplanation {
            class_id: "none".to_string(),
            severity: "info".to_string(),
            reason: "witness digests and outcomes match".to_string(),
        };
    }

    if x86_run.toolchain_fingerprint != arm64_run.toolchain_fingerprint {
        return DeltaExplanation {
            class_id: "toolchain_fingerprint_delta".to_string(),
            severity: "warning".to_string(),
            reason: "digest drift is explainable by toolchain fingerprint differences".to_string(),
        };
    }

    DeltaExplanation {
        class_id: "digest_delta_unexplained".to_string(),
        severity: "critical".to_string(),
        reason: "digest drift without toolchain fingerprint delta".to_string(),
    }
}

fn classify_matrix_input_status(
    matrix_complete: bool,
    strict_mode: bool,
    critical_delta_count: u64,
) -> &'static str {
    if !matrix_complete {
        if strict_mode {
            return "incomplete_matrix";
        }
        return "pending_upstream_matrix";
    }

    if critical_delta_count > 0 {
        return "blocked_critical_deltas";
    }

    "ready_for_external_rerun"
}

fn build_lane_delta_event(
    fixture: &ParserCrossArchReproMatrixFixture,
    lane_id: &str,
    delta: &DeltaExplanation,
) -> Value {
    let error_code = match delta.class_id.as_str() {
        "none" => Value::Null,
        "toolchain_fingerprint_delta" => Value::Null,
        "digest_delta_unexplained" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0001".to_string()),
        "upstream_lane_regression" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0002".to_string()),
        "missing_input" => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0003".to_string()),
        _ => Value::String("FE-PARSER-CROSS-ARCH-MATRIX-0099".to_string()),
    };

    json!({
        "schema_version": "franken-engine.parser-cross-arch-repro-matrix.event.v1",
        "trace_id": format!("trace-parser-cross-arch-repro-{lane_id}"),
        "decision_id": format!("decision-parser-cross-arch-repro-{lane_id}"),
        "policy_id": fixture.policy_id,
        "component": "parser_cross_arch_repro_matrix_gate",
        "event": "lane_delta_evaluated",
        "scenario_id": lane_id,
        "outcome": if delta.severity == "critical" { "fail" } else { "pass" },
        "error_code": error_code,
        "delta_class": delta.class_id,
        "delta_reason": delta.reason,
        "replay_command": fixture.replay_command
    })
}

fn lane_error_code(class_id: &str) -> Option<&'static str> {
    match class_id {
        "digest_delta_unexplained" => Some("FE-PARSER-CROSS-ARCH-MATRIX-0001"),
        "upstream_lane_regression" => Some("FE-PARSER-CROSS-ARCH-MATRIX-0002"),
        "missing_input" => Some("FE-PARSER-CROSS-ARCH-MATRIX-0003"),
        "none" | "toolchain_fingerprint_delta" => None,
        _ => Some("FE-PARSER-CROSS-ARCH-MATRIX-0099"),
    }
}

fn gate_error_code(
    failed_command: Option<&str>,
    first_critical_delta: Option<&str>,
) -> Option<&'static str> {
    if let Some(command) = failed_command
        && command != "evaluate_matrix"
    {
        return Some("FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001");
    }

    first_critical_delta
        .and_then(lane_error_code)
        .or_else(|| failed_command.map(|_| "FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001"))
}

fn assert_required_event_keys(event: &Value, required_keys: &[String]) {
    for key in required_keys {
        let value = event
            .get(key)
            .unwrap_or_else(|| panic!("missing required key in event: {key}"));
        if key == "error_code" {
            assert!(
                value.is_null() || value.as_str().is_some_and(|raw| !raw.is_empty()),
                "error_code must be null or non-empty string"
            );
            continue;
        }
        assert!(
            value.as_str().is_some_and(|raw| !raw.is_empty()),
            "key `{key}` must be non-empty string"
        );
    }
}

#[test]
fn parser_cross_arch_repro_matrix_contract_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "# Parser Cross-Architecture Reproducibility Matrix Contract",
        "## Scope",
        "## Contract Version",
        "## Matrix Dimensions",
        "## Drift Classification",
        "## Structured Logging Contract",
        "## Replay and Execution",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "cross-arch reproducibility contract doc missing section: {section}"
        );
    }

    for marker in [
        "PARSER_CROSS_ARCH_AUTO_DISCOVER_MANIFESTS",
        "artifacts/parser_event_ast_equivalence",
        "artifacts/parser_parallel_interference",
        "matrix_inputs",
        "missing_required_inputs",
        "incomplete_matrix",
        "latest complete run directory",
        "scratch-only partial directories",
        "fail non-zero",
    ] {
        assert!(
            doc.contains(marker),
            "cross-arch reproducibility contract doc missing auto-discovery marker: {marker}"
        );
    }
}

#[test]
fn parser_cross_arch_matrix_fixture_covers_required_architectures_and_lanes() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-cross-arch-repro-matrix.fixture.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(fixture.bead_id, "bd-2mds.1.7.2");
    assert_eq!(
        fixture.policy_id,
        "policy-parser-cross-arch-repro-matrix-v1"
    );
    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh"
    );
    let expected_statuses: BTreeSet<_> = [
        "pending_upstream_matrix".to_string(),
        "incomplete_matrix".to_string(),
        "blocked_critical_deltas".to_string(),
        "ready_for_external_rerun".to_string(),
    ]
    .into_iter()
    .collect();
    let actual_statuses: BTreeSet<_> = fixture.matrix_input_statuses.iter().cloned().collect();
    assert_eq!(actual_statuses, expected_statuses);

    let expected_arches: BTreeSet<_> = [
        "x86_64-unknown-linux-gnu".to_string(),
        "aarch64-unknown-linux-gnu".to_string(),
    ]
    .into_iter()
    .collect();
    let actual_arches: BTreeSet<_> = fixture.architecture_targets.iter().cloned().collect();
    assert_eq!(actual_arches, expected_arches);

    let lane_ids: BTreeSet<_> = fixture
        .required_lanes
        .iter()
        .map(|lane| lane.lane_id.clone())
        .collect();
    let expected_lanes: BTreeSet<_> = [
        "parser_event_ast_equivalence".to_string(),
        "parser_parallel_interference".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(lane_ids, expected_lanes);

    for lane in &fixture.required_lanes {
        assert!(
            lane.manifest_schema_version
                .starts_with("franken-engine.parser-"),
            "unexpected lane manifest schema version: {}",
            lane.manifest_schema_version
        );
        assert!(
            lane.replay_command.starts_with("./scripts/"),
            "lane replay command must be script entrypoint: {}",
            lane.replay_command
        );
    }
}

#[test]
fn parser_cross_arch_matrix_input_status_classifier_is_deterministic() {
    assert_eq!(
        classify_matrix_input_status(false, false, 0),
        "pending_upstream_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(false, true, 0),
        "incomplete_matrix"
    );
    assert_eq!(
        classify_matrix_input_status(true, false, 1),
        "blocked_critical_deltas"
    );
    assert_eq!(
        classify_matrix_input_status(true, true, 0),
        "ready_for_external_rerun"
    );
}

#[test]
fn parser_cross_arch_matrix_delta_classifier_assigns_expected_classes() {
    let fixture = load_fixture();
    let allowed_classes: BTreeSet<_> = fixture
        .delta_classes
        .iter()
        .map(|entry| entry.class_id.as_str())
        .collect();

    let x86_stable = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "x86_64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-host".to_string(),
    };
    let arm64_stable = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:stable".to_string(),
        toolchain_fingerprint: "fp-host".to_string(),
    };
    let parity = explain_delta(&x86_stable, &arm64_stable, false);
    assert_eq!(parity.class_id, "none");
    assert!(allowed_classes.contains(parity.class_id.as_str()));

    let arm64_toolchain_delta = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:different".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let toolchain_delta = explain_delta(&x86_stable, &arm64_toolchain_delta, false);
    assert_eq!(toolchain_delta.class_id, "toolchain_fingerprint_delta");
    assert_eq!(toolchain_delta.severity, "warning");
    assert!(allowed_classes.contains(toolchain_delta.class_id.as_str()));

    let arm64_regression = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-PARSER-EVENT-AST-EQUIV-REPLAY-0001".to_string()),
        witness_digest: "sha256:different".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let regression = explain_delta(&x86_stable, &arm64_regression, false);
    assert_eq!(regression.class_id, "upstream_lane_regression");
    assert_eq!(regression.severity, "critical");
    assert!(allowed_classes.contains(regression.class_id.as_str()));

    let missing = LaneRunSummary {
        lane_id: "parser_event_ast_equivalence".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "unknown".to_string(),
        error_code: Some("FE-PARSER-CROSS-ARCH-MATRIX-0003".to_string()),
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "unknown".to_string(),
    };
    let missing_input = explain_delta(&x86_stable, &missing, true);
    assert_eq!(missing_input.class_id, "missing_input");
    assert_eq!(missing_input.severity, "critical");
    assert!(allowed_classes.contains(missing_input.class_id.as_str()));
}

#[test]
fn parser_cross_arch_matrix_structured_events_include_required_keys() {
    let fixture = load_fixture();

    let x86 = LaneRunSummary {
        lane_id: "parser_parallel_interference".to_string(),
        arch_profile: "x86_64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:lane-x86".to_string(),
        toolchain_fingerprint: "fp-shared".to_string(),
    };
    let arm64 = LaneRunSummary {
        lane_id: "parser_parallel_interference".to_string(),
        arch_profile: "aarch64-unknown-linux-gnu".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:lane-arm".to_string(),
        toolchain_fingerprint: "fp-arm".to_string(),
    };
    let delta = explain_delta(&x86, &arm64, false);

    let event_a = build_lane_delta_event(&fixture, &x86.lane_id, &delta);
    let event_b = build_lane_delta_event(&fixture, &x86.lane_id, &delta);
    assert_eq!(event_a, event_b, "event emission must be deterministic");

    assert_required_event_keys(&event_a, &fixture.required_log_keys);
    assert_eq!(
        event_a["replay_command"].as_str(),
        Some("./scripts/e2e/parser_cross_arch_repro_matrix_replay.sh")
    );
    assert_eq!(
        event_a["delta_class"].as_str(),
        Some("toolchain_fingerprint_delta")
    );
}

// ---------- load_fixture helper ----------

#[test]
fn load_fixture_returns_valid_fixture() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.is_empty());
    assert!(!fixture.architecture_targets.is_empty());
    assert!(!fixture.required_lanes.is_empty());
    assert!(!fixture.delta_classes.is_empty());
}

// ---------- load_doc helper ----------

#[test]
fn load_doc_returns_nonempty_string() {
    let doc = load_doc();
    assert!(!doc.is_empty());
    assert!(doc.contains("Reproducibility"));
}

#[test]
fn runner_script_contains_manifest_auto_discovery_contract() {
    let script = load_runner_script();
    for marker in [
        "PARSER_CROSS_ARCH_AUTO_DISCOVER_MANIFESTS",
        "PARSER_CROSS_ARCH_EVENT_AST_ARTIFACT_ROOT",
        "PARSER_CROSS_ARCH_PARALLEL_INTERFERENCE_ARTIFACT_ROOT",
        "find_latest_manifest_for_arch",
        "resolve_manifest_input",
        "missing_required_inputs_json",
        "run_rch_strict_logged",
        "rch-pid.",
        "rch-local-fallback-detected",
        "register_temp_path",
        "cleanup_temp_path",
        "cleanup_registered_temp_paths",
        "trap cleanup_registered_temp_paths EXIT",
        "pkill -P \"$current_rch_pid\"",
        "pkill -f 'frankenengine-engine --test parser_cross_arch_repro_matrix'",
        "pkill -f \"CARGO_TARGET_DIR=${target_dir}\"",
        "delta_class_error_code",
        "gate_error_code",
        "FE-PARSER-CROSS-ARCH-MATRIX-0001",
        "FE-PARSER-CROSS-ARCH-MATRIX-0002",
        "FE-PARSER-CROSS-ARCH-MATRIX-0003",
        "\"matrix_inputs\": {",
        "\"missing_required_inputs\":",
        "auto_discovered",
    ] {
        assert!(
            script.contains(marker),
            "runner script missing manifest auto-discovery marker: {marker}"
        );
    }
}

#[test]
fn replay_wrapper_surfaces_latest_artifacts_after_run() {
    let wrapper = load_replay_wrapper();
    for marker in [
        "mode=\"${1:-matrix}\"",
        "main_exit=0",
        "latest_artifact_dir()",
        "latest_complete_run_dir()",
        "missing_bundle_exit_code()",
        "latest manifest:",
        "latest matrix summary:",
        "latest events:",
        "[[ -f \"${candidate}/run_manifest.json\" ]]",
        "[[ -f \"${candidate}/matrix_summary.json\" ]]",
        "[[ -f \"${candidate}/events.jsonl\" ]]",
        "could not locate a complete run directory under ${artifact_root}",
        "exit \"$(missing_bundle_exit_code \"${main_exit:-1}\")\"",
        "newest directory ${latest_artifact_dir_path} is incomplete; using latest complete run directory ${latest_run_dir}",
    ] {
        assert!(
            wrapper.contains(marker),
            "replay wrapper missing latest-artifact marker: {marker}"
        );
    }
}

// ---------- explain_delta ----------

#[test]
fn explain_delta_no_diff_returns_none_class() {
    let run_a = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:same".to_string(),
        toolchain_fingerprint: "fp1".to_string(),
    };
    let run_b = run_a.clone();
    let delta = explain_delta(&run_a, &run_b, false);
    assert_eq!(delta.class_id, "none");
    assert_eq!(delta.severity, "info");
}

#[test]
fn explain_delta_outcome_divergence_is_critical() {
    let x86 = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:a".to_string(),
        toolchain_fingerprint: "fp1".to_string(),
    };
    let arm = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "arm".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("ERR".to_string()),
        witness_digest: "sha256:b".to_string(),
        toolchain_fingerprint: "fp1".to_string(),
    };
    let delta = explain_delta(&x86, &arm, false);
    assert_eq!(delta.class_id, "upstream_lane_regression");
    assert_eq!(delta.severity, "critical");
}

#[test]
fn explain_delta_digest_divergence_same_toolchain_is_unexplained() {
    let x86 = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:a".to_string(),
        toolchain_fingerprint: "fp-same".to_string(),
    };
    let arm = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "arm".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:b".to_string(),
        toolchain_fingerprint: "fp-same".to_string(),
    };
    let delta = explain_delta(&x86, &arm, false);
    assert_eq!(delta.class_id, "digest_delta_unexplained");
    assert_eq!(delta.severity, "critical");
}

// ---------- classify_matrix_input_status ----------

#[test]
fn classify_matrix_status_complete_no_deltas_is_ready() {
    assert_eq!(
        classify_matrix_input_status(true, false, 0),
        "ready_for_external_rerun"
    );
}

#[test]
fn classify_matrix_status_complete_strict_no_deltas_is_ready() {
    assert_eq!(
        classify_matrix_input_status(true, true, 0),
        "ready_for_external_rerun"
    );
}

// ---------- build_lane_delta_event ----------

#[test]
fn build_lane_delta_event_none_has_null_error_code() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "none".to_string(),
        severity: "info".to_string(),
        reason: "ok".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert!(event["error_code"].is_null());
    assert_eq!(event["outcome"], "pass");
}

#[test]
fn build_lane_delta_event_critical_has_fail_outcome() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "digest_delta_unexplained".to_string(),
        severity: "critical".to_string(),
        reason: "unexplained".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert_eq!(event["outcome"], "fail");
    assert_eq!(event["error_code"], "FE-PARSER-CROSS-ARCH-MATRIX-0001");
}

// ---------- assert_required_event_keys ----------

#[test]
fn assert_required_event_keys_passes_for_valid_event() {
    let event = json!({
        "trace_id": "t1",
        "decision_id": "d1",
        "policy_id": "p1",
        "component": "c1",
        "event": "e1",
        "outcome": "pass",
        "error_code": serde_json::Value::Null,
        "scenario_id": "s1",
        "replay_command": "cmd"
    });
    let keys = vec!["trace_id".to_string(), "error_code".to_string()];
    assert_required_event_keys(&event, &keys);
}

// ---------- determinism ----------

#[test]
fn delta_classifier_is_deterministic() {
    let x86 = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:a".to_string(),
        toolchain_fingerprint: "fp1".to_string(),
    };
    let arm = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "arm".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:b".to_string(),
        toolchain_fingerprint: "fp2".to_string(),
    };
    let a = explain_delta(&x86, &arm, false);
    let b = explain_delta(&x86, &arm, false);
    assert_eq!(a, b);
}

// ---------- delta_classes uniqueness ----------

#[test]
fn fixture_delta_class_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for dc in &fixture.delta_classes {
        assert!(
            seen.insert(&dc.class_id),
            "duplicate delta class_id: {}",
            dc.class_id
        );
    }
}

// ---------- required_lanes uniqueness ----------

#[test]
fn fixture_required_lane_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for lane in &fixture.required_lanes {
        assert!(
            seen.insert(&lane.lane_id),
            "duplicate lane_id: {}",
            lane.lane_id
        );
    }
}

// ---------- missing_input with allow_missing=false ----------

#[test]
fn explain_delta_missing_input_ignored_when_allow_missing_false() {
    let x86 = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "unknown".to_string(),
        error_code: Some("ERR".to_string()),
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "fp".to_string(),
    };
    let arm = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "arm".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        witness_digest: "sha256:ok".to_string(),
        toolchain_fingerprint: "fp".to_string(),
    };
    // allow_missing=false means the missing-input sentinel is NOT special-cased
    let delta = explain_delta(&x86, &arm, false);
    assert_ne!(delta.class_id, "missing_input");
    // outcome divergence should trigger upstream_lane_regression instead
    assert_eq!(delta.class_id, "upstream_lane_regression");
}

// ---------- build_lane_delta_event missing_input error code ----------

#[test]
fn build_lane_delta_event_missing_input_has_correct_error_code() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "missing_input".to_string(),
        severity: "critical".to_string(),
        reason: "missing".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert_eq!(event["error_code"], "FE-PARSER-CROSS-ARCH-MATRIX-0003");
    assert_eq!(event["outcome"], "fail");
}

// ---------- classify_matrix_input_status incomplete + critical deltas ----------

#[test]
fn classify_matrix_status_incomplete_strict_ignores_critical_deltas() {
    // When matrix is incomplete in strict mode, the status is incomplete
    // regardless of critical delta count
    assert_eq!(
        classify_matrix_input_status(false, true, 5),
        "incomplete_matrix"
    );
}

#[test]
fn fixture_has_nonempty_bead_id() {
    let fixture = load_fixture();
    assert!(!fixture.bead_id.trim().is_empty());
}

#[test]
fn fixture_has_nonempty_policy_id() {
    let fixture = load_fixture();
    assert!(!fixture.policy_id.trim().is_empty());
}

#[test]
fn fixture_deterministic_triple_parse() {
    let a = load_fixture();
    let b = load_fixture();
    let c = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(b.schema_version, c.schema_version);
    assert_eq!(a.bead_id, c.bead_id);
}

// ---------- explain_delta missing_input with allow_missing=true on both sides ----------

#[test]
fn explain_delta_both_sides_missing_input_with_allow() {
    let x86 = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "x86".to_string(),
        outcome: "unknown".to_string(),
        error_code: None,
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "fp".to_string(),
    };
    let arm = LaneRunSummary {
        lane_id: "lane1".to_string(),
        arch_profile: "arm".to_string(),
        outcome: "unknown".to_string(),
        error_code: None,
        witness_digest: "missing-input".to_string(),
        toolchain_fingerprint: "fp".to_string(),
    };
    let delta = explain_delta(&x86, &arm, true);
    assert_eq!(delta.class_id, "missing_input");
    assert_eq!(delta.severity, "critical");
}

// ---------- build_lane_delta_event upstream_lane_regression error code ----------

#[test]
fn build_lane_delta_event_upstream_regression_has_correct_error_code() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "upstream_lane_regression".to_string(),
        severity: "critical".to_string(),
        reason: "diverged".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert_eq!(event["error_code"], "FE-PARSER-CROSS-ARCH-MATRIX-0002");
    assert_eq!(event["outcome"], "fail");
}

// ---------- build_lane_delta_event toolchain delta has null error_code ----------

#[test]
fn build_lane_delta_event_toolchain_delta_has_null_error_code() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "toolchain_fingerprint_delta".to_string(),
        severity: "warning".to_string(),
        reason: "fp differs".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert!(event["error_code"].is_null());
    assert_eq!(event["outcome"], "pass");
}

// ---------- classify_matrix_input_status boundary: complete with many critical deltas ----------

#[test]
fn classify_matrix_status_complete_with_many_critical_deltas() {
    assert_eq!(
        classify_matrix_input_status(true, true, 100),
        "blocked_critical_deltas"
    );
    assert_eq!(
        classify_matrix_input_status(true, false, 100),
        "blocked_critical_deltas"
    );
}

// ---------- fixture delta_classes all have nonempty descriptions ----------

#[test]
fn fixture_delta_classes_have_nonempty_descriptions() {
    let fixture = load_fixture();
    for dc in &fixture.delta_classes {
        assert!(
            !dc.description.trim().is_empty(),
            "delta class {} has empty description",
            dc.class_id
        );
        assert!(
            !dc.severity.trim().is_empty(),
            "delta class {} has empty severity",
            dc.class_id
        );
    }
}

// ---------- fixture required_lanes have nonempty replay commands ----------

#[test]
fn fixture_required_lanes_have_nonempty_replay_commands() {
    let fixture = load_fixture();
    for lane in &fixture.required_lanes {
        assert!(
            !lane.replay_command.trim().is_empty(),
            "lane {} has empty replay_command",
            lane.lane_id
        );
        assert!(
            !lane.manifest_schema_version.trim().is_empty(),
            "lane {} has empty manifest_schema_version",
            lane.lane_id
        );
    }
}

// ---------- build_lane_delta_event unknown class gets fallback error code ----------

#[test]
fn build_lane_delta_event_unknown_class_gets_fallback_error_code() {
    let fixture = load_fixture();
    let delta = DeltaExplanation {
        class_id: "some_unknown_class".to_string(),
        severity: "critical".to_string(),
        reason: "unknown".to_string(),
    };
    let event = build_lane_delta_event(&fixture, "lane1", &delta);
    assert_eq!(event["error_code"], "FE-PARSER-CROSS-ARCH-MATRIX-0099");
    assert_eq!(event["outcome"], "fail");
}

// ---------- gate_error_code favors runner failures over matrix deltas ----------

#[test]
fn gate_error_code_prefers_runner_failure_for_command_errors() {
    assert_eq!(
        gate_error_code(
            Some("cargo check -p frankenengine-engine --test parser_cross_arch_repro_matrix"),
            Some("missing_input")
        ),
        Some("FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001")
    );
}

#[test]
fn gate_error_code_uses_matrix_delta_code_for_matrix_failures() {
    assert_eq!(
        gate_error_code(Some("evaluate_matrix"), Some("missing_input")),
        Some("FE-PARSER-CROSS-ARCH-MATRIX-0003")
    );
    assert_eq!(
        gate_error_code(Some("evaluate_matrix"), Some("upstream_lane_regression")),
        Some("FE-PARSER-CROSS-ARCH-MATRIX-0002")
    );
    assert_eq!(
        gate_error_code(Some("evaluate_matrix"), Some("digest_delta_unexplained")),
        Some("FE-PARSER-CROSS-ARCH-MATRIX-0001")
    );
}

#[test]
fn gate_error_code_keeps_runner_failure_generic_for_local_fallback() {
    assert_eq!(
        gate_error_code(
            Some(
                "cargo test -p frankenengine-engine --test parser_cross_arch_repro_matrix (rch-local-fallback-detected)"
            ),
            Some("missing_input")
        ),
        Some("FE-PARSER-CROSS-ARCH-REPRO-MATRIX-0001")
    );
}
