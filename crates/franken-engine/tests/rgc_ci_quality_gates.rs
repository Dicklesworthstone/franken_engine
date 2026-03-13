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
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LaneCommandContract {
    lane: String,
    command: String,
    requires_rch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct OperatorEntrypointContract {
    mode: String,
    command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RegressionVerdictSample {
    sample_id: String,
    verdict: Value,
    expected_blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RgcCiQualityGatesFixture {
    schema_version: String,
    gate_version: String,
    required_modes: Vec<String>,
    required_structured_log_fields: Vec<String>,
    required_error_codes: Vec<String>,
    lane_command_contract: Vec<LaneCommandContract>,
    operator_entrypoints: Vec<OperatorEntrypointContract>,
    regression_verdict_samples: Vec<RegressionVerdictSample>,
    required_artifacts: Vec<String>,
}

fn load_fixture() -> RgcCiQualityGatesFixture {
    let path = Path::new("tests/fixtures/rgc_ci_quality_gates_v1.json");
    let bytes = fs::read(path).expect("read rgc ci quality gates fixture");
    serde_json::from_slice(&bytes).expect("deserialize rgc ci quality gates fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_CI_QUALITY_GATES.md");
    fs::read_to_string(path).expect("read rgc ci quality gates doc")
}

fn severity_is_blocking(raw: &str) -> bool {
    matches!(raw, "critical" | "high")
}

fn verdict_blocks(verdict: &Value) -> bool {
    let highest = verdict
        .get("highest_severity")
        .or_else(|| verdict.get("severity"))
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_ascii_lowercase();

    let blocking_flag = verdict
        .get("blocking")
        .or_else(|| verdict.get("is_blocking"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let has_open_high_or_critical = verdict
        .get("regressions")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter().any(|row| {
                let status = row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("active")
                    .to_ascii_lowercase();
                if status == "waived" {
                    return false;
                }
                let severity = row
                    .get("severity")
                    .or_else(|| row.get("level"))
                    .and_then(Value::as_str)
                    .unwrap_or("none")
                    .to_ascii_lowercase();
                severity_is_blocking(&severity)
            })
        })
        .unwrap_or(false);

    blocking_flag || severity_is_blocking(&highest) || has_open_high_or_critical
}

#[test]
fn rgc_ci_quality_fixture_schema_and_modes_are_stable() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-ci-quality-gates.v1"
    );
    assert_eq!(fixture.gate_version, "1.0.0");

    let modes = fixture.required_modes.into_iter().collect::<BTreeSet<_>>();
    for mode in [
        "fmt",
        "check",
        "clippy",
        "unit",
        "integration",
        "e2e",
        "replay",
        "regression",
        "ci",
    ] {
        assert!(modes.contains(mode), "missing required mode {mode}");
    }
}

#[test]
fn rgc_ci_quality_log_and_artifact_contract_is_complete() {
    let fixture = load_fixture();

    let log_fields = fixture
        .required_structured_log_fields
        .into_iter()
        .collect::<BTreeSet<_>>();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(log_fields.contains(key), "missing structured log key {key}");
    }

    let artifacts = fixture
        .required_artifacts
        .into_iter()
        .collect::<BTreeSet<_>>();
    for required in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "failure_summary.json",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let error_codes = fixture
        .required_error_codes
        .into_iter()
        .collect::<BTreeSet<_>>();
    for code in [
        "FE-RGC-CI-QUALITY-GATE-0000",
        "FE-RGC-CI-QUALITY-GATE-0002",
        "FE-RGC-CI-QUALITY-GATE-0003",
        "FE-RGC-CI-QUALITY-GATE-0004",
        "FE-RGC-CI-QUALITY-GATE-0005",
        "FE-RGC-CI-QUALITY-GATE-0006",
        "FE-RGC-CI-QUALITY-GATE-0007",
        "FE-RGC-CI-QUALITY-GATE-0008",
        "FE-RGC-CI-QUALITY-GATE-0009",
        "FE-RGC-CI-QUALITY-GATE-0010",
    ] {
        assert!(error_codes.contains(code), "missing error code {code}");
    }
}

#[test]
fn rgc_ci_quality_regression_verdict_samples_match_policy() {
    let fixture = load_fixture();

    for sample in fixture.regression_verdict_samples {
        let observed = verdict_blocks(&sample.verdict);
        assert_eq!(
            observed, sample.expected_blocking,
            "sample {} expected blocking={} but observed {}",
            sample.sample_id, sample.expected_blocking, observed
        );
    }
}

#[test]
fn rgc_ci_quality_script_contract_references_rch_for_heavy_lanes() {
    let fixture = load_fixture();
    let script = fs::read_to_string("../../scripts/run_rgc_ci_quality_gates.sh")
        .expect("read rgc ci quality script");

    assert!(
        script.contains("run_rch"),
        "script must define run_rch helper"
    );
    assert!(
        script.contains("rch exec -- env"),
        "script must route heavy lanes through rch"
    );
    assert!(
        script.contains("timeout-before-remote-exit-marker"),
        "script must classify timeout marker loss separately"
    );
    assert!(
        script.contains("remote-exit-marker-lost-after-remote-start"),
        "script must classify post-remote-start marker loss separately"
    );
    assert!(
        script.contains("exec called with non-compilation command"),
        "script must detect rch non-compilation command warnings"
    );
    assert!(
        script.contains(
            "remote exit marker missing for non-compilation command; using rch process exit=${run_rch_exit}"
        ),
        "script must use the rch process exit for non-compilation commands without a remote marker"
    );
    assert!(
        script.contains("PIPESTATUS"),
        "script must capture pipeline status after tee before classifying fmt lane output"
    );
    assert!(
        script.contains("< <(rch_strip_ansi \"$log_path\")"),
        "script must inspect stripped logs via process substitution so grep -q stays correct under pipefail"
    );
    assert!(
        script.contains("commands_run+=(\"$(regression_verdict_command_text)\")"),
        "script must record a replayable regression command in commands.txt and the manifest"
    );
    assert!(
        script.contains(
            "record_event \"regression_verdict_missing\" \"fail\" \"FE-RGC-CI-QUALITY-GATE-0005\""
        ),
        "script must emit FE-RGC-CI-QUALITY-GATE-0005 when strict regression mode lacks a verdict path"
    );
    assert!(
        script.contains(
            "record_event \"regression_verdict_missing\" \"fail\" \"FE-RGC-CI-QUALITY-GATE-0006\""
        ),
        "script must emit FE-RGC-CI-QUALITY-GATE-0006 when the configured verdict file is missing"
    );
    assert!(
        script.contains(
            "record_event \"regression_verdict_blocked\" \"fail\" \"FE-RGC-CI-QUALITY-GATE-0007\""
        ),
        "script must emit FE-RGC-CI-QUALITY-GATE-0007 when the verdict blocks promotion"
    );
    assert!(
        script.contains("RGC_CI_QUALITY_REGRESSION_VERDICT_PATH="),
        "script must publish canonical regression replay commands with the RGC_CI_QUALITY_* env spelling"
    );

    for contract in fixture.lane_command_contract {
        assert!(
            script.contains(&contract.command),
            "script missing lane command {}",
            contract.command
        );
        if contract.requires_rch {
            assert!(
                matches!(
                    contract.lane.as_str(),
                    "fmt" | "check" | "clippy" | "unit" | "integration"
                ),
                "unexpected rch-required lane {}",
                contract.lane
            );
        }
    }

    for code in fixture.required_error_codes {
        assert!(
            script.contains(&code),
            "script missing required failure code {code}"
        );
    }
}

#[test]
fn rgc_ci_quality_doc_and_replay_wrapper_exist_and_reference_contract() {
    let fixture = load_fixture();
    let doc = load_doc();
    let replay = fs::read_to_string("../../scripts/e2e/rgc_ci_quality_gates_replay.sh")
        .expect("read rgc ci quality replay wrapper");

    assert!(
        doc.contains("# RGC CI Quality Gates Contract (`bd-1lsy.11.5`)"),
        "doc title must include bead id"
    );
    assert!(doc.contains("## Lane Entry Points"));
    assert!(doc.contains("## Regression Verdict Ingestion (RGC-703 hook)"));
    assert!(doc.contains("## Required Artifacts"));
    assert!(doc.contains("./scripts/run_rgc_ci_quality_gates.sh ci"));
    assert!(doc.contains("cargo fmt --check"));
    assert!(doc.contains("non-compilation command"));
    assert!(doc.contains("daemon may omit the usual remote-exit marker"));
    assert!(doc.contains("authoritative fallback exit code"));
    assert!(doc.contains("./scripts/run_rgc_test_harness_suite.sh ci"));
    assert!(doc.contains("./scripts/run_rgc_verification_coverage_matrix.sh ci"));
    assert!(doc.contains("./scripts/e2e/rgc_test_harness_replay.sh ci"));
    assert!(doc.contains("./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci"));
    assert!(doc.contains("FE-RGC-CI-QUALITY-GATE-0005"));
    assert!(doc.contains("FE-RGC-CI-QUALITY-GATE-0006"));
    assert!(doc.contains("FE-RGC-CI-QUALITY-GATE-0007"));
    for entrypoint in fixture.operator_entrypoints {
        assert!(
            doc.contains(&entrypoint.command),
            "doc missing operator entrypoint {} for mode {}",
            entrypoint.command,
            entrypoint.mode
        );
    }

    assert!(
        replay.contains("run_rgc_ci_quality_gates.sh"),
        "replay wrapper must call main gate script"
    );
    assert!(
        replay.contains("mode=\"${1:-ci}\""),
        "replay wrapper must default to ci mode"
    );
    assert!(
        replay.contains("\"${root_dir}/scripts/run_rgc_ci_quality_gates.sh\" \"${mode}\""),
        "replay wrapper must forward the requested mode to the main gate script"
    );
    assert!(
        replay.contains("parser_frontier_bootstrap_env"),
        "replay wrapper must bootstrap deterministic env"
    );
}

// ── Severity classification tests ─────────────────────────────────────

#[test]
fn severity_critical_is_blocking() {
    assert!(severity_is_blocking("critical"));
}

#[test]
fn severity_high_is_blocking() {
    assert!(severity_is_blocking("high"));
}

#[test]
fn severity_medium_is_not_blocking() {
    assert!(!severity_is_blocking("medium"));
}

#[test]
fn severity_low_is_not_blocking() {
    assert!(!severity_is_blocking("low"));
}

#[test]
fn severity_none_is_not_blocking() {
    assert!(!severity_is_blocking("none"));
}

#[test]
fn severity_empty_is_not_blocking() {
    assert!(!severity_is_blocking(""));
}

// ── Verdict blocking tests ────────────────────────────────────────────

#[test]
fn verdict_blocks_when_blocking_flag_true() {
    let verdict = serde_json::json!({
        "blocking": true,
        "severity": "low"
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_is_blocking_flag_true() {
    let verdict = serde_json::json!({
        "is_blocking": true,
        "severity": "low"
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_highest_severity_critical() {
    let verdict = serde_json::json!({
        "highest_severity": "critical",
        "blocking": false
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_highest_severity_high() {
    let verdict = serde_json::json!({
        "highest_severity": "high"
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_highest_severity_medium() {
    let verdict = serde_json::json!({
        "highest_severity": "medium",
        "blocking": false
    });
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_empty_object() {
    let verdict = serde_json::json!({});
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_regressions_have_critical_severity() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "critical", "status": "active"}
        ]
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_regressions_have_high_severity() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "high", "status": "active"}
        ]
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_regressions_waived() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "critical", "status": "waived"}
        ]
    });
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_regressions_only_medium() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "medium", "status": "active"}
        ]
    });
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_blocks_when_mixed_regressions_contain_high() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "low", "status": "active"},
            {"severity": "high", "status": "active"},
            {"severity": "medium", "status": "active"}
        ]
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_uses_level_as_fallback_for_severity() {
    let verdict = serde_json::json!({
        "regressions": [
            {"level": "critical", "status": "active"}
        ]
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_uses_severity_over_level_when_both_present() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "low", "level": "critical", "status": "active"}
        ]
    });
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_default_status_is_active_when_missing() {
    let verdict = serde_json::json!({
        "regressions": [
            {"severity": "critical"}
        ]
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_highest_severity_takes_precedence_over_severity() {
    let verdict = serde_json::json!({
        "highest_severity": "critical",
        "severity": "low"
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_falls_back_to_severity_when_no_highest() {
    let verdict = serde_json::json!({
        "severity": "high"
    });
    assert!(verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_regressions_empty_array() {
    let verdict = serde_json::json!({
        "regressions": []
    });
    assert!(!verdict_blocks(&verdict));
}

#[test]
fn verdict_does_not_block_when_all_low_severity() {
    let verdict = serde_json::json!({
        "highest_severity": "low",
        "blocking": false,
        "regressions": [
            {"severity": "low", "status": "active"}
        ]
    });
    assert!(!verdict_blocks(&verdict));
}

// ── Fixture contract stability tests ──────────────────────────────────

#[test]
fn fixture_required_modes_are_complete() {
    let fixture = load_fixture();
    let modes: BTreeSet<_> = fixture.required_modes.into_iter().collect();
    assert!(modes.len() >= 9, "expected at least 9 required modes");
}

#[test]
fn fixture_error_codes_follow_naming_convention() {
    let fixture = load_fixture();
    for code in &fixture.required_error_codes {
        assert!(
            code.starts_with("FE-RGC-CI-QUALITY-GATE-"),
            "error code must follow naming convention: {code}"
        );
    }
}

#[test]
fn fixture_lane_command_contract_is_non_empty() {
    let fixture = load_fixture();
    assert!(
        !fixture.lane_command_contract.is_empty(),
        "lane command contract should not be empty"
    );
}

#[test]
fn fixture_lane_command_contract_covers_dual_e2e_and_replay_commands() {
    let fixture = load_fixture();
    let commands: BTreeSet<_> = fixture
        .lane_command_contract
        .into_iter()
        .map(|contract| contract.command)
        .collect();

    for command in [
        "./scripts/run_rgc_test_harness_suite.sh ci",
        "./scripts/run_rgc_verification_coverage_matrix.sh ci",
        "./scripts/e2e/rgc_test_harness_replay.sh ci",
        "./scripts/e2e/rgc_verification_coverage_matrix_replay.sh ci",
    ] {
        assert!(
            commands.contains(command),
            "fixture missing lane command {command}"
        );
    }
}

#[test]
fn fixture_operator_entrypoints_cover_gate_and_replay_regression_modes() {
    let fixture = load_fixture();
    let commands: BTreeSet<_> = fixture
        .operator_entrypoints
        .into_iter()
        .map(|entry| entry.command)
        .collect();

    for command in [
        "./scripts/run_rgc_ci_quality_gates.sh ci",
        "./scripts/run_rgc_ci_quality_gates.sh regression",
        "./scripts/e2e/rgc_ci_quality_gates_replay.sh ci",
        "./scripts/e2e/rgc_ci_quality_gates_replay.sh regression",
    ] {
        assert!(
            commands.contains(command),
            "fixture missing operator entrypoint {command}"
        );
    }
}

#[test]
fn fixture_operator_entrypoint_modes_are_valid() {
    let fixture = load_fixture();
    for entrypoint in &fixture.operator_entrypoints {
        assert!(
            matches!(entrypoint.mode.as_str(), "ci" | "regression"),
            "unexpected operator entrypoint mode {}",
            entrypoint.mode
        );
    }
}

#[test]
fn fixture_lane_commands_have_valid_lanes() {
    let fixture = load_fixture();
    let valid_lanes = [
        "fmt",
        "check",
        "clippy",
        "unit",
        "integration",
        "e2e",
        "replay",
        "regression",
    ];
    for contract in &fixture.lane_command_contract {
        assert!(
            valid_lanes.contains(&contract.lane.as_str()),
            "unexpected lane: {}",
            contract.lane
        );
    }
}

#[test]
fn fixture_regression_samples_cover_both_blocking_and_non_blocking() {
    let fixture = load_fixture();
    let has_blocking = fixture
        .regression_verdict_samples
        .iter()
        .any(|s| s.expected_blocking);
    let has_non_blocking = fixture
        .regression_verdict_samples
        .iter()
        .any(|s| !s.expected_blocking);
    assert!(has_blocking, "should have at least one blocking sample");
    assert!(
        has_non_blocking,
        "should have at least one non-blocking sample"
    );
}

#[test]
fn fixture_required_artifacts_include_run_manifest() {
    let fixture = load_fixture();
    assert!(
        fixture
            .required_artifacts
            .contains(&"run_manifest.json".to_string())
    );
}

#[test]
fn fixture_regression_sample_ids_are_unique() {
    let fixture = load_fixture();
    let ids: BTreeSet<_> = fixture
        .regression_verdict_samples
        .iter()
        .map(|s| s.sample_id.as_str())
        .collect();
    assert_eq!(ids.len(), fixture.regression_verdict_samples.len());
}
