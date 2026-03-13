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

use std::fs;
use std::path::PathBuf;

use frankenengine_engine::performance_regression_gate::{
    RegressionGateInput, RegressionGatePolicy, RegressionObservation, RegressionWaiver,
    evaluate_performance_regression_gate,
};
use serde::Deserialize;

const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_performance_regression_gate_v1.json");

#[derive(Debug, Deserialize)]
struct Contract {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
}

#[derive(Debug, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &std::path::Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn rgc_703_contract_is_parseable_and_points_to_expected_surfaces() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("contract must parse");
    assert_eq!(
        contract.schema_version,
        "franken-engine.rgc-performance-regression-gate.contract.v1"
    );
    assert_eq!(contract.bead_id, "bd-1lsy.8.3");
    assert!(
        contract
            .required_artifacts
            .iter()
            .any(|artifact| artifact == "regression_report.json")
    );

    let root = repo_root();
    assert!(root.join(&contract.gate_runner.script).is_file());
    assert!(root.join(&contract.gate_runner.replay_wrapper).is_file());
}

#[test]
fn regression_gate_produces_fail_closed_decision_and_culprit_ranking() {
    let input = RegressionGateInput::new(
        "trace",
        "decision",
        "policy",
        1_700_000_000,
        vec![
            RegressionObservation::new(
                "scheduler_lane",
                "baseline",
                "sha256:scheduler",
                100_000,
                121_000,
                20_000,
                Some("commit-a".to_string()),
            ),
            RegressionObservation::new(
                "dom_commit",
                "baseline",
                "sha256:dom",
                200_000,
                245_000,
                15_000,
                Some("commit-b".to_string()),
            ),
        ],
        Vec::new(),
    );

    let policy = RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 40_000,
        critical_regression_millionths: 200_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    };
    let report = evaluate_performance_regression_gate(&input, &policy);

    assert!(report.blocking, "high regressions must block promotion");
    assert_eq!(report.culprit_ranking.len(), 2);
    assert_eq!(report.culprit_ranking[0].workload_id, "dom_commit");
    assert_eq!(report.culprit_ranking[1].workload_id, "scheduler_lane");
}

#[test]
fn valid_waiver_clears_blocking_outcome() {
    let input = RegressionGateInput::new(
        "trace",
        "decision",
        "policy",
        1_700_000_000,
        vec![RegressionObservation::new(
            "scheduler_lane",
            "baseline",
            "sha256:scheduler",
            100_000,
            150_000,
            20_000,
            Some("commit-a".to_string()),
        )],
        vec![RegressionWaiver::new(
            "waiver-rgc-703",
            "scheduler_lane",
            "perf-oncall",
            1_800_000_000,
            "temporary host jitter",
        )],
    );

    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(
        !report.blocking,
        "valid waiver should suppress blocking finding"
    );
    assert_eq!(report.culprit_ranking.len(), 0);
    assert_eq!(report.regressions.len(), 1);
    assert_eq!(report.regressions[0].status.as_str(), "waived");
}

#[test]
fn readme_mentions_rgc_703_gate_commands() {
    let readme_path = repo_root().join("README.md");
    let readme = read_to_string(&readme_path);

    for fragment in [
        "## RGC Performance Regression Gate",
        "./scripts/run_rgc_performance_regression_gate.sh ci",
        "./scripts/e2e/rgc_performance_regression_gate_replay.sh ci",
    ] {
        assert!(
            readme.contains(fragment),
            "missing README fragment: {fragment}"
        );
    }
}

#[test]
fn rgc_703_lane_script_preserves_failure_classification() {
    let path = repo_root().join("scripts/run_rgc_performance_regression_gate.sh");
    let script = read_to_string(&path);

    for required_fragment in [
        "rch_build_timeout_sec=\"${RCH_BUILD_TIMEOUT_SEC:-${RCH_BUILD_TIMEOUT_SECONDS:-${rch_timeout_seconds}}}\"",
        "RCH_BUILD_TIMEOUT_SECONDS=\"${rch_build_timeout_sec}\"",
        "timeout --kill-after=30 \"${rch_timeout_seconds}\"",
        "kill_process_tree()",
        "rch reported timeout_secs=${reported_timeout} but requested build timeout is ${rch_build_timeout_sec}",
        "(rch-timeout-mismatch-${reported_timeout}-lt-${rch_build_timeout_sec})",
        "rch_progress_stall_seconds=\"${RCH_PROGRESS_STALL_SECONDS:-0}\"",
        "no remote progress for ${stall_seconds}s after remote execution started",
        "(rch-stalled-no-progress-${rch_progress_stall_seconds}s)",
        "(timeout-${rch_timeout_seconds}s)",
        "(rch-exit=${status}; remote-exit=${remote_exit_code})",
        "(rch-exit=${status}; missing-remote-exit-marker)",
        "(rch-local-fallback-detected)",
        "rgc-performance-regression-gate.run-manifest.v1",
    ] {
        assert!(
            script.contains(required_fragment),
            "missing script fragment in {}: {required_fragment}",
            path.display()
        );
    }
}

// ---------- RegressionGateInput ----------

#[test]
fn regression_gate_input_serde_roundtrip() {
    let input = RegressionGateInput::new(
        "trace-1",
        "decision-1",
        "policy-1",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload",
            "baseline",
            "sha256:abc",
            100_000,
            110_000,
            10_000,
            Some("commit-x".to_string()),
        )],
        Vec::new(),
    );
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: RegressionGateInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-1");
    assert_eq!(recovered.observations.len(), 1);
}

#[test]
fn regression_gate_input_empty_observations() {
    let input = RegressionGateInput::new(
        "trace-empty",
        "decision-empty",
        "policy-empty",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.blocking);
    assert_eq!(report.culprit_ranking.len(), 0);
    assert_eq!(report.regressions.len(), 0);
}

// ---------- RegressionObservation ----------

#[test]
fn regression_observation_serde_roundtrip() {
    let obs = RegressionObservation::new(
        "workload-a",
        "scenario-1",
        "sha256:meta",
        50_000,
        60_000,
        30_000,
        None,
    );
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RegressionObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "workload-a");
    assert_eq!(recovered.baseline_ns, 50_000);
    assert!(recovered.commit_id.is_none());
}

// ---------- RegressionWaiver ----------

#[test]
fn regression_waiver_serde_roundtrip() {
    let waiver = RegressionWaiver::new(
        "waiver-1",
        "workload-a",
        "oncall-alice",
        1_800_000_000,
        "host jitter",
    );
    let json = serde_json::to_string(&waiver).expect("serialize");
    let recovered: RegressionWaiver = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.waiver_id, "waiver-1");
    assert_eq!(recovered.owner, "oncall-alice");
}

// ---------- RegressionGatePolicy ----------

#[test]
fn regression_gate_policy_default_values() {
    let policy = RegressionGatePolicy::default();
    assert_eq!(policy.warning_regression_millionths, 25_000);
    assert_eq!(policy.fail_regression_millionths, 50_000);
    assert_eq!(policy.critical_regression_millionths, 100_000);
    assert_eq!(policy.max_p_value_millionths, 50_000);
    assert_eq!(policy.max_culprits, 10);
}

#[test]
fn regression_gate_policy_serde_roundtrip() {
    let policy = RegressionGatePolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: RegressionGatePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

// ---------- severity classification ----------

#[test]
fn zero_baseline_produces_critical_finding() {
    let input = RegressionGateInput::new(
        "trace-zero",
        "decision-zero",
        "policy-zero",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-zero-base",
            "scenario-zero",
            "sha256:meta",
            0,
            100_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking);
    assert!(!report.regressions.is_empty());
    assert!(
        report
            .regressions
            .iter()
            .any(|finding| finding.error_code.contains("BASELINE"))
    );
}

#[test]
fn missing_metadata_hash_produces_high_severity() {
    let input = RegressionGateInput::new(
        "trace-meta",
        "decision-meta",
        "policy-meta",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-no-meta",
            "scenario-meta",
            "",
            100_000,
            200_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking);
    assert!(
        report
            .regressions
            .iter()
            .any(|finding| finding.error_code.contains("INTEGRITY"))
    );
}

#[test]
fn warning_level_regression_does_not_block() {
    let policy = RegressionGatePolicy {
        warning_regression_millionths: 20_000,
        fail_regression_millionths: 200_000,
        critical_regression_millionths: 500_000,
        max_p_value_millionths: 50_000,
        max_culprits: 5,
    };
    let input = RegressionGateInput::new(
        "trace-warn",
        "decision-warn",
        "policy-warn",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-small-regression",
            "scenario-warn",
            "sha256:meta",
            1_000_000,
            1_030_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(!report.blocking, "warning-only regression should not block");
}

// ---------- culprit ranking ----------

#[test]
fn culprit_ranking_is_bounded_by_max_culprits() {
    let mut observations = Vec::new();
    for i in 0..15 {
        observations.push(RegressionObservation::new(
            format!("workload-{i}"),
            "scenario-rank",
            "sha256:meta",
            100_000,
            200_000,
            10_000,
            Some(format!("commit-{i}")),
        ));
    }
    let policy = RegressionGatePolicy {
        max_culprits: 5,
        ..RegressionGatePolicy::default()
    };
    let input = RegressionGateInput::new(
        "trace-rank",
        "decision-rank",
        "policy-rank",
        1_700_000_000,
        observations,
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(report.culprit_ranking.len() <= 5);
}

// ---------- expired waiver ----------

#[test]
fn expired_waiver_does_not_suppress_blocking() {
    let input = RegressionGateInput::new(
        "trace-expired",
        "decision-expired",
        "policy-expired",
        1_700_000_000,
        vec![RegressionObservation::new(
            "workload-expired",
            "scenario-expired",
            "sha256:meta",
            100_000,
            200_000,
            10_000,
            None,
        )],
        vec![RegressionWaiver::new(
            "waiver-old",
            "workload-expired",
            "oncall-bob",
            1_600_000_000,
            "no longer valid",
        )],
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(
        report.blocking,
        "expired waiver should not suppress blocking"
    );
}

// ---------- report fields ----------

#[test]
fn report_schema_version_is_set() {
    let input = RegressionGateInput::new(
        "trace-schema",
        "decision-schema",
        "policy-schema",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.schema_version.is_empty());
    assert_eq!(report.trace_id, "trace-schema");
    assert_eq!(report.decision_id, "decision-schema");
    assert_eq!(report.policy_id, "policy-schema");
    assert_eq!(report.component, "performance_regression_gate");
}

// ---------- determinism ----------

#[test]
fn gate_evaluation_is_deterministic() {
    let input = RegressionGateInput::new(
        "trace-det",
        "decision-det",
        "policy-det",
        1_700_000_000,
        vec![
            RegressionObservation::new("wl-b", "scen", "sha256:b", 100_000, 180_000, 10_000, None),
            RegressionObservation::new("wl-a", "scen", "sha256:a", 100_000, 160_000, 10_000, None),
        ],
        Vec::new(),
    );
    let policy = RegressionGatePolicy::default();
    let left = evaluate_performance_regression_gate(&input, &policy);
    let right = evaluate_performance_regression_gate(&input, &policy);
    assert_eq!(
        serde_json::to_string(&left).unwrap(),
        serde_json::to_string(&right).unwrap()
    );
}

#[test]
fn no_observations_produces_non_blocking_report() {
    let input = RegressionGateInput::new(
        "trace-empty",
        "decision-empty",
        "policy-empty",
        1_700_000_000,
        Vec::new(),
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.blocking, "no observations should not block");
    assert!(report.regressions.is_empty());
}

#[test]
fn contract_json_has_schema_version() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse contract");
    assert!(!contract.schema_version.is_empty());
    assert!(!contract.bead_id.is_empty());
}

#[test]
fn regression_gate_policy_custom_thresholds_roundtrip() {
    let policy = RegressionGatePolicy {
        warning_regression_millionths: 10_000,
        fail_regression_millionths: 80_000,
        critical_regression_millionths: 200_000,
        max_p_value_millionths: 25_000,
        max_culprits: 3,
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: RegressionGatePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

#[test]
fn regression_gate_policy_default_is_constructible() {
    let policy = RegressionGatePolicy::default();
    assert!(policy.max_culprits > 0);
}

#[test]
fn contract_json_deterministic_double_parse() {
    let a: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse a");
    let b: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse b");
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

#[test]
fn regression_observation_all_fields_serde_roundtrip() {
    let obs = RegressionObservation {
        workload_id: "w1".to_string(),
        scenario_id: "s1".to_string(),
        benchmark_metadata_hash: "sha256:abc".to_string(),
        baseline_ns: 1000,
        observed_ns: 1100,
        p_value_millionths: 50_000,
        commit_id: None,
    };
    let json = serde_json::to_string(&obs).expect("serialize");
    let recovered: RegressionObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "w1");
}

// ---------- multiple waivers ----------

#[test]
fn waiver_only_suppresses_matching_workload() {
    let input = RegressionGateInput::new(
        "trace-partial",
        "decision-partial",
        "policy-partial",
        1_700_000_000,
        vec![
            RegressionObservation::new(
                "workload-a",
                "scenario",
                "sha256:a",
                100_000,
                200_000,
                10_000,
                None,
            ),
            RegressionObservation::new(
                "workload-b",
                "scenario",
                "sha256:b",
                100_000,
                200_000,
                10_000,
                None,
            ),
        ],
        vec![RegressionWaiver::new(
            "waiver-a-only",
            "workload-a",
            "oncall",
            1_800_000_000,
            "suppress a only",
        )],
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    // workload-b is still unwaived → should still block
    assert!(
        report.blocking,
        "unwaived workload-b should still cause blocking"
    );
}

// ---------- report serde roundtrip ----------

#[test]
fn gate_report_serde_roundtrip() {
    let input = RegressionGateInput::new(
        "trace-rt",
        "decision-rt",
        "policy-rt",
        1_700_000_000,
        vec![RegressionObservation::new(
            "wl-rt",
            "scen",
            "sha256:rt",
            100_000,
            120_000,
            10_000,
            Some("commit-rt".to_string()),
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    let json = serde_json::to_string(&report).expect("serialize report");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse as value");
    assert!(value.is_object());
    assert!(value.get("schema_version").is_some());
    assert!(value.get("blocking").is_some());
    assert!(value.get("regressions").is_some());
}

// ---------- contract required_artifacts nonempty ----------

#[test]
fn contract_required_artifacts_are_nonempty() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse");
    assert!(!contract.required_artifacts.is_empty());
    for artifact in &contract.required_artifacts {
        assert!(
            !artifact.trim().is_empty(),
            "required_artifact must not be blank"
        );
    }
}

// ---------- critical regression produces blocking ----------

#[test]
fn critical_regression_produces_blocking_decision() {
    let policy = RegressionGatePolicy {
        warning_regression_millionths: 10_000,
        fail_regression_millionths: 50_000,
        critical_regression_millionths: 200_000,
        max_p_value_millionths: 50_000,
        max_culprits: 10,
    };
    // 5x regression (400%) → well above critical
    let input = RegressionGateInput::new(
        "trace-crit",
        "decision-crit",
        "policy-crit",
        1_700_000_000,
        vec![RegressionObservation::new(
            "wl-critical",
            "scen",
            "sha256:c",
            100_000,
            500_000,
            5_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &policy);
    assert!(report.blocking, "critical regression must block");
    assert!(!report.culprit_ranking.is_empty());
}

// ---------- improvement does not block ----------

#[test]
fn performance_improvement_does_not_block() {
    let input = RegressionGateInput::new(
        "trace-improve",
        "decision-improve",
        "policy-improve",
        1_700_000_000,
        vec![RegressionObservation::new(
            "wl-improved",
            "scen",
            "sha256:imp",
            200_000,
            100_000,
            10_000,
            None,
        )],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(!report.blocking, "improvement should not block");
    assert!(report.culprit_ranking.is_empty());
}

// ---------- waiver with commit_id roundtrip ----------

#[test]
fn regression_waiver_fields_preserved_in_serde() {
    let waiver = RegressionWaiver::new(
        "waiver-field-check",
        "workload-fc",
        "oncall-zara",
        1_900_000_000,
        "approved perf hit for new feature",
    );
    let json = serde_json::to_string(&waiver).expect("serialize");
    let recovered: RegressionWaiver = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.workload_id, "workload-fc");
    assert_eq!(recovered.expires_at_unix_seconds, 1_900_000_000);
    assert_eq!(recovered.reason, "approved perf hit for new feature");
}

// ---------- multiple observations sorted by severity in culprit ranking ----------

#[test]
fn culprit_ranking_sorted_by_regression_magnitude() {
    let input = RegressionGateInput::new(
        "trace-sort",
        "decision-sort",
        "policy-sort",
        1_700_000_000,
        vec![
            RegressionObservation::new(
                "small-regression",
                "scen",
                "sha256:s",
                100_000,
                160_000,
                10_000,
                Some("commit-s".to_string()),
            ),
            RegressionObservation::new(
                "large-regression",
                "scen",
                "sha256:l",
                100_000,
                300_000,
                10_000,
                Some("commit-l".to_string()),
            ),
        ],
        Vec::new(),
    );
    let report = evaluate_performance_regression_gate(&input, &RegressionGatePolicy::default());
    assert!(report.blocking);
    if report.culprit_ranking.len() >= 2 {
        // The most severe regression should appear first
        assert_eq!(report.culprit_ranking[0].workload_id, "large-regression");
        assert_eq!(report.culprit_ranking[1].workload_id, "small-regression");
    }
}

#[test]
fn regression_gate_policy_debug_is_nonempty() {
    let policy = RegressionGatePolicy::default();
    assert!(!format!("{policy:?}").is_empty());
}

#[test]
fn regression_observation_debug_is_nonempty() {
    let obs = RegressionObservation::new("w1", "s1", "sha256:abc", 1000, 1100, 50_000, None);
    assert!(!format!("{obs:?}").is_empty());
}

#[test]
fn contract_debug_is_nonempty() {
    let contract: Contract = serde_json::from_str(CONTRACT_JSON).expect("parse");
    assert!(!format!("{contract:?}").is_empty());
}
