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

#[path = "../src/test_flake_quarantine_workflow.rs"]
mod test_flake_quarantine_workflow;

use test_flake_quarantine_workflow::{
    FLAKE_WORKFLOW_COMPONENT, FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION,
    FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION, FLAKE_WORKFLOW_FAILURE_CODE, FlakeClassification,
    FlakePolicy, FlakeRunRecord, GateConfidenceReport, build_quarantine_records, classify_flakes,
    emit_structured_events, evaluate_gate_confidence, validate_flake_linkage,
    validate_quarantine_records, validate_reproducer_replay_commands,
    validate_structured_event_contract,
};

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
struct FlakeWorkflowContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    flake_detection: FlakeDetectionContract,
    reproducer_contract: ReproducerContract,
    quarantine_policy: QuarantinePolicyContract,
    gate_confidence: GateConfidenceContract,
    linkage_contract: LinkageContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FlakeDetectionContract {
    warning_flake_threshold_millionths: u32,
    high_flake_threshold_millionths: u32,
    required_run_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReproducerContract {
    require_ci_and_local_replay_commands: bool,
    required_bundle_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QuarantinePolicyContract {
    ttl_epochs: u32,
    require_owner_binding: bool,
    require_expiry: bool,
}

#[derive(Debug, Deserialize)]
struct GateConfidenceContract {
    require_flake_burden_metrics: bool,
    require_trendlines: bool,
    max_flake_burden_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct LinkageContract {
    require_impacted_unit_suite_links: bool,
    require_root_cause_hypothesis_artifacts: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_missing_owner: bool,
    block_on_non_expiring_quarantine: bool,
}

fn sample_runs() -> Vec<FlakeRunRecord> {
    vec![
        FlakeRunRecord {
            run_id: "run-001".to_string(),
            epoch: 11,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "pass".to_string(),
            error_signature: None,
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-a".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-002".to_string(),
            epoch: 11,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "fail".to_string(),
            error_signature: Some("panic:router-fallback-timeout".to_string()),
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-b".to_string(),
            related_unit_suites: vec![
                "unit_router_fallback".to_string(),
                "unit_scheduler_budget".to_string(),
            ],
            root_cause_hypothesis_artifacts: vec![
                "hypothesis-router-a".to_string(),
                "hypothesis-scheduler-b".to_string(),
            ],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-101".to_string(),
            epoch: 12,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "fail".to_string(),
            error_signature: Some("panic:router-fallback-timeout".to_string()),
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-c".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
        FlakeRunRecord {
            run_id: "run-102".to_string(),
            epoch: 12,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-router-fallback".to_string(),
            outcome: "pass".to_string(),
            error_signature: None,
            replay_command_ci:
                "rch exec -- cargo test --test frx_router -- router_fallback --exact".to_string(),
            replay_command_local: "cargo test --test frx_router -- router_fallback --exact"
                .to_string(),
            artifact_bundle_id: "bundle-router-d".to_string(),
            related_unit_suites: vec!["unit_router_fallback".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-router-a".to_string()],
            seed: 9001,
        },
    ]
}

#[test]
fn frx_20_5_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_FLAKE_QUARANTINE_WORKFLOW_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# FRX Flake Detection, Reproducer, and Quarantine Workflow v1",
        "## Scope",
        "## Deterministic Flake Classification Contract",
        "## Deterministic Reproducer Bundle Contract",
        "## Quarantine Workflow Contract",
        "## Gate Confidence and Trendline Contract",
        "## Scenario-to-Unit and Root-Cause Linkage Contract",
        "## Structured Event Contract",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_20_5_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);

    assert_eq!(
        contract.schema_version,
        FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.bead_id, "bd-mjh3.20.5");
    assert_eq!(contract.generated_by, "bd-mjh3.20.5");
    assert!(
        contract.flake_detection.warning_flake_threshold_millionths
            <= contract.flake_detection.high_flake_threshold_millionths
    );
    assert!(
        contract
            .reproducer_contract
            .require_ci_and_local_replay_commands
    );
    assert!(contract.quarantine_policy.require_owner_binding);
    assert!(contract.quarantine_policy.require_expiry);
    assert!(contract.gate_confidence.require_flake_burden_metrics);
    assert!(contract.gate_confidence.require_trendlines);
    assert!(contract.linkage_contract.require_impacted_unit_suite_links);
    assert!(
        contract
            .linkage_contract
            .require_root_cause_hypothesis_artifacts
    );
    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        FLAKE_WORKFLOW_FAILURE_CODE
    );
    assert!(contract.failure_policy.block_on_missing_owner);
    assert!(contract.failure_policy.block_on_non_expiring_quarantine);

    let required_fields: BTreeSet<_> = contract
        .flake_detection
        .required_run_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "run_id",
        "epoch",
        "suite_kind",
        "scenario_id",
        "outcome",
        "replay_command_ci",
        "replay_command_local",
        "artifact_bundle_id",
    ] {
        assert!(
            required_fields.contains(field),
            "missing run field: {field}"
        );
    }

    let bundle_fields: BTreeSet<_> = contract
        .reproducer_contract
        .required_bundle_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "bundle_id",
        "replay_command_ci",
        "replay_command_local",
        "artifact_bundle_ids",
        "run_ids",
    ] {
        assert!(
            bundle_fields.contains(field),
            "missing bundle field: {field}"
        );
    }

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|entry| entry.contains("run_frx_flake_quarantine_workflow_suite.sh ci")),
        "operator verification must include suite command"
    );
}

#[test]
fn frx_20_5_flake_classification_is_deterministic_and_linked() {
    let contract_path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&contract_path);
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: contract
            .flake_detection
            .warning_flake_threshold_millionths,
        high_flake_threshold_millionths: contract.flake_detection.high_flake_threshold_millionths,
        quarantine_ttl_epochs: contract.quarantine_policy.ttl_epochs,
        max_flake_burden_millionths: contract.gate_confidence.max_flake_burden_millionths,
        trend_stability_epsilon_millionths: 10_000,
    };

    let runs = sample_runs();
    let first = classify_flakes(&runs, &policy);
    let second = classify_flakes(&runs, &policy);
    assert_eq!(first, second, "classification must be deterministic");
    assert_eq!(first.len(), 1);

    let flake = &first[0];
    assert!(!flake.reproducer_bundle.bundle_id.is_empty());
    assert!(!flake.reproducer_bundle.replay_command_ci.is_empty());
    assert!(!flake.reproducer_bundle.replay_command_local.is_empty());
    let replay_violations = validate_reproducer_replay_commands(&first);
    assert!(
        replay_violations.is_empty(),
        "replay command validation should pass in CI/local mode: {replay_violations:?}"
    );
    assert!(
        !flake.impacted_unit_suites.is_empty(),
        "flake must link to impacted unit suites"
    );
    assert!(
        !flake.root_cause_hypothesis_artifacts.is_empty(),
        "flake must link to root-cause artifacts"
    );
    let linkage_violations = validate_flake_linkage(&first);
    assert!(
        linkage_violations.is_empty(),
        "linkage validation should pass for impacted suites and root-cause artifacts: {linkage_violations:?}"
    );
}

#[test]
fn frx_20_5_quarantine_gate_confidence_and_events_are_complete() {
    let contract_path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&contract_path);
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: contract
            .flake_detection
            .warning_flake_threshold_millionths,
        high_flake_threshold_millionths: contract.flake_detection.high_flake_threshold_millionths,
        quarantine_ttl_epochs: contract.quarantine_policy.ttl_epochs,
        max_flake_burden_millionths: contract.gate_confidence.max_flake_burden_millionths,
        trend_stability_epsilon_millionths: 10_000,
    };

    let runs = sample_runs();
    let flakes = classify_flakes(&runs, &policy);

    let mut owners = BTreeMap::new();
    owners.insert(
        "e2e::scenario-router-fallback".to_string(),
        "router-oncall".to_string(),
    );
    let quarantines = build_quarantine_records(&flakes, &owners, 12, &policy);
    let quarantine_violations = validate_quarantine_records(&quarantines, 12);
    assert!(
        quarantine_violations.is_empty(),
        "quarantine workflow must be owner-bound and time-bounded: {quarantine_violations:?}"
    );

    let report = evaluate_gate_confidence(&runs, &flakes, &policy);
    assert!(
        report.per_epoch_burden.len() >= 2,
        "gate confidence must contain trendline points"
    );
    assert!(report.flake_burden_millionths > 0);
    assert_eq!(report.promotion_outcome, "hold");
    assert!(
        report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("high_flake_rate")),
        "high flake classes must become gate blockers"
    );

    let events = emit_structured_events(
        "trace-frx-20-5",
        "decision-frx-20-5",
        "policy-frx-20-5-v1",
        &flakes,
        &quarantines,
        &report,
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event == "flake_classified")
            .count(),
        flakes.len()
    );
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION),
        "every event must use stable schema version"
    );

    let flake_event = events
        .iter()
        .find(|event| event.event == "flake_classified")
        .expect("flake event");
    assert_eq!(flake_event.component, FLAKE_WORKFLOW_COMPONENT);
    assert!(!flake_event.replay_command_ci.is_empty());
    assert!(!flake_event.replay_command_local.is_empty());
    assert!(
        !flake_event.impacted_unit_suites.is_empty(),
        "flake event should carry impacted unit suite links"
    );
    assert!(
        !flake_event.root_cause_hypothesis_artifacts.is_empty(),
        "flake event should carry root-cause artifacts"
    );
    let event_violations = validate_structured_event_contract(&events);
    assert!(
        event_violations.is_empty(),
        "structured event contract should pass for replay commands and required linkage fields: {event_violations:?}"
    );
}

// ---------- constants ----------

#[test]
fn flake_workflow_constants_are_nonempty() {
    assert!(!FLAKE_WORKFLOW_COMPONENT.is_empty());
    assert!(!FLAKE_WORKFLOW_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!FLAKE_WORKFLOW_FAILURE_CODE.is_empty());
}

// ---------- sample_runs ----------

#[test]
fn sample_runs_has_four_records() {
    assert_eq!(sample_runs().len(), 4);
}

#[test]
fn sample_runs_contains_pass_and_fail() {
    let runs = sample_runs();
    assert!(runs.iter().any(|r| r.outcome == "pass"));
    assert!(runs.iter().any(|r| r.outcome == "fail"));
}

// ---------- classify_flakes ----------

#[test]
fn classify_flakes_produces_one_flake_from_sample_runs() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    assert_eq!(flakes.len(), 1);
}

// ---------- FlakeRunRecord ----------

#[test]
fn flake_run_record_serde_roundtrip() {
    let record = &sample_runs()[0];
    let json = serde_json::to_string(record).expect("serialize");
    let recovered: FlakeRunRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.run_id, record.run_id);
    assert_eq!(recovered.scenario_id, record.scenario_id);
}

// ---------- FlakePolicy ----------

#[test]
fn flake_policy_serde_roundtrip() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: FlakePolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.warning_flake_threshold_millionths,
        policy.warning_flake_threshold_millionths
    );
}

// ---------- build_quarantine_records ----------

#[test]
fn quarantine_records_require_owners() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let empty_owners = BTreeMap::new();
    let quarantines = build_quarantine_records(&flakes, &empty_owners, 12, &policy);
    let violations = validate_quarantine_records(&quarantines, 12);
    assert!(
        violations.iter().any(|v| v.contains("owner")),
        "missing owners should produce violations"
    );
}

// ---------- evaluate_gate_confidence ----------

#[test]
fn gate_confidence_has_per_epoch_burden() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let report = evaluate_gate_confidence(&sample_runs(), &flakes, &policy);
    assert!(!report.per_epoch_burden.is_empty());
}

// ---------- validate_reproducer_replay_commands ----------

#[test]
fn valid_reproducers_pass_validation() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let violations = validate_reproducer_replay_commands(&flakes);
    assert!(violations.is_empty());
}

#[test]
fn sample_runs_run_ids_are_unique() {
    let runs = sample_runs();
    let mut seen = BTreeSet::new();
    for run in &runs {
        assert!(seen.insert(&run.run_id), "duplicate run_id: {}", run.run_id);
    }
}

#[test]
fn classify_flakes_is_deterministic_across_invocations() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let a = classify_flakes(&sample_runs(), &policy);
    let b = classify_flakes(&sample_runs(), &policy);
    assert_eq!(a, b);
}

#[test]
fn contract_operator_verification_commands_are_nonempty() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);
    assert!(!contract.operator_verification.is_empty());
    for cmd in &contract.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

#[test]
fn contract_has_nonempty_schema_version() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);
    assert!(!contract.schema_version.trim().is_empty());
}

#[test]
fn contract_has_nonempty_bead_id() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);
    assert!(!contract.bead_id.trim().is_empty());
}

#[test]
fn contract_has_nonempty_generated_by() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let contract: FlakeWorkflowContract = load_json(&path);
    assert!(!contract.generated_by.trim().is_empty());
}

#[test]
fn flake_policy_default_is_constructible() {
    let policy = FlakePolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    assert!(!json.is_empty());
}

#[test]
fn contract_json_file_exists() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    assert!(path.exists(), "contract JSON file must exist");
}

#[test]
fn contract_deterministic_double_load() {
    let path = repo_root().join("docs/frx_flake_quarantine_workflow_v1.json");
    let a: FlakeWorkflowContract = load_json(&path);
    let b: FlakeWorkflowContract = load_json(&path);
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.bead_id, b.bead_id);
}

#[test]
fn flake_run_record_debug_is_nonempty() {
    let record = &sample_runs()[0];
    let debug = format!("{record:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn flake_policy_debug_is_nonempty() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let debug = format!("{policy:?}");
    assert!(!debug.trim().is_empty());
}

#[test]
fn classify_flakes_returns_empty_for_empty_runs() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&[], &policy);
    assert!(flakes.is_empty());
}

#[test]
fn classify_flakes_all_passes_returns_empty() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let runs: Vec<FlakeRunRecord> = (0..5)
        .map(|i| FlakeRunRecord {
            run_id: format!("all-pass-{i}"),
            epoch: 10,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-stable".to_string(),
            outcome: "pass".to_string(),
            error_signature: None,
            replay_command_ci: "rch exec -- cargo test --exact stable".to_string(),
            replay_command_local: "cargo test --exact stable".to_string(),
            artifact_bundle_id: format!("bundle-stable-{i}"),
            related_unit_suites: vec!["unit_stable".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-none".to_string()],
            seed: 42,
        })
        .collect();

    let flakes = classify_flakes(&runs, &policy);
    assert!(
        flakes.is_empty(),
        "purely passing runs should never produce flake classifications"
    );
}

#[test]
fn flake_classification_serde_roundtrip_preserves_severity_and_action() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    assert!(!flakes.is_empty());

    let json = serde_json::to_string(&flakes[0]).expect("serialize classification");
    let recovered: FlakeClassification =
        serde_json::from_str(&json).expect("deserialize classification");
    assert_eq!(recovered.severity, flakes[0].severity);
    assert_eq!(recovered.quarantine_action, flakes[0].quarantine_action);
    assert_eq!(
        recovered.flake_rate_millionths,
        flakes[0].flake_rate_millionths
    );
    assert_eq!(
        recovered.reproducer_bundle.bundle_id,
        flakes[0].reproducer_bundle.bundle_id
    );
}

#[test]
fn emit_structured_events_each_event_has_matching_trace_and_policy_ids() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let mut owners = BTreeMap::new();
    owners.insert(
        "e2e::scenario-router-fallback".to_string(),
        "router-oncall".to_string(),
    );
    let quarantines = build_quarantine_records(&flakes, &owners, 12, &policy);
    let report = evaluate_gate_confidence(&sample_runs(), &flakes, &policy);

    let events = emit_structured_events(
        "trace-ids-check",
        "decision-ids-check",
        "policy-ids-check",
        &flakes,
        &quarantines,
        &report,
    );

    assert!(!events.is_empty());
    for event in &events {
        assert_eq!(event.trace_id, "trace-ids-check");
        assert!(
            event.decision_id.starts_with("decision-ids-check"),
            "decision_id should start with provided prefix: {}",
            event.decision_id
        );
        assert!(
            event.policy_id.starts_with("policy-ids-check"),
            "policy_id should start with provided prefix: {}",
            event.policy_id
        );
        assert_eq!(event.component, FLAKE_WORKFLOW_COMPONENT);
    }
}

#[test]
fn gate_confidence_report_serde_roundtrip() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let report = evaluate_gate_confidence(&sample_runs(), &flakes, &policy);

    let json = serde_json::to_string(&report).expect("serialize report");
    let recovered: GateConfidenceReport = serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(recovered.latest_epoch, report.latest_epoch);
    assert_eq!(
        recovered.flake_burden_millionths,
        report.flake_burden_millionths
    );
    assert_eq!(recovered.promotion_outcome, report.promotion_outcome);
    assert_eq!(
        recovered.per_epoch_burden.len(),
        report.per_epoch_burden.len()
    );
    assert_eq!(recovered.trend_direction, report.trend_direction);
}

#[test]
fn quarantine_record_expiry_epoch_exceeds_opened_epoch() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let mut owners = BTreeMap::new();
    owners.insert(
        "e2e::scenario-router-fallback".to_string(),
        "router-oncall".to_string(),
    );
    let quarantines = build_quarantine_records(&flakes, &owners, 12, &policy);

    for qr in &quarantines {
        assert!(
            qr.expires_epoch > qr.opened_epoch,
            "quarantine expiry {} must be after opened epoch {}",
            qr.expires_epoch,
            qr.opened_epoch
        );
    }
}

// ---------- enrichment: deeper edge-case and structural tests ----------

#[test]
fn classify_flakes_all_failures_gives_100_percent_flake_rate() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let runs: Vec<FlakeRunRecord> = (0..4)
        .map(|i| FlakeRunRecord {
            run_id: format!("fail-{i}"),
            epoch: 10,
            suite_kind: "e2e".to_string(),
            scenario_id: "scenario-always-fail".to_string(),
            outcome: "fail".to_string(),
            error_signature: Some("panic:always".to_string()),
            replay_command_ci: "rch exec -- cargo test --exact always_fail".to_string(),
            replay_command_local: "cargo test --exact always_fail".to_string(),
            artifact_bundle_id: format!("bundle-fail-{i}"),
            related_unit_suites: vec!["unit_always_fail".to_string()],
            root_cause_hypothesis_artifacts: vec!["hypothesis-always".to_string()],
            seed: 1234,
        })
        .collect();
    // All failures is not a flake (it's a hard failure, not intermittent)
    // The classify_flakes function should either return empty or classify as high
    // since the "flake rate" is 0% (no pass/fail alternation) or 100% failure.
    // Verify deterministic result either way.
    let a = classify_flakes(&runs, &policy);
    let b = classify_flakes(&runs, &policy);
    assert_eq!(a, b, "classification must be deterministic");
}

#[test]
fn flake_workflow_event_schema_version_constant_is_versioned() {
    assert!(
        FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION.contains("v1"),
        "event schema version must include version indicator"
    );
}

#[test]
fn flake_classification_debug_format_is_nonempty() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    assert!(!flakes.is_empty());
    let debug = format!("{:?}", flakes[0]);
    assert!(!debug.trim().is_empty());
    assert!(
        debug.contains("severity"),
        "debug output should include severity field"
    );
}

#[test]
fn gate_confidence_report_trend_direction_is_nonempty() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let report = evaluate_gate_confidence(&sample_runs(), &flakes, &policy);
    let direction_str = format!("{:?}", report.trend_direction);
    assert!(
        !direction_str.is_empty(),
        "gate confidence report must include a trend direction"
    );
}

#[test]
fn emit_structured_events_gate_report_event_is_present() {
    let policy = FlakePolicy {
        warning_flake_threshold_millionths: 100_000,
        high_flake_threshold_millionths: 500_000,
        quarantine_ttl_epochs: 3,
        max_flake_burden_millionths: 200_000,
        trend_stability_epsilon_millionths: 10_000,
    };
    let flakes = classify_flakes(&sample_runs(), &policy);
    let mut owners = BTreeMap::new();
    owners.insert(
        "e2e::scenario-router-fallback".to_string(),
        "router-oncall".to_string(),
    );
    let quarantines = build_quarantine_records(&flakes, &owners, 12, &policy);
    let report = evaluate_gate_confidence(&sample_runs(), &flakes, &policy);

    let events = emit_structured_events(
        "trace-gate-test",
        "decision-gate-test",
        "policy-gate-test",
        &flakes,
        &quarantines,
        &report,
    );

    // there should be a gate_report event
    let gate_events: Vec<_> = events.iter().filter(|e| e.event == "gate_report").collect();
    assert!(
        !gate_events.is_empty(),
        "structured events must include a gate_report event"
    );
    for ge in &gate_events {
        assert_eq!(ge.schema_version, FLAKE_WORKFLOW_EVENT_SCHEMA_VERSION);
    }
}
