#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

const CONTRACT_JSON: &str = include_str!("../../../docs/ecosystem_capture_strategy_v1.json");

#[derive(Debug, Deserialize)]
struct EcosystemCaptureStrategyContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    generated_by: String,
    generated_at_utc: String,
    execution_pillars: Vec<ExecutionPillar>,
    adoption_targets: Vec<AdoptionTarget>,
    upstream_prerequisites: Vec<UpstreamPrerequisite>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExecutionPillar {
    pillar_id: String,
    delivery_beads: Vec<String>,
    user_outcome: String,
}

#[derive(Debug, Deserialize)]
struct AdoptionTarget {
    target_id: String,
    delivery_beads: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpstreamPrerequisite {
    bead_id: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &str) -> String {
    let full = repo_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()))
}

fn parse_contract() -> EcosystemCaptureStrategyContract {
    serde_json::from_str(CONTRACT_JSON).expect("ecosystem capture strategy contract must parse")
}

#[test]
fn strategy_doc_contains_required_sections() {
    let doc = read_to_string("docs/ECOSYSTEM_CAPTURE_STRATEGY_V1.md");

    for section in [
        "# Ecosystem Capture Strategy V1",
        "## Purpose",
        "## Execution Pillars",
        "## Adoption Targets",
        "## Upstream Prerequisites",
        "## Closure Semantics",
        "## Bundle Artifacts",
        "## Operator Verification",
    ] {
        assert!(doc.contains(section), "missing section: {section}");
    }
}

#[test]
fn strategy_contract_has_expected_identity_and_counts() {
    let contract = parse_contract();

    assert_eq!(
        contract.schema_version,
        "franken-engine.ecosystem-capture-strategy.v1"
    );
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-3bz4");
    assert_eq!(contract.policy_id, "policy-ecosystem-capture-strategy-v1");
    assert_eq!(contract.generated_by, "bd-3bz4");
    assert!(contract.generated_at_utc.ends_with('Z'));

    assert_eq!(contract.execution_pillars.len(), 5);
    assert_eq!(contract.adoption_targets.len(), 3);
    assert_eq!(contract.upstream_prerequisites.len(), 8);
}

#[test]
fn strategy_contract_tracks_expected_delivery_beads() {
    let contract = parse_contract();

    let pillar_ids: Vec<_> = contract
        .execution_pillars
        .iter()
        .map(|pillar| pillar.pillar_id.as_str())
        .collect();
    assert_eq!(
        pillar_ids,
        vec![
            "signed_extension_registry",
            "migration_validation",
            "enterprise_governance",
            "reputation_graph_apis",
            "partner_program",
        ]
    );

    let registry = &contract.execution_pillars[0];
    assert_eq!(registry.delivery_beads, vec!["bd-3bz4.1", "bd-mrf8"]);
    assert!(registry.user_outcome.contains("publish"));

    let migration = &contract.execution_pillars[1];
    assert_eq!(
        migration.delivery_beads,
        vec!["bd-3bz4.2", "bd-iqrn", "bd-2wft"]
    );

    let governance = &contract.execution_pillars[2];
    assert_eq!(governance.delivery_beads, vec!["bd-3bz4.3", "bd-2r0c"]);

    let reputation = &contract.execution_pillars[3];
    assert_eq!(reputation.delivery_beads, vec!["bd-2x4b"]);

    let partner = &contract.execution_pillars[4];
    assert_eq!(partner.delivery_beads, vec!["bd-1wqa", "bd-3j5s"]);

    let target_ids: Vec<_> = contract
        .adoption_targets
        .iter()
        .map(|target| target.target_id.as_str())
        .collect();
    assert_eq!(
        target_ids,
        vec![
            "greenfield_onboarding",
            "migration_validation",
            "public_case_studies",
        ]
    );
    assert_eq!(contract.adoption_targets[0].delivery_beads, vec!["bd-3qhv"]);
    assert_eq!(contract.adoption_targets[1].delivery_beads, vec!["bd-2wft"]);
    assert_eq!(contract.adoption_targets[2].delivery_beads, vec!["bd-3j5s"]);
}

#[test]
fn strategy_contract_tracks_expected_upstream_prerequisites() {
    let contract = parse_contract();
    let actual: Vec<_> = contract
        .upstream_prerequisites
        .iter()
        .map(|prerequisite| prerequisite.bead_id.as_str())
        .collect();
    assert_eq!(
        actual,
        vec![
            "bd-uvmm", "bd-3a5e", "bd-1bzp", "bd-2vu", "bd-3gsv", "bd-3ovc", "bd-39f0", "bd-26o",
        ]
    );
    assert!(
        contract
            .upstream_prerequisites
            .iter()
            .all(|item| !item.reason.is_empty())
    );
}

#[test]
fn strategy_runner_and_operator_commands_are_replayable() {
    let contract = parse_contract();
    let runner_script = read_to_string("scripts/run_ecosystem_capture_strategy.sh");
    let replay_script = read_to_string("scripts/e2e/ecosystem_capture_strategy_replay.sh");

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_ecosystem_capture_strategy.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/ecosystem_capture_strategy_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "set -euo pipefail");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.ecosystem-capture-strategy.run-manifest.v1"
    );

    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "milestone_status_report.json",
        "blocker_status_report.json",
        "strategy_summary.md",
        "ecosystem_capture_strategy_v1.json",
        "ecosystem_capture_strategy_v1.md",
    ] {
        assert!(
            contract
                .required_artifacts
                .iter()
                .any(|value| value == artifact),
            "missing required artifact {artifact}"
        );
    }

    assert_eq!(
        contract.required_log_keys,
        vec![
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
        ]
    );

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("target_rch_ecosystem_capture_strategy_verify")),
        "operator verification should include an rch-backed cargo target"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_ecosystem_capture_strategy.sh ci")),
        "operator verification should include the strategy runner"
    );

    assert!(
        runner_script
            .contains("cargo check -p frankenengine-engine --test ecosystem_capture_strategy")
    );
    assert!(
        runner_script
            .contains("cargo test -p frankenengine-engine --test ecosystem_capture_strategy")
    );
    assert!(runner_script.contains(
        "cargo clippy -p frankenengine-engine --test ecosystem_capture_strategy -- -D warnings"
    ));
    assert!(runner_script.contains("target_rch_ecosystem_capture_strategy_verify"));
    assert!(runner_script.contains("milestone_status_report.json"));
    assert!(runner_script.contains("blocker_status_report.json"));
    assert!(runner_script.contains("strategy_summary.md"));
    assert!(replay_script.contains("run_ecosystem_capture_strategy.sh"));
}
