#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

const CONTRACT_JSON: &str = include_str!("../../../docs/scientific_contribution_targets_v1.json");

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ScientificContributionTargetsContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    generated_by: String,
    generated_at_utc: String,
    source_inputs: Vec<String>,
    required_contributions: Vec<RequiredContribution>,
    output_contract_milestones: Vec<OutputContractMilestone>,
    upstream_dependencies: Vec<UpstreamDependency>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RequiredContribution {
    contribution_id: String,
    description: String,
    delivery_beads: Vec<String>,
    user_outcome: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct OutputContractMilestone {
    milestone_id: String,
    description: String,
    status_bead_id: String,
    supporting_delivery_beads: Vec<String>,
    success_threshold: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct UpstreamDependency {
    bead_id: String,
    reason: String,
}

#[allow(dead_code)]
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

fn parse_contract() -> ScientificContributionTargetsContract {
    serde_json::from_str(CONTRACT_JSON)
        .expect("scientific contribution targets contract must parse")
}

#[test]
fn strategy_doc_contains_required_sections() {
    let doc = read_to_string("docs/SCIENTIFIC_CONTRIBUTION_TARGETS_V1.md");

    for section in [
        "# Scientific Contribution Targets V1",
        "## Purpose",
        "## Required Contributions",
        "## Output Contract Milestones",
        "## Upstream Dependencies",
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
        "franken-engine.scientific-contribution-targets.v1"
    );
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-2501");
    assert_eq!(
        contract.policy_id,
        "policy-scientific-contribution-targets-v1"
    );
    assert_eq!(contract.generated_by, "bd-2501");
    assert!(contract.generated_at_utc.ends_with('Z'));

    assert_eq!(contract.required_contributions.len(), 5);
    assert_eq!(contract.output_contract_milestones.len(), 3);
    assert_eq!(contract.upstream_dependencies.len(), 7);
}

#[test]
fn strategy_contract_tracks_expected_contributions_and_output_milestones() {
    let contract = parse_contract();

    let contribution_ids: Vec<_> = contract
        .required_contributions
        .iter()
        .map(|item| item.contribution_id.as_str())
        .collect();
    assert_eq!(
        contribution_ids,
        vec![
            "open_specifications",
            "reproducible_datasets",
            "reference_proofs",
            "external_evaluations",
            "public_technical_reports",
        ]
    );

    assert_eq!(
        contract.required_contributions[0].delivery_beads,
        vec!["bd-3ebk"]
    );
    assert_eq!(
        contract.required_contributions[1].delivery_beads,
        vec!["bd-2pwr"]
    );
    assert_eq!(
        contract.required_contributions[2].delivery_beads,
        vec!["bd-16up"]
    );
    assert_eq!(
        contract.required_contributions[3].delivery_beads,
        vec!["bd-52ko"]
    );
    assert_eq!(
        contract.required_contributions[4].delivery_beads,
        vec!["bd-2cc8"]
    );

    let milestone_ids: Vec<_> = contract
        .output_contract_milestones
        .iter()
        .map(|item| item.milestone_id.as_str())
        .collect();
    assert_eq!(
        milestone_ids,
        vec![
            "publishable_reports",
            "externally_replicated_claims",
            "adopted_open_tool",
        ]
    );

    assert_eq!(
        contract.output_contract_milestones[0].status_bead_id,
        "bd-2501.1"
    );
    assert_eq!(
        contract.output_contract_milestones[0].supporting_delivery_beads,
        vec!["bd-2zk0"]
    );
    assert_eq!(
        contract.output_contract_milestones[1].status_bead_id,
        "bd-2501.2"
    );
    assert_eq!(
        contract.output_contract_milestones[1].supporting_delivery_beads,
        vec!["bd-3c8n"]
    );
    assert_eq!(
        contract.output_contract_milestones[2].status_bead_id,
        "bd-2501.3"
    );
    assert_eq!(
        contract.output_contract_milestones[2].supporting_delivery_beads,
        vec!["bd-37cc"]
    );
}

#[test]
fn strategy_contract_tracks_expected_dependencies() {
    let contract = parse_contract();
    let actual: Vec<_> = contract
        .upstream_dependencies
        .iter()
        .map(|dependency| dependency.bead_id.as_str())
        .collect();
    assert_eq!(
        actual,
        vec![
            "bd-19l0", "bd-25b7", "bd-3ab3", "bd-3gsv", "bd-f7n", "bd-3rd", "bd-1ze",
        ]
    );
    assert!(
        contract
            .upstream_dependencies
            .iter()
            .all(|item| !item.reason.is_empty())
    );
}

#[test]
fn strategy_runner_and_replay_scripts_are_replayable() {
    let contract = parse_contract();
    let runner_script = read_to_string("scripts/run_scientific_contribution_targets.sh");
    let replay_script = read_to_string("scripts/e2e/scientific_contribution_targets_replay.sh");

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_scientific_contribution_targets.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/scientific_contribution_targets_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "set -euo pipefail");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.scientific-contribution-targets.run-manifest.v1"
    );

    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "contribution_status_report.json",
        "output_contract_status_report.json",
        "dependency_status_report.json",
        "scientific_contribution_summary.md",
        "scientific_contribution_targets_v1.json",
        "scientific_contribution_targets_v1.md",
        "step_logs/step_*.log",
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
            .any(|cmd| cmd.contains("./scripts/run_scientific_contribution_targets.sh bundle")),
        "operator verification should include the local bundle runner"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/e2e/scientific_contribution_targets_replay.sh show")),
        "operator verification should include the replay wrapper"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("target_rch_scientific_contribution_targets_verify")),
        "operator verification should include an rch-backed cargo target"
    );

    for snippet in [
        "cargo check -p frankenengine-engine --test scientific_contribution_targets",
        "cargo test -p frankenengine-engine --test scientific_contribution_targets",
        "cargo clippy -p frankenengine-engine --test scientific_contribution_targets -- -D warnings",
        "declared source input is missing",
        "scientific contribution targets have open output-contract milestone beads",
        "manifest: $manifest",
        "contribution_status_report.json",
        "output_contract_status_report.json",
        "dependency_status_report.json",
        "target_rch_scientific_contribution_targets_verify",
    ] {
        assert!(
            runner_script.contains(snippet),
            "runner script missing required snippet: {snippet}"
        );
    }

    for snippet in [
        "run_scientific_contribution_targets.sh",
        "latest_complete_run_dir",
        "newest directory",
        "contribution_status_report.json",
        "output_contract_status_report.json",
        "dependency_status_report.json",
        "scientific_contribution_summary.md",
        "scientific_contribution_targets_v1.json",
        "scientific_contribution_targets_v1.md",
        "latest first step log unavailable",
    ] {
        assert!(
            replay_script.contains(snippet),
            "replay script missing required snippet: {snippet}"
        );
    }
}
