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
    required_readme_fragments: Vec<String>,
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ScientificReportCatalog {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    minimum_report_count: usize,
    reports: Vec<ScientificReportEntry>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ScientificReportEntry {
    report_id: String,
    title: String,
    status_bead_id: String,
    supporting_beads: Vec<String>,
    primary_doc: String,
    artifact_root: String,
    verification_commands: Vec<String>,
    research_claim: String,
    negative_result_surface: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ExternalReplicationCatalog {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    minimum_claim_count: usize,
    claims: Vec<ExternalReplicationEntry>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ExternalReplicationEntry {
    claim_id: String,
    title: String,
    status_bead_id: String,
    supporting_beads: Vec<String>,
    primary_doc: String,
    verifier_doc: String,
    artifact_root: String,
    verification_commands: Vec<String>,
    claim_summary: String,
    replication_gap: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct OpenToolAdoptionCatalog {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    minimum_tool_count: usize,
    tools: Vec<OpenToolAdoptionEntry>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct OpenToolAdoptionEntry {
    tool_id: String,
    title: String,
    release_status_bead_id: String,
    supporting_beads: Vec<String>,
    primary_doc: String,
    artifact_root: String,
    adoption_evidence_doc: String,
    verification_commands: Vec<String>,
    external_user_value: String,
    adoption_gap: String,
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

fn parse_report_catalog() -> ScientificReportCatalog {
    let raw = read_to_string("docs/scientific_report_catalog_v1.json");
    serde_json::from_str(&raw).expect("scientific report catalog must parse")
}

fn parse_external_replication_catalog() -> ExternalReplicationCatalog {
    let raw = read_to_string("docs/external_replication_catalog_v1.json");
    serde_json::from_str(&raw).expect("external replication catalog must parse")
}

fn parse_open_tool_adoption_catalog() -> OpenToolAdoptionCatalog {
    let raw = read_to_string("docs/open_tool_adoption_catalog_v1.json");
    serde_json::from_str(&raw).expect("open tool adoption catalog must parse")
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
        "## Technical Report Catalog",
        "## External Replication Catalog",
        "## Open Tool Adoption Catalog",
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
fn report_catalog_has_expected_identity_and_four_report_lanes() {
    let catalog = parse_report_catalog();

    assert_eq!(
        catalog.schema_version,
        "franken-engine.scientific-report-catalog.v1"
    );
    assert_eq!(catalog.contract_version, "1.0.0");
    assert_eq!(catalog.bead_id, "bd-2501.1");
    assert_eq!(catalog.generated_by, "bd-2501.1");
    assert!(catalog.generated_at_utc.ends_with('Z'));
    assert_eq!(catalog.minimum_report_count, 4);
    assert_eq!(catalog.reports.len(), 4);

    let report_ids: Vec<_> = catalog
        .reports
        .iter()
        .map(|entry| entry.report_id.as_str())
        .collect();
    assert_eq!(
        report_ids,
        vec![
            "probabilistic_guardplane_observability",
            "security_enforcement_verification",
            "runtime_semantics_replay_pack",
            "extension_heavy_benchmark_methodology",
        ]
    );
}

#[test]
fn report_catalog_entries_reference_existing_docs_and_replayable_surfaces() {
    let catalog = parse_report_catalog();

    for entry in &catalog.reports {
        let full = repo_root().join(&entry.primary_doc);
        assert!(
            full.exists(),
            "primary doc missing for {}: {}",
            entry.report_id,
            full.display()
        );
        assert!(
            entry.artifact_root.contains("<timestamp>"),
            "artifact root must stay operator-readable for {}",
            entry.report_id
        );
        assert!(
            !entry.title.is_empty()
                && !entry.status_bead_id.is_empty()
                && !entry.research_claim.is_empty()
                && !entry.negative_result_surface.is_empty(),
            "catalog entry {} must be fully described",
            entry.report_id
        );
        assert!(
            !entry.verification_commands.is_empty(),
            "catalog entry {} must declare verification commands",
            entry.report_id
        );
    }
}

#[test]
fn external_replication_catalog_has_expected_identity_and_claim_lanes() {
    let catalog = parse_external_replication_catalog();

    assert_eq!(
        catalog.schema_version,
        "franken-engine.external-replication-catalog.v1"
    );
    assert_eq!(catalog.contract_version, "1.0.0");
    assert_eq!(catalog.bead_id, "bd-2501.2");
    assert_eq!(catalog.generated_by, "bd-2501.2");
    assert!(catalog.generated_at_utc.ends_with('Z'));
    assert_eq!(catalog.minimum_claim_count, 2);
    assert_eq!(catalog.claims.len(), 3);

    let claim_ids: Vec<_> = catalog
        .claims
        .iter()
        .map(|entry| entry.claim_id.as_str())
        .collect();
    assert_eq!(
        claim_ids,
        vec![
            "benchmark_peer_claim_bundle",
            "security_enforcement_verifier_bundle",
            "runtime_replay_verifier_bundle",
        ]
    );
}

#[test]
fn external_replication_catalog_entries_reference_existing_docs_and_verifier_surfaces() {
    let catalog = parse_external_replication_catalog();

    for entry in &catalog.claims {
        let primary_doc = repo_root().join(&entry.primary_doc);
        let verifier_doc = repo_root().join(&entry.verifier_doc);
        assert!(
            primary_doc.exists(),
            "primary doc missing for {}: {}",
            entry.claim_id,
            primary_doc.display()
        );
        assert!(
            verifier_doc.exists(),
            "verifier doc missing for {}: {}",
            entry.claim_id,
            verifier_doc.display()
        );
        assert!(
            entry.artifact_root.contains("<timestamp>"),
            "artifact root must stay operator-readable for {}",
            entry.claim_id
        );
        assert!(
            !entry.title.is_empty()
                && !entry.status_bead_id.is_empty()
                && !entry.claim_summary.is_empty()
                && !entry.replication_gap.is_empty(),
            "catalog entry {} must be fully described",
            entry.claim_id
        );
        assert!(
            !entry.verification_commands.is_empty(),
            "catalog entry {} must declare verification commands",
            entry.claim_id
        );
    }
}

#[test]
fn open_tool_adoption_catalog_has_expected_identity_and_candidate_tools() {
    let catalog = parse_open_tool_adoption_catalog();

    assert_eq!(
        catalog.schema_version,
        "franken-engine.open-tool-adoption-catalog.v1"
    );
    assert_eq!(catalog.contract_version, "1.0.0");
    assert_eq!(catalog.bead_id, "bd-2501.3");
    assert_eq!(catalog.generated_by, "bd-2501.3");
    assert!(catalog.generated_at_utc.ends_with('Z'));
    assert_eq!(catalog.minimum_tool_count, 1);
    assert_eq!(catalog.tools.len(), 3);

    let tool_ids: Vec<_> = catalog.tools.iter().map(|entry| entry.tool_id.as_str()).collect();
    assert_eq!(
        tool_ids,
        vec![
            "third_party_verifier_toolkit",
            "extension_heavy_benchmark_suite",
            "parser_third_party_rerun_kit",
        ]
    );
}

#[test]
fn open_tool_adoption_catalog_entries_reference_existing_docs_and_adoption_surfaces() {
    let catalog = parse_open_tool_adoption_catalog();

    for entry in &catalog.tools {
        let primary_doc = repo_root().join(&entry.primary_doc);
        assert!(
            primary_doc.exists(),
            "primary doc missing for {}: {}",
            entry.tool_id,
            primary_doc.display()
        );
        assert!(
            entry.artifact_root.contains("<timestamp>"),
            "artifact root must stay operator-readable for {}",
            entry.tool_id
        );
        assert!(
            entry.adoption_evidence_doc.starts_with("docs/")
                && entry.adoption_evidence_doc.ends_with(".md"),
            "tool {} must declare an operator-readable adoption evidence path",
            entry.tool_id
        );
        assert!(
            !entry.title.is_empty()
                && !entry.release_status_bead_id.is_empty()
                && !entry.external_user_value.is_empty()
                && !entry.adoption_gap.is_empty(),
            "catalog entry {} must be fully described",
            entry.tool_id
        );
        assert!(
            !entry.verification_commands.is_empty(),
            "catalog entry {} must declare verification commands",
            entry.tool_id
        );
    }
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
        "technical_report_status_report.json",
        "external_replication_status_report.json",
        "open_tool_adoption_status_report.json",
        "scientific_contribution_summary.md",
        "scientific_contribution_targets_v1.json",
        "scientific_contribution_targets_v1.md",
        "scientific_report_catalog_v1.json",
        "SCIENTIFIC_REPORT_CATALOG_V1.md",
        "external_replication_catalog_v1.json",
        "EXTERNAL_REPLICATION_CATALOG_V1.md",
        "open_tool_adoption_catalog_v1.json",
        "OPEN_TOOL_ADOPTION_CATALOG_V1.md",
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
            .any(|cmd| cmd.contains("jq empty docs/scientific_report_catalog_v1.json")),
        "operator verification should include the scientific report catalog JSON check"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/external_replication_catalog_v1.json")),
        "operator verification should include the external replication catalog JSON check"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/open_tool_adoption_catalog_v1.json")),
        "operator verification should include the open tool adoption catalog JSON check"
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
        "scientific report catalog JSON is invalid",
        "scientific report catalog has fewer than four declared report lanes",
        "external replication catalog JSON is invalid",
        "external replication catalog has fewer than two declared claim lanes",
        "open tool adoption catalog JSON is invalid",
        "open tool adoption catalog has fewer than one declared tool lane",
        "scientific contribution targets have open output-contract milestone beads",
        "manifest: $manifest",
        "contribution_status_report.json",
        "output_contract_status_report.json",
        "dependency_status_report.json",
        "technical_report_status_report.json",
        "external_replication_status_report.json",
        "open_tool_adoption_status_report.json",
        "scientific_report_catalog_v1.json",
        "SCIENTIFIC_REPORT_CATALOG_V1.md",
        "external_replication_catalog_v1.json",
        "EXTERNAL_REPLICATION_CATALOG_V1.md",
        "open_tool_adoption_catalog_v1.json",
        "OPEN_TOOL_ADOPTION_CATALOG_V1.md",
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

#[test]
fn readme_surface_is_pinned_by_machine_contract() {
    let contract = parse_contract();
    let readme = read_to_string("README.md");

    assert_eq!(
        contract.required_readme_fragments,
        vec![
            "## Scientific Contribution Targets Gate",
            "./scripts/run_scientific_contribution_targets.sh bundle",
            "./scripts/run_scientific_contribution_targets.sh ci",
            "./scripts/e2e/scientific_contribution_targets_replay.sh show",
            "bd-2501.1",
            "bd-2501.2",
            "bd-2501.3",
            "docs/SCIENTIFIC_REPORT_CATALOG_V1.md",
            "docs/EXTERNAL_REPLICATION_CATALOG_V1.md",
            "docs/OPEN_TOOL_ADOPTION_CATALOG_V1.md",
            "technical_report_status_report.json",
            "external_replication_status_report.json",
            "open_tool_adoption_status_report.json",
            "artifacts/scientific_contribution_targets/<timestamp>/trace_ids.json",
            "target_rch_scientific_contribution_targets_verify",
        ]
    );

    for fragment in &contract.required_readme_fragments {
        assert!(
            readme.contains(fragment),
            "README scientific contribution surface missing required fragment: {fragment}"
        );
    }
}
