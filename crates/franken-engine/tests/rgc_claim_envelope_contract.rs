#![forbid(unsafe_code)]

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde::Deserialize;

#[path = "../src/claim_envelope_contract.rs"]
mod claim_envelope_contract;

use claim_envelope_contract::{
    CLAIM_ENVELOPE_CONTRACT_COMPONENT, CLAIM_ENVELOPE_CONTRACT_POLICY_ID,
    CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION, ClaimEnvelopeContract, ClaimEnvelopeScenario,
    ClaimEnvelopeTier, ClaimEnvelopeVerdict,
};

#[derive(Debug, Deserialize)]
struct ContractFixture {
    schema_version: String,
    required_artifacts: Vec<String>,
    required_consumers: Vec<String>,
    claim_envelope_contract: ClaimEnvelopeContract,
    publication_scenarios: Vec<PublicationScenarioFixture>,
}

#[derive(Debug, Deserialize)]
struct PublicationScenarioFixture {
    scenario_id: String,
    requested_class: ClaimEnvelopeTier,
    phrase_text: String,
    declared_scope_complete: bool,
    declared_board_complete: bool,
    evidence_complete: bool,
    shipped_path: bool,
    frontier_gap_open: bool,
    stale_contract_hours: u64,
    replay_command: String,
    expected_verdict: ClaimEnvelopeVerdict,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_contract() -> ClaimEnvelopeContract {
    ClaimEnvelopeContract::from_embedded_json()
}

fn load_fixture() -> ContractFixture {
    let path = repo_root()
        .join("crates/franken-engine/tests/fixtures/rgc_claim_envelope_contract_v1.json");
    let bytes =
        fs::read(&path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn find_scenario<'a>(
    fixture: &'a ContractFixture,
    scenario_id: &str,
) -> &'a PublicationScenarioFixture {
    fixture
        .publication_scenarios
        .iter()
        .find(|scenario| scenario.scenario_id == scenario_id)
        .unwrap_or_else(|| panic!("missing scenario {scenario_id}"))
}

fn as_runtime_scenario(fixture: &PublicationScenarioFixture) -> ClaimEnvelopeScenario {
    ClaimEnvelopeScenario {
        scenario_id: fixture.scenario_id.clone(),
        requested_class: fixture.requested_class,
        phrase_text: fixture.phrase_text.clone(),
        declared_scope_complete: fixture.declared_scope_complete,
        declared_board_complete: fixture.declared_board_complete,
        evidence_complete: fixture.evidence_complete,
        shipped_path: fixture.shipped_path,
        frontier_gap_open: fixture.frontier_gap_open,
        stale_contract_hours: fixture.stale_contract_hours,
        replay_command: fixture.replay_command.clone(),
    }
}

fn assert_publication_scenario(
    contract: &ClaimEnvelopeContract,
    fixture: &ContractFixture,
    id: &str,
) {
    let scenario = find_scenario(fixture, id);
    let verdict = contract.evaluate(&as_runtime_scenario(scenario));
    assert_eq!(
        verdict, scenario.expected_verdict,
        "unexpected verdict for scenario {}",
        scenario.scenario_id
    );
}

#[test]
fn rgc_016c_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_CLAIM_ENVELOPE_CONTRACT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# RGC Claim Envelope Contract (`bd-1lsy.1.6.3`)",
        "## Contract Version",
        "## Purpose",
        "## Claim Classes",
        "## Contract Inputs",
        "## Declared Board Linkage",
        "## Downgrade Ladder",
        "## Consumer Channels",
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
fn rgc_016c_contract_parses_matches_fixture_and_validates() {
    let contract = load_contract();
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.rgc-claim-envelope-contract-fixture.v1"
    );
    assert_eq!(contract, fixture.claim_envelope_contract);
    assert_eq!(
        contract.schema_version,
        CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION
    );
    assert_eq!(contract.track.id, "RGC-016C");
    assert_eq!(contract.track.name, "Claim Envelope Contract");
    assert_eq!(contract.bead_id, "bd-1lsy.1.6.3");
    assert_eq!(contract.generated_by, "bd-1lsy.1.6.3");
    assert!(contract.generated_at_utc.ends_with('Z'));

    contract
        .validate()
        .unwrap_or_else(|errors| panic!("contract validation failed: {errors:#?}"));
}

#[test]
fn rgc_016c_contract_inputs_and_board_linkage_are_stable() {
    let contract = load_contract();
    let input_beads = contract
        .contract_inputs
        .iter()
        .map(|input| input.bead_id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(input_beads.contains("bd-1lsy.1.6.1"));
    assert!(input_beads.contains("bd-1lsy.1.6.2"));

    assert_eq!(
        contract.board_linkage.react_contract_json,
        "docs/rgc_react_capability_contract_v1.json"
    );
    assert_eq!(
        contract.board_linkage.supremacy_contract_json,
        "crates/franken-engine/tests/fixtures/rgc_v8_supremacy_claim_contract_v1.json"
    );
    assert_eq!(contract.board_linkage.frontier_gap_bead, "bd-1lsy.1.6.4");

    let families = contract
        .board_linkage
        .declared_board_families
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for family in [
        "parse_compile",
        "react_compile",
        "react_ssr",
        "react_client",
        "macro_workloads",
        "tail_latency",
        "memory",
    ] {
        assert!(families.contains(family), "missing board family {family}");
    }
}

#[test]
fn rgc_016c_claim_classes_and_consumers_cover_required_surfaces() {
    let fixture = load_fixture();
    let contract = &fixture.claim_envelope_contract;

    let required_artifacts = fixture
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for artifact in [
        "claim_envelope_contract.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
    ] {
        assert!(
            required_artifacts.contains(artifact),
            "missing required artifact {artifact}"
        );
    }

    let classes = contract
        .claim_classes
        .iter()
        .map(|class| class.class_id.as_str())
        .collect::<BTreeSet<_>>();
    for class in [
        "frontier_objective",
        "publishable_universal",
        "publishable_scoped",
        "target",
        "hypothesis",
    ] {
        assert!(classes.contains(class), "missing claim class {class}");
    }

    let consumers = contract
        .consumer_channels
        .iter()
        .map(|channel| channel.channel_id.as_str())
        .collect::<BTreeSet<_>>();
    for consumer in [
        "docs_channel",
        "advisories_channel",
        "rollout_channel",
        "ga_channel",
    ] {
        assert!(
            consumers.contains(consumer),
            "missing consumer channel {consumer}"
        );
    }

    let required_consumers = fixture
        .required_consumers
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for consumer in ["docs", "advisories", "rollout", "ga"] {
        assert!(
            required_consumers.contains(consumer),
            "missing required consumer {consumer}"
        );
    }
}

#[test]
fn publication_scenario_frontier_objective_allowed() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(&contract, &fixture, "frontier_objective_allowed");
}

#[test]
fn publication_scenario_publishable_universal_allowed() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(&contract, &fixture, "publishable_universal_allowed");
}

#[test]
fn publication_scenario_universal_downgrades_to_scoped() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(&contract, &fixture, "universal_downgrades_to_scoped");
}

#[test]
fn publication_scenario_scoped_downgrades_to_target_when_evidence_missing() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(
        &contract,
        &fixture,
        "scoped_downgrades_to_target_when_evidence_missing",
    );
}

#[test]
fn publication_scenario_scoped_phrase_without_qualifier_is_forbidden() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(
        &contract,
        &fixture,
        "scoped_phrase_without_qualifier_is_forbidden",
    );
}

#[test]
fn publication_scenario_stale_publishable_downgrades_to_hypothesis() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(
        &contract,
        &fixture,
        "stale_publishable_downgrades_to_hypothesis",
    );
}

#[test]
fn publication_scenario_frontier_phrase_without_qualifier_is_forbidden() {
    let contract = load_contract();
    let fixture = load_fixture();
    assert_publication_scenario(
        &contract,
        &fixture,
        "frontier_phrase_without_qualifier_is_forbidden",
    );
}

#[test]
fn rgc_016c_operator_verification_references_gate_and_replay() {
    let contract = load_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command == "jq empty docs/rgc_claim_envelope_contract_v1.json")
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command == "./scripts/run_rgc_claim_envelope_contract.sh ci")
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command == "./scripts/e2e/rgc_claim_envelope_contract_replay.sh ci")
    );
}

#[test]
fn rgc_016c_gate_script_is_rch_backed_and_materializes_expected_artifacts() {
    let path = repo_root().join("scripts/run_rgc_claim_envelope_contract.sh");
    let script = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for required_fragment in [
        "rch exec -- env",
        "setsid rch exec -- env",
        "kill -TERM -- \"-$rch_pid\"",
        "cargo check -p frankenengine-engine --test rgc_claim_envelope_contract",
        "cargo test -p frankenengine-engine --test rgc_claim_envelope_contract",
        "cargo clippy -p frankenengine-engine --test rgc_claim_envelope_contract -- -D warnings",
        "claim_envelope_contract.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
    ] {
        assert!(
            script.contains(required_fragment),
            "script missing fragment `{required_fragment}`"
        );
    }
}

#[test]
fn rgc_016c_component_and_policy_ids_are_stable() {
    assert_eq!(
        CLAIM_ENVELOPE_CONTRACT_COMPONENT,
        "rgc_claim_envelope_contract"
    );
    assert_eq!(
        CLAIM_ENVELOPE_CONTRACT_POLICY_ID,
        "policy-rgc-claim-envelope-contract-v1"
    );
}
