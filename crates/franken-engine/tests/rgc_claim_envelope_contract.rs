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

// --- New enrichment tests below ---

#[test]
fn tier_serde_roundtrip_frontier_objective() {
    let tier = ClaimEnvelopeTier::FrontierObjective;
    let json = serde_json::to_string(&tier).unwrap();
    assert_eq!(json, "\"frontier_objective\"");
    let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tier);
}

#[test]
fn tier_serde_roundtrip_publishable_universal() {
    let tier = ClaimEnvelopeTier::PublishableUniversal;
    let json = serde_json::to_string(&tier).unwrap();
    assert_eq!(json, "\"publishable_universal\"");
    let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tier);
}

#[test]
fn tier_serde_roundtrip_publishable_scoped() {
    let tier = ClaimEnvelopeTier::PublishableScoped;
    let json = serde_json::to_string(&tier).unwrap();
    assert_eq!(json, "\"publishable_scoped\"");
    let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tier);
}

#[test]
fn tier_serde_roundtrip_target() {
    let tier = ClaimEnvelopeTier::Target;
    let json = serde_json::to_string(&tier).unwrap();
    assert_eq!(json, "\"target\"");
    let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tier);
}

#[test]
fn tier_serde_roundtrip_hypothesis() {
    let tier = ClaimEnvelopeTier::Hypothesis;
    let json = serde_json::to_string(&tier).unwrap();
    assert_eq!(json, "\"hypothesis\"");
    let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tier);
}

#[test]
fn verdict_serde_roundtrip_allow_requested() {
    let v = ClaimEnvelopeVerdict::AllowRequested;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"allow_requested\"");
    let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn verdict_serde_roundtrip_downgrade_to_scoped() {
    let v = ClaimEnvelopeVerdict::DowngradeToScoped;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"downgrade_to_scoped\"");
    let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn verdict_serde_roundtrip_downgrade_to_target() {
    let v = ClaimEnvelopeVerdict::DowngradeToTarget;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"downgrade_to_target\"");
    let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn verdict_serde_roundtrip_downgrade_to_hypothesis() {
    let v = ClaimEnvelopeVerdict::DowngradeToHypothesis;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"downgrade_to_hypothesis\"");
    let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn verdict_serde_roundtrip_forbid() {
    let v = ClaimEnvelopeVerdict::Forbid;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"forbid\"");
    let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn contract_validate_succeeds_on_embedded() {
    let contract = load_contract();
    contract
        .validate()
        .expect("embedded contract must validate without errors");
}

#[test]
fn contract_claim_classes_count_is_five() {
    let contract = load_contract();
    assert_eq!(
        contract.claim_classes.len(),
        5,
        "expected exactly 5 claim classes"
    );
}

#[test]
fn contract_consumer_channels_count_at_least_four() {
    let contract = load_contract();
    assert!(
        contract.consumer_channels.len() >= 4,
        "expected at least 4 consumer channels, got {}",
        contract.consumer_channels.len()
    );
}

#[test]
fn contract_downgrade_rules_are_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.downgrade_rules.is_empty(),
        "downgrade_rules must not be empty"
    );
}

#[test]
fn contract_inputs_are_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.contract_inputs.is_empty(),
        "contract_inputs must not be empty"
    );
}

#[test]
fn all_claim_classes_have_non_empty_class_id() {
    let contract = load_contract();
    for class in &contract.claim_classes {
        assert!(!class.class_id.is_empty(), "claim class has empty class_id");
    }
}

#[test]
fn all_claim_classes_have_non_empty_description() {
    let contract = load_contract();
    for class in &contract.claim_classes {
        assert!(
            !class.description.is_empty(),
            "claim class {} has empty description",
            class.class_id
        );
    }
}

#[test]
fn all_consumer_channels_have_non_empty_channel_id() {
    let contract = load_contract();
    for channel in &contract.consumer_channels {
        assert!(
            !channel.channel_id.is_empty(),
            "consumer channel has empty channel_id"
        );
    }
}

#[test]
fn board_linkage_frontier_gap_bead_is_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.board_linkage.frontier_gap_bead.is_empty(),
        "frontier_gap_bead must not be empty"
    );
}

#[test]
fn max_publishable_staleness_hours_is_168() {
    assert_eq!(
        claim_envelope_contract::MAX_PUBLISHABLE_STALENESS_HOURS,
        168,
        "MAX_PUBLISHABLE_STALENESS_HOURS must be 168 (one week)"
    );
}

#[test]
fn scenario_fields_comprehensive_check() {
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "test_scenario".to_string(),
        requested_class: ClaimEnvelopeTier::Target,
        phrase_text: "This is a target claim.".to_string(),
        declared_scope_complete: true,
        declared_board_complete: false,
        evidence_complete: true,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 42,
        replay_command: "replay --test".to_string(),
    };
    assert_eq!(scenario.scenario_id, "test_scenario");
    assert_eq!(scenario.requested_class, ClaimEnvelopeTier::Target);
    assert_eq!(scenario.phrase_text, "This is a target claim.");
    assert!(scenario.declared_scope_complete);
    assert!(!scenario.declared_board_complete);
    assert!(scenario.evidence_complete);
    assert!(!scenario.shipped_path);
    assert!(scenario.frontier_gap_open);
    assert_eq!(scenario.stale_contract_hours, 42);
    assert_eq!(scenario.replay_command, "replay --test");
}

#[test]
fn contract_serde_roundtrip() {
    let contract = load_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: ClaimEnvelopeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, contract);
}

#[test]
fn fixture_has_non_empty_publication_scenarios() {
    let fixture = load_fixture();
    assert!(
        !fixture.publication_scenarios.is_empty(),
        "publication_scenarios must not be empty"
    );
}

#[test]
fn all_fixture_scenarios_have_non_empty_scenario_id() {
    let fixture = load_fixture();
    for scenario in &fixture.publication_scenarios {
        assert!(
            !scenario.scenario_id.is_empty(),
            "fixture scenario has empty scenario_id"
        );
    }
}

#[test]
fn all_downgrade_rules_have_non_empty_rule_id_and_rationale() {
    let contract = load_contract();
    for rule in &contract.downgrade_rules {
        assert!(!rule.rule_id.is_empty(), "downgrade rule has empty rule_id");
        assert!(
            !rule.rationale.is_empty(),
            "downgrade rule {} has empty rationale",
            rule.rule_id
        );
    }
}

#[test]
fn evaluate_target_tier_always_allows() {
    let contract = load_contract();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "synth_target".to_string(),
        requested_class: ClaimEnvelopeTier::Target,
        phrase_text: "This is a target claim for the next milestone.".to_string(),
        declared_scope_complete: false,
        declared_board_complete: false,
        evidence_complete: false,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 999,
        replay_command: String::new(),
    };
    let verdict = contract.evaluate(&scenario);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_hypothesis_tier_always_allows() {
    let contract = load_contract();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "synth_hypothesis".to_string(),
        requested_class: ClaimEnvelopeTier::Hypothesis,
        phrase_text: "This is a hypothesis about future performance.".to_string(),
        declared_scope_complete: false,
        declared_board_complete: false,
        evidence_complete: false,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 999,
        replay_command: String::new(),
    };
    let verdict = contract.evaluate(&scenario);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn contract_required_structured_log_fields_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.required_structured_log_fields.is_empty(),
        "required_structured_log_fields must not be empty"
    );
}

#[test]
fn contract_operator_verification_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
}

#[test]
fn all_consumer_channels_have_non_empty_allowed_classes() {
    let contract = load_contract();
    for channel in &contract.consumer_channels {
        assert!(
            !channel.allowed_classes.is_empty(),
            "consumer channel {} has empty allowed_classes",
            channel.channel_id
        );
    }
}

#[test]
fn universal_with_frontier_gap_downgrades_to_scoped() {
    let contract = load_contract();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "synth_gap_open".to_string(),
        requested_class: ClaimEnvelopeTier::PublishableUniversal,
        phrase_text: "FrankenEngine beats V8 across the declared shipped board.".to_string(),
        declared_scope_complete: true,
        declared_board_complete: true,
        evidence_complete: true,
        shipped_path: true,
        frontier_gap_open: true,
        stale_contract_hours: 10,
        replay_command: String::new(),
    };
    let verdict = contract.evaluate(&scenario);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToScoped);
}

#[test]
fn scoped_stale_contract_downgrades_to_hypothesis() {
    let contract = load_contract();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "synth_scoped_stale".to_string(),
        requested_class: ClaimEnvelopeTier::PublishableScoped,
        phrase_text: "Observed gains on the declared board.".to_string(),
        declared_scope_complete: true,
        declared_board_complete: false,
        evidence_complete: true,
        shipped_path: true,
        frontier_gap_open: false,
        stale_contract_hours: 200,
        replay_command: String::new(),
    };
    let verdict = contract.evaluate(&scenario);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

#[test]
fn board_linkage_declared_board_dimensions_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.board_linkage.declared_board_dimensions.is_empty(),
        "declared_board_dimensions must not be empty"
    );
}

#[test]
fn board_linkage_declared_board_families_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.board_linkage.declared_board_families.is_empty(),
        "declared_board_families must not be empty"
    );
}

#[test]
fn contract_required_artifacts_non_empty() {
    let contract = load_contract();
    assert!(
        !contract.required_artifacts.is_empty(),
        "required_artifacts must not be empty"
    );
}

#[test]
fn claim_class_ids_are_unique() {
    let contract = load_contract();
    let mut seen = BTreeSet::new();
    for class in &contract.claim_classes {
        assert!(
            seen.insert(class.class_id.as_str()),
            "duplicate claim class id: {}",
            class.class_id
        );
    }
}
