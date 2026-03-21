#![forbid(unsafe_code)]

//! Integration tests for the claim_envelope_contract module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::claim_envelope_contract::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn scenario(
    id: &str,
    tier: ClaimEnvelopeTier,
    phrase: &str,
    scope_complete: bool,
    board_complete: bool,
    evidence_complete: bool,
    shipped: bool,
    gap_open: bool,
    stale_hours: u64,
) -> ClaimEnvelopeScenario {
    ClaimEnvelopeScenario {
        scenario_id: id.to_string(),
        requested_class: tier,
        phrase_text: phrase.to_string(),
        declared_scope_complete: scope_complete,
        declared_board_complete: board_complete,
        evidence_complete,
        shipped_path: shipped,
        frontier_gap_open: gap_open,
        stale_contract_hours: stale_hours,
        replay_command: "cargo test".to_string(),
    }
}

fn full_ready_scenario(id: &str, tier: ClaimEnvelopeTier, phrase: &str) -> ClaimEnvelopeScenario {
    scenario(id, tier, phrase, true, true, true, true, false, 0)
}

fn embedded_contract() -> ClaimEnvelopeContract {
    ClaimEnvelopeContract::from_embedded_json()
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.contains("claim-envelope"));
}

#[test]
fn component_name_nonempty() {
    assert!(!CLAIM_ENVELOPE_CONTRACT_COMPONENT.is_empty());
}

#[test]
fn policy_id_format() {
    assert!(CLAIM_ENVELOPE_CONTRACT_POLICY_ID.starts_with("policy-"));
}

#[test]
fn max_staleness_hours_positive() {
    const { assert!(MAX_PUBLISHABLE_STALENESS_HOURS > 0) };
    assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168); // 7 days
}

#[test]
fn embedded_json_nonempty() {
    assert!(!CLAIM_ENVELOPE_CONTRACT_JSON.is_empty());
    assert!(CLAIM_ENVELOPE_CONTRACT_JSON.contains("schema_version"));
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeTier
// ---------------------------------------------------------------------------

#[test]
fn claim_envelope_tier_serde_all_variants() {
    for tier in &[
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ] {
        let json = serde_json::to_string(tier).unwrap();
        let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
    }
}

#[test]
fn claim_envelope_tier_ord() {
    assert!(ClaimEnvelopeTier::FrontierObjective < ClaimEnvelopeTier::Hypothesis);
    assert!(ClaimEnvelopeTier::PublishableUniversal < ClaimEnvelopeTier::Target);
}

#[test]
fn claim_envelope_tier_snake_case_serde() {
    let json = serde_json::to_string(&ClaimEnvelopeTier::PublishableUniversal).unwrap();
    assert_eq!(json, "\"publishable_universal\"");
    let json = serde_json::to_string(&ClaimEnvelopeTier::FrontierObjective).unwrap();
    assert_eq!(json, "\"frontier_objective\"");
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeVerdict
// ---------------------------------------------------------------------------

#[test]
fn claim_envelope_verdict_serde_all_variants() {
    for verdict in &[
        ClaimEnvelopeVerdict::AllowRequested,
        ClaimEnvelopeVerdict::DowngradeToScoped,
        ClaimEnvelopeVerdict::DowngradeToTarget,
        ClaimEnvelopeVerdict::DowngradeToHypothesis,
        ClaimEnvelopeVerdict::Forbid,
    ] {
        let json = serde_json::to_string(verdict).unwrap();
        let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, back);
    }
}

#[test]
fn claim_envelope_verdict_snake_case_serde() {
    let json = serde_json::to_string(&ClaimEnvelopeVerdict::AllowRequested).unwrap();
    assert_eq!(json, "\"allow_requested\"");
    let json = serde_json::to_string(&ClaimEnvelopeVerdict::DowngradeToHypothesis).unwrap();
    assert_eq!(json, "\"downgrade_to_hypothesis\"");
}

// ---------------------------------------------------------------------------
// Embedded contract
// ---------------------------------------------------------------------------

#[test]
fn embedded_contract_parses() {
    let contract = embedded_contract();
    assert_eq!(
        contract.schema_version,
        CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION
    );
}

#[test]
fn embedded_contract_validates() {
    let contract = embedded_contract();
    let result = contract.validate();
    assert!(result.is_ok(), "validation failed: {:?}", result.err());
}

#[test]
fn embedded_contract_has_claim_classes() {
    let contract = embedded_contract();
    assert!(!contract.claim_classes.is_empty());
}

#[test]
fn embedded_contract_has_all_tiers() {
    let contract = embedded_contract();
    for tier in &[
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ] {
        assert!(
            contract.claim_classes.iter().any(|c| c.tier == *tier),
            "missing class for tier {:?}",
            tier
        );
    }
}

#[test]
fn embedded_contract_has_contract_inputs() {
    let contract = embedded_contract();
    assert!(!contract.contract_inputs.is_empty());
}

#[test]
fn embedded_contract_has_downgrade_rules() {
    let contract = embedded_contract();
    assert!(!contract.downgrade_rules.is_empty());
}

#[test]
fn embedded_contract_has_consumer_channels() {
    let contract = embedded_contract();
    assert!(!contract.consumer_channels.is_empty());
}

#[test]
fn embedded_contract_has_operator_verification() {
    let contract = embedded_contract();
    assert!(!contract.operator_verification.is_empty());
}

#[test]
fn embedded_contract_has_required_artifacts() {
    let contract = embedded_contract();
    assert!(
        contract
            .required_artifacts
            .contains(&"claim_envelope_contract.json".to_string())
    );
    assert!(
        contract
            .required_artifacts
            .contains(&"run_manifest.json".to_string())
    );
    assert!(
        contract
            .required_artifacts
            .contains(&"events.jsonl".to_string())
    );
}

#[test]
fn embedded_contract_has_required_log_fields() {
    let contract = embedded_contract();
    for field in &[
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "verdict",
    ] {
        assert!(
            contract
                .required_structured_log_fields
                .contains(&field.to_string()),
            "missing log field: {}",
            field
        );
    }
}

#[test]
fn embedded_contract_board_linkage() {
    let contract = embedded_contract();
    assert!(!contract.board_linkage.supremacy_contract_doc.is_empty());
    assert!(!contract.board_linkage.react_contract_doc.is_empty());
    assert!(!contract.board_linkage.declared_board_families.is_empty());
    assert!(!contract.board_linkage.declared_board_dimensions.is_empty());
}

// ---------------------------------------------------------------------------
// Contract serde
// ---------------------------------------------------------------------------

#[test]
fn contract_serde_round_trip() {
    let contract = embedded_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: ClaimEnvelopeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

#[test]
fn contract_json_structure() {
    let contract = embedded_contract();
    let v: serde_json::Value = serde_json::to_value(&contract).unwrap();
    assert!(v["schema_version"].is_string());
    assert!(v["contract_version"].is_string());
    assert!(v["claim_classes"].is_array());
    assert!(v["downgrade_rules"].is_array());
    assert!(v["consumer_channels"].is_array());
}

// ---------------------------------------------------------------------------
// Scenario serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_serde_round_trip() {
    let s = full_ready_scenario(
        "test-1",
        ClaimEnvelopeTier::PublishableUniversal,
        "test phrase",
    );
    let json = serde_json::to_string(&s).unwrap();
    let back: ClaimEnvelopeScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn scenario_json_structure() {
    let s = scenario(
        "test-2",
        ClaimEnvelopeTier::Target,
        "some phrase",
        true,
        false,
        true,
        true,
        false,
        24,
    );
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    assert_eq!(v["scenario_id"], "test-2");
    assert_eq!(v["requested_class"], "target");
    assert_eq!(v["stale_contract_hours"], 24);
}

// ---------------------------------------------------------------------------
// Evaluation — FrontierObjective
// ---------------------------------------------------------------------------

#[test]
fn frontier_objective_always_allowed() {
    let contract = embedded_contract();
    let s = scenario(
        "frontier-1",
        ClaimEnvelopeTier::FrontierObjective,
        "frontier objective",
        false,
        false,
        false,
        false,
        true,
        9999,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

// ---------------------------------------------------------------------------
// Evaluation — PublishableUniversal
// ---------------------------------------------------------------------------

#[test]
fn publishable_universal_allowed_when_all_ready() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = full_ready_scenario(
        "pub-uni-1",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn publishable_universal_downgrade_to_scoped_when_board_incomplete() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-uni-2",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        true,
        false, // board not complete
        true,
        true,
        false,
        0,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToScoped);
}

#[test]
fn publishable_universal_downgrade_to_scoped_when_gap_open() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-uni-3",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        true,
        true,
        true,
        true,
        true, // gap open
        0,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToScoped);
}

#[test]
fn publishable_universal_downgrade_to_target_when_evidence_missing() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-uni-4",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        true,
        true,
        false, // evidence not complete
        true,
        false,
        0,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToTarget);
}

#[test]
fn publishable_universal_downgrade_to_hypothesis_when_stale() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-uni-5",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        false,
        false,
        false,
        false,
        false,
        MAX_PUBLISHABLE_STALENESS_HOURS + 1, // stale
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

// ---------------------------------------------------------------------------
// Evaluation — PublishableScoped
// ---------------------------------------------------------------------------

#[test]
fn publishable_scoped_allowed_when_ready() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let scoped = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = scoped.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-scoped-1",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        true,
        false, // board doesn't matter for scoped
        true,
        true,
        false,
        0,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn publishable_scoped_downgrade_to_target_when_not_shipped() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let scoped = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = scoped.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-scoped-2",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        true,
        true,
        true,
        false, // not shipped
        false,
        0,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToTarget);
}

#[test]
fn publishable_scoped_downgrade_to_hypothesis_when_stale() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let scoped = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = scoped.required_qualifier_terms.join(" ");
    let s = scenario(
        "pub-scoped-3",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        false,
        false,
        false,
        false,
        false,
        MAX_PUBLISHABLE_STALENESS_HOURS + 1,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

// ---------------------------------------------------------------------------
// Evaluation — Target and Hypothesis
// ---------------------------------------------------------------------------

#[test]
fn target_always_allowed() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let target = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::Target)
        .unwrap();
    let phrase = target.required_qualifier_terms.join(" ");
    let s = scenario(
        "target-1",
        ClaimEnvelopeTier::Target,
        &phrase,
        false,
        false,
        false,
        false,
        true,
        9999,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn hypothesis_always_allowed() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let hypothesis = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::Hypothesis)
        .unwrap();
    let phrase = hypothesis.required_qualifier_terms.join(" ");
    let s = scenario(
        "hypo-1",
        ClaimEnvelopeTier::Hypothesis,
        &phrase,
        false,
        false,
        false,
        false,
        true,
        9999,
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

// ---------------------------------------------------------------------------
// Evaluation — phrase filtering
// ---------------------------------------------------------------------------

#[test]
fn wrong_phrase_forbids_request() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    // Only test if there are required qualifier terms
    if !universal.required_qualifier_terms.is_empty() {
        let s = full_ready_scenario(
            "phrase-1",
            ClaimEnvelopeTier::PublishableUniversal,
            "completely_wrong_phrase_xyz",
        );
        let verdict = contract.evaluate(&s);
        assert_eq!(verdict, ClaimEnvelopeVerdict::Forbid);
    }
}

// ---------------------------------------------------------------------------
// Evaluation — staleness boundary
// ---------------------------------------------------------------------------

#[test]
fn staleness_at_boundary_is_fresh() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let scoped = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = scoped.required_qualifier_terms.join(" ");
    let s = scenario(
        "stale-boundary-1",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        true,
        true,
        true,
        true,
        false,
        MAX_PUBLISHABLE_STALENESS_HOURS, // exactly at boundary
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn staleness_one_over_boundary_is_stale() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let scoped = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = scoped.required_qualifier_terms.join(" ");
    let s = scenario(
        "stale-boundary-2",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        true,
        true,
        true,
        true,
        false,
        MAX_PUBLISHABLE_STALENESS_HOURS + 1, // one over
    );
    let verdict = contract.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

// ---------------------------------------------------------------------------
// Evaluation determinism
// ---------------------------------------------------------------------------

#[test]
fn evaluation_deterministic() {
    let contract = embedded_contract();
    let classes = &contract.claim_classes;
    let universal = classes
        .iter()
        .find(|c| c.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = universal.required_qualifier_terms.join(" ");
    let s = full_ready_scenario("det-1", ClaimEnvelopeTier::PublishableUniversal, &phrase);
    let v1 = contract.evaluate(&s);
    let v2 = contract.evaluate(&s);
    assert_eq!(v1, v2);
}

// ---------------------------------------------------------------------------
// Struct serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn contract_track_serde() {
    let track = ContractTrack {
        id: "RGC-016C".to_string(),
        name: "test track".to_string(),
    };
    let json = serde_json::to_string(&track).unwrap();
    let back: ContractTrack = serde_json::from_str(&json).unwrap();
    assert_eq!(track, back);
}

#[test]
fn contract_input_serde() {
    let input = ContractInput {
        input_id: "input-1".to_string(),
        bead_id: "bd-test".to_string(),
        contract_doc: "doc.md".to_string(),
        contract_json: "contract.json".to_string(),
        contract_policy_id: Some("policy-test-001".to_string()),
        role: "source".to_string(),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: ContractInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

#[test]
fn claim_class_spec_serde() {
    let spec = ClaimClassSpec {
        class_id: "class-1".to_string(),
        tier: ClaimEnvelopeTier::PublishableScoped,
        publishable: true,
        description: "test class".to_string(),
        required_qualifier_terms: vec!["shipped".to_string()],
        allowed_surfaces: vec!["docs".to_string()],
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: ClaimClassSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

#[test]
fn board_linkage_serde() {
    let linkage = BoardLinkage {
        supremacy_contract_doc: "sup.md".to_string(),
        supremacy_contract_json: "sup.json".to_string(),
        react_contract_doc: "react.md".to_string(),
        react_contract_json: "react.json".to_string(),
        react_contract_policy_id: "react-policy-001".to_string(),
        declared_board_dimensions: vec!["workload_cell".to_string()],
        declared_board_families: vec!["parse_compile".to_string()],
        frontier_gap_artifact: "gap.json".to_string(),
        frontier_gap_bead: "bd-gap".to_string(),
    };
    let json = serde_json::to_string(&linkage).unwrap();
    let back: BoardLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(linkage, back);
}

#[test]
fn downgrade_rule_serde() {
    let rule = DowngradeRule {
        rule_id: "rule-1".to_string(),
        when_condition: "stale > 168h".to_string(),
        resulting_class: ClaimEnvelopeTier::Hypothesis,
        rationale: "evidence too old".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: DowngradeRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn consumer_channel_serde() {
    let channel = ConsumerChannel {
        channel_id: "channel-1".to_string(),
        consumer_bead: "bd-consumer".to_string(),
        allowed_classes: vec!["class-1".to_string()],
        requires_artifacts: vec!["run_manifest.json".to_string()],
        rationale: "needs evidence".to_string(),
    };
    let json = serde_json::to_string(&channel).unwrap();
    let back: ConsumerChannel = serde_json::from_str(&json).unwrap();
    assert_eq!(channel, back);
}

// ---------------------------------------------------------------------------
// Validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn validation_serde_errors_on_wrong_schema() {
    let mut contract = embedded_contract();
    contract.schema_version = "wrong-schema".to_string();
    let result = contract.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("schema_version")));
}

#[test]
fn validation_errors_on_wrong_track() {
    let mut contract = embedded_contract();
    contract.track.id = "WRONG-TRACK".to_string();
    let result = contract.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("track id")));
}

#[test]
fn validation_errors_on_empty_inputs() {
    let mut contract = embedded_contract();
    contract.contract_inputs.clear();
    let result = contract.validate();
    assert!(result.is_err());
}

#[test]
fn validation_errors_on_missing_tier() {
    let mut contract = embedded_contract();
    contract
        .claim_classes
        .retain(|c| c.tier != ClaimEnvelopeTier::Hypothesis);
    let result = contract.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("Hypothesis")));
}

#[test]
fn validation_errors_on_empty_operator_verification() {
    let mut contract = embedded_contract();
    contract.operator_verification.clear();
    let result = contract.validate();
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("operator verification")));
}
