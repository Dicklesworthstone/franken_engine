#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `claim_envelope_contract`.

use std::collections::BTreeSet;

use frankenengine_engine::claim_envelope_contract::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn embedded() -> ClaimEnvelopeContract {
    ClaimEnvelopeContract::from_embedded_json()
}

fn make_scenario(
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

fn full_ready(id: &str, tier: ClaimEnvelopeTier, phrase: &str) -> ClaimEnvelopeScenario {
    make_scenario(id, tier, phrase, true, true, true, true, false, 0)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_contains_claim_envelope() {
    assert!(CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.contains("claim-envelope"));
}

#[test]
fn schema_version_starts_with_franken_engine() {
    assert!(CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn component_name_is_nonempty() {
    assert!(!CLAIM_ENVELOPE_CONTRACT_COMPONENT.is_empty());
}

#[test]
fn policy_id_starts_with_policy() {
    assert!(CLAIM_ENVELOPE_CONTRACT_POLICY_ID.starts_with("policy-"));
}

#[test]
fn max_staleness_is_one_week() {
    assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168);
}

#[test]
fn embedded_json_is_valid() {
    assert!(!CLAIM_ENVELOPE_CONTRACT_JSON.is_empty());
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeTier serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn tier_serde_roundtrip_all_variants() {
    let tiers = [
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ];
    for tier in &tiers {
        let json = serde_json::to_string(tier).unwrap();
        let back: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*tier, back);
    }
}

#[test]
fn tier_display_distinctness() {
    let tiers = [
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ];
    let displays: BTreeSet<String> = tiers.iter().map(|t| format!("{t:?}")).collect();
    assert_eq!(displays.len(), tiers.len());
}

#[test]
fn tier_ordering() {
    assert!(ClaimEnvelopeTier::FrontierObjective < ClaimEnvelopeTier::PublishableUniversal);
    assert!(ClaimEnvelopeTier::PublishableUniversal < ClaimEnvelopeTier::PublishableScoped);
    assert!(ClaimEnvelopeTier::PublishableScoped < ClaimEnvelopeTier::Target);
    assert!(ClaimEnvelopeTier::Target < ClaimEnvelopeTier::Hypothesis);
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeVerdict serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde_roundtrip_all_variants() {
    let verdicts = [
        ClaimEnvelopeVerdict::AllowRequested,
        ClaimEnvelopeVerdict::DowngradeToScoped,
        ClaimEnvelopeVerdict::DowngradeToTarget,
        ClaimEnvelopeVerdict::DowngradeToHypothesis,
        ClaimEnvelopeVerdict::Forbid,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn verdict_display_distinctness() {
    let verdicts = [
        ClaimEnvelopeVerdict::AllowRequested,
        ClaimEnvelopeVerdict::DowngradeToScoped,
        ClaimEnvelopeVerdict::DowngradeToTarget,
        ClaimEnvelopeVerdict::DowngradeToHypothesis,
        ClaimEnvelopeVerdict::Forbid,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(displays.len(), verdicts.len());
}

// ---------------------------------------------------------------------------
// ContractTrack serde
// ---------------------------------------------------------------------------

#[test]
fn contract_track_serde_roundtrip() {
    let track = ContractTrack {
        id: "RGC-016C".to_string(),
        name: "claim envelope".to_string(),
    };
    let json = serde_json::to_string(&track).unwrap();
    let back: ContractTrack = serde_json::from_str(&json).unwrap();
    assert_eq!(track, back);
}

// ---------------------------------------------------------------------------
// ContractInput serde
// ---------------------------------------------------------------------------

#[test]
fn contract_input_serde_roundtrip() {
    let input = ContractInput {
        input_id: "input-1".to_string(),
        bead_id: "bd-1".to_string(),
        contract_doc: "doc.md".to_string(),
        contract_json: "doc.json".to_string(),
        role: "primary".to_string(),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: ContractInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ---------------------------------------------------------------------------
// ClaimClassSpec serde
// ---------------------------------------------------------------------------

#[test]
fn claim_class_spec_serde_roundtrip() {
    let spec = ClaimClassSpec {
        class_id: "frontier".to_string(),
        tier: ClaimEnvelopeTier::FrontierObjective,
        publishable: false,
        description: "frontier objective".to_string(),
        required_qualifier_terms: vec!["frontier".to_string()],
        allowed_surfaces: vec!["internal".to_string()],
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: ClaimClassSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// BoardLinkage serde
// ---------------------------------------------------------------------------

#[test]
fn board_linkage_serde_roundtrip() {
    let bl = BoardLinkage {
        supremacy_contract_doc: "s.md".to_string(),
        supremacy_contract_json: "s.json".to_string(),
        react_contract_doc: "r.md".to_string(),
        react_contract_json: "r.json".to_string(),
        declared_board_dimensions: vec!["dim1".to_string()],
        declared_board_families: vec!["fam1".to_string()],
        frontier_gap_artifact: "gaps.json".to_string(),
        frontier_gap_bead: "bd-gap".to_string(),
    };
    let json = serde_json::to_string(&bl).unwrap();
    let back: BoardLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(bl, back);
}

// ---------------------------------------------------------------------------
// DowngradeRule serde
// ---------------------------------------------------------------------------

#[test]
fn downgrade_rule_serde_roundtrip() {
    let rule = DowngradeRule {
        rule_id: "stale".to_string(),
        when_condition: "stale > 168h".to_string(),
        resulting_class: ClaimEnvelopeTier::Hypothesis,
        rationale: "stale contracts".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: DowngradeRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ---------------------------------------------------------------------------
// ConsumerChannel serde
// ---------------------------------------------------------------------------

#[test]
fn consumer_channel_serde_roundtrip() {
    let ch = ConsumerChannel {
        channel_id: "docs".to_string(),
        consumer_bead: "bd-docs".to_string(),
        allowed_classes: vec!["frontier".to_string()],
        requires_artifacts: vec!["run_manifest.json".to_string()],
        rationale: "test".to_string(),
    };
    let json = serde_json::to_string(&ch).unwrap();
    let back: ConsumerChannel = serde_json::from_str(&json).unwrap();
    assert_eq!(ch, back);
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeScenario serde
// ---------------------------------------------------------------------------

#[test]
fn scenario_serde_roundtrip() {
    let s = full_ready("s1", ClaimEnvelopeTier::Target, "a test phrase");
    let json = serde_json::to_string(&s).unwrap();
    let back: ClaimEnvelopeScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// from_embedded_json + validate
// ---------------------------------------------------------------------------

#[test]
fn embedded_contract_parses_successfully() {
    let contract = embedded();
    assert!(!contract.schema_version.is_empty());
}

#[test]
fn embedded_contract_validates() {
    let contract = embedded();
    assert!(contract.validate().is_ok());
}

#[test]
fn embedded_contract_has_all_tiers() {
    let contract = embedded();
    let tiers = [
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ];
    for tier in &tiers {
        assert!(
            contract.claim_classes.iter().any(|c| c.tier == *tier),
            "Missing tier {tier:?}"
        );
    }
}

#[test]
fn embedded_contract_serde_roundtrip() {
    let contract = embedded();
    let json = serde_json::to_string(&contract).unwrap();
    let back: ClaimEnvelopeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

// ---------------------------------------------------------------------------
// evaluate
// ---------------------------------------------------------------------------

#[test]
fn evaluate_frontier_always_allows() {
    let c = embedded();
    let s = full_ready(
        "s1",
        ClaimEnvelopeTier::FrontierObjective,
        "frontier objective universal",
    );
    assert_eq!(c.evaluate(&s), ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_target_allows_with_matching_phrase() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::Target)
        .unwrap();
    let phrase = if class.required_qualifier_terms.is_empty() {
        "any phrase here".to_string()
    } else {
        class.required_qualifier_terms.join(" ")
    };
    let s = full_ready("s2", ClaimEnvelopeTier::Target, &phrase);
    assert_eq!(c.evaluate(&s), ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_hypothesis_allows_with_matching_phrase() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::Hypothesis)
        .unwrap();
    let phrase = if class.required_qualifier_terms.is_empty() {
        "any phrase".to_string()
    } else {
        class.required_qualifier_terms.join(" ")
    };
    let s = full_ready("s3", ClaimEnvelopeTier::Hypothesis, &phrase);
    assert_eq!(c.evaluate(&s), ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_publishable_universal_all_ready() {
    let c = embedded();
    // Need to use a phrase that contains the required qualifier terms for universal tier
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = full_ready("s4", ClaimEnvelopeTier::PublishableUniversal, &phrase);
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_publishable_scoped_all_ready() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = full_ready("s5", ClaimEnvelopeTier::PublishableScoped, &phrase);
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn evaluate_publishable_universal_missing_board_downgrades_to_scoped() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = make_scenario(
        "s6",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        true,
        false,
        true,
        true,
        false,
        0,
    );
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToScoped);
}

#[test]
fn evaluate_publishable_universal_stale_contract_downgrades() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = make_scenario(
        "s7",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        false,
        false,
        false,
        false,
        false,
        200,
    );
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

#[test]
fn evaluate_publishable_scoped_not_ready_downgrades_to_target() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableScoped)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = make_scenario(
        "s8",
        ClaimEnvelopeTier::PublishableScoped,
        &phrase,
        false,
        false,
        true,
        true,
        false,
        0,
    );
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToTarget);
}

#[test]
fn evaluate_forbids_on_missing_qualifier_terms() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    if !class.required_qualifier_terms.is_empty() {
        let s = full_ready(
            "s9",
            ClaimEnvelopeTier::PublishableUniversal,
            "no matching terms here xyz",
        );
        let verdict = c.evaluate(&s);
        assert_eq!(verdict, ClaimEnvelopeVerdict::Forbid);
    }
}

#[test]
fn evaluate_publishable_universal_frontier_gap_open_downgrades() {
    let c = embedded();
    let class = c
        .claim_classes
        .iter()
        .find(|cc| cc.tier == ClaimEnvelopeTier::PublishableUniversal)
        .unwrap();
    let phrase = class.required_qualifier_terms.join(" ");
    let s = make_scenario(
        "s10",
        ClaimEnvelopeTier::PublishableUniversal,
        &phrase,
        true,
        true,
        true,
        true,
        true,
        0,
    );
    let verdict = c.evaluate(&s);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToScoped);
}

// ---------------------------------------------------------------------------
// validate: negative cases
// ---------------------------------------------------------------------------

#[test]
fn validate_bad_schema_version() {
    let mut c = embedded();
    c.schema_version = "wrong".to_string();
    assert!(c.validate().is_err());
}

#[test]
fn validate_bad_track_id() {
    let mut c = embedded();
    c.track.id = "WRONG".to_string();
    assert!(c.validate().is_err());
}

#[test]
fn validate_empty_operator_verification() {
    let mut c = embedded();
    c.operator_verification.clear();
    assert!(c.validate().is_err());
}

#[test]
fn validate_missing_artifact() {
    let mut c = embedded();
    c.required_artifacts.clear();
    assert!(c.validate().is_err());
}

#[test]
fn validate_duplicate_class_ids() {
    let mut c = embedded();
    if c.claim_classes.len() >= 2 {
        c.claim_classes[1].class_id = c.claim_classes[0].class_id.clone();
        assert!(c.validate().is_err());
    }
}

// ---------------------------------------------------------------------------
// Clone / Eq
// ---------------------------------------------------------------------------

#[test]
fn claim_envelope_contract_clone_eq() {
    let c = embedded();
    let c2 = c.clone();
    assert_eq!(c, c2);
}

#[test]
fn scenario_clone_eq() {
    let s = full_ready("s1", ClaimEnvelopeTier::Target, "phrase");
    let s2 = s.clone();
    assert_eq!(s, s2);
}
