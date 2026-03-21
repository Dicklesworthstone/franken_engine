//! Deep integration tests for claim_envelope_contract module.
//!
//! Covers: embedded contract loading, validation exhaustive paths, scenario
//! evaluation verdicts, tier serde roundtrips, and verdict classification.

use frankenengine_engine::claim_envelope_contract::{
    CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION, ClaimEnvelopeContract, ClaimEnvelopeScenario,
    ClaimEnvelopeTier, ClaimEnvelopeVerdict, MAX_PUBLISHABLE_STALENESS_HOURS,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_schema_version_nonempty() {
    assert!(!CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn deep_max_staleness_sane() {
    assert!(MAX_PUBLISHABLE_STALENESS_HOURS > 0);
    assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168); // 7 days
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeTier serde
// ---------------------------------------------------------------------------

#[test]
fn deep_tier_serde_roundtrip() {
    let tiers = [
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ];
    for tier in tiers {
        let json = serde_json::to_string(&tier).unwrap();
        let decoded: ClaimEnvelopeTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, decoded);
    }
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeVerdict serde
// ---------------------------------------------------------------------------

#[test]
fn deep_verdict_serde_roundtrip() {
    let verdicts = [
        ClaimEnvelopeVerdict::AllowRequested,
        ClaimEnvelopeVerdict::DowngradeToScoped,
        ClaimEnvelopeVerdict::DowngradeToTarget,
        ClaimEnvelopeVerdict::DowngradeToHypothesis,
        ClaimEnvelopeVerdict::Forbid,
    ];
    for verdict in verdicts {
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: ClaimEnvelopeVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, decoded);
    }
}

// ---------------------------------------------------------------------------
// Embedded contract
// ---------------------------------------------------------------------------

#[test]
fn deep_embedded_contract_loads() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert_eq!(
        contract.schema_version,
        CLAIM_ENVELOPE_CONTRACT_SCHEMA_VERSION
    );
}

#[test]
fn deep_embedded_contract_validates() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(
        contract.validate().is_ok(),
        "Embedded contract must validate: {:?}",
        contract.validate().err()
    );
}

#[test]
fn deep_embedded_contract_has_claim_classes() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.claim_classes.is_empty());
}

#[test]
fn deep_embedded_contract_has_contract_inputs() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.contract_inputs.is_empty());
}

#[test]
fn deep_embedded_contract_has_consumer_channels() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.consumer_channels.is_empty());
}

#[test]
fn deep_embedded_contract_has_downgrade_rules() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.downgrade_rules.is_empty());
}

#[test]
fn deep_embedded_contract_serde_roundtrip() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let decoded: ClaimEnvelopeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, decoded);
}

// ---------------------------------------------------------------------------
// Evaluation — FrontierObjective always allowed
// ---------------------------------------------------------------------------

#[test]
fn deep_evaluate_frontier_objective_always_allowed() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-frontier".to_string(),
        requested_class: ClaimEnvelopeTier::FrontierObjective,
        phrase_text: "Frontier objective claim".to_string(),
        declared_scope_complete: false,
        declared_board_complete: false,
        evidence_complete: false,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 1000,
        replay_command: "cargo test".to_string(),
    };
    assert_eq!(
        contract.evaluate(&scenario),
        ClaimEnvelopeVerdict::AllowRequested
    );
}

// ---------------------------------------------------------------------------
// Evaluation — Target and Hypothesis always allowed
// ---------------------------------------------------------------------------

#[test]
fn deep_evaluate_target_always_allowed() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-target".to_string(),
        requested_class: ClaimEnvelopeTier::Target,
        phrase_text: "Target: claim text".to_string(),
        declared_scope_complete: false,
        declared_board_complete: false,
        evidence_complete: false,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 0,
        replay_command: "cargo test".to_string(),
    };
    assert_eq!(
        contract.evaluate(&scenario),
        ClaimEnvelopeVerdict::AllowRequested
    );
}

#[test]
fn deep_evaluate_hypothesis_always_allowed() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-hypothesis".to_string(),
        requested_class: ClaimEnvelopeTier::Hypothesis,
        phrase_text: "Hypothesis: test claim".to_string(),
        declared_scope_complete: false,
        declared_board_complete: false,
        evidence_complete: false,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 0,
        replay_command: "cargo test".to_string(),
    };
    assert_eq!(
        contract.evaluate(&scenario),
        ClaimEnvelopeVerdict::AllowRequested
    );
}

// ---------------------------------------------------------------------------
// Evaluation — PublishableScoped scenarios
// ---------------------------------------------------------------------------

#[test]
fn deep_evaluate_publishable_scoped_all_met() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-scoped-pass".to_string(),
        requested_class: ClaimEnvelopeTier::PublishableScoped,
        phrase_text:
            "Observed and declared: FrankenEngine outperforms V8 on deterministic workloads within the supported surface"
                .to_string(),
        declared_scope_complete: true,
        declared_board_complete: true,
        evidence_complete: true,
        shipped_path: true,
        frontier_gap_open: false,
        stale_contract_hours: 0,
        replay_command: "cargo test".to_string(),
    };
    assert_eq!(
        contract.evaluate(&scenario),
        ClaimEnvelopeVerdict::AllowRequested
    );
}

#[test]
fn deep_evaluate_publishable_scoped_stale_downgrade() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-scoped-stale".to_string(),
        requested_class: ClaimEnvelopeTier::PublishableScoped,
        phrase_text:
            "Observed and declared: FrankenEngine outperforms V8 on deterministic workloads within the supported surface"
                .to_string(),
        declared_scope_complete: true,
        declared_board_complete: true,
        evidence_complete: true,
        shipped_path: true,
        frontier_gap_open: false,
        stale_contract_hours: MAX_PUBLISHABLE_STALENESS_HOURS + 1,
        replay_command: "cargo test".to_string(),
    };
    let verdict = contract.evaluate(&scenario);
    assert_eq!(verdict, ClaimEnvelopeVerdict::DowngradeToHypothesis);
}

// ---------------------------------------------------------------------------
// ClaimEnvelopeScenario serde
// ---------------------------------------------------------------------------

#[test]
fn deep_scenario_serde_roundtrip() {
    let scenario = ClaimEnvelopeScenario {
        scenario_id: "deep-serde".to_string(),
        requested_class: ClaimEnvelopeTier::PublishableUniversal,
        phrase_text: "Test phrase".to_string(),
        declared_scope_complete: true,
        declared_board_complete: false,
        evidence_complete: true,
        shipped_path: false,
        frontier_gap_open: true,
        stale_contract_hours: 24,
        replay_command: "cargo test".to_string(),
    };
    let json = serde_json::to_string(&scenario).unwrap();
    let decoded: ClaimEnvelopeScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(scenario, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: evaluation — PublishableUniversal scenarios
// ---------------------------------------------------------------------------

fn make_scenario(
    id: &str,
    tier: ClaimEnvelopeTier,
    scope: bool,
    board: bool,
    evidence: bool,
    shipped: bool,
    gap: bool,
    stale: u64,
) -> ClaimEnvelopeScenario {
    ClaimEnvelopeScenario {
        scenario_id: id.to_string(),
        requested_class: tier,
        phrase_text: match tier {
            ClaimEnvelopeTier::FrontierObjective => format!("Frontier objective {id}"),
            ClaimEnvelopeTier::PublishableUniversal => format!("Universal claim {id}"),
            ClaimEnvelopeTier::PublishableScoped => format!("Observed and declared scoped claim {id}"),
            ClaimEnvelopeTier::Target => format!("Target claim {id}"),
            ClaimEnvelopeTier::Hypothesis => format!("Hypothesis claim {id}"),
        },
        declared_scope_complete: scope,
        declared_board_complete: board,
        evidence_complete: evidence,
        shipped_path: shipped,
        frontier_gap_open: gap,
        stale_contract_hours: stale,
        replay_command: "cargo test".to_string(),
    }
}

#[test]
fn deep_evaluate_publishable_universal_all_met() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = make_scenario(
        "universal-pass",
        ClaimEnvelopeTier::PublishableUniversal,
        true,
        true,
        true,
        true,
        false,
        0,
    );
    assert_eq!(
        contract.evaluate(&scenario),
        ClaimEnvelopeVerdict::AllowRequested,
    );
}

#[test]
fn deep_evaluate_publishable_universal_missing_evidence_downgrades() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = make_scenario(
        "universal-no-evidence",
        ClaimEnvelopeTier::PublishableUniversal,
        true,
        true,
        false,
        true,
        false,
        0,
    );
    let verdict = contract.evaluate(&scenario);
    assert_ne!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn deep_evaluate_publishable_universal_frontier_gap_open_downgrades() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = make_scenario(
        "universal-gap-open",
        ClaimEnvelopeTier::PublishableUniversal,
        true,
        true,
        true,
        true,
        true,
        0,
    );
    let verdict = contract.evaluate(&scenario);
    // Open frontier gap should prevent universal publication
    assert_ne!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn deep_evaluate_publishable_scoped_incomplete_scope_downgrades() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = make_scenario(
        "scoped-incomplete",
        ClaimEnvelopeTier::PublishableScoped,
        false,
        true,
        true,
        true,
        false,
        0,
    );
    let verdict = contract.evaluate(&scenario);
    assert_ne!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

#[test]
fn deep_evaluate_publishable_scoped_not_shipped_downgrades() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    let scenario = make_scenario(
        "scoped-not-shipped",
        ClaimEnvelopeTier::PublishableScoped,
        true,
        true,
        true,
        false,
        false,
        0,
    );
    let verdict = contract.evaluate(&scenario);
    assert_ne!(verdict, ClaimEnvelopeVerdict::AllowRequested);
}

// ---------------------------------------------------------------------------
// Enrichment: contract component and policy constants
// ---------------------------------------------------------------------------

#[test]
fn deep_contract_bead_id_nonempty() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.bead_id.is_empty());
    assert!(contract.bead_id.starts_with("bd-"));
}

#[test]
fn deep_contract_has_track() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.track.id.is_empty());
}

#[test]
fn deep_contract_has_required_artifacts() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.required_artifacts.is_empty());
}

#[test]
fn deep_contract_has_operator_verification() {
    let contract = ClaimEnvelopeContract::from_embedded_json();
    assert!(!contract.operator_verification.is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: tier Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn deep_tier_debug_all_distinct() {
    let tiers = [
        ClaimEnvelopeTier::FrontierObjective,
        ClaimEnvelopeTier::PublishableUniversal,
        ClaimEnvelopeTier::PublishableScoped,
        ClaimEnvelopeTier::Target,
        ClaimEnvelopeTier::Hypothesis,
    ];
    let displays: std::collections::BTreeSet<String> =
        tiers.iter().map(|t| format!("{t:?}")).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// Enrichment: verdict Debug uniqueness
// ---------------------------------------------------------------------------

#[test]
fn deep_verdict_debug_all_distinct() {
    let verdicts = [
        ClaimEnvelopeVerdict::AllowRequested,
        ClaimEnvelopeVerdict::DowngradeToScoped,
        ClaimEnvelopeVerdict::DowngradeToTarget,
        ClaimEnvelopeVerdict::DowngradeToHypothesis,
        ClaimEnvelopeVerdict::Forbid,
    ];
    let displays: std::collections::BTreeSet<String> =
        verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(displays.len(), 5);
}
