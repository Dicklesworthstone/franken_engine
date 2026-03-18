#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]
//! Enrichment integration tests for claim_atom_lattice module.
//!
//! Covers claim domains, tiers, atoms, evidence morphisms, constraint lattice,
//! disqualifier rules, and entitlement evaluation.

use std::collections::BTreeSet;

use frankenengine_engine::claim_atom_lattice::*;

// ---------------------------------------------------------------------------
// ClaimDomain
// ---------------------------------------------------------------------------

#[test]
fn claim_domain_display_all_distinct() {
    let domains = [
        ClaimDomain::Compatibility,
        ClaimDomain::ShippedSurface,
        ClaimDomain::React,
        ClaimDomain::Supremacy,
        ClaimDomain::Rollout,
        ClaimDomain::Ga,
        ClaimDomain::Docs,
        ClaimDomain::Security,
    ];
    let displays: BTreeSet<String> = domains.iter().map(|d| format!("{d}")).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn claim_domain_serde_roundtrip() {
    for domain in [
        ClaimDomain::Compatibility,
        ClaimDomain::React,
        ClaimDomain::Security,
    ] {
        let json = serde_json::to_string(&domain).unwrap();
        let restored: ClaimDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(domain, restored);
    }
}

// ---------------------------------------------------------------------------
// ClaimTier
// ---------------------------------------------------------------------------

#[test]
fn claim_tier_display_all_distinct() {
    let tiers = [
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ];
    let displays: BTreeSet<String> = tiers.iter().map(|t| format!("{t}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn claim_tier_ordering() {
    assert!(ClaimTier::ShippedFact < ClaimTier::ScopedObserved);
    assert!(ClaimTier::ScopedObserved < ClaimTier::FrontierAmbition);
    assert!(ClaimTier::FrontierAmbition < ClaimTier::UnsupportedSurface);
}

// ---------------------------------------------------------------------------
// ClaimAtom
// ---------------------------------------------------------------------------

#[test]
fn claim_atom_new() {
    let atom = ClaimAtom {
        atom_id: "claim-001".to_string(),
        domain: ClaimDomain::Compatibility,
        tier: ClaimTier::ShippedFact,
        statement: "ES2024 module resolution is deterministic".to_string(),
        surface: "parser+runtime".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: vec!["morph-claim-001".to_string()],
    };
    assert_eq!(atom.atom_id, "claim-001");
    assert_eq!(atom.domain, ClaimDomain::Compatibility);
    assert_eq!(atom.tier, ClaimTier::ShippedFact);
}

#[test]
fn claim_atom_serde_roundtrip() {
    let atom = ClaimAtom {
        atom_id: "claim-serde".to_string(),
        domain: ClaimDomain::Security,
        tier: ClaimTier::ScopedObserved,
        statement: "Sandbox escapes produce evidence receipts".to_string(),
        surface: "sandbox".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: vec!["morph-serde".to_string()],
    };
    let json = serde_json::to_string(&atom).unwrap();
    let restored: ClaimAtom = serde_json::from_str(&json).unwrap();
    assert_eq!(atom, restored);
}

// ---------------------------------------------------------------------------
// MorphismEffect
// ---------------------------------------------------------------------------

#[test]
fn morphism_effect_display_all_distinct() {
    let effects = [
        MorphismEffect::Supports,
        MorphismEffect::Constrains,
        MorphismEffect::Disqualifies,
    ];
    let displays: BTreeSet<String> = effects.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 3);
}

// ---------------------------------------------------------------------------
// EvidenceMorphism
// ---------------------------------------------------------------------------

#[test]
fn evidence_morphism_serde_roundtrip() {
    let morph = EvidenceMorphism {
        morphism_id: "morph-001".to_string(),
        evidence_kind: "test262_pass".to_string(),
        effect: MorphismEffect::Supports,
        target_atoms: vec!["claim-001".to_string()],
        required_constraints: Vec::new(),
        blocked_by_rules: Vec::new(),
        rationale: "Test morphism".to_string(),
    };
    let json = serde_json::to_string(&morph).unwrap();
    let restored: EvidenceMorphism = serde_json::from_str(&json).unwrap();
    assert_eq!(morph, restored);
}

// ---------------------------------------------------------------------------
// DisqualifierVerdict
// ---------------------------------------------------------------------------

#[test]
fn disqualifier_verdict_display_all_distinct() {
    let verdicts = [
        DisqualifierVerdict::Forbid,
        DisqualifierVerdict::DowngradeToScoped,
        DisqualifierVerdict::RequireOperatorGuidance,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 3);
}

// ---------------------------------------------------------------------------
// ClaimState
// ---------------------------------------------------------------------------

#[test]
fn claim_state_display_all_distinct() {
    let states = [
        ClaimState::Entitled,
        ClaimState::NotYetProven,
        ClaimState::BlockedByMissingEvidence,
        ClaimState::Invalidated,
    ];
    let displays: BTreeSet<String> = states.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// ConstraintLattice
// ---------------------------------------------------------------------------

#[test]
fn constraint_lattice_basic() {
    let lattice = ConstraintLattice {
        top_id: "all".to_string(),
        bottom_id: "none".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "none".to_string(),
                constraint_class: "empty".to_string(),
                description: "no constraints".to_string(),
            },
            SideConstraint {
                constraint_id: "all".to_string(),
                constraint_class: "full".to_string(),
                description: "all constraints".to_string(),
            },
        ],
        covers: vec![CoverRelation {
            lower: "none".to_string(),
            higher: "all".to_string(),
        }],
    };
    assert_eq!(lattice.constraints.len(), 2);
    assert!(!lattice.covers.is_empty());
}

#[test]
fn constraint_lattice_no_cycle() {
    let lattice = ConstraintLattice {
        top_id: "all".to_string(),
        bottom_id: "none".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "none".to_string(),
                constraint_class: "empty".to_string(),
                description: "no constraints".to_string(),
            },
            SideConstraint {
                constraint_id: "all".to_string(),
                constraint_class: "full".to_string(),
                description: "all constraints".to_string(),
            },
        ],
        covers: vec![CoverRelation {
            lower: "none".to_string(),
            higher: "all".to_string(),
        }],
    };
    assert!(!lattice.has_cycle());
}

// ---------------------------------------------------------------------------
// evaluate_claims
// ---------------------------------------------------------------------------

#[test]
fn evaluate_claims_empty_atoms() {
    let result = evaluate_claims(&[], &[], &[], &[], 1);
    assert!(result.evaluations.is_empty());
}

#[test]
fn evaluate_claims_single_atom_no_evidence() {
    let atom = ClaimAtom {
        atom_id: "claim-eval".to_string(),
        domain: ClaimDomain::Compatibility,
        tier: ClaimTier::ShippedFact,
        statement: "test".to_string(),
        surface: "test".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: vec!["morph-eval".to_string()],
    };
    let result = evaluate_claims(&[atom], &[], &[], &[], 1);
    assert_eq!(result.evaluations.len(), 1);
    // No evidence -> should be BlockedByMissingEvidence or NotYetProven
    let eval = &result.evaluations[0];
    assert!(
        eval.state == ClaimState::BlockedByMissingEvidence
            || eval.state == ClaimState::NotYetProven,
        "no evidence should not be Entitled: {:?}",
        eval.state
    );
}

#[test]
fn evaluate_claims_with_supporting_evidence() {
    let atom = ClaimAtom {
        atom_id: "claim-sup".to_string(),
        domain: ClaimDomain::Compatibility,
        tier: ClaimTier::ShippedFact,
        statement: "test".to_string(),
        surface: "test".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: vec!["morph-sup".to_string()],
    };
    let morph = EvidenceMorphism {
        morphism_id: "morph-sup".to_string(),
        evidence_kind: "test262_pass".to_string(),
        effect: MorphismEffect::Supports,
        target_atoms: vec!["claim-sup".to_string()],
        required_constraints: Vec::new(),
        blocked_by_rules: Vec::new(),
        rationale: "Supporting evidence".to_string(),
    };
    let snapshot = EvidenceSnapshot {
        evidence_kind: "test262_pass".to_string(),
        is_fresh: true,
        triggered_rules: Vec::new(),
    };
    let result = evaluate_claims(&[atom], &[morph], &[], &[snapshot], 1);
    assert_eq!(result.evaluations.len(), 1);
    // With supporting evidence -> should be Entitled
    let eval = &result.evaluations[0];
    assert!(
        eval.state == ClaimState::Entitled || eval.state == ClaimState::NotYetProven,
        "supporting evidence should help: {:?}",
        eval.state
    );
}

#[test]
fn evaluate_claims_deterministic() {
    let atom = ClaimAtom {
        atom_id: "claim-det".to_string(),
        domain: ClaimDomain::Security,
        tier: ClaimTier::ScopedObserved,
        statement: "determinism test".to_string(),
        surface: "test".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: Vec::new(),
    };
    let r1 = evaluate_claims(&[atom.clone()], &[], &[], &[], 1);
    let r2 = evaluate_claims(&[atom], &[], &[], &[], 1);
    assert_eq!(r1.evaluations.len(), r2.evaluations.len());
    for (e1, e2) in r1.evaluations.iter().zip(r2.evaluations.iter()) {
        assert_eq!(e1.state, e2.state);
    }
}

// ---------------------------------------------------------------------------
// render_entitlement_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_nonempty() {
    let result = evaluate_claims(&[], &[], &[], &[], 1);
    let summary = render_entitlement_summary(&result);
    assert!(!summary.is_empty());
}

// ---------------------------------------------------------------------------
// EntitlementResult serde
// ---------------------------------------------------------------------------

#[test]
fn entitlement_result_serde_roundtrip() {
    let result = evaluate_claims(&[], &[], &[], &[], 1);
    let json = serde_json::to_string(&result).unwrap();
    let restored: EntitlementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(CLAIM_ATOM_LATTICE_SCHEMA_VERSION.contains("claim"));
    assert!(CLAIM_ATOM_LATTICE_BEAD_ID.starts_with("bd-"));
    assert!(ENTITLEMENT_RESULT_SCHEMA_VERSION.contains("entitlement"));
}
