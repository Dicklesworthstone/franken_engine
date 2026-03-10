#![forbid(unsafe_code)]

//! Integration tests for the claim-atom lattice module.
//!
//! Bead: bd-1lsy.1.7.1 [RGC-017A]

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

use frankenengine_engine::claim_atom_lattice::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn atom(id: &str, domain: ClaimDomain, tier: ClaimTier, morphisms: &[&str]) -> ClaimAtom {
    ClaimAtom {
        atom_id: id.to_string(),
        domain,
        tier,
        statement: format!("Claim {id}"),
        surface: "test-surface".to_string(),
        owning_beads: vec!["bd-test".to_string()],
        required_morphisms: morphisms.iter().map(|s| s.to_string()).collect(),
    }
}

fn morphism(id: &str, target: &str, kind: &str, effect: MorphismEffect) -> EvidenceMorphism {
    EvidenceMorphism {
        morphism_id: id.to_string(),
        evidence_kind: kind.to_string(),
        effect,
        target_atoms: vec![target.to_string()],
        required_constraints: Vec::new(),
        blocked_by_rules: Vec::new(),
        rationale: format!("morphism {id}"),
    }
}

fn evidence(kind: &str, fresh: bool) -> EvidenceSnapshot {
    EvidenceSnapshot {
        evidence_kind: kind.to_string(),
        is_fresh: fresh,
        triggered_rules: Vec::new(),
    }
}

fn evidence_with_rules(kind: &str, rules: &[&str]) -> EvidenceSnapshot {
    EvidenceSnapshot {
        evidence_kind: kind.to_string(),
        is_fresh: true,
        triggered_rules: rules.iter().map(|s| s.to_string()).collect(),
    }
}

fn rule(id: &str, target: &str, verdict: DisqualifierVerdict, precedence: u64) -> DisqualifierRule {
    DisqualifierRule {
        rule_id: id.to_string(),
        precedence,
        trigger_evidence_kind: "test".to_string(),
        condition: format!("condition for {id}"),
        target_atoms: vec![target.to_string()],
        verdict,
        remediation: format!("remediation for {id}"),
    }
}

fn simple_lattice() -> ConstraintLattice {
    ConstraintLattice {
        top_id: "top".to_string(),
        bottom_id: "bot".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "bot".to_string(),
                constraint_class: "none".to_string(),
                description: "bottom".to_string(),
            },
            SideConstraint {
                constraint_id: "mid".to_string(),
                constraint_class: "freshness".to_string(),
                description: "freshness check".to_string(),
            },
            SideConstraint {
                constraint_id: "top".to_string(),
                constraint_class: "full".to_string(),
                description: "all constraints".to_string(),
            },
        ],
        covers: vec![
            CoverRelation {
                lower: "bot".to_string(),
                higher: "mid".to_string(),
            },
            CoverRelation {
                lower: "mid".to_string(),
                higher: "top".to_string(),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_format() {
    assert!(CLAIM_ATOM_LATTICE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CLAIM_ATOM_LATTICE_SCHEMA_VERSION.contains("claim-atom-lattice"));
}

#[test]
fn bead_id_format() {
    assert!(CLAIM_ATOM_LATTICE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn entitlement_result_schema_version_format() {
    assert!(ENTITLEMENT_RESULT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ENTITLEMENT_RESULT_SCHEMA_VERSION.contains("entitlement"));
}

// ---------------------------------------------------------------------------
// ClaimDomain
// ---------------------------------------------------------------------------

#[test]
fn claim_domain_all_variants_display() {
    let cases = [
        (ClaimDomain::Compatibility, "compatibility"),
        (ClaimDomain::ShippedSurface, "shipped_surface"),
        (ClaimDomain::React, "react"),
        (ClaimDomain::Supremacy, "supremacy"),
        (ClaimDomain::Rollout, "rollout"),
        (ClaimDomain::Ga, "ga"),
        (ClaimDomain::Docs, "docs"),
        (ClaimDomain::Security, "security"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn claim_domain_serde_all_variants() {
    let all = [
        ClaimDomain::Compatibility,
        ClaimDomain::ShippedSurface,
        ClaimDomain::React,
        ClaimDomain::Supremacy,
        ClaimDomain::Rollout,
        ClaimDomain::Ga,
        ClaimDomain::Docs,
        ClaimDomain::Security,
    ];
    for d in &all {
        let json = serde_json::to_string(d).unwrap();
        let back: ClaimDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn claim_domain_ord() {
    assert!(ClaimDomain::Compatibility < ClaimDomain::Security);
}

// ---------------------------------------------------------------------------
// ClaimTier
// ---------------------------------------------------------------------------

#[test]
fn claim_tier_all_variants_display() {
    let cases = [
        (ClaimTier::ShippedFact, "shipped_fact"),
        (ClaimTier::ScopedObserved, "scoped_observed"),
        (ClaimTier::FrontierAmbition, "frontier_ambition"),
        (ClaimTier::UnsupportedSurface, "unsupported_surface"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn claim_tier_serde_all_variants() {
    let all = [
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ];
    for t in &all {
        let json = serde_json::to_string(t).unwrap();
        let back: ClaimTier = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn claim_tier_ord() {
    assert!(ClaimTier::ShippedFact < ClaimTier::UnsupportedSurface);
}

// ---------------------------------------------------------------------------
// MorphismEffect
// ---------------------------------------------------------------------------

#[test]
fn morphism_effect_all_variants_display() {
    assert_eq!(MorphismEffect::Supports.to_string(), "supports");
    assert_eq!(MorphismEffect::Constrains.to_string(), "constrains");
    assert_eq!(MorphismEffect::Disqualifies.to_string(), "disqualifies");
}

#[test]
fn morphism_effect_serde_all_variants() {
    for e in &[
        MorphismEffect::Supports,
        MorphismEffect::Constrains,
        MorphismEffect::Disqualifies,
    ] {
        let json = serde_json::to_string(e).unwrap();
        let back: MorphismEffect = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn morphism_effect_ord() {
    assert!(MorphismEffect::Supports < MorphismEffect::Disqualifies);
}

// ---------------------------------------------------------------------------
// ClaimState
// ---------------------------------------------------------------------------

#[test]
fn claim_state_all_variants_display() {
    assert_eq!(ClaimState::Entitled.to_string(), "entitled");
    assert_eq!(ClaimState::NotYetProven.to_string(), "not_yet_proven");
    assert_eq!(
        ClaimState::BlockedByMissingEvidence.to_string(),
        "blocked_by_missing_evidence"
    );
    assert_eq!(ClaimState::Invalidated.to_string(), "invalidated");
}

#[test]
fn claim_state_serde_all_variants() {
    for s in &[
        ClaimState::Entitled,
        ClaimState::NotYetProven,
        ClaimState::BlockedByMissingEvidence,
        ClaimState::Invalidated,
    ] {
        let json = serde_json::to_string(s).unwrap();
        let back: ClaimState = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn claim_state_ord() {
    assert!(ClaimState::Entitled < ClaimState::Invalidated);
}

// ---------------------------------------------------------------------------
// DisqualifierVerdict
// ---------------------------------------------------------------------------

#[test]
fn disqualifier_verdict_all_variants_display() {
    assert_eq!(DisqualifierVerdict::Forbid.to_string(), "forbid");
    assert_eq!(
        DisqualifierVerdict::DowngradeToScoped.to_string(),
        "downgrade_to_scoped"
    );
    assert_eq!(
        DisqualifierVerdict::RequireOperatorGuidance.to_string(),
        "require_operator_guidance"
    );
}

#[test]
fn disqualifier_verdict_serde_all_variants() {
    for v in &[
        DisqualifierVerdict::Forbid,
        DisqualifierVerdict::DowngradeToScoped,
        DisqualifierVerdict::RequireOperatorGuidance,
    ] {
        let json = serde_json::to_string(v).unwrap();
        let back: DisqualifierVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// ClaimAtom
// ---------------------------------------------------------------------------

#[test]
fn claim_atom_display_format() {
    let a = atom(
        "claim-compat-es2024",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    );
    let display = a.to_string();
    assert!(display.contains("claim-compat-es2024"));
    assert!(display.contains("compatibility"));
    assert!(display.contains("shipped_fact"));
}

#[test]
fn claim_atom_serde_round_trip() {
    let a = atom(
        "claim-sec-sandbox",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1", "m2"],
    );
    let json = serde_json::to_string(&a).unwrap();
    let back: ClaimAtom = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

#[test]
fn claim_atom_json_structure() {
    let a = atom(
        "claim-react-hooks",
        ClaimDomain::React,
        ClaimTier::ScopedObserved,
        &["morph-hooks"],
    );
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    assert_eq!(v["atom_id"], "claim-react-hooks");
    assert_eq!(v["domain"], "react");
    assert_eq!(v["tier"], "scoped_observed");
    assert!(v["required_morphisms"].as_array().unwrap().len() == 1);
}

#[test]
fn claim_atom_empty_morphisms() {
    let a = atom(
        "claim-docs-api",
        ClaimDomain::Docs,
        ClaimTier::FrontierAmbition,
        &[],
    );
    assert!(a.required_morphisms.is_empty());
}

// ---------------------------------------------------------------------------
// EvidenceMorphism
// ---------------------------------------------------------------------------

#[test]
fn evidence_morphism_display_format() {
    let m = morphism(
        "morph-test262",
        "claim-compat",
        "test262_pass",
        MorphismEffect::Supports,
    );
    let display = m.to_string();
    assert!(display.contains("morph-test262"));
    assert!(display.contains("supports"));
    assert!(display.contains("claim-compat"));
}

#[test]
fn evidence_morphism_serde_round_trip() {
    let m = morphism(
        "morph-bench",
        "claim-perf",
        "benchmark_cell",
        MorphismEffect::Constrains,
    );
    let json = serde_json::to_string(&m).unwrap();
    let back: EvidenceMorphism = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn evidence_morphism_with_blocked_rules() {
    let m = EvidenceMorphism {
        morphism_id: "morph-1".to_string(),
        evidence_kind: "test".to_string(),
        effect: MorphismEffect::Supports,
        target_atoms: vec!["a1".to_string()],
        required_constraints: vec!["c1".to_string()],
        blocked_by_rules: vec!["rule-flaky".to_string()],
        rationale: "test".to_string(),
    };
    assert_eq!(m.blocked_by_rules.len(), 1);
    let json = serde_json::to_string(&m).unwrap();
    let back: EvidenceMorphism = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

// ---------------------------------------------------------------------------
// SideConstraint
// ---------------------------------------------------------------------------

#[test]
fn side_constraint_display() {
    let c = SideConstraint {
        constraint_id: "freshness-24h".to_string(),
        constraint_class: "freshness".to_string(),
        description: "evidence must be < 24h old".to_string(),
    };
    let display = c.to_string();
    assert!(display.contains("freshness-24h"));
    assert!(display.contains("freshness"));
}

#[test]
fn side_constraint_serde_round_trip() {
    let c = SideConstraint {
        constraint_id: "sample-1k".to_string(),
        constraint_class: "sample_size".to_string(),
        description: "at least 1000 samples".to_string(),
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: SideConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// CoverRelation
// ---------------------------------------------------------------------------

#[test]
fn cover_relation_serde_round_trip() {
    let cr = CoverRelation {
        lower: "none".to_string(),
        higher: "freshness".to_string(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CoverRelation = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

// ---------------------------------------------------------------------------
// ConstraintLattice — cycle detection
// ---------------------------------------------------------------------------

#[test]
fn lattice_simple_chain_no_cycle() {
    let lat = simple_lattice();
    assert!(!lat.has_cycle());
}

#[test]
fn lattice_two_node_cycle() {
    let lat = ConstraintLattice {
        top_id: "a".to_string(),
        bottom_id: "b".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "a".to_string(),
                constraint_class: "x".to_string(),
                description: "a".to_string(),
            },
            SideConstraint {
                constraint_id: "b".to_string(),
                constraint_class: "x".to_string(),
                description: "b".to_string(),
            },
        ],
        covers: vec![
            CoverRelation {
                lower: "a".to_string(),
                higher: "b".to_string(),
            },
            CoverRelation {
                lower: "b".to_string(),
                higher: "a".to_string(),
            },
        ],
    };
    assert!(lat.has_cycle());
}

#[test]
fn lattice_three_node_cycle() {
    let lat = ConstraintLattice {
        top_id: "a".to_string(),
        bottom_id: "c".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "a".to_string(),
                constraint_class: "x".to_string(),
                description: "a".to_string(),
            },
            SideConstraint {
                constraint_id: "b".to_string(),
                constraint_class: "x".to_string(),
                description: "b".to_string(),
            },
            SideConstraint {
                constraint_id: "c".to_string(),
                constraint_class: "x".to_string(),
                description: "c".to_string(),
            },
        ],
        covers: vec![
            CoverRelation {
                lower: "a".to_string(),
                higher: "b".to_string(),
            },
            CoverRelation {
                lower: "b".to_string(),
                higher: "c".to_string(),
            },
            CoverRelation {
                lower: "c".to_string(),
                higher: "a".to_string(),
            },
        ],
    };
    assert!(lat.has_cycle());
}

#[test]
fn lattice_diamond_no_cycle() {
    let lat = ConstraintLattice {
        top_id: "top".to_string(),
        bottom_id: "bot".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "bot".to_string(),
                constraint_class: "x".to_string(),
                description: "bot".to_string(),
            },
            SideConstraint {
                constraint_id: "left".to_string(),
                constraint_class: "x".to_string(),
                description: "left".to_string(),
            },
            SideConstraint {
                constraint_id: "right".to_string(),
                constraint_class: "x".to_string(),
                description: "right".to_string(),
            },
            SideConstraint {
                constraint_id: "top".to_string(),
                constraint_class: "x".to_string(),
                description: "top".to_string(),
            },
        ],
        covers: vec![
            CoverRelation {
                lower: "bot".to_string(),
                higher: "left".to_string(),
            },
            CoverRelation {
                lower: "bot".to_string(),
                higher: "right".to_string(),
            },
            CoverRelation {
                lower: "left".to_string(),
                higher: "top".to_string(),
            },
            CoverRelation {
                lower: "right".to_string(),
                higher: "top".to_string(),
            },
        ],
    };
    assert!(!lat.has_cycle());
}

#[test]
fn lattice_empty_no_cycle() {
    let lat = ConstraintLattice {
        top_id: "t".to_string(),
        bottom_id: "b".to_string(),
        constraints: Vec::new(),
        covers: Vec::new(),
    };
    assert!(!lat.has_cycle());
}

// ---------------------------------------------------------------------------
// ConstraintLattice — reachability
// ---------------------------------------------------------------------------

#[test]
fn lattice_reachable_from_bottom_self() {
    let lat = simple_lattice();
    assert!(lat.is_reachable_from_bottom("bot"));
}

#[test]
fn lattice_reachable_from_bottom_transitive() {
    let lat = simple_lattice();
    assert!(lat.is_reachable_from_bottom("top"));
    assert!(lat.is_reachable_from_bottom("mid"));
}

#[test]
fn lattice_unreachable_node() {
    let lat = ConstraintLattice {
        top_id: "top".to_string(),
        bottom_id: "bot".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "bot".to_string(),
                constraint_class: "x".to_string(),
                description: "b".to_string(),
            },
            SideConstraint {
                constraint_id: "top".to_string(),
                constraint_class: "x".to_string(),
                description: "t".to_string(),
            },
            SideConstraint {
                constraint_id: "island".to_string(),
                constraint_class: "x".to_string(),
                description: "i".to_string(),
            },
        ],
        covers: vec![CoverRelation {
            lower: "bot".to_string(),
            higher: "top".to_string(),
        }],
    };
    assert!(!lat.is_reachable_from_bottom("island"));
}

#[test]
fn lattice_diamond_reachability() {
    let lat = ConstraintLattice {
        top_id: "top".to_string(),
        bottom_id: "bot".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "bot".to_string(),
                constraint_class: "x".to_string(),
                description: "b".to_string(),
            },
            SideConstraint {
                constraint_id: "l".to_string(),
                constraint_class: "x".to_string(),
                description: "l".to_string(),
            },
            SideConstraint {
                constraint_id: "r".to_string(),
                constraint_class: "x".to_string(),
                description: "r".to_string(),
            },
            SideConstraint {
                constraint_id: "top".to_string(),
                constraint_class: "x".to_string(),
                description: "t".to_string(),
            },
        ],
        covers: vec![
            CoverRelation {
                lower: "bot".to_string(),
                higher: "l".to_string(),
            },
            CoverRelation {
                lower: "bot".to_string(),
                higher: "r".to_string(),
            },
            CoverRelation {
                lower: "l".to_string(),
                higher: "top".to_string(),
            },
            CoverRelation {
                lower: "r".to_string(),
                higher: "top".to_string(),
            },
        ],
    };
    assert!(lat.is_reachable_from_bottom("l"));
    assert!(lat.is_reachable_from_bottom("r"));
    assert!(lat.is_reachable_from_bottom("top"));
}

// ---------------------------------------------------------------------------
// ConstraintLattice serde
// ---------------------------------------------------------------------------

#[test]
fn constraint_lattice_serde_round_trip() {
    let lat = simple_lattice();
    let json = serde_json::to_string(&lat).unwrap();
    let back: ConstraintLattice = serde_json::from_str(&json).unwrap();
    assert_eq!(lat, back);
}

#[test]
fn constraint_lattice_json_structure() {
    let lat = simple_lattice();
    let v: serde_json::Value = serde_json::to_value(&lat).unwrap();
    assert_eq!(v["top_id"], "top");
    assert_eq!(v["bottom_id"], "bot");
    assert_eq!(v["constraints"].as_array().unwrap().len(), 3);
    assert_eq!(v["covers"].as_array().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// DisqualifierRule
// ---------------------------------------------------------------------------

#[test]
fn disqualifier_rule_display() {
    let r = rule("rule-flaky", "claim-compat", DisqualifierVerdict::Forbid, 0);
    let display = r.to_string();
    assert!(display.contains("rule-flaky"));
    assert!(display.contains("forbid"));
    assert!(display.contains("prec=0"));
}

#[test]
fn disqualifier_rule_serde_round_trip() {
    let r = rule(
        "rule-stale",
        "claim-perf",
        DisqualifierVerdict::DowngradeToScoped,
        10,
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DisqualifierRule = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn disqualifier_rule_json_structure() {
    let r = rule("r1", "a1", DisqualifierVerdict::RequireOperatorGuidance, 5);
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["rule_id"], "r1");
    assert_eq!(v["precedence"], 5);
    assert_eq!(v["verdict"], "require_operator_guidance");
}

// ---------------------------------------------------------------------------
// EvidenceSnapshot
// ---------------------------------------------------------------------------

#[test]
fn evidence_snapshot_serde_round_trip() {
    let e = evidence("test262_pass", true);
    let json = serde_json::to_string(&e).unwrap();
    let back: EvidenceSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn evidence_snapshot_with_triggered_rules_serde() {
    let e = evidence_with_rules("bench", &["rule-a", "rule-b"]);
    let json = serde_json::to_string(&e).unwrap();
    let back: EvidenceSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
    assert_eq!(back.triggered_rules.len(), 2);
}

// ---------------------------------------------------------------------------
// evaluate_claims — single atom scenarios
// ---------------------------------------------------------------------------

#[test]
fn eval_single_atom_entitled() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism(
        "m1",
        "a1",
        "test262_pass",
        MorphismEffect::Supports,
    )];
    let ev = vec![evidence("test262_pass", true)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 1);
    assert_eq!(result.overall_state, ClaimState::Entitled);
    assert_eq!(result.entitled_count, 1);
    assert_eq!(result.evaluated_epoch, 1);
}

#[test]
fn eval_single_atom_blocked_no_evidence() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism(
        "m1",
        "a1",
        "test262_pass",
        MorphismEffect::Supports,
    )];
    let result = evaluate_claims(&atoms, &morphisms, &[], &[], 2);
    assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
    assert_eq!(result.blocked_count, 1);
}

#[test]
fn eval_single_atom_stale_evidence() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism(
        "m1",
        "a1",
        "test262_pass",
        MorphismEffect::Supports,
    )];
    let ev = vec![evidence("test262_pass", false)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 3);
    assert_ne!(result.overall_state, ClaimState::Entitled);
}

#[test]
fn eval_single_atom_invalidated_by_forbid() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "audit", MorphismEffect::Supports)];
    let rules = vec![rule("rule-cve", "a1", DisqualifierVerdict::Forbid, 0)];
    let ev = vec![evidence_with_rules("audit", &["rule-cve"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 4);
    assert_eq!(result.overall_state, ClaimState::Invalidated);
    assert_eq!(result.invalidated_count, 1);
}

#[test]
fn eval_single_atom_downgrade_not_forbid() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Supremacy,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "bench", MorphismEffect::Supports)];
    let rules = vec![rule(
        "rule-env",
        "a1",
        DisqualifierVerdict::DowngradeToScoped,
        0,
    )];
    let ev = vec![evidence_with_rules("bench", &["rule-env"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 5);
    // Downgrade means not_yet_proven, not invalidated
    assert_eq!(result.overall_state, ClaimState::NotYetProven);
}

#[test]
fn eval_atom_no_morphisms_entitled() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Docs,
        ClaimTier::FrontierAmbition,
        &[],
    )];
    let result = evaluate_claims(&atoms, &[], &[], &[], 6);
    assert_eq!(result.overall_state, ClaimState::Entitled);
    assert_eq!(result.entitled_count, 1);
}

// ---------------------------------------------------------------------------
// evaluate_claims — multi-atom scenarios
// ---------------------------------------------------------------------------

#[test]
fn eval_multi_atom_all_entitled() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ScopedObserved, &["m2"]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262_pass", MorphismEffect::Supports),
        morphism("m2", "a2", "react_test", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262_pass", true), evidence("react_test", true)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 10);
    assert_eq!(result.overall_state, ClaimState::Entitled);
    assert_eq!(result.entitled_count, 2);
}

#[test]
fn eval_multi_atom_one_blocked() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ScopedObserved, &["m2"]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262_pass", MorphismEffect::Supports),
        morphism("m2", "a2", "react_test", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262_pass", true)]; // missing react_test
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 11);
    assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
    assert_eq!(result.entitled_count, 1);
    assert_eq!(result.blocked_count, 1);
}

#[test]
fn eval_multi_atom_one_invalidated() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::Security, ClaimTier::ShippedFact, &["m2"]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262_pass", MorphismEffect::Supports),
        morphism("m2", "a2", "audit", MorphismEffect::Supports),
    ];
    let rules = vec![rule("rule-cve", "a2", DisqualifierVerdict::Forbid, 0)];
    let ev = vec![
        evidence("test262_pass", true),
        evidence_with_rules("audit", &["rule-cve"]),
    ];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 12);
    assert_eq!(result.overall_state, ClaimState::Invalidated);
    assert_eq!(result.invalidated_count, 1);
    assert_eq!(result.entitled_count, 1);
}

#[test]
fn eval_empty_atoms_entitled() {
    let result = evaluate_claims(&[], &[], &[], &[], 0);
    assert_eq!(result.overall_state, ClaimState::Entitled);
    assert_eq!(result.evaluations.len(), 0);
}

// ---------------------------------------------------------------------------
// evaluate_claims — morphism blocked by rule
// ---------------------------------------------------------------------------

#[test]
fn eval_morphism_blocked_by_triggered_rule() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let m = EvidenceMorphism {
        morphism_id: "m1".to_string(),
        evidence_kind: "test262_pass".to_string(),
        effect: MorphismEffect::Supports,
        target_atoms: vec!["a1".to_string()],
        required_constraints: Vec::new(),
        blocked_by_rules: vec!["blocker-rule".to_string()],
        rationale: "test".to_string(),
    };
    let ev = vec![evidence_with_rules("test262_pass", &["blocker-rule"])];
    let result = evaluate_claims(&atoms, &[m], &[], &ev, 20);
    // Morphism is blocked => evidence not satisfied => blocked
    assert_ne!(result.overall_state, ClaimState::Entitled);
}

// ---------------------------------------------------------------------------
// evaluate_claims — multiple morphisms per atom
// ---------------------------------------------------------------------------

#[test]
fn eval_atom_needs_two_morphisms_both_present() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1", "m2"],
    )];
    let morphisms = vec![
        morphism("m1", "a1", "test262_pass", MorphismEffect::Supports),
        morphism("m2", "a1", "benchmark_cell", MorphismEffect::Supports),
    ];
    let ev = vec![
        evidence("test262_pass", true),
        evidence("benchmark_cell", true),
    ];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 30);
    assert_eq!(result.overall_state, ClaimState::Entitled);
}

#[test]
fn eval_atom_needs_two_morphisms_one_missing() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1", "m2"],
    )];
    let morphisms = vec![
        morphism("m1", "a1", "test262_pass", MorphismEffect::Supports),
        morphism("m2", "a1", "benchmark_cell", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262_pass", true)]; // missing benchmark_cell
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 31);
    assert_eq!(result.overall_state, ClaimState::NotYetProven);
    assert_eq!(result.not_yet_proven_count, 1);
}

// ---------------------------------------------------------------------------
// evaluate_claims — overall state priority
// ---------------------------------------------------------------------------

#[test]
fn eval_overall_state_invalidated_takes_precedence() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &[],
        ),
        atom("a2", ClaimDomain::Security, ClaimTier::ShippedFact, &["m2"]),
        atom("a3", ClaimDomain::React, ClaimTier::ShippedFact, &["m3"]),
    ];
    let morphisms = vec![morphism("m2", "a2", "audit", MorphismEffect::Supports)];
    let rules = vec![rule("rule-cve", "a2", DisqualifierVerdict::Forbid, 0)];
    let ev = vec![evidence_with_rules("audit", &["rule-cve"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 40);
    // a1 entitled, a2 invalidated, a3 blocked => overall invalidated
    assert_eq!(result.overall_state, ClaimState::Invalidated);
}

#[test]
fn eval_overall_state_blocked_over_not_yet_proven() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1", "m2"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ShippedFact, &["m3"]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test_a", MorphismEffect::Supports),
        morphism("m2", "a1", "test_b", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test_a", true)]; // a1=not_yet_proven, a2=blocked
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 41);
    assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
}

// ---------------------------------------------------------------------------
// ClaimAtomEvaluation
// ---------------------------------------------------------------------------

#[test]
fn claim_atom_evaluation_serde_round_trip() {
    let eval = ClaimAtomEvaluation {
        atom_id: "a1".to_string(),
        state: ClaimState::NotYetProven,
        satisfied_morphisms: vec!["m1".to_string()],
        missing_morphisms: vec!["m2".to_string()],
        active_disqualifiers: vec!["r1".to_string()],
    };
    let json = serde_json::to_string(&eval).unwrap();
    let back: ClaimAtomEvaluation = serde_json::from_str(&json).unwrap();
    assert_eq!(eval, back);
}

// ---------------------------------------------------------------------------
// EntitlementResult
// ---------------------------------------------------------------------------

#[test]
fn entitlement_result_schema_version_populated() {
    let result = evaluate_claims(&[], &[], &[], &[], 99);
    assert_eq!(result.schema_version, ENTITLEMENT_RESULT_SCHEMA_VERSION);
    assert_eq!(result.bead_id, CLAIM_ATOM_LATTICE_BEAD_ID);
}

#[test]
fn entitlement_result_serde_round_trip() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ScopedObserved, &["m2"]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262", MorphismEffect::Supports),
        morphism("m2", "a2", "react_test", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262", true)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 100);
    let json = serde_json::to_string(&result).unwrap();
    let back: EntitlementResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn entitlement_result_json_structure() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Docs,
        ClaimTier::FrontierAmbition,
        &[],
    )];
    let result = evaluate_claims(&atoms, &[], &[], &[], 42);
    let v: serde_json::Value = serde_json::to_value(&result).unwrap();
    assert!(v["schema_version"].is_string());
    assert!(v["bead_id"].is_string());
    assert!(v["evaluations"].is_array());
    assert_eq!(v["overall_state"], "entitled");
    assert_eq!(v["evaluated_epoch"], 42);
    assert_eq!(v["entitled_count"], 1);
}

#[test]
fn entitlement_result_counts_consistency() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ScopedObserved, &["m2"]),
        atom("a3", ClaimDomain::Docs, ClaimTier::FrontierAmbition, &[]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262", MorphismEffect::Supports),
        morphism("m2", "a2", "react_test", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262", true)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 50);
    assert_eq!(
        result.entitled_count
            + result.not_yet_proven_count
            + result.blocked_count
            + result.invalidated_count,
        result.evaluations.len()
    );
}

// ---------------------------------------------------------------------------
// render_entitlement_summary
// ---------------------------------------------------------------------------

#[test]
fn summary_contains_all_fields() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "test", MorphismEffect::Supports)];
    let ev = vec![evidence("test", true)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 7);
    let summary = render_entitlement_summary(&result);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("evaluated_epoch: 7"));
    assert!(summary.contains("overall_state: entitled"));
    assert!(summary.contains("entitled: 1"));
    assert!(summary.contains("not_yet_proven: 0"));
    assert!(summary.contains("blocked: 0"));
    assert!(summary.contains("invalidated: 0"));
}

#[test]
fn summary_blocked_state() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "audit", MorphismEffect::Supports)];
    let result = evaluate_claims(&atoms, &morphisms, &[], &[], 8);
    let summary = render_entitlement_summary(&result);
    assert!(summary.contains("overall_state: blocked_by_missing_evidence"));
    assert!(summary.contains("blocked: 1"));
}

#[test]
fn summary_invalidated_state() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "audit", MorphismEffect::Supports)];
    let rules = vec![rule("rule-cve", "a1", DisqualifierVerdict::Forbid, 0)];
    let ev = vec![evidence_with_rules("audit", &["rule-cve"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 9);
    let summary = render_entitlement_summary(&result);
    assert!(summary.contains("overall_state: invalidated"));
    assert!(summary.contains("invalidated: 1"));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn evaluation_deterministic() {
    let atoms = vec![
        atom(
            "a1",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
            &["m1"],
        ),
        atom("a2", ClaimDomain::React, ClaimTier::ScopedObserved, &["m2"]),
        atom("a3", ClaimDomain::Docs, ClaimTier::FrontierAmbition, &[]),
    ];
    let morphisms = vec![
        morphism("m1", "a1", "test262", MorphismEffect::Supports),
        morphism("m2", "a2", "react_test", MorphismEffect::Supports),
    ];
    let ev = vec![evidence("test262", true)];
    let r1 = evaluate_claims(&atoms, &morphisms, &[], &ev, 1);
    let r2 = evaluate_claims(&atoms, &morphisms, &[], &ev, 1);
    assert_eq!(r1, r2);
}

#[test]
fn evaluation_json_deterministic() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "test", MorphismEffect::Supports)];
    let ev = vec![evidence("test", true)];
    let r1 = evaluate_claims(&atoms, &morphisms, &[], &ev, 1);
    let r2 = evaluate_claims(&atoms, &morphisms, &[], &ev, 1);
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn eval_morphism_not_in_list_blocks() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["missing-morph"],
    )];
    let ev = vec![evidence("test", true)];
    let result = evaluate_claims(&atoms, &[], &[], &ev, 0);
    assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
}

#[test]
fn eval_rule_targets_wrong_atom() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Compatibility,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "test", MorphismEffect::Supports)];
    let rules = vec![rule("rule-1", "other-atom", DisqualifierVerdict::Forbid, 0)];
    let ev = vec![evidence_with_rules("test", &["rule-1"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 0);
    // Rule targets other-atom, not a1, so a1 should still be entitled
    assert_eq!(result.overall_state, ClaimState::Entitled);
}

#[test]
fn eval_require_operator_guidance_verdict() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Rollout,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "check", MorphismEffect::Supports)];
    let rules = vec![rule(
        "rule-op",
        "a1",
        DisqualifierVerdict::RequireOperatorGuidance,
        0,
    )];
    let ev = vec![evidence_with_rules("check", &["rule-op"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 0);
    assert_eq!(result.overall_state, ClaimState::NotYetProven);
}

#[test]
fn eval_large_atom_set() {
    let atoms: Vec<ClaimAtom> = (0..50)
        .map(|i| {
            atom(
                &format!("a{i}"),
                ClaimDomain::Compatibility,
                ClaimTier::ShippedFact,
                &[&format!("m{i}")],
            )
        })
        .collect();
    let morphisms: Vec<EvidenceMorphism> = (0..50)
        .map(|i| {
            morphism(
                &format!("m{i}"),
                &format!("a{i}"),
                &format!("ev{i}"),
                MorphismEffect::Supports,
            )
        })
        .collect();
    let ev: Vec<EvidenceSnapshot> = (0..50).map(|i| evidence(&format!("ev{i}"), true)).collect();
    let result = evaluate_claims(&atoms, &morphisms, &[], &ev, 0);
    assert_eq!(result.overall_state, ClaimState::Entitled);
    assert_eq!(result.entitled_count, 50);
}

#[test]
fn eval_multiple_rules_same_atom() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "audit", MorphismEffect::Supports)];
    let rules = vec![
        rule("rule-1", "a1", DisqualifierVerdict::DowngradeToScoped, 0),
        rule(
            "rule-2",
            "a1",
            DisqualifierVerdict::RequireOperatorGuidance,
            1,
        ),
    ];
    let ev = vec![evidence_with_rules("audit", &["rule-1", "rule-2"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 0);
    // Both downgrade and require_guidance, no forbid => not_yet_proven
    assert_eq!(result.overall_state, ClaimState::NotYetProven);
    assert_eq!(result.evaluations[0].active_disqualifiers.len(), 2);
}

#[test]
fn eval_mixed_forbid_and_downgrade() {
    let atoms = vec![atom(
        "a1",
        ClaimDomain::Security,
        ClaimTier::ShippedFact,
        &["m1"],
    )];
    let morphisms = vec![morphism("m1", "a1", "audit", MorphismEffect::Supports)];
    let rules = vec![
        rule("rule-1", "a1", DisqualifierVerdict::DowngradeToScoped, 1),
        rule("rule-2", "a1", DisqualifierVerdict::Forbid, 0),
    ];
    let ev = vec![evidence_with_rules("audit", &["rule-1", "rule-2"])];
    let result = evaluate_claims(&atoms, &morphisms, &rules, &ev, 0);
    // Forbid overrides everything
    assert_eq!(result.overall_state, ClaimState::Invalidated);
}

#[test]
fn eval_epoch_propagated() {
    let result = evaluate_claims(&[], &[], &[], &[], 99999);
    assert_eq!(result.evaluated_epoch, 99999);
}

#[test]
fn summary_newline_separated() {
    let result = evaluate_claims(&[], &[], &[], &[], 0);
    let summary = render_entitlement_summary(&result);
    let lines: Vec<&str> = summary.lines().collect();
    assert_eq!(lines.len(), 7);
}
