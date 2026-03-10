//! Integration tests for claim_entitlement algebra module.

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

use frankenengine_engine::claim_entitlement::{
    self, CLAIM_ENTITLEMENT_COMPONENT, CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION, CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_POLICY_ID, CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION, CLAIM_ENTITLEMENT_SCHEMA_VERSION, ClaimAtom,
    ClaimAtomCatalog, ClaimDomain, ClaimEntitlementContract, ClaimEvaluationOutputs,
    ClaimEvaluationScenario, ClaimEvaluationScenarioSet, ClaimTier, ClaimVerdictState,
    ConstraintRelation, ContractTrack, DisqualifierRule, DisqualifierRuleSet, DisqualifierVerdict,
    EvidenceMorphism, EvidenceMorphismCatalog, EvidenceState, ExpectedClaimOutcome, MorphismEffect,
    ObservedEvidence, SideConstraint, SideConstraintLattice,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn minimal_contract() -> ClaimEntitlementContract {
    ClaimEntitlementContract {
        schema_version: CLAIM_ENTITLEMENT_SCHEMA_VERSION.to_string(),
        contract_version: "v1-test".to_string(),
        bead_id: "bd-test".to_string(),
        generated_by: "test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        track: ContractTrack {
            id: "RGC-017".to_string(),
            name: "test track".to_string(),
        },
        required_artifacts: vec!["artifact-a".to_string()],
        required_structured_log_fields: vec!["field-a".to_string()],
        claim_atom_catalog: ClaimAtomCatalog {
            schema_version: "v1".to_string(),
            atoms: vec![
                ClaimAtom {
                    atom_id: "atom-shipped".to_string(),
                    domain: ClaimDomain::Compatibility,
                    tier: ClaimTier::ShippedFact,
                    statement_class: "class-a".to_string(),
                    surface: "docs".to_string(),
                    description: "shipped fact atom".to_string(),
                    source_documents: vec![],
                    owning_beads: vec![],
                },
                ClaimAtom {
                    atom_id: "atom-frontier".to_string(),
                    domain: ClaimDomain::Supremacy,
                    tier: ClaimTier::FrontierAmbition,
                    statement_class: "class-b".to_string(),
                    surface: "supremacy".to_string(),
                    description: "frontier atom".to_string(),
                    source_documents: vec![],
                    owning_beads: vec![],
                },
                ClaimAtom {
                    atom_id: "atom-unsupported".to_string(),
                    domain: ClaimDomain::SupportSurface,
                    tier: ClaimTier::UnsupportedSurface,
                    statement_class: "class-c".to_string(),
                    surface: "advisory".to_string(),
                    description: "unsupported surface atom".to_string(),
                    source_documents: vec![],
                    owning_beads: vec![],
                },
            ],
        },
        evidence_morphism_catalog: EvidenceMorphismCatalog {
            schema_version: "v1".to_string(),
            morphisms: vec![EvidenceMorphism {
                morphism_id: "morph-compat".to_string(),
                evidence_kind: "compatibility_test_suite".to_string(),
                effect: MorphismEffect::Supports,
                target_atoms: vec!["atom-shipped".to_string()],
                requires_side_constraints: vec!["constraint-top".to_string()],
                blocked_by_rules: vec![],
                rationale: "test suite evidence".to_string(),
            }],
        },
        side_constraint_lattice: SideConstraintLattice {
            schema_version: "v1".to_string(),
            top_constraint_id: "constraint-top".to_string(),
            bottom_constraint_id: "constraint-bottom".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "constraint-top".to_string(),
                    constraint_class: "universal".to_string(),
                    description: "top constraint".to_string(),
                },
                SideConstraint {
                    constraint_id: "constraint-bottom".to_string(),
                    constraint_class: "minimal".to_string(),
                    description: "bottom constraint".to_string(),
                },
            ],
            cover_relations: vec![ConstraintRelation {
                lower_constraint_id: "constraint-bottom".to_string(),
                higher_constraint_id: "constraint-top".to_string(),
            }],
        },
        disqualifier_rules: DisqualifierRuleSet {
            schema_version: "v1".to_string(),
            precedence_order: vec!["rule-forbid".to_string()],
            rules: vec![DisqualifierRule {
                rule_id: "rule-forbid".to_string(),
                precedence: 1,
                evidence_kind: "counterexample_suite".to_string(),
                condition: "regression found".to_string(),
                target_atoms: vec!["atom-shipped".to_string()],
                verdict: DisqualifierVerdict::Forbid,
                remediation: "fix the regression".to_string(),
            }],
        },
        operator_verification: vec!["check-a".to_string()],
    }
}

fn minimal_scenario_set() -> ClaimEvaluationScenarioSet {
    ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "scenario-happy".to_string(),
            description: "all evidence fresh".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "compatibility_test_suite".to_string(),
                state: EvidenceState::Fresh,
                triggered_rule_ids: vec![],
            }],
            satisfied_constraints: vec!["constraint-top".to_string()],
            expected_outcomes: vec![ExpectedClaimOutcome {
                atom_id: "atom-shipped".to_string(),
                state: ClaimVerdictState::Entitled,
                minimal_morphism_id: Some("morph-compat".to_string()),
                impossible_rule_id: None,
            }],
        }],
    }
}

fn counterexample_scenario_set() -> ClaimEvaluationScenarioSet {
    ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "counterexample".to_string(),
            description: "forbid rule triggered".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "counterexample_suite".to_string(),
                state: EvidenceState::Fresh,
                triggered_rule_ids: vec!["rule-forbid".to_string()],
            }],
            satisfied_constraints: vec![],
            expected_outcomes: vec![],
        }],
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_SCHEMA_VERSION.is_empty());
    assert!(CLAIM_ENTITLEMENT_SCHEMA_VERSION.contains("claim-entitlement"));
}

#[test]
fn test_component_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_COMPONENT.is_empty());
}

#[test]
fn test_policy_id_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_POLICY_ID.is_empty());
}

#[test]
fn test_scenario_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.is_empty());
}

#[test]
fn test_report_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION.is_empty());
}

#[test]
fn test_cutset_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION.is_empty());
}

#[test]
fn test_impossibility_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION.is_empty());
}

#[test]
fn test_counterexample_ledger_schema_version_non_empty() {
    assert!(!CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_claim_domain_serde_all_variants() {
    for domain in [
        ClaimDomain::Compatibility,
        ClaimDomain::ShippedSurface,
        ClaimDomain::React,
        ClaimDomain::Supremacy,
        ClaimDomain::Rollout,
        ClaimDomain::Ga,
        ClaimDomain::SupportSurface,
    ] {
        let json = serde_json::to_string(&domain).unwrap();
        let back: ClaimDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(back, domain);
    }
}

#[test]
fn test_claim_tier_serde_all_variants() {
    for tier in [
        ClaimTier::ShippedFact,
        ClaimTier::ScopedObserved,
        ClaimTier::FrontierAmbition,
        ClaimTier::UnsupportedSurface,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let back: ClaimTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tier);
    }
}

#[test]
fn test_morphism_effect_serde_all_variants() {
    for effect in [
        MorphismEffect::Supports,
        MorphismEffect::Constrains,
        MorphismEffect::Disqualifies,
    ] {
        let json = serde_json::to_string(&effect).unwrap();
        let back: MorphismEffect = serde_json::from_str(&json).unwrap();
        assert_eq!(back, effect);
    }
}

#[test]
fn test_disqualifier_verdict_serde_all_variants() {
    for verdict in [
        DisqualifierVerdict::Forbid,
        DisqualifierVerdict::DowngradeToScoped,
        DisqualifierVerdict::DowngradeToTarget,
        DisqualifierVerdict::RequireOperatorGuidance,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let back: DisqualifierVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, verdict);
    }
}

#[test]
fn test_evidence_state_serde_all_variants() {
    for state in [EvidenceState::Fresh, EvidenceState::Stale] {
        let json = serde_json::to_string(&state).unwrap();
        let back: EvidenceState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn test_claim_verdict_state_serde_all_variants() {
    for state in [
        ClaimVerdictState::Entitled,
        ClaimVerdictState::NotYetProven,
        ClaimVerdictState::BlockedByMissingEvidence,
        ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: ClaimVerdictState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

// ---------------------------------------------------------------------------
// Embedded contract
// ---------------------------------------------------------------------------

#[test]
fn test_embedded_contract_loads() {
    let contract = ClaimEntitlementContract::from_embedded_json();
    assert_eq!(contract.schema_version, CLAIM_ENTITLEMENT_SCHEMA_VERSION);
    assert_eq!(contract.track.id, "RGC-017");
}

#[test]
fn test_embedded_contract_has_atoms() {
    let contract = ClaimEntitlementContract::from_embedded_json();
    assert!(!contract.claim_atom_catalog.atoms.is_empty());
}

#[test]
fn test_embedded_contract_has_morphisms() {
    let contract = ClaimEntitlementContract::from_embedded_json();
    assert!(!contract.evidence_morphism_catalog.morphisms.is_empty());
}

#[test]
fn test_embedded_contract_validates() {
    let contract = ClaimEntitlementContract::from_embedded_json();
    contract
        .validate()
        .expect("embedded contract must validate");
}

// ---------------------------------------------------------------------------
// Contract validation — happy path
// ---------------------------------------------------------------------------

#[test]
fn test_minimal_contract_validates() {
    let contract = minimal_contract();
    contract
        .validate()
        .expect("minimal contract should validate");
}

// ---------------------------------------------------------------------------
// Contract validation — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_validate_rejects_wrong_schema_version() {
    let mut contract = minimal_contract();
    contract.schema_version = "wrong-version".to_string();
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("schema_version")));
}

#[test]
fn test_validate_rejects_wrong_track_id() {
    let mut contract = minimal_contract();
    contract.track.id = "RGC-999".to_string();
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("track id")));
}

#[test]
fn test_validate_rejects_duplicate_atom_ids() {
    let mut contract = minimal_contract();
    let dup = contract.claim_atom_catalog.atoms[0].clone();
    contract.claim_atom_catalog.atoms.push(dup);
    let errors = contract.validate().expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("duplicate") && e.contains("claim atom"))
    );
}

#[test]
fn test_validate_rejects_missing_top_constraint() {
    let mut contract = minimal_contract();
    contract.side_constraint_lattice.top_constraint_id = "nonexistent".to_string();
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("top constraint")));
}

#[test]
fn test_validate_rejects_missing_bottom_constraint() {
    let mut contract = minimal_contract();
    contract.side_constraint_lattice.bottom_constraint_id = "nonexistent".to_string();
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("bottom constraint")));
}

#[test]
fn test_validate_rejects_morphism_unknown_atom() {
    let mut contract = minimal_contract();
    contract.evidence_morphism_catalog.morphisms[0]
        .target_atoms
        .push("atom-nonexistent".to_string());
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("unknown atom")));
}

#[test]
fn test_validate_rejects_morphism_unknown_constraint() {
    let mut contract = minimal_contract();
    contract.evidence_morphism_catalog.morphisms[0]
        .requires_side_constraints
        .push("constraint-nonexistent".to_string());
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("unknown side constraint")));
}

#[test]
fn test_validate_rejects_self_referential_cover_relation() {
    let mut contract = minimal_contract();
    contract
        .side_constraint_lattice
        .cover_relations
        .push(ConstraintRelation {
            lower_constraint_id: "constraint-top".to_string(),
            higher_constraint_id: "constraint-top".to_string(),
        });
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("self-referential")));
}

#[test]
fn test_validate_rejects_duplicate_precedence() {
    let mut contract = minimal_contract();
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule-dup".to_string(),
        precedence: 1,
        evidence_kind: "counterexample_suite".to_string(),
        condition: "dup".to_string(),
        target_atoms: vec!["atom-shipped".to_string()],
        verdict: DisqualifierVerdict::Forbid,
        remediation: "fix".to_string(),
    });
    contract
        .disqualifier_rules
        .precedence_order
        .push("rule-dup".to_string());
    let errors = contract.validate().expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("duplicate") && e.contains("precedence"))
    );
}

#[test]
fn test_validate_rejects_missing_shipped_fact_tier() {
    let mut contract = minimal_contract();
    contract
        .claim_atom_catalog
        .atoms
        .retain(|a| a.tier != ClaimTier::ShippedFact);
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("shipped_fact")));
}

#[test]
fn test_validate_rejects_missing_frontier_tier() {
    let mut contract = minimal_contract();
    contract
        .claim_atom_catalog
        .atoms
        .retain(|a| a.tier != ClaimTier::FrontierAmbition);
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("frontier_ambition")));
}

#[test]
fn test_validate_rejects_missing_unsupported_tier() {
    let mut contract = minimal_contract();
    contract
        .claim_atom_catalog
        .atoms
        .retain(|a| a.tier != ClaimTier::UnsupportedSurface);
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("unsupported_surface")));
}

#[test]
fn test_validate_rejects_lattice_cycle() {
    let mut contract = minimal_contract();
    contract
        .side_constraint_lattice
        .cover_relations
        .push(ConstraintRelation {
            lower_constraint_id: "constraint-top".to_string(),
            higher_constraint_id: "constraint-bottom".to_string(),
        });
    let errors = contract.validate().expect_err("should detect cycle");
    assert!(errors.iter().any(|e| e.contains("cycle")));
}

#[test]
fn test_validate_rejects_mismatched_precedence_order() {
    let mut contract = minimal_contract();
    contract.disqualifier_rules.precedence_order = vec!["wrong-order".to_string()];
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("precedence_order")));
}

// ---------------------------------------------------------------------------
// lattice_has_cycle
// ---------------------------------------------------------------------------

#[test]
fn test_lattice_acyclic() {
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "a".to_string(),
        bottom_constraint_id: "c".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "a".into(),
                constraint_class: "top".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "b".into(),
                constraint_class: "mid".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "c".into(),
                constraint_class: "bot".into(),
                description: String::new(),
            },
        ],
        cover_relations: vec![
            ConstraintRelation {
                lower_constraint_id: "c".into(),
                higher_constraint_id: "b".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "b".into(),
                higher_constraint_id: "a".into(),
            },
        ],
    };
    assert!(!claim_entitlement::lattice_has_cycle(&lattice));
}

#[test]
fn test_lattice_cyclic() {
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "a".to_string(),
        bottom_constraint_id: "b".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "a".into(),
                constraint_class: "top".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "b".into(),
                constraint_class: "bot".into(),
                description: String::new(),
            },
        ],
        cover_relations: vec![
            ConstraintRelation {
                lower_constraint_id: "a".into(),
                higher_constraint_id: "b".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "b".into(),
                higher_constraint_id: "a".into(),
            },
        ],
    };
    assert!(claim_entitlement::lattice_has_cycle(&lattice));
}

#[test]
fn test_lattice_empty_no_cycle() {
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "x".to_string(),
        bottom_constraint_id: "x".to_string(),
        constraints: vec![SideConstraint {
            constraint_id: "x".into(),
            constraint_class: "only".into(),
            description: String::new(),
        }],
        cover_relations: vec![],
    };
    assert!(!claim_entitlement::lattice_has_cycle(&lattice));
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — entitled
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_entitled() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped = verdicts
        .iter()
        .find(|v| v.atom_id == "atom-shipped")
        .unwrap();
    assert_eq!(shipped.state, ClaimVerdictState::Entitled);
    assert!(
        shipped
            .supporting_morphism_ids
            .contains(&"morph-compat".to_string())
    );
}

#[test]
fn test_evaluate_entitled_has_no_cutsets() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped = verdicts
        .iter()
        .find(|v| v.atom_id == "atom-shipped")
        .unwrap();
    assert!(shipped.minimal_cutset_ids.is_empty());
    assert!(shipped.impossibility_certificate_ids.is_empty());
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — not yet proven
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_not_yet_proven_when_no_evidence() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "no-evidence".to_string(),
            description: "no evidence".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![],
            satisfied_constraints: vec![],
            expected_outcomes: vec![],
        }],
    };
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped = verdicts
        .iter()
        .find(|v| v.atom_id == "atom-shipped")
        .unwrap();
    assert_eq!(shipped.state, ClaimVerdictState::NotYetProven);
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — blocked by missing evidence
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_blocked_by_stale_evidence() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "stale".to_string(),
            description: "stale evidence".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "compatibility_test_suite".to_string(),
                state: EvidenceState::Stale,
                triggered_rule_ids: vec![],
            }],
            satisfied_constraints: vec!["constraint-top".to_string()],
            expected_outcomes: vec![],
        }],
    };
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped = verdicts
        .iter()
        .find(|v| v.atom_id == "atom-shipped")
        .unwrap();
    assert_eq!(shipped.state, ClaimVerdictState::BlockedByMissingEvidence);
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — counterexample (forbid)
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_counterexample_forbids() {
    let contract = minimal_contract();
    let scenarios = counterexample_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped = verdicts
        .iter()
        .find(|v| v.atom_id == "atom-shipped")
        .unwrap();
    assert_eq!(
        shipped.state,
        ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample
    );
    assert!(shipped.active_rule_ids.contains(&"rule-forbid".to_string()));
}

#[test]
fn test_evaluate_counterexample_produces_impossibility_certificate() {
    let contract = minimal_contract();
    let scenarios = counterexample_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let certs = &outputs.impossibility_certificates.evaluated_scenarios[0].certificates;
    assert!(!certs.is_empty());
    assert_eq!(certs[0].blocking_rule_id, "rule-forbid");
    assert_eq!(certs[0].atom_id, "atom-shipped");
}

#[test]
fn test_evaluate_counterexample_produces_ledger_entry() {
    let contract = minimal_contract();
    let scenarios = counterexample_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let entries = &outputs.claim_counterexample_ledger.evaluated_scenarios[0].entries;
    assert!(!entries.is_empty());
    assert_eq!(entries[0].blocking_rule_id, "rule-forbid");
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — missing constraint produces cutset
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_missing_constraint_produces_cutset() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "missing-constraint".to_string(),
            description: "evidence present but constraint not satisfied".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "compatibility_test_suite".to_string(),
                state: EvidenceState::Fresh,
                triggered_rule_ids: vec![],
            }],
            satisfied_constraints: vec![], // constraint-top NOT satisfied
            expected_outcomes: vec![],
        }],
    };
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let cutsets = &outputs.missing_evidence_cutsets.evaluated_scenarios[0].cutsets;
    let shipped_cutset = cutsets.iter().find(|c| c.atom_id == "atom-shipped");
    assert!(shipped_cutset.is_some());
    assert!(
        shipped_cutset
            .unwrap()
            .missing_constraint_ids
            .contains(&"constraint-top".to_string())
    );
}

// ---------------------------------------------------------------------------
// evaluate_scenarios — validation errors
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_rejects_unknown_evidence_kind() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "bad".to_string(),
            description: "bad evidence".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "nonexistent_suite".to_string(),
                state: EvidenceState::Fresh,
                triggered_rule_ids: vec![],
            }],
            satisfied_constraints: vec![],
            expected_outcomes: vec![],
        }],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("unknown evidence_kind")));
}

#[test]
fn test_evaluate_rejects_wrong_scenario_schema_version() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: "wrong".to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("scenario schema_version")));
}

// ---------------------------------------------------------------------------
// Output schema versions
// ---------------------------------------------------------------------------

#[test]
fn test_output_schema_versions() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    assert_eq!(
        outputs.claim_entitlement_report.schema_version,
        CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.missing_evidence_cutsets.schema_version,
        CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.impossibility_certificates.schema_version,
        CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION
    );
    assert_eq!(
        outputs.claim_counterexample_ledger.schema_version,
        CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrips for complex types
// ---------------------------------------------------------------------------

#[test]
fn test_contract_serde_roundtrip() {
    let contract = minimal_contract();
    let json = serde_json::to_string(&contract).unwrap();
    let back: ClaimEntitlementContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, contract);
}

#[test]
fn test_evaluation_outputs_serde_roundtrip() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let json = serde_json::to_string(&outputs).unwrap();
    let back: ClaimEvaluationOutputs = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outputs);
}

#[test]
fn test_scenario_set_serde_roundtrip() {
    let scenarios = minimal_scenario_set();
    let json = serde_json::to_string(&scenarios).unwrap();
    let back: ClaimEvaluationScenarioSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, scenarios);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_deterministic() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let out1 = serde_json::to_string(&contract.evaluate_scenarios(&scenarios).unwrap()).unwrap();
    let out2 = serde_json::to_string(&contract.evaluate_scenarios(&scenarios).unwrap()).unwrap();
    assert_eq!(out1, out2);
}

// ---------------------------------------------------------------------------
// Multi-scenario evaluation
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_multiple_scenarios() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![
            ClaimEvaluationScenario {
                scenario_id: "happy".to_string(),
                description: "happy path".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![ObservedEvidence {
                    evidence_kind: "compatibility_test_suite".to_string(),
                    state: EvidenceState::Fresh,
                    triggered_rule_ids: vec![],
                }],
                satisfied_constraints: vec!["constraint-top".to_string()],
                expected_outcomes: vec![],
            },
            ClaimEvaluationScenario {
                scenario_id: "sad".to_string(),
                description: "no evidence".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            },
        ],
    };
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    assert_eq!(
        outputs.claim_entitlement_report.evaluated_scenarios.len(),
        2
    );

    // First scenario: atom-shipped should be Entitled
    let v1 = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    let shipped1 = v1.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
    assert_eq!(shipped1.state, ClaimVerdictState::Entitled);

    // Second scenario: atom-shipped should be NotYetProven
    let v2 = &outputs.claim_entitlement_report.evaluated_scenarios[1].verdicts;
    let shipped2 = v2.iter().find(|v| v.atom_id == "atom-shipped").unwrap();
    assert_eq!(shipped2.state, ClaimVerdictState::NotYetProven);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_contract_with_multiple_morphisms() {
    let mut contract = minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morph-frontier".to_string(),
            evidence_kind: "compatibility_test_suite".to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec!["atom-frontier".to_string()],
            requires_side_constraints: vec![],
            blocked_by_rules: vec![],
            rationale: "frontier morphism".to_string(),
        });
    contract
        .validate()
        .expect("should validate with two morphisms");
}

#[test]
fn test_morphism_with_blocked_by_rules() {
    let mut contract = minimal_contract();
    contract.evidence_morphism_catalog.morphisms[0].blocked_by_rules =
        vec!["rule-forbid".to_string()];
    contract
        .validate()
        .expect("should validate with blocked_by_rules ref");
}

#[test]
fn test_disqualifier_with_downgrade_verdict() {
    let mut contract = minimal_contract();
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule-downgrade".to_string(),
        precedence: 2,
        evidence_kind: "counterexample_suite".to_string(),
        condition: "partial regression".to_string(),
        target_atoms: vec!["atom-shipped".to_string()],
        verdict: DisqualifierVerdict::DowngradeToScoped,
        remediation: "scope the claim".to_string(),
    });
    contract
        .disqualifier_rules
        .precedence_order
        .push("rule-downgrade".to_string());
    contract
        .validate()
        .expect("should validate with downgrade rule");
}

#[test]
fn test_clone_contract() {
    let contract = minimal_contract();
    let cloned = contract.clone();
    assert_eq!(contract, cloned);
}

#[test]
fn test_debug_contract() {
    let contract = minimal_contract();
    let dbg = format!("{contract:?}");
    assert!(dbg.contains("RGC-017"));
}

#[test]
fn test_contract_with_scoped_observed_atom() {
    let mut contract = minimal_contract();
    contract.claim_atom_catalog.atoms.push(ClaimAtom {
        atom_id: "atom-scoped".to_string(),
        domain: ClaimDomain::React,
        tier: ClaimTier::ScopedObserved,
        statement_class: "class-d".to_string(),
        surface: "react".to_string(),
        description: "scoped observed atom".to_string(),
        source_documents: vec!["doc-1".to_string()],
        owning_beads: vec!["bd-test-2".to_string()],
    });
    contract
        .validate()
        .expect("should validate with scoped atom");
}
