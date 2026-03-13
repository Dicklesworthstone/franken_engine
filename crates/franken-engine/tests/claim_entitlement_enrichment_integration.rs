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
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::claim_entitlement::{
    CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION, CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION, CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION,
    CLAIM_ENTITLEMENT_SCHEMA_VERSION, ClaimAtom, ClaimAtomCatalog, ClaimCounterexampleLedger,
    ClaimDomain, ClaimEntitlementContract, ClaimEntitlementReport, ClaimEvaluationScenario,
    ClaimEvaluationScenarioSet, ClaimTier, ClaimVerdict, ClaimVerdictState, ConstraintRelation,
    ContractTrack, CounterexampleLedgerEntry, DisqualifierRule, DisqualifierRuleSet,
    DisqualifierVerdict, EvidenceMorphism, EvidenceMorphismCatalog, EvidenceState,
    ExpectedClaimOutcome, ImpossibilityCertificate, ImpossibilityCertificateReport,
    MissingEvidenceCutset, MissingEvidenceCutsetReport, MorphismEffect, ObservedEvidence,
    ScenarioCounterexampleLedger, ScenarioImpossibilityCertificates,
    ScenarioMissingEvidenceCutsets, ScenarioVerdictReport, SideConstraint, SideConstraintLattice,
    lattice_has_cycle,
};

fn minimal_contract() -> ClaimEntitlementContract {
    ClaimEntitlementContract {
        schema_version: CLAIM_ENTITLEMENT_SCHEMA_VERSION.to_string(),
        contract_version: "v1".to_string(),
        bead_id: "bd-test".to_string(),
        generated_by: "test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        track: ContractTrack {
            id: "RGC-017".to_string(),
            name: "Claim Entitlement Algebra".to_string(),
        },
        required_artifacts: vec!["artifact-1".to_string()],
        required_structured_log_fields: vec!["field-1".to_string()],
        claim_atom_catalog: ClaimAtomCatalog {
            schema_version: "v1".to_string(),
            atoms: vec![
                ClaimAtom {
                    atom_id: "atom-shipped".to_string(),
                    domain: ClaimDomain::Compatibility,
                    tier: ClaimTier::ShippedFact,
                    statement_class: "class-a".to_string(),
                    surface: "compat".to_string(),
                    description: "shipped atom".to_string(),
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

// =========================================================================
// A. BTreeSet ordering and dedup for all enums with Ord
// =========================================================================

#[test]
fn enrichment_claim_domain_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ClaimDomain::Compatibility);
    set.insert(ClaimDomain::ShippedSurface);
    set.insert(ClaimDomain::React);
    set.insert(ClaimDomain::Supremacy);
    set.insert(ClaimDomain::Rollout);
    set.insert(ClaimDomain::Ga);
    set.insert(ClaimDomain::SupportSurface);
    set.insert(ClaimDomain::Compatibility); // duplicate
    set.insert(ClaimDomain::React); // duplicate
    assert_eq!(set.len(), 7);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_claim_tier_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ClaimTier::ShippedFact);
    set.insert(ClaimTier::ScopedObserved);
    set.insert(ClaimTier::FrontierAmbition);
    set.insert(ClaimTier::UnsupportedSurface);
    set.insert(ClaimTier::ShippedFact); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_morphism_effect_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(MorphismEffect::Supports);
    set.insert(MorphismEffect::Constrains);
    set.insert(MorphismEffect::Disqualifies);
    set.insert(MorphismEffect::Supports); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_disqualifier_verdict_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(DisqualifierVerdict::Forbid);
    set.insert(DisqualifierVerdict::DowngradeToScoped);
    set.insert(DisqualifierVerdict::DowngradeToTarget);
    set.insert(DisqualifierVerdict::RequireOperatorGuidance);
    set.insert(DisqualifierVerdict::Forbid); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_evidence_state_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(EvidenceState::Fresh);
    set.insert(EvidenceState::Stale);
    set.insert(EvidenceState::Fresh); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_claim_verdict_state_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ClaimVerdictState::Entitled);
    set.insert(ClaimVerdictState::NotYetProven);
    set.insert(ClaimVerdictState::BlockedByMissingEvidence);
    set.insert(ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample);
    set.insert(ClaimVerdictState::Entitled); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_enums() {
    assert!(!format!("{:?}", ClaimDomain::Compatibility).is_empty());
    assert!(!format!("{:?}", ClaimDomain::ShippedSurface).is_empty());
    assert!(!format!("{:?}", ClaimDomain::React).is_empty());
    assert!(!format!("{:?}", ClaimDomain::Supremacy).is_empty());
    assert!(!format!("{:?}", ClaimDomain::Rollout).is_empty());
    assert!(!format!("{:?}", ClaimDomain::Ga).is_empty());
    assert!(!format!("{:?}", ClaimDomain::SupportSurface).is_empty());
    assert!(!format!("{:?}", ClaimTier::ShippedFact).is_empty());
    assert!(!format!("{:?}", ClaimTier::ScopedObserved).is_empty());
    assert!(!format!("{:?}", ClaimTier::FrontierAmbition).is_empty());
    assert!(!format!("{:?}", ClaimTier::UnsupportedSurface).is_empty());
    assert!(!format!("{:?}", MorphismEffect::Supports).is_empty());
    assert!(!format!("{:?}", MorphismEffect::Constrains).is_empty());
    assert!(!format!("{:?}", MorphismEffect::Disqualifies).is_empty());
    assert!(!format!("{:?}", DisqualifierVerdict::Forbid).is_empty());
    assert!(!format!("{:?}", DisqualifierVerdict::DowngradeToScoped).is_empty());
    assert!(!format!("{:?}", DisqualifierVerdict::DowngradeToTarget).is_empty());
    assert!(!format!("{:?}", DisqualifierVerdict::RequireOperatorGuidance).is_empty());
    assert!(!format!("{:?}", EvidenceState::Fresh).is_empty());
    assert!(!format!("{:?}", EvidenceState::Stale).is_empty());
    assert!(!format!("{:?}", ClaimVerdictState::Entitled).is_empty());
    assert!(!format!("{:?}", ClaimVerdictState::NotYetProven).is_empty());
    assert!(!format!("{:?}", ClaimVerdictState::BlockedByMissingEvidence).is_empty());
    assert!(
        !format!(
            "{:?}",
            ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample
        )
        .is_empty()
    );
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let atom = ClaimAtom {
        atom_id: "a".to_string(),
        domain: ClaimDomain::Compatibility,
        tier: ClaimTier::ShippedFact,
        statement_class: "c".to_string(),
        surface: "s".to_string(),
        description: "d".to_string(),
        source_documents: vec![],
        owning_beads: vec![],
    };
    assert!(!format!("{atom:?}").is_empty());
    let morphism = EvidenceMorphism {
        morphism_id: "m".to_string(),
        evidence_kind: "k".to_string(),
        effect: MorphismEffect::Supports,
        target_atoms: vec![],
        requires_side_constraints: vec![],
        blocked_by_rules: vec![],
        rationale: "r".to_string(),
    };
    assert!(!format!("{morphism:?}").is_empty());
    let constraint = SideConstraint {
        constraint_id: "c".to_string(),
        constraint_class: "cc".to_string(),
        description: "d".to_string(),
    };
    assert!(!format!("{constraint:?}").is_empty());
    let relation = ConstraintRelation {
        lower_constraint_id: "lo".to_string(),
        higher_constraint_id: "hi".to_string(),
    };
    assert!(!format!("{relation:?}").is_empty());
    let rule = DisqualifierRule {
        rule_id: "r".to_string(),
        precedence: 1,
        evidence_kind: "e".to_string(),
        condition: "c".to_string(),
        target_atoms: vec![],
        verdict: DisqualifierVerdict::Forbid,
        remediation: "fix".to_string(),
    };
    assert!(!format!("{rule:?}").is_empty());
    let evidence = ObservedEvidence {
        evidence_kind: "k".to_string(),
        state: EvidenceState::Fresh,
        triggered_rule_ids: vec![],
    };
    assert!(!format!("{evidence:?}").is_empty());
    let outcome = ExpectedClaimOutcome {
        atom_id: "a".to_string(),
        state: ClaimVerdictState::Entitled,
        minimal_morphism_id: None,
        impossible_rule_id: None,
    };
    assert!(!format!("{outcome:?}").is_empty());
}

// =========================================================================
// C. Clone independence for complex structs
// =========================================================================

#[test]
fn enrichment_clone_independence_contract() {
    let contract = minimal_contract();
    let mut cloned = contract.clone();
    cloned.bead_id = "bd-modified".to_string();
    cloned.claim_atom_catalog.atoms[0].atom_id = "atom-changed".to_string();
    assert_eq!(contract.bead_id, "bd-test");
    assert_eq!(contract.claim_atom_catalog.atoms[0].atom_id, "atom-shipped");
}

#[test]
fn enrichment_clone_independence_scenario_set() {
    let scenarios = minimal_scenario_set();
    let mut cloned = scenarios.clone();
    cloned.scenarios[0].scenario_id = "modified".to_string();
    assert_eq!(scenarios.scenarios[0].scenario_id, "scenario-happy");
}

#[test]
fn enrichment_clone_independence_outputs() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let mut cloned = outputs.clone();
    cloned.claim_entitlement_report.contract_version = "modified".to_string();
    assert_eq!(outputs.claim_entitlement_report.contract_version, "v1");
}

// =========================================================================
// D. Serde roundtrips for individual intermediate structs
// =========================================================================

#[test]
fn enrichment_claim_atom_serde_roundtrip() {
    let atom = ClaimAtom {
        atom_id: "atom-test".to_string(),
        domain: ClaimDomain::React,
        tier: ClaimTier::ScopedObserved,
        statement_class: "class-x".to_string(),
        surface: "react".to_string(),
        description: "test atom".to_string(),
        source_documents: vec!["doc-a".to_string(), "doc-b".to_string()],
        owning_beads: vec!["bd-1".to_string()],
    };
    let json = serde_json::to_string(&atom).unwrap();
    let back: ClaimAtom = serde_json::from_str(&json).unwrap();
    assert_eq!(back, atom);
}

#[test]
fn enrichment_evidence_morphism_serde_roundtrip() {
    let morphism = EvidenceMorphism {
        morphism_id: "morph-test".to_string(),
        evidence_kind: "test_suite".to_string(),
        effect: MorphismEffect::Constrains,
        target_atoms: vec!["atom-a".to_string(), "atom-b".to_string()],
        requires_side_constraints: vec!["constraint-x".to_string()],
        blocked_by_rules: vec!["rule-y".to_string()],
        rationale: "test rationale".to_string(),
    };
    let json = serde_json::to_string(&morphism).unwrap();
    let back: EvidenceMorphism = serde_json::from_str(&json).unwrap();
    assert_eq!(back, morphism);
}

#[test]
fn enrichment_disqualifier_rule_serde_roundtrip() {
    let rule = DisqualifierRule {
        rule_id: "rule-test".to_string(),
        precedence: 42,
        evidence_kind: "counterexample_suite".to_string(),
        condition: "regression found".to_string(),
        target_atoms: vec!["atom-x".to_string()],
        verdict: DisqualifierVerdict::RequireOperatorGuidance,
        remediation: "ask operator".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: DisqualifierRule = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rule);
}

#[test]
fn enrichment_constraint_relation_serde_roundtrip() {
    let relation = ConstraintRelation {
        lower_constraint_id: "lo".to_string(),
        higher_constraint_id: "hi".to_string(),
    };
    let json = serde_json::to_string(&relation).unwrap();
    let back: ConstraintRelation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, relation);
}

#[test]
fn enrichment_observed_evidence_serde_roundtrip() {
    let evidence = ObservedEvidence {
        evidence_kind: "test_suite".to_string(),
        state: EvidenceState::Stale,
        triggered_rule_ids: vec!["rule-a".to_string(), "rule-b".to_string()],
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let back: ObservedEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evidence);
}

#[test]
fn enrichment_expected_claim_outcome_serde_roundtrip() {
    let outcome = ExpectedClaimOutcome {
        atom_id: "atom-test".to_string(),
        state: ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
        minimal_morphism_id: Some("morph-x".to_string()),
        impossible_rule_id: Some("rule-y".to_string()),
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: ExpectedClaimOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, outcome);
}

#[test]
fn enrichment_claim_verdict_serde_roundtrip() {
    let verdict = ClaimVerdict {
        atom_id: "atom-shipped".to_string(),
        state: ClaimVerdictState::Entitled,
        supporting_morphism_ids: vec!["morph-a".to_string()],
        active_rule_ids: vec![],
        minimal_cutset_ids: vec![],
        impossibility_certificate_ids: vec![],
    };
    let json = serde_json::to_string(&verdict).unwrap();
    let back: ClaimVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(back, verdict);
}

#[test]
fn enrichment_missing_evidence_cutset_serde_roundtrip() {
    let cutset = MissingEvidenceCutset {
        cutset_id: "cutset-1".to_string(),
        atom_id: "atom-shipped".to_string(),
        supporting_morphism_id: "morph-compat".to_string(),
        missing_evidence_kinds: vec!["test_suite".to_string()],
        missing_constraint_ids: vec!["constraint-top".to_string()],
        blocking_rule_ids: vec!["rule-forbid".to_string()],
        cost: 3,
    };
    let json = serde_json::to_string(&cutset).unwrap();
    let back: MissingEvidenceCutset = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cutset);
}

#[test]
fn enrichment_impossibility_certificate_serde_roundtrip() {
    let cert = ImpossibilityCertificate {
        certificate_id: "cert-1".to_string(),
        atom_id: "atom-shipped".to_string(),
        blocking_rule_id: "rule-forbid".to_string(),
        evidence_kind: "counterexample_suite".to_string(),
        remediation: "fix regression".to_string(),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: ImpossibilityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cert);
}

#[test]
fn enrichment_counterexample_ledger_entry_serde_roundtrip() {
    let entry = CounterexampleLedgerEntry {
        entry_id: "entry-1".to_string(),
        atom_id: "atom-shipped".to_string(),
        blocking_rule_id: "rule-forbid".to_string(),
        evidence_kind: "counterexample_suite".to_string(),
        remediation: "fix regression".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: CounterexampleLedgerEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// =========================================================================
// E. Lattice edge cases
// =========================================================================

#[test]
fn enrichment_lattice_diamond_no_cycle() {
    // Diamond: top -> left, top -> right, left -> bottom, right -> bottom
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "top".to_string(),
        bottom_constraint_id: "bottom".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "top".into(),
                constraint_class: "t".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "left".into(),
                constraint_class: "l".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "right".into(),
                constraint_class: "r".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "bottom".into(),
                constraint_class: "b".into(),
                description: String::new(),
            },
        ],
        cover_relations: vec![
            ConstraintRelation {
                lower_constraint_id: "left".into(),
                higher_constraint_id: "top".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "right".into(),
                higher_constraint_id: "top".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "bottom".into(),
                higher_constraint_id: "left".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "bottom".into(),
                higher_constraint_id: "right".into(),
            },
        ],
    };
    assert!(!lattice_has_cycle(&lattice));
}

#[test]
fn enrichment_lattice_three_node_cycle() {
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "a".to_string(),
        bottom_constraint_id: "c".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "a".into(),
                constraint_class: "x".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "b".into(),
                constraint_class: "x".into(),
                description: String::new(),
            },
            SideConstraint {
                constraint_id: "c".into(),
                constraint_class: "x".into(),
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
                higher_constraint_id: "c".into(),
            },
            ConstraintRelation {
                lower_constraint_id: "c".into(),
                higher_constraint_id: "a".into(),
            },
        ],
    };
    assert!(lattice_has_cycle(&lattice));
}

// =========================================================================
// F. Validation: morphism references unknown rule in blocked_by_rules
// =========================================================================

#[test]
fn enrichment_validate_rejects_morphism_unknown_blocked_rule() {
    let mut contract = minimal_contract();
    contract.evidence_morphism_catalog.morphisms[0]
        .blocked_by_rules
        .push("nonexistent-rule".to_string());
    let errors = contract.validate().expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unknown disqualifier rule"))
    );
}

// =========================================================================
// G. Validation: disqualifier rule references unknown atom
// =========================================================================

#[test]
fn enrichment_validate_rejects_disqualifier_rule_unknown_atom() {
    let mut contract = minimal_contract();
    contract.disqualifier_rules.rules[0]
        .target_atoms
        .push("atom-nonexistent".to_string());
    let errors = contract.validate().expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unknown atom") && e.contains("rule-forbid"))
    );
}

// =========================================================================
// H. Scenario validation: duplicate scenario IDs
// =========================================================================

#[test]
fn enrichment_evaluate_rejects_duplicate_scenario_ids() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![
            ClaimEvaluationScenario {
                scenario_id: "dup-id".to_string(),
                description: "first".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            },
            ClaimEvaluationScenario {
                scenario_id: "dup-id".to_string(),
                description: "second".to_string(),
                evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
                observed_evidence: vec![],
                satisfied_constraints: vec![],
                expected_outcomes: vec![],
            },
        ],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("duplicate") && e.contains("dup-id"))
    );
}

// =========================================================================
// I. Scenario validation: unknown satisfied constraint
// =========================================================================

#[test]
fn enrichment_evaluate_rejects_unknown_satisfied_constraint() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "bad-constraint".to_string(),
            description: "unknown constraint".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![],
            satisfied_constraints: vec!["constraint-nonexistent".to_string()],
            expected_outcomes: vec![],
        }],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unknown satisfied constraint"))
    );
}

// =========================================================================
// J. Scenario validation: expected outcome references unknown atom
// =========================================================================

#[test]
fn enrichment_evaluate_rejects_unknown_expected_atom() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "bad-expected".to_string(),
            description: "unknown expected atom".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![],
            satisfied_constraints: vec![],
            expected_outcomes: vec![ExpectedClaimOutcome {
                atom_id: "atom-nonexistent".to_string(),
                state: ClaimVerdictState::Entitled,
                minimal_morphism_id: None,
                impossible_rule_id: None,
            }],
        }],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(errors.iter().any(|e| e.contains("unknown expected atom")));
}

// =========================================================================
// K. Scenario validation: expected outcome references unknown morphism
// =========================================================================

#[test]
fn enrichment_evaluate_rejects_unknown_expected_morphism() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "bad-morph".to_string(),
            description: "unknown expected morphism".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![],
            satisfied_constraints: vec![],
            expected_outcomes: vec![ExpectedClaimOutcome {
                atom_id: "atom-shipped".to_string(),
                state: ClaimVerdictState::Entitled,
                minimal_morphism_id: Some("morph-nonexistent".to_string()),
                impossible_rule_id: None,
            }],
        }],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unknown expected morphism"))
    );
}

// =========================================================================
// L. Scenario validation: triggered unknown rule
// =========================================================================

#[test]
fn enrichment_evaluate_rejects_unknown_triggered_rule() {
    let contract = minimal_contract();
    let scenarios = ClaimEvaluationScenarioSet {
        schema_version: CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION.to_string(),
        scenario_version: "v1".to_string(),
        scenarios: vec![ClaimEvaluationScenario {
            scenario_id: "bad-trigger".to_string(),
            description: "unknown triggered rule".to_string(),
            evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            observed_evidence: vec![ObservedEvidence {
                evidence_kind: "counterexample_suite".to_string(),
                state: EvidenceState::Fresh,
                triggered_rule_ids: vec!["rule-nonexistent".to_string()],
            }],
            satisfied_constraints: vec![],
            expected_outcomes: vec![],
        }],
    };
    let errors = contract
        .evaluate_scenarios(&scenarios)
        .expect_err("should fail");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("unknown rule") && e.contains("rule-nonexistent"))
    );
}

// =========================================================================
// M. Multiple validation errors accumulate
// =========================================================================

#[test]
fn enrichment_validate_accumulates_multiple_errors() {
    let mut contract = minimal_contract();
    contract.schema_version = "wrong".to_string();
    contract.track.id = "RGC-999".to_string();
    let errors = contract.validate().expect_err("should fail");
    assert!(errors.len() >= 2);
    assert!(errors.iter().any(|e| e.contains("schema_version")));
    assert!(errors.iter().any(|e| e.contains("track id")));
}

// =========================================================================
// N. Full report struct serde roundtrips
// =========================================================================

#[test]
fn enrichment_scenario_verdict_report_serde_roundtrip() {
    let report = ScenarioVerdictReport {
        scenario_id: "s1".to_string(),
        evaluated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        verdicts: vec![ClaimVerdict {
            atom_id: "atom-shipped".to_string(),
            state: ClaimVerdictState::NotYetProven,
            supporting_morphism_ids: vec![],
            active_rule_ids: vec![],
            minimal_cutset_ids: vec![],
            impossibility_certificate_ids: vec![],
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ScenarioVerdictReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn enrichment_claim_entitlement_report_serde_roundtrip() {
    let report = ClaimEntitlementReport {
        schema_version: CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION.to_string(),
        contract_version: "v1".to_string(),
        evaluated_scenarios: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ClaimEntitlementReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn enrichment_missing_evidence_cutset_report_serde_roundtrip() {
    let report = MissingEvidenceCutsetReport {
        schema_version: CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION.to_string(),
        contract_version: "v1".to_string(),
        evaluated_scenarios: vec![ScenarioMissingEvidenceCutsets {
            scenario_id: "s1".to_string(),
            cutsets: vec![],
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: MissingEvidenceCutsetReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn enrichment_impossibility_certificate_report_serde_roundtrip() {
    let report = ImpossibilityCertificateReport {
        schema_version: CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION.to_string(),
        contract_version: "v1".to_string(),
        evaluated_scenarios: vec![ScenarioImpossibilityCertificates {
            scenario_id: "s1".to_string(),
            certificates: vec![],
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: ImpossibilityCertificateReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
}

#[test]
fn enrichment_claim_counterexample_ledger_serde_roundtrip() {
    let ledger = ClaimCounterexampleLedger {
        schema_version: CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION.to_string(),
        contract_version: "v1".to_string(),
        evaluated_scenarios: vec![ScenarioCounterexampleLedger {
            scenario_id: "s1".to_string(),
            entries: vec![],
        }],
    };
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ClaimCounterexampleLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ledger);
}

// =========================================================================
// O. Contract with multiple disqualifier rules at different precedences
// =========================================================================

#[test]
fn enrichment_contract_multiple_disqualifier_rules_validates() {
    let mut contract = minimal_contract();
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule-downgrade".to_string(),
        precedence: 2,
        evidence_kind: "counterexample_suite".to_string(),
        condition: "partial regression".to_string(),
        target_atoms: vec!["atom-shipped".to_string()],
        verdict: DisqualifierVerdict::DowngradeToTarget,
        remediation: "scope the claim".to_string(),
    });
    contract.disqualifier_rules.rules.push(DisqualifierRule {
        rule_id: "rule-guidance".to_string(),
        precedence: 3,
        evidence_kind: "counterexample_suite".to_string(),
        condition: "ambiguous regression".to_string(),
        target_atoms: vec!["atom-frontier".to_string()],
        verdict: DisqualifierVerdict::RequireOperatorGuidance,
        remediation: "ask operator".to_string(),
    });
    contract.disqualifier_rules.precedence_order = vec![
        "rule-forbid".to_string(),
        "rule-downgrade".to_string(),
        "rule-guidance".to_string(),
    ];
    contract
        .validate()
        .expect("should validate with three rules");
}

// =========================================================================
// P. Evaluation with multiple morphisms targeting same atom
// =========================================================================

#[test]
fn enrichment_evaluate_multiple_morphisms_same_atom() {
    let mut contract = minimal_contract();
    contract
        .evidence_morphism_catalog
        .morphisms
        .push(EvidenceMorphism {
            morphism_id: "morph-extra".to_string(),
            evidence_kind: "compatibility_test_suite".to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec!["atom-shipped".to_string()],
            requires_side_constraints: vec![],
            blocked_by_rules: vec![],
            rationale: "extra evidence".to_string(),
        });
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
    // Both morphisms should appear as supporting
    assert!(shipped.supporting_morphism_ids.len() >= 2);
}

// =========================================================================
// Q. Atom with populated source_documents and owning_beads roundtrip
// =========================================================================

#[test]
fn enrichment_atom_with_metadata_serde_roundtrip() {
    let atom = ClaimAtom {
        atom_id: "atom-meta".to_string(),
        domain: ClaimDomain::Rollout,
        tier: ClaimTier::ScopedObserved,
        statement_class: "class-meta".to_string(),
        surface: "rollout".to_string(),
        description: "atom with metadata".to_string(),
        source_documents: vec![
            "doc-1".to_string(),
            "doc-2".to_string(),
            "doc-3".to_string(),
        ],
        owning_beads: vec!["bd-a".to_string(), "bd-b".to_string()],
    };
    let json = serde_json::to_string(&atom).unwrap();
    let back: ClaimAtom = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source_documents.len(), 3);
    assert_eq!(back.owning_beads.len(), 2);
    assert_eq!(back, atom);
}

// =========================================================================
// R. Copy semantics for enums
// =========================================================================

#[test]
fn enrichment_enum_copy_semantics() {
    let domain = ClaimDomain::React;
    let copy = domain;
    assert_eq!(domain, copy); // original still valid after copy

    let tier = ClaimTier::FrontierAmbition;
    let copy = tier;
    assert_eq!(tier, copy);

    let effect = MorphismEffect::Disqualifies;
    let copy = effect;
    assert_eq!(effect, copy);

    let verdict = DisqualifierVerdict::DowngradeToScoped;
    let copy = verdict;
    assert_eq!(verdict, copy);

    let state = EvidenceState::Stale;
    let copy = state;
    assert_eq!(state, copy);

    let vstate = ClaimVerdictState::BlockedByMissingEvidence;
    let copy = vstate;
    assert_eq!(vstate, copy);
}

// =========================================================================
// S. Evaluation outputs all atoms for each scenario
// =========================================================================

#[test]
fn enrichment_evaluate_outputs_all_atoms_per_scenario() {
    let contract = minimal_contract();
    let scenarios = minimal_scenario_set();
    let outputs = contract
        .evaluate_scenarios(&scenarios)
        .expect("should succeed");
    let verdicts = &outputs.claim_entitlement_report.evaluated_scenarios[0].verdicts;
    // Contract has 3 atoms, so verdicts should have at least 3 entries
    assert!(verdicts.len() >= 3);
    let atom_ids: BTreeSet<_> = verdicts.iter().map(|v| v.atom_id.as_str()).collect();
    assert!(atom_ids.contains("atom-shipped"));
    assert!(atom_ids.contains("atom-frontier"));
    assert!(atom_ids.contains("atom-unsupported"));
}

// =========================================================================
// T. Schema version constants are distinct
// =========================================================================

#[test]
fn enrichment_schema_version_constants_distinct() {
    let versions = [
        CLAIM_ENTITLEMENT_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_SCENARIO_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_REPORT_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_CUTSET_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_IMPOSSIBILITY_SCHEMA_VERSION,
        CLAIM_ENTITLEMENT_COUNTEREXAMPLE_LEDGER_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<_> = versions.iter().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "all schema versions must be distinct"
    );
}

// =========================================================================
// U. SideConstraintLattice serde roundtrip
// =========================================================================

#[test]
fn enrichment_side_constraint_lattice_serde_roundtrip() {
    let lattice = SideConstraintLattice {
        schema_version: "v1".to_string(),
        top_constraint_id: "top".to_string(),
        bottom_constraint_id: "bottom".to_string(),
        constraints: vec![
            SideConstraint {
                constraint_id: "top".to_string(),
                constraint_class: "universal".to_string(),
                description: "top".to_string(),
            },
            SideConstraint {
                constraint_id: "bottom".to_string(),
                constraint_class: "minimal".to_string(),
                description: "bottom".to_string(),
            },
        ],
        cover_relations: vec![ConstraintRelation {
            lower_constraint_id: "bottom".to_string(),
            higher_constraint_id: "top".to_string(),
        }],
    };
    let json = serde_json::to_string(&lattice).unwrap();
    let back: SideConstraintLattice = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lattice);
}

// =========================================================================
// V. DisqualifierRuleSet serde roundtrip
// =========================================================================

#[test]
fn enrichment_disqualifier_rule_set_serde_roundtrip() {
    let rule_set = DisqualifierRuleSet {
        schema_version: "v1".to_string(),
        precedence_order: vec!["rule-a".to_string(), "rule-b".to_string()],
        rules: vec![
            DisqualifierRule {
                rule_id: "rule-a".to_string(),
                precedence: 1,
                evidence_kind: "k".to_string(),
                condition: "c".to_string(),
                target_atoms: vec![],
                verdict: DisqualifierVerdict::Forbid,
                remediation: "fix".to_string(),
            },
            DisqualifierRule {
                rule_id: "rule-b".to_string(),
                precedence: 2,
                evidence_kind: "k".to_string(),
                condition: "c".to_string(),
                target_atoms: vec![],
                verdict: DisqualifierVerdict::DowngradeToScoped,
                remediation: "scope".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&rule_set).unwrap();
    let back: DisqualifierRuleSet = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rule_set);
}
