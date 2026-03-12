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

use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;

const ALGEBRA_JSON: &str = include_str!("../../../docs/rgc_claim_entitlement_algebra_v1.json");

// --- Top-level contract ---

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ClaimEntitlementAlgebra {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    required_artifacts: Vec<String>,
    required_structured_log_fields: Vec<String>,
    claim_atom_catalog: ClaimAtomCatalog,
    evidence_morphism_catalog: EvidenceMorphismCatalog,
    side_constraint_lattice: SideConstraintLattice,
    disqualifier_rules: DisqualifierRules,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

// --- Claim Atom Catalog ---

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ClaimAtomCatalog {
    schema_version: String,
    atoms: Vec<ClaimAtom>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ClaimAtom {
    atom_id: String,
    domain: String,
    tier: String,
    statement_class: String,
    surface: String,
    description: String,
    source_documents: Vec<String>,
    owning_beads: Vec<String>,
}

// --- Evidence Morphism Catalog ---

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceMorphismCatalog {
    schema_version: String,
    morphisms: Vec<EvidenceMorphism>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceMorphism {
    morphism_id: String,
    evidence_kind: String,
    effect: String,
    target_atoms: Vec<String>,
    requires_side_constraints: Vec<String>,
    blocked_by_rules: Vec<String>,
    rationale: String,
}

// --- Side Constraint Lattice ---

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SideConstraintLattice {
    schema_version: String,
    top_constraint_id: String,
    bottom_constraint_id: String,
    constraints: Vec<SideConstraint>,
    cover_relations: Vec<CoverRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SideConstraint {
    constraint_id: String,
    constraint_class: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CoverRelation {
    lower_constraint_id: String,
    higher_constraint_id: String,
}

// --- Disqualifier Rules ---

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DisqualifierRules {
    schema_version: String,
    precedence_order: Vec<String>,
    rules: Vec<DisqualifierRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct DisqualifierRule {
    rule_id: String,
    precedence: u64,
    evidence_kind: String,
    condition: String,
    target_atoms: Vec<String>,
    verdict: String,
    remediation: String,
}

fn parse_algebra() -> ClaimEntitlementAlgebra {
    serde_json::from_str(ALGEBRA_JSON).expect("claim entitlement algebra must parse")
}

// ===== Top-level contract tests =====

#[test]
fn parses_with_expected_schema_version() {
    let a = parse_algebra();
    assert_eq!(
        a.schema_version,
        "franken-engine.rgc-claim-entitlement-algebra.v1"
    );
}

#[test]
fn contract_version_is_semver() {
    let a = parse_algebra();
    let parts: Vec<&str> = a.contract_version.split('.').collect();
    assert_eq!(parts.len(), 3, "contract_version must be semver");
    for part in &parts {
        assert!(
            part.parse::<u32>().is_ok(),
            "contract_version segment must be numeric: {part}"
        );
    }
}

#[test]
fn bead_id_and_generated_by_are_valid() {
    let a = parse_algebra();
    assert!(a.bead_id.starts_with("bd-"), "bead_id must start with bd-");
    assert!(
        a.generated_by.starts_with("bd-"),
        "generated_by must start with bd-"
    );
}

#[test]
fn generated_at_utc_is_iso8601() {
    let a = parse_algebra();
    assert!(
        a.generated_at_utc.ends_with('Z'),
        "generated_at_utc must end with Z"
    );
    assert!(
        a.generated_at_utc.contains('T'),
        "generated_at_utc must contain T separator"
    );
    assert!(
        a.generated_at_utc.len() >= 20,
        "generated_at_utc must be full ISO-8601"
    );
}

#[test]
fn track_has_rgc_prefix_id() {
    let a = parse_algebra();
    assert!(
        a.track.id.starts_with("RGC-"),
        "track.id must start with RGC-: {}",
        a.track.id
    );
    assert!(
        !a.track.name.trim().is_empty(),
        "track.name must not be empty"
    );
}

#[test]
fn required_artifacts_include_standard_rgc_set() {
    let a = parse_algebra();
    let artifacts: BTreeSet<&str> = a.required_artifacts.iter().map(String::as_str).collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn required_artifacts_are_unique() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for artifact in &a.required_artifacts {
        assert!(
            seen.insert(artifact.clone()),
            "duplicate artifact: {artifact}"
        );
    }
}

#[test]
fn required_artifacts_count() {
    let a = parse_algebra();
    assert_eq!(
        a.required_artifacts.len(),
        11,
        "must have exactly 11 required artifacts"
    );
}

#[test]
fn required_structured_log_fields_include_traceability() {
    let a = parse_algebra();
    let fields: BTreeSet<&str> = a
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    for required in [
        "trace_id",
        "decision_id",
        "policy_id",
        "schema_version",
        "scenario_id",
    ] {
        assert!(fields.contains(required), "missing log field: {required}");
    }
}

#[test]
fn required_structured_log_fields_are_unique_and_snake_case() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for field in &a.required_structured_log_fields {
        assert!(
            field
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "log field must be snake_case: {field}"
        );
        assert!(seen.insert(field.clone()), "duplicate log field: {field}");
    }
}

#[test]
fn operator_verification_is_nonempty() {
    let a = parse_algebra();
    assert!(
        !a.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
    for cmd in &a.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator verification command must not be empty"
        );
    }
}

#[test]
fn operator_verification_references_algebra_contract() {
    let a = parse_algebra();
    assert!(
        a.operator_verification
            .iter()
            .any(|cmd| cmd.contains("claim_entitlement_algebra")),
        "operator verification must reference claim_entitlement_algebra"
    );
}

// ===== Claim Atom Catalog tests =====

#[test]
fn atom_catalog_has_expected_schema() {
    let a = parse_algebra();
    assert_eq!(
        a.claim_atom_catalog.schema_version,
        "franken-engine.rgc-claim-atom-catalog.v1"
    );
}

#[test]
fn atom_count_is_13() {
    let a = parse_algebra();
    assert_eq!(
        a.claim_atom_catalog.atoms.len(),
        13,
        "must have exactly 13 claim atoms"
    );
}

#[test]
fn atom_ids_are_unique() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            seen.insert(atom.atom_id.clone()),
            "duplicate atom_id: {}",
            atom.atom_id
        );
    }
}

#[test]
fn atom_ids_follow_claim_dot_prefix() {
    let a = parse_algebra();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            atom.atom_id.starts_with("claim."),
            "atom_id must start with claim.: {}",
            atom.atom_id
        );
    }
}

#[test]
fn atom_tiers_from_known_set() {
    let a = parse_algebra();
    let known: BTreeSet<&str> = [
        "shipped_fact",
        "frontier_ambition",
        "unsupported_surface",
        "scoped_observed",
    ]
    .into_iter()
    .collect();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            known.contains(atom.tier.as_str()),
            "unknown tier '{}' for {}",
            atom.tier,
            atom.atom_id
        );
    }
}

#[test]
fn atom_domains_are_diverse() {
    let a = parse_algebra();
    let domains: BTreeSet<&str> = a
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.domain.as_str())
        .collect();
    assert!(
        domains.len() >= 4,
        "must have at least 4 distinct domains, got {}",
        domains.len()
    );
}

#[test]
fn atom_source_documents_are_nonempty() {
    let a = parse_algebra();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            !atom.source_documents.is_empty(),
            "atom {} must have at least one source document",
            atom.atom_id
        );
    }
}

#[test]
fn atom_owning_beads_reference_beads() {
    let a = parse_algebra();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            !atom.owning_beads.is_empty(),
            "atom {} must have at least one owning bead",
            atom.atom_id
        );
        for bead in &atom.owning_beads {
            assert!(
                bead.starts_with("bd-"),
                "owning_bead must start with bd-: {} in {}",
                bead,
                atom.atom_id
            );
        }
    }
}

#[test]
fn atom_descriptions_are_nonempty() {
    let a = parse_algebra();
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            !atom.description.trim().is_empty(),
            "atom {} must have a nonempty description",
            atom.atom_id
        );
    }
}

#[test]
fn shipped_fact_atoms_have_shipped_surface_or_rollout_domain() {
    let a = parse_algebra();
    for atom in &a.claim_atom_catalog.atoms {
        if atom.tier == "shipped_fact" {
            assert!(
                atom.domain == "shipped_surface"
                    || atom.domain == "rollout"
                    || atom.domain == "support_surface",
                "shipped_fact atom {} should be in shipped_surface/rollout/support_surface domain, got {}",
                atom.atom_id,
                atom.domain
            );
        }
    }
}

// ===== Evidence Morphism Catalog tests =====

#[test]
fn morphism_catalog_has_expected_schema() {
    let a = parse_algebra();
    assert_eq!(
        a.evidence_morphism_catalog.schema_version,
        "franken-engine.rgc-evidence-morphism-catalog.v1"
    );
}

#[test]
fn morphism_count_is_8() {
    let a = parse_algebra();
    assert_eq!(
        a.evidence_morphism_catalog.morphisms.len(),
        8,
        "must have exactly 8 evidence morphisms"
    );
}

#[test]
fn morphism_ids_are_unique() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for m in &a.evidence_morphism_catalog.morphisms {
        assert!(
            seen.insert(m.morphism_id.clone()),
            "duplicate morphism_id: {}",
            m.morphism_id
        );
    }
}

#[test]
fn morphism_ids_follow_morphism_dot_prefix() {
    let a = parse_algebra();
    for m in &a.evidence_morphism_catalog.morphisms {
        assert!(
            m.morphism_id.starts_with("morphism."),
            "morphism_id must start with morphism.: {}",
            m.morphism_id
        );
    }
}

#[test]
fn morphism_effects_from_known_set() {
    let a = parse_algebra();
    let known: BTreeSet<&str> = ["supports", "constrains", "disqualifies"]
        .into_iter()
        .collect();
    for m in &a.evidence_morphism_catalog.morphisms {
        assert!(
            known.contains(m.effect.as_str()),
            "unknown effect '{}' for {}",
            m.effect,
            m.morphism_id
        );
    }
}

#[test]
fn morphism_target_atoms_reference_existing_atoms() {
    let a = parse_algebra();
    let atom_ids: BTreeSet<&str> = a
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.atom_id.as_str())
        .collect();
    for m in &a.evidence_morphism_catalog.morphisms {
        for target in &m.target_atoms {
            assert!(
                atom_ids.contains(target.as_str()),
                "morphism {} references unknown atom: {}",
                m.morphism_id,
                target
            );
        }
    }
}

#[test]
fn morphism_side_constraints_reference_existing_constraints() {
    let a = parse_algebra();
    let constraint_ids: BTreeSet<&str> = a
        .side_constraint_lattice
        .constraints
        .iter()
        .map(|c| c.constraint_id.as_str())
        .collect();
    for m in &a.evidence_morphism_catalog.morphisms {
        for sc in &m.requires_side_constraints {
            assert!(
                constraint_ids.contains(sc.as_str()),
                "morphism {} references unknown constraint: {}",
                m.morphism_id,
                sc
            );
        }
    }
}

#[test]
fn morphism_blocked_by_rules_reference_existing_rules() {
    let a = parse_algebra();
    let rule_ids: BTreeSet<&str> = a
        .disqualifier_rules
        .rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    for m in &a.evidence_morphism_catalog.morphisms {
        for rule in &m.blocked_by_rules {
            assert!(
                rule_ids.contains(rule.as_str()),
                "morphism {} references unknown rule: {}",
                m.morphism_id,
                rule
            );
        }
    }
}

#[test]
fn morphism_rationales_are_nonempty() {
    let a = parse_algebra();
    for m in &a.evidence_morphism_catalog.morphisms {
        assert!(
            !m.rationale.trim().is_empty(),
            "morphism {} must have a nonempty rationale",
            m.morphism_id
        );
    }
}

#[test]
fn exactly_one_disqualifies_morphism() {
    let a = parse_algebra();
    let count = a
        .evidence_morphism_catalog
        .morphisms
        .iter()
        .filter(|m| m.effect == "disqualifies")
        .count();
    assert_eq!(
        count, 1,
        "must have exactly 1 disqualifies morphism, got {count}"
    );
}

// ===== Side Constraint Lattice tests =====

#[test]
fn lattice_has_expected_schema() {
    let a = parse_algebra();
    assert_eq!(
        a.side_constraint_lattice.schema_version,
        "franken-engine.rgc-side-constraint-lattice.v1"
    );
}

#[test]
fn lattice_constraint_count_is_9() {
    let a = parse_algebra();
    assert_eq!(
        a.side_constraint_lattice.constraints.len(),
        9,
        "must have exactly 9 constraints"
    );
}

#[test]
fn lattice_constraint_ids_are_unique() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for c in &a.side_constraint_lattice.constraints {
        assert!(
            seen.insert(c.constraint_id.clone()),
            "duplicate constraint_id: {}",
            c.constraint_id
        );
    }
}

#[test]
fn lattice_constraint_ids_follow_constraint_dot_prefix() {
    let a = parse_algebra();
    for c in &a.side_constraint_lattice.constraints {
        assert!(
            c.constraint_id.starts_with("constraint."),
            "constraint_id must start with constraint.: {}",
            c.constraint_id
        );
    }
}

#[test]
fn lattice_top_and_bottom_are_declared_constraints() {
    let a = parse_algebra();
    let ids: BTreeSet<&str> = a
        .side_constraint_lattice
        .constraints
        .iter()
        .map(|c| c.constraint_id.as_str())
        .collect();
    assert!(
        ids.contains(a.side_constraint_lattice.top_constraint_id.as_str()),
        "top_constraint_id must be a declared constraint"
    );
    assert!(
        ids.contains(a.side_constraint_lattice.bottom_constraint_id.as_str()),
        "bottom_constraint_id must be a declared constraint"
    );
}

#[test]
fn lattice_top_is_not_bottom() {
    let a = parse_algebra();
    assert_ne!(
        a.side_constraint_lattice.top_constraint_id, a.side_constraint_lattice.bottom_constraint_id,
        "top and bottom must differ"
    );
}

#[test]
fn lattice_cover_relations_reference_declared_constraints() {
    let a = parse_algebra();
    let ids: BTreeSet<&str> = a
        .side_constraint_lattice
        .constraints
        .iter()
        .map(|c| c.constraint_id.as_str())
        .collect();
    for rel in &a.side_constraint_lattice.cover_relations {
        assert!(
            ids.contains(rel.lower_constraint_id.as_str()),
            "cover relation references unknown lower: {}",
            rel.lower_constraint_id
        );
        assert!(
            ids.contains(rel.higher_constraint_id.as_str()),
            "cover relation references unknown higher: {}",
            rel.higher_constraint_id
        );
    }
}

#[test]
fn lattice_cover_relations_are_irreflexive() {
    let a = parse_algebra();
    for rel in &a.side_constraint_lattice.cover_relations {
        assert_ne!(
            rel.lower_constraint_id, rel.higher_constraint_id,
            "cover relation must be irreflexive: {}",
            rel.lower_constraint_id
        );
    }
}

#[test]
fn lattice_bottom_has_no_incoming_cover() {
    let a = parse_algebra();
    let bottom = &a.side_constraint_lattice.bottom_constraint_id;
    for rel in &a.side_constraint_lattice.cover_relations {
        assert_ne!(
            &rel.higher_constraint_id, bottom,
            "bottom constraint must not appear as higher in a cover relation"
        );
    }
}

#[test]
fn lattice_top_has_no_outgoing_cover() {
    let a = parse_algebra();
    let top = &a.side_constraint_lattice.top_constraint_id;
    for rel in &a.side_constraint_lattice.cover_relations {
        assert_ne!(
            &rel.lower_constraint_id, top,
            "top constraint must not appear as lower in a cover relation"
        );
    }
}

#[test]
fn lattice_constraint_classes_are_diverse() {
    let a = parse_algebra();
    let classes: BTreeSet<&str> = a
        .side_constraint_lattice
        .constraints
        .iter()
        .map(|c| c.constraint_class.as_str())
        .collect();
    assert!(
        classes.len() >= 3,
        "must have at least 3 distinct constraint classes, got {}",
        classes.len()
    );
}

// ===== Disqualifier Rules tests =====

#[test]
fn disqualifier_rules_has_expected_schema() {
    let a = parse_algebra();
    assert_eq!(
        a.disqualifier_rules.schema_version,
        "franken-engine.rgc-disqualifier-rules.v1"
    );
}

#[test]
fn disqualifier_rule_count_is_7() {
    let a = parse_algebra();
    assert_eq!(
        a.disqualifier_rules.rules.len(),
        7,
        "must have exactly 7 disqualifier rules"
    );
}

#[test]
fn disqualifier_rule_ids_are_unique() {
    let a = parse_algebra();
    let mut seen = BTreeSet::new();
    for r in &a.disqualifier_rules.rules {
        assert!(
            seen.insert(r.rule_id.clone()),
            "duplicate rule_id: {}",
            r.rule_id
        );
    }
}

#[test]
fn disqualifier_rule_ids_follow_rule_dot_prefix() {
    let a = parse_algebra();
    for r in &a.disqualifier_rules.rules {
        assert!(
            r.rule_id.starts_with("rule."),
            "rule_id must start with rule.: {}",
            r.rule_id
        );
    }
}

#[test]
fn disqualifier_precedences_are_contiguous_from_zero() {
    let a = parse_algebra();
    let mut precedences: Vec<u64> = a
        .disqualifier_rules
        .rules
        .iter()
        .map(|r| r.precedence)
        .collect();
    precedences.sort();
    for (i, prec) in precedences.iter().enumerate() {
        assert_eq!(
            *prec, i as u64,
            "precedences must be contiguous from 0: expected {i}, got {prec}"
        );
    }
}

#[test]
fn disqualifier_precedence_order_matches_rules() {
    let a = parse_algebra();
    assert_eq!(
        a.disqualifier_rules.precedence_order.len(),
        a.disqualifier_rules.rules.len(),
        "precedence_order length must match rules length"
    );
    for (i, rule_id) in a.disqualifier_rules.precedence_order.iter().enumerate() {
        let rule = a
            .disqualifier_rules
            .rules
            .iter()
            .find(|r| &r.rule_id == rule_id)
            .unwrap_or_else(|| panic!("precedence_order references unknown rule: {rule_id}"));
        assert_eq!(
            rule.precedence, i as u64,
            "rule {} precedence mismatch: order index {i}, got {}",
            rule_id, rule.precedence
        );
    }
}

#[test]
fn disqualifier_verdicts_from_known_set() {
    let a = parse_algebra();
    let known: BTreeSet<&str> = [
        "forbid",
        "downgrade_to_target",
        "downgrade_to_scoped",
        "require_operator_guidance",
    ]
    .into_iter()
    .collect();
    for r in &a.disqualifier_rules.rules {
        assert!(
            known.contains(r.verdict.as_str()),
            "unknown verdict '{}' for {}",
            r.verdict,
            r.rule_id
        );
    }
}

#[test]
fn disqualifier_target_atoms_reference_existing_atoms() {
    let a = parse_algebra();
    let atom_ids: BTreeSet<&str> = a
        .claim_atom_catalog
        .atoms
        .iter()
        .map(|atom| atom.atom_id.as_str())
        .collect();
    for r in &a.disqualifier_rules.rules {
        for target in &r.target_atoms {
            assert!(
                atom_ids.contains(target.as_str()),
                "rule {} references unknown atom: {}",
                r.rule_id,
                target
            );
        }
    }
}

#[test]
fn disqualifier_conditions_are_nonempty() {
    let a = parse_algebra();
    for r in &a.disqualifier_rules.rules {
        assert!(
            !r.condition.trim().is_empty(),
            "rule {} must have a nonempty condition",
            r.rule_id
        );
    }
}

#[test]
fn disqualifier_remediations_are_nonempty() {
    let a = parse_algebra();
    for r in &a.disqualifier_rules.rules {
        assert!(
            !r.remediation.trim().is_empty(),
            "rule {} must have a nonempty remediation",
            r.rule_id
        );
    }
}

#[test]
fn highest_precedence_rule_has_forbid_verdict() {
    let a = parse_algebra();
    let top_rule = a
        .disqualifier_rules
        .rules
        .iter()
        .find(|r| r.precedence == 0)
        .expect("must have a precedence-0 rule");
    assert_eq!(
        top_rule.verdict, "forbid",
        "highest-precedence rule must have 'forbid' verdict"
    );
}

// ===== Cross-catalog referential integrity =====

#[test]
fn every_atom_is_targeted_by_at_least_one_morphism_or_rule() {
    let a = parse_algebra();
    let mut targeted: BTreeSet<&str> = BTreeSet::new();
    for m in &a.evidence_morphism_catalog.morphisms {
        for t in &m.target_atoms {
            targeted.insert(t.as_str());
        }
    }
    for r in &a.disqualifier_rules.rules {
        for t in &r.target_atoms {
            targeted.insert(t.as_str());
        }
    }
    for atom in &a.claim_atom_catalog.atoms {
        assert!(
            targeted.contains(atom.atom_id.as_str()),
            "atom {} is not targeted by any morphism or rule",
            atom.atom_id
        );
    }
}

// ===== Top-level key structure =====

#[test]
fn top_level_keys_match_expected_schema() {
    let raw: Value = serde_json::from_str(ALGEBRA_JSON).expect("must parse as Value");
    let obj = raw.as_object().expect("must be a JSON object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = BTreeSet::from([
        "schema_version",
        "contract_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "track",
        "required_artifacts",
        "required_structured_log_fields",
        "claim_atom_catalog",
        "evidence_morphism_catalog",
        "side_constraint_lattice",
        "disqualifier_rules",
        "operator_verification",
    ]);
    assert_eq!(keys, expected);
}

#[test]
fn deterministic_double_parse() {
    let a = parse_algebra();
    let b = parse_algebra();
    assert_eq!(a, b);
}
