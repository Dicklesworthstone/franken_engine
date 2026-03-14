#![forbid(unsafe_code)]

//! Claim atoms, evidence morphisms, and side-constraint lattice for shipped
//! and frontier claims.
//!
//! Bead: bd-1lsy.1.7.1 [RGC-017A]
//!
//! Defines the primitive claim atoms (indivisible statements about engine
//! behavior), evidence morphisms (how test/benchmark/audit evidence supports
//! or constrains claim atoms), disqualifier rules, and a side-constraint
//! lattice so later modules can compose entitlement verdicts, cut-set
//! analyses, and impossibility certificates.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const CLAIM_ATOM_LATTICE_SCHEMA_VERSION: &str = "franken-engine.claim-atom-lattice.v1";
pub const CLAIM_ATOM_LATTICE_BEAD_ID: &str = "bd-1lsy.1.7.1";
pub const ENTITLEMENT_RESULT_SCHEMA_VERSION: &str = "franken-engine.claim-entitlement-result.v1";

// ---------------------------------------------------------------------------
// Claim domain (what area the claim covers)
// ---------------------------------------------------------------------------

/// Domain of a claim atom: which aspect of the engine the claim describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDomain {
    /// Compatibility with existing JS/TS semantics.
    Compatibility,
    /// Shipped execution surface coverage.
    ShippedSurface,
    /// React-specific behavior.
    React,
    /// Performance supremacy vs V8/other engines.
    Supremacy,
    /// Rollout readiness.
    Rollout,
    /// GA (general availability) readiness.
    Ga,
    /// Documentation accuracy.
    Docs,
    /// Security and isolation.
    Security,
}

impl fmt::Display for ClaimDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Compatibility => "compatibility",
            Self::ShippedSurface => "shipped_surface",
            Self::React => "react",
            Self::Supremacy => "supremacy",
            Self::Rollout => "rollout",
            Self::Ga => "ga",
            Self::Docs => "docs",
            Self::Security => "security",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Claim tier (strength of evidence required)
// ---------------------------------------------------------------------------

/// Tier of a claim: how strong the evidence must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimTier {
    /// Shipped-path fact: reproducible, test-backed, deterministic.
    ShippedFact,
    /// Scoped observation: true under measured conditions.
    ScopedObserved,
    /// Frontier ambition: aspiration, not yet proven.
    FrontierAmbition,
    /// Unsupported surface: explicitly not claimed.
    UnsupportedSurface,
}

impl fmt::Display for ClaimTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ShippedFact => "shipped_fact",
            Self::ScopedObserved => "scoped_observed",
            Self::FrontierAmbition => "frontier_ambition",
            Self::UnsupportedSurface => "unsupported_surface",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Claim atom (indivisible statement)
// ---------------------------------------------------------------------------

/// A single indivisible claim about engine behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAtom {
    /// Unique identifier (e.g., "claim-compat-es2024-strict").
    pub atom_id: String,
    /// Domain of the claim.
    pub domain: ClaimDomain,
    /// Required evidence tier.
    pub tier: ClaimTier,
    /// Short statement (e.g., "ES2024 strict mode semantics").
    pub statement: String,
    /// Surface or scope (e.g., "parser+runtime").
    pub surface: String,
    /// Owning bead IDs.
    pub owning_beads: Vec<String>,
    /// Required evidence morphism IDs to prove this claim.
    pub required_morphisms: Vec<String>,
}

impl fmt::Display for ClaimAtom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}:{}]", self.atom_id, self.domain, self.tier)
    }
}

// ---------------------------------------------------------------------------
// Evidence morphism (how evidence connects to claims)
// ---------------------------------------------------------------------------

/// How a piece of evidence supports, constrains, or disqualifies a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphismEffect {
    /// Evidence supports the claim (positive evidence).
    Supports,
    /// Evidence constrains the claim's scope.
    Constrains,
    /// Evidence actively disqualifies the claim.
    Disqualifies,
}

impl fmt::Display for MorphismEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Supports => "supports",
            Self::Constrains => "constrains",
            Self::Disqualifies => "disqualifies",
        };
        write!(f, "{label}")
    }
}

/// A morphism from an evidence artifact to one or more claim atoms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceMorphism {
    /// Unique identifier.
    pub morphism_id: String,
    /// Kind of evidence (e.g., "test262_pass", "benchmark_cell", "audit_report").
    pub evidence_kind: String,
    /// Effect on the target claims.
    pub effect: MorphismEffect,
    /// Claim atom IDs this morphism targets.
    pub target_atoms: Vec<String>,
    /// Side-constraint IDs required for this morphism to apply.
    pub required_constraints: Vec<String>,
    /// Disqualifier rule IDs that can block this morphism.
    pub blocked_by_rules: Vec<String>,
    /// Human-readable rationale.
    pub rationale: String,
}

impl fmt::Display for EvidenceMorphism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({} → [{}])",
            self.morphism_id,
            self.effect,
            self.target_atoms.join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// Side-constraint lattice
// ---------------------------------------------------------------------------

/// A constraint that must be satisfied for evidence to apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideConstraint {
    /// Unique identifier.
    pub constraint_id: String,
    /// Class of constraint (e.g., "freshness", "reproducibility", "sample_size").
    pub constraint_class: String,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for SideConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.constraint_id, self.constraint_class)
    }
}

/// A cover relation in the constraint lattice: lower ≤ higher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverRelation {
    /// The weaker constraint.
    pub lower: String,
    /// The stronger constraint.
    pub higher: String,
}

/// The lattice of side constraints.
///
/// Constraints form a partial order where satisfying a higher constraint
/// implies satisfying all lower ones.  The `top` constraint is the
/// most restrictive (all constraints satisfied).  The `bottom` is the
/// least restrictive (no constraints satisfied).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintLattice {
    /// Identifier of the top (most restrictive) element.
    pub top_id: String,
    /// Identifier of the bottom (least restrictive) element.
    pub bottom_id: String,
    /// All constraints in the lattice.
    pub constraints: Vec<SideConstraint>,
    /// Cover relations defining the partial order.
    pub covers: Vec<CoverRelation>,
}

impl ConstraintLattice {
    /// Check whether the lattice has a cycle (which would make it invalid).
    pub fn has_cycle(&self) -> bool {
        // Build adjacency from lower → higher
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for cover in &self.covers {
            adj.entry(cover.lower.as_str())
                .or_default()
                .push(cover.higher.as_str());
        }

        // DFS cycle detection
        let mut visited: BTreeMap<&str, u8> = BTreeMap::new(); // 0=unvisited, 1=in-stack, 2=done
        for constraint in &self.constraints {
            if has_cycle_dfs(constraint.constraint_id.as_str(), &adj, &mut visited) {
                return true;
            }
        }
        false
    }

    /// Check whether a constraint is reachable from the bottom.
    pub fn is_reachable_from_bottom(&self, constraint_id: &str) -> bool {
        if constraint_id == self.bottom_id {
            return true;
        }
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for cover in &self.covers {
            adj.entry(cover.lower.as_str())
                .or_default()
                .push(cover.higher.as_str());
        }
        let mut visited = BTreeMap::new();
        reachable_dfs(self.bottom_id.as_str(), constraint_id, &adj, &mut visited)
    }
}

// ---------------------------------------------------------------------------
// Disqualifier rules
// ---------------------------------------------------------------------------

/// Verdict when a disqualifier rule fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisqualifierVerdict {
    /// Claim is absolutely forbidden.
    Forbid,
    /// Downgrade to scoped-observed tier.
    DowngradeToScoped,
    /// Require operator guidance before proceeding.
    RequireOperatorGuidance,
}

impl fmt::Display for DisqualifierVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Forbid => "forbid",
            Self::DowngradeToScoped => "downgrade_to_scoped",
            Self::RequireOperatorGuidance => "require_operator_guidance",
        };
        write!(f, "{label}")
    }
}

/// A rule that disqualifies or downgrades a claim under specific conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisqualifierRule {
    /// Unique identifier.
    pub rule_id: String,
    /// Precedence (lower = higher priority).
    pub precedence: u64,
    /// What evidence kind triggers this rule.
    pub trigger_evidence_kind: String,
    /// Condition description.
    pub condition: String,
    /// Claim atoms affected.
    pub target_atoms: Vec<String>,
    /// Verdict when triggered.
    pub verdict: DisqualifierVerdict,
    /// Remediation guidance.
    pub remediation: String,
}

impl fmt::Display for DisqualifierRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(prec={}, {})",
            self.rule_id, self.precedence, self.verdict
        )
    }
}

// ---------------------------------------------------------------------------
// Claim evaluation state
// ---------------------------------------------------------------------------

/// State of a claim atom during evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    /// Claim is fully supported by evidence.
    Entitled,
    /// Evidence exists but is not yet sufficient.
    NotYetProven,
    /// Missing required evidence.
    BlockedByMissingEvidence,
    /// Active counterexample invalidates the claim.
    Invalidated,
}

impl fmt::Display for ClaimState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Entitled => "entitled",
            Self::NotYetProven => "not_yet_proven",
            Self::BlockedByMissingEvidence => "blocked_by_missing_evidence",
            Self::Invalidated => "invalidated",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/// A snapshot of observed evidence for evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSnapshot {
    /// Evidence kind (must match morphism evidence_kind).
    pub evidence_kind: String,
    /// Whether the evidence is fresh or stale.
    pub is_fresh: bool,
    /// Triggered disqualifier rule IDs.
    pub triggered_rules: Vec<String>,
}

/// Evaluation result for a single claim atom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAtomEvaluation {
    /// The claim atom ID.
    pub atom_id: String,
    /// Resulting state.
    pub state: ClaimState,
    /// Supporting morphism IDs that were satisfied.
    pub satisfied_morphisms: Vec<String>,
    /// Morphism IDs that are missing evidence.
    pub missing_morphisms: Vec<String>,
    /// Active disqualifier rule IDs.
    pub active_disqualifiers: Vec<String>,
}

/// Full evaluation result for a set of claim atoms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementResult {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Per-atom evaluations.
    pub evaluations: Vec<ClaimAtomEvaluation>,
    /// Overall state (worst across all atoms).
    pub overall_state: ClaimState,
    /// Epoch at which evaluation was performed.
    pub evaluated_epoch: u64,
    /// Number of entitled atoms.
    pub entitled_count: usize,
    /// Number of not-yet-proven atoms.
    pub not_yet_proven_count: usize,
    /// Number of blocked atoms.
    pub blocked_count: usize,
    /// Number of invalidated atoms.
    pub invalidated_count: usize,
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Evaluate a set of claim atoms against observed evidence.
pub fn evaluate_claims(
    atoms: &[ClaimAtom],
    morphisms: &[EvidenceMorphism],
    rules: &[DisqualifierRule],
    evidence: &[EvidenceSnapshot],
    epoch: u64,
) -> EntitlementResult {
    let evidence_map: BTreeMap<&str, &EvidenceSnapshot> = evidence
        .iter()
        .map(|e| (e.evidence_kind.as_str(), e))
        .collect();

    let triggered_rules: Vec<&str> = evidence
        .iter()
        .flat_map(|e| e.triggered_rules.iter().map(|r| r.as_str()))
        .collect();

    let mut evaluations = Vec::new();

    for atom in atoms {
        let eval = evaluate_single_atom(atom, morphisms, rules, &evidence_map, &triggered_rules);
        evaluations.push(eval);
    }

    let entitled_count = evaluations
        .iter()
        .filter(|e| e.state == ClaimState::Entitled)
        .count();
    let not_yet_proven_count = evaluations
        .iter()
        .filter(|e| e.state == ClaimState::NotYetProven)
        .count();
    let blocked_count = evaluations
        .iter()
        .filter(|e| e.state == ClaimState::BlockedByMissingEvidence)
        .count();
    let invalidated_count = evaluations
        .iter()
        .filter(|e| e.state == ClaimState::Invalidated)
        .count();

    let overall_state = if invalidated_count > 0 {
        ClaimState::Invalidated
    } else if blocked_count > 0 {
        ClaimState::BlockedByMissingEvidence
    } else if not_yet_proven_count > 0 {
        ClaimState::NotYetProven
    } else {
        ClaimState::Entitled
    };

    EntitlementResult {
        schema_version: ENTITLEMENT_RESULT_SCHEMA_VERSION.to_string(),
        bead_id: CLAIM_ATOM_LATTICE_BEAD_ID.to_string(),
        evaluations,
        overall_state,
        evaluated_epoch: epoch,
        entitled_count,
        not_yet_proven_count,
        blocked_count,
        invalidated_count,
    }
}

/// Render a human-readable summary of an entitlement result.
pub fn render_entitlement_summary(result: &EntitlementResult) -> String {
    [
        format!("schema_version: {}", result.schema_version),
        format!("evaluated_epoch: {}", result.evaluated_epoch),
        format!("overall_state: {}", result.overall_state),
        format!("entitled: {}", result.entitled_count),
        format!("not_yet_proven: {}", result.not_yet_proven_count),
        format!("blocked: {}", result.blocked_count),
        format!("invalidated: {}", result.invalidated_count),
    ]
    .join("\n")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn evaluate_single_atom(
    atom: &ClaimAtom,
    morphisms: &[EvidenceMorphism],
    rules: &[DisqualifierRule],
    evidence_map: &BTreeMap<&str, &EvidenceSnapshot>,
    triggered_rules: &[&str],
) -> ClaimAtomEvaluation {
    // Check for active disqualifiers
    let mut active_disqualifiers = Vec::new();
    let mut has_forbid = false;

    for rule in rules {
        if rule.target_atoms.contains(&atom.atom_id)
            && triggered_rules.contains(&rule.rule_id.as_str())
        {
            active_disqualifiers.push(rule.rule_id.clone());
            if rule.verdict == DisqualifierVerdict::Forbid {
                has_forbid = true;
            }
        }
    }

    if has_forbid {
        return ClaimAtomEvaluation {
            atom_id: atom.atom_id.clone(),
            state: ClaimState::Invalidated,
            satisfied_morphisms: Vec::new(),
            missing_morphisms: atom.required_morphisms.clone(),
            active_disqualifiers,
        };
    }

    // Check morphisms
    let relevant_morphisms: Vec<&EvidenceMorphism> = morphisms
        .iter()
        .filter(|m| m.target_atoms.contains(&atom.atom_id))
        .collect();

    let mut satisfied = Vec::new();
    let mut missing = Vec::new();

    for morphism_id in &atom.required_morphisms {
        let morphism = relevant_morphisms
            .iter()
            .find(|m| &m.morphism_id == morphism_id);

        if let Some(m) = morphism {
            let has_evidence = evidence_map.contains_key(m.evidence_kind.as_str());
            let is_fresh = evidence_map
                .get(m.evidence_kind.as_str())
                .map(|e| e.is_fresh)
                .unwrap_or(false);
            let not_blocked = !m
                .blocked_by_rules
                .iter()
                .any(|r| triggered_rules.contains(&r.as_str()));

            if has_evidence && is_fresh && not_blocked {
                satisfied.push(morphism_id.clone());
            } else {
                missing.push(morphism_id.clone());
            }
        } else {
            missing.push(morphism_id.clone());
        }
    }

    let state = if !active_disqualifiers.is_empty() {
        ClaimState::NotYetProven
    } else if missing.is_empty() && (!satisfied.is_empty() || atom.required_morphisms.is_empty()) {
        ClaimState::Entitled
    } else if satisfied.is_empty() {
        ClaimState::BlockedByMissingEvidence
    } else {
        ClaimState::NotYetProven
    };

    ClaimAtomEvaluation {
        atom_id: atom.atom_id.clone(),
        state,
        satisfied_morphisms: satisfied,
        missing_morphisms: missing,
        active_disqualifiers,
    }
}

fn has_cycle_dfs<'a>(
    node: &'a str,
    adj: &BTreeMap<&str, Vec<&'a str>>,
    visited: &mut BTreeMap<&'a str, u8>,
) -> bool {
    match visited.get(node) {
        Some(1) => return true,  // in-stack = cycle
        Some(2) => return false, // done
        _ => {}
    }
    visited.insert(node, 1);
    if let Some(neighbors) = adj.get(node) {
        for neighbor in neighbors {
            if has_cycle_dfs(neighbor, adj, visited) {
                return true;
            }
        }
    }
    visited.insert(node, 2);
    false
}

fn reachable_dfs<'a>(
    current: &'a str,
    target: &str,
    adj: &BTreeMap<&str, Vec<&'a str>>,
    visited: &mut BTreeMap<&'a str, bool>,
) -> bool {
    if current == target {
        return true;
    }
    if visited.contains_key(current) {
        return false;
    }
    visited.insert(current, true);
    if let Some(neighbors) = adj.get(current) {
        for neighbor in neighbors {
            if reachable_dfs(neighbor, target, adj, visited) {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_atom(id: &str, domain: ClaimDomain, tier: ClaimTier) -> ClaimAtom {
        ClaimAtom {
            atom_id: id.to_string(),
            domain,
            tier,
            statement: format!("Test claim {id}"),
            surface: "test".to_string(),
            owning_beads: vec!["bd-test".to_string()],
            required_morphisms: vec![format!("morph-{id}")],
        }
    }

    fn test_morphism(id: &str, target: &str, kind: &str) -> EvidenceMorphism {
        EvidenceMorphism {
            morphism_id: id.to_string(),
            evidence_kind: kind.to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec![target.to_string()],
            required_constraints: Vec::new(),
            blocked_by_rules: Vec::new(),
            rationale: format!("Test morphism {id}"),
        }
    }

    fn test_evidence(kind: &str) -> EvidenceSnapshot {
        EvidenceSnapshot {
            evidence_kind: kind.to_string(),
            is_fresh: true,
            triggered_rules: Vec::new(),
        }
    }

    fn test_rule(id: &str, target: &str, verdict: DisqualifierVerdict) -> DisqualifierRule {
        DisqualifierRule {
            rule_id: id.to_string(),
            precedence: 0,
            trigger_evidence_kind: "test".to_string(),
            condition: "test condition".to_string(),
            target_atoms: vec![target.to_string()],
            verdict,
            remediation: "fix it".to_string(),
        }
    }

    #[test]
    fn schema_version_constants_are_non_empty() {
        assert!(!CLAIM_ATOM_LATTICE_SCHEMA_VERSION.is_empty());
        assert!(!CLAIM_ATOM_LATTICE_BEAD_ID.is_empty());
        assert!(!ENTITLEMENT_RESULT_SCHEMA_VERSION.is_empty());
    }

    // -- Display --

    #[test]
    fn domain_display_all() {
        let domains = [
            (ClaimDomain::Compatibility, "compatibility"),
            (ClaimDomain::ShippedSurface, "shipped_surface"),
            (ClaimDomain::React, "react"),
            (ClaimDomain::Supremacy, "supremacy"),
            (ClaimDomain::Rollout, "rollout"),
            (ClaimDomain::Ga, "ga"),
            (ClaimDomain::Docs, "docs"),
            (ClaimDomain::Security, "security"),
        ];
        for (d, expected) in &domains {
            assert_eq!(d.to_string(), *expected);
        }
    }

    #[test]
    fn tier_display_all() {
        assert_eq!(ClaimTier::ShippedFact.to_string(), "shipped_fact");
        assert_eq!(ClaimTier::ScopedObserved.to_string(), "scoped_observed");
        assert_eq!(ClaimTier::FrontierAmbition.to_string(), "frontier_ambition");
        assert_eq!(
            ClaimTier::UnsupportedSurface.to_string(),
            "unsupported_surface"
        );
    }

    #[test]
    fn morphism_effect_display() {
        assert_eq!(MorphismEffect::Supports.to_string(), "supports");
        assert_eq!(MorphismEffect::Constrains.to_string(), "constrains");
        assert_eq!(MorphismEffect::Disqualifies.to_string(), "disqualifies");
    }

    #[test]
    fn claim_state_display() {
        assert_eq!(ClaimState::Entitled.to_string(), "entitled");
        assert_eq!(ClaimState::NotYetProven.to_string(), "not_yet_proven");
        assert_eq!(
            ClaimState::BlockedByMissingEvidence.to_string(),
            "blocked_by_missing_evidence"
        );
        assert_eq!(ClaimState::Invalidated.to_string(), "invalidated");
    }

    #[test]
    fn disqualifier_verdict_display() {
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

    // -- Serde round-trips --

    #[test]
    fn domain_serde_round_trip() {
        for d in &[
            ClaimDomain::Compatibility,
            ClaimDomain::React,
            ClaimDomain::Security,
        ] {
            let json = serde_json::to_string(d).expect("serialize");
            let deser: ClaimDomain = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*d, deser);
        }
    }

    #[test]
    fn atom_serde_round_trip() {
        let atom = test_atom("compat", ClaimDomain::Compatibility, ClaimTier::ShippedFact);
        let json = serde_json::to_string(&atom).expect("serialize");
        let deser: ClaimAtom = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(atom, deser);
    }

    #[test]
    fn morphism_serde_round_trip() {
        let m = test_morphism("morph-1", "compat", "test262_pass");
        let json = serde_json::to_string(&m).expect("serialize");
        let deser: EvidenceMorphism = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(m, deser);
    }

    #[test]
    fn constraint_lattice_serde_round_trip() {
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
        let json = serde_json::to_string(&lattice).expect("serialize");
        let deser: ConstraintLattice = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lattice, deser);
    }

    // -- Lattice cycle detection --

    #[test]
    fn lattice_no_cycle() {
        let lattice = ConstraintLattice {
            top_id: "top".to_string(),
            bottom_id: "bot".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "bot".to_string(),
                    constraint_class: "base".to_string(),
                    description: "bottom".to_string(),
                },
                SideConstraint {
                    constraint_id: "mid".to_string(),
                    constraint_class: "middle".to_string(),
                    description: "middle".to_string(),
                },
                SideConstraint {
                    constraint_id: "top".to_string(),
                    constraint_class: "full".to_string(),
                    description: "top".to_string(),
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
        };
        assert!(!lattice.has_cycle());
    }

    #[test]
    fn lattice_with_cycle() {
        let lattice = ConstraintLattice {
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
        assert!(lattice.has_cycle());
    }

    #[test]
    fn lattice_reachability() {
        let lattice = ConstraintLattice {
            top_id: "top".to_string(),
            bottom_id: "bot".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "bot".to_string(),
                    constraint_class: "x".to_string(),
                    description: "bottom".to_string(),
                },
                SideConstraint {
                    constraint_id: "top".to_string(),
                    constraint_class: "x".to_string(),
                    description: "top".to_string(),
                },
            ],
            covers: vec![CoverRelation {
                lower: "bot".to_string(),
                higher: "top".to_string(),
            }],
        };
        assert!(lattice.is_reachable_from_bottom("top"));
        assert!(lattice.is_reachable_from_bottom("bot"));
    }

    // -- Claim evaluation --

    #[test]
    fn evaluate_entitled_when_all_evidence_present() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let evidence = vec![test_evidence("test262_pass")];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 0);
        assert_eq!(result.overall_state, ClaimState::Entitled);
        assert_eq!(result.entitled_count, 1);
    }

    #[test]
    fn evaluate_blocked_when_evidence_missing() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let result = evaluate_claims(&atoms, &morphisms, &[], &[], 0);
        assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
    }

    #[test]
    fn evaluate_invalidated_when_forbid_rule_fires() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let rules = vec![test_rule("rule-1", "a", DisqualifierVerdict::Forbid)];
        let evidence = vec![EvidenceSnapshot {
            evidence_kind: "test262_pass".to_string(),
            is_fresh: true,
            triggered_rules: vec!["rule-1".to_string()],
        }];
        let result = evaluate_claims(&atoms, &morphisms, &rules, &evidence, 0);
        assert_eq!(result.overall_state, ClaimState::Invalidated);
        assert_eq!(result.invalidated_count, 1);
    }

    #[test]
    fn evaluate_stale_evidence_blocks() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let evidence = vec![EvidenceSnapshot {
            evidence_kind: "test262_pass".to_string(),
            is_fresh: false,
            triggered_rules: Vec::new(),
        }];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 0);
        assert!(matches!(
            result.overall_state,
            ClaimState::BlockedByMissingEvidence | ClaimState::NotYetProven
        ));
    }

    #[test]
    fn evaluate_empty_atoms() {
        let result = evaluate_claims(&[], &[], &[], &[], 0);
        assert_eq!(result.overall_state, ClaimState::Entitled);
        assert_eq!(result.entitled_count, 0);
    }

    #[test]
    fn entitlement_result_serde_round_trip() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let evidence = vec![test_evidence("test262_pass")];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 42);
        let json = serde_json::to_string(&result).expect("serialize");
        let deser: EntitlementResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, deser);
    }

    // -- Summary --

    #[test]
    fn summary_contains_key_fields() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "test262_pass")];
        let evidence = vec![test_evidence("test262_pass")];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 5);
        let summary = render_entitlement_summary(&result);
        assert!(summary.contains("overall_state: entitled"));
        assert!(summary.contains("evaluated_epoch: 5"));
        assert!(summary.contains("entitled: 1"));
    }

    // -- Additional Display tests for composite types --

    #[test]
    fn claim_atom_display_format() {
        let atom = test_atom(
            "compat-es2024",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        );
        let display = atom.to_string();
        assert_eq!(display, "compat-es2024[compatibility:shipped_fact]");
    }

    #[test]
    fn evidence_morphism_display_format() {
        let m = EvidenceMorphism {
            morphism_id: "morph-42".to_string(),
            evidence_kind: "test262_pass".to_string(),
            effect: MorphismEffect::Disqualifies,
            target_atoms: vec!["atom-a".to_string(), "atom-b".to_string()],
            required_constraints: Vec::new(),
            blocked_by_rules: Vec::new(),
            rationale: "test".to_string(),
        };
        assert_eq!(m.to_string(), "morph-42(disqualifies → [atom-a, atom-b])");
    }

    #[test]
    fn side_constraint_display_format() {
        let sc = SideConstraint {
            constraint_id: "freshness-24h".to_string(),
            constraint_class: "freshness".to_string(),
            description: "Evidence must be less than 24h old".to_string(),
        };
        assert_eq!(sc.to_string(), "freshness-24h(freshness)");
    }

    #[test]
    fn disqualifier_rule_display_format() {
        let rule = test_rule("rule-sec-1", "atom-a", DisqualifierVerdict::Forbid);
        assert_eq!(rule.to_string(), "rule-sec-1(prec=0, forbid)");
    }

    // -- Additional serde roundtrip tests --

    #[test]
    fn claim_tier_serde_round_trip_all_variants() {
        for tier in &[
            ClaimTier::ShippedFact,
            ClaimTier::ScopedObserved,
            ClaimTier::FrontierAmbition,
            ClaimTier::UnsupportedSurface,
        ] {
            let json = serde_json::to_string(tier).expect("serialize");
            let deser: ClaimTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*tier, deser);
        }
    }

    #[test]
    fn claim_state_serde_round_trip_all_variants() {
        for state in &[
            ClaimState::Entitled,
            ClaimState::NotYetProven,
            ClaimState::BlockedByMissingEvidence,
            ClaimState::Invalidated,
        ] {
            let json = serde_json::to_string(state).expect("serialize");
            let deser: ClaimState = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*state, deser);
        }
    }

    #[test]
    fn disqualifier_verdict_serde_round_trip_all_variants() {
        for verdict in &[
            DisqualifierVerdict::Forbid,
            DisqualifierVerdict::DowngradeToScoped,
            DisqualifierVerdict::RequireOperatorGuidance,
        ] {
            let json = serde_json::to_string(verdict).expect("serialize");
            let deser: DisqualifierVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*verdict, deser);
        }
    }

    #[test]
    fn morphism_effect_serde_round_trip_all_variants() {
        for effect in &[
            MorphismEffect::Supports,
            MorphismEffect::Constrains,
            MorphismEffect::Disqualifies,
        ] {
            let json = serde_json::to_string(effect).expect("serialize");
            let deser: MorphismEffect = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*effect, deser);
        }
    }

    #[test]
    fn evidence_snapshot_serde_round_trip() {
        let snap = EvidenceSnapshot {
            evidence_kind: "benchmark_cell".to_string(),
            is_fresh: false,
            triggered_rules: vec!["rule-1".to_string(), "rule-2".to_string()],
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let deser: EvidenceSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, deser);
    }

    #[test]
    fn disqualifier_rule_serde_round_trip() {
        let rule = DisqualifierRule {
            rule_id: "disq-perf-regression".to_string(),
            precedence: 10,
            trigger_evidence_kind: "benchmark_cell".to_string(),
            condition: "p99 latency > 10ms".to_string(),
            target_atoms: vec!["atom-perf-1".to_string(), "atom-perf-2".to_string()],
            verdict: DisqualifierVerdict::DowngradeToScoped,
            remediation: "Profile and fix hotspots".to_string(),
        };
        let json = serde_json::to_string(&rule).expect("serialize");
        let deser: DisqualifierRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rule, deser);
    }

    #[test]
    fn claim_atom_evaluation_serde_round_trip() {
        let eval = ClaimAtomEvaluation {
            atom_id: "claim-x".to_string(),
            state: ClaimState::NotYetProven,
            satisfied_morphisms: vec!["morph-1".to_string()],
            missing_morphisms: vec!["morph-2".to_string()],
            active_disqualifiers: vec!["rule-a".to_string()],
        };
        let json = serde_json::to_string(&eval).expect("serialize");
        let deser: ClaimAtomEvaluation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(eval, deser);
    }

    #[test]
    fn cover_relation_serde_round_trip() {
        let cr = CoverRelation {
            lower: "base".to_string(),
            higher: "strict".to_string(),
        };
        let json = serde_json::to_string(&cr).expect("serialize");
        let deser: CoverRelation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cr, deser);
    }

    // -- Enum variant count tests --

    #[test]
    fn claim_domain_has_eight_variants() {
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
        assert_eq!(all.len(), 8);
        // Verify all distinct via Ord
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 8);
    }

    #[test]
    fn claim_tier_has_four_variants() {
        let all = [
            ClaimTier::ShippedFact,
            ClaimTier::ScopedObserved,
            ClaimTier::FrontierAmbition,
            ClaimTier::UnsupportedSurface,
        ];
        assert_eq!(all.len(), 4);
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn claim_state_has_four_variants() {
        let all = [
            ClaimState::Entitled,
            ClaimState::NotYetProven,
            ClaimState::BlockedByMissingEvidence,
            ClaimState::Invalidated,
        ];
        assert_eq!(all.len(), 4);
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    // -- Lattice edge cases --

    #[test]
    fn lattice_unreachable_node_not_found_from_bottom() {
        let lattice = ConstraintLattice {
            top_id: "top".to_string(),
            bottom_id: "bot".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "bot".to_string(),
                    constraint_class: "x".to_string(),
                    description: "bottom".to_string(),
                },
                SideConstraint {
                    constraint_id: "top".to_string(),
                    constraint_class: "x".to_string(),
                    description: "top".to_string(),
                },
                SideConstraint {
                    constraint_id: "island".to_string(),
                    constraint_class: "x".to_string(),
                    description: "disconnected node".to_string(),
                },
            ],
            covers: vec![CoverRelation {
                lower: "bot".to_string(),
                higher: "top".to_string(),
            }],
        };
        assert!(!lattice.is_reachable_from_bottom("island"));
    }

    #[test]
    fn lattice_diamond_shape_reachability() {
        // bot -> left, bot -> right, left -> top, right -> top
        let lattice = ConstraintLattice {
            top_id: "top".to_string(),
            bottom_id: "bot".to_string(),
            constraints: vec![
                SideConstraint {
                    constraint_id: "bot".to_string(),
                    constraint_class: "x".to_string(),
                    description: "bottom".to_string(),
                },
                SideConstraint {
                    constraint_id: "left".to_string(),
                    constraint_class: "x".to_string(),
                    description: "left path".to_string(),
                },
                SideConstraint {
                    constraint_id: "right".to_string(),
                    constraint_class: "x".to_string(),
                    description: "right path".to_string(),
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
        assert!(!lattice.has_cycle());
        assert!(lattice.is_reachable_from_bottom("left"));
        assert!(lattice.is_reachable_from_bottom("right"));
        assert!(lattice.is_reachable_from_bottom("top"));
    }

    #[test]
    fn lattice_empty_covers_no_cycle() {
        let lattice = ConstraintLattice {
            top_id: "sole".to_string(),
            bottom_id: "sole".to_string(),
            constraints: vec![SideConstraint {
                constraint_id: "sole".to_string(),
                constraint_class: "x".to_string(),
                description: "single node".to_string(),
            }],
            covers: Vec::new(),
        };
        assert!(!lattice.has_cycle());
        assert!(lattice.is_reachable_from_bottom("sole"));
    }

    // -- Evaluation edge cases --

    #[test]
    fn evaluate_multiple_atoms_mixed_states() {
        let atoms = vec![
            test_atom("a", ClaimDomain::Compatibility, ClaimTier::ShippedFact),
            test_atom("b", ClaimDomain::Security, ClaimTier::ShippedFact),
        ];
        let morphisms = vec![
            test_morphism("morph-a", "a", "test262_pass"),
            test_morphism("morph-b", "b", "audit_report"),
        ];
        // Only provide evidence for atom "a", not "b"
        let evidence = vec![test_evidence("test262_pass")];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 10);
        assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
        assert_eq!(result.entitled_count, 1);
        assert_eq!(result.blocked_count, 1);
        assert_eq!(result.evaluated_epoch, 10);
    }

    #[test]
    fn evaluate_downgrade_verdict_yields_not_yet_proven() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Supremacy,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "benchmark_cell")];
        let rules = vec![test_rule(
            "rule-dg",
            "a",
            DisqualifierVerdict::DowngradeToScoped,
        )];
        let evidence = vec![EvidenceSnapshot {
            evidence_kind: "benchmark_cell".to_string(),
            is_fresh: true,
            triggered_rules: vec!["rule-dg".to_string()],
        }];
        let result = evaluate_claims(&atoms, &morphisms, &rules, &evidence, 0);
        // DowngradeToScoped does not Forbid, so atom should be NotYetProven (has active disqualifiers)
        assert_eq!(result.overall_state, ClaimState::NotYetProven);
        assert_eq!(result.not_yet_proven_count, 1);
        assert_eq!(result.invalidated_count, 0);
    }

    #[test]
    fn evaluate_morphism_blocked_by_rule_yields_missing() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Compatibility,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![EvidenceMorphism {
            morphism_id: "morph-a".to_string(),
            evidence_kind: "test262_pass".to_string(),
            effect: MorphismEffect::Supports,
            target_atoms: vec!["a".to_string()],
            required_constraints: Vec::new(),
            blocked_by_rules: vec!["blocker-1".to_string()],
            rationale: "test".to_string(),
        }];
        let evidence = vec![EvidenceSnapshot {
            evidence_kind: "test262_pass".to_string(),
            is_fresh: true,
            triggered_rules: vec!["blocker-1".to_string()],
        }];
        let result = evaluate_claims(&atoms, &morphisms, &[], &evidence, 0);
        // The morphism is blocked, so evidence doesn't count
        assert_eq!(result.overall_state, ClaimState::BlockedByMissingEvidence);
        assert_eq!(result.evaluations[0].missing_morphisms, vec!["morph-a"]);
    }

    #[test]
    fn evaluate_atom_with_no_required_morphisms_is_entitled() {
        let atom = ClaimAtom {
            atom_id: "trivial".to_string(),
            domain: ClaimDomain::Docs,
            tier: ClaimTier::ScopedObserved,
            statement: "Docs exist".to_string(),
            surface: "docs".to_string(),
            owning_beads: vec!["bd-test".to_string()],
            required_morphisms: Vec::new(),
        };
        let result = evaluate_claims(&[atom], &[], &[], &[], 0);
        assert_eq!(result.overall_state, ClaimState::Entitled);
        assert_eq!(result.entitled_count, 1);
    }

    // -- Summary edge cases --

    #[test]
    fn summary_for_invalidated_result_shows_invalidated_state() {
        let atoms = vec![test_atom(
            "a",
            ClaimDomain::Security,
            ClaimTier::ShippedFact,
        )];
        let morphisms = vec![test_morphism("morph-a", "a", "audit_report")];
        let rules = vec![test_rule("rule-sec", "a", DisqualifierVerdict::Forbid)];
        let evidence = vec![EvidenceSnapshot {
            evidence_kind: "audit_report".to_string(),
            is_fresh: true,
            triggered_rules: vec!["rule-sec".to_string()],
        }];
        let result = evaluate_claims(&atoms, &morphisms, &rules, &evidence, 99);
        let summary = render_entitlement_summary(&result);
        assert!(summary.contains("overall_state: invalidated"));
        assert!(summary.contains("invalidated: 1"));
        assert!(summary.contains("evaluated_epoch: 99"));
    }

    #[test]
    fn entitlement_result_schema_version_matches_constant() {
        let result = evaluate_claims(&[], &[], &[], &[], 0);
        assert_eq!(result.schema_version, ENTITLEMENT_RESULT_SCHEMA_VERSION);
        assert_eq!(result.bead_id, CLAIM_ATOM_LATTICE_BEAD_ID);
    }
}
