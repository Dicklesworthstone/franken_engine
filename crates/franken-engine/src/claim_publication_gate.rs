#![forbid(unsafe_code)]

//! Claim publication gate: wires claim-entitlement verdicts into publication
//! surfaces for docs, rollout, GA, React, and supremacy evidence.
//!
//! Bead: bd-1lsy.1.7.3 [RGC-017C]
//!
//! Layer 3 of the claim-entitlement system:
//!   1. claim_atom_lattice  → primitive atoms + evidence morphisms
//!   2. claim_entitlement   → verdicts, cut sets, impossibility certificates
//!   3. claim_publication_gate (this module) → surface routing + gate decisions
//!
//! Each publication surface (Docs, Rollout, Ga, React, Supremacy) has its own
//! gate that consumes verdicts, cross-references the ratchet board, and emits
//! a per-surface artifact describing what may and may not be published.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::claim_entitlement::{ClaimVerdict, ClaimVerdictState};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const CLAIM_PUBLICATION_GATE_SCHEMA_VERSION: &str = "franken-engine.claim-publication-gate.v1";
pub const CLAIM_PUBLICATION_GATE_BEAD_ID: &str = "bd-1lsy.1.7.3";

/// Maximum staleness (in hours) before evidence is considered too old
/// for publication-grade claims.
pub const MAX_PUBLISHABLE_STALENESS_HOURS: u64 = 168;

// ---------------------------------------------------------------------------
// Publication surface
// ---------------------------------------------------------------------------

/// A target surface where claims may be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationSurface {
    /// Public documentation (README, API docs, architecture docs).
    Docs,
    /// Rollout readiness (shadow → canary → active promotion).
    Rollout,
    /// General availability readiness.
    Ga,
    /// React-specific compilation and execution claims.
    React,
    /// V8 supremacy claims (performance board cells).
    Supremacy,
}

impl fmt::Display for PublicationSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Docs => "docs",
            Self::Rollout => "rollout",
            Self::Ga => "ga",
            Self::React => "react",
            Self::Supremacy => "supremacy",
        };
        write!(f, "{label}")
    }
}

/// All surfaces in canonical order.
pub const ALL_SURFACES: [PublicationSurface; 5] = [
    PublicationSurface::Docs,
    PublicationSurface::Rollout,
    PublicationSurface::Ga,
    PublicationSurface::React,
    PublicationSurface::Supremacy,
];

// ---------------------------------------------------------------------------
// Gate decision
// ---------------------------------------------------------------------------

/// The outcome of evaluating a publication gate for a specific surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// All claims for this surface are entitled; publication is approved.
    Approved,
    /// Claims are entitled but with caveats requiring operator awareness.
    ApprovedWithCaveats { caveat_ids: Vec<String> },
    /// Operator must review before publication can proceed.
    RequireOperatorGuidance { reason: String },
    /// Publication is rejected due to missing or invalidated evidence.
    Rejected { reason: String },
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::ApprovedWithCaveats { caveat_ids } => {
                write!(f, "approved_with_caveats({})", caveat_ids.len())
            }
            Self::RequireOperatorGuidance { reason } => {
                write!(f, "require_operator_guidance: {reason}")
            }
            Self::Rejected { reason } => write!(f, "rejected: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Claim tier visibility
// ---------------------------------------------------------------------------

/// Visibility tier for publication: which claim tiers are allowed on which surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationTier {
    /// Full shipped-fact claims (highest confidence).
    ShippedFact,
    /// Scoped observations (true under measured conditions).
    ScopedObserved,
    /// Frontier ambitions (aspirational, not yet proven).
    FrontierAmbition,
}

impl fmt::Display for PublicationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ShippedFact => "shipped_fact",
            Self::ScopedObserved => "scoped_observed",
            Self::FrontierAmbition => "frontier_ambition",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Publishable claim
// ---------------------------------------------------------------------------

/// A claim that has passed the publication gate for a specific surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishableClaim {
    /// The original claim atom ID.
    pub atom_id: String,
    /// Target publication surface.
    pub surface: PublicationSurface,
    /// Publication tier (may be downgraded from the original atom tier).
    pub publication_tier: PublicationTier,
    /// Morphism IDs that support this claim.
    pub supporting_morphisms: Vec<String>,
    /// Impossibility certificate IDs (for scoped/downgraded claims).
    pub impossibility_certificates: Vec<String>,
    /// Domain of the original claim.
    pub domain: String,
    /// Statement summary.
    pub statement: String,
}

impl fmt::Display for PublishableClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}:{}]",
            self.atom_id, self.surface, self.publication_tier
        )
    }
}

// ---------------------------------------------------------------------------
// Frontier gap publication
// ---------------------------------------------------------------------------

/// A frontier gap that must be disclosed alongside published claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierGapDisclosure {
    /// Gap identifier.
    pub gap_id: String,
    /// Human-readable description of the gap.
    pub description: String,
    /// Domain where the gap exists.
    pub domain: String,
    /// Whether this gap blocks any publication surface.
    pub blocks_surfaces: Vec<PublicationSurface>,
    /// Remediation plan or bead reference.
    pub remediation: String,
}

impl fmt::Display for FrontierGapDisclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gap:{}[{}]", self.gap_id, self.domain)
    }
}

// ---------------------------------------------------------------------------
// Risk flag
// ---------------------------------------------------------------------------

/// A risk flag raised during publication gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFlag {
    /// Unique identifier for this flag.
    pub flag_id: String,
    /// Severity: "info", "warning", "critical".
    pub severity: RiskSeverity,
    /// Which surface this flag applies to.
    pub surface: PublicationSurface,
    /// Human-readable description.
    pub description: String,
}

impl fmt::Display for RiskFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}:{}]", self.flag_id, self.severity, self.surface)
    }
}

/// Severity of a risk flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for RiskSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Surface routing configuration
// ---------------------------------------------------------------------------

/// Configuration for which claim domains route to which publication surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceRoutingConfig {
    /// Mapping from claim domain name to allowed publication surfaces.
    pub domain_to_surfaces: BTreeMap<String, Vec<PublicationSurface>>,
    /// Minimum tier required for each surface (claims below this tier are excluded).
    pub min_tier_for_surface: BTreeMap<PublicationSurface, PublicationTier>,
    /// Maximum staleness in hours per surface.
    pub max_staleness_hours: BTreeMap<PublicationSurface, u64>,
}

impl Default for SurfaceRoutingConfig {
    fn default() -> Self {
        let mut domain_to_surfaces = BTreeMap::new();
        domain_to_surfaces.insert(
            "compatibility".to_string(),
            vec![
                PublicationSurface::Docs,
                PublicationSurface::Rollout,
                PublicationSurface::Ga,
            ],
        );
        domain_to_surfaces.insert(
            "shipped_surface".to_string(),
            vec![
                PublicationSurface::Docs,
                PublicationSurface::Rollout,
                PublicationSurface::Ga,
            ],
        );
        domain_to_surfaces.insert(
            "react".to_string(),
            vec![
                PublicationSurface::Docs,
                PublicationSurface::React,
                PublicationSurface::Ga,
            ],
        );
        domain_to_surfaces.insert(
            "supremacy".to_string(),
            vec![PublicationSurface::Supremacy, PublicationSurface::Docs],
        );
        domain_to_surfaces.insert("rollout".to_string(), vec![PublicationSurface::Rollout]);
        domain_to_surfaces.insert("ga".to_string(), vec![PublicationSurface::Ga]);
        domain_to_surfaces.insert("docs".to_string(), vec![PublicationSurface::Docs]);
        domain_to_surfaces.insert(
            "security".to_string(),
            vec![
                PublicationSurface::Docs,
                PublicationSurface::Rollout,
                PublicationSurface::Ga,
            ],
        );
        domain_to_surfaces.insert(
            "support_surface".to_string(),
            vec![PublicationSurface::Docs, PublicationSurface::Rollout],
        );

        let mut min_tier_for_surface = BTreeMap::new();
        // Supremacy requires shipped-fact tier
        min_tier_for_surface.insert(PublicationSurface::Supremacy, PublicationTier::ShippedFact);
        // GA requires at least scoped-observed
        min_tier_for_surface.insert(PublicationSurface::Ga, PublicationTier::ScopedObserved);
        // Rollout requires at least scoped-observed
        min_tier_for_surface.insert(PublicationSurface::Rollout, PublicationTier::ScopedObserved);
        // React requires shipped-fact
        min_tier_for_surface.insert(PublicationSurface::React, PublicationTier::ShippedFact);
        // Docs allows frontier ambitions (with appropriate caveats)
        min_tier_for_surface.insert(PublicationSurface::Docs, PublicationTier::FrontierAmbition);

        let mut max_staleness_hours = BTreeMap::new();
        max_staleness_hours.insert(PublicationSurface::Supremacy, 72);
        max_staleness_hours.insert(PublicationSurface::Ga, MAX_PUBLISHABLE_STALENESS_HOURS);
        max_staleness_hours.insert(PublicationSurface::Rollout, MAX_PUBLISHABLE_STALENESS_HOURS);
        max_staleness_hours.insert(PublicationSurface::React, MAX_PUBLISHABLE_STALENESS_HOURS);
        max_staleness_hours.insert(
            PublicationSurface::Docs,
            MAX_PUBLISHABLE_STALENESS_HOURS * 2,
        );

        Self {
            domain_to_surfaces,
            min_tier_for_surface,
            max_staleness_hours,
        }
    }
}

// ---------------------------------------------------------------------------
// Verdict input (domain-annotated claim verdict)
// ---------------------------------------------------------------------------

/// A claim verdict annotated with domain and tier information for routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnotatedVerdict {
    /// The underlying verdict from claim_entitlement.
    pub verdict: ClaimVerdict,
    /// Claim domain (e.g., "compatibility", "supremacy").
    pub domain: String,
    /// Claim tier name (e.g., "shipped_fact", "scoped_observed").
    pub tier: String,
    /// Statement describing the claim.
    pub statement: String,
    /// Evidence staleness in hours (0 = fresh).
    pub staleness_hours: u64,
}

// ---------------------------------------------------------------------------
// Publication gate evaluation
// ---------------------------------------------------------------------------

/// Full publication gate evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationGateEvaluation {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Epoch at which evaluation was performed.
    pub evaluated_epoch: u64,
    /// Per-surface gate decisions.
    pub gate_decisions: BTreeMap<String, GateDecision>,
    /// Per-surface publishable claims.
    pub surface_claims: BTreeMap<String, Vec<PublishableClaim>>,
    /// Frontier gaps that must be disclosed.
    pub frontier_gaps: Vec<FrontierGapDisclosure>,
    /// Risk flags raised during evaluation.
    pub risk_flags: Vec<RiskFlag>,
    /// Summary counts.
    pub summary: PublicationGateSummary,
}

impl fmt::Display for PublicationGateEvaluation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "publication_gate(epoch={}, approved={}, rejected={}, flags={})",
            self.evaluated_epoch,
            self.summary.approved_surfaces,
            self.summary.rejected_surfaces,
            self.summary.risk_flag_count
        )
    }
}

/// Summary counts for a publication gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationGateSummary {
    /// Total verdicts evaluated.
    pub total_verdicts: usize,
    /// Number of surfaces approved (including with-caveats).
    pub approved_surfaces: usize,
    /// Number of surfaces rejected.
    pub rejected_surfaces: usize,
    /// Number of surfaces requiring operator guidance.
    pub guidance_required_surfaces: usize,
    /// Total publishable claims across all surfaces.
    pub total_publishable_claims: usize,
    /// Total frontier gaps disclosed.
    pub frontier_gap_count: usize,
    /// Total risk flags raised.
    pub risk_flag_count: usize,
}

// ---------------------------------------------------------------------------
// Publication gate error
// ---------------------------------------------------------------------------

/// Error from publication gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicationGateError {
    /// No verdicts provided for evaluation.
    EmptyVerdicts,
    /// Unknown domain encountered in verdict.
    UnknownDomain { domain: String },
    /// Invalid configuration.
    InvalidConfig { reason: String },
}

impl fmt::Display for PublicationGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyVerdicts => write!(f, "no verdicts provided for evaluation"),
            Self::UnknownDomain { domain } => {
                write!(f, "unknown domain in verdict: {domain}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid publication gate config: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Evaluate the publication gate for all surfaces given a set of annotated verdicts.
pub fn evaluate_publication_gate(
    verdicts: &[AnnotatedVerdict],
    frontier_gaps: &[FrontierGapDisclosure],
    config: &SurfaceRoutingConfig,
    epoch: u64,
) -> Result<PublicationGateEvaluation, PublicationGateError> {
    if verdicts.is_empty() {
        return Err(PublicationGateError::EmptyVerdicts);
    }

    let mut surface_claims: BTreeMap<String, Vec<PublishableClaim>> = BTreeMap::new();
    let mut risk_flags: Vec<RiskFlag> = Vec::new();
    let mut flag_counter = 0u64;

    // Route each verdict to its target surfaces
    for av in verdicts {
        let surfaces = route_verdict_to_surfaces(av, config);

        for surface in surfaces {
            let surface_key = surface.to_string();

            // Check tier eligibility
            let pub_tier = match tier_from_str(&av.tier) {
                Some(t) => t,
                None => continue,
            };

            if let Some(min_tier) = config.min_tier_for_surface.get(&surface)
                && !tier_meets_minimum(pub_tier, *min_tier)
            {
                continue;
            }

            // Check staleness
            if let Some(max_hours) = config.max_staleness_hours.get(&surface)
                && av.staleness_hours > *max_hours
            {
                flag_counter += 1;
                risk_flags.push(RiskFlag {
                    flag_id: format!("stale-{flag_counter}"),
                    severity: RiskSeverity::Warning,
                    surface,
                    description: format!(
                        "claim {} has staleness {}h exceeding {}h limit for {}",
                        av.verdict.atom_id, av.staleness_hours, max_hours, surface
                    ),
                });
                continue;
            }

            // Only entitled claims are publishable
            if av.verdict.state == ClaimVerdictState::Entitled {
                let claim = PublishableClaim {
                    atom_id: av.verdict.atom_id.clone(),
                    surface,
                    publication_tier: pub_tier,
                    supporting_morphisms: av.verdict.supporting_morphism_ids.clone(),
                    impossibility_certificates: av.verdict.impossibility_certificate_ids.clone(),
                    domain: av.domain.clone(),
                    statement: av.statement.clone(),
                };
                surface_claims.entry(surface_key).or_default().push(claim);
            } else {
                // Non-entitled claims generate risk flags
                let severity = match av.verdict.state {
                    ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample => {
                        RiskSeverity::Critical
                    }
                    ClaimVerdictState::BlockedByMissingEvidence => RiskSeverity::Warning,
                    ClaimVerdictState::NotYetProven => RiskSeverity::Info,
                    ClaimVerdictState::Entitled => unreachable!(),
                };
                flag_counter += 1;
                risk_flags.push(RiskFlag {
                    flag_id: format!("verdict-{flag_counter}"),
                    severity,
                    surface,
                    description: format!(
                        "claim {} is {:?} on surface {}",
                        av.verdict.atom_id, av.verdict.state, surface
                    ),
                });
            }
        }
    }

    // Check frontier gaps that block surfaces
    for gap in frontier_gaps {
        for surface in &gap.blocks_surfaces {
            flag_counter += 1;
            risk_flags.push(RiskFlag {
                flag_id: format!("gap-{flag_counter}"),
                severity: RiskSeverity::Warning,
                surface: *surface,
                description: format!(
                    "frontier gap {} blocks {}: {}",
                    gap.gap_id, surface, gap.description
                ),
            });
        }
    }

    // Compute per-surface gate decisions
    let mut gate_decisions: BTreeMap<String, GateDecision> = BTreeMap::new();

    for surface in &ALL_SURFACES {
        let surface_key = surface.to_string();
        let claims = surface_claims.get(&surface_key);
        let has_claims = claims.is_some_and(|c| !c.is_empty());

        let surface_flags: Vec<&RiskFlag> = risk_flags
            .iter()
            .filter(|f| f.surface == *surface)
            .collect();

        let has_critical = surface_flags
            .iter()
            .any(|f| f.severity == RiskSeverity::Critical);
        let has_warnings = surface_flags
            .iter()
            .any(|f| f.severity == RiskSeverity::Warning);
        let has_blocking_gaps = frontier_gaps
            .iter()
            .any(|g| g.blocks_surfaces.contains(surface));

        let decision = if has_critical {
            GateDecision::Rejected {
                reason: format!(
                    "critical risk flags on {}: {}",
                    surface,
                    surface_flags
                        .iter()
                        .filter(|f| f.severity == RiskSeverity::Critical)
                        .map(|f| f.flag_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        } else if has_blocking_gaps {
            GateDecision::RequireOperatorGuidance {
                reason: format!("frontier gaps block publication on {surface}"),
            }
        } else if !has_claims {
            GateDecision::Rejected {
                reason: format!("no entitled claims for {surface}"),
            }
        } else if has_warnings {
            let caveat_ids: Vec<String> = surface_flags
                .iter()
                .filter(|f| f.severity == RiskSeverity::Warning)
                .map(|f| f.flag_id.clone())
                .collect();
            GateDecision::ApprovedWithCaveats { caveat_ids }
        } else {
            GateDecision::Approved
        };

        gate_decisions.insert(surface_key, decision);
    }

    // Compute summary
    let total_publishable_claims: usize = surface_claims.values().map(|c| c.len()).sum();
    let approved_surfaces = gate_decisions
        .values()
        .filter(|d| {
            matches!(
                d,
                GateDecision::Approved | GateDecision::ApprovedWithCaveats { .. }
            )
        })
        .count();
    let rejected_surfaces = gate_decisions
        .values()
        .filter(|d| matches!(d, GateDecision::Rejected { .. }))
        .count();
    let guidance_required_surfaces = gate_decisions
        .values()
        .filter(|d| matches!(d, GateDecision::RequireOperatorGuidance { .. }))
        .count();

    Ok(PublicationGateEvaluation {
        schema_version: CLAIM_PUBLICATION_GATE_SCHEMA_VERSION.to_string(),
        bead_id: CLAIM_PUBLICATION_GATE_BEAD_ID.to_string(),
        evaluated_epoch: epoch,
        gate_decisions,
        surface_claims,
        frontier_gaps: frontier_gaps.to_vec(),
        risk_flags,
        summary: PublicationGateSummary {
            total_verdicts: verdicts.len(),
            approved_surfaces,
            rejected_surfaces,
            guidance_required_surfaces,
            total_publishable_claims,
            frontier_gap_count: frontier_gaps.len(),
            risk_flag_count: flag_counter as usize,
        },
    })
}

/// Route a verdict to its target publication surfaces based on domain routing config.
pub fn route_verdict_to_surfaces(
    av: &AnnotatedVerdict,
    config: &SurfaceRoutingConfig,
) -> Vec<PublicationSurface> {
    config
        .domain_to_surfaces
        .get(&av.domain)
        .cloned()
        .unwrap_or_default()
}

/// Render a human-readable summary of a publication gate evaluation.
pub fn render_publication_gate_summary(eval: &PublicationGateEvaluation) -> String {
    let mut lines = vec![
        format!("schema_version: {}", eval.schema_version),
        format!("evaluated_epoch: {}", eval.evaluated_epoch),
        format!("total_verdicts: {}", eval.summary.total_verdicts),
        format!("approved_surfaces: {}", eval.summary.approved_surfaces),
        format!("rejected_surfaces: {}", eval.summary.rejected_surfaces),
        format!(
            "guidance_required: {}",
            eval.summary.guidance_required_surfaces
        ),
        format!(
            "publishable_claims: {}",
            eval.summary.total_publishable_claims
        ),
        format!("frontier_gaps: {}", eval.summary.frontier_gap_count),
        format!("risk_flags: {}", eval.summary.risk_flag_count),
        String::new(),
        "--- Per-surface decisions ---".to_string(),
    ];

    for (surface, decision) in &eval.gate_decisions {
        lines.push(format!("  {surface}: {decision}"));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn tier_from_str(tier: &str) -> Option<PublicationTier> {
    match tier {
        "shipped_fact" => Some(PublicationTier::ShippedFact),
        "scoped_observed" => Some(PublicationTier::ScopedObserved),
        "frontier_ambition" => Some(PublicationTier::FrontierAmbition),
        _ => None,
    }
}

fn tier_meets_minimum(actual: PublicationTier, minimum: PublicationTier) -> bool {
    // ShippedFact > ScopedObserved > FrontierAmbition
    let rank = |t: PublicationTier| -> u8 {
        match t {
            PublicationTier::ShippedFact => 2,
            PublicationTier::ScopedObserved => 1,
            PublicationTier::FrontierAmbition => 0,
        }
    };
    rank(actual) >= rank(minimum)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entitled_verdict(atom_id: &str) -> ClaimVerdict {
        ClaimVerdict {
            atom_id: atom_id.to_string(),
            state: ClaimVerdictState::Entitled,
            supporting_morphism_ids: vec![format!("morph-{atom_id}")],
            active_rule_ids: Vec::new(),
            minimal_cutset_ids: Vec::new(),
            impossibility_certificate_ids: Vec::new(),
        }
    }

    fn blocked_verdict(atom_id: &str) -> ClaimVerdict {
        ClaimVerdict {
            atom_id: atom_id.to_string(),
            state: ClaimVerdictState::BlockedByMissingEvidence,
            supporting_morphism_ids: Vec::new(),
            active_rule_ids: Vec::new(),
            minimal_cutset_ids: vec![format!("cutset-{atom_id}")],
            impossibility_certificate_ids: Vec::new(),
        }
    }

    fn counterexample_verdict(atom_id: &str) -> ClaimVerdict {
        ClaimVerdict {
            atom_id: atom_id.to_string(),
            state: ClaimVerdictState::CurrentlyFalseUnderActiveCounterexample,
            supporting_morphism_ids: Vec::new(),
            active_rule_ids: vec![format!("rule-{atom_id}")],
            minimal_cutset_ids: Vec::new(),
            impossibility_certificate_ids: vec![format!("cert-{atom_id}")],
        }
    }

    fn make_annotated(verdict: ClaimVerdict, domain: &str, tier: &str) -> AnnotatedVerdict {
        AnnotatedVerdict {
            statement: format!("Test claim {}", verdict.atom_id),
            verdict,
            domain: domain.to_string(),
            tier: tier.to_string(),
            staleness_hours: 0,
        }
    }

    fn make_stale_annotated(
        verdict: ClaimVerdict,
        domain: &str,
        tier: &str,
        staleness_hours: u64,
    ) -> AnnotatedVerdict {
        AnnotatedVerdict {
            statement: format!("Test claim {}", verdict.atom_id),
            verdict,
            domain: domain.to_string(),
            tier: tier.to_string(),
            staleness_hours,
        }
    }

    fn default_config() -> SurfaceRoutingConfig {
        SurfaceRoutingConfig::default()
    }

    // -- Display --

    #[test]
    fn surface_display_all() {
        assert_eq!(PublicationSurface::Docs.to_string(), "docs");
        assert_eq!(PublicationSurface::Rollout.to_string(), "rollout");
        assert_eq!(PublicationSurface::Ga.to_string(), "ga");
        assert_eq!(PublicationSurface::React.to_string(), "react");
        assert_eq!(PublicationSurface::Supremacy.to_string(), "supremacy");
    }

    #[test]
    fn gate_decision_display() {
        assert_eq!(GateDecision::Approved.to_string(), "approved");
        let caveats = GateDecision::ApprovedWithCaveats {
            caveat_ids: vec!["c1".to_string()],
        };
        assert!(caveats.to_string().contains("approved_with_caveats"));
        let rejected = GateDecision::Rejected {
            reason: "fail".to_string(),
        };
        assert!(rejected.to_string().contains("rejected"));
        let guidance = GateDecision::RequireOperatorGuidance {
            reason: "check".to_string(),
        };
        assert!(guidance.to_string().contains("require_operator_guidance"));
    }

    #[test]
    fn publication_tier_display() {
        assert_eq!(PublicationTier::ShippedFact.to_string(), "shipped_fact");
        assert_eq!(
            PublicationTier::ScopedObserved.to_string(),
            "scoped_observed"
        );
        assert_eq!(
            PublicationTier::FrontierAmbition.to_string(),
            "frontier_ambition"
        );
    }

    #[test]
    fn risk_severity_display() {
        assert_eq!(RiskSeverity::Info.to_string(), "info");
        assert_eq!(RiskSeverity::Warning.to_string(), "warning");
        assert_eq!(RiskSeverity::Critical.to_string(), "critical");
    }

    // -- Serde round-trips --

    #[test]
    fn surface_serde_round_trip() {
        for s in &ALL_SURFACES {
            let json = serde_json::to_string(s).expect("serialize");
            let deser: PublicationSurface = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*s, deser);
        }
    }

    #[test]
    fn gate_decision_serde_round_trip() {
        let decisions = [
            GateDecision::Approved,
            GateDecision::ApprovedWithCaveats {
                caveat_ids: vec!["c1".to_string()],
            },
            GateDecision::RequireOperatorGuidance {
                reason: "test".to_string(),
            },
            GateDecision::Rejected {
                reason: "fail".to_string(),
            },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).expect("serialize");
            let deser: GateDecision = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*d, deser);
        }
    }

    #[test]
    fn publishable_claim_serde_round_trip() {
        let claim = PublishableClaim {
            atom_id: "atom-1".to_string(),
            surface: PublicationSurface::Docs,
            publication_tier: PublicationTier::ShippedFact,
            supporting_morphisms: vec!["m1".to_string()],
            impossibility_certificates: Vec::new(),
            domain: "compatibility".to_string(),
            statement: "ES2024 strict mode".to_string(),
        };
        let json = serde_json::to_string(&claim).expect("serialize");
        let deser: PublishableClaim = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(claim, deser);
    }

    #[test]
    fn frontier_gap_serde_round_trip() {
        let gap = FrontierGapDisclosure {
            gap_id: "gap-1".to_string(),
            description: "Missing generator support".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Ga],
            remediation: "bd-1lsy.4.9".to_string(),
        };
        let json = serde_json::to_string(&gap).expect("serialize");
        let deser: FrontierGapDisclosure = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(gap, deser);
    }

    #[test]
    fn risk_flag_serde_round_trip() {
        let flag = RiskFlag {
            flag_id: "rf-1".to_string(),
            severity: RiskSeverity::Warning,
            surface: PublicationSurface::Supremacy,
            description: "stale evidence".to_string(),
        };
        let json = serde_json::to_string(&flag).expect("serialize");
        let deser: RiskFlag = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(flag, deser);
    }

    #[test]
    fn evaluation_serde_round_trip() {
        let verdicts = vec![make_annotated(
            entitled_verdict("a"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 42).expect("evaluate");
        let json = serde_json::to_string(&eval).expect("serialize");
        let deser: PublicationGateEvaluation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(eval, deser);
    }

    // -- Tier helpers --

    #[test]
    fn tier_from_str_valid() {
        assert_eq!(
            tier_from_str("shipped_fact"),
            Some(PublicationTier::ShippedFact)
        );
        assert_eq!(
            tier_from_str("scoped_observed"),
            Some(PublicationTier::ScopedObserved)
        );
        assert_eq!(
            tier_from_str("frontier_ambition"),
            Some(PublicationTier::FrontierAmbition)
        );
    }

    #[test]
    fn tier_from_str_invalid() {
        assert_eq!(tier_from_str("unknown"), None);
        assert_eq!(tier_from_str("unsupported_surface"), None);
    }

    #[test]
    fn tier_meets_minimum_shipped_fact() {
        assert!(tier_meets_minimum(
            PublicationTier::ShippedFact,
            PublicationTier::ShippedFact
        ));
        assert!(tier_meets_minimum(
            PublicationTier::ShippedFact,
            PublicationTier::ScopedObserved
        ));
        assert!(tier_meets_minimum(
            PublicationTier::ShippedFact,
            PublicationTier::FrontierAmbition
        ));
    }

    #[test]
    fn tier_meets_minimum_scoped_observed() {
        assert!(!tier_meets_minimum(
            PublicationTier::ScopedObserved,
            PublicationTier::ShippedFact
        ));
        assert!(tier_meets_minimum(
            PublicationTier::ScopedObserved,
            PublicationTier::ScopedObserved
        ));
        assert!(tier_meets_minimum(
            PublicationTier::ScopedObserved,
            PublicationTier::FrontierAmbition
        ));
    }

    #[test]
    fn tier_meets_minimum_frontier_only_docs() {
        assert!(!tier_meets_minimum(
            PublicationTier::FrontierAmbition,
            PublicationTier::ShippedFact
        ));
        assert!(!tier_meets_minimum(
            PublicationTier::FrontierAmbition,
            PublicationTier::ScopedObserved
        ));
        assert!(tier_meets_minimum(
            PublicationTier::FrontierAmbition,
            PublicationTier::FrontierAmbition
        ));
    }

    // -- Routing --

    #[test]
    fn route_compatibility_to_docs_rollout_ga() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("a"), "compatibility", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::Docs));
        assert!(surfaces.contains(&PublicationSurface::Rollout));
        assert!(surfaces.contains(&PublicationSurface::Ga));
    }

    #[test]
    fn route_supremacy_to_supremacy_and_docs() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("s"), "supremacy", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::Supremacy));
        assert!(surfaces.contains(&PublicationSurface::Docs));
    }

    #[test]
    fn route_react_to_react_docs_ga() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("r"), "react", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::React));
        assert!(surfaces.contains(&PublicationSurface::Docs));
        assert!(surfaces.contains(&PublicationSurface::Ga));
    }

    #[test]
    fn route_unknown_domain_returns_empty() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("x"), "unknown_domain", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.is_empty());
    }

    // -- Gate evaluation --

    #[test]
    fn empty_verdicts_error() {
        let result = evaluate_publication_gate(&[], &[], &default_config(), 0);
        assert!(matches!(result, Err(PublicationGateError::EmptyVerdicts)));
    }

    #[test]
    fn all_entitled_compatibility_approved() {
        let verdicts = vec![make_annotated(
            entitled_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        // Should be approved on docs, rollout, ga
        let docs_decision = eval.gate_decisions.get("docs").expect("docs decision");
        assert!(matches!(docs_decision, GateDecision::Approved));
    }

    #[test]
    fn blocked_verdict_rejects_surface() {
        let verdicts = vec![make_annotated(
            blocked_verdict("c1"),
            "supremacy",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let sup_decision = eval.gate_decisions.get("supremacy").expect("sup decision");
        // No entitled claims → rejected
        assert!(matches!(sup_decision, GateDecision::Rejected { .. }));
    }

    #[test]
    fn counterexample_verdict_rejects_surface() {
        let verdicts = vec![make_annotated(
            counterexample_verdict("c1"),
            "supremacy",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let sup_decision = eval.gate_decisions.get("supremacy").expect("sup decision");
        assert!(matches!(sup_decision, GateDecision::Rejected { .. }));
    }

    #[test]
    fn mixed_entitled_and_blocked_shows_caveats() {
        let verdicts = vec![
            make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
            make_annotated(blocked_verdict("c2"), "compatibility", "shipped_fact"),
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_decision = eval.gate_decisions.get("docs").expect("docs decision");
        assert!(matches!(
            docs_decision,
            GateDecision::ApprovedWithCaveats { .. }
        ));
    }

    #[test]
    fn frontier_gap_requires_guidance() {
        let verdicts = vec![make_annotated(
            entitled_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let gaps = vec![FrontierGapDisclosure {
            gap_id: "gap-1".to_string(),
            description: "Missing generator support".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Ga],
            remediation: "bd-test".to_string(),
        }];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        let ga_decision = eval.gate_decisions.get("ga").expect("ga decision");
        assert!(matches!(
            ga_decision,
            GateDecision::RequireOperatorGuidance { .. }
        ));
    }

    #[test]
    fn stale_evidence_generates_warning() {
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("c1"),
            "supremacy",
            "shipped_fact",
            200, // exceeds 72h supremacy limit
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        assert!(!eval.risk_flags.is_empty());
        let stale_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.description.contains("staleness"))
            .collect();
        assert!(!stale_flags.is_empty());
    }

    #[test]
    fn scoped_tier_excluded_from_supremacy() {
        let verdicts = vec![make_annotated(
            entitled_verdict("s1"),
            "supremacy",
            "scoped_observed", // below shipped_fact minimum for supremacy
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let sup_claims = eval.surface_claims.get("supremacy");
        assert!(sup_claims.is_none() || sup_claims.is_some_and(|c| c.is_empty()));
    }

    #[test]
    fn frontier_tier_allowed_on_docs() {
        let verdicts = vec![make_annotated(
            entitled_verdict("d1"),
            "compatibility",
            "frontier_ambition",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_claims = eval.surface_claims.get("docs");
        assert!(docs_claims.is_some_and(|c| !c.is_empty()));
    }

    #[test]
    fn frontier_tier_excluded_from_ga() {
        let verdicts = vec![make_annotated(
            entitled_verdict("d1"),
            "compatibility",
            "frontier_ambition",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let ga_claims = eval.surface_claims.get("ga");
        // frontier_ambition doesn't meet scoped_observed min for GA
        assert!(ga_claims.is_none() || ga_claims.is_some_and(|c| c.is_empty()));
    }

    #[test]
    fn summary_counts_correct() {
        let verdicts = vec![
            make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
            make_annotated(entitled_verdict("r1"), "react", "shipped_fact"),
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.total_verdicts, 2);
        assert!(eval.summary.total_publishable_claims > 0);
    }

    #[test]
    fn render_summary_contains_key_fields() {
        let verdicts = vec![make_annotated(
            entitled_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 42).expect("evaluate");
        let summary = render_publication_gate_summary(&eval);
        assert!(summary.contains("evaluated_epoch: 42"));
        assert!(summary.contains("total_verdicts: 1"));
    }

    #[test]
    fn default_config_serde_round_trip() {
        let config = default_config();
        let json = serde_json::to_string(&config).expect("serialize");
        let deser: SurfaceRoutingConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, deser);
    }

    #[test]
    fn evaluation_display_format() {
        let verdicts = vec![make_annotated(
            entitled_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 5).expect("evaluate");
        let display = format!("{eval}");
        assert!(display.contains("publication_gate"));
        assert!(display.contains("epoch=5"));
    }

    #[test]
    fn multiple_surfaces_independent_decisions() {
        let verdicts = vec![
            make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
            make_annotated(counterexample_verdict("s1"), "supremacy", "shipped_fact"),
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_decision = eval.gate_decisions.get("docs").expect("docs");
        let sup_decision = eval.gate_decisions.get("supremacy").expect("supremacy");
        // Docs is rejected because the supremacy counterexample also routes
        // to docs and produces a critical risk flag (fail-closed).
        // Supremacy should be rejected (counterexample)
        assert!(matches!(docs_decision, GateDecision::Rejected { .. }));
        assert!(matches!(sup_decision, GateDecision::Rejected { .. }));
    }

    #[test]
    fn publishable_claim_display() {
        let claim = PublishableClaim {
            atom_id: "test".to_string(),
            surface: PublicationSurface::Docs,
            publication_tier: PublicationTier::ShippedFact,
            supporting_morphisms: Vec::new(),
            impossibility_certificates: Vec::new(),
            domain: "compat".to_string(),
            statement: "test".to_string(),
        };
        assert!(claim.to_string().contains("test"));
        assert!(claim.to_string().contains("docs"));
    }

    #[test]
    fn error_display() {
        let e = PublicationGateError::EmptyVerdicts;
        assert!(e.to_string().contains("no verdicts"));
        let e = PublicationGateError::UnknownDomain {
            domain: "foo".to_string(),
        };
        assert!(e.to_string().contains("foo"));
        let e = PublicationGateError::InvalidConfig {
            reason: "bad".to_string(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn all_surfaces_in_gate_decisions() {
        let verdicts = vec![make_annotated(
            entitled_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 0).expect("evaluate");
        for surface in &ALL_SURFACES {
            assert!(
                eval.gate_decisions.contains_key(&surface.to_string()),
                "missing gate decision for {surface}"
            );
        }
    }

    #[test]
    fn no_entitled_claims_all_rejected() {
        let verdicts = vec![make_annotated(
            blocked_verdict("c1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 0).expect("evaluate");
        // All surfaces with compat routing should be rejected (no entitled)
        // Surfaces without compat routing should also be rejected (no claims at all)
        for decision in eval.gate_decisions.values() {
            assert!(
                matches!(
                    decision,
                    GateDecision::Rejected { .. } | GateDecision::ApprovedWithCaveats { .. }
                ),
                "expected rejected or caveats, got {decision}"
            );
        }
    }

    #[test]
    fn security_domain_routes_to_docs_rollout_ga() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("sec1"), "security", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::Docs));
        assert!(surfaces.contains(&PublicationSurface::Rollout));
        assert!(surfaces.contains(&PublicationSurface::Ga));
    }

    #[test]
    fn multiple_gaps_multiple_surfaces() {
        let verdicts = vec![
            make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
            make_annotated(entitled_verdict("r1"), "react", "shipped_fact"),
        ];
        let gaps = vec![
            FrontierGapDisclosure {
                gap_id: "gap-1".to_string(),
                description: "Missing generators".to_string(),
                domain: "compatibility".to_string(),
                blocks_surfaces: vec![PublicationSurface::Ga],
                remediation: "bd-test1".to_string(),
            },
            FrontierGapDisclosure {
                gap_id: "gap-2".to_string(),
                description: "Missing React SSR".to_string(),
                domain: "react".to_string(),
                blocks_surfaces: vec![PublicationSurface::React],
                remediation: "bd-test2".to_string(),
            },
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.frontier_gap_count, 2);
        let ga = eval.gate_decisions.get("ga").expect("ga");
        assert!(matches!(ga, GateDecision::RequireOperatorGuidance { .. }));
        let react = eval.gate_decisions.get("react").expect("react");
        assert!(matches!(
            react,
            GateDecision::RequireOperatorGuidance { .. }
        ));
    }

    #[test]
    fn publication_gate_error_serde_round_trip() {
        let errors = [
            PublicationGateError::EmptyVerdicts,
            PublicationGateError::UnknownDomain {
                domain: "test".to_string(),
            },
            PublicationGateError::InvalidConfig {
                reason: "bad config".to_string(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).expect("serialize");
            let deser: PublicationGateError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*e, deser);
        }
    }

    // -----------------------------------------------------------------------
    // Additional tests: edge cases, determinism, routing, tier boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn not_yet_proven_generates_info_risk_flag() {
        let verdict = ClaimVerdict {
            atom_id: "nyp-1".to_string(),
            state: ClaimVerdictState::NotYetProven,
            supporting_morphism_ids: Vec::new(),
            active_rule_ids: Vec::new(),
            minimal_cutset_ids: Vec::new(),
            impossibility_certificate_ids: Vec::new(),
        };
        let verdicts = vec![make_annotated(verdict, "compatibility", "shipped_fact")];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let info_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.severity == RiskSeverity::Info)
            .collect();
        assert!(
            !info_flags.is_empty(),
            "NotYetProven should produce info-severity flags"
        );
    }

    #[test]
    fn counterexample_generates_critical_risk_flag() {
        let verdicts = vec![make_annotated(
            counterexample_verdict("cx-1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let critical_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.severity == RiskSeverity::Critical)
            .collect();
        assert!(
            !critical_flags.is_empty(),
            "counterexample should produce critical flags"
        );
    }

    #[test]
    fn schema_version_and_bead_id_in_evaluation() {
        let verdicts = vec![make_annotated(
            entitled_verdict("sv-1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 99).expect("evaluate");
        assert_eq!(eval.schema_version, CLAIM_PUBLICATION_GATE_SCHEMA_VERSION);
        assert_eq!(eval.bead_id, CLAIM_PUBLICATION_GATE_BEAD_ID);
        assert_eq!(eval.evaluated_epoch, 99);
    }

    #[test]
    fn staleness_at_exact_boundary_is_not_flagged() {
        // Supremacy has 72h max staleness; exactly 72 should pass
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("boundary-1"),
            "supremacy",
            "shipped_fact",
            72,
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let stale_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.description.contains("staleness"))
            .collect();
        assert!(
            stale_flags.is_empty(),
            "staleness at exact boundary should not be flagged"
        );
        let sup_claims = eval.surface_claims.get("supremacy");
        assert!(sup_claims.is_some_and(|c| !c.is_empty()));
    }

    #[test]
    fn staleness_one_over_boundary_is_flagged() {
        // Supremacy has 72h max staleness; 73 should be flagged
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("over-1"),
            "supremacy",
            "shipped_fact",
            73,
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let stale_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.description.contains("staleness"))
            .collect();
        assert!(
            !stale_flags.is_empty(),
            "staleness 1 over boundary should be flagged"
        );
        // The claim should NOT appear in surface_claims because it was skipped
        let sup_claims = eval.surface_claims.get("supremacy");
        assert!(sup_claims.is_none() || sup_claims.is_some_and(|c| c.is_empty()));
    }

    #[test]
    fn docs_has_double_max_staleness() {
        // Docs allows MAX_PUBLISHABLE_STALENESS_HOURS * 2 = 336h
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("docs-stale-1"),
            "docs",
            "frontier_ambition",
            335,
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_claims = eval.surface_claims.get("docs");
        assert!(
            docs_claims.is_some_and(|c| !c.is_empty()),
            "335h should be within docs limit"
        );
    }

    #[test]
    fn docs_staleness_exceeded() {
        // Docs allows 336h; 337 should be stale
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("docs-stale-2"),
            "docs",
            "frontier_ambition",
            337,
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_claims = eval.surface_claims.get("docs");
        assert!(
            docs_claims.is_none() || docs_claims.is_some_and(|c| c.is_empty()),
            "337h should exceed docs staleness limit"
        );
    }

    #[test]
    fn invalid_tier_string_skips_verdict() {
        let verdicts = vec![make_annotated(
            entitled_verdict("bad-tier-1"),
            "compatibility",
            "bogus_tier",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        // No claims should be routed because tier_from_str returns None
        assert_eq!(eval.summary.total_publishable_claims, 0);
    }

    #[test]
    fn unknown_domain_verdict_produces_no_claims() {
        let verdicts = vec![make_annotated(
            entitled_verdict("unk-1"),
            "nonexistent_domain",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.total_publishable_claims, 0);
        // All surfaces should be rejected (no claims anywhere)
        for decision in eval.gate_decisions.values() {
            assert!(matches!(decision, GateDecision::Rejected { .. }));
        }
    }

    #[test]
    fn rollout_domain_routes_only_to_rollout() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("ro-1"), "rollout", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert_eq!(surfaces, vec![PublicationSurface::Rollout]);
    }

    #[test]
    fn ga_domain_routes_only_to_ga() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("ga-1"), "ga", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert_eq!(surfaces, vec![PublicationSurface::Ga]);
    }

    #[test]
    fn docs_domain_routes_only_to_docs() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("d-1"), "docs", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert_eq!(surfaces, vec![PublicationSurface::Docs]);
    }

    #[test]
    fn support_surface_domain_routes_to_docs_and_rollout() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("ss-1"), "support_surface", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::Docs));
        assert!(surfaces.contains(&PublicationSurface::Rollout));
        assert_eq!(surfaces.len(), 2);
    }

    #[test]
    fn shipped_surface_domain_routing() {
        let config = default_config();
        let av = make_annotated(entitled_verdict("sh-1"), "shipped_surface", "shipped_fact");
        let surfaces = route_verdict_to_surfaces(&av, &config);
        assert!(surfaces.contains(&PublicationSurface::Docs));
        assert!(surfaces.contains(&PublicationSurface::Rollout));
        assert!(surfaces.contains(&PublicationSurface::Ga));
        assert_eq!(surfaces.len(), 3);
    }

    #[test]
    fn frontier_gap_disclosure_display_format() {
        let gap = FrontierGapDisclosure {
            gap_id: "g-42".to_string(),
            description: "Missing async iterators".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Ga],
            remediation: "bd-xyz".to_string(),
        };
        let display = gap.to_string();
        assert!(display.contains("g-42"));
        assert!(display.contains("compatibility"));
        assert!(display.starts_with("gap:"));
    }

    #[test]
    fn risk_flag_display_format() {
        let flag = RiskFlag {
            flag_id: "rf-99".to_string(),
            severity: RiskSeverity::Critical,
            surface: PublicationSurface::React,
            description: "test flag".to_string(),
        };
        let display = flag.to_string();
        assert!(display.contains("rf-99"));
        assert!(display.contains("critical"));
        assert!(display.contains("react"));
    }

    #[test]
    fn publishable_claim_display_includes_tier() {
        let claim = PublishableClaim {
            atom_id: "atom-tier".to_string(),
            surface: PublicationSurface::Supremacy,
            publication_tier: PublicationTier::ScopedObserved,
            supporting_morphisms: Vec::new(),
            impossibility_certificates: Vec::new(),
            domain: "supremacy".to_string(),
            statement: "perf claim".to_string(),
        };
        let display = claim.to_string();
        assert!(display.contains("atom-tier"));
        assert!(display.contains("supremacy"));
        assert!(display.contains("scoped_observed"));
    }

    #[test]
    fn evaluation_display_shows_flag_count() {
        let verdicts = vec![
            make_annotated(entitled_verdict("c1"), "compatibility", "shipped_fact"),
            make_annotated(blocked_verdict("c2"), "compatibility", "shipped_fact"),
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 10).expect("evaluate");
        let display = format!("{eval}");
        assert!(display.contains("epoch=10"));
        assert!(display.contains("flags="));
    }

    #[test]
    fn gate_decision_display_approved_with_caveats_count() {
        let decision = GateDecision::ApprovedWithCaveats {
            caveat_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };
        assert_eq!(decision.to_string(), "approved_with_caveats(3)");
    }

    #[test]
    fn gate_decision_display_rejected_reason() {
        let decision = GateDecision::Rejected {
            reason: "no entitled claims".to_string(),
        };
        assert_eq!(decision.to_string(), "rejected: no entitled claims");
    }

    #[test]
    fn gate_decision_display_guidance_reason() {
        let decision = GateDecision::RequireOperatorGuidance {
            reason: "frontier gaps block".to_string(),
        };
        assert_eq!(
            decision.to_string(),
            "require_operator_guidance: frontier gaps block"
        );
    }

    #[test]
    fn critical_flag_takes_precedence_over_gaps() {
        // When a surface has both critical flags and blocking gaps,
        // the critical flag should result in Rejected (not RequireOperatorGuidance)
        let verdicts = vec![make_annotated(
            counterexample_verdict("cx-prec"),
            "compatibility",
            "shipped_fact",
        )];
        let gaps = vec![FrontierGapDisclosure {
            gap_id: "gap-prec".to_string(),
            description: "test gap".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Docs, PublicationSurface::Rollout],
            remediation: "bd-prec".to_string(),
        }];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        let docs = eval.gate_decisions.get("docs").expect("docs");
        // Critical flags should override gap-based guidance
        assert!(matches!(docs, GateDecision::Rejected { .. }));
    }

    #[test]
    fn gap_blocking_no_surfaces_has_no_effect() {
        let verdicts = vec![make_annotated(
            entitled_verdict("g-none"),
            "compatibility",
            "shipped_fact",
        )];
        let gaps = vec![FrontierGapDisclosure {
            gap_id: "gap-empty".to_string(),
            description: "gap that blocks nothing".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: Vec::new(),
            remediation: "bd-none".to_string(),
        }];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        // Docs should be approved since gap blocks no surfaces
        let docs = eval.gate_decisions.get("docs").expect("docs");
        assert!(matches!(docs, GateDecision::Approved));
    }

    #[test]
    fn many_verdicts_all_entitled_single_domain() {
        let verdicts: Vec<_> = (0..20)
            .map(|i| {
                make_annotated(
                    entitled_verdict(&format!("bulk-{i}")),
                    "compatibility",
                    "shipped_fact",
                )
            })
            .collect();
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.total_verdicts, 20);
        // Each verdict routes to docs, rollout, ga => 20 * 3 = 60 claims
        assert_eq!(eval.summary.total_publishable_claims, 60);
        let docs = eval.gate_decisions.get("docs").expect("docs");
        assert!(matches!(docs, GateDecision::Approved));
    }

    #[test]
    fn scoped_observed_allowed_on_rollout_and_ga() {
        let verdicts = vec![make_annotated(
            entitled_verdict("so-1"),
            "compatibility",
            "scoped_observed",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let rollout_claims = eval.surface_claims.get("rollout");
        assert!(rollout_claims.is_some_and(|c| !c.is_empty()));
        let ga_claims = eval.surface_claims.get("ga");
        assert!(ga_claims.is_some_and(|c| !c.is_empty()));
    }

    #[test]
    fn scoped_observed_excluded_from_react_surface() {
        // React requires shipped_fact
        let verdicts = vec![make_annotated(
            entitled_verdict("so-react"),
            "react",
            "scoped_observed",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let react_claims = eval.surface_claims.get("react");
        assert!(
            react_claims.is_none() || react_claims.is_some_and(|c| c.is_empty()),
            "scoped_observed should not appear on react surface"
        );
    }

    #[test]
    fn render_summary_includes_per_surface_decisions() {
        let verdicts = vec![make_annotated(
            entitled_verdict("render-1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 7).expect("evaluate");
        let summary = render_publication_gate_summary(&eval);
        assert!(summary.contains("Per-surface decisions"));
        assert!(summary.contains("docs:"));
        assert!(summary.contains("rollout:"));
        assert!(summary.contains("ga:"));
        assert!(summary.contains("react:"));
        assert!(summary.contains("supremacy:"));
    }

    #[test]
    fn render_summary_shows_schema_version() {
        let verdicts = vec![make_annotated(
            entitled_verdict("schema-1"),
            "docs",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let summary = render_publication_gate_summary(&eval);
        assert!(summary.contains(CLAIM_PUBLICATION_GATE_SCHEMA_VERSION));
    }

    #[test]
    fn surface_ordering_is_deterministic() {
        // PublicationSurface derives Ord; verify canonical ordering
        let mut surfaces = vec![
            PublicationSurface::Supremacy,
            PublicationSurface::React,
            PublicationSurface::Ga,
            PublicationSurface::Rollout,
            PublicationSurface::Docs,
        ];
        surfaces.sort();
        assert_eq!(surfaces, ALL_SURFACES.to_vec());
    }

    #[test]
    fn risk_severity_ordering() {
        assert!(RiskSeverity::Info < RiskSeverity::Warning);
        assert!(RiskSeverity::Warning < RiskSeverity::Critical);
        assert!(RiskSeverity::Info < RiskSeverity::Critical);
    }

    #[test]
    fn publication_tier_ordering() {
        assert!(PublicationTier::ShippedFact < PublicationTier::ScopedObserved);
        assert!(PublicationTier::ScopedObserved < PublicationTier::FrontierAmbition);
    }

    #[test]
    fn annotated_verdict_serde_round_trip() {
        let av = make_stale_annotated(
            entitled_verdict("serde-av"),
            "supremacy",
            "shipped_fact",
            42,
        );
        let json = serde_json::to_string(&av).expect("serialize");
        let deser: AnnotatedVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(av, deser);
    }

    #[test]
    fn publication_gate_summary_serde_round_trip() {
        let summary = PublicationGateSummary {
            total_verdicts: 10,
            approved_surfaces: 3,
            rejected_surfaces: 1,
            guidance_required_surfaces: 1,
            total_publishable_claims: 25,
            frontier_gap_count: 2,
            risk_flag_count: 4,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        let deser: PublicationGateSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(summary, deser);
    }

    #[test]
    fn risk_severity_serde_round_trip() {
        for severity in [
            RiskSeverity::Info,
            RiskSeverity::Warning,
            RiskSeverity::Critical,
        ] {
            let json = serde_json::to_string(&severity).expect("serialize");
            let deser: RiskSeverity = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(severity, deser);
        }
    }

    #[test]
    fn publication_tier_serde_round_trip() {
        for tier in [
            PublicationTier::ShippedFact,
            PublicationTier::ScopedObserved,
            PublicationTier::FrontierAmbition,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize");
            let deser: PublicationTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(tier, deser);
        }
    }

    #[test]
    fn evaluation_determinism_same_inputs() {
        let verdicts = vec![
            make_annotated(entitled_verdict("det-1"), "compatibility", "shipped_fact"),
            make_annotated(blocked_verdict("det-2"), "supremacy", "shipped_fact"),
            make_annotated(entitled_verdict("det-3"), "react", "shipped_fact"),
        ];
        let gaps = vec![FrontierGapDisclosure {
            gap_id: "det-gap".to_string(),
            description: "det test".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Ga],
            remediation: "bd-det".to_string(),
        }];
        let eval1 =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 50).expect("eval1");
        let eval2 =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 50).expect("eval2");
        // Same inputs must produce identical outputs
        assert_eq!(eval1.gate_decisions, eval2.gate_decisions);
        assert_eq!(eval1.surface_claims, eval2.surface_claims);
        assert_eq!(eval1.risk_flags, eval2.risk_flags);
        assert_eq!(eval1.summary, eval2.summary);
    }

    #[test]
    fn empty_frontier_gaps_produces_zero_gap_count() {
        let verdicts = vec![make_annotated(
            entitled_verdict("no-gap"),
            "docs",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.frontier_gap_count, 0);
        assert!(eval.frontier_gaps.is_empty());
    }

    #[test]
    fn frontier_gaps_preserved_in_evaluation() {
        let verdicts = vec![make_annotated(
            entitled_verdict("gap-pres"),
            "docs",
            "shipped_fact",
        )];
        let gaps = vec![
            FrontierGapDisclosure {
                gap_id: "g1".to_string(),
                description: "first gap".to_string(),
                domain: "compat".to_string(),
                blocks_surfaces: Vec::new(),
                remediation: "bd-g1".to_string(),
            },
            FrontierGapDisclosure {
                gap_id: "g2".to_string(),
                description: "second gap".to_string(),
                domain: "react".to_string(),
                blocks_surfaces: vec![PublicationSurface::React],
                remediation: "bd-g2".to_string(),
            },
        ];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        assert_eq!(eval.frontier_gaps.len(), 2);
        assert_eq!(eval.frontier_gaps[0].gap_id, "g1");
        assert_eq!(eval.frontier_gaps[1].gap_id, "g2");
    }

    #[test]
    fn summary_guidance_required_counted_correctly() {
        let verdicts = vec![make_annotated(
            entitled_verdict("guide-1"),
            "compatibility",
            "shipped_fact",
        )];
        let gaps = vec![FrontierGapDisclosure {
            gap_id: "guide-gap".to_string(),
            description: "test".to_string(),
            domain: "compatibility".to_string(),
            blocks_surfaces: vec![PublicationSurface::Rollout, PublicationSurface::Ga],
            remediation: "bd-guide".to_string(),
        }];
        let eval =
            evaluate_publication_gate(&verdicts, &gaps, &default_config(), 1).expect("evaluate");
        assert_eq!(eval.summary.guidance_required_surfaces, 2);
    }

    #[test]
    fn all_surfaces_constant_has_five_elements() {
        assert_eq!(ALL_SURFACES.len(), 5);
    }

    #[test]
    fn max_publishable_staleness_hours_value() {
        assert_eq!(MAX_PUBLISHABLE_STALENESS_HOURS, 168);
    }

    #[test]
    fn custom_config_empty_domain_map() {
        let config = SurfaceRoutingConfig {
            domain_to_surfaces: BTreeMap::new(),
            min_tier_for_surface: BTreeMap::new(),
            max_staleness_hours: BTreeMap::new(),
        };
        let verdicts = vec![make_annotated(
            entitled_verdict("custom-1"),
            "compatibility",
            "shipped_fact",
        )];
        let eval = evaluate_publication_gate(&verdicts, &[], &config, 1).expect("evaluate");
        // No domain routing => no claims anywhere
        assert_eq!(eval.summary.total_publishable_claims, 0);
        for decision in eval.gate_decisions.values() {
            assert!(matches!(decision, GateDecision::Rejected { .. }));
        }
    }

    #[test]
    fn custom_config_no_min_tier_allows_all() {
        let mut domain_to_surfaces = BTreeMap::new();
        domain_to_surfaces.insert("custom".to_string(), vec![PublicationSurface::Supremacy]);
        let config = SurfaceRoutingConfig {
            domain_to_surfaces,
            min_tier_for_surface: BTreeMap::new(),
            max_staleness_hours: BTreeMap::new(),
        };
        // With no min_tier for supremacy, even frontier_ambition should pass
        let verdicts = vec![make_annotated(
            entitled_verdict("lax-1"),
            "custom",
            "frontier_ambition",
        )];
        let eval = evaluate_publication_gate(&verdicts, &[], &config, 1).expect("evaluate");
        let sup_claims = eval.surface_claims.get("supremacy");
        assert!(sup_claims.is_some_and(|c| !c.is_empty()));
    }

    #[test]
    fn stale_claim_does_not_appear_in_surface_claims() {
        // GA has 168h limit
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("stale-ga"),
            "compatibility",
            "shipped_fact",
            200,
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let ga_claims = eval.surface_claims.get("ga");
        assert!(
            ga_claims.is_none() || ga_claims.is_some_and(|c| c.is_empty()),
            "stale claim should not appear in ga surface_claims"
        );
    }

    #[test]
    fn risk_flag_counter_increments_across_surfaces() {
        // A single stale verdict routed to multiple surfaces should produce
        // multiple flags with distinct IDs
        let verdicts = vec![make_stale_annotated(
            entitled_verdict("multi-flag"),
            "compatibility",
            "shipped_fact",
            500, // exceeds all surface staleness limits
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let stale_flags: Vec<_> = eval
            .risk_flags
            .iter()
            .filter(|f| f.flag_id.starts_with("stale-"))
            .collect();
        assert!(
            stale_flags.len() >= 2,
            "should produce flags for multiple surfaces"
        );
        // All flag IDs should be unique
        let mut flag_ids: Vec<_> = stale_flags.iter().map(|f| &f.flag_id).collect();
        let pre_dedup = flag_ids.len();
        flag_ids.sort();
        flag_ids.dedup();
        assert_eq!(flag_ids.len(), pre_dedup, "all flag IDs should be unique");
    }

    #[test]
    fn publishable_claim_fields_populated_from_verdict() {
        let verdict = ClaimVerdict {
            atom_id: "atom-verify".to_string(),
            state: ClaimVerdictState::Entitled,
            supporting_morphism_ids: vec!["m1".to_string(), "m2".to_string()],
            active_rule_ids: Vec::new(),
            minimal_cutset_ids: Vec::new(),
            impossibility_certificate_ids: vec!["cert-1".to_string()],
        };
        let verdicts = vec![AnnotatedVerdict {
            verdict,
            domain: "docs".to_string(),
            tier: "shipped_fact".to_string(),
            statement: "The engine supports ES2024".to_string(),
            staleness_hours: 0,
        }];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 1).expect("evaluate");
        let docs_claims = eval.surface_claims.get("docs").expect("docs claims");
        assert_eq!(docs_claims.len(), 1);
        let claim = &docs_claims[0];
        assert_eq!(claim.atom_id, "atom-verify");
        assert_eq!(claim.surface, PublicationSurface::Docs);
        assert_eq!(claim.publication_tier, PublicationTier::ShippedFact);
        assert_eq!(claim.supporting_morphisms, vec!["m1", "m2"]);
        assert_eq!(claim.impossibility_certificates, vec!["cert-1"]);
        assert_eq!(claim.domain, "docs");
        assert_eq!(claim.statement, "The engine supports ES2024");
    }

    #[test]
    fn epoch_zero_is_valid() {
        let verdicts = vec![make_annotated(
            entitled_verdict("ep0"),
            "docs",
            "shipped_fact",
        )];
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), 0).expect("evaluate");
        assert_eq!(eval.evaluated_epoch, 0);
    }

    #[test]
    fn large_epoch_value() {
        let verdicts = vec![make_annotated(
            entitled_verdict("big-ep"),
            "docs",
            "shipped_fact",
        )];
        let epoch = u64::MAX;
        let eval =
            evaluate_publication_gate(&verdicts, &[], &default_config(), epoch).expect("evaluate");
        assert_eq!(eval.evaluated_epoch, epoch);
    }
}
