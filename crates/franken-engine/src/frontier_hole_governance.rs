#![forbid(unsafe_code)]

//! Frontier-Hole Governance — RGC-809C
//!
//! Bead: bd-1lsy.9.9.3
//!
//! Wires frontier-hole ledgers from the cartography layer into the
//! universal-dominance ratchet, coverage gates, and user-visible support
//! boundaries.  Persistent holes affect what the project is willing to
//! claim, what docs say is supported, and what experiments are mandatory.
//!
//! All fractional arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for frontier-hole governance artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.frontier-hole-governance.v1";
/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.9.9.3";
/// Component name used in evidence records and receipts.
pub const COMPONENT: &str = "frontier_hole_governance";
/// Policy reference.
pub const POLICY_ID: &str = "RGC-809C";

const MILLION: u64 = 1_000_000;
/// Default maximum persistent holes before downgrading claims.
pub const DEFAULT_MAX_PERSISTENT_HOLES: u64 = 5;
/// Default minimum coverage to allow supremacy claims (millionths).
/// 900_000 = 90%.
pub const DEFAULT_MIN_SUPREMACY_COVERAGE: u64 = 900_000;
/// Default minimum coverage for parity claims (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_PARITY_COVERAGE: u64 = 800_000;
/// Default structural hole tolerance (0 = zero tolerance for structural holes).
pub const DEFAULT_MAX_STRUCTURAL_HOLES: u64 = 0;
/// Default ratchet decay per epoch (millionths). 50_000 = 5%.
pub const DEFAULT_RATCHET_DECAY: u64 = 50_000;

// ---------------------------------------------------------------------------
// Hole severity for governance
// ---------------------------------------------------------------------------

/// Classification of hole significance from the governance perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoleGovernanceSeverity {
    /// Informational — does not affect claims.
    Informational,
    /// Warning — may downgrade conditional claims.
    Warning,
    /// Blocking — prevents claims in the affected surface.
    Blocking,
    /// Critical — forces immediate claim suppression.
    Critical,
}

impl fmt::Display for HoleGovernanceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "informational"),
            Self::Warning => write!(f, "warning"),
            Self::Blocking => write!(f, "blocking"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// Support boundary
// ---------------------------------------------------------------------------

/// A user-visible support boundary for a specific surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBoundary {
    /// Surface name (e.g. "parser", "runtime", "react").
    pub surface: String,
    /// Whether the surface is fully supported.
    pub fully_supported: bool,
    /// Coverage fraction (millionths).
    pub coverage_millionths: u64,
    /// Number of persistent holes.
    pub persistent_holes: u64,
    /// Number of structural holes.
    pub structural_holes: u64,
    /// Hole IDs blocking full support.
    pub blocking_hole_ids: Vec<String>,
    /// Human-readable boundary statement.
    pub boundary_statement: String,
}

impl SupportBoundary {
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"support_boundary:");
        h.update(self.surface.as_bytes());
        h.update(b"|full:");
        h.update(if self.fully_supported { b"1" } else { b"0" });
        h.update(b"|cov:");
        h.update(self.coverage_millionths.to_le_bytes());
        h.update(b"|pers:");
        h.update(self.persistent_holes.to_le_bytes());
        h.update(b"|struct:");
        h.update(self.structural_holes.to_le_bytes());
        let mut sorted_ids: Vec<_> = self.blocking_hole_ids.iter().collect();
        sorted_ids.sort();
        for id in &sorted_ids {
            h.update(b"|blk:");
            h.update(id.as_bytes());
        }
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// Claim category
// ---------------------------------------------------------------------------

/// Category of claim subject to governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCategory {
    /// Supremacy claim — requires highest coverage.
    Supremacy,
    /// Parity claim — requires moderate coverage.
    Parity,
    /// Experimental claim — informational only.
    Experimental,
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supremacy => write!(f, "supremacy"),
            Self::Parity => write!(f, "parity"),
            Self::Experimental => write!(f, "experimental"),
        }
    }
}

// ---------------------------------------------------------------------------
// Governance action
// ---------------------------------------------------------------------------

/// Action the governance gate recommends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    /// Allow the claim as stated.
    AllowClaim,
    /// Downgrade the claim to a weaker category.
    DowngradeClaim,
    /// Suppress the claim entirely.
    SuppressClaim,
    /// Require additional evidence before deciding.
    RequireEvidence,
    /// Force an experiment targeting the specific holes.
    ForceExperiment,
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowClaim => write!(f, "allow_claim"),
            Self::DowngradeClaim => write!(f, "downgrade_claim"),
            Self::SuppressClaim => write!(f, "suppress_claim"),
            Self::RequireEvidence => write!(f, "require_evidence"),
            Self::ForceExperiment => write!(f, "force_experiment"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hole entry (input)
// ---------------------------------------------------------------------------

/// A hole entry for governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceHoleEntry {
    /// Hole identifier.
    pub hole_id: String,
    /// Surface where the hole resides.
    pub surface: String,
    /// Whether the hole is persistent.
    pub is_persistent: bool,
    /// Whether the hole is structural (infinite persistence).
    pub is_structural: bool,
    /// Persistence in millionths.
    pub persistence_millionths: u64,
    /// Whether a witness program exists for this hole.
    pub has_witness: bool,
    /// Topological dimension.
    pub dimension: u32,
}

impl GovernanceHoleEntry {
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(b"gov_hole_entry:");
        h.update(self.hole_id.as_bytes());
        h.update(b"|surf:");
        h.update(self.surface.as_bytes());
        h.update(b"|pers:");
        h.update(if self.is_persistent { b"1" } else { b"0" });
        h.update(b"|struct:");
        h.update(if self.is_structural { b"1" } else { b"0" });
        h.update(b"|pmil:");
        h.update(self.persistence_millionths.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }

    /// Whether this hole is actionable (persistent or structural).
    pub fn is_actionable(&self) -> bool {
        self.is_persistent || self.is_structural
    }
}

// ---------------------------------------------------------------------------
// Governance configuration
// ---------------------------------------------------------------------------

/// Configuration for the frontier-hole governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Maximum persistent holes before downgrading supremacy claims.
    pub max_persistent_holes: u64,
    /// Maximum structural holes (zero tolerance by default).
    pub max_structural_holes: u64,
    /// Minimum coverage for supremacy claims (millionths).
    pub min_supremacy_coverage_millionths: u64,
    /// Minimum coverage for parity claims (millionths).
    pub min_parity_coverage_millionths: u64,
    /// Ratchet decay per epoch (millionths).
    pub ratchet_decay_millionths: u64,
    /// Surfaces that require full coverage for any claim.
    pub critical_surfaces: BTreeSet<String>,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        let mut critical = BTreeSet::new();
        critical.insert("parser".to_string());
        critical.insert("runtime".to_string());
        Self {
            max_persistent_holes: DEFAULT_MAX_PERSISTENT_HOLES,
            max_structural_holes: DEFAULT_MAX_STRUCTURAL_HOLES,
            min_supremacy_coverage_millionths: DEFAULT_MIN_SUPREMACY_COVERAGE,
            min_parity_coverage_millionths: DEFAULT_MIN_PARITY_COVERAGE,
            ratchet_decay_millionths: DEFAULT_RATCHET_DECAY,
            critical_surfaces: critical,
        }
    }
}

// ---------------------------------------------------------------------------
// Ratchet state
// ---------------------------------------------------------------------------

/// Tracks the dominance ratchet — coverage can only improve or stay level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetState {
    /// Current ratchet level per surface (millionths).
    pub surface_levels: BTreeMap<String, u64>,
    /// Overall ratchet level (millionths).
    pub overall_level_millionths: u64,
    /// Epoch of the last ratchet update.
    pub last_epoch: SecurityEpoch,
    /// Whether the ratchet has ever been initialized.
    pub initialized: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl RatchetState {
    /// Create an uninitialized ratchet.
    pub fn new() -> Self {
        Self {
            surface_levels: BTreeMap::new(),
            overall_level_millionths: 0,
            last_epoch: SecurityEpoch::from_raw(0),
            initialized: false,
            content_hash: ContentHash::compute(b"ratchet_uninitialized"),
        }
    }

    /// Recompute the content hash.
    pub fn seal(&mut self) {
        let mut h = Sha256::new();
        h.update(b"ratchet_state:");
        h.update(b"|overall:");
        h.update(self.overall_level_millionths.to_le_bytes());
        h.update(b"|ep:");
        h.update(self.last_epoch.as_u64().to_le_bytes());
        h.update(b"|init:");
        h.update(if self.initialized { b"1" } else { b"0" });
        for (k, v) in &self.surface_levels {
            h.update(b"|s:");
            h.update(k.as_bytes());
            h.update(b"=");
            h.update(v.to_le_bytes());
        }
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

impl Default for RatchetState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Governance decision
// ---------------------------------------------------------------------------

/// A single governance decision about a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDecision {
    /// Decision identifier.
    pub decision_id: String,
    /// Claim category being evaluated.
    pub claim_category: ClaimCategory,
    /// Surface being evaluated (empty string = overall).
    pub surface: String,
    /// Recommended action.
    pub action: GovernanceAction,
    /// Reasons for the decision.
    pub reasons: Vec<String>,
    /// Severity of blocking holes.
    pub max_severity: HoleGovernanceSeverity,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GovernanceDecision {
    pub fn seal(&mut self) {
        let mut h = Sha256::new();
        h.update(b"governance_decision:");
        h.update(self.decision_id.as_bytes());
        h.update(b"|cat:");
        h.update(format!("{}", self.claim_category).as_bytes());
        h.update(b"|surf:");
        h.update(self.surface.as_bytes());
        h.update(b"|act:");
        h.update(format!("{}", self.action).as_bytes());
        h.update(b"|sev:");
        h.update(format!("{}", self.max_severity).as_bytes());
        let mut sorted_reasons = self.reasons.clone();
        sorted_reasons.sort();
        for r in &sorted_reasons {
            h.update(b"|r:");
            h.update(r.as_bytes());
        }
        self.content_hash = ContentHash::compute(&h.finalize());
    }

    pub fn is_allowed(&self) -> bool {
        self.action == GovernanceAction::AllowClaim
    }

    pub fn is_suppressed(&self) -> bool {
        self.action == GovernanceAction::SuppressClaim
    }
}

// ---------------------------------------------------------------------------
// Governance report
// ---------------------------------------------------------------------------

/// Outcome of a governance evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceOutcome {
    /// All claims are allowed.
    AllClear,
    /// Some claims downgraded.
    Downgraded,
    /// Some claims suppressed.
    Suppressed,
    /// All claims suppressed.
    FullSuppression,
}

impl fmt::Display for GovernanceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllClear => write!(f, "all_clear"),
            Self::Downgraded => write!(f, "downgraded"),
            Self::Suppressed => write!(f, "suppressed"),
            Self::FullSuppression => write!(f, "full_suppression"),
        }
    }
}

/// Full governance evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReport {
    /// Report identifier.
    pub report_id: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Overall outcome.
    pub outcome: GovernanceOutcome,
    /// Per-claim decisions.
    pub decisions: Vec<GovernanceDecision>,
    /// Support boundaries per surface.
    pub boundaries: Vec<SupportBoundary>,
    /// Updated ratchet state.
    pub ratchet: RatchetState,
    /// Total holes evaluated.
    pub total_holes: u64,
    /// Actionable holes.
    pub actionable_holes: u64,
    /// Mandatory experiments (hole IDs).
    pub mandatory_experiments: Vec<String>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GovernanceReport {
    /// Recompute the report hash.
    pub fn seal(&mut self) {
        let mut h = Sha256::new();
        h.update(b"governance_report:");
        h.update(self.report_id.as_bytes());
        h.update(b"|ep:");
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(b"|out:");
        h.update(format!("{}", self.outcome).as_bytes());
        h.update(b"|total:");
        h.update(self.total_holes.to_le_bytes());
        h.update(b"|act:");
        h.update(self.actionable_holes.to_le_bytes());
        let mut sorted_dec_hashes: Vec<_> = self.decisions.iter().map(|d| d.content_hash).collect();
        sorted_dec_hashes.sort();
        for ch in &sorted_dec_hashes {
            h.update(b"|dec:");
            h.update(ch.as_bytes());
        }
        let mut sorted_bnd_hashes: Vec<_> =
            self.boundaries.iter().map(|b| b.content_hash()).collect();
        sorted_bnd_hashes.sort();
        for ch in &sorted_bnd_hashes {
            h.update(b"|bnd:");
            h.update(ch.as_bytes());
        }
        let mut sorted_mandatory = self.mandatory_experiments.clone();
        sorted_mandatory.sort();
        for experiment in &sorted_mandatory {
            h.update(b"|exp:");
            h.update(experiment.as_bytes());
        }
        h.update(b"|ratchet:");
        h.update(self.ratchet.content_hash.as_bytes());
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

// ---------------------------------------------------------------------------
// Governance errors
// ---------------------------------------------------------------------------

/// Errors from the governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceError {
    /// No holes provided.
    EmptyInput,
    /// Invalid hole entry.
    InvalidHoleEntry(String),
    /// Ratchet regression detected.
    RatchetRegression {
        surface: String,
        previous_millionths: u64,
        current_millionths: u64,
    },
    /// Internal error.
    InternalError(String),
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "no holes provided"),
            Self::InvalidHoleEntry(id) => write!(f, "invalid hole entry: {id}"),
            Self::RatchetRegression {
                surface,
                previous_millionths,
                current_millionths,
            } => write!(
                f,
                "ratchet regression on {surface}: {previous_millionths} -> {current_millionths}"
            ),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for GovernanceError {}

// ---------------------------------------------------------------------------
// Core: classify hole severity
// ---------------------------------------------------------------------------

/// Classify a governance hole entry into severity.
pub fn classify_severity(
    entry: &GovernanceHoleEntry,
    config: &GovernanceConfig,
) -> HoleGovernanceSeverity {
    if entry.is_structural {
        return HoleGovernanceSeverity::Critical;
    }
    if entry.is_persistent && config.critical_surfaces.contains(&entry.surface) {
        return HoleGovernanceSeverity::Blocking;
    }
    if entry.is_persistent {
        return HoleGovernanceSeverity::Warning;
    }
    HoleGovernanceSeverity::Informational
}

// ---------------------------------------------------------------------------
// Core: compute surface coverage
// ---------------------------------------------------------------------------

/// Compute per-surface coverage from hole entries.
/// Coverage = 1.0 - (actionable_holes / total_holes) per surface.
/// If a surface has no holes at all, coverage = 1.0.
pub fn compute_surface_coverage(holes: &[GovernanceHoleEntry]) -> BTreeMap<String, u64> {
    let mut surface_totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for h in holes {
        let entry = surface_totals.entry(h.surface.clone()).or_insert((0, 0));
        entry.0 += 1;
        if h.is_actionable() {
            entry.1 += 1;
        }
    }
    surface_totals
        .into_iter()
        .map(|(s, (total, actionable))| {
            let covered = total.saturating_sub(actionable);
            let cov = if total == 0 {
                MILLION
            } else {
                covered
                    .saturating_mul(MILLION)
                    .checked_div(total)
                    .unwrap_or(0)
            };
            (s, cov)
        })
        .collect()
}

/// Compute overall coverage from per-surface coverage.
pub fn overall_coverage(surface_cov: &BTreeMap<String, u64>) -> u64 {
    if surface_cov.is_empty() {
        return MILLION;
    }
    let sum: u64 = surface_cov.values().sum();
    sum.checked_div(surface_cov.len() as u64).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Core: build support boundaries
// ---------------------------------------------------------------------------

/// Build support boundaries for each surface.
pub fn build_boundaries(
    holes: &[GovernanceHoleEntry],
    surface_cov: &BTreeMap<String, u64>,
    config: &GovernanceConfig,
) -> Vec<SupportBoundary> {
    let mut per_surface: BTreeMap<String, Vec<&GovernanceHoleEntry>> = BTreeMap::new();
    for h in holes {
        per_surface.entry(h.surface.clone()).or_default().push(h);
    }

    let mut boundaries = Vec::new();
    for (surface, entries) in &per_surface {
        let persistent = entries.iter().filter(|e| e.is_persistent).count() as u64;
        let structural = entries.iter().filter(|e| e.is_structural).count() as u64;
        let blocking_ids: Vec<String> = entries
            .iter()
            .filter(|e| e.is_actionable())
            .map(|e| e.hole_id.clone())
            .collect();
        let cov = surface_cov.get(surface).copied().unwrap_or(MILLION);
        let fully_supported =
            persistent == 0 && structural == 0 && cov >= config.min_supremacy_coverage_millionths;

        let statement = if fully_supported {
            format!("{surface}: fully supported")
        } else if structural > 0 {
            format!("{surface}: {structural} structural hole(s) — support incomplete")
        } else if persistent > 0 {
            format!("{surface}: {persistent} persistent hole(s) — coverage {cov}/1000000")
        } else {
            format!("{surface}: coverage {cov}/1000000")
        };

        boundaries.push(SupportBoundary {
            surface: surface.clone(),
            fully_supported,
            coverage_millionths: cov,
            persistent_holes: persistent,
            structural_holes: structural,
            blocking_hole_ids: blocking_ids,
            boundary_statement: statement,
        });
    }
    boundaries
}

// ---------------------------------------------------------------------------
// Core: evaluate claims
// ---------------------------------------------------------------------------

/// Evaluate a single claim category against hole evidence.
pub fn evaluate_claim(
    category: ClaimCategory,
    surface: &str,
    holes: &[GovernanceHoleEntry],
    surface_cov: &BTreeMap<String, u64>,
    config: &GovernanceConfig,
) -> GovernanceDecision {
    let surface_holes: Vec<&GovernanceHoleEntry> =
        holes.iter().filter(|h| h.surface == surface).collect();
    let persistent = surface_holes.iter().filter(|h| h.is_persistent).count() as u64;
    let structural = surface_holes.iter().filter(|h| h.is_structural).count() as u64;
    let cov = surface_cov.get(surface).copied().unwrap_or(MILLION);

    let mut reasons = Vec::new();
    let mut max_severity = HoleGovernanceSeverity::Informational;
    let mut action = GovernanceAction::AllowClaim;

    // Structural holes → critical.
    if structural > config.max_structural_holes {
        reasons.push(format!(
            "{structural} structural holes exceed max {}",
            config.max_structural_holes
        ));
        max_severity = HoleGovernanceSeverity::Critical;
        action = GovernanceAction::SuppressClaim;
    }

    // Persistent holes → depends on category.
    if persistent > config.max_persistent_holes && action != GovernanceAction::SuppressClaim {
        reasons.push(format!(
            "{persistent} persistent holes exceed max {}",
            config.max_persistent_holes
        ));
        if max_severity < HoleGovernanceSeverity::Blocking {
            max_severity = HoleGovernanceSeverity::Blocking;
        }
        match category {
            ClaimCategory::Supremacy => action = GovernanceAction::SuppressClaim,
            ClaimCategory::Parity => action = GovernanceAction::DowngradeClaim,
            ClaimCategory::Experimental => action = GovernanceAction::RequireEvidence,
        }
    }

    // Coverage threshold check.
    if action == GovernanceAction::AllowClaim {
        let min_cov = match category {
            ClaimCategory::Supremacy => config.min_supremacy_coverage_millionths,
            ClaimCategory::Parity => config.min_parity_coverage_millionths,
            ClaimCategory::Experimental => 0,
        };
        if cov < min_cov {
            reasons.push(format!(
                "coverage {cov} below minimum {min_cov} for {category}"
            ));
            if max_severity < HoleGovernanceSeverity::Warning {
                max_severity = HoleGovernanceSeverity::Warning;
            }
            match category {
                ClaimCategory::Supremacy => action = GovernanceAction::DowngradeClaim,
                ClaimCategory::Parity => action = GovernanceAction::RequireEvidence,
                ClaimCategory::Experimental => {}
            }
        }
    }

    // Critical surface check.
    if config.critical_surfaces.contains(surface)
        && persistent > 0
        && action == GovernanceAction::AllowClaim
    {
        reasons.push(format!(
            "critical surface {surface} has {persistent} persistent holes"
        ));
        if max_severity < HoleGovernanceSeverity::Warning {
            max_severity = HoleGovernanceSeverity::Warning;
        }
        if category == ClaimCategory::Supremacy {
            action = GovernanceAction::DowngradeClaim;
        }
    }

    if reasons.is_empty() {
        reasons.push("no governance issues detected".to_string());
    }

    let decision_id = format!("gov-{}-{}-{}", category, surface, action);
    let mut dec = GovernanceDecision {
        decision_id,
        claim_category: category,
        surface: surface.to_string(),
        action,
        reasons,
        max_severity,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    dec.seal();
    dec
}

// ---------------------------------------------------------------------------
// Core: update ratchet
// ---------------------------------------------------------------------------

/// Update the ratchet state with new coverage data.
/// Ratchet only allows improvement — coverage cannot decrease.
pub fn update_ratchet(
    ratchet: &RatchetState,
    surface_cov: &BTreeMap<String, u64>,
    epoch: SecurityEpoch,
    config: &GovernanceConfig,
) -> Result<RatchetState, GovernanceError> {
    let mut new_levels = ratchet.surface_levels.clone();
    for (surface, &new_cov) in surface_cov {
        let prev = new_levels.get(surface).copied().unwrap_or(0);
        // Apply decay: if epoch advanced, allow slight regression.
        let epoch_diff = epoch.as_u64().saturating_sub(ratchet.last_epoch.as_u64());
        let decay = epoch_diff.saturating_mul(config.ratchet_decay_millionths);
        let effective_prev = prev.saturating_sub(decay);
        if new_cov < effective_prev && ratchet.initialized {
            return Err(GovernanceError::RatchetRegression {
                surface: surface.clone(),
                previous_millionths: effective_prev,
                current_millionths: new_cov,
            });
        }
        new_levels.insert(surface.clone(), new_cov);
    }

    let overall = overall_coverage(&new_levels);
    let mut state = RatchetState {
        surface_levels: new_levels,
        overall_level_millionths: overall,
        last_epoch: epoch,
        initialized: true,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    state.seal();
    Ok(state)
}

// ---------------------------------------------------------------------------
// Core: full evaluation
// ---------------------------------------------------------------------------

/// Run a full governance evaluation.
pub fn evaluate(
    holes: &[GovernanceHoleEntry],
    claims: &[(ClaimCategory, String)],
    ratchet: &RatchetState,
    epoch: SecurityEpoch,
    config: &GovernanceConfig,
) -> Result<GovernanceReport, GovernanceError> {
    if holes.is_empty() {
        return Err(GovernanceError::EmptyInput);
    }

    // Validate entries.
    for h in holes {
        if h.hole_id.is_empty() {
            return Err(GovernanceError::InvalidHoleEntry("empty hole_id".into()));
        }
    }

    let surface_cov = compute_surface_coverage(holes);
    let boundaries = build_boundaries(holes, &surface_cov, config);

    let mut decisions = Vec::new();
    for (category, surface) in claims {
        let dec = evaluate_claim(*category, surface, holes, &surface_cov, config);
        decisions.push(dec);
    }

    let new_ratchet = update_ratchet(ratchet, &surface_cov, epoch, config)?;

    let total = holes.len() as u64;
    let actionable = holes.iter().filter(|h| h.is_actionable()).count() as u64;
    let mandatory: Vec<String> = holes
        .iter()
        .filter(|h| {
            h.is_structural || (h.is_persistent && config.critical_surfaces.contains(&h.surface))
        })
        .map(|h| h.hole_id.clone())
        .collect();

    let any_suppressed = decisions
        .iter()
        .any(|d| d.action == GovernanceAction::SuppressClaim);
    let any_downgraded = decisions
        .iter()
        .any(|d| d.action == GovernanceAction::DowngradeClaim);
    let all_suppressed = !decisions.is_empty()
        && decisions
            .iter()
            .all(|d| d.action == GovernanceAction::SuppressClaim);

    let outcome = if all_suppressed {
        GovernanceOutcome::FullSuppression
    } else if any_suppressed {
        GovernanceOutcome::Suppressed
    } else if any_downgraded {
        GovernanceOutcome::Downgraded
    } else {
        GovernanceOutcome::AllClear
    };

    let mut report = GovernanceReport {
        report_id: format!("govrpt-{}", epoch.as_u64()),
        epoch,
        outcome,
        decisions,
        boundaries,
        ratchet: new_ratchet,
        total_holes: total,
        actionable_holes: actionable,
        mandatory_experiments: mandatory,
        content_hash: ContentHash::compute(b"placeholder"),
    };
    report.seal();
    Ok(report)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Count suppressed decisions in a report.
pub fn suppressed_count(report: &GovernanceReport) -> usize {
    report
        .decisions
        .iter()
        .filter(|d| d.is_suppressed())
        .count()
}

/// Count allowed decisions.
pub fn allowed_count(report: &GovernanceReport) -> usize {
    report.decisions.iter().filter(|d| d.is_allowed()).count()
}

/// Extract all blocked surfaces.
pub fn blocked_surfaces(report: &GovernanceReport) -> BTreeSet<String> {
    report
        .boundaries
        .iter()
        .filter(|b| !b.fully_supported)
        .map(|b| b.surface.clone())
        .collect()
}

/// Summary of a governance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSummary {
    pub report_id: String,
    pub epoch: SecurityEpoch,
    pub outcome: GovernanceOutcome,
    pub total_holes: u64,
    pub actionable_holes: u64,
    pub decisions_count: u64,
    pub suppressed_count: u64,
    pub allowed_count: u64,
    pub mandatory_experiments_count: u64,
    pub overall_coverage_millionths: u64,
    pub content_hash: ContentHash,
}

/// Build a summary from a governance report.
pub fn summarize(report: &GovernanceReport) -> GovernanceSummary {
    let decisions_count = report.decisions.len() as u64;
    let suppressed = suppressed_count(report) as u64;
    let allowed = allowed_count(report) as u64;
    let mandatory_experiments_count = report.mandatory_experiments.len() as u64;
    let overall_coverage_millionths = report.ratchet.overall_level_millionths;

    let mut h = Sha256::new();
    h.update(b"gov_summary:");
    h.update(report.report_id.as_bytes());
    h.update(b"|ep:");
    h.update(report.epoch.as_u64().to_le_bytes());
    h.update(b"|out:");
    h.update(format!("{}", report.outcome).as_bytes());
    h.update(b"|total:");
    h.update(report.total_holes.to_le_bytes());
    h.update(b"|act:");
    h.update(report.actionable_holes.to_le_bytes());
    h.update(b"|dec:");
    h.update(decisions_count.to_le_bytes());
    h.update(b"|supp:");
    h.update(suppressed.to_le_bytes());
    h.update(b"|allow:");
    h.update(allowed.to_le_bytes());
    h.update(b"|exp:");
    h.update(mandatory_experiments_count.to_le_bytes());
    h.update(b"|cov:");
    h.update(overall_coverage_millionths.to_le_bytes());

    GovernanceSummary {
        report_id: report.report_id.clone(),
        epoch: report.epoch,
        outcome: report.outcome,
        total_holes: report.total_holes,
        actionable_holes: report.actionable_holes,
        decisions_count,
        suppressed_count: suppressed,
        allowed_count: allowed,
        mandatory_experiments_count,
        overall_coverage_millionths,
        content_hash: ContentHash::compute(&h.finalize()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hole(
        id: &str,
        surface: &str,
        persistent: bool,
        structural: bool,
    ) -> GovernanceHoleEntry {
        GovernanceHoleEntry {
            hole_id: id.to_string(),
            surface: surface.to_string(),
            is_persistent: persistent,
            is_structural: structural,
            persistence_millionths: if structural {
                u64::MAX
            } else if persistent {
                200_000
            } else {
                10_000
            },
            has_witness: true,
            dimension: 1,
        }
    }

    fn default_config() -> GovernanceConfig {
        GovernanceConfig::default()
    }

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // --- Constants ---

    #[test]
    fn schema_version_matches() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.frontier-hole-governance.v1");
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(BEAD_ID, "bd-1lsy.9.9.3");
    }

    #[test]
    fn component_matches() {
        assert_eq!(COMPONENT, "frontier_hole_governance");
    }

    #[test]
    fn policy_id_matches() {
        assert_eq!(POLICY_ID, "RGC-809C");
    }

    // --- Enums ---

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", HoleGovernanceSeverity::Critical), "critical");
        assert_eq!(format!("{}", HoleGovernanceSeverity::Blocking), "blocking");
    }

    #[test]
    fn claim_category_display() {
        assert_eq!(format!("{}", ClaimCategory::Supremacy), "supremacy");
        assert_eq!(format!("{}", ClaimCategory::Parity), "parity");
    }

    #[test]
    fn action_display() {
        assert_eq!(format!("{}", GovernanceAction::AllowClaim), "allow_claim");
        assert_eq!(
            format!("{}", GovernanceAction::SuppressClaim),
            "suppress_claim"
        );
    }

    #[test]
    fn outcome_display() {
        assert_eq!(format!("{}", GovernanceOutcome::AllClear), "all_clear");
        assert_eq!(
            format!("{}", GovernanceOutcome::FullSuppression),
            "full_suppression"
        );
    }

    #[test]
    fn severity_serde_roundtrip() {
        let s = HoleGovernanceSeverity::Blocking;
        let json = serde_json::to_string(&s).unwrap();
        let back: HoleGovernanceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn action_serde_roundtrip() {
        let a = GovernanceAction::ForceExperiment;
        let json = serde_json::to_string(&a).unwrap();
        let back: GovernanceAction = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- HoleEntry ---

    #[test]
    fn hole_entry_actionable() {
        let h = make_hole("h1", "parser", true, false);
        assert!(h.is_actionable());
    }

    #[test]
    fn hole_entry_not_actionable() {
        let h = make_hole("h1", "parser", false, false);
        assert!(!h.is_actionable());
    }

    #[test]
    fn hole_entry_hash_deterministic() {
        let h1 = make_hole("h1", "parser", true, false);
        let h2 = make_hole("h1", "parser", true, false);
        assert_eq!(h1.content_hash(), h2.content_hash());
    }

    // --- classify_severity ---

    #[test]
    fn structural_is_critical() {
        let h = make_hole("s1", "parser", false, true);
        let sev = classify_severity(&h, &default_config());
        assert_eq!(sev, HoleGovernanceSeverity::Critical);
    }

    #[test]
    fn persistent_critical_surface_is_blocking() {
        let h = make_hole("p1", "parser", true, false);
        let sev = classify_severity(&h, &default_config());
        assert_eq!(sev, HoleGovernanceSeverity::Blocking);
    }

    #[test]
    fn persistent_noncritical_is_warning() {
        let h = make_hole("p1", "react", true, false);
        let sev = classify_severity(&h, &default_config());
        assert_eq!(sev, HoleGovernanceSeverity::Warning);
    }

    #[test]
    fn noise_is_informational() {
        let h = make_hole("n1", "parser", false, false);
        let sev = classify_severity(&h, &default_config());
        assert_eq!(sev, HoleGovernanceSeverity::Informational);
    }

    // --- surface_coverage ---

    #[test]
    fn coverage_all_noise() {
        let holes = vec![
            make_hole("n1", "parser", false, false),
            make_hole("n2", "parser", false, false),
        ];
        let cov = compute_surface_coverage(&holes);
        assert_eq!(*cov.get("parser").unwrap(), MILLION);
    }

    #[test]
    fn coverage_half_persistent() {
        let holes = vec![
            make_hole("p1", "parser", true, false),
            make_hole("n1", "parser", false, false),
        ];
        let cov = compute_surface_coverage(&holes);
        assert_eq!(*cov.get("parser").unwrap(), 500_000);
    }

    #[test]
    fn coverage_all_persistent() {
        let holes = vec![
            make_hole("p1", "parser", true, false),
            make_hole("p2", "parser", true, false),
        ];
        let cov = compute_surface_coverage(&holes);
        assert_eq!(*cov.get("parser").unwrap(), 0);
    }

    #[test]
    fn overall_coverage_average() {
        let mut sc = BTreeMap::new();
        sc.insert("parser".to_string(), 800_000u64);
        sc.insert("runtime".to_string(), 600_000u64);
        assert_eq!(overall_coverage(&sc), 700_000);
    }

    // --- evaluate_claim ---

    #[test]
    fn supremacy_allowed_no_holes() {
        let holes = vec![make_hole("n1", "parser", false, false)];
        let cov = compute_surface_coverage(&holes);
        let dec = evaluate_claim(
            ClaimCategory::Supremacy,
            "parser",
            &holes,
            &cov,
            &default_config(),
        );
        assert!(dec.is_allowed());
    }

    #[test]
    fn supremacy_suppressed_with_structural() {
        let holes = vec![make_hole("s1", "parser", false, true)];
        let cov = compute_surface_coverage(&holes);
        let dec = evaluate_claim(
            ClaimCategory::Supremacy,
            "parser",
            &holes,
            &cov,
            &default_config(),
        );
        assert!(dec.is_suppressed());
    }

    #[test]
    fn parity_downgraded_many_persistent() {
        let mut holes = Vec::new();
        for i in 0..10 {
            holes.push(make_hole(&format!("p{i}"), "parser", true, false));
        }
        let cov = compute_surface_coverage(&holes);
        let dec = evaluate_claim(
            ClaimCategory::Parity,
            "parser",
            &holes,
            &cov,
            &default_config(),
        );
        assert_eq!(dec.action, GovernanceAction::DowngradeClaim);
    }

    #[test]
    fn experimental_requires_evidence_many_persistent() {
        let mut holes = Vec::new();
        for i in 0..10 {
            holes.push(make_hole(&format!("p{i}"), "react", true, false));
        }
        let cov = compute_surface_coverage(&holes);
        let dec = evaluate_claim(
            ClaimCategory::Experimental,
            "react",
            &holes,
            &cov,
            &default_config(),
        );
        assert_eq!(dec.action, GovernanceAction::RequireEvidence);
    }

    // --- RatchetState ---

    #[test]
    fn ratchet_new_uninitialized() {
        let r = RatchetState::new();
        assert!(!r.initialized);
        assert!(r.surface_levels.is_empty());
    }

    #[test]
    fn ratchet_seal_updates_hash() {
        let mut r = RatchetState::new();
        let h1 = r.content_hash;
        r.initialized = true;
        r.seal();
        assert_ne!(h1, r.content_hash);
    }

    #[test]
    fn ratchet_update_succeeds_on_improvement() {
        let r = RatchetState::new();
        let mut cov = BTreeMap::new();
        cov.insert("parser".to_string(), 800_000u64);
        let new_r = update_ratchet(&r, &cov, epoch(), &default_config()).unwrap();
        assert!(new_r.initialized);
        assert_eq!(*new_r.surface_levels.get("parser").unwrap(), 800_000);
    }

    #[test]
    fn ratchet_regression_blocked() {
        let mut r = RatchetState::new();
        r.initialized = true;
        r.surface_levels.insert("parser".to_string(), 900_000);
        r.last_epoch = SecurityEpoch::from_raw(1);
        r.seal();

        let mut cov = BTreeMap::new();
        cov.insert("parser".to_string(), 500_000u64);
        let err = update_ratchet(&r, &cov, SecurityEpoch::from_raw(1), &default_config());
        assert!(err.is_err());
    }

    #[test]
    fn ratchet_allows_decay_over_epochs() {
        let mut r = RatchetState::new();
        r.initialized = true;
        r.surface_levels.insert("parser".to_string(), 900_000);
        r.last_epoch = SecurityEpoch::from_raw(1);
        r.seal();

        // After many epochs, decay allows lower values.
        let mut cov = BTreeMap::new();
        cov.insert("parser".to_string(), 800_000u64);
        let result = update_ratchet(&r, &cov, SecurityEpoch::from_raw(10), &default_config());
        assert!(result.is_ok());
    }

    // --- full evaluation ---

    #[test]
    fn evaluate_all_clear() {
        let holes = vec![
            make_hole("n1", "parser", false, false),
            make_hole("n2", "runtime", false, false),
        ];
        let claims = vec![
            (ClaimCategory::Supremacy, "parser".to_string()),
            (ClaimCategory::Parity, "runtime".to_string()),
        ];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        assert_eq!(report.outcome, GovernanceOutcome::AllClear);
        assert_eq!(report.actionable_holes, 0);
    }

    #[test]
    fn evaluate_suppressed_structural() {
        let holes = vec![make_hole("s1", "parser", false, true)];
        let claims = vec![(ClaimCategory::Supremacy, "parser".to_string())];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        assert_eq!(report.outcome, GovernanceOutcome::FullSuppression);
    }

    #[test]
    fn evaluate_empty_returns_error() {
        let claims = vec![(ClaimCategory::Supremacy, "parser".to_string())];
        let ratchet = RatchetState::new();
        let err = evaluate(&[], &claims, &ratchet, epoch(), &default_config());
        assert!(err.is_err());
    }

    #[test]
    fn evaluate_boundaries_correct() {
        let holes = vec![
            make_hole("p1", "parser", true, false),
            make_hole("n1", "parser", false, false),
            make_hole("n2", "runtime", false, false),
        ];
        let claims = vec![];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let parser_b = report
            .boundaries
            .iter()
            .find(|b| b.surface == "parser")
            .unwrap();
        assert!(!parser_b.fully_supported);
        assert_eq!(parser_b.persistent_holes, 1);
    }

    #[test]
    fn evaluate_mandatory_experiments() {
        let holes = vec![
            make_hole("s1", "parser", false, true),
            make_hole("p1", "parser", true, false),
        ];
        let claims = vec![];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        assert!(report.mandatory_experiments.contains(&"s1".to_string()));
        assert!(report.mandatory_experiments.contains(&"p1".to_string()));
    }

    // --- helpers ---

    #[test]
    fn suppressed_and_allowed_counts() {
        let holes = vec![
            make_hole("s1", "parser", false, true),
            make_hole("n1", "runtime", false, false),
        ];
        let claims = vec![
            (ClaimCategory::Supremacy, "parser".to_string()),
            (ClaimCategory::Parity, "runtime".to_string()),
        ];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        assert_eq!(suppressed_count(&report), 1);
        assert_eq!(allowed_count(&report), 1);
    }

    #[test]
    fn blocked_surfaces_correct() {
        let holes = vec![
            make_hole("p1", "parser", true, false),
            make_hole("n1", "runtime", false, false),
        ];
        let claims = vec![];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let blocked = blocked_surfaces(&report);
        assert!(blocked.contains("parser"));
        assert!(!blocked.contains("runtime"));
    }

    // --- summary ---

    #[test]
    fn summary_matches_report() {
        let holes = vec![
            make_hole("n1", "parser", false, false),
            make_hole("p1", "react", true, false),
        ];
        let claims = vec![
            (ClaimCategory::Supremacy, "parser".to_string()),
            (ClaimCategory::Parity, "react".to_string()),
        ];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let s = summarize(&report);
        assert_eq!(s.total_holes, report.total_holes);
        assert_eq!(s.decisions_count, 2);
    }

    #[test]
    fn summary_serde_roundtrip() {
        let holes = vec![make_hole("n1", "parser", false, false)];
        let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let s = summarize(&report);
        let json = serde_json::to_string(&s).unwrap();
        let back: GovernanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- Error types ---

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", GovernanceError::EmptyInput),
            "no holes provided"
        );
    }

    #[test]
    fn error_serde_roundtrip() {
        let e = GovernanceError::RatchetRegression {
            surface: "parser".into(),
            previous_millionths: 900_000,
            current_millionths: 500_000,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: GovernanceError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Config ---

    #[test]
    fn config_default_has_critical_surfaces() {
        let cfg = GovernanceConfig::default();
        assert!(cfg.critical_surfaces.contains("parser"));
        assert!(cfg.critical_surfaces.contains("runtime"));
    }

    #[test]
    fn config_serde_roundtrip() {
        let cfg = GovernanceConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- SupportBoundary ---

    #[test]
    fn boundary_hash_deterministic() {
        let b1 = SupportBoundary {
            surface: "parser".into(),
            fully_supported: true,
            coverage_millionths: MILLION,
            persistent_holes: 0,
            structural_holes: 0,
            blocking_hole_ids: vec![],
            boundary_statement: "parser: fully supported".into(),
        };
        let b2 = b1.clone();
        assert_eq!(b1.content_hash(), b2.content_hash());
    }

    // --- Report ---

    #[test]
    fn report_hash_deterministic() {
        let holes = vec![make_hole("n1", "parser", false, false)];
        let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
        let ratchet = RatchetState::new();
        let r1 = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let r2 = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_hash_changes_when_mandatory_experiments_change() {
        let holes = vec![make_hole("s1", "parser", true, false)];
        let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();

        let mut modified = report.clone();
        modified
            .mandatory_experiments
            .push("manual-rerun".to_string());
        modified.seal();

        assert_ne!(report.content_hash, modified.content_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let holes = vec![make_hole("n1", "parser", false, false)];
        let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: GovernanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn summary_hash_changes_when_summary_fields_change() {
        let holes = vec![make_hole("s1", "parser", true, false)];
        let claims = vec![(ClaimCategory::Parity, "parser".to_string())];
        let ratchet = RatchetState::new();
        let report = evaluate(&holes, &claims, &ratchet, epoch(), &default_config()).unwrap();
        let summary = summarize(&report);

        let mut modified = report.clone();
        modified
            .mandatory_experiments
            .push("manual-rerun".to_string());
        modified.seal();
        let modified_summary = summarize(&modified);

        assert_ne!(summary.content_hash, modified_summary.content_hash);
    }
}
