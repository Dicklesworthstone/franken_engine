//! Low-latency reputation updates and explainable trust-card generation.
//!
//! Builds on [`crate::reputation`] to produce operator-facing trust summaries
//! that update as new evidence arrives.  Every field in a trust card traces
//! back to specific graph data for full explainability.
//!
//! Plan references: Section 10.12 item 18, 9H.8 (Secure Extension Reputation
//! Graph), success criterion 13.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::reputation::{
    EvidenceNode, EvidenceType, ReputationGraph, ReputationGraphError, TrustLevel, TrustTransition,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// RiskTrend — direction of risk change
// ---------------------------------------------------------------------------

/// Direction of risk change over a recent window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskTrend {
    /// Risk is decreasing (positive evidence accumulating).
    Improving,
    /// Risk is stable (no significant change).
    Stable,
    /// Risk is increasing (negative evidence accumulating).
    Degrading,
}

impl fmt::Display for RiskTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Improving => "improving",
            Self::Stable => "stable",
            Self::Degrading => "degrading",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// RiskDriver — individual risk contributor
// ---------------------------------------------------------------------------

/// A single contributing factor to the overall risk score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskDriver {
    /// Human-readable description of the risk factor.
    pub description: String,
    /// Contribution to overall risk score (0..=100).
    pub contribution: u32,
}

// ---------------------------------------------------------------------------
// EvidenceSummary — counts and recency of evidence
// ---------------------------------------------------------------------------

/// Summary of evidence linked to an extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Count of positive (benign) evidence items.
    pub positive_count: u64,
    /// Count of negative (suspicious/malicious) evidence items.
    pub negative_count: u64,
    /// Count of neutral (informational) evidence items.
    pub neutral_count: u64,
    /// Timestamp of most recent evidence item (nanoseconds).
    pub most_recent_ns: Option<u64>,
    /// Description of the most recent significant evidence item.
    pub most_recent_description: Option<String>,
}

// ---------------------------------------------------------------------------
// ProvenanceSummary — supply-chain trust posture
// ---------------------------------------------------------------------------

/// Supply-chain provenance summary for a trust card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    /// Whether publisher identity has been verified.
    pub publisher_verified: bool,
    /// Whether build provenance is attested.
    pub build_attested: bool,
    /// Summary of dependency chain risk (millionths).
    pub dependency_risk: i64,
    /// Whether any provenance gap exists.
    pub has_provenance_gap: bool,
}

// ---------------------------------------------------------------------------
// TrustHistoryEntry — timeline of trust transitions
// ---------------------------------------------------------------------------

/// A single entry in the trust-level timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustHistoryEntry {
    /// Previous trust level.
    pub old_level: TrustLevel,
    /// New trust level.
    pub new_level: TrustLevel,
    /// Reason for the transition (brief summary).
    pub reason: String,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Whether this was an operator override.
    pub operator_override: bool,
}

impl From<&TrustTransition> for TrustHistoryEntry {
    fn from(tt: &TrustTransition) -> Self {
        let reason = if tt.operator_override {
            tt.operator_justification
                .clone()
                .unwrap_or_else(|| "operator override".to_string())
        } else {
            format!("evidence: {}", tt.triggering_evidence_ids.join(", "))
        };
        Self {
            old_level: tt.old_level,
            new_level: tt.new_level,
            reason,
            timestamp_ns: tt.timestamp_ns,
            operator_override: tt.operator_override,
        }
    }
}

// ---------------------------------------------------------------------------
// RecommendedAction — operator-facing suggestion
// ---------------------------------------------------------------------------

/// Suggested operator action for an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// Continue normal operation; no action needed.
    Monitor,
    /// Review extension behavior more closely.
    Review,
    /// Restrict extension capabilities.
    Restrict,
    /// Remove extension from deployment.
    Remove,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Monitor => "monitor",
            Self::Review => "review",
            Self::Restrict => "restrict",
            Self::Remove => "remove",
        };
        f.write_str(name)
    }
}

/// A recommendation with confidence and rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    /// Suggested action.
    pub action: RecommendedAction,
    /// Confidence in the recommendation (millionths, 0..=1_000_000).
    pub confidence: i64,
    /// Human-readable rationale.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// TrustCard — the main output artifact
// ---------------------------------------------------------------------------

/// Concise, structured summary of an extension's trust posture.
///
/// Every field traces to specific reputation graph data for full
/// explainability.  Cards are regenerated on trust-level changes or
/// at a configurable staleness interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCard {
    // -- Header --
    /// Extension identifier.
    pub extension_id: String,
    /// Package name.
    pub package_name: String,
    /// Semantic version.
    pub version: String,
    /// Current trust level.
    pub current_trust_level: TrustLevel,
    /// Timestamp when current trust level was established (nanoseconds).
    pub trust_level_since_ns: u64,
    /// Publisher trust score (millionths, 0..=1_000_000).
    pub publisher_trust_score: Option<i64>,

    // -- Risk summary --
    /// Overall risk score (0..=100).
    pub risk_score: u32,
    /// Risk trend over recent window.
    pub risk_trend: RiskTrend,
    /// Top contributing risk factors (max 3).
    pub risk_drivers: Vec<RiskDriver>,

    // -- Evidence summary --
    pub evidence: EvidenceSummary,

    // -- Provenance --
    pub provenance: ProvenanceSummary,

    // -- History --
    /// Trust level timeline (most recent first, max entries configurable).
    pub history: Vec<TrustHistoryEntry>,
    /// Number of incidents this extension has been involved in.
    pub incident_count: u64,

    // -- Recommendation --
    pub recommendation: Recommendation,

    // -- Metadata --
    /// Epoch under which this card was generated.
    pub epoch: SecurityEpoch,
    /// Timestamp when this card was generated (nanoseconds).
    pub generated_at_ns: u64,
}

impl fmt::Display for TrustCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "[{}] {} v{} — trust: {} (since {}ns)",
            self.extension_id,
            self.package_name,
            self.version,
            self.current_trust_level,
            self.trust_level_since_ns,
        )?;
        writeln!(f, "  risk: {}/100 ({})", self.risk_score, self.risk_trend,)?;
        for driver in &self.risk_drivers {
            writeln!(f, "    +{} ({})", driver.contribution, driver.description)?;
        }
        writeln!(
            f,
            "  evidence: +{} -{} ~{}",
            self.evidence.positive_count, self.evidence.negative_count, self.evidence.neutral_count,
        )?;
        writeln!(
            f,
            "  provenance: publisher={} build={} gaps={}",
            self.provenance.publisher_verified,
            self.provenance.build_attested,
            self.provenance.has_provenance_gap,
        )?;
        writeln!(
            f,
            "  recommendation: {} (confidence: {})",
            self.recommendation.action, self.recommendation.confidence,
        )?;
        write!(f, "  rationale: {}", self.recommendation.rationale)
    }
}

// ---------------------------------------------------------------------------
// TrustCardDiff — comparison between two card snapshots
// ---------------------------------------------------------------------------

/// Diff between two trust card snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustCardDiff {
    /// Extension identifier.
    pub extension_id: String,
    /// Old trust level.
    pub old_trust_level: TrustLevel,
    /// New trust level.
    pub new_trust_level: TrustLevel,
    /// Change in risk score (new - old, can be negative).
    pub risk_score_delta: i32,
    /// Old recommendation.
    pub old_recommendation: RecommendedAction,
    /// New recommendation.
    pub new_recommendation: RecommendedAction,
    /// Summary of what changed.
    pub change_summary: String,
}

impl TrustCardDiff {
    /// Compute diff between two trust card snapshots.
    pub fn compute(old: &TrustCard, new: &TrustCard) -> Self {
        let mut changes = Vec::new();

        if old.current_trust_level != new.current_trust_level {
            changes.push(format!(
                "trust: {} -> {}",
                old.current_trust_level, new.current_trust_level
            ));
        }
        if old.risk_score != new.risk_score {
            changes.push(format!("risk: {} -> {}", old.risk_score, new.risk_score));
        }
        if old.recommendation.action != new.recommendation.action {
            changes.push(format!(
                "recommendation: {} -> {}",
                old.recommendation.action, new.recommendation.action
            ));
        }

        let summary = if changes.is_empty() {
            "no significant changes".to_string()
        } else {
            changes.join("; ")
        };

        Self {
            extension_id: new.extension_id.clone(),
            old_trust_level: old.current_trust_level,
            new_trust_level: new.current_trust_level,
            risk_score_delta: new.risk_score as i32 - old.risk_score as i32,
            old_recommendation: old.recommendation.action,
            new_recommendation: new.recommendation.action,
            change_summary: summary,
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateNotification — push notification for trust changes
// ---------------------------------------------------------------------------

/// Notification emitted when a trust level changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateNotification {
    /// Extension whose trust changed.
    pub extension_id: String,
    /// Previous trust level.
    pub old_level: TrustLevel,
    /// New trust level.
    pub new_level: TrustLevel,
    /// Brief summary of triggering evidence.
    pub triggering_evidence_summary: String,
    /// Timestamp of the change (nanoseconds).
    pub timestamp_ns: u64,
}

impl fmt::Display for UpdateNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] trust change: {} -> {} ({})",
            self.extension_id, self.old_level, self.new_level, self.triggering_evidence_summary,
        )
    }
}

// ---------------------------------------------------------------------------
// TrustCardError
// ---------------------------------------------------------------------------

/// Errors from trust card operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustCardError {
    /// Extension not found in reputation graph.
    ExtensionNotFound { extension_id: String },
    /// Card generation failed.
    GenerationFailed {
        extension_id: String,
        reason: String,
    },
    /// Graph error.
    GraphError { message: String },
}

impl fmt::Display for TrustCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::GenerationFailed {
                extension_id,
                reason,
            } => write!(f, "card generation failed for {extension_id}: {reason}"),
            Self::GraphError { message } => write!(f, "graph error: {message}"),
        }
    }
}

impl std::error::Error for TrustCardError {}

impl From<ReputationGraphError> for TrustCardError {
    fn from(err: ReputationGraphError) -> Self {
        Self::GraphError {
            message: err.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// CardFormat — output format selection
// ---------------------------------------------------------------------------

/// Output format for trust cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CardFormat {
    /// Structured JSON for programmatic consumption.
    Json,
    /// Human-readable text for CLI/TUI display.
    Text,
    /// Compact one-line summary for dashboard widgets.
    Compact,
}

// ---------------------------------------------------------------------------
// TrustCardGenerator — produces cards from graph data
// ---------------------------------------------------------------------------

/// Configuration for trust card generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorConfig {
    /// Maximum number of history entries in a card.
    pub max_history_entries: usize,
    /// Maximum number of risk drivers to include.
    pub max_risk_drivers: usize,
    /// Time window for trend analysis (nanoseconds).
    pub trend_window_ns: u64,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            max_history_entries: 10,
            max_risk_drivers: 3,
            trend_window_ns: 86_400_000_000_000, // 24 hours in nanoseconds
        }
    }
}

/// Generates trust cards from reputation graph data.
///
/// Stateless: each `generate` call reads from the graph and produces
/// a fresh card.  Caching is handled by [`TrustCardCache`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCardGenerator {
    /// Configuration parameters.
    config: GeneratorConfig,
}

impl TrustCardGenerator {
    /// Create a generator with default configuration.
    pub fn new() -> Self {
        Self {
            config: GeneratorConfig::default(),
        }
    }

    /// Create a generator with custom configuration.
    pub fn with_config(config: GeneratorConfig) -> Self {
        Self { config }
    }

    /// Generate a trust card for an extension.
    pub fn generate(
        &self,
        graph: &ReputationGraph,
        extension_id: &str,
        epoch: SecurityEpoch,
        now_ns: u64,
    ) -> Result<TrustCard, TrustCardError> {
        let ext =
            graph
                .get_extension(extension_id)
                .ok_or_else(|| TrustCardError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                })?;

        let publisher_trust = graph
            .get_publisher(&ext.publisher_id)
            .map(|p| p.trust_score);

        let lookup = graph.trust_lookup(extension_id)?;

        let history = self.build_history(graph, extension_id);
        let trust_level_since = history
            .first()
            .map(|h| h.timestamp_ns)
            .unwrap_or(ext.first_seen_ns);

        let evidence = self.build_evidence_summary(graph, extension_id);
        let provenance =
            self.build_provenance_summary(graph, extension_id, lookup.dependency_risk_score);

        let risk_drivers = self.compute_risk_drivers(
            ext.current_trust_level,
            &provenance,
            &evidence,
            lookup.dependency_risk_score,
        );
        let risk_score = risk_drivers
            .iter()
            .map(|d| d.contribution)
            .fold(0u32, |acc, x| acc.saturating_add(x))
            .min(100);

        let risk_trend = self.compute_risk_trend(graph, extension_id, now_ns);

        let recommendation = self.compute_recommendation(
            ext.current_trust_level,
            risk_score,
            &evidence,
            &provenance,
        );

        let incident_count = self.count_incidents(graph, extension_id);

        Ok(TrustCard {
            extension_id: extension_id.to_string(),
            package_name: ext.package_name.clone(),
            version: ext.version.clone(),
            current_trust_level: ext.current_trust_level,
            trust_level_since_ns: trust_level_since,
            publisher_trust_score: publisher_trust,
            risk_score,
            risk_trend,
            risk_drivers,
            evidence,
            provenance,
            history,
            incident_count,
            recommendation,
            epoch,
            generated_at_ns: now_ns,
        })
    }

    /// Format a trust card in the specified format.
    pub fn format_card(card: &TrustCard, format: CardFormat) -> String {
        match format {
            CardFormat::Json => serde_json::to_string_pretty(card).expect("serialization failed"),
            CardFormat::Text => card.to_string(),
            CardFormat::Compact => format!(
                "{} v{} | {} | risk:{}/100 ({}) | {}",
                card.package_name,
                card.version,
                card.current_trust_level,
                card.risk_score,
                card.risk_trend,
                card.recommendation.action,
            ),
        }
    }

    // -- Internal helpers --

    fn build_history(&self, graph: &ReputationGraph, extension_id: &str) -> Vec<TrustHistoryEntry> {
        let transitions = graph.trust_history(extension_id);
        transitions
            .iter()
            .rev()
            .take(self.config.max_history_entries)
            .map(|tt| TrustHistoryEntry::from(*tt))
            .collect()
    }

    fn build_evidence_summary(
        &self,
        graph: &ReputationGraph,
        extension_id: &str,
    ) -> EvidenceSummary {
        let evidence_items = graph.get_evidence_for_extension(extension_id);
        let mut positive: u64 = 0;
        let mut negative: u64 = 0;
        let mut neutral: u64 = 0;
        let mut most_recent_ns: Option<u64> = None;
        let mut most_recent_desc: Option<String> = None;

        for ev in &evidence_items {
            match classify_evidence(ev) {
                EvidenceValence::Positive => positive += 1,
                EvidenceValence::Negative => negative += 1,
                EvidenceValence::Neutral => neutral += 1,
            }

            if most_recent_ns.is_none() || Some(ev.timestamp_ns) > most_recent_ns {
                most_recent_ns = Some(ev.timestamp_ns);
                most_recent_desc = Some(format!(
                    "{:?} from {:?} at {}ns",
                    ev.evidence_type, ev.source, ev.timestamp_ns
                ));
            }
        }

        EvidenceSummary {
            positive_count: positive,
            negative_count: negative,
            neutral_count: neutral,
            most_recent_ns,
            most_recent_description: most_recent_desc,
        }
    }

    fn build_provenance_summary(
        &self,
        graph: &ReputationGraph,
        extension_id: &str,
        dependency_risk: i64,
    ) -> ProvenanceSummary {
        match graph.get_provenance(extension_id) {
            Some(prov) => ProvenanceSummary {
                publisher_verified: prov.publisher_verified,
                build_attested: prov.build_attested,
                dependency_risk,
                has_provenance_gap: prov.has_provenance_gap,
            },
            None => ProvenanceSummary {
                publisher_verified: false,
                build_attested: false,
                dependency_risk,
                has_provenance_gap: true,
            },
        }
    }

    fn compute_risk_drivers(
        &self,
        trust_level: TrustLevel,
        provenance: &ProvenanceSummary,
        evidence: &EvidenceSummary,
        dependency_risk: i64,
    ) -> Vec<RiskDriver> {
        let mut drivers = Vec::new();

        // Trust level contributes to risk.
        let trust_risk = match trust_level {
            TrustLevel::Revoked => 40,
            TrustLevel::Compromised => 35,
            TrustLevel::Suspicious => 25,
            TrustLevel::Unknown => 15,
            TrustLevel::Provisional => 5,
            TrustLevel::Established | TrustLevel::Trusted => 0,
        };
        if trust_risk > 0 {
            drivers.push(RiskDriver {
                description: format!("trust level: {trust_level}"),
                contribution: trust_risk,
            });
        }

        // Provenance gaps.
        if !provenance.publisher_verified {
            drivers.push(RiskDriver {
                description: "unverified publisher identity".to_string(),
                contribution: 20,
            });
        }
        if !provenance.build_attested {
            drivers.push(RiskDriver {
                description: "unattested build provenance".to_string(),
                contribution: 15,
            });
        }
        if provenance.has_provenance_gap {
            drivers.push(RiskDriver {
                description: "provenance gap in supply chain".to_string(),
                contribution: 10,
            });
        }

        // Negative evidence.
        if evidence.negative_count > 0 {
            let neg_risk = (evidence.negative_count as u32 * 10).min(30);
            drivers.push(RiskDriver {
                description: format!("{} negative evidence item(s)", evidence.negative_count),
                contribution: neg_risk,
            });
        }

        // Dependency risk (convert from millionths to 0..=20 scale).
        if dependency_risk > 0 {
            let dep_score = ((dependency_risk as u64 * 20) / 1_000_000) as u32;
            if dep_score > 0 {
                drivers.push(RiskDriver {
                    description: "transitive dependency risk".to_string(),
                    contribution: dep_score.min(20),
                });
            }
        }

        // Sort by contribution descending.
        drivers.sort_by_key(|d| std::cmp::Reverse(d.contribution));
        drivers.truncate(self.config.max_risk_drivers);
        drivers
    }

    fn compute_risk_trend(
        &self,
        graph: &ReputationGraph,
        extension_id: &str,
        now_ns: u64,
    ) -> RiskTrend {
        let history = graph.trust_history(extension_id);
        let window_start = now_ns.saturating_sub(self.config.trend_window_ns);

        let recent_transitions: Vec<&&TrustTransition> = history
            .iter()
            .filter(|tt| tt.timestamp_ns >= window_start)
            .collect();

        if recent_transitions.is_empty() {
            return RiskTrend::Stable;
        }

        let mut improvements = 0i32;
        let mut degradations = 0i32;

        for tt in &recent_transitions {
            if tt.new_level.is_degraded() && !tt.old_level.is_degraded() {
                degradations += 1;
            } else if !tt.new_level.is_degraded() && tt.old_level.is_degraded() {
                improvements += 1;
            } else if !tt.new_level.is_degraded() && !tt.old_level.is_degraded() {
                // Within non-degraded tiers, moving up is improvement.
                if tt.new_level > tt.old_level {
                    improvements += 1;
                } else if tt.new_level < tt.old_level {
                    degradations += 1;
                }
            } else if tt.new_level.is_degraded() && tt.old_level.is_degraded() {
                // Within degraded tiers, moving up the enum is worse.
                if tt.new_level > tt.old_level {
                    degradations += 1;
                } else if tt.new_level < tt.old_level {
                    improvements += 1;
                }
            }
        }

        if degradations > improvements {
            RiskTrend::Degrading
        } else if improvements > degradations {
            RiskTrend::Improving
        } else {
            RiskTrend::Stable
        }
    }

    fn compute_recommendation(
        &self,
        trust_level: TrustLevel,
        risk_score: u32,
        evidence: &EvidenceSummary,
        provenance: &ProvenanceSummary,
    ) -> Recommendation {
        let (action, confidence, rationale) = match trust_level {
            TrustLevel::Revoked => (
                RecommendedAction::Remove,
                900_000,
                "extension is revoked; execution forbidden".to_string(),
            ),
            TrustLevel::Compromised => (
                RecommendedAction::Remove,
                850_000,
                format!(
                    "integrity violation confirmed; {} negative evidence item(s)",
                    evidence.negative_count
                ),
            ),
            TrustLevel::Suspicious => {
                if risk_score >= 60 {
                    (
                        RecommendedAction::Restrict,
                        750_000,
                        format!("suspicious behavior with high risk score ({risk_score}/100)"),
                    )
                } else {
                    (
                        RecommendedAction::Review,
                        700_000,
                        "anomalous behavior detected; review recommended".to_string(),
                    )
                }
            }
            TrustLevel::Unknown | TrustLevel::Provisional => {
                if !provenance.publisher_verified || provenance.has_provenance_gap {
                    (
                        RecommendedAction::Review,
                        600_000,
                        "insufficient provenance data; manual review recommended".to_string(),
                    )
                } else {
                    (
                        RecommendedAction::Monitor,
                        500_000,
                        "new extension under observation; continue monitoring".to_string(),
                    )
                }
            }
            TrustLevel::Established | TrustLevel::Trusted => {
                if evidence.negative_count > 0 {
                    (
                        RecommendedAction::Review,
                        600_000,
                        format!(
                            "established extension with {} recent negative evidence item(s)",
                            evidence.negative_count
                        ),
                    )
                } else {
                    (
                        RecommendedAction::Monitor,
                        800_000,
                        "healthy extension; continue normal monitoring".to_string(),
                    )
                }
            }
        };

        Recommendation {
            action,
            confidence,
            rationale,
        }
    }

    fn count_incidents(&self, graph: &ReputationGraph, extension_id: &str) -> u64 {
        graph.incident_count_for_extension(extension_id) as u64
    }
}

impl Default for TrustCardGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TrustCardCache — invalidation-based card caching
// ---------------------------------------------------------------------------

/// Cached trust card with generation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCard {
    card: TrustCard,
    /// Graph transition count when card was generated.
    graph_version: usize,
}

/// Cache for trust cards with invalidation on graph updates.
///
/// Cards are invalidated when the graph's transition count changes
/// (indicating new trust transitions have occurred).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCardCache {
    /// Cached cards indexed by extension_id.
    cards: BTreeMap<String, CachedCard>,
    /// Maximum staleness before forced regeneration (nanoseconds).
    max_staleness_ns: u64,
}

impl TrustCardCache {
    /// Create a new cache with default max staleness (5 minutes).
    pub fn new() -> Self {
        Self {
            cards: BTreeMap::new(),
            max_staleness_ns: 300_000_000_000, // 5 minutes
        }
    }

    /// Create a cache with custom max staleness.
    pub fn with_max_staleness_ns(max_staleness_ns: u64) -> Self {
        Self {
            cards: BTreeMap::new(),
            max_staleness_ns,
        }
    }

    /// Get a cached card if it's still valid.
    ///
    /// Returns `None` if the card is stale (graph has changed or
    /// max staleness exceeded).
    pub fn get(
        &self,
        extension_id: &str,
        graph: &ReputationGraph,
        now_ns: u64,
    ) -> Option<&TrustCard> {
        let cached = self.cards.get(extension_id)?;

        // Check if graph has changed since card was generated.
        if cached.graph_version != graph.total_transitions() {
            return None;
        }

        // Check staleness.
        if now_ns.saturating_sub(cached.card.generated_at_ns) > self.max_staleness_ns {
            return None;
        }

        Some(&cached.card)
    }

    /// Get a card, generating it if not cached or stale.
    pub fn get_or_generate(
        &mut self,
        generator: &TrustCardGenerator,
        graph: &ReputationGraph,
        extension_id: &str,
        epoch: SecurityEpoch,
        now_ns: u64,
    ) -> Result<&TrustCard, TrustCardError> {
        let graph_version = graph.total_transitions();
        let needs_regeneration = match self.cards.get(extension_id) {
            None => true,
            Some(cached) => {
                cached.graph_version != graph_version
                    || now_ns.saturating_sub(cached.card.generated_at_ns) > self.max_staleness_ns
            }
        };

        if needs_regeneration {
            let card = generator.generate(graph, extension_id, epoch, now_ns)?;
            self.cards.insert(
                extension_id.to_string(),
                CachedCard {
                    card,
                    graph_version,
                },
            );
        }

        Ok(&self.cards[extension_id].card)
    }

    /// Invalidate all cached cards.
    pub fn invalidate_all(&mut self) {
        self.cards.clear();
    }

    /// Invalidate a specific extension's cached card.
    pub fn invalidate(&mut self, extension_id: &str) {
        self.cards.remove(extension_id);
    }

    /// Number of cached cards.
    pub fn cached_count(&self) -> usize {
        self.cards.len()
    }
}

impl Default for TrustCardCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UpdatePipeline — incremental update + notification emission
// ---------------------------------------------------------------------------

/// Tracks update notifications emitted by the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePipeline {
    /// Pending notifications (drained by consumers).
    notifications: Vec<UpdateNotification>,
    /// Subscription filter: extension IDs to monitor (empty = all).
    subscriptions: BTreeSet<String>,
}

impl UpdatePipeline {
    /// Create a new pipeline monitoring all extensions.
    pub fn new() -> Self {
        Self {
            notifications: Vec::new(),
            subscriptions: BTreeSet::new(),
        }
    }

    /// Subscribe to notifications for a specific extension.
    pub fn subscribe(&mut self, extension_id: &str) {
        self.subscriptions.insert(extension_id.to_string());
    }

    /// Unsubscribe from notifications for a specific extension.
    pub fn unsubscribe(&mut self, extension_id: &str) {
        self.subscriptions.remove(extension_id);
    }

    /// Record a trust transition and emit notification if subscribed.
    pub fn on_trust_transition(&mut self, transition: &TrustTransition) {
        let should_notify =
            self.subscriptions.is_empty() || self.subscriptions.contains(&transition.extension_id);

        if should_notify {
            let evidence_summary = if transition.triggering_evidence_ids.is_empty() {
                "no linked evidence".to_string()
            } else {
                transition.triggering_evidence_ids.join(", ")
            };

            self.notifications.push(UpdateNotification {
                extension_id: transition.extension_id.clone(),
                old_level: transition.old_level,
                new_level: transition.new_level,
                triggering_evidence_summary: evidence_summary,
                timestamp_ns: transition.timestamp_ns,
            });
        }
    }

    /// Drain all pending notifications.
    pub fn drain_notifications(&mut self) -> Vec<UpdateNotification> {
        std::mem::take(&mut self.notifications)
    }

    /// Number of pending notifications.
    pub fn pending_count(&self) -> usize {
        self.notifications.len()
    }

    /// Number of subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

impl Default for UpdatePipeline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Evidence classification helper
// ---------------------------------------------------------------------------

/// Evidence valence for risk decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceValence {
    Positive,
    Negative,
    Neutral,
}

/// Classify evidence as positive, negative, or neutral.
fn classify_evidence(ev: &EvidenceNode) -> EvidenceValence {
    match ev.evidence_type {
        EvidenceType::ProvenanceAttestation | EvidenceType::OperatorAssessment => {
            EvidenceValence::Positive
        }
        EvidenceType::IncidentRecord | EvidenceType::ThreatIntelligence => {
            EvidenceValence::Negative
        }
        EvidenceType::BehavioralObservation
        | EvidenceType::AdversarialCampaignResult
        | EvidenceType::FleetEvidence => EvidenceValence::Neutral,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::{
        EvidenceNode, EvidenceSource, EvidenceType, ExtensionNode, IncidentNode, IncidentSeverity,
        ProvenanceRecord, PublisherNode, ReputationGraph, ResolutionStatus,
    };

    // -- Test helpers --

    fn test_extension(id: &str, publisher: &str) -> ExtensionNode {
        ExtensionNode {
            extension_id: id.to_string(),
            package_name: format!("pkg-{id}"),
            version: "1.0.0".to_string(),
            publisher_id: publisher.to_string(),
            manifest_hash: [0u8; 32],
            first_seen_ns: 1_000_000_000,
            current_trust_level: TrustLevel::Unknown,
            dependencies: BTreeSet::new(),
        }
    }

    fn test_extension_with_deps(id: &str, publisher: &str, deps: &[&str]) -> ExtensionNode {
        let mut ext = test_extension(id, publisher);
        ext.dependencies = deps.iter().map(|d| d.to_string()).collect();
        ext
    }

    fn test_publisher(id: &str) -> PublisherNode {
        PublisherNode {
            publisher_id: id.to_string(),
            identity_attestation: [1u8; 32],
            published_count: 1,
            trust_score: 500_000,
            first_published_ns: 1_000_000_000,
        }
    }

    fn test_evidence(id: &str, etype: EvidenceType) -> EvidenceNode {
        EvidenceNode {
            evidence_id: id.to_string(),
            evidence_type: etype,
            source: EvidenceSource::BayesianSentinel,
            timestamp_ns: 2_000_000_000,
            content_hash: [2u8; 32],
            linked_decision_ids: vec!["dec-1".to_string()],
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    fn test_graph_with_extension() -> ReputationGraph {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph
    }

    fn test_graph_with_provenance() -> ReputationGraph {
        let mut graph = test_graph_with_extension();
        graph
            .set_provenance(ProvenanceRecord {
                extension_id: "ext-1".into(),
                publisher_verified: true,
                build_attested: true,
                attestation_source: Some("sigstore".into()),
                dependency_depth: 0,
                has_provenance_gap: false,
                gap_descriptions: vec![],
            })
            .unwrap();
        graph
    }

    // -- RiskTrend --

    #[test]
    fn risk_trend_display() {
        assert_eq!(RiskTrend::Improving.to_string(), "improving");
        assert_eq!(RiskTrend::Stable.to_string(), "stable");
        assert_eq!(RiskTrend::Degrading.to_string(), "degrading");
    }

    #[test]
    fn risk_trend_serde_roundtrip() {
        for trend in [
            RiskTrend::Improving,
            RiskTrend::Stable,
            RiskTrend::Degrading,
        ] {
            let json = serde_json::to_string(&trend).unwrap();
            let restored: RiskTrend = serde_json::from_str(&json).unwrap();
            assert_eq!(trend, restored);
        }
    }

    // -- RecommendedAction --

    #[test]
    fn recommended_action_display() {
        assert_eq!(RecommendedAction::Monitor.to_string(), "monitor");
        assert_eq!(RecommendedAction::Review.to_string(), "review");
        assert_eq!(RecommendedAction::Restrict.to_string(), "restrict");
        assert_eq!(RecommendedAction::Remove.to_string(), "remove");
    }

    #[test]
    fn recommended_action_serde_roundtrip() {
        for action in [
            RecommendedAction::Monitor,
            RecommendedAction::Review,
            RecommendedAction::Restrict,
            RecommendedAction::Remove,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let restored: RecommendedAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, restored);
        }
    }

    // -- CardFormat --

    #[test]
    fn card_format_serde_roundtrip() {
        for fmt in [CardFormat::Json, CardFormat::Text, CardFormat::Compact] {
            let json = serde_json::to_string(&fmt).unwrap();
            let restored: CardFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(fmt, restored);
        }
    }

    // -- TrustCardError --

    #[test]
    fn error_display() {
        let err = TrustCardError::ExtensionNotFound {
            extension_id: "ext-1".into(),
        };
        assert_eq!(err.to_string(), "extension not found: ext-1");

        let err = TrustCardError::GenerationFailed {
            extension_id: "ext-2".into(),
            reason: "bad data".into(),
        };
        assert!(err.to_string().contains("bad data"));

        let err = TrustCardError::GraphError {
            message: "oops".into(),
        };
        assert!(err.to_string().contains("oops"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            TrustCardError::ExtensionNotFound {
                extension_id: "ext-1".into(),
            },
            TrustCardError::GenerationFailed {
                extension_id: "ext-2".into(),
                reason: "test".into(),
            },
            TrustCardError::GraphError {
                message: "msg".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: TrustCardError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -- TrustCardGenerator: basic card generation --

    #[test]
    fn generate_card_for_unknown_extension() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.extension_id, "ext-1");
        assert_eq!(card.package_name, "pkg-ext-1");
        assert_eq!(card.current_trust_level, TrustLevel::Unknown);
        assert_eq!(card.publisher_trust_score, Some(500_000));
        assert!(
            card.risk_score > 0,
            "unknown extension should have some risk"
        );
    }

    #[test]
    fn generate_card_for_trusted_extension_with_provenance() {
        let mut graph = test_graph_with_provenance();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Trusted,
                vec!["ev-good".into()],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.current_trust_level, TrustLevel::Trusted);
        assert_eq!(card.risk_score, 0, "trusted with full provenance = 0 risk");
        assert_eq!(card.recommendation.action, RecommendedAction::Monitor);
    }

    #[test]
    fn generate_card_missing_extension_fails() {
        let graph = ReputationGraph::new();
        let generator = TrustCardGenerator::new();
        assert!(matches!(
            generator.generate(&graph, "nonexistent", SecurityEpoch::from_raw(1), 0),
            Err(TrustCardError::ExtensionNotFound { .. })
        ));
    }

    // -- Risk drivers --

    #[test]
    fn risk_drivers_include_unverified_provenance() {
        let graph = test_graph_with_extension(); // no provenance set
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let descriptions: Vec<&str> = card
            .risk_drivers
            .iter()
            .map(|d| d.description.as_str())
            .collect();
        assert!(
            descriptions
                .iter()
                .any(|d| d.contains("unverified publisher")),
            "expected unverified publisher driver, got: {descriptions:?}"
        );
    }

    #[test]
    fn risk_drivers_max_three() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::with_config(GeneratorConfig {
            max_risk_drivers: 3,
            ..Default::default()
        });
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert!(card.risk_drivers.len() <= 3);
    }

    #[test]
    fn risk_drivers_sorted_by_contribution_descending() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        for pair in card.risk_drivers.windows(2) {
            assert!(
                pair[0].contribution >= pair[1].contribution,
                "risk drivers not sorted descending: {} >= {}",
                pair[0].contribution,
                pair[1].contribution,
            );
        }
    }

    #[test]
    fn risk_score_capped_at_100() {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = TrustLevel::Revoked;
        graph.register_extension(ext).unwrap();
        // Add many negative evidence items.
        for i in 0..20 {
            graph
                .add_evidence(
                    "ext-1",
                    test_evidence(&format!("ev-{i}"), EvidenceType::IncidentRecord),
                )
                .unwrap();
        }

        let generator = TrustCardGenerator::with_config(GeneratorConfig {
            max_risk_drivers: 10, // allow all drivers
            ..Default::default()
        });
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert!(card.risk_score <= 100);
    }

    // -- Recommendations --

    #[test]
    fn recommendation_remove_for_revoked() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Revoked,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.recommendation.action, RecommendedAction::Remove);
    }

    #[test]
    fn recommendation_remove_for_compromised() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Compromised,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.recommendation.action, RecommendedAction::Remove);
    }

    #[test]
    fn recommendation_review_for_suspicious() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        // Could be Review or Restrict depending on risk score.
        assert!(
            card.recommendation.action == RecommendedAction::Review
                || card.recommendation.action == RecommendedAction::Restrict
        );
    }

    #[test]
    fn recommendation_review_for_unknown_no_provenance() {
        let graph = test_graph_with_extension(); // unknown, no provenance
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.recommendation.action, RecommendedAction::Review);
    }

    #[test]
    fn recommendation_monitor_for_trusted_no_negatives() {
        let mut graph = test_graph_with_provenance();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Trusted,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.recommendation.action, RecommendedAction::Monitor);
    }

    // -- Evidence summary --

    #[test]
    fn evidence_summary_counts() {
        let mut graph = test_graph_with_extension();
        graph
            .add_evidence(
                "ext-1",
                test_evidence("ev-1", EvidenceType::ProvenanceAttestation),
            )
            .unwrap();
        graph
            .add_evidence("ext-1", test_evidence("ev-2", EvidenceType::IncidentRecord))
            .unwrap();
        graph
            .add_evidence(
                "ext-1",
                test_evidence("ev-3", EvidenceType::BehavioralObservation),
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.evidence.positive_count, 1);
        assert_eq!(card.evidence.negative_count, 1);
        assert_eq!(card.evidence.neutral_count, 1);
        assert!(card.evidence.most_recent_ns.is_some());
        assert!(card.evidence.most_recent_description.is_some());
    }

    #[test]
    fn evidence_summary_empty() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.evidence.positive_count, 0);
        assert_eq!(card.evidence.negative_count, 0);
        assert_eq!(card.evidence.neutral_count, 0);
        assert!(card.evidence.most_recent_ns.is_none());
    }

    // -- Risk trend --

    #[test]
    fn risk_trend_degrading_on_recent_demotion() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec!["ev-bad".into()],
                1,
                SecurityEpoch::from_raw(1),
                9_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.risk_trend, RiskTrend::Degrading);
    }

    #[test]
    fn risk_trend_stable_when_no_recent_transitions() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.risk_trend, RiskTrend::Stable);
    }

    #[test]
    fn risk_trend_improving_on_upgrade() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec!["ev-good".into()],
                1,
                SecurityEpoch::from_raw(1),
                9_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.risk_trend, RiskTrend::Improving);
    }

    // -- History --

    #[test]
    fn history_entries_most_recent_first() {
        let mut graph = test_graph_with_extension();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                2_000_000_000,
            )
            .unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                3_000_000_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.history.len(), 2);
        // Most recent first.
        assert_eq!(card.history[0].new_level, TrustLevel::Established);
        assert_eq!(card.history[1].new_level, TrustLevel::Provisional);
    }

    #[test]
    fn history_capped_at_max_entries() {
        let mut graph = test_graph_with_extension();
        // Create many transitions.
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                2_000,
            )
            .unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                3_000,
            )
            .unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                4_000,
            )
            .unwrap();

        let generator = TrustCardGenerator::with_config(GeneratorConfig {
            max_history_entries: 2,
            ..Default::default()
        });
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.history.len(), 2);
    }

    // -- Card formatting --

    #[test]
    fn format_json_is_valid() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let json_str = TrustCardGenerator::format_card(&card, CardFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.is_object());
    }

    #[test]
    fn format_text_contains_extension_id() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let text = TrustCardGenerator::format_card(&card, CardFormat::Text);
        assert!(text.contains("ext-1"));
        assert!(text.contains("pkg-ext-1"));
    }

    #[test]
    fn format_compact_is_single_line() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let compact = TrustCardGenerator::format_card(&card, CardFormat::Compact);
        assert!(
            !compact.contains('\n'),
            "compact format should be single line"
        );
        assert!(compact.contains("pkg-ext-1"));
    }

    // -- TrustCard serde --

    #[test]
    fn trust_card_serde_roundtrip() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let json = serde_json::to_string(&card).unwrap();
        let restored: TrustCard = serde_json::from_str(&json).unwrap();
        assert_eq!(card, restored);
    }

    // -- TrustCardDiff --

    #[test]
    fn diff_detects_trust_level_change() {
        let mut graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card_before = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec!["ev-bad".into()],
                1,
                SecurityEpoch::from_raw(1),
                11_000_000_000,
            )
            .unwrap();
        let card_after = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
            .unwrap();

        let diff = TrustCardDiff::compute(&card_before, &card_after);
        assert_eq!(diff.old_trust_level, TrustLevel::Unknown);
        assert_eq!(diff.new_trust_level, TrustLevel::Suspicious);
        assert!(diff.change_summary.contains("trust:"));
    }

    #[test]
    fn diff_no_changes() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let diff = TrustCardDiff::compute(&card, &card);
        assert_eq!(diff.risk_score_delta, 0);
        assert!(diff.change_summary.contains("no significant changes"));
    }

    #[test]
    fn diff_serde_roundtrip() {
        let diff = TrustCardDiff {
            extension_id: "ext-1".into(),
            old_trust_level: TrustLevel::Established,
            new_trust_level: TrustLevel::Suspicious,
            risk_score_delta: 25,
            old_recommendation: RecommendedAction::Monitor,
            new_recommendation: RecommendedAction::Review,
            change_summary: "trust degraded".into(),
        };
        let json = serde_json::to_string(&diff).unwrap();
        let restored: TrustCardDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(diff, restored);
    }

    // -- UpdateNotification --

    #[test]
    fn notification_display() {
        let notif = UpdateNotification {
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Established,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_summary: "ev-1, ev-2".into(),
            timestamp_ns: 5_000_000_000,
        };

        let s = notif.to_string();
        assert!(s.contains("ext-1"));
        assert!(s.contains("established"));
        assert!(s.contains("suspicious"));
    }

    #[test]
    fn notification_serde_roundtrip() {
        let notif = UpdateNotification {
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_summary: "ev-1".into(),
            timestamp_ns: 5_000_000_000,
        };
        let json = serde_json::to_string(&notif).unwrap();
        let restored: UpdateNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(notif, restored);
    }

    // -- UpdatePipeline --

    #[test]
    fn pipeline_emits_notifications_on_transition() {
        let mut pipeline = UpdatePipeline::new();
        let transition = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec!["ev-1".into()],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        pipeline.on_trust_transition(&transition);
        assert_eq!(pipeline.pending_count(), 1);

        let notifications = pipeline.drain_notifications();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].extension_id, "ext-1");
        assert_eq!(notifications[0].old_level, TrustLevel::Unknown);
        assert_eq!(notifications[0].new_level, TrustLevel::Suspicious);
        assert_eq!(pipeline.pending_count(), 0);
    }

    #[test]
    fn pipeline_subscription_filter() {
        let mut pipeline = UpdatePipeline::new();
        pipeline.subscribe("ext-2");

        let transition_ext1 = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        pipeline.on_trust_transition(&transition_ext1);
        // ext-1 not subscribed, should be filtered.
        assert_eq!(pipeline.pending_count(), 0);

        let transition_ext2 = crate::reputation::TrustTransition {
            transition_id: "tt-2".into(),
            extension_id: "ext-2".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 6_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        pipeline.on_trust_transition(&transition_ext2);
        assert_eq!(pipeline.pending_count(), 1);
    }

    #[test]
    fn pipeline_unsubscribe() {
        let mut pipeline = UpdatePipeline::new();
        pipeline.subscribe("ext-1");
        assert_eq!(pipeline.subscription_count(), 1);
        pipeline.unsubscribe("ext-1");
        assert_eq!(pipeline.subscription_count(), 0);
    }

    // -- TrustCardCache --

    #[test]
    fn cache_miss_on_empty() {
        let cache = TrustCardCache::new();
        let graph = test_graph_with_extension();
        assert!(cache.get("ext-1", &graph, 10_000_000_000).is_none());
    }

    #[test]
    fn cache_hit_after_generation() {
        let mut cache = TrustCardCache::new();
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);
        let now = 10_000_000_000u64;

        cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now)
            .unwrap();
        assert_eq!(cache.cached_count(), 1);

        // Should be a cache hit.
        let card = cache.get("ext-1", &graph, now + 1_000_000);
        assert!(card.is_some());
    }

    #[test]
    fn cache_invalidated_on_graph_change() {
        let mut cache = TrustCardCache::new();
        let mut graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);
        let now = 10_000_000_000u64;

        cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now)
            .unwrap();

        // Change the graph.
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec![],
                1,
                epoch,
                now + 1_000,
            )
            .unwrap();

        // Cache should be invalid due to transition count change.
        assert!(cache.get("ext-1", &graph, now + 2_000).is_none());
    }

    #[test]
    fn cache_invalidated_on_staleness() {
        let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000); // 1 second
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);
        let now = 10_000_000_000u64;

        cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now)
            .unwrap();

        // After staleness period.
        assert!(cache.get("ext-1", &graph, now + 2_000_000_000).is_none());
    }

    #[test]
    fn cache_invalidate_specific() {
        let mut cache = TrustCardCache::new();
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);

        cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, 10_000_000_000)
            .unwrap();
        assert_eq!(cache.cached_count(), 1);

        cache.invalidate("ext-1");
        assert_eq!(cache.cached_count(), 0);
    }

    #[test]
    fn cache_invalidate_all() {
        let mut cache = TrustCardCache::new();
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph
            .register_extension(test_extension("ext-2", "pub-1"))
            .unwrap();

        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);
        let now = 10_000_000_000u64;

        cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now)
            .unwrap();
        cache
            .get_or_generate(&generator, &graph, "ext-2", epoch, now)
            .unwrap();
        assert_eq!(cache.cached_count(), 2);

        cache.invalidate_all();
        assert_eq!(cache.cached_count(), 0);
    }

    // -- Dependency risk in cards --

    #[test]
    fn card_includes_dependency_risk() {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));

        let dep = test_extension("dep-1", "pub-1");
        graph.register_extension(dep).unwrap();

        let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-1"]);
        graph.register_extension(ext).unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        // dep-1 is Unknown, so dependency_risk > 0.
        assert!(card.provenance.dependency_risk > 0);
    }

    // -- Incident count --

    #[test]
    fn card_incident_count() {
        let mut graph = test_graph_with_extension();
        graph.add_incident(IncidentNode {
            incident_id: "inc-1".into(),
            severity: IncidentSeverity::High,
            affected_extensions: ["ext-1".into()].into_iter().collect(),
            containment_actions: vec!["quarantine".into()],
            resolution_status: ResolutionStatus::Active,
            timestamp_ns: 5_000_000_000,
        });

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.incident_count, 1);
    }

    // -- Determinism --

    #[test]
    fn card_generation_is_deterministic() {
        let build = || {
            let mut g = ReputationGraph::new();
            g.register_publisher(test_publisher("pub-1"));
            g.register_extension(test_extension("ext-1", "pub-1"))
                .unwrap();
            g.add_evidence(
                "ext-1",
                test_evidence("ev-1", EvidenceType::BehavioralObservation),
            )
            .unwrap();
            g.transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                5_000,
            )
            .unwrap();
            g
        };

        let generator = TrustCardGenerator::new();
        let card1 = generator
            .generate(
                &build(),
                "ext-1",
                SecurityEpoch::from_raw(1),
                10_000_000_000,
            )
            .unwrap();
        let card2 = generator
            .generate(
                &build(),
                "ext-1",
                SecurityEpoch::from_raw(1),
                10_000_000_000,
            )
            .unwrap();

        let json1 = serde_json::to_string(&card1).unwrap();
        let json2 = serde_json::to_string(&card2).unwrap();
        assert_eq!(
            json1, json2,
            "identical inputs must produce identical cards"
        );
    }

    // -- TrustHistoryEntry from TrustTransition --

    #[test]
    fn history_entry_from_transition() {
        let tt = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec!["ev-1".into(), "ev-2".into()],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        let entry = TrustHistoryEntry::from(&tt);
        assert_eq!(entry.old_level, TrustLevel::Unknown);
        assert_eq!(entry.new_level, TrustLevel::Provisional);
        assert!(!entry.operator_override);
        assert!(entry.reason.contains("ev-1"));
    }

    #[test]
    fn history_entry_from_operator_override() {
        let tt = crate::reputation::TrustTransition {
            transition_id: "tt-2".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Compromised,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec![],
            policy_version: 2,
            operator_override: true,
            operator_justification: Some("incident resolved".into()),
            timestamp_ns: 6_000_000_000,
            epoch: SecurityEpoch::from_raw(2),
        };

        let entry = TrustHistoryEntry::from(&tt);
        assert!(entry.operator_override);
        assert_eq!(entry.reason, "incident resolved");
    }

    // -- Provenance summary --

    #[test]
    fn provenance_summary_without_record() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert!(!card.provenance.publisher_verified);
        assert!(!card.provenance.build_attested);
        assert!(card.provenance.has_provenance_gap);
    }

    #[test]
    fn provenance_summary_with_record() {
        let graph = test_graph_with_provenance();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert!(card.provenance.publisher_verified);
        assert!(card.provenance.build_attested);
        assert!(!card.provenance.has_provenance_gap);
    }

    // -- GeneratorConfig --

    #[test]
    fn generator_config_serde_roundtrip() {
        let config = GeneratorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: GeneratorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn generator_config_defaults() {
        let config = GeneratorConfig::default();
        assert_eq!(config.max_history_entries, 10);
        assert_eq!(config.max_risk_drivers, 3);
        assert_eq!(config.trend_window_ns, 86_400_000_000_000);
    }

    // -- Batch card generation --

    #[test]
    fn generate_cards_for_multiple_extensions() {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        for i in 0..5 {
            graph
                .register_extension(test_extension(&format!("ext-{i}"), "pub-1"))
                .unwrap();
        }

        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);

        let cards: Vec<TrustCard> = (0..5)
            .map(|i| {
                generator
                    .generate(&graph, &format!("ext-{i}"), epoch, 10_000_000_000)
                    .unwrap()
            })
            .collect();

        assert_eq!(cards.len(), 5);
        for (i, card) in cards.iter().enumerate() {
            assert_eq!(card.extension_id, format!("ext-{i}"));
        }
    }

    // -- Enrichment: struct serde roundtrips --

    #[test]
    fn risk_driver_serde_roundtrip() {
        let driver = RiskDriver {
            description: "unverified publisher identity".into(),
            contribution: 20,
        };
        let json = serde_json::to_string(&driver).unwrap();
        let back: RiskDriver = serde_json::from_str(&json).unwrap();
        assert_eq!(driver, back);
    }

    #[test]
    fn evidence_summary_serde_roundtrip() {
        let summary = EvidenceSummary {
            positive_count: 5,
            negative_count: 2,
            neutral_count: 3,
            most_recent_ns: Some(9_000_000_000),
            most_recent_description: Some("behavioral observation".into()),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: EvidenceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn evidence_summary_serde_roundtrip_none_fields() {
        let summary = EvidenceSummary {
            positive_count: 0,
            negative_count: 0,
            neutral_count: 0,
            most_recent_ns: None,
            most_recent_description: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: EvidenceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn provenance_summary_serde_roundtrip() {
        let prov = ProvenanceSummary {
            publisher_verified: true,
            build_attested: true,
            dependency_risk: 500_000,
            has_provenance_gap: false,
        };
        let json = serde_json::to_string(&prov).unwrap();
        let back: ProvenanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(prov, back);
    }

    #[test]
    fn trust_history_entry_serde_roundtrip() {
        let entry = TrustHistoryEntry {
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            reason: "evidence: ev-1".into(),
            timestamp_ns: 5_000_000_000,
            operator_override: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: TrustHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn recommendation_serde_roundtrip() {
        let rec = Recommendation {
            action: RecommendedAction::Review,
            confidence: 700_000,
            rationale: "anomalous behavior detected".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: Recommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    // -- Enrichment: TrustCardError std::error::Error --

    #[test]
    fn trust_card_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TrustCardError::ExtensionNotFound {
            extension_id: "ext-1".into(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: TrustCardError Display uniqueness --

    #[test]
    fn trust_card_error_display_all_distinct() {
        let errors = vec![
            TrustCardError::ExtensionNotFound {
                extension_id: "ext-1".into(),
            },
            TrustCardError::GenerationFailed {
                extension_id: "ext-2".into(),
                reason: "bad".into(),
            },
            TrustCardError::GraphError {
                message: "graph".into(),
            },
        ];
        let mut displays = BTreeSet::new();
        for err in &errors {
            displays.insert(err.to_string());
        }
        assert_eq!(displays.len(), 3);
    }

    // -- Enrichment: enum ordering --

    #[test]
    fn risk_trend_ordering() {
        assert!(RiskTrend::Improving < RiskTrend::Stable);
        assert!(RiskTrend::Stable < RiskTrend::Degrading);
    }

    #[test]
    fn recommended_action_ordering() {
        assert!(RecommendedAction::Monitor < RecommendedAction::Review);
        assert!(RecommendedAction::Review < RecommendedAction::Restrict);
        assert!(RecommendedAction::Restrict < RecommendedAction::Remove);
    }

    #[test]
    fn card_format_ordering() {
        assert!(CardFormat::Json < CardFormat::Text);
        assert!(CardFormat::Text < CardFormat::Compact);
    }

    // -- Enrichment: TrustCardGenerator with_config --

    #[test]
    fn generator_with_custom_config() {
        let config = GeneratorConfig {
            max_history_entries: 5,
            max_risk_drivers: 2,
            trend_window_ns: 3_600_000_000_000,
        };
        let generator = TrustCardGenerator::with_config(config.clone());
        let graph = test_graph_with_extension();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();
        assert!(card.risk_drivers.len() <= 2);
    }

    // -- Enrichment: Default impls --

    #[test]
    fn trust_card_generator_default() {
        let gen1 = TrustCardGenerator::new();
        let gen2 = TrustCardGenerator::default();
        assert_eq!(gen1.config, gen2.config);
    }

    #[test]
    fn trust_card_cache_default() {
        let cache = TrustCardCache::default();
        assert_eq!(cache.cached_count(), 0);
    }

    #[test]
    fn update_pipeline_default() {
        let pipeline = UpdatePipeline::default();
        assert_eq!(pipeline.pending_count(), 0);
        assert_eq!(pipeline.subscription_count(), 0);
    }

    // -- Enrichment: pipeline no subscription = all --

    #[test]
    fn pipeline_no_subscription_notifies_all() {
        let mut pipeline = UpdatePipeline::new();
        // No subscriptions -> should notify for all extensions.
        let tt1 = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let tt2 = crate::reputation::TrustTransition {
            transition_id: "tt-2".into(),
            extension_id: "ext-2".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 6_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        pipeline.on_trust_transition(&tt1);
        pipeline.on_trust_transition(&tt2);
        assert_eq!(pipeline.pending_count(), 2);
    }

    // -- Enrichment: pipeline drain empties buffer --

    #[test]
    fn pipeline_drain_empties_buffer() {
        let mut pipeline = UpdatePipeline::new();
        let tt = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec!["ev-1".into()],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        pipeline.on_trust_transition(&tt);
        assert_eq!(pipeline.pending_count(), 1);
        let _ = pipeline.drain_notifications();
        assert_eq!(pipeline.pending_count(), 0);
    }

    // -- Enrichment: TrustHistoryEntry from operator override without justification --

    #[test]
    fn history_entry_from_operator_override_no_justification() {
        let tt = crate::reputation::TrustTransition {
            transition_id: "tt-3".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Suspicious,
            new_level: TrustLevel::Provisional,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: true,
            operator_justification: None,
            timestamp_ns: 7_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let entry = TrustHistoryEntry::from(&tt);
        assert!(entry.operator_override);
        assert_eq!(entry.reason, "operator override");
    }

    // -- Enrichment: TrustCard Display output structure --

    #[test]
    fn trust_card_display_contains_all_sections() {
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        let display = card.to_string();
        assert!(display.contains("ext-1"));
        assert!(display.contains("pkg-ext-1"));
        assert!(display.contains("risk:"));
        assert!(display.contains("evidence:"));
        assert!(display.contains("provenance:"));
        assert!(display.contains("recommendation:"));
        assert!(display.contains("rationale:"));
    }

    // -- Enrichment: recommendation for established with negative evidence --

    #[test]
    fn recommendation_review_for_established_with_negatives() {
        let mut graph = test_graph_with_provenance();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Established,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();
        graph
            .add_evidence(
                "ext-1",
                test_evidence("ev-neg", EvidenceType::IncidentRecord),
            )
            .unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.recommendation.action, RecommendedAction::Review);
    }

    // -- Enrichment: diff with recommendation change --

    #[test]
    fn diff_detects_recommendation_change() {
        let mut graph = test_graph_with_provenance();
        let generator = TrustCardGenerator::new();

        // Start as trusted (Monitor recommendation).
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Trusted,
                vec![],
                1,
                SecurityEpoch::from_raw(1),
                5_000_000_000,
            )
            .unwrap();
        let card_before = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();
        assert_eq!(
            card_before.recommendation.action,
            RecommendedAction::Monitor
        );

        // Transition to suspicious (Review/Restrict recommendation).
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Suspicious,
                vec!["ev-bad".into()],
                1,
                SecurityEpoch::from_raw(1),
                11_000_000_000,
            )
            .unwrap();
        let card_after = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
            .unwrap();

        let diff = TrustCardDiff::compute(&card_before, &card_after);
        assert!(diff.change_summary.contains("recommendation:"));
        assert_ne!(diff.old_recommendation, diff.new_recommendation);
    }

    // -- Enrichment: UpdatePipeline notification evidence summary --

    #[test]
    fn pipeline_notification_no_evidence_summary() {
        let mut pipeline = UpdatePipeline::new();
        let tt = crate::reputation::TrustTransition {
            transition_id: "tt-1".into(),
            extension_id: "ext-1".into(),
            old_level: TrustLevel::Unknown,
            new_level: TrustLevel::Suspicious,
            triggering_evidence_ids: vec![],
            policy_version: 1,
            operator_override: false,
            operator_justification: None,
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        };
        pipeline.on_trust_transition(&tt);
        let notifications = pipeline.drain_notifications();
        assert_eq!(
            notifications[0].triggering_evidence_summary,
            "no linked evidence"
        );
    }

    // -- Enrichment: TrustCardCache get_or_generate returns same card --

    #[test]
    fn cache_get_or_generate_returns_cached() {
        let mut cache = TrustCardCache::new();
        let graph = test_graph_with_extension();
        let generator = TrustCardGenerator::new();
        let epoch = SecurityEpoch::from_raw(1);
        let now = 10_000_000_000u64;

        let card1 = cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now)
            .unwrap()
            .clone();
        let card2 = cache
            .get_or_generate(&generator, &graph, "ext-1", epoch, now + 1_000)
            .unwrap()
            .clone();

        // Should be the same card (cached), same generated_at_ns.
        assert_eq!(card1.generated_at_ns, card2.generated_at_ns);
    }
}
