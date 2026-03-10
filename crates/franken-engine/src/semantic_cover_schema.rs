#![forbid(unsafe_code)]

//! Semantic cover schema and overlap restriction maps for cross-surface support reasoning.
//!
//! Implements [RGC-808A]: defines the concrete semantic cover, overlap objects, and
//! transport metadata that make local-to-global support reasoning mechanically possible.
//! Each engine surface (parser, lowering, runtime, module, TS, React, CLI) declares its
//! support scope; overlap restriction maps constrain which surfaces may claim overlapping
//! semantics and under what conditions.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for semantic cover artifacts.
pub const COVER_SCHEMA_VERSION: &str = "franken-engine.semantic-cover-schema.v1";

/// Maximum number of surfaces supported.
pub const MAX_SURFACES: usize = 16;

/// Maximum number of features per surface.
pub const MAX_FEATURES_PER_SURFACE: usize = 512;

// ---------------------------------------------------------------------------
// Surface taxonomy
// ---------------------------------------------------------------------------

/// An engine surface — a distinct subsystem that declares support for JS/TS features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EngineSurface {
    /// Parser: lexing, AST construction, syntax support.
    Parser,
    /// Lowering: AST → IR translation, desugaring.
    Lowering,
    /// Runtime: bytecode execution, built-in semantics.
    Runtime,
    /// Module: resolution, loading, linking, live bindings.
    Module,
    /// TypeScript: type erasure, normalization, tsconfig handling.
    TypeScript,
    /// React: JSX/TSX, component model, runtime modes.
    React,
    /// CLI: frankenctl commands, operator workflows.
    Cli,
}

impl fmt::Display for EngineSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parser => write!(f, "parser"),
            Self::Lowering => write!(f, "lowering"),
            Self::Runtime => write!(f, "runtime"),
            Self::Module => write!(f, "module"),
            Self::TypeScript => write!(f, "typescript"),
            Self::React => write!(f, "react"),
            Self::Cli => write!(f, "cli"),
        }
    }
}

impl EngineSurface {
    /// All surface variants.
    pub fn all() -> &'static [EngineSurface] {
        &[
            Self::Parser,
            Self::Lowering,
            Self::Runtime,
            Self::Module,
            Self::TypeScript,
            Self::React,
            Self::Cli,
        ]
    }
}

// ---------------------------------------------------------------------------
// Feature support status
// ---------------------------------------------------------------------------

/// Support status for a feature on a specific surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SupportStatus {
    /// Fully supported with evidence.
    Supported,
    /// Partially supported — some sub-features missing.
    Partial,
    /// Explicitly unsupported with documented reason.
    Unsupported,
    /// Support status unknown / not yet assessed.
    Unknown,
    /// Not applicable to this surface.
    NotApplicable,
}

impl fmt::Display for SupportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supported => write!(f, "supported"),
            Self::Partial => write!(f, "partial"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::Unknown => write!(f, "unknown"),
            Self::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

// ---------------------------------------------------------------------------
// Feature declaration
// ---------------------------------------------------------------------------

/// A single feature in the semantic cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverFeature {
    /// Unique key for this feature (e.g. "es2024.array.groupBy").
    pub key: String,
    /// Human-readable description.
    pub description: String,
    /// Which ECMAScript/TS/React spec area this belongs to.
    pub spec_area: String,
    /// Which surfaces are relevant for this feature.
    pub relevant_surfaces: BTreeSet<EngineSurface>,
    /// Per-surface support status.
    pub support_map: BTreeMap<EngineSurface, SupportStatus>,
    /// Evidence keys supporting the declared status.
    pub evidence_keys: BTreeSet<String>,
}

impl CoverFeature {
    /// True if the feature is fully supported on all relevant surfaces.
    pub fn is_fully_covered(&self) -> bool {
        self.relevant_surfaces
            .iter()
            .all(|s| self.support_map.get(s) == Some(&SupportStatus::Supported))
    }

    /// True if the feature has at least one unsupported surface.
    pub fn has_gap(&self) -> bool {
        self.relevant_surfaces
            .iter()
            .any(|s| matches!(self.support_map.get(s), Some(SupportStatus::Unsupported) | Some(SupportStatus::Unknown)))
    }

    /// Count of surfaces where this feature is supported.
    pub fn supported_surface_count(&self) -> usize {
        self.relevant_surfaces
            .iter()
            .filter(|s| self.support_map.get(s) == Some(&SupportStatus::Supported))
            .count()
    }

    /// Coverage ratio (millionths): supported / relevant.
    pub fn coverage_ratio_millionths(&self) -> i64 {
        if self.relevant_surfaces.is_empty() {
            return 0;
        }
        let supported = self.supported_surface_count() as i64;
        let total = self.relevant_surfaces.len() as i64;
        supported
            .checked_mul(1_000_000)
            .map(|n| n / total)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Overlap restriction
// ---------------------------------------------------------------------------

/// Why an overlap between surfaces is restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OverlapRestriction {
    /// Both surfaces may claim the same feature if they provide independent evidence.
    Allowed,
    /// Overlap is permitted only if one surface delegates to the other.
    DelegationRequired,
    /// Overlap is forbidden — exactly one surface must own the feature.
    Exclusive,
    /// Overlap requires reconciliation evidence (both must produce identical observable results).
    ReconciliationRequired,
}

impl fmt::Display for OverlapRestriction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::DelegationRequired => write!(f, "delegation_required"),
            Self::Exclusive => write!(f, "exclusive"),
            Self::ReconciliationRequired => write!(f, "reconciliation_required"),
        }
    }
}

/// An overlap restriction map entry: governs how two surfaces interact on shared features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlapEntry {
    /// First surface (lexicographically smaller).
    pub surface_a: EngineSurface,
    /// Second surface.
    pub surface_b: EngineSurface,
    /// The restriction governing this pair.
    pub restriction: OverlapRestriction,
    /// Optional scope: if set, restriction applies only to features matching this prefix.
    pub scope_prefix: Option<String>,
    /// Rationale for this restriction.
    pub rationale: String,
}

/// The full overlap restriction map across all surface pairs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlapRestrictionMap {
    /// Schema version.
    pub schema_version: String,
    /// Entries in the map.
    pub entries: Vec<OverlapEntry>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl OverlapRestrictionMap {
    /// Build from a list of entries, computing the content hash.
    pub fn new(entries: Vec<OverlapEntry>) -> Self {
        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(COVER_SCHEMA_VERSION.as_bytes());
            for e in &entries {
                buf.extend_from_slice(e.surface_a.to_string().as_bytes());
                buf.extend_from_slice(e.surface_b.to_string().as_bytes());
                buf.extend_from_slice(e.restriction.to_string().as_bytes());
                if let Some(scope) = &e.scope_prefix {
                    buf.extend_from_slice(scope.as_bytes());
                }
            }
            ContentHash::compute(&buf)
        };
        Self {
            schema_version: COVER_SCHEMA_VERSION.to_string(),
            entries,
            content_hash,
        }
    }

    /// Look up the restriction for a surface pair.
    pub fn restriction_for(
        &self,
        a: EngineSurface,
        b: EngineSurface,
    ) -> Option<OverlapRestriction> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        self.entries
            .iter()
            .find(|e| e.surface_a == lo && e.surface_b == hi && e.scope_prefix.is_none())
            .map(|e| e.restriction)
    }

    /// Look up restrictions with a scope filter.
    pub fn restrictions_for_scope(
        &self,
        a: EngineSurface,
        b: EngineSurface,
        feature_key: &str,
    ) -> Vec<&OverlapEntry> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        self.entries
            .iter()
            .filter(|e| {
                e.surface_a == lo
                    && e.surface_b == hi
                    && e
                        .scope_prefix
                        .as_ref()
                        .map_or(true, |p| feature_key.starts_with(p.as_str()))
            })
            .collect()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Semantic cover
// ---------------------------------------------------------------------------

/// A gap in the semantic cover — a feature not fully covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverGap {
    /// Feature key.
    pub feature_key: String,
    /// Surfaces where the feature is not supported.
    pub unsupported_surfaces: BTreeSet<EngineSurface>,
    /// Surfaces where the feature is unknown.
    pub unknown_surfaces: BTreeSet<EngineSurface>,
    /// Severity assessment.
    pub severity: GapSeverity,
}

/// How severe a cover gap is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GapSeverity {
    /// Critical — feature is commonly used and gap blocks important workloads.
    Critical,
    /// Moderate — feature matters for specific workload families.
    Moderate,
    /// Low — feature is rarely used or has workarounds.
    Low,
    /// Informational — gap is documented but not actionable yet.
    Informational,
}

impl fmt::Display for GapSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::Moderate => write!(f, "moderate"),
            Self::Low => write!(f, "low"),
            Self::Informational => write!(f, "informational"),
        }
    }
}

/// The full semantic cover for the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticCover {
    /// Schema version.
    pub schema_version: String,
    /// All features in the cover.
    pub features: Vec<CoverFeature>,
    /// Overlap restriction map.
    pub overlap_map: OverlapRestrictionMap,
    /// Security epoch at cover construction.
    pub epoch: SecurityEpoch,
    /// Content hash for the entire cover.
    pub content_hash: ContentHash,
}

impl SemanticCover {
    /// Build a cover from features and overlap map.
    pub fn new(
        features: Vec<CoverFeature>,
        overlap_map: OverlapRestrictionMap,
        epoch: SecurityEpoch,
    ) -> Self {
        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(COVER_SCHEMA_VERSION.as_bytes());
            for f in &features {
                buf.extend_from_slice(f.key.as_bytes());
                buf.extend_from_slice(&f.coverage_ratio_millionths().to_le_bytes());
            }
            buf.extend_from_slice(overlap_map.content_hash.as_bytes());
            ContentHash::compute(&buf)
        };
        Self {
            schema_version: COVER_SCHEMA_VERSION.to_string(),
            features,
            overlap_map,
            epoch,
            content_hash,
        }
    }

    /// Total feature count.
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }

    /// Number of fully covered features.
    pub fn fully_covered_count(&self) -> usize {
        self.features.iter().filter(|f| f.is_fully_covered()).count()
    }

    /// Number of features with gaps.
    pub fn gap_count(&self) -> usize {
        self.features.iter().filter(|f| f.has_gap()).count()
    }

    /// Overall coverage ratio (millionths).
    pub fn coverage_ratio_millionths(&self) -> i64 {
        if self.features.is_empty() {
            return 0;
        }
        let total_supported: i64 = self
            .features
            .iter()
            .map(|f| f.coverage_ratio_millionths())
            .sum();
        total_supported / self.features.len() as i64
    }

    /// Find all gaps, sorted by severity then feature key.
    pub fn find_gaps(&self) -> Vec<CoverGap> {
        let mut gaps: Vec<CoverGap> = self
            .features
            .iter()
            .filter(|f| f.has_gap())
            .map(|f| {
                let unsupported: BTreeSet<EngineSurface> = f
                    .relevant_surfaces
                    .iter()
                    .filter(|s| f.support_map.get(s) == Some(&SupportStatus::Unsupported))
                    .copied()
                    .collect();
                let unknown: BTreeSet<EngineSurface> = f
                    .relevant_surfaces
                    .iter()
                    .filter(|s| f.support_map.get(s) == Some(&SupportStatus::Unknown))
                    .copied()
                    .collect();
                let severity = if unsupported.len() >= 2 {
                    GapSeverity::Critical
                } else if !unsupported.is_empty() {
                    GapSeverity::Moderate
                } else if !unknown.is_empty() {
                    GapSeverity::Low
                } else {
                    GapSeverity::Informational
                };
                CoverGap {
                    feature_key: f.key.clone(),
                    unsupported_surfaces: unsupported,
                    unknown_surfaces: unknown,
                    severity,
                }
            })
            .collect();
        gaps.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.feature_key.cmp(&b.feature_key)));
        gaps
    }

    /// Per-surface coverage summary.
    pub fn surface_summary(&self) -> BTreeMap<EngineSurface, SurfaceSummary> {
        let mut summaries: BTreeMap<EngineSurface, SurfaceSummary> = BTreeMap::new();
        for surface in EngineSurface::all() {
            let relevant: Vec<&CoverFeature> = self
                .features
                .iter()
                .filter(|f| f.relevant_surfaces.contains(surface))
                .collect();
            let supported = relevant
                .iter()
                .filter(|f| f.support_map.get(surface) == Some(&SupportStatus::Supported))
                .count();
            let partial = relevant
                .iter()
                .filter(|f| f.support_map.get(surface) == Some(&SupportStatus::Partial))
                .count();
            let unsupported = relevant
                .iter()
                .filter(|f| f.support_map.get(surface) == Some(&SupportStatus::Unsupported))
                .count();
            let unknown = relevant
                .iter()
                .filter(|f| f.support_map.get(surface) == Some(&SupportStatus::Unknown))
                .count();
            summaries.insert(
                *surface,
                SurfaceSummary {
                    surface: *surface,
                    total_relevant: relevant.len(),
                    supported,
                    partial,
                    unsupported,
                    unknown,
                },
            );
        }
        summaries
    }

    /// Look up a feature by key.
    pub fn get_feature(&self, key: &str) -> Option<&CoverFeature> {
        self.features.iter().find(|f| f.key == key)
    }
}

/// Per-surface coverage summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceSummary {
    /// Which surface.
    pub surface: EngineSurface,
    /// Total features relevant to this surface.
    pub total_relevant: usize,
    /// Fully supported features.
    pub supported: usize,
    /// Partially supported features.
    pub partial: usize,
    /// Explicitly unsupported features.
    pub unsupported: usize,
    /// Unknown status features.
    pub unknown: usize,
}

// ---------------------------------------------------------------------------
// Overlap violation detection
// ---------------------------------------------------------------------------

/// An overlap violation: two surfaces claim the same feature in conflicting ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlapViolation {
    /// Feature key.
    pub feature_key: String,
    /// First surface.
    pub surface_a: EngineSurface,
    /// Second surface.
    pub surface_b: EngineSurface,
    /// What restriction was violated.
    pub restriction: OverlapRestriction,
    /// Description of the violation.
    pub description: String,
}

/// Check the cover for overlap violations.
pub fn detect_overlap_violations(cover: &SemanticCover) -> Vec<OverlapViolation> {
    let mut violations = Vec::new();

    for feature in &cover.features {
        // For each pair of relevant surfaces that both claim support:
        let supported_surfaces: Vec<EngineSurface> = feature
            .relevant_surfaces
            .iter()
            .filter(|s| {
                matches!(
                    feature.support_map.get(s),
                    Some(SupportStatus::Supported) | Some(SupportStatus::Partial)
                )
            })
            .copied()
            .collect();

        for i in 0..supported_surfaces.len() {
            for j in (i + 1)..supported_surfaces.len() {
                let a = supported_surfaces[i];
                let b = supported_surfaces[j];
                let restrictions = cover
                    .overlap_map
                    .restrictions_for_scope(a, b, &feature.key);
                for entry in restrictions {
                    if entry.restriction == OverlapRestriction::Exclusive {
                        violations.push(OverlapViolation {
                            feature_key: feature.key.clone(),
                            surface_a: a,
                            surface_b: b,
                            restriction: OverlapRestriction::Exclusive,
                            description: format!(
                                "Both {} and {} claim support for '{}' but overlap is exclusive",
                                a, b, feature.key
                            ),
                        });
                    }
                }
            }
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Default overlap map
// ---------------------------------------------------------------------------

/// Build the default overlap restriction map for FrankenEngine.
pub fn default_overlap_map() -> OverlapRestrictionMap {
    let entries = vec![
        OverlapEntry {
            surface_a: EngineSurface::Parser,
            surface_b: EngineSurface::Lowering,
            restriction: OverlapRestriction::DelegationRequired,
            scope_prefix: None,
            rationale: "Parser produces AST; lowering consumes it. Overlap requires explicit delegation chain.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Parser,
            surface_b: EngineSurface::TypeScript,
            restriction: OverlapRestriction::ReconciliationRequired,
            scope_prefix: Some("ts.".into()),
            rationale: "TS syntax parsed by parser must match TS normalization expectations.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Parser,
            surface_b: EngineSurface::React,
            restriction: OverlapRestriction::ReconciliationRequired,
            scope_prefix: Some("jsx.".into()),
            rationale: "JSX syntax in parser must reconcile with React runtime semantics.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Lowering,
            surface_b: EngineSurface::Runtime,
            restriction: OverlapRestriction::DelegationRequired,
            scope_prefix: None,
            rationale: "Lowering emits IR; runtime executes it. Semantic overlap needs delegation evidence.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Module,
            surface_b: EngineSurface::Runtime,
            restriction: OverlapRestriction::Allowed,
            scope_prefix: None,
            rationale: "Module system and runtime cooperate on import/export; independent evidence is acceptable.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Module,
            surface_b: EngineSurface::TypeScript,
            restriction: OverlapRestriction::ReconciliationRequired,
            scope_prefix: Some("ts.module.".into()),
            rationale: "TS module resolution must reconcile with runtime module semantics.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::React,
            surface_b: EngineSurface::Runtime,
            restriction: OverlapRestriction::ReconciliationRequired,
            scope_prefix: Some("react.".into()),
            rationale: "React component execution must reconcile with runtime value semantics.".into(),
        },
        OverlapEntry {
            surface_a: EngineSurface::Cli,
            surface_b: EngineSurface::Runtime,
            restriction: OverlapRestriction::Exclusive,
            scope_prefix: None,
            rationale: "CLI commands and runtime are separate domains; features must be owned by one.".into(),
        },
    ];
    OverlapRestrictionMap::new(entries)
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family for cover schema evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoverSpecimenFamily {
    /// Full coverage across surfaces.
    FullCoverage,
    /// Partial coverage with known gaps.
    PartialCoverage,
    /// Overlap violation detected.
    OverlapViolation,
    /// Unknown status on some surfaces.
    UnknownStatus,
    /// Not applicable surfaces.
    NotApplicable,
}

impl fmt::Display for CoverSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullCoverage => write!(f, "full_coverage"),
            Self::PartialCoverage => write!(f, "partial_coverage"),
            Self::OverlapViolation => write!(f, "overlap_violation"),
            Self::UnknownStatus => write!(f, "unknown_status"),
            Self::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

/// Evidence specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverSpecimen {
    pub id: String,
    pub family: CoverSpecimenFamily,
    pub description: String,
    pub feature: CoverFeature,
}

/// Build the evidence corpus.
pub fn build_evidence_corpus() -> Vec<CoverSpecimen> {
    let mut specimens = Vec::new();

    // 1. Full coverage — supported on all relevant surfaces.
    {
        let mut support = BTreeMap::new();
        support.insert(EngineSurface::Parser, SupportStatus::Supported);
        support.insert(EngineSurface::Lowering, SupportStatus::Supported);
        support.insert(EngineSurface::Runtime, SupportStatus::Supported);
        let mut relevant = BTreeSet::new();
        relevant.insert(EngineSurface::Parser);
        relevant.insert(EngineSurface::Lowering);
        relevant.insert(EngineSurface::Runtime);
        specimens.push(CoverSpecimen {
            id: "cover-full-01".into(),
            family: CoverSpecimenFamily::FullCoverage,
            description: "Arrow function fully supported across parser/lowering/runtime".into(),
            feature: CoverFeature {
                key: "es2015.arrowFunction".into(),
                description: "Arrow function expressions".into(),
                spec_area: "es2015".into(),
                relevant_surfaces: relevant,
                support_map: support,
                evidence_keys: {
                    let mut s = BTreeSet::new();
                    s.insert("parser.arrow_test".into());
                    s.insert("lowering.arrow_test".into());
                    s
                },
            },
        });
    }

    // 2. Partial coverage — runtime unsupported.
    {
        let mut support = BTreeMap::new();
        support.insert(EngineSurface::Parser, SupportStatus::Supported);
        support.insert(EngineSurface::Lowering, SupportStatus::Supported);
        support.insert(EngineSurface::Runtime, SupportStatus::Unsupported);
        let mut relevant = BTreeSet::new();
        relevant.insert(EngineSurface::Parser);
        relevant.insert(EngineSurface::Lowering);
        relevant.insert(EngineSurface::Runtime);
        specimens.push(CoverSpecimen {
            id: "cover-partial-01".into(),
            family: CoverSpecimenFamily::PartialCoverage,
            description: "WeakRef parsed and lowered but not executed".into(),
            feature: CoverFeature {
                key: "es2021.weakRef".into(),
                description: "WeakRef and FinalizationRegistry".into(),
                spec_area: "es2021".into(),
                relevant_surfaces: relevant,
                support_map: support,
                evidence_keys: BTreeSet::new(),
            },
        });
    }

    // 3. Unknown status.
    {
        let mut support = BTreeMap::new();
        support.insert(EngineSurface::Parser, SupportStatus::Supported);
        support.insert(EngineSurface::Lowering, SupportStatus::Unknown);
        support.insert(EngineSurface::Runtime, SupportStatus::Unknown);
        let mut relevant = BTreeSet::new();
        relevant.insert(EngineSurface::Parser);
        relevant.insert(EngineSurface::Lowering);
        relevant.insert(EngineSurface::Runtime);
        specimens.push(CoverSpecimen {
            id: "cover-unknown-01".into(),
            family: CoverSpecimenFamily::UnknownStatus,
            description: "Decorators parsed but lowering/runtime status unknown".into(),
            feature: CoverFeature {
                key: "stage3.decorators".into(),
                description: "TC39 Stage 3 decorators".into(),
                spec_area: "stage3".into(),
                relevant_surfaces: relevant,
                support_map: support,
                evidence_keys: BTreeSet::new(),
            },
        });
    }

    // 4. Not-applicable surfaces.
    {
        let mut support = BTreeMap::new();
        support.insert(EngineSurface::Cli, SupportStatus::Supported);
        let mut relevant = BTreeSet::new();
        relevant.insert(EngineSurface::Cli);
        specimens.push(CoverSpecimen {
            id: "cover-na-01".into(),
            family: CoverSpecimenFamily::NotApplicable,
            description: "CLI-only feature: frankenctl doctor".into(),
            feature: CoverFeature {
                key: "cli.doctor".into(),
                description: "frankenctl doctor diagnostic command".into(),
                spec_area: "cli".into(),
                relevant_surfaces: relevant,
                support_map: support,
                evidence_keys: BTreeSet::new(),
            },
        });
    }

    specimens
}

/// Run evidence corpus and return manifest hash.
pub fn run_evidence_corpus() -> (Vec<CoverSpecimen>, ContentHash) {
    let specimens = build_evidence_corpus();
    let mut buf = Vec::new();
    buf.extend_from_slice(COVER_SCHEMA_VERSION.as_bytes());
    for s in &specimens {
        buf.extend_from_slice(s.id.as_bytes());
        buf.extend_from_slice(s.feature.key.as_bytes());
    }
    let hash = ContentHash::compute(&buf);
    (specimens, hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_feature(
        key: &str,
        surfaces: &[(EngineSurface, SupportStatus)],
    ) -> CoverFeature {
        let relevant: BTreeSet<EngineSurface> = surfaces.iter().map(|(s, _)| *s).collect();
        let support_map: BTreeMap<EngineSurface, SupportStatus> =
            surfaces.iter().cloned().collect();
        CoverFeature {
            key: key.to_string(),
            description: format!("Test feature {key}"),
            spec_area: "test".into(),
            relevant_surfaces: relevant,
            support_map,
            evidence_keys: BTreeSet::new(),
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(COVER_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(COVER_SCHEMA_VERSION.contains(".v1"));
    }

    // --- EngineSurface ---

    #[test]
    fn surface_all_count() {
        assert_eq!(EngineSurface::all().len(), 7);
    }

    #[test]
    fn surface_display() {
        assert_eq!(EngineSurface::Parser.to_string(), "parser");
        assert_eq!(EngineSurface::Runtime.to_string(), "runtime");
        assert_eq!(EngineSurface::TypeScript.to_string(), "typescript");
        assert_eq!(EngineSurface::React.to_string(), "react");
        assert_eq!(EngineSurface::Cli.to_string(), "cli");
    }

    #[test]
    fn surface_ordering() {
        assert!(EngineSurface::Parser < EngineSurface::Lowering);
        assert!(EngineSurface::Lowering < EngineSurface::Runtime);
    }

    #[test]
    fn surface_serde() {
        let s = EngineSurface::Module;
        let json = serde_json::to_string(&s).unwrap();
        let back: EngineSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- SupportStatus ---

    #[test]
    fn support_status_display_all() {
        let statuses = [
            SupportStatus::Supported,
            SupportStatus::Partial,
            SupportStatus::Unsupported,
            SupportStatus::Unknown,
            SupportStatus::NotApplicable,
        ];
        for s in statuses {
            assert!(!s.to_string().is_empty());
        }
    }

    #[test]
    fn support_status_serde() {
        let s = SupportStatus::Partial;
        let json = serde_json::to_string(&s).unwrap();
        let back: SupportStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- CoverFeature ---

    #[test]
    fn feature_fully_covered() {
        let f = make_feature("test", &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Supported),
        ]);
        assert!(f.is_fully_covered());
        assert!(!f.has_gap());
        assert_eq!(f.supported_surface_count(), 2);
        assert_eq!(f.coverage_ratio_millionths(), 1_000_000);
    }

    #[test]
    fn feature_with_gap() {
        let f = make_feature("gap", &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Runtime, SupportStatus::Unsupported),
        ]);
        assert!(!f.is_fully_covered());
        assert!(f.has_gap());
        assert_eq!(f.supported_surface_count(), 1);
        assert_eq!(f.coverage_ratio_millionths(), 500_000);
    }

    #[test]
    fn feature_unknown_is_gap() {
        let f = make_feature("unk", &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Lowering, SupportStatus::Unknown),
        ]);
        assert!(f.has_gap());
    }

    #[test]
    fn feature_empty_relevant() {
        let f = CoverFeature {
            key: "empty".into(),
            description: "no surfaces".into(),
            spec_area: "test".into(),
            relevant_surfaces: BTreeSet::new(),
            support_map: BTreeMap::new(),
            evidence_keys: BTreeSet::new(),
        };
        assert!(f.is_fully_covered()); // vacuously true
        assert_eq!(f.coverage_ratio_millionths(), 0);
    }

    #[test]
    fn feature_serde_roundtrip() {
        let f = make_feature("serde_test", &[
            (EngineSurface::Parser, SupportStatus::Supported),
            (EngineSurface::Module, SupportStatus::Partial),
        ]);
        let json = serde_json::to_string(&f).unwrap();
        let back: CoverFeature = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // --- OverlapRestriction ---

    #[test]
    fn overlap_restriction_display() {
        assert_eq!(OverlapRestriction::Allowed.to_string(), "allowed");
        assert_eq!(OverlapRestriction::DelegationRequired.to_string(), "delegation_required");
        assert_eq!(OverlapRestriction::Exclusive.to_string(), "exclusive");
        assert_eq!(OverlapRestriction::ReconciliationRequired.to_string(), "reconciliation_required");
    }

    #[test]
    fn overlap_restriction_serde() {
        let r = OverlapRestriction::Exclusive;
        let json = serde_json::to_string(&r).unwrap();
        let back: OverlapRestriction = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- OverlapRestrictionMap ---

    #[test]
    fn default_overlap_map_not_empty() {
        let map = default_overlap_map();
        assert!(!map.is_empty());
        assert!(map.len() >= 5);
    }

    #[test]
    fn overlap_map_lookup() {
        let map = default_overlap_map();
        let r = map.restriction_for(EngineSurface::Cli, EngineSurface::Runtime);
        assert_eq!(r, Some(OverlapRestriction::Exclusive));
    }

    #[test]
    fn overlap_map_lookup_reverse_order() {
        let map = default_overlap_map();
        let r = map.restriction_for(EngineSurface::Runtime, EngineSurface::Cli);
        assert_eq!(r, Some(OverlapRestriction::Exclusive));
    }

    #[test]
    fn overlap_map_scope_filter() {
        let map = default_overlap_map();
        let entries = map.restrictions_for_scope(
            EngineSurface::Parser,
            EngineSurface::TypeScript,
            "ts.enum",
        );
        assert!(!entries.is_empty());
        assert_eq!(entries[0].restriction, OverlapRestriction::ReconciliationRequired);
    }

    #[test]
    fn overlap_map_content_hash_deterministic() {
        let m1 = default_overlap_map();
        let m2 = default_overlap_map();
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    // --- GapSeverity ---

    #[test]
    fn gap_severity_display() {
        assert_eq!(GapSeverity::Critical.to_string(), "critical");
        assert_eq!(GapSeverity::Moderate.to_string(), "moderate");
        assert_eq!(GapSeverity::Low.to_string(), "low");
        assert_eq!(GapSeverity::Informational.to_string(), "informational");
    }

    #[test]
    fn gap_severity_ordering() {
        assert!(GapSeverity::Critical < GapSeverity::Moderate);
        assert!(GapSeverity::Moderate < GapSeverity::Low);
    }

    // --- SemanticCover ---

    #[test]
    fn cover_basic() {
        let features = vec![
            make_feature("f1", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ]),
            make_feature("f2", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        assert_eq!(cover.feature_count(), 2);
        assert_eq!(cover.fully_covered_count(), 1);
        assert_eq!(cover.gap_count(), 1);
    }

    #[test]
    fn cover_find_gaps() {
        let features = vec![
            make_feature("ok", &[
                (EngineSurface::Parser, SupportStatus::Supported),
            ]),
            make_feature("bad", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
                (EngineSurface::Lowering, SupportStatus::Unsupported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        let gaps = cover.find_gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].feature_key, "bad");
        assert_eq!(gaps[0].severity, GapSeverity::Critical); // 2 unsupported
    }

    #[test]
    fn cover_surface_summary() {
        let features = vec![
            make_feature("f1", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        let summary = cover.surface_summary();
        let parser_sum = summary.get(&EngineSurface::Parser).unwrap();
        assert_eq!(parser_sum.total_relevant, 1);
        assert_eq!(parser_sum.supported, 1);
    }

    #[test]
    fn cover_get_feature() {
        let features = vec![
            make_feature("findme", &[(EngineSurface::Parser, SupportStatus::Supported)]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        assert!(cover.get_feature("findme").is_some());
        assert!(cover.get_feature("nope").is_none());
    }

    #[test]
    fn cover_content_hash_deterministic() {
        let features = vec![
            make_feature("f1", &[(EngineSurface::Parser, SupportStatus::Supported)]),
        ];
        let map = default_overlap_map();
        let c1 = SemanticCover::new(features.clone(), map.clone(), test_epoch());
        let c2 = SemanticCover::new(features, map, test_epoch());
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn cover_coverage_ratio() {
        let features = vec![
            make_feature("full", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ]),
            make_feature("half", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Unsupported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        // (1_000_000 + 500_000) / 2 = 750_000
        assert_eq!(cover.coverage_ratio_millionths(), 750_000);
    }

    // --- Overlap violation detection ---

    #[test]
    fn detect_no_violations() {
        let features = vec![
            make_feature("f1", &[
                (EngineSurface::Parser, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        let violations = detect_overlap_violations(&cover);
        // Parser+Runtime has DelegationRequired (via Lowering), not exclusive
        // But direct Parser-Runtime isn't in the map, so no violation.
        assert!(violations.is_empty());
    }

    #[test]
    fn detect_exclusive_violation() {
        // CLI and Runtime both claim support → exclusive violation
        let features = vec![
            make_feature("shared", &[
                (EngineSurface::Cli, SupportStatus::Supported),
                (EngineSurface::Runtime, SupportStatus::Supported),
            ]),
        ];
        let map = default_overlap_map();
        let cover = SemanticCover::new(features, map, test_epoch());
        let violations = detect_overlap_violations(&cover);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].restriction, OverlapRestriction::Exclusive);
    }

    // --- Evidence corpus ---

    #[test]
    fn evidence_corpus_builds() {
        let (specimens, hash) = run_evidence_corpus();
        assert_eq!(specimens.len(), 4);
        assert!(!hash.to_hex().is_empty());
    }

    #[test]
    fn evidence_corpus_deterministic() {
        let (_, h1) = run_evidence_corpus();
        let (_, h2) = run_evidence_corpus();
        assert_eq!(h1, h2);
    }

    #[test]
    fn evidence_corpus_ids_unique() {
        let (specimens, _) = run_evidence_corpus();
        let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids.len(), specimens.len());
    }

    #[test]
    fn evidence_corpus_serde() {
        let (specimens, _) = run_evidence_corpus();
        for s in &specimens {
            let json = serde_json::to_string(s).unwrap();
            let back: CoverSpecimen = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn specimen_family_display() {
        assert_eq!(CoverSpecimenFamily::FullCoverage.to_string(), "full_coverage");
        assert_eq!(CoverSpecimenFamily::PartialCoverage.to_string(), "partial_coverage");
        assert_eq!(CoverSpecimenFamily::OverlapViolation.to_string(), "overlap_violation");
    }
}
