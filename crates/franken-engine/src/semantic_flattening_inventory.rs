//! Semantic Flattening Inventory — bd-3nr.1.1.3 [10.13X.A3]
//!
//! Inventories every boundary where Budget, Outcome, capability, severity,
//! or user/operator diagnostics are preserved, collapsed, or translated.
//! Each occurrence is classified as intentional, must-fix, acceptable, or
//! false positive.
//!
//! The inventory provides a systematic audit surface so that semantic
//! lossy boundaries can be tracked, remediated, and verified across
//! security epochs.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the flattening inventory format.
pub const FLATTENING_SCHEMA_VERSION: &str = "franken-engine.semantic-flattening-inventory.v1";

/// Bead identifier for this inventory work item.
pub const FLATTENING_BEAD_ID: &str = "bd-3nr.1.1.3";

// ---------------------------------------------------------------------------
// SemanticDomain
// ---------------------------------------------------------------------------

/// The semantic domain being preserved, collapsed, or translated at a
/// boundary crossing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SemanticDomain {
    /// Execution budget (gas, time, memory).
    Budget,
    /// Execution outcome (success, failure, partial).
    Outcome,
    /// Capability token or authority scope.
    Capability,
    /// Error or diagnostic severity level.
    Severity,
    /// User- or operator-facing diagnostic messages.
    Diagnostics,
    /// Policy identifier crossing a boundary.
    PolicyId,
    /// Trace identifier crossing a boundary.
    TraceId,
    /// Decision identifier crossing a boundary.
    DecisionId,
    /// Evidence link reference crossing a boundary.
    EvidenceLink,
    /// Schema version crossing a boundary.
    SchemaVersion,
}

impl fmt::Display for SemanticDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Budget => "Budget",
            Self::Outcome => "Outcome",
            Self::Capability => "Capability",
            Self::Severity => "Severity",
            Self::Diagnostics => "Diagnostics",
            Self::PolicyId => "PolicyId",
            Self::TraceId => "TraceId",
            Self::DecisionId => "DecisionId",
            Self::EvidenceLink => "EvidenceLink",
            Self::SchemaVersion => "SchemaVersion",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// TranslationKind
// ---------------------------------------------------------------------------

/// How the semantic value is transformed at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TranslationKind {
    /// Exact pass-through — no transformation.
    Preserved,
    /// Capability reduced or severity collapsed (lossy, narrowing).
    Narrowed,
    /// Capability added — suspicious, may indicate a bug.
    Widened,
    /// Multi-valued input collapsed to a single value (lossy).
    Collapsed,
    /// Semantically equivalent but different representation.
    Translated,
    /// Value lost entirely at the boundary.
    Dropped,
}

impl fmt::Display for TranslationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Preserved => "Preserved",
            Self::Narrowed => "Narrowed",
            Self::Widened => "Widened",
            Self::Collapsed => "Collapsed",
            Self::Translated => "Translated",
            Self::Dropped => "Dropped",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// FlatteningClassification
// ---------------------------------------------------------------------------

/// Classification of a flattening occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlatteningClassification {
    /// By design — documented policy decision.
    Intentional,
    /// Semantic loss that causes incorrect behavior.
    MustFix,
    /// Known limitation, acceptable for GA.
    AcceptableEdge,
    /// Not actually a flattening upon closer inspection.
    FalsePositive,
}

impl fmt::Display for FlatteningClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Intentional => "Intentional",
            Self::MustFix => "MustFix",
            Self::AcceptableEdge => "AcceptableEdge",
            Self::FalsePositive => "FalsePositive",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// FlatteningSeverity
// ---------------------------------------------------------------------------

/// Severity level of a flattening occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlatteningSeverity {
    /// Blocks release — data loss or security violation.
    Critical,
    /// Must fix before GA — significant semantic loss.
    High,
    /// Should fix — noticeable but non-blocking.
    Medium,
    /// Minor — cosmetic or low-impact.
    Low,
    /// Informational — noted for future reference.
    Info,
}

impl fmt::Display for FlatteningSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Info => "Info",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// BoundaryPoint
// ---------------------------------------------------------------------------

/// Identifies a specific API boundary where semantic translation occurs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BoundaryPoint {
    /// The module emitting the semantic value.
    pub source_module: String,
    /// The module receiving the semantic value.
    pub target_module: String,
    /// The API surface (function, trait method, message type) at the boundary.
    pub api_surface: String,
    /// Optional source line hint for the boundary crossing.
    pub line_hint: Option<u32>,
}

impl fmt::Display for BoundaryPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line_hint {
            Some(line) => write!(
                f,
                "{} -> {} via {} (line {})",
                self.source_module, self.target_module, self.api_surface, line
            ),
            None => write!(
                f,
                "{} -> {} via {}",
                self.source_module, self.target_module, self.api_surface
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// FlatteningOccurrence
// ---------------------------------------------------------------------------

/// A single inventoried flattening occurrence at a boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlatteningOccurrence {
    /// Unique identifier for this occurrence.
    pub id: String,
    /// The semantic domain affected.
    pub domain: SemanticDomain,
    /// The boundary where the translation occurs.
    pub boundary: BoundaryPoint,
    /// How the value is transformed.
    pub translation_kind: TranslationKind,
    /// Classification of the flattening.
    pub classification: FlatteningClassification,
    /// Severity of the flattening.
    pub severity: FlatteningSeverity,
    /// Human-readable description of what happens at this boundary.
    pub description: String,
    /// Recommended remediation action.
    pub remediation: String,
    /// Bead identifier for the remediation work item.
    pub remediation_bead: String,
    /// Content hash of this occurrence for integrity verification.
    pub content_hash: ContentHash,
}

impl FlatteningOccurrence {
    /// Compute a content hash for this occurrence based on its identity
    /// fields (id, domain, boundary, translation kind, classification).
    pub fn compute_content_hash(
        id: &str,
        domain: SemanticDomain,
        boundary: &BoundaryPoint,
        translation_kind: TranslationKind,
        classification: FlatteningClassification,
    ) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(format!("{domain}").as_bytes());
        buf.extend_from_slice(boundary.source_module.as_bytes());
        buf.extend_from_slice(boundary.target_module.as_bytes());
        buf.extend_from_slice(boundary.api_surface.as_bytes());
        if let Some(line) = boundary.line_hint {
            buf.extend_from_slice(&line.to_le_bytes());
        }
        buf.extend_from_slice(format!("{translation_kind}").as_bytes());
        buf.extend_from_slice(format!("{classification}").as_bytes());
        ContentHash::compute(&buf)
    }

    /// Create a new occurrence, computing the content hash automatically.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        domain: SemanticDomain,
        boundary: BoundaryPoint,
        translation_kind: TranslationKind,
        classification: FlatteningClassification,
        severity: FlatteningSeverity,
        description: String,
        remediation: String,
        remediation_bead: String,
    ) -> Self {
        let content_hash =
            Self::compute_content_hash(&id, domain, &boundary, translation_kind, classification);
        Self {
            id,
            domain,
            boundary,
            translation_kind,
            classification,
            severity,
            description,
            remediation,
            remediation_bead,
            content_hash,
        }
    }
}

impl fmt::Display for FlatteningOccurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} ({}) at {} — {}",
            self.id,
            self.severity,
            self.classification,
            self.translation_kind,
            self.boundary,
            self.description,
        )
    }
}

// ---------------------------------------------------------------------------
// FlatteningSummary
// ---------------------------------------------------------------------------

/// Aggregate summary of a flattening inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatteningSummary {
    /// Total number of occurrences.
    pub total: usize,
    /// Number classified as must-fix.
    pub must_fix: usize,
    /// Number classified as intentional.
    pub intentional: usize,
    /// Number classified as acceptable edge.
    pub acceptable: usize,
    /// Number classified as false positive.
    pub false_positive: usize,
    /// Count by semantic domain (key is Display string).
    pub by_domain: BTreeMap<String, usize>,
    /// Count by severity (key is Display string).
    pub by_severity: BTreeMap<String, usize>,
}

impl fmt::Display for FlatteningSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlatteningSummary(total={}, must_fix={}, intentional={}, acceptable={}, false_positive={})",
            self.total, self.must_fix, self.intentional, self.acceptable, self.false_positive,
        )
    }
}

// ---------------------------------------------------------------------------
// FlatteningInventory
// ---------------------------------------------------------------------------

/// Top-level inventory of all semantic flattening occurrences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatteningInventory {
    /// All inventoried flattening occurrences.
    pub occurrences: Vec<FlatteningOccurrence>,
    /// Schema version of this inventory.
    pub schema_version: String,
    /// The security epoch at which this inventory was assessed.
    pub assessed_epoch: SecurityEpoch,
}

impl FlatteningInventory {
    /// Create a new empty inventory for the given security epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            occurrences: Vec::new(),
            schema_version: FLATTENING_SCHEMA_VERSION.to_string(),
            assessed_epoch: epoch,
        }
    }

    /// Add an occurrence to the inventory.
    pub fn add(&mut self, occ: FlatteningOccurrence) {
        self.occurrences.push(occ);
    }

    /// Return all occurrences classified as must-fix.
    pub fn must_fix_items(&self) -> Vec<&FlatteningOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.classification == FlatteningClassification::MustFix)
            .collect()
    }

    /// Return all occurrences in the given semantic domain.
    pub fn by_domain(&self, domain: SemanticDomain) -> Vec<&FlatteningOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.domain == domain)
            .collect()
    }

    /// Return all occurrences with the given severity.
    pub fn by_severity(&self, severity: FlatteningSeverity) -> Vec<&FlatteningOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.severity == severity)
            .collect()
    }

    /// Produce an aggregate summary of the inventory.
    pub fn summary(&self) -> FlatteningSummary {
        let mut must_fix = 0usize;
        let mut intentional = 0usize;
        let mut acceptable = 0usize;
        let mut false_positive = 0usize;
        let mut by_domain: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();

        for occ in &self.occurrences {
            match occ.classification {
                FlatteningClassification::MustFix => must_fix += 1,
                FlatteningClassification::Intentional => intentional += 1,
                FlatteningClassification::AcceptableEdge => acceptable += 1,
                FlatteningClassification::FalsePositive => false_positive += 1,
            }
            *by_domain.entry(format!("{}", occ.domain)).or_insert(0) += 1;
            *by_severity.entry(format!("{}", occ.severity)).or_insert(0) += 1;
        }

        FlatteningSummary {
            total: self.occurrences.len(),
            must_fix,
            intentional,
            acceptable,
            false_positive,
            by_domain,
            by_severity,
        }
    }

    /// Compute a content hash over the entire inventory.
    ///
    /// The hash covers schema version, epoch, and all occurrence hashes.
    /// Occurrences are sorted by id for insertion-order independence.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.schema_version.as_bytes());
        buf.extend_from_slice(&self.assessed_epoch.as_u64().to_le_bytes());
        let mut sorted: Vec<_> = self.occurrences.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for occ in &sorted {
            buf.extend_from_slice(occ.id.as_bytes());
            buf.extend_from_slice(occ.content_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for FlatteningInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FlatteningInventory(schema={}, epoch={}, count={})",
            self.schema_version,
            self.assessed_epoch,
            self.occurrences.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helper --

    fn sample_boundary() -> BoundaryPoint {
        BoundaryPoint {
            source_module: "policy_controller".to_string(),
            target_module: "execution_orchestrator".to_string(),
            api_surface: "apply_policy".to_string(),
            line_hint: Some(42),
        }
    }

    fn sample_occurrence(id: &str) -> FlatteningOccurrence {
        FlatteningOccurrence::new(
            id.to_string(),
            SemanticDomain::Budget,
            sample_boundary(),
            TranslationKind::Collapsed,
            FlatteningClassification::MustFix,
            FlatteningSeverity::High,
            "Budget collapsed from multi-tier to single flat value".to_string(),
            "Preserve tier breakdown across boundary".to_string(),
            "bd-fix-001".to_string(),
        )
    }

    // -- enum Display tests --

    #[test]
    fn test_semantic_domain_display() {
        assert_eq!(format!("{}", SemanticDomain::Budget), "Budget");
        assert_eq!(format!("{}", SemanticDomain::Outcome), "Outcome");
        assert_eq!(format!("{}", SemanticDomain::Capability), "Capability");
        assert_eq!(format!("{}", SemanticDomain::Severity), "Severity");
        assert_eq!(format!("{}", SemanticDomain::Diagnostics), "Diagnostics");
        assert_eq!(format!("{}", SemanticDomain::PolicyId), "PolicyId");
        assert_eq!(format!("{}", SemanticDomain::TraceId), "TraceId");
        assert_eq!(format!("{}", SemanticDomain::DecisionId), "DecisionId");
        assert_eq!(format!("{}", SemanticDomain::EvidenceLink), "EvidenceLink");
        assert_eq!(
            format!("{}", SemanticDomain::SchemaVersion),
            "SchemaVersion"
        );
    }

    #[test]
    fn test_translation_kind_display() {
        assert_eq!(format!("{}", TranslationKind::Preserved), "Preserved");
        assert_eq!(format!("{}", TranslationKind::Narrowed), "Narrowed");
        assert_eq!(format!("{}", TranslationKind::Widened), "Widened");
        assert_eq!(format!("{}", TranslationKind::Collapsed), "Collapsed");
        assert_eq!(format!("{}", TranslationKind::Translated), "Translated");
        assert_eq!(format!("{}", TranslationKind::Dropped), "Dropped");
    }

    #[test]
    fn test_flattening_classification_display() {
        assert_eq!(
            format!("{}", FlatteningClassification::Intentional),
            "Intentional"
        );
        assert_eq!(format!("{}", FlatteningClassification::MustFix), "MustFix");
        assert_eq!(
            format!("{}", FlatteningClassification::AcceptableEdge),
            "AcceptableEdge"
        );
        assert_eq!(
            format!("{}", FlatteningClassification::FalsePositive),
            "FalsePositive"
        );
    }

    #[test]
    fn test_flattening_severity_display() {
        assert_eq!(format!("{}", FlatteningSeverity::Critical), "Critical");
        assert_eq!(format!("{}", FlatteningSeverity::High), "High");
        assert_eq!(format!("{}", FlatteningSeverity::Medium), "Medium");
        assert_eq!(format!("{}", FlatteningSeverity::Low), "Low");
        assert_eq!(format!("{}", FlatteningSeverity::Info), "Info");
    }

    // -- serde round-trip tests --

    #[test]
    fn test_semantic_domain_serde_roundtrip() {
        for domain in [
            SemanticDomain::Budget,
            SemanticDomain::Outcome,
            SemanticDomain::Capability,
            SemanticDomain::Severity,
            SemanticDomain::Diagnostics,
            SemanticDomain::PolicyId,
            SemanticDomain::TraceId,
            SemanticDomain::DecisionId,
            SemanticDomain::EvidenceLink,
            SemanticDomain::SchemaVersion,
        ] {
            let json = serde_json::to_string(&domain).unwrap();
            let back: SemanticDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(domain, back);
        }
    }

    #[test]
    fn test_translation_kind_serde_roundtrip() {
        for kind in [
            TranslationKind::Preserved,
            TranslationKind::Narrowed,
            TranslationKind::Widened,
            TranslationKind::Collapsed,
            TranslationKind::Translated,
            TranslationKind::Dropped,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: TranslationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn test_flattening_classification_serde_roundtrip() {
        for cls in [
            FlatteningClassification::Intentional,
            FlatteningClassification::MustFix,
            FlatteningClassification::AcceptableEdge,
            FlatteningClassification::FalsePositive,
        ] {
            let json = serde_json::to_string(&cls).unwrap();
            let back: FlatteningClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(cls, back);
        }
    }

    #[test]
    fn test_flattening_severity_serde_roundtrip() {
        for sev in [
            FlatteningSeverity::Critical,
            FlatteningSeverity::High,
            FlatteningSeverity::Medium,
            FlatteningSeverity::Low,
            FlatteningSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: FlatteningSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    // -- BoundaryPoint tests --

    #[test]
    fn test_boundary_point_display_with_line() {
        let bp = sample_boundary();
        let s = format!("{bp}");
        assert!(s.contains("policy_controller"));
        assert!(s.contains("execution_orchestrator"));
        assert!(s.contains("apply_policy"));
        assert!(s.contains("line 42"));
    }

    #[test]
    fn test_boundary_point_display_without_line() {
        let bp = BoundaryPoint {
            source_module: "src".to_string(),
            target_module: "dst".to_string(),
            api_surface: "call".to_string(),
            line_hint: None,
        };
        let s = format!("{bp}");
        assert!(s.contains("src -> dst via call"));
        assert!(!s.contains("line"));
    }

    #[test]
    fn test_boundary_point_serde_roundtrip() {
        let bp = sample_boundary();
        let json = serde_json::to_string(&bp).unwrap();
        let back: BoundaryPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    // -- FlatteningOccurrence tests --

    #[test]
    fn test_occurrence_construction_and_hash() {
        let occ = sample_occurrence("FLAT-001");
        assert_eq!(occ.id, "FLAT-001");
        assert_eq!(occ.domain, SemanticDomain::Budget);
        assert_eq!(occ.translation_kind, TranslationKind::Collapsed);
        assert_eq!(occ.classification, FlatteningClassification::MustFix);
        assert_eq!(occ.severity, FlatteningSeverity::High);
        // Content hash should be non-zero
        assert_ne!(occ.content_hash, ContentHash::default());
    }

    #[test]
    fn test_occurrence_hash_determinism() {
        let occ1 = sample_occurrence("FLAT-DET");
        let occ2 = sample_occurrence("FLAT-DET");
        assert_eq!(occ1.content_hash, occ2.content_hash);
    }

    #[test]
    fn test_occurrence_hash_differs_for_different_ids() {
        let occ1 = sample_occurrence("FLAT-A");
        let occ2 = sample_occurrence("FLAT-B");
        assert_ne!(occ1.content_hash, occ2.content_hash);
    }

    #[test]
    fn test_occurrence_display() {
        let occ = sample_occurrence("FLAT-DISP");
        let s = format!("{occ}");
        assert!(s.contains("FLAT-DISP"));
        assert!(s.contains("High"));
        assert!(s.contains("MustFix"));
        assert!(s.contains("Collapsed"));
    }

    #[test]
    fn test_occurrence_serde_roundtrip() {
        let occ = sample_occurrence("FLAT-SERDE");
        let json = serde_json::to_string(&occ).unwrap();
        let back: FlatteningOccurrence = serde_json::from_str(&json).unwrap();
        assert_eq!(occ, back);
    }

    // -- FlatteningInventory tests --

    #[test]
    fn test_inventory_new() {
        let inv = FlatteningInventory::new(SecurityEpoch::from_raw(5));
        assert_eq!(inv.occurrences.len(), 0);
        assert_eq!(inv.schema_version, FLATTENING_SCHEMA_VERSION);
        assert_eq!(inv.assessed_epoch, SecurityEpoch::from_raw(5));
    }

    #[test]
    fn test_inventory_add() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("A"));
        inv.add(sample_occurrence("B"));
        assert_eq!(inv.occurrences.len(), 2);
    }

    #[test]
    fn test_must_fix_items() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("MF-1")); // MustFix
        inv.add(FlatteningOccurrence::new(
            "INT-1".to_string(),
            SemanticDomain::Capability,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
            "Intentional pass-through".to_string(),
            "None needed".to_string(),
            String::new(),
        ));
        let must_fix = inv.must_fix_items();
        assert_eq!(must_fix.len(), 1);
        assert_eq!(must_fix[0].id, "MF-1");
    }

    #[test]
    fn test_by_domain() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("BD-1")); // Budget
        inv.add(FlatteningOccurrence::new(
            "CAP-1".to_string(),
            SemanticDomain::Capability,
            sample_boundary(),
            TranslationKind::Narrowed,
            FlatteningClassification::AcceptableEdge,
            FlatteningSeverity::Medium,
            "Capability narrowed".to_string(),
            "Widen capability".to_string(),
            String::new(),
        ));
        inv.add(sample_occurrence("BD-2")); // Budget
        let budget_items = inv.by_domain(SemanticDomain::Budget);
        assert_eq!(budget_items.len(), 2);
        let cap_items = inv.by_domain(SemanticDomain::Capability);
        assert_eq!(cap_items.len(), 1);
    }

    #[test]
    fn test_by_severity() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("S-1")); // High
        inv.add(FlatteningOccurrence::new(
            "S-2".to_string(),
            SemanticDomain::Outcome,
            sample_boundary(),
            TranslationKind::Dropped,
            FlatteningClassification::MustFix,
            FlatteningSeverity::Critical,
            "Outcome dropped".to_string(),
            "Preserve outcome".to_string(),
            "bd-fix-002".to_string(),
        ));
        let high = inv.by_severity(FlatteningSeverity::High);
        assert_eq!(high.len(), 1);
        let critical = inv.by_severity(FlatteningSeverity::Critical);
        assert_eq!(critical.len(), 1);
        let low = inv.by_severity(FlatteningSeverity::Low);
        assert_eq!(low.len(), 0);
    }

    #[test]
    fn test_summary_empty() {
        let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        let s = inv.summary();
        assert_eq!(s.total, 0);
        assert_eq!(s.must_fix, 0);
        assert_eq!(s.intentional, 0);
        assert_eq!(s.acceptable, 0);
        assert_eq!(s.false_positive, 0);
        assert!(s.by_domain.is_empty());
        assert!(s.by_severity.is_empty());
    }

    #[test]
    fn test_summary_populated() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(3));

        // MustFix, Budget, High
        inv.add(sample_occurrence("SUM-1"));

        // Intentional, Capability, Info
        inv.add(FlatteningOccurrence::new(
            "SUM-2".to_string(),
            SemanticDomain::Capability,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
            "desc".to_string(),
            "none".to_string(),
            String::new(),
        ));

        // AcceptableEdge, Capability, Medium
        inv.add(FlatteningOccurrence::new(
            "SUM-3".to_string(),
            SemanticDomain::Capability,
            sample_boundary(),
            TranslationKind::Narrowed,
            FlatteningClassification::AcceptableEdge,
            FlatteningSeverity::Medium,
            "desc".to_string(),
            "none".to_string(),
            String::new(),
        ));

        // FalsePositive, TraceId, Low
        inv.add(FlatteningOccurrence::new(
            "SUM-4".to_string(),
            SemanticDomain::TraceId,
            sample_boundary(),
            TranslationKind::Translated,
            FlatteningClassification::FalsePositive,
            FlatteningSeverity::Low,
            "desc".to_string(),
            "none".to_string(),
            String::new(),
        ));

        let s = inv.summary();
        assert_eq!(s.total, 4);
        assert_eq!(s.must_fix, 1);
        assert_eq!(s.intentional, 1);
        assert_eq!(s.acceptable, 1);
        assert_eq!(s.false_positive, 1);
        assert_eq!(s.by_domain.get("Budget"), Some(&1));
        assert_eq!(s.by_domain.get("Capability"), Some(&2));
        assert_eq!(s.by_domain.get("TraceId"), Some(&1));
        assert_eq!(s.by_severity.get("High"), Some(&1));
        assert_eq!(s.by_severity.get("Info"), Some(&1));
        assert_eq!(s.by_severity.get("Medium"), Some(&1));
        assert_eq!(s.by_severity.get("Low"), Some(&1));
    }

    #[test]
    fn test_inventory_content_hash_determinism() {
        let mut inv1 = FlatteningInventory::new(SecurityEpoch::from_raw(7));
        inv1.add(sample_occurrence("DET-1"));
        inv1.add(sample_occurrence("DET-2"));

        let mut inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(7));
        inv2.add(sample_occurrence("DET-1"));
        inv2.add(sample_occurrence("DET-2"));

        assert_eq!(inv1.content_hash(), inv2.content_hash());
    }

    #[test]
    fn test_inventory_content_hash_differs_for_different_epochs() {
        let mut inv1 = FlatteningInventory::new(SecurityEpoch::from_raw(1));
        inv1.add(sample_occurrence("EP-1"));

        let mut inv2 = FlatteningInventory::new(SecurityEpoch::from_raw(2));
        inv2.add(sample_occurrence("EP-1"));

        assert_ne!(inv1.content_hash(), inv2.content_hash());
    }

    #[test]
    fn test_inventory_content_hash_differs_for_different_items() {
        let mut inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv1.add(sample_occurrence("X"));

        let mut inv2 = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv2.add(sample_occurrence("Y"));

        assert_ne!(inv1.content_hash(), inv2.content_hash());
    }

    #[test]
    fn test_inventory_display() {
        let inv = FlatteningInventory::new(SecurityEpoch::from_raw(10));
        let s = format!("{inv}");
        assert!(s.contains("FlatteningInventory"));
        assert!(s.contains("count=0"));
    }

    #[test]
    fn test_summary_display() {
        let s = FlatteningSummary {
            total: 10,
            must_fix: 2,
            intentional: 5,
            acceptable: 2,
            false_positive: 1,
            by_domain: BTreeMap::new(),
            by_severity: BTreeMap::new(),
        };
        let txt = format!("{s}");
        assert!(txt.contains("total=10"));
        assert!(txt.contains("must_fix=2"));
    }

    #[test]
    fn test_summary_serde_roundtrip() {
        let s = FlatteningSummary {
            total: 3,
            must_fix: 1,
            intentional: 1,
            acceptable: 1,
            false_positive: 0,
            by_domain: BTreeMap::from([("Budget".to_string(), 2), ("Capability".to_string(), 1)]),
            by_severity: BTreeMap::from([("High".to_string(), 1), ("Low".to_string(), 2)]),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: FlatteningSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn test_inventory_serde_roundtrip() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(99));
        inv.add(sample_occurrence("RND-1"));
        let json = serde_json::to_string(&inv).unwrap();
        let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn test_constants() {
        assert_eq!(
            FLATTENING_SCHEMA_VERSION,
            "franken-engine.semantic-flattening-inventory.v1"
        );
        assert_eq!(FLATTENING_BEAD_ID, "bd-3nr.1.1.3");
    }

    #[test]
    fn test_must_fix_empty_inventory() {
        let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        assert!(inv.must_fix_items().is_empty());
    }

    #[test]
    fn test_by_domain_no_match() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("NM-1")); // Budget
        let result = inv.by_domain(SemanticDomain::Diagnostics);
        assert!(result.is_empty());
    }

    #[test]
    fn test_by_severity_no_match() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv.add(sample_occurrence("NMS-1")); // High
        let result = inv.by_severity(FlatteningSeverity::Info);
        assert!(result.is_empty());
    }

    #[test]
    fn test_occurrence_with_all_translation_kinds() {
        let kinds = [
            TranslationKind::Preserved,
            TranslationKind::Narrowed,
            TranslationKind::Widened,
            TranslationKind::Collapsed,
            TranslationKind::Translated,
            TranslationKind::Dropped,
        ];
        for (i, kind) in kinds.iter().enumerate() {
            let occ = FlatteningOccurrence::new(
                format!("TK-{i}"),
                SemanticDomain::Budget,
                sample_boundary(),
                *kind,
                FlatteningClassification::Intentional,
                FlatteningSeverity::Info,
                "test".to_string(),
                "none".to_string(),
                String::new(),
            );
            assert_eq!(occ.translation_kind, *kind);
            assert_ne!(occ.content_hash, ContentHash::default());
        }
    }

    #[test]
    fn test_empty_inventory_content_hash_is_not_default() {
        let inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        // Even empty inventories have a hash derived from schema version and epoch
        let hash = inv.content_hash();
        assert_ne!(hash, ContentHash::default());
    }

    // -- Additional tests: enum ordering --

    #[test]
    fn test_semantic_domain_ord_is_variant_order() {
        // Ord should follow declaration order: Budget < Outcome < ... < SchemaVersion
        assert!(SemanticDomain::Budget < SemanticDomain::Outcome);
        assert!(SemanticDomain::Outcome < SemanticDomain::Capability);
        assert!(SemanticDomain::Capability < SemanticDomain::Severity);
        assert!(SemanticDomain::Severity < SemanticDomain::Diagnostics);
        assert!(SemanticDomain::Diagnostics < SemanticDomain::PolicyId);
        assert!(SemanticDomain::PolicyId < SemanticDomain::TraceId);
        assert!(SemanticDomain::TraceId < SemanticDomain::DecisionId);
        assert!(SemanticDomain::DecisionId < SemanticDomain::EvidenceLink);
        assert!(SemanticDomain::EvidenceLink < SemanticDomain::SchemaVersion);
    }

    #[test]
    fn test_translation_kind_ord_is_variant_order() {
        assert!(TranslationKind::Preserved < TranslationKind::Narrowed);
        assert!(TranslationKind::Narrowed < TranslationKind::Widened);
        assert!(TranslationKind::Widened < TranslationKind::Collapsed);
        assert!(TranslationKind::Collapsed < TranslationKind::Translated);
        assert!(TranslationKind::Translated < TranslationKind::Dropped);
    }

    #[test]
    fn test_flattening_classification_ord_is_variant_order() {
        assert!(FlatteningClassification::Intentional < FlatteningClassification::MustFix);
        assert!(FlatteningClassification::MustFix < FlatteningClassification::AcceptableEdge);
        assert!(FlatteningClassification::AcceptableEdge < FlatteningClassification::FalsePositive);
    }

    #[test]
    fn test_flattening_severity_ord_is_variant_order() {
        assert!(FlatteningSeverity::Critical < FlatteningSeverity::High);
        assert!(FlatteningSeverity::High < FlatteningSeverity::Medium);
        assert!(FlatteningSeverity::Medium < FlatteningSeverity::Low);
        assert!(FlatteningSeverity::Low < FlatteningSeverity::Info);
    }

    // -- Additional tests: BoundaryPoint edge cases --

    #[test]
    fn test_boundary_point_with_empty_strings() {
        let bp = BoundaryPoint {
            source_module: String::new(),
            target_module: String::new(),
            api_surface: String::new(),
            line_hint: None,
        };
        let s = format!("{bp}");
        assert_eq!(s, " ->  via ");
    }

    #[test]
    fn test_boundary_point_with_line_hint_zero() {
        let bp = BoundaryPoint {
            source_module: "a".to_string(),
            target_module: "b".to_string(),
            api_surface: "f".to_string(),
            line_hint: Some(0),
        };
        let s = format!("{bp}");
        assert!(s.contains("line 0"));
    }

    #[test]
    fn test_boundary_point_with_max_line_hint() {
        let bp = BoundaryPoint {
            source_module: "mod_a".to_string(),
            target_module: "mod_b".to_string(),
            api_surface: "call".to_string(),
            line_hint: Some(u32::MAX),
        };
        let s = format!("{bp}");
        assert!(s.contains(&u32::MAX.to_string()));
    }

    #[test]
    fn test_boundary_point_clone_equality() {
        let bp = sample_boundary();
        let bp2 = bp.clone();
        assert_eq!(bp, bp2);
    }

    #[test]
    fn test_boundary_point_ord_by_source_module() {
        let bp_a = BoundaryPoint {
            source_module: "aaa".to_string(),
            target_module: "zzz".to_string(),
            api_surface: "x".to_string(),
            line_hint: None,
        };
        let bp_b = BoundaryPoint {
            source_module: "bbb".to_string(),
            target_module: "aaa".to_string(),
            api_surface: "x".to_string(),
            line_hint: None,
        };
        assert!(
            bp_a < bp_b,
            "BoundaryPoint should order by source_module first"
        );
    }

    #[test]
    fn test_boundary_point_serde_roundtrip_no_line_hint() {
        let bp = BoundaryPoint {
            source_module: "src".to_string(),
            target_module: "dst".to_string(),
            api_surface: "api".to_string(),
            line_hint: None,
        };
        let json = serde_json::to_string(&bp).unwrap();
        assert!(
            json.contains("null"),
            "None line_hint should serialize as null"
        );
        let back: BoundaryPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(bp, back);
    }

    // -- Additional tests: content hash sensitivity --

    #[test]
    fn test_content_hash_sensitive_to_domain_change() {
        let bp = sample_boundary();
        let h1 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        let h2 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Outcome,
            &bp,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        assert_ne!(h1, h2, "Different domains should produce different hashes");
    }

    #[test]
    fn test_content_hash_sensitive_to_translation_kind() {
        let bp = sample_boundary();
        let h1 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        let h2 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp,
            TranslationKind::Dropped,
            FlatteningClassification::Intentional,
        );
        assert_ne!(
            h1, h2,
            "Different translation kinds should produce different hashes"
        );
    }

    #[test]
    fn test_content_hash_sensitive_to_classification() {
        let bp = sample_boundary();
        let h1 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        let h2 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp,
            TranslationKind::Preserved,
            FlatteningClassification::MustFix,
        );
        assert_ne!(
            h1, h2,
            "Different classifications should produce different hashes"
        );
    }

    #[test]
    fn test_content_hash_sensitive_to_line_hint_presence() {
        let bp_with = BoundaryPoint {
            source_module: "s".to_string(),
            target_module: "t".to_string(),
            api_surface: "a".to_string(),
            line_hint: Some(10),
        };
        let bp_without = BoundaryPoint {
            source_module: "s".to_string(),
            target_module: "t".to_string(),
            api_surface: "a".to_string(),
            line_hint: None,
        };
        let h1 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp_with,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        let h2 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp_without,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        assert_ne!(h1, h2, "Line hint presence should affect the hash");
    }

    #[test]
    fn test_content_hash_sensitive_to_boundary_modules() {
        let bp1 = BoundaryPoint {
            source_module: "alpha".to_string(),
            target_module: "beta".to_string(),
            api_surface: "fn_call".to_string(),
            line_hint: None,
        };
        let bp2 = BoundaryPoint {
            source_module: "beta".to_string(),
            target_module: "alpha".to_string(),
            api_surface: "fn_call".to_string(),
            line_hint: None,
        };
        let h1 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp1,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        let h2 = FlatteningOccurrence::compute_content_hash(
            "id",
            SemanticDomain::Budget,
            &bp2,
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
        );
        assert_ne!(
            h1, h2,
            "Swapped source/target should produce different hashes"
        );
    }

    // -- Additional tests: occurrence Display edge cases --

    #[test]
    fn test_occurrence_display_contains_boundary_info() {
        let occ = FlatteningOccurrence::new(
            "OCC-DISP-2".to_string(),
            SemanticDomain::EvidenceLink,
            BoundaryPoint {
                source_module: "evidence_store".to_string(),
                target_module: "audit_log".to_string(),
                api_surface: "record_evidence".to_string(),
                line_hint: Some(999),
            },
            TranslationKind::Dropped,
            FlatteningClassification::MustFix,
            FlatteningSeverity::Critical,
            "Evidence link dropped at audit boundary".to_string(),
            "Preserve evidence link".to_string(),
            "bd-fix-003".to_string(),
        );
        let s = format!("{occ}");
        assert!(s.contains("OCC-DISP-2"));
        assert!(s.contains("Critical"));
        assert!(s.contains("MustFix"));
        assert!(s.contains("Dropped"));
        assert!(s.contains("evidence_store"));
        assert!(s.contains("audit_log"));
        assert!(s.contains("line 999"));
        assert!(s.contains("Evidence link dropped"));
    }

    // -- Additional tests: inventory filter combinations --

    #[test]
    fn test_by_domain_all_ten_domains() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        let domains = [
            SemanticDomain::Budget,
            SemanticDomain::Outcome,
            SemanticDomain::Capability,
            SemanticDomain::Severity,
            SemanticDomain::Diagnostics,
            SemanticDomain::PolicyId,
            SemanticDomain::TraceId,
            SemanticDomain::DecisionId,
            SemanticDomain::EvidenceLink,
            SemanticDomain::SchemaVersion,
        ];
        for (i, domain) in domains.iter().enumerate() {
            inv.add(FlatteningOccurrence::new(
                format!("DOM-{i}"),
                *domain,
                sample_boundary(),
                TranslationKind::Preserved,
                FlatteningClassification::Intentional,
                FlatteningSeverity::Info,
                "test".to_string(),
                "none".to_string(),
                String::new(),
            ));
        }
        for domain in &domains {
            let items = inv.by_domain(*domain);
            assert_eq!(items.len(), 1, "Each domain should have exactly one item");
        }
    }

    #[test]
    fn test_by_severity_all_five_levels() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        let severities = [
            FlatteningSeverity::Critical,
            FlatteningSeverity::High,
            FlatteningSeverity::Medium,
            FlatteningSeverity::Low,
            FlatteningSeverity::Info,
        ];
        for (i, sev) in severities.iter().enumerate() {
            inv.add(FlatteningOccurrence::new(
                format!("SEV-{i}"),
                SemanticDomain::Budget,
                sample_boundary(),
                TranslationKind::Collapsed,
                FlatteningClassification::MustFix,
                *sev,
                "test".to_string(),
                "fix".to_string(),
                String::new(),
            ));
        }
        for sev in &severities {
            let items = inv.by_severity(*sev);
            assert_eq!(items.len(), 1, "Each severity should have exactly one item");
        }
    }

    #[test]
    fn test_must_fix_items_ignores_other_classifications() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        let classifications = [
            FlatteningClassification::Intentional,
            FlatteningClassification::AcceptableEdge,
            FlatteningClassification::FalsePositive,
        ];
        for (i, cls) in classifications.iter().enumerate() {
            inv.add(FlatteningOccurrence::new(
                format!("NON-MF-{i}"),
                SemanticDomain::Budget,
                sample_boundary(),
                TranslationKind::Narrowed,
                *cls,
                FlatteningSeverity::High,
                "test".to_string(),
                "none".to_string(),
                String::new(),
            ));
        }
        assert!(inv.must_fix_items().is_empty());
    }

    // -- Additional tests: inventory content hash sensitivity --

    #[test]
    fn test_inventory_hash_is_order_independent() {
        let mut inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv1.add(sample_occurrence("ORD-A"));
        inv1.add(sample_occurrence("ORD-B"));

        let mut inv2 = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv2.add(sample_occurrence("ORD-B"));
        inv2.add(sample_occurrence("ORD-A"));

        assert_eq!(
            inv1.content_hash(),
            inv2.content_hash(),
            "Inventory hash must be insertion-order independent"
        );
    }

    #[test]
    fn test_inventory_hash_changes_with_added_occurrence() {
        let mut inv1 = FlatteningInventory::new(SecurityEpoch::GENESIS);
        inv1.add(sample_occurrence("GROW-1"));
        let h1 = inv1.content_hash();

        inv1.add(sample_occurrence("GROW-2"));
        let h2 = inv1.content_hash();

        assert_ne!(
            h1, h2,
            "Adding an occurrence should change the inventory hash"
        );
    }

    // -- Additional tests: summary with all-one-classification --

    #[test]
    fn test_summary_all_must_fix() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        for i in 0..5 {
            inv.add(sample_occurrence(&format!("AMF-{i}")));
        }
        let s = inv.summary();
        assert_eq!(s.total, 5);
        assert_eq!(s.must_fix, 5);
        assert_eq!(s.intentional, 0);
        assert_eq!(s.acceptable, 0);
        assert_eq!(s.false_positive, 0);
    }

    #[test]
    fn test_summary_all_false_positive() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        for i in 0..3 {
            inv.add(FlatteningOccurrence::new(
                format!("AFP-{i}"),
                SemanticDomain::Diagnostics,
                sample_boundary(),
                TranslationKind::Preserved,
                FlatteningClassification::FalsePositive,
                FlatteningSeverity::Info,
                "not a real flattening".to_string(),
                "none".to_string(),
                String::new(),
            ));
        }
        let s = inv.summary();
        assert_eq!(s.total, 3);
        assert_eq!(s.must_fix, 0);
        assert_eq!(s.false_positive, 3);
        assert_eq!(s.by_domain.get("Diagnostics"), Some(&3));
        assert_eq!(s.by_severity.get("Info"), Some(&3));
    }

    #[test]
    fn test_summary_by_domain_keys_are_sorted() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::GENESIS);
        // Add in reverse alphabetical domain order
        inv.add(FlatteningOccurrence::new(
            "K-1".to_string(),
            SemanticDomain::TraceId,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
            "t".to_string(),
            "n".to_string(),
            String::new(),
        ));
        inv.add(FlatteningOccurrence::new(
            "K-2".to_string(),
            SemanticDomain::Budget,
            sample_boundary(),
            TranslationKind::Preserved,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Info,
            "t".to_string(),
            "n".to_string(),
            String::new(),
        ));
        let s = inv.summary();
        let keys: Vec<&String> = s.by_domain.keys().collect();
        assert_eq!(
            keys,
            vec!["Budget", "TraceId"],
            "BTreeMap keys should be sorted"
        );
    }

    // -- Additional tests: serde round-trip for full inventory with multiple items --

    #[test]
    fn test_inventory_serde_roundtrip_multiple_items() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(42));
        inv.add(FlatteningOccurrence::new(
            "SER-1".to_string(),
            SemanticDomain::PolicyId,
            BoundaryPoint {
                source_module: "policy".to_string(),
                target_module: "enforcer".to_string(),
                api_surface: "apply".to_string(),
                line_hint: Some(100),
            },
            TranslationKind::Translated,
            FlatteningClassification::AcceptableEdge,
            FlatteningSeverity::Medium,
            "Policy ID format changed".to_string(),
            "Use canonical form".to_string(),
            "bd-fix-100".to_string(),
        ));
        inv.add(FlatteningOccurrence::new(
            "SER-2".to_string(),
            SemanticDomain::DecisionId,
            BoundaryPoint {
                source_module: "decision".to_string(),
                target_module: "logger".to_string(),
                api_surface: "log_decision".to_string(),
                line_hint: None,
            },
            TranslationKind::Narrowed,
            FlatteningClassification::Intentional,
            FlatteningSeverity::Low,
            "Decision ID truncated for log".to_string(),
            "Log full ID".to_string(),
            "bd-fix-101".to_string(),
        ));
        let json = serde_json::to_string_pretty(&inv).unwrap();
        let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
        assert_eq!(inv.content_hash(), back.content_hash());
    }

    // -- Additional tests: occurrence clone preserves hash --

    #[test]
    fn test_occurrence_clone_preserves_content_hash() {
        let occ = sample_occurrence("CLONE-TEST");
        let cloned = occ.clone();
        assert_eq!(occ.content_hash, cloned.content_hash);
        assert_eq!(occ, cloned);
    }

    // -- Additional tests: inventory Display with items --

    #[test]
    fn test_inventory_display_with_items() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(77));
        inv.add(sample_occurrence("DISP-1"));
        inv.add(sample_occurrence("DISP-2"));
        inv.add(sample_occurrence("DISP-3"));
        let s = format!("{inv}");
        assert!(s.contains("count=3"));
        assert!(s.contains("epoch="));
    }

    // -- Additional tests: summary Display all fields --

    #[test]
    fn test_summary_display_all_fields() {
        let s = FlatteningSummary {
            total: 100,
            must_fix: 10,
            intentional: 50,
            acceptable: 30,
            false_positive: 10,
            by_domain: BTreeMap::new(),
            by_severity: BTreeMap::new(),
        };
        let txt = format!("{s}");
        assert!(txt.contains("total=100"));
        assert!(txt.contains("must_fix=10"));
        assert!(txt.contains("intentional=50"));
        assert!(txt.contains("acceptable=30"));
        assert!(txt.contains("false_positive=10"));
    }

    // -- Additional tests: occurrence with empty strings --

    #[test]
    fn test_occurrence_with_empty_description_and_remediation() {
        let occ = FlatteningOccurrence::new(
            "EMPTY-DESC".to_string(),
            SemanticDomain::SchemaVersion,
            sample_boundary(),
            TranslationKind::Widened,
            FlatteningClassification::MustFix,
            FlatteningSeverity::Critical,
            String::new(),
            String::new(),
            String::new(),
        );
        assert_eq!(occ.description, "");
        assert_eq!(occ.remediation, "");
        assert_eq!(occ.remediation_bead, "");
        // Hash should still be non-default even with empty strings
        assert_ne!(occ.content_hash, ContentHash::default());
    }

    // -- Additional tests: inventory at genesis vs non-genesis --

    #[test]
    fn test_inventory_genesis_vs_from_raw_zero() {
        let inv_genesis = FlatteningInventory::new(SecurityEpoch::GENESIS);
        let inv_zero = FlatteningInventory::new(SecurityEpoch::from_raw(0));
        assert_eq!(inv_genesis.assessed_epoch, inv_zero.assessed_epoch);
        assert_eq!(inv_genesis.content_hash(), inv_zero.content_hash());
    }

    // -- Additional tests: BoundaryPoint hash in BTreeSet --

    #[test]
    fn test_boundary_point_usable_as_btreeset_key() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(sample_boundary());
        set.insert(sample_boundary());
        assert_eq!(
            set.len(),
            1,
            "Identical BoundaryPoints should deduplicate in BTreeSet"
        );

        let other = BoundaryPoint {
            source_module: "other".to_string(),
            target_module: "other".to_string(),
            api_surface: "other".to_string(),
            line_hint: None,
        };
        set.insert(other);
        assert_eq!(set.len(), 2);
    }

    // -- Additional tests: large inventory summary counts --

    #[test]
    fn test_summary_with_many_occurrences() {
        let mut inv = FlatteningInventory::new(SecurityEpoch::from_raw(1));
        let classifications = [
            FlatteningClassification::Intentional,
            FlatteningClassification::MustFix,
            FlatteningClassification::AcceptableEdge,
            FlatteningClassification::FalsePositive,
        ];
        for i in 0..40 {
            inv.add(FlatteningOccurrence::new(
                format!("MANY-{i}"),
                SemanticDomain::Budget,
                sample_boundary(),
                TranslationKind::Collapsed,
                classifications[i % 4],
                FlatteningSeverity::Medium,
                "desc".to_string(),
                "fix".to_string(),
                String::new(),
            ));
        }
        let s = inv.summary();
        assert_eq!(s.total, 40);
        assert_eq!(s.must_fix, 10);
        assert_eq!(s.intentional, 10);
        assert_eq!(s.acceptable, 10);
        assert_eq!(s.false_positive, 10);
        assert_eq!(s.by_domain.get("Budget"), Some(&40));
        assert_eq!(s.by_severity.get("Medium"), Some(&40));
    }

    // -- Additional tests: enum Hash trait --

    #[test]
    fn test_semantic_domain_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let compute_hash = |d: SemanticDomain| {
            let mut h = DefaultHasher::new();
            d.hash(&mut h);
            h.finish()
        };
        // Same variant should always hash the same
        assert_eq!(
            compute_hash(SemanticDomain::Budget),
            compute_hash(SemanticDomain::Budget),
        );
        // Different variants should (almost certainly) hash differently
        assert_ne!(
            compute_hash(SemanticDomain::Budget),
            compute_hash(SemanticDomain::Outcome),
        );
    }

    // -- Additional tests: occurrence Ord --

    #[test]
    fn test_occurrence_ord_by_id() {
        let occ_a = sample_occurrence("AAA");
        let occ_b = sample_occurrence("BBB");
        // FlatteningOccurrence derives Ord; first field is `id`
        assert!(
            occ_a < occ_b,
            "Occurrences should be ordered by id (first field)"
        );
    }

    // -- Additional tests: inventory schema version preserved --

    #[test]
    fn test_inventory_schema_version_preserved_through_serde() {
        let inv = FlatteningInventory::new(SecurityEpoch::from_raw(50));
        let json = serde_json::to_string(&inv).unwrap();
        assert!(json.contains(FLATTENING_SCHEMA_VERSION));
        let back: FlatteningInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, FLATTENING_SCHEMA_VERSION);
    }
}
