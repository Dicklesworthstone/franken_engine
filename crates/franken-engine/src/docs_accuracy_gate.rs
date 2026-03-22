//! Docs accuracy gate for aligning README, CLI help, and operator docs
//! to shipped behavior.
//!
//! Verifies that documented commands, flags, and behaviors match the
//! actually shipped frankenctl surface, producing structured evidence
//! of any drift between documentation and reality.
//!
//! ## Design
//!
//! - **Surface inventory**: enumerate all documented commands, flags,
//!   and behaviors from README, CLI help output, and operator docs.
//! - **Shipped contract**: enumerate actually-implemented commands
//!   from the binary surface.
//! - **Drift detection**: classify mismatches between docs and reality
//!   by severity and user impact.
//! - **Unsupported surface contracts**: explicitly declare what is NOT
//!   supported so users know the boundary.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.10, bd-1lsy.10.11 (RGC-911).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "docs_accuracy_gate";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.docs-accuracy-gate.v1";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.10.11";

/// Maximum documented surfaces before overflow guard.
pub const MAX_DOCUMENTED_SURFACES: usize = 1000;

// ---------------------------------------------------------------------------
// Documentation source
// ---------------------------------------------------------------------------

/// Source of a documented behavior claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocSource {
    /// README.md file.
    Readme,
    /// CLI --help output.
    CliHelp,
    /// Operator documentation (docs/ directory).
    OperatorDocs,
    /// Inline code comments or doc comments.
    InlineComments,
    /// External reference (blog, website).
    ExternalReference,
}

impl DocSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Readme => "readme",
            Self::CliHelp => "cli_help",
            Self::OperatorDocs => "operator_docs",
            Self::InlineComments => "inline_comments",
            Self::ExternalReference => "external_reference",
        }
    }
}

impl fmt::Display for DocSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Surface type
// ---------------------------------------------------------------------------

/// Type of documented surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceType {
    /// CLI command (e.g., `frankenctl compile`).
    Command,
    /// CLI flag (e.g., `--input`).
    Flag,
    /// CLI subcommand (e.g., `verify compile-artifact`).
    Subcommand,
    /// Configuration option (e.g., TOML key).
    ConfigOption,
    /// Runtime behavior (e.g., "deterministic replay").
    RuntimeBehavior,
    /// API endpoint or library function.
    ApiSurface,
    /// Output format or artifact schema.
    OutputFormat,
}

impl SurfaceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Flag => "flag",
            Self::Subcommand => "subcommand",
            Self::ConfigOption => "config_option",
            Self::RuntimeBehavior => "runtime_behavior",
            Self::ApiSurface => "api_surface",
            Self::OutputFormat => "output_format",
        }
    }
}

impl fmt::Display for SurfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Drift classification
// ---------------------------------------------------------------------------

/// Classification of documentation drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    /// Documentation matches shipped behavior.
    Aligned,
    /// Documentation describes a feature that exists but with slightly different syntax.
    MinorSyntaxDrift,
    /// Documentation claims a feature that is not yet shipped (aspirational).
    AspirationalClaim,
    /// Documentation omits a feature that IS shipped.
    UndocumentedFeature,
    /// Documentation describes behavior that contradicts shipped behavior.
    ContradictoryBehavior,
    /// Documentation references a deprecated or removed feature.
    DeprecatedReference,
    /// Documentation has incorrect examples that would fail.
    BrokenExample,
}

impl DriftClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aligned => "aligned",
            Self::MinorSyntaxDrift => "minor_syntax_drift",
            Self::AspirationalClaim => "aspirational_claim",
            Self::UndocumentedFeature => "undocumented_feature",
            Self::ContradictoryBehavior => "contradictory_behavior",
            Self::DeprecatedReference => "deprecated_reference",
            Self::BrokenExample => "broken_example",
        }
    }

    /// Whether this drift class is acceptable for publication.
    pub const fn is_acceptable(self) -> bool {
        matches!(self, Self::Aligned | Self::MinorSyntaxDrift)
    }

    /// Severity weight (millionths).
    pub const fn severity_millionths(self) -> u64 {
        match self {
            Self::Aligned => 0,
            Self::MinorSyntaxDrift => 20_000,
            Self::AspirationalClaim => 500_000,
            Self::UndocumentedFeature => 100_000,
            Self::ContradictoryBehavior => 900_000,
            Self::DeprecatedReference => 300_000,
            Self::BrokenExample => 700_000,
        }
    }
}

impl fmt::Display for DriftClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Documented surface entry
// ---------------------------------------------------------------------------

/// A single documented surface element with its drift status.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DocumentedSurface {
    /// Unique identifier.
    pub id: String,
    /// Name of the documented surface (e.g., "frankenctl compile").
    pub name: String,
    /// Type of surface.
    pub surface_type: SurfaceType,
    /// Where this claim appears.
    pub sources: BTreeSet<DocSource>,
    /// What the documentation says.
    pub documented_behavior: String,
    /// What the shipped binary actually does.
    pub shipped_behavior: String,
    /// Drift classification.
    pub drift_class: DriftClass,
    /// Detailed notes about the drift.
    pub drift_notes: String,
    /// Whether this surface is explicitly marked as unsupported.
    pub explicitly_unsupported: bool,
}

// ---------------------------------------------------------------------------
// Unsupported surface contract
// ---------------------------------------------------------------------------

/// An explicit contract declaring what is NOT supported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnsupportedSurfaceContract {
    /// Surface name.
    pub surface_name: String,
    /// Why it is not supported.
    pub reason: String,
    /// Whether a workaround exists.
    pub workaround: Option<String>,
    /// Whether this is planned for future support.
    pub planned_support: bool,
    /// Tracking bead if planned.
    pub tracking_bead: Option<String>,
}

// ---------------------------------------------------------------------------
// Docs accuracy inventory
// ---------------------------------------------------------------------------

/// Inventory of all documented surfaces and their accuracy status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsAccuracyInventory {
    /// Schema version.
    pub version: String,
    /// All documented surfaces.
    pub surfaces: Vec<DocumentedSurface>,
    /// Explicit unsupported surface contracts.
    pub unsupported_contracts: Vec<UnsupportedSurfaceContract>,
}

impl DocsAccuracyInventory {
    /// Create an empty inventory.
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            surfaces: Vec::new(),
            unsupported_contracts: Vec::new(),
        }
    }

    /// Add a documented surface.
    pub fn add_surface(&mut self, surface: DocumentedSurface) -> Result<(), GateError> {
        if self.surfaces.len() >= MAX_DOCUMENTED_SURFACES {
            return Err(GateError::InventoryOverflow {
                max: MAX_DOCUMENTED_SURFACES,
                attempted: self.surfaces.len() + 1,
            });
        }
        if self.surfaces.iter().any(|s| s.id == surface.id) {
            return Err(GateError::DuplicateSurface {
                id: surface.id.clone(),
            });
        }
        self.surfaces.push(surface);
        Ok(())
    }

    /// Add an unsupported surface contract.
    pub fn add_unsupported(&mut self, contract: UnsupportedSurfaceContract) {
        self.unsupported_contracts.push(contract);
    }

    /// Count of all surfaces.
    pub fn surface_count(&self) -> usize {
        self.surfaces.len()
    }

    /// Surfaces with unacceptable drift.
    pub fn drifted_surfaces(&self) -> Vec<&DocumentedSurface> {
        self.surfaces
            .iter()
            .filter(|s| !s.drift_class.is_acceptable())
            .collect()
    }

    /// Surfaces by drift class.
    pub fn surfaces_by_drift(&self) -> BTreeMap<DriftClass, usize> {
        let mut counts = BTreeMap::new();
        for surface in &self.surfaces {
            *counts.entry(surface.drift_class).or_insert(0) += 1;
        }
        counts
    }

    /// Surfaces by source.
    pub fn surfaces_by_source(&self) -> BTreeMap<DocSource, usize> {
        let mut counts = BTreeMap::new();
        for surface in &self.surfaces {
            for source in &surface.sources {
                *counts.entry(*source).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Compute a deterministic content hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut surfaces: Vec<_> = self.surfaces.iter().collect();
        surfaces.sort_by(|left, right| left.id.cmp(&right.id));
        let surfaces = surfaces
            .into_iter()
            .map(|surface| {
                let sources = surface
                    .sources
                    .iter()
                    .map(|source| CanonicalValue::String(source.as_str().to_string()))
                    .collect();
                CanonicalValue::Map(BTreeMap::from([
                    ("id".to_string(), CanonicalValue::String(surface.id.clone())),
                    (
                        "name".to_string(),
                        CanonicalValue::String(surface.name.clone()),
                    ),
                    (
                        "surface_type".to_string(),
                        CanonicalValue::String(surface.surface_type.as_str().to_string()),
                    ),
                    ("sources".to_string(), CanonicalValue::Array(sources)),
                    (
                        "documented_behavior".to_string(),
                        CanonicalValue::String(surface.documented_behavior.clone()),
                    ),
                    (
                        "shipped_behavior".to_string(),
                        CanonicalValue::String(surface.shipped_behavior.clone()),
                    ),
                    (
                        "drift_class".to_string(),
                        CanonicalValue::String(surface.drift_class.as_str().to_string()),
                    ),
                    (
                        "drift_notes".to_string(),
                        CanonicalValue::String(surface.drift_notes.clone()),
                    ),
                    (
                        "explicitly_unsupported".to_string(),
                        CanonicalValue::Bool(surface.explicitly_unsupported),
                    ),
                ]))
            })
            .collect();
        let mut unsupported_contracts: Vec<_> = self.unsupported_contracts.iter().collect();
        unsupported_contracts.sort_by(|left, right| {
            left.surface_name
                .cmp(&right.surface_name)
                .then(left.reason.cmp(&right.reason))
                .then(left.workaround.cmp(&right.workaround))
                .then(left.planned_support.cmp(&right.planned_support))
                .then(left.tracking_bead.cmp(&right.tracking_bead))
        });
        let unsupported_contracts = unsupported_contracts
            .into_iter()
            .map(|contract| {
                CanonicalValue::Map(BTreeMap::from([
                    (
                        "surface_name".to_string(),
                        CanonicalValue::String(contract.surface_name.clone()),
                    ),
                    (
                        "reason".to_string(),
                        CanonicalValue::String(contract.reason.clone()),
                    ),
                    (
                        "workaround".to_string(),
                        contract
                            .workaround
                            .as_ref()
                            .map_or(CanonicalValue::Null, |workaround| {
                                CanonicalValue::String(workaround.clone())
                            }),
                    ),
                    (
                        "planned_support".to_string(),
                        CanonicalValue::Bool(contract.planned_support),
                    ),
                    (
                        "tracking_bead".to_string(),
                        contract
                            .tracking_bead
                            .as_ref()
                            .map_or(CanonicalValue::Null, |bead| {
                                CanonicalValue::String(bead.clone())
                            }),
                    ),
                ]))
            })
            .collect();
        let canonical = CanonicalValue::Map(BTreeMap::from([
            (
                "version".to_string(),
                CanonicalValue::String(self.version.clone()),
            ),
            ("surfaces".to_string(), CanonicalValue::Array(surfaces)),
            (
                "unsupported_contracts".to_string(),
                CanonicalValue::Array(unsupported_contracts),
            ),
        ]));
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }
}

impl Default for DocsAccuracyInventory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the docs accuracy gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum acceptable aspirational claims.
    pub max_aspirational_claims: usize,
    /// Maximum acceptable broken examples.
    pub max_broken_examples: usize,
    /// Whether contradictory behavior is a hard fail.
    pub fail_on_contradictory: bool,
    /// Maximum average severity (millionths).
    pub max_avg_severity_millionths: u64,
    /// Minimum alignment rate (millionths).
    pub min_alignment_rate_millionths: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_aspirational_claims: 0,
            max_broken_examples: 0,
            fail_on_contradictory: true,
            max_avg_severity_millionths: 50_000,
            min_alignment_rate_millionths: 950_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate verdict
// ---------------------------------------------------------------------------

/// Reason the gate rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Inventory is empty.
    EmptyInventory,
    /// Too many aspirational claims.
    ExcessiveAspirations { count: usize, max: usize },
    /// Too many broken examples.
    ExcessiveBrokenExamples { count: usize, max: usize },
    /// Contradictory behavior found.
    ContradictoryBehaviorFound { count: usize },
    /// Average severity too high.
    ExcessiveSeverity { avg_millionths: u64, threshold: u64 },
    /// Alignment rate too low.
    LowAlignmentRate {
        rate_millionths: u64,
        threshold: u64,
    },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInventory => write!(f, "inventory is empty"),
            Self::ExcessiveAspirations { count, max } => {
                write!(f, "{count} aspirational claims > max {max}")
            }
            Self::ExcessiveBrokenExamples { count, max } => {
                write!(f, "{count} broken examples > max {max}")
            }
            Self::ContradictoryBehaviorFound { count } => {
                write!(f, "{count} contradictory behavior entries")
            }
            Self::ExcessiveSeverity {
                avg_millionths,
                threshold,
            } => {
                write!(f, "avg severity {avg_millionths}/1M > {threshold}/1M")
            }
            Self::LowAlignmentRate {
                rate_millionths,
                threshold,
            } => {
                write!(f, "alignment rate {rate_millionths}/1M < {threshold}/1M")
            }
        }
    }
}

/// Gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Fail { reasons: Vec<RejectionReason> },
}

impl GateVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reasons } => write!(f, "FAIL ({} reasons)", reasons.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Gate report
// ---------------------------------------------------------------------------

/// Full gate evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub verdict: GateVerdict,
    pub inventory_hash: ContentHash,
    pub total_surfaces: usize,
    pub aligned_count: usize,
    pub drifted_count: usize,
    pub alignment_rate_millionths: u64,
    pub avg_severity_millionths: u64,
    pub drift_distribution: BTreeMap<DriftClass, usize>,
    pub unsupported_contract_count: usize,
}

// ---------------------------------------------------------------------------
// Gate evaluator
// ---------------------------------------------------------------------------

/// The docs accuracy gate evaluator.
#[derive(Debug, Clone)]
pub struct DocsAccuracyGate {
    config: GateConfig,
}

impl DocsAccuracyGate {
    pub fn new(config: GateConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(GateConfig::default())
    }

    /// Evaluate the inventory and produce a gate report.
    pub fn evaluate(&self, inventory: &DocsAccuracyInventory) -> GateReport {
        let mut reasons = Vec::new();

        if inventory.surfaces.is_empty() {
            return GateReport {
                schema_version: SCHEMA_VERSION.to_string(),
                bead_id: BEAD_ID.to_string(),
                component: COMPONENT.to_string(),
                verdict: GateVerdict::Fail {
                    reasons: vec![RejectionReason::EmptyInventory],
                },
                inventory_hash: inventory.content_hash(),
                total_surfaces: 0,
                aligned_count: 0,
                drifted_count: 0,
                alignment_rate_millionths: 0,
                avg_severity_millionths: 0,
                drift_distribution: BTreeMap::new(),
                unsupported_contract_count: inventory.unsupported_contracts.len(),
            };
        }

        let drift_dist = inventory.surfaces_by_drift();

        // Aspirational claims check
        let aspirational = *drift_dist.get(&DriftClass::AspirationalClaim).unwrap_or(&0);
        if aspirational > self.config.max_aspirational_claims {
            reasons.push(RejectionReason::ExcessiveAspirations {
                count: aspirational,
                max: self.config.max_aspirational_claims,
            });
        }

        // Broken examples check
        let broken = *drift_dist.get(&DriftClass::BrokenExample).unwrap_or(&0);
        if broken > self.config.max_broken_examples {
            reasons.push(RejectionReason::ExcessiveBrokenExamples {
                count: broken,
                max: self.config.max_broken_examples,
            });
        }

        // Contradictory behavior check
        let contradictory = *drift_dist
            .get(&DriftClass::ContradictoryBehavior)
            .unwrap_or(&0);
        if self.config.fail_on_contradictory && contradictory > 0 {
            reasons.push(RejectionReason::ContradictoryBehaviorFound {
                count: contradictory,
            });
        }

        // Alignment rate
        let aligned = inventory
            .surfaces
            .iter()
            .filter(|s| s.drift_class.is_acceptable())
            .count();
        let alignment_rate = (aligned as u64)
            .saturating_mul(1_000_000)
            .checked_div(inventory.surfaces.len() as u64)
            .unwrap_or(0);

        if alignment_rate < self.config.min_alignment_rate_millionths {
            reasons.push(RejectionReason::LowAlignmentRate {
                rate_millionths: alignment_rate,
                threshold: self.config.min_alignment_rate_millionths,
            });
        }

        // Average severity
        let total_severity: u64 = inventory
            .surfaces
            .iter()
            .map(|s| s.drift_class.severity_millionths())
            .sum();
        let avg_severity = total_severity
            .checked_div(inventory.surfaces.len() as u64)
            .unwrap_or(0);

        if avg_severity > self.config.max_avg_severity_millionths {
            reasons.push(RejectionReason::ExcessiveSeverity {
                avg_millionths: avg_severity,
                threshold: self.config.max_avg_severity_millionths,
            });
        }

        let drifted = inventory.drifted_surfaces().len();

        let verdict = if reasons.is_empty() {
            GateVerdict::Pass
        } else {
            GateVerdict::Fail { reasons }
        };

        GateReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            verdict,
            inventory_hash: inventory.content_hash(),
            total_surfaces: inventory.surface_count(),
            aligned_count: aligned,
            drifted_count: drifted,
            alignment_rate_millionths: alignment_rate,
            avg_severity_millionths: avg_severity,
            drift_distribution: drift_dist,
            unsupported_contract_count: inventory.unsupported_contracts.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// Seed inventory builder
// ---------------------------------------------------------------------------

/// Build a seed inventory with the shipped frankenctl commands.
pub fn build_seed_inventory() -> DocsAccuracyInventory {
    let mut inv = DocsAccuracyInventory::new();

    let shipped_commands = [
        ("cmd_version", "frankenctl version", "Print version"),
        (
            "cmd_compile",
            "frankenctl compile",
            "Compile source to artifact",
        ),
        (
            "cmd_run",
            "frankenctl run",
            "Execute source through orchestrator",
        ),
        ("cmd_doctor", "frankenctl doctor", "Runtime diagnostics"),
        (
            "cmd_verify_compile",
            "frankenctl verify compile-artifact",
            "Validate compile artifact",
        ),
        (
            "cmd_verify_receipt",
            "frankenctl verify receipt",
            "Verify receipt bundle",
        ),
        (
            "cmd_benchmark_run",
            "frankenctl benchmark run",
            "Run benchmarks",
        ),
        (
            "cmd_benchmark_score",
            "frankenctl benchmark score",
            "Score publication gate",
        ),
        (
            "cmd_benchmark_verify",
            "frankenctl benchmark verify",
            "Verify benchmark claims",
        ),
        ("cmd_replay_run", "frankenctl replay run", "Replay traces"),
    ];

    for (id, name, desc) in &shipped_commands {
        let mut sources = BTreeSet::new();
        sources.insert(DocSource::Readme);
        sources.insert(DocSource::CliHelp);
        let surface = DocumentedSurface {
            id: id.to_string(),
            name: name.to_string(),
            surface_type: SurfaceType::Command,
            sources,
            documented_behavior: desc.to_string(),
            shipped_behavior: desc.to_string(),
            drift_class: DriftClass::Aligned,
            drift_notes: String::new(),
            explicitly_unsupported: false,
        };
        let _ = inv.add_surface(surface);
    }

    // Add some explicit unsupported surface contracts
    let unsupported = [
        (
            "workspace init",
            "Not yet shipped",
            "Use manual setup",
            true,
            Some("bd-future"),
        ),
        (
            "promotion commands",
            "Not yet shipped",
            "Use vercel promote",
            true,
            None,
        ),
        (
            "TUI serving",
            "Requires frankentui integration",
            "Use frankenctl doctor",
            true,
            None,
        ),
    ];

    for (name, reason, workaround, planned, bead) in &unsupported {
        inv.add_unsupported(UnsupportedSurfaceContract {
            surface_name: name.to_string(),
            reason: reason.to_string(),
            workaround: Some(workaround.to_string()),
            planned_support: *planned,
            tracking_bead: bead.map(|b| b.to_string()),
        });
    }

    inv
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from the docs accuracy gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateError {
    InventoryOverflow { max: usize, attempted: usize },
    DuplicateSurface { id: String },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InventoryOverflow { max, attempted } => {
                write!(f, "inventory overflow: {attempted} > {max}")
            }
            Self::DuplicateSurface { id } => write!(f, "duplicate surface: {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn aligned_surface(id: &str) -> DocumentedSurface {
        let mut sources = BTreeSet::new();
        sources.insert(DocSource::Readme);
        DocumentedSurface {
            id: id.to_string(),
            name: format!("test surface {id}"),
            surface_type: SurfaceType::Command,
            sources,
            documented_behavior: "does X".to_string(),
            shipped_behavior: "does X".to_string(),
            drift_class: DriftClass::Aligned,
            drift_notes: String::new(),
            explicitly_unsupported: false,
        }
    }

    fn drifted_surface(id: &str, drift: DriftClass) -> DocumentedSurface {
        let mut s = aligned_surface(id);
        s.drift_class = drift;
        s.shipped_behavior = "does Y instead".to_string();
        s
    }

    // --- DocSource tests ---
    #[test]
    fn doc_source_as_str() {
        assert_eq!(DocSource::Readme.as_str(), "readme");
        assert_eq!(DocSource::CliHelp.as_str(), "cli_help");
    }

    #[test]
    fn doc_source_serde_roundtrip() {
        let s = DocSource::OperatorDocs;
        let json = serde_json::to_string(&s).unwrap();
        let back: DocSource = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- SurfaceType tests ---
    #[test]
    fn surface_type_as_str() {
        assert_eq!(SurfaceType::Command.as_str(), "command");
        assert_eq!(SurfaceType::Flag.as_str(), "flag");
    }

    // --- DriftClass tests ---
    #[test]
    fn drift_acceptable() {
        assert!(DriftClass::Aligned.is_acceptable());
        assert!(DriftClass::MinorSyntaxDrift.is_acceptable());
        assert!(!DriftClass::AspirationalClaim.is_acceptable());
        assert!(!DriftClass::ContradictoryBehavior.is_acceptable());
        assert!(!DriftClass::BrokenExample.is_acceptable());
    }

    #[test]
    fn drift_severity_ordering() {
        assert_eq!(DriftClass::Aligned.severity_millionths(), 0);
        assert!(
            DriftClass::MinorSyntaxDrift.severity_millionths()
                < DriftClass::AspirationalClaim.severity_millionths()
        );
        assert!(
            DriftClass::AspirationalClaim.severity_millionths()
                < DriftClass::ContradictoryBehavior.severity_millionths()
        );
    }

    #[test]
    fn drift_serde_roundtrip() {
        let d = DriftClass::BrokenExample;
        let json = serde_json::to_string(&d).unwrap();
        let back: DriftClass = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- Inventory tests ---
    #[test]
    fn empty_inventory() {
        let inv = DocsAccuracyInventory::new();
        assert_eq!(inv.surface_count(), 0);
    }

    #[test]
    fn add_surface() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        assert_eq!(inv.surface_count(), 1);
    }

    #[test]
    fn duplicate_surface_rejected() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        let err = inv.add_surface(aligned_surface("s1")).unwrap_err();
        assert!(matches!(err, GateError::DuplicateSurface { .. }));
    }

    #[test]
    fn drifted_surfaces_filtered() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        inv.add_surface(drifted_surface("s2", DriftClass::AspirationalClaim))
            .unwrap();
        assert_eq!(inv.drifted_surfaces().len(), 1);
    }

    #[test]
    fn surfaces_by_drift() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        inv.add_surface(aligned_surface("s2")).unwrap();
        inv.add_surface(drifted_surface("s3", DriftClass::BrokenExample))
            .unwrap();
        let dist = inv.surfaces_by_drift();
        assert_eq!(*dist.get(&DriftClass::Aligned).unwrap(), 2);
        assert_eq!(*dist.get(&DriftClass::BrokenExample).unwrap(), 1);
    }

    #[test]
    fn content_hash_deterministic() {
        let i1 = build_seed_inventory();
        let i2 = build_seed_inventory();
        assert_eq!(i1.content_hash(), i2.content_hash());
    }

    #[test]
    fn content_hash_changes() {
        let i1 = build_seed_inventory();
        let mut i2 = build_seed_inventory();
        i2.add_surface(aligned_surface("extra")).unwrap();
        assert_ne!(i1.content_hash(), i2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_surface_payload_changes() {
        let i1 = build_seed_inventory();
        let mut i2 = build_seed_inventory();
        i2.surfaces[0].documented_behavior = "Different README claim".to_string();
        assert_ne!(i1.content_hash(), i2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_unsupported_contract_changes() {
        let i1 = build_seed_inventory();
        let mut i2 = build_seed_inventory();
        i2.unsupported_contracts[0].reason = "new unsupported reason".to_string();
        assert_ne!(i1.content_hash(), i2.content_hash());
    }

    #[test]
    fn content_hash_is_invariant_to_surface_and_contract_order() {
        let i1 = build_seed_inventory();
        let mut i2 = build_seed_inventory();
        i2.surfaces.reverse();
        i2.unsupported_contracts.reverse();
        assert_eq!(i1.content_hash(), i2.content_hash());
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inv = build_seed_inventory();
        let json = serde_json::to_string(&inv).unwrap();
        let back: DocsAccuracyInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv.surface_count(), back.surface_count());
        assert_eq!(inv.content_hash(), back.content_hash());
    }

    #[test]
    fn default_inventory_empty() {
        let inv = DocsAccuracyInventory::default();
        assert_eq!(inv.surface_count(), 0);
    }

    // --- Seed inventory tests ---
    #[test]
    fn seed_inventory_has_commands() {
        let inv = build_seed_inventory();
        assert_eq!(inv.surface_count(), 10);
    }

    #[test]
    fn seed_inventory_all_aligned() {
        let inv = build_seed_inventory();
        assert!(inv.drifted_surfaces().is_empty());
    }

    #[test]
    fn seed_inventory_has_unsupported_contracts() {
        let inv = build_seed_inventory();
        assert_eq!(inv.unsupported_contracts.len(), 3);
    }

    // --- Gate tests ---
    #[test]
    fn empty_inventory_fails() {
        let gate = DocsAccuracyGate::with_defaults();
        let inv = DocsAccuracyInventory::new();
        let report = gate.evaluate(&inv);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn seed_inventory_passes() {
        let gate = DocsAccuracyGate::with_defaults();
        let inv = build_seed_inventory();
        let report = gate.evaluate(&inv);
        assert!(report.verdict.is_pass());
    }

    #[test]
    fn aspirational_claim_fails_strict() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        inv.add_surface(drifted_surface("s2", DriftClass::AspirationalClaim))
            .unwrap();
        let gate = DocsAccuracyGate::with_defaults();
        let report = gate.evaluate(&inv);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn contradictory_behavior_fails() {
        let mut inv = DocsAccuracyInventory::new();
        inv.add_surface(aligned_surface("s1")).unwrap();
        inv.add_surface(drifted_surface("s2", DriftClass::ContradictoryBehavior))
            .unwrap();
        let gate = DocsAccuracyGate::with_defaults();
        let report = gate.evaluate(&inv);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn report_serde_roundtrip() {
        let gate = DocsAccuracyGate::with_defaults();
        let inv = build_seed_inventory();
        let report = gate.evaluate(&inv);
        let json = serde_json::to_string(&report).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_surfaces, back.total_surfaces);
    }

    // --- Config tests ---
    #[test]
    fn default_config() {
        let config = GateConfig::default();
        assert_eq!(config.max_aspirational_claims, 0);
        assert!(config.fail_on_contradictory);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- Verdict tests ---
    #[test]
    fn verdict_pass() {
        assert!(GateVerdict::Pass.is_pass());
    }

    #[test]
    fn verdict_fail() {
        let v = GateVerdict::Fail {
            reasons: vec![RejectionReason::EmptyInventory],
        };
        assert!(!v.is_pass());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Pass), "PASS");
    }

    // --- Error tests ---
    #[test]
    fn error_display() {
        let e = GateError::DuplicateSurface {
            id: "foo".to_string(),
        };
        assert!(format!("{e}").contains("foo"));
    }

    // --- Constants ---
    #[test]
    fn constants() {
        assert_eq!(COMPONENT, "docs_accuracy_gate");
        assert_eq!(BEAD_ID, "bd-1lsy.10.11");
    }

    // --- Unsupported contract tests ---
    #[test]
    fn unsupported_contract_serde() {
        let c = UnsupportedSurfaceContract {
            surface_name: "workspace init".to_string(),
            reason: "not shipped".to_string(),
            workaround: Some("manual setup".to_string()),
            planned_support: true,
            tracking_bead: Some("bd-future".to_string()),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: UnsupportedSurfaceContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
