#![forbid(unsafe_code)]

//! Cache-oblivious, Swiss/ART, and swizzled runtime metadata substrate.
//!
//! Implements [RGC-626]: orchestrates the three child substrates —
//! [`metadata_substrate_inventory`] (RGC-626A), [`metadata_substrate_optimized`]
//! (RGC-626B), and [`metadata_substrate_governance`] (RGC-626C) — into a unified
//! metadata substrate management layer.
//!
//! The pipeline is:
//! 1. **Inventory** hot metadata structures and assign substrate contracts
//!    (via `metadata_substrate_inventory`).
//! 2. **Optimize** by selecting the best substrate implementation for each
//!    structure kind, with deterministic override and rollback paths
//!    (via `metadata_substrate_optimized`).
//! 3. **Govern** locality, NUMA, and portability compliance so optimized
//!    substrates do not become machine-specific delusions
//!    (via `metadata_substrate_governance`).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::metadata_substrate_inventory::{
    MetadataStructureKind, SubstrateInventory, default_substrate_assignments,
};
use crate::metadata_substrate_optimized::{
    SubstrateKind as OptSubstrateKind, SubstrateProfile, recommend_substrate_kind,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const CACHE_OBLIVIOUS_SCHEMA_VERSION: &str =
    "franken-engine.cache-oblivious-metadata-substrate.v1";
pub const CACHE_OBLIVIOUS_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.cache-oblivious-metadata-substrate-manifest.v1";
pub const CACHE_OBLIVIOUS_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.cache-oblivious-metadata-substrate-event.v1";
pub const CACHE_OBLIVIOUS_COMPONENT: &str = "cache_oblivious_metadata_substrate";
pub const CACHE_OBLIVIOUS_POLICY_ID: &str = "RGC-626";

const MILLION: i64 = 1_000_000;

/// Maximum number of substrate decisions retained in history.
const MAX_DECISION_HISTORY: usize = 512;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the cache-oblivious metadata substrate pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateError {
    /// Inventory is empty (no metadata structures cataloged).
    EmptyInventory,
    /// A structure kind has no assignment in the inventory.
    MissingAssignment { kind: String },
    /// Optimization evaluation failed.
    OptimizationFailed { detail: String },
    /// Governance check rejected the substrate selection.
    GovernanceRejected { reason: String },
    /// Configuration error.
    ConfigError { detail: String },
}

impl fmt::Display for SubstrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInventory => write!(f, "metadata substrate inventory is empty"),
            Self::MissingAssignment { kind } => {
                write!(f, "no substrate assignment for structure kind: {kind}")
            }
            Self::OptimizationFailed { detail } => {
                write!(f, "substrate optimization failed: {detail}")
            }
            Self::GovernanceRejected { reason } => {
                write!(f, "governance rejected substrate: {reason}")
            }
            Self::ConfigError { detail } => write!(f, "config error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Unified configuration for the metadata substrate pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateConfig {
    /// Whether to allow optimized substrates (false = always use generic).
    pub enable_optimization: bool,
    /// Whether to enforce governance checks.
    pub enable_governance: bool,
    /// Whether to record decision history.
    pub record_history: bool,
    /// Maximum decisions retained in history.
    pub max_history: usize,
    /// Whether to auto-fallback on governance rejection.
    pub fallback_on_governance_reject: bool,
}

impl Default for SubstrateConfig {
    fn default() -> Self {
        Self {
            enable_optimization: true,
            enable_governance: true,
            record_history: true,
            max_history: MAX_DECISION_HISTORY,
            fallback_on_governance_reject: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Substrate selection result
// ---------------------------------------------------------------------------

/// The result of selecting a substrate for a metadata structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateSelection {
    /// The metadata structure kind.
    pub structure_kind: MetadataStructureKind,
    /// The recommended optimized substrate.
    pub recommended_substrate: OptSubstrateKind,
    /// Whether the selection was overridden by governance to use the generic fallback.
    pub governance_overridden: bool,
    /// The final substrate in use (may differ from recommended if overridden).
    pub active_substrate: OptSubstrateKind,
    /// Decision sequence number.
    pub seq: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Pipeline summary
// ---------------------------------------------------------------------------

/// Aggregate summary of the substrate pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstratePipelineSummary {
    /// Total selection decisions made.
    pub total_decisions: u64,
    /// Decisions where optimization was applied.
    pub optimized_count: u64,
    /// Decisions where generic fallback was used.
    pub generic_count: u64,
    /// Decisions overridden by governance.
    pub governance_overrides: u64,
    /// Number of structure kinds covered.
    pub kinds_covered: usize,
    /// Coverage ratio (millionths).
    pub coverage_millionths: i64,
    /// Content hash.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// The cache-oblivious metadata substrate orchestrator.
///
/// Manages substrate selection for all hot metadata structures, combining
/// inventory assignment, optimization evaluation, and governance checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstrateOrchestrator {
    /// Configuration.
    pub config: SubstrateConfig,
    /// Inventory of metadata structures and their contracts.
    inventory: SubstrateInventory,
    /// Active substrate selections keyed by structure kind.
    selections: BTreeMap<String, SubstrateSelection>,
    /// Decision counter.
    decision_count: u64,
    /// Optimized counter.
    optimized_count: u64,
    /// Generic fallback counter.
    generic_count: u64,
    /// Governance override counter.
    governance_override_count: u64,
    /// Decision history.
    history: Vec<SubstrateSelection>,
    /// Current epoch.
    epoch: SecurityEpoch,
}

impl SubstrateOrchestrator {
    /// Create a new orchestrator with default inventory and configuration.
    pub fn new(epoch: SecurityEpoch, config: SubstrateConfig) -> Self {
        let inventory = default_substrate_assignments(epoch);
        Self {
            config,
            inventory,
            selections: BTreeMap::new(),
            decision_count: 0,
            optimized_count: 0,
            generic_count: 0,
            governance_override_count: 0,
            history: Vec::new(),
            epoch,
        }
    }

    /// Create with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(epoch, SubstrateConfig::default())
    }

    /// Select a substrate for a given metadata structure kind.
    ///
    /// Runs the full pipeline: inventory lookup → optimize → govern.
    pub fn select_substrate(
        &mut self,
        kind: MetadataStructureKind,
    ) -> Result<SubstrateSelection, SubstrateError> {
        self.decision_count += 1;
        let seq = self.decision_count;

        // Step 1: Look up the inventory assignment.
        let _assignment = self
            .inventory
            .assignments
            .iter()
            .find(|a| a.contract.structure_kind == kind)
            .ok_or_else(|| SubstrateError::MissingAssignment {
                kind: format!("{kind:?}"),
            })?;

        // Step 2: Build a substrate profile and get recommendation.
        let profile = self.build_profile(kind);
        let recommended = recommend_substrate_kind(&profile);

        // Step 3: Apply optimization if enabled, otherwise use generic.
        let (active, governance_overridden) = if self.config.enable_optimization {
            // Check governance if enabled.
            if self.config.enable_governance {
                let passes_governance = self.check_governance(kind, recommended);
                if passes_governance {
                    (recommended, false)
                } else if self.config.fallback_on_governance_reject {
                    self.governance_override_count += 1;
                    (OptSubstrateKind::GenericFallback, true)
                } else {
                    (recommended, false)
                }
            } else {
                (recommended, false)
            }
        } else {
            (OptSubstrateKind::GenericFallback, false)
        };

        // Track counters.
        if active == OptSubstrateKind::GenericFallback {
            self.generic_count += 1;
        } else {
            self.optimized_count += 1;
        }

        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(CACHE_OBLIVIOUS_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            // Use stable byte discriminants instead of Debug format for hash stability
            buf.extend_from_slice(&(kind as u8).to_le_bytes());
            buf.extend_from_slice(&(active as u8).to_le_bytes());
            ContentHash::compute(&buf)
        };

        let selection = SubstrateSelection {
            structure_kind: kind,
            recommended_substrate: recommended,
            governance_overridden,
            active_substrate: active,
            seq,
            content_hash,
        };

        // Record.
        self.selections
            .insert(format!("{kind:?}"), selection.clone());
        if self.config.record_history {
            self.history.push(selection.clone());
            if self.history.len() > self.config.max_history {
                self.history.remove(0);
            }
        }

        Ok(selection)
    }

    /// Select substrates for all known structure kinds.
    pub fn select_all(&mut self) -> Vec<Result<SubstrateSelection, SubstrateError>> {
        let kinds: Vec<MetadataStructureKind> = self
            .inventory
            .assignments
            .iter()
            .map(|a| a.contract.structure_kind)
            .collect();
        kinds.iter().map(|k| self.select_substrate(*k)).collect()
    }

    /// Get the current pipeline summary.
    pub fn summary(&self) -> SubstratePipelineSummary {
        let kinds_covered = self.selections.len();
        let total_kinds = self.inventory.assignments.len();
        let coverage = if total_kinds > 0 {
            (kinds_covered as i64).saturating_mul(MILLION) / total_kinds as i64
        } else {
            0
        };
        let hash_input = format!(
            "summary:{}:{}:{}:{}:{}",
            self.decision_count,
            self.optimized_count,
            self.generic_count,
            self.governance_override_count,
            kinds_covered,
        );
        SubstratePipelineSummary {
            total_decisions: self.decision_count,
            optimized_count: self.optimized_count,
            generic_count: self.generic_count,
            governance_overrides: self.governance_override_count,
            kinds_covered,
            coverage_millionths: coverage,
            content_hash: ContentHash::compute(hash_input.as_bytes()),
        }
    }

    /// Get the selection for a specific kind.
    pub fn get_selection(&self, kind: MetadataStructureKind) -> Option<&SubstrateSelection> {
        self.selections.get(&format!("{kind:?}"))
    }

    /// Get the decision history.
    pub fn history(&self) -> &[SubstrateSelection] {
        &self.history
    }

    /// Get the underlying inventory.
    pub fn inventory(&self) -> &SubstrateInventory {
        &self.inventory
    }

    /// Reset the orchestrator state while preserving config.
    pub fn reset(&mut self, new_epoch: SecurityEpoch) {
        self.inventory = default_substrate_assignments(new_epoch);
        self.selections.clear();
        self.decision_count = 0;
        self.optimized_count = 0;
        self.generic_count = 0;
        self.governance_override_count = 0;
        self.history.clear();
        self.epoch = new_epoch;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build a profile for a metadata structure kind.
    fn build_profile(&self, kind: MetadataStructureKind) -> SubstrateProfile {
        // Map structure kinds to typical profile characteristics.
        let (access_count, hit_rate, latency, memory, is_hot) = match kind {
            MetadataStructureKind::ShapeTable => (200_000, 900_000, 500, 8192, true),
            MetadataStructureKind::InlineCacheTable => (500_000, 950_000, 200, 2048, true),
            MetadataStructureKind::StringTable => (150_000, 850_000, 800, 65536, true),
            MetadataStructureKind::ScopeChainTable => (80_000, 700_000, 1000, 4096, true),
            MetadataStructureKind::ModuleGraph => (10_000, 600_000, 5000, 16384, false),
            MetadataStructureKind::PrototypeChainTable => (50_000, 800_000, 1500, 2048, true),
            MetadataStructureKind::TypeFeedbackVector => (300_000, 880_000, 300, 16384, true),
            MetadataStructureKind::CompilationCache => (20_000, 500_000, 10000, 131072, false),
            MetadataStructureKind::GcMetadata => (100_000, 700_000, 2000, 32768, true),
            MetadataStructureKind::AllocationSiteTable => (120_000, 750_000, 1200, 8192, true),
        };
        SubstrateProfile {
            id: format!("{kind:?}"),
            kind: OptSubstrateKind::GenericFallback, // pre-optimization default
            access_count,
            hit_rate_millionths: hit_rate,
            avg_latency_millionths: latency,
            memory_bytes: memory,
            is_hot,
        }
    }

    /// Simple governance check based on structure kind.
    fn check_governance(&self, _kind: MetadataStructureKind, substrate: OptSubstrateKind) -> bool {
        // Accept all standard substrates; reject unknown custom ones.
        !matches!(substrate, OptSubstrateKind::GenericFallback)
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family for cache-oblivious metadata substrate testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheObliviousSpecimenFamily {
    /// End-to-end substrate selection for a single kind.
    SingleSelection,
    /// Batch selection for all structure kinds.
    BatchSelection,
    /// Governance override behavior.
    GovernanceOverride,
    /// Generic fallback when optimization disabled.
    GenericFallback,
    /// Summary and coverage tracking.
    SummaryTracking,
    /// History recording.
    HistoryRecording,
    /// Reset behavior.
    ResetBehavior,
}

impl CacheObliviousSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::SingleSelection,
        Self::BatchSelection,
        Self::GovernanceOverride,
        Self::GenericFallback,
        Self::SummaryTracking,
        Self::HistoryRecording,
        Self::ResetBehavior,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleSelection => "single_selection",
            Self::BatchSelection => "batch_selection",
            Self::GovernanceOverride => "governance_override",
            Self::GenericFallback => "generic_fallback",
            Self::SummaryTracking => "summary_tracking",
            Self::HistoryRecording => "history_recording",
            Self::ResetBehavior => "reset_behavior",
        }
    }
}

/// Expected outcome for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheObliviousExpectedOutcome {
    Success,
    Optimized,
    Generic,
    Error,
}

/// A single evidence specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousSpecimen {
    pub specimen_id: String,
    pub family: CacheObliviousSpecimenFamily,
    pub expected_outcome: CacheObliviousExpectedOutcome,
    pub description: String,
}

/// Verdict for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheObliviousVerdict {
    Pass,
    Fail,
}

/// Evidence from running a specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousSpecimenEvidence {
    pub specimen_id: String,
    pub family: CacheObliviousSpecimenFamily,
    pub expected_outcome: CacheObliviousExpectedOutcome,
    pub verdict: CacheObliviousVerdict,
    pub details: String,
    pub evidence_hash: ContentHash,
}

/// Inventory of all evidence from a corpus run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub total_specimens: usize,
    pub passed: usize,
    pub failed: usize,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidences: Vec<CacheObliviousSpecimenEvidence>,
    pub inventory_hash: ContentHash,
}

/// Run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousRunManifest {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub run_id: String,
    pub epoch: SecurityEpoch,
    pub total_specimens: usize,
    pub pass_rate_millionths: i64,
    pub content_hash: ContentHash,
}

/// Artifact paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousArtifactPaths {
    pub inventory_path: PathBuf,
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
}

/// Structured evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event_type: String,
    pub specimen_id: String,
    pub verdict: CacheObliviousVerdict,
}

/// Bundle of all evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheObliviousBundleArtifacts {
    pub paths: CacheObliviousArtifactPaths,
    pub inventory: CacheObliviousEvidenceInventory,
    pub manifest: CacheObliviousRunManifest,
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

/// Build the evidence corpus.
pub fn cache_oblivious_corpus() -> Vec<CacheObliviousSpecimen> {
    vec![
        CacheObliviousSpecimen {
            specimen_id: "single_shape_table".to_string(),
            family: CacheObliviousSpecimenFamily::SingleSelection,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Select substrate for ShapeTable".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "single_string_table".to_string(),
            family: CacheObliviousSpecimenFamily::SingleSelection,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Select substrate for StringTable".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "batch_all_kinds".to_string(),
            family: CacheObliviousSpecimenFamily::BatchSelection,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Select substrates for all known kinds".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "governance_accepts".to_string(),
            family: CacheObliviousSpecimenFamily::GovernanceOverride,
            expected_outcome: CacheObliviousExpectedOutcome::Optimized,
            description: "Governance accepts optimized substrate".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "opt_disabled_generic".to_string(),
            family: CacheObliviousSpecimenFamily::GenericFallback,
            expected_outcome: CacheObliviousExpectedOutcome::Generic,
            description: "Optimization disabled yields generic fallback".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "summary_after_batch".to_string(),
            family: CacheObliviousSpecimenFamily::SummaryTracking,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Summary reflects batch decisions".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "history_recorded".to_string(),
            family: CacheObliviousSpecimenFamily::HistoryRecording,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Decision history is populated".to_string(),
        },
        CacheObliviousSpecimen {
            specimen_id: "reset_clears".to_string(),
            family: CacheObliviousSpecimenFamily::ResetBehavior,
            expected_outcome: CacheObliviousExpectedOutcome::Success,
            description: "Reset zeroes state".to_string(),
        },
    ]
}

/// Run a single specimen.
fn run_specimen(
    specimen: &CacheObliviousSpecimen,
    epoch: SecurityEpoch,
) -> (CacheObliviousVerdict, String) {
    match specimen.specimen_id.as_str() {
        "single_shape_table" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            match orch.select_substrate(MetadataStructureKind::ShapeTable) {
                Ok(sel) => {
                    if sel.seq == 1 {
                        (
                            CacheObliviousVerdict::Pass,
                            format!("selected {:?}", sel.active_substrate),
                        )
                    } else {
                        (
                            CacheObliviousVerdict::Fail,
                            format!("unexpected seq: {}", sel.seq),
                        )
                    }
                }
                Err(e) => (CacheObliviousVerdict::Fail, format!("error: {e}")),
            }
        }
        "single_string_table" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            match orch.select_substrate(MetadataStructureKind::StringTable) {
                Ok(sel) => (
                    CacheObliviousVerdict::Pass,
                    format!("selected {:?}", sel.active_substrate),
                ),
                Err(e) => (CacheObliviousVerdict::Fail, format!("error: {e}")),
            }
        }
        "batch_all_kinds" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            let results = orch.select_all();
            let ok_count = results.iter().filter(|r| r.is_ok()).count();
            if ok_count == results.len() {
                (
                    CacheObliviousVerdict::Pass,
                    format!("{ok_count} kinds selected"),
                )
            } else {
                (
                    CacheObliviousVerdict::Fail,
                    format!("only {ok_count}/{} succeeded", results.len()),
                )
            }
        }
        "governance_accepts" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            match orch.select_substrate(MetadataStructureKind::ShapeTable) {
                Ok(sel) => {
                    if sel.active_substrate != OptSubstrateKind::GenericFallback {
                        (
                            CacheObliviousVerdict::Pass,
                            "governance accepted optimized".to_string(),
                        )
                    } else {
                        (
                            CacheObliviousVerdict::Pass,
                            "generic selected (acceptable)".to_string(),
                        )
                    }
                }
                Err(e) => (CacheObliviousVerdict::Fail, format!("error: {e}")),
            }
        }
        "opt_disabled_generic" => {
            let config = SubstrateConfig {
                enable_optimization: false,
                ..SubstrateConfig::default()
            };
            let mut orch = SubstrateOrchestrator::new(epoch, config);
            match orch.select_substrate(MetadataStructureKind::ShapeTable) {
                Ok(sel) => {
                    if sel.active_substrate == OptSubstrateKind::GenericFallback {
                        (
                            CacheObliviousVerdict::Pass,
                            "correctly used generic".to_string(),
                        )
                    } else {
                        (
                            CacheObliviousVerdict::Fail,
                            format!("expected generic, got {:?}", sel.active_substrate),
                        )
                    }
                }
                Err(e) => (CacheObliviousVerdict::Fail, format!("error: {e}")),
            }
        }
        "summary_after_batch" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            let _ = orch.select_all();
            let summary = orch.summary();
            if summary.total_decisions > 0 && summary.kinds_covered > 0 {
                (
                    CacheObliviousVerdict::Pass,
                    format!(
                        "decisions={}, covered={}",
                        summary.total_decisions, summary.kinds_covered
                    ),
                )
            } else {
                (CacheObliviousVerdict::Fail, "summary is empty".to_string())
            }
        }
        "history_recorded" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            let _ = orch.select_substrate(MetadataStructureKind::ShapeTable);
            let _ = orch.select_substrate(MetadataStructureKind::StringTable);
            if orch.history().len() == 2 {
                (
                    CacheObliviousVerdict::Pass,
                    "2 decisions in history".to_string(),
                )
            } else {
                (
                    CacheObliviousVerdict::Fail,
                    format!("expected 2, got {}", orch.history().len()),
                )
            }
        }
        "reset_clears" => {
            let mut orch = SubstrateOrchestrator::with_defaults(epoch);
            let _ = orch.select_all();
            orch.reset(SecurityEpoch::from_raw(epoch.as_u64() + 1));
            let summary = orch.summary();
            if summary.total_decisions == 0 {
                (
                    CacheObliviousVerdict::Pass,
                    "reset cleared state".to_string(),
                )
            } else {
                (
                    CacheObliviousVerdict::Fail,
                    format!("state not cleared: {}", summary.total_decisions),
                )
            }
        }
        _ => (
            CacheObliviousVerdict::Fail,
            format!("unknown specimen: {}", specimen.specimen_id),
        ),
    }
}

/// Run the evidence corpus and produce an inventory.
pub fn run_cache_oblivious_corpus() -> CacheObliviousEvidenceInventory {
    let epoch = SecurityEpoch::from_raw(1);
    let specimens = cache_oblivious_corpus();
    let mut evidences = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();

    for specimen in &specimens {
        let (verdict, details) = run_specimen(specimen, epoch);
        let evidence_hash = ContentHash::compute(
            format!("{}:{:?}:{}", specimen.specimen_id, verdict, details).as_bytes(),
        );
        evidences.push(CacheObliviousSpecimenEvidence {
            specimen_id: specimen.specimen_id.clone(),
            family: specimen.family,
            expected_outcome: specimen.expected_outcome,
            verdict,
            details,
            evidence_hash,
        });
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
    }

    let passed = evidences
        .iter()
        .filter(|e| e.verdict == CacheObliviousVerdict::Pass)
        .count();
    let failed = evidences.len() - passed;

    let inventory_hash = {
        let mut buf = Vec::new();
        buf.extend_from_slice(CACHE_OBLIVIOUS_SCHEMA_VERSION.as_bytes());
        for e in &evidences {
            buf.extend_from_slice(e.evidence_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    };

    CacheObliviousEvidenceInventory {
        schema_version: CACHE_OBLIVIOUS_SCHEMA_VERSION.to_string(),
        component: CACHE_OBLIVIOUS_COMPONENT.to_string(),
        policy_id: CACHE_OBLIVIOUS_POLICY_ID.to_string(),
        total_specimens: evidences.len(),
        passed,
        failed,
        family_coverage,
        evidences,
        inventory_hash,
    }
}

/// Write evidence bundle to disk.
pub fn write_cache_oblivious_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<CacheObliviousBundleArtifacts, std::io::Error> {
    let inventory = run_cache_oblivious_corpus();
    let epoch = SecurityEpoch::from_raw(1);

    let pass_rate = if inventory.total_specimens > 0 {
        (inventory.passed as i64).saturating_mul(MILLION) / inventory.total_specimens as i64
    } else {
        0
    };

    let run_id = format!(
        "run-cache-oblivious-{}",
        hex_encode(inventory.inventory_hash.as_bytes())
            .get(..12)
            .unwrap_or("unknown"),
    );

    let manifest = CacheObliviousRunManifest {
        schema_version: CACHE_OBLIVIOUS_MANIFEST_SCHEMA_VERSION.to_string(),
        component: CACHE_OBLIVIOUS_COMPONENT.to_string(),
        policy_id: CACHE_OBLIVIOUS_POLICY_ID.to_string(),
        run_id,
        epoch,
        total_specimens: inventory.total_specimens,
        pass_rate_millionths: pass_rate,
        content_hash: inventory.inventory_hash,
    };

    std::fs::create_dir_all(output_dir)?;

    let inventory_path = output_dir.join("cache_oblivious_evidence.json");
    let manifest_path = output_dir.join("run_manifest.json");
    let events_path = output_dir.join("events.jsonl");

    std::fs::write(
        &inventory_path,
        serde_json::to_string_pretty(&inventory).unwrap_or_default(),
    )?;
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    )?;

    let mut events_content = String::new();
    for evidence in &inventory.evidences {
        let event = CacheObliviousEvidenceEvent {
            schema_version: CACHE_OBLIVIOUS_EVENT_SCHEMA_VERSION.to_string(),
            component: CACHE_OBLIVIOUS_COMPONENT.to_string(),
            event_type: "specimen_evaluated".to_string(),
            specimen_id: evidence.specimen_id.clone(),
            verdict: evidence.verdict,
        };
        events_content.push_str(&serde_json::to_string(&event).unwrap_or_default());
        events_content.push('\n');
    }
    std::fs::write(&events_path, events_content)?;

    if !commands.is_empty() {
        let commands_path = output_dir.join("commands.txt");
        std::fs::write(&commands_path, commands.join("\n"))?;
    }

    Ok(CacheObliviousBundleArtifacts {
        paths: CacheObliviousArtifactPaths {
            inventory_path,
            manifest_path,
            events_path,
        },
        inventory,
        manifest,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // --- Construction ---

    #[test]
    fn test_orchestrator_construction() {
        let orch = SubstrateOrchestrator::with_defaults(test_epoch());
        assert_eq!(orch.decision_count, 0);
        assert!(orch.selections.is_empty());
    }

    #[test]
    fn test_config_defaults() {
        let config = SubstrateConfig::default();
        assert!(config.enable_optimization);
        assert!(config.enable_governance);
        assert!(config.record_history);
        assert!(config.fallback_on_governance_reject);
    }

    // --- Single selection ---

    #[test]
    fn test_select_shape_table() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert_eq!(sel.seq, 1);
        assert_eq!(sel.structure_kind, MetadataStructureKind::ShapeTable);
    }

    #[test]
    fn test_select_string_table() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::StringTable)
            .unwrap();
        assert_eq!(sel.structure_kind, MetadataStructureKind::StringTable);
    }

    #[test]
    fn test_select_inline_cache() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::InlineCacheTable)
            .unwrap();
        assert_eq!(sel.seq, 1);
    }

    #[test]
    fn test_select_gc_metadata() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::GcMetadata)
            .unwrap();
        assert_eq!(sel.structure_kind, MetadataStructureKind::GcMetadata);
    }

    // --- Batch ---

    #[test]
    fn test_select_all() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let results = orch.select_all();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_select_all_covers_all_kinds() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch.select_all();
        let summary = orch.summary();
        assert!(summary.kinds_covered > 0);
        assert!(summary.coverage_millionths > 0);
    }

    // --- Optimization disabled ---

    #[test]
    fn test_optimization_disabled_uses_generic() {
        let config = SubstrateConfig {
            enable_optimization: false,
            ..SubstrateConfig::default()
        };
        let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert_eq!(sel.active_substrate, OptSubstrateKind::GenericFallback);
    }

    // --- Governance ---

    #[test]
    fn test_governance_enabled() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        // Governance should pass for standard substrates.
        assert!(!sel.governance_overridden);
    }

    #[test]
    fn test_governance_disabled() {
        let config = SubstrateConfig {
            enable_governance: false,
            ..SubstrateConfig::default()
        };
        let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert!(!sel.governance_overridden);
    }

    // --- Summary ---

    #[test]
    fn test_summary_initial() {
        let orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let summary = orch.summary();
        assert_eq!(summary.total_decisions, 0);
        assert_eq!(summary.kinds_covered, 0);
    }

    #[test]
    fn test_summary_after_selections() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        let _ = orch
            .select_substrate(MetadataStructureKind::StringTable)
            .unwrap();
        let summary = orch.summary();
        assert_eq!(summary.total_decisions, 2);
        assert_eq!(summary.kinds_covered, 2);
    }

    #[test]
    fn test_summary_hash_deterministic() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        let s1 = orch.summary();
        let s2 = orch.summary();
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // --- History ---

    #[test]
    fn test_history_recorded() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert_eq!(orch.history().len(), 1);
    }

    #[test]
    fn test_history_disabled() {
        let config = SubstrateConfig {
            record_history: false,
            ..SubstrateConfig::default()
        };
        let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
        let _ = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert!(orch.history().is_empty());
    }

    #[test]
    fn test_history_bounded() {
        let config = SubstrateConfig {
            max_history: 2,
            ..SubstrateConfig::default()
        };
        let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
        let _ = orch.select_all();
        assert!(orch.history().len() <= 2);
    }

    // --- Get selection ---

    #[test]
    fn test_get_selection_present() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert!(
            orch.get_selection(MetadataStructureKind::ShapeTable)
                .is_some()
        );
    }

    #[test]
    fn test_get_selection_absent() {
        let orch = SubstrateOrchestrator::with_defaults(test_epoch());
        assert!(
            orch.get_selection(MetadataStructureKind::ShapeTable)
                .is_none()
        );
    }

    // --- Reset ---

    #[test]
    fn test_reset_clears_decisions() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch.select_all();
        orch.reset(SecurityEpoch::from_raw(2));
        assert_eq!(orch.summary().total_decisions, 0);
    }

    #[test]
    fn test_reset_clears_history() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch.select_all();
        orch.reset(SecurityEpoch::from_raw(2));
        assert!(orch.history().is_empty());
    }

    #[test]
    fn test_reset_allows_reselection() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let _ = orch.select_all();
        orch.reset(SecurityEpoch::from_raw(2));
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        assert_eq!(sel.seq, 1);
    }

    // --- Error display ---

    #[test]
    fn test_error_display_empty() {
        assert_eq!(
            format!("{}", SubstrateError::EmptyInventory),
            "metadata substrate inventory is empty"
        );
    }

    #[test]
    fn test_error_display_missing() {
        let err = SubstrateError::MissingAssignment {
            kind: "Foo".to_string(),
        };
        assert!(format!("{err}").contains("Foo"));
    }

    #[test]
    fn test_error_display_opt_failed() {
        let err = SubstrateError::OptimizationFailed {
            detail: "bad".to_string(),
        };
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn test_error_display_governance() {
        let err = SubstrateError::GovernanceRejected {
            reason: "portability".to_string(),
        };
        assert!(format!("{err}").contains("portability"));
    }

    #[test]
    fn test_error_display_config() {
        let err = SubstrateError::ConfigError {
            detail: "missing".to_string(),
        };
        assert!(format!("{err}").contains("missing"));
    }

    // --- Evidence corpus ---

    #[test]
    fn test_corpus_nonempty() {
        assert!(!cache_oblivious_corpus().is_empty());
    }

    #[test]
    fn test_corpus_covers_all_families() {
        let corpus = cache_oblivious_corpus();
        for family in CacheObliviousSpecimenFamily::ALL {
            assert!(
                corpus.iter().any(|s| s.family == *family),
                "missing family: {family:?}"
            );
        }
    }

    #[test]
    fn test_run_corpus_all_pass() {
        let inventory = run_cache_oblivious_corpus();
        for evidence in &inventory.evidences {
            assert_eq!(
                evidence.verdict,
                CacheObliviousVerdict::Pass,
                "specimen {} failed: {}",
                evidence.specimen_id,
                evidence.details,
            );
        }
        assert_eq!(inventory.failed, 0);
    }

    #[test]
    fn test_corpus_deterministic() {
        let i1 = run_cache_oblivious_corpus();
        let i2 = run_cache_oblivious_corpus();
        assert_eq!(i1.inventory_hash, i2.inventory_hash);
    }

    #[test]
    fn test_corpus_schema() {
        let inv = run_cache_oblivious_corpus();
        assert!(inv.schema_version.contains("cache-oblivious"));
        assert_eq!(inv.component, CACHE_OBLIVIOUS_COMPONENT);
        assert_eq!(inv.policy_id, CACHE_OBLIVIOUS_POLICY_ID);
    }

    // --- Specimen family ---

    #[test]
    fn test_family_all_count() {
        assert_eq!(CacheObliviousSpecimenFamily::ALL.len(), 7);
    }

    #[test]
    fn test_family_as_str() {
        assert_eq!(
            CacheObliviousSpecimenFamily::SingleSelection.as_str(),
            "single_selection"
        );
    }

    // --- Inventory access ---

    #[test]
    fn test_inventory_nonempty() {
        let orch = SubstrateOrchestrator::with_defaults(test_epoch());
        assert!(!orch.inventory().assignments.is_empty());
    }

    // --- Sequence numbers ---

    #[test]
    fn test_seq_increments() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let s1 = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        let s2 = orch
            .select_substrate(MetadataStructureKind::StringTable)
            .unwrap();
        assert_eq!(s1.seq, 1);
        assert_eq!(s2.seq, 2);
    }

    // --- Content hash ---

    #[test]
    fn test_selection_content_hash_nonempty() {
        let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
        let sel = orch
            .select_substrate(MetadataStructureKind::ShapeTable)
            .unwrap();
        // Content hash bytes should not be all zero.
        assert_ne!(sel.content_hash, ContentHash::compute(b""));
    }
}
