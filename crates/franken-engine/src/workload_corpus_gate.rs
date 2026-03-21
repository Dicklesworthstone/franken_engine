//! Workload corpus gate for performance claims.
//!
//! Manages an arbitrary-JS/TS workload corpus with explicit provenance,
//! selection logic, and behavior-equivalence verification so performance
//! claims are measured on workloads that resemble what users actually run.
//!
//! ## Design
//!
//! - **Workload families**: 16 canonical families covering the full
//!   performance-critical surface (regex, allocation churn, module
//!   resolution, megamorphic dispatch, etc.).
//! - **Provenance tracking**: every workload carries origin, license,
//!   selection rationale, and user-value justification.
//! - **Behavior equivalence**: performance claims are screened for semantic
//!   parity before publication — a faster wrong answer is not a win.
//! - **Verdict engine**: emit structured gate reports with pass/fail per
//!   family, aggregate corpus health, and evidence artifact hashes.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.8, bd-1lsy.8.4 (RGC-704).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "workload_corpus_gate";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.workload-corpus-gate.v1";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.4";

/// Maximum workloads per family for bounded analysis.
pub const MAX_WORKLOADS_PER_FAMILY: usize = 200;

/// Maximum total corpus size before overflow guard.
pub const MAX_CORPUS_SIZE: usize = 5000;

/// Minimum families required for a corpus to be considered representative.
pub const MIN_REQUIRED_FAMILIES: usize = 10;

/// Minimum workloads per family for coverage adequacy.
pub const MIN_WORKLOADS_PER_FAMILY: usize = 3;

/// Equivalence confidence threshold (millionths): 950_000 = 95%.
pub const EQUIVALENCE_CONFIDENCE_THRESHOLD: u64 = 950_000;

/// Maximum tolerable divergence ratio (millionths): 50_000 = 5%.
pub const MAX_DIVERGENCE_RATIO: u64 = 50_000;

// ---------------------------------------------------------------------------
// Workload family taxonomy
// ---------------------------------------------------------------------------

/// Canonical workload families covering the full performance-critical surface.
///
/// Each family represents a distinct performance axis that can dominate
/// real-world workloads. The taxonomy is grounded in the workload families
/// specified in RGC-704A.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFamily {
    /// Regex and Unicode text processing.
    RegexUnicode,
    /// String-heavy transform pipelines.
    StringTransform,
    /// Package-resolution-heavy npm graphs.
    NpmResolutionGraph,
    /// Allocation-churn-heavy object and iterator workloads.
    AllocationChurn,
    /// Branch-heavy megamorphic dispatch.
    MegamorphicDispatch,
    /// Vectorizable builtin kernels (array ops, JSON, etc.).
    VectorizableBuiltin,
    /// Resource-spiky effect or hostcall scenarios.
    HostcallSpike,
    /// Required native-addon packages.
    NativeAddon,
    /// Startup-storm and warm-image workloads.
    StartupStorm,
    /// Cache-miss-heavy metadata stressors.
    MetadataStress,
    /// Observability-sensitive telemetry variants.
    ObservabilitySensitive,
    /// Parse-heavy workloads (large AST generation).
    ParseHeavy,
    /// Async/promise-heavy event-loop workloads.
    AsyncHeavy,
    /// Module-graph-heavy resolution and linking.
    ModuleHeavy,
    /// TypeScript-heavy type erasure and normalization.
    TypeScriptHeavy,
    /// Mixed real-world application workloads.
    MixedRealWorld,
}

impl WorkloadFamily {
    /// All canonical families in deterministic order.
    pub const ALL: &'static [Self] = &[
        Self::RegexUnicode,
        Self::StringTransform,
        Self::NpmResolutionGraph,
        Self::AllocationChurn,
        Self::MegamorphicDispatch,
        Self::VectorizableBuiltin,
        Self::HostcallSpike,
        Self::NativeAddon,
        Self::StartupStorm,
        Self::MetadataStress,
        Self::ObservabilitySensitive,
        Self::ParseHeavy,
        Self::AsyncHeavy,
        Self::ModuleHeavy,
        Self::TypeScriptHeavy,
        Self::MixedRealWorld,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegexUnicode => "regex_unicode",
            Self::StringTransform => "string_transform",
            Self::NpmResolutionGraph => "npm_resolution_graph",
            Self::AllocationChurn => "allocation_churn",
            Self::MegamorphicDispatch => "megamorphic_dispatch",
            Self::VectorizableBuiltin => "vectorizable_builtin",
            Self::HostcallSpike => "hostcall_spike",
            Self::NativeAddon => "native_addon",
            Self::StartupStorm => "startup_storm",
            Self::MetadataStress => "metadata_stress",
            Self::ObservabilitySensitive => "observability_sensitive",
            Self::ParseHeavy => "parse_heavy",
            Self::AsyncHeavy => "async_heavy",
            Self::ModuleHeavy => "module_heavy",
            Self::TypeScriptHeavy => "typescript_heavy",
            Self::MixedRealWorld => "mixed_real_world",
        }
    }

    /// Human-readable description of what this family exercises.
    pub const fn description(self) -> &'static str {
        match self {
            Self::RegexUnicode => "Regex and Unicode text processing patterns",
            Self::StringTransform => "String-heavy transform and concatenation pipelines",
            Self::NpmResolutionGraph => "Package-resolution-heavy npm dependency graphs",
            Self::AllocationChurn => "Allocation-churn-heavy object and iterator workloads",
            Self::MegamorphicDispatch => "Branch-heavy megamorphic method dispatch",
            Self::VectorizableBuiltin => "Vectorizable builtin kernels (array ops, JSON, etc.)",
            Self::HostcallSpike => "Resource-spiky effect or hostcall scenarios",
            Self::NativeAddon => "Required native-addon packages (N-API surfaces)",
            Self::StartupStorm => "Startup-storm and warm-image cold/hot boot",
            Self::MetadataStress => "Cache-miss-heavy metadata and property stressors",
            Self::ObservabilitySensitive => "Observability-sensitive telemetry variants",
            Self::ParseHeavy => "Parse-heavy workloads with large AST generation",
            Self::AsyncHeavy => "Async/promise-heavy event-loop saturation",
            Self::ModuleHeavy => "Module-graph-heavy resolution, linking, and binding",
            Self::TypeScriptHeavy => "TypeScript-heavy type erasure and normalization",
            Self::MixedRealWorld => "Mixed real-world application patterns",
        }
    }
}

impl fmt::Display for WorkloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Origin category for a workload specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadOrigin {
    /// Published npm package.
    NpmPackage,
    /// Open-source project on GitHub/GitLab.
    OpenSourceProject,
    /// Standard benchmark suite (e.g., Octane, JetStream).
    BenchmarkSuite,
    /// Synthetic workload generated for coverage.
    Synthetic,
    /// Real user workload (anonymized).
    RealUserAnonymized,
    /// Internal test fixture.
    InternalFixture,
}

impl WorkloadOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NpmPackage => "npm_package",
            Self::OpenSourceProject => "open_source_project",
            Self::BenchmarkSuite => "benchmark_suite",
            Self::Synthetic => "synthetic",
            Self::RealUserAnonymized => "real_user_anonymized",
            Self::InternalFixture => "internal_fixture",
        }
    }
}

impl fmt::Display for WorkloadOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// License compatibility status for a workload specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseStatus {
    /// Permissive license (MIT, Apache-2.0, BSD).
    Permissive,
    /// Copyleft license (GPL, LGPL, AGPL).
    Copyleft,
    /// Proprietary or restricted.
    Restricted,
    /// License unknown or unverified.
    Unknown,
}

impl LicenseStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Copyleft => "copyleft",
            Self::Restricted => "restricted",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this license status is acceptable for benchmark publication.
    pub const fn is_publishable(self) -> bool {
        matches!(self, Self::Permissive)
    }
}

impl fmt::Display for LicenseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provenance record for a workload specimen.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadProvenance {
    /// Where the workload came from.
    pub origin: WorkloadOrigin,
    /// Source URL or identifier.
    pub source_url: String,
    /// License information.
    pub license: LicenseStatus,
    /// SPDX license identifier if known.
    pub spdx_id: Option<String>,
    /// Version or commit hash of the source.
    pub source_version: String,
    /// Why this workload was selected (user-value justification).
    pub selection_rationale: String,
    /// Content hash of the workload source.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Workload specimen
// ---------------------------------------------------------------------------

/// Observability mode under which a workload should be tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityMode {
    /// Default shipped budgeted telemetry.
    BudgetedDefault,
    /// Exact-shadow validation mode.
    ExactShadow,
    /// Degraded operation mode.
    Degraded,
    /// Incident/full-capture escalation.
    IncidentFullCapture,
}

impl ObservabilityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetedDefault => "budgeted_default",
            Self::ExactShadow => "exact_shadow",
            Self::Degraded => "degraded",
            Self::IncidentFullCapture => "incident_full_capture",
        }
    }
}

impl fmt::Display for ObservabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Input language type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputLanguage {
    JavaScript,
    TypeScript,
    Jsx,
    Tsx,
}

impl InputLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
        }
    }
}

impl fmt::Display for InputLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single workload specimen in the corpus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadSpecimen {
    /// Unique identifier within the corpus.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Primary workload family.
    pub family: WorkloadFamily,
    /// Secondary families exercised.
    pub secondary_families: BTreeSet<WorkloadFamily>,
    /// Input language.
    pub language: InputLanguage,
    /// Provenance record.
    pub provenance: WorkloadProvenance,
    /// Required observability modes for testing.
    pub observability_modes: BTreeSet<ObservabilityMode>,
    /// Expected approximate line count of the workload source.
    pub approximate_lines: u64,
    /// Whether this workload requires native addons.
    pub requires_native_addons: bool,
    /// Whether this workload exercises async/event-loop behavior.
    pub exercises_async: bool,
    /// Tags for filtering and grouping.
    pub tags: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Behavior equivalence
// ---------------------------------------------------------------------------

/// External baseline runtime for behavior comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineRuntime {
    NodeJs,
    Bun,
    Deno,
}

impl BaselineRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeJs => "node_js",
            Self::Bun => "bun",
            Self::Deno => "deno",
        }
    }
}

impl fmt::Display for BaselineRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classification of a behavioral divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceClass {
    /// Output is semantically identical.
    Identical,
    /// Output differs only in formatting/whitespace.
    CosmeticOnly,
    /// Output differs in observable but tolerable ways (e.g., error message wording).
    TolerableDivergence,
    /// Output differs in semantically meaningful ways.
    SemanticDivergence,
    /// One runtime crashes or errors while the other succeeds.
    CrashVsSuccess,
    /// Both error but with different error types.
    DifferentErrorType,
    /// Timeout divergence (one runtime hangs).
    TimeoutDivergence,
}

impl DivergenceClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identical => "identical",
            Self::CosmeticOnly => "cosmetic_only",
            Self::TolerableDivergence => "tolerable_divergence",
            Self::SemanticDivergence => "semantic_divergence",
            Self::CrashVsSuccess => "crash_vs_success",
            Self::DifferentErrorType => "different_error_type",
            Self::TimeoutDivergence => "timeout_divergence",
        }
    }

    /// Whether this divergence class is acceptable for publication.
    pub const fn is_acceptable(self) -> bool {
        matches!(
            self,
            Self::Identical | Self::CosmeticOnly | Self::TolerableDivergence
        )
    }

    /// Severity weight for aggregate scoring (millionths).
    pub const fn severity_weight_millionths(self) -> u64 {
        match self {
            Self::Identical => 0,
            Self::CosmeticOnly => 10_000,        // 1%
            Self::TolerableDivergence => 50_000, // 5%
            Self::SemanticDivergence => 500_000, // 50%
            Self::CrashVsSuccess => 1_000_000,   // 100%
            Self::DifferentErrorType => 300_000, // 30%
            Self::TimeoutDivergence => 800_000,  // 80%
        }
    }
}

impl fmt::Display for DivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of comparing a single workload against a baseline runtime.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EquivalenceResult {
    /// Workload specimen ID.
    pub specimen_id: String,
    /// Baseline runtime.
    pub baseline: BaselineRuntime,
    /// Classification of the divergence.
    pub divergence_class: DivergenceClass,
    /// Description of the divergence (if any).
    pub divergence_description: String,
    /// Whether FrankenEngine output hash matches baseline output hash.
    pub output_hash_matches: bool,
    /// FrankenEngine output content hash.
    pub franken_output_hash: ContentHash,
    /// Baseline output content hash.
    pub baseline_output_hash: ContentHash,
    /// Evidence artifact path (if captured).
    pub evidence_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// The workload corpus: a managed collection of specimens with provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadCorpus {
    /// Corpus version for schema evolution.
    pub version: String,
    /// All specimens indexed by ID.
    pub specimens: BTreeMap<String, WorkloadSpecimen>,
    /// Family coverage map: family -> set of specimen IDs.
    pub family_coverage: BTreeMap<WorkloadFamily, BTreeSet<String>>,
    /// Equivalence results indexed by (specimen_id, baseline).
    pub equivalence_results: Vec<EquivalenceResult>,
}

impl WorkloadCorpus {
    /// Create an empty corpus.
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            specimens: BTreeMap::new(),
            family_coverage: BTreeMap::new(),
            equivalence_results: Vec::new(),
        }
    }

    /// Add a specimen to the corpus.
    ///
    /// Returns an error if the corpus is full or the specimen ID is duplicate.
    pub fn add_specimen(&mut self, specimen: WorkloadSpecimen) -> Result<(), GateError> {
        if self.specimens.len() >= MAX_CORPUS_SIZE {
            return Err(GateError::CorpusOverflow {
                max: MAX_CORPUS_SIZE,
                attempted: self.specimens.len() + 1,
            });
        }
        let family = specimen.family;
        let id = specimen.id.clone();
        if self.specimens.contains_key(&id) {
            return Err(GateError::DuplicateSpecimen { id });
        }
        // Check per-family limit
        let family_count = self.family_coverage.get(&family).map_or(0, |s| s.len());
        if family_count >= MAX_WORKLOADS_PER_FAMILY {
            return Err(GateError::FamilyOverflow {
                family,
                max: MAX_WORKLOADS_PER_FAMILY,
                attempted: family_count + 1,
            });
        }
        self.family_coverage
            .entry(family)
            .or_default()
            .insert(id.clone());
        // Also register secondary families
        for secondary in &specimen.secondary_families {
            self.family_coverage
                .entry(*secondary)
                .or_default()
                .insert(id.clone());
        }
        self.specimens.insert(id, specimen);
        Ok(())
    }

    /// Remove a specimen by ID.
    pub fn remove_specimen(&mut self, id: &str) -> Option<WorkloadSpecimen> {
        let specimen = self.specimens.remove(id)?;
        // Clean up family coverage
        if let Some(ids) = self.family_coverage.get_mut(&specimen.family) {
            ids.remove(id);
            if ids.is_empty() {
                self.family_coverage.remove(&specimen.family);
            }
        }
        for secondary in &specimen.secondary_families {
            if let Some(ids) = self.family_coverage.get_mut(secondary) {
                ids.remove(id);
                if ids.is_empty() {
                    self.family_coverage.remove(secondary);
                }
            }
        }
        // Remove equivalence results for this specimen
        self.equivalence_results.retain(|r| r.specimen_id != id);
        Some(specimen)
    }

    /// Record an equivalence result.
    pub fn record_equivalence(&mut self, result: EquivalenceResult) {
        self.equivalence_results.push(result);
    }

    /// Number of specimens.
    pub fn specimen_count(&self) -> usize {
        self.specimens.len()
    }

    /// Number of families with at least one specimen.
    pub fn covered_family_count(&self) -> usize {
        self.family_coverage.len()
    }

    /// Families that have fewer than the minimum required workloads.
    pub fn undercovered_families(&self) -> BTreeMap<WorkloadFamily, usize> {
        let mut result = BTreeMap::new();
        for family in WorkloadFamily::ALL {
            let count = self.family_coverage.get(family).map_or(0, |s| s.len());
            if count < MIN_WORKLOADS_PER_FAMILY {
                result.insert(*family, count);
            }
        }
        result
    }

    /// Families with zero specimens.
    pub fn missing_families(&self) -> BTreeSet<WorkloadFamily> {
        let mut missing = BTreeSet::new();
        for family in WorkloadFamily::ALL {
            if !self.family_coverage.contains_key(family) {
                missing.insert(*family);
            }
        }
        missing
    }

    /// Compute a deterministic content hash over the entire corpus.
    pub fn content_hash(&self) -> ContentHash {
        let mut entries = Vec::new();
        for (id, specimen) in &self.specimens {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                ("id".to_string(), CanonicalValue::String(id.clone())),
                (
                    "family".to_string(),
                    CanonicalValue::String(specimen.family.as_str().to_string()),
                ),
                (
                    "language".to_string(),
                    CanonicalValue::String(specimen.language.as_str().to_string()),
                ),
                (
                    "content_hash".to_string(),
                    CanonicalValue::String(hex::encode(specimen.provenance.content_hash.0)),
                ),
            ])));
        }
        let canonical = CanonicalValue::Array(entries);
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }

    /// Specimens filtered by family.
    pub fn specimens_by_family(&self, family: WorkloadFamily) -> Vec<&WorkloadSpecimen> {
        self.family_coverage
            .get(&family)
            .map(|ids| ids.iter().filter_map(|id| self.specimens.get(id)).collect())
            .unwrap_or_default()
    }

    /// All specimens with unpublishable licenses.
    pub fn unpublishable_specimens(&self) -> Vec<&WorkloadSpecimen> {
        self.specimens
            .values()
            .filter(|s| !s.provenance.license.is_publishable())
            .collect()
    }
}

impl Default for WorkloadCorpus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

/// Configuration for the workload corpus gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum number of families required to pass the gate.
    pub min_families: usize,
    /// Minimum workloads per family.
    pub min_per_family: usize,
    /// Equivalence confidence threshold (millionths).
    pub equivalence_threshold: u64,
    /// Maximum tolerable divergence ratio (millionths).
    pub max_divergence_ratio: u64,
    /// Whether to require all specimens to have publishable licenses.
    pub require_publishable_licenses: bool,
    /// Whether to require observability mode coverage.
    pub require_observability_coverage: bool,
    /// Baselines to compare against.
    pub required_baselines: BTreeSet<BaselineRuntime>,
}

impl Default for GateConfig {
    fn default() -> Self {
        let mut baselines = BTreeSet::new();
        baselines.insert(BaselineRuntime::NodeJs);
        Self {
            min_families: MIN_REQUIRED_FAMILIES,
            min_per_family: MIN_WORKLOADS_PER_FAMILY,
            equivalence_threshold: EQUIVALENCE_CONFIDENCE_THRESHOLD,
            max_divergence_ratio: MAX_DIVERGENCE_RATIO,
            require_publishable_licenses: true,
            require_observability_coverage: false,
            required_baselines: baselines,
        }
    }
}

// ---------------------------------------------------------------------------
// Gate verdict
// ---------------------------------------------------------------------------

/// Reason why the gate rejected the corpus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Not enough families are covered.
    InsufficientFamilyCoverage { required: usize, actual: usize },
    /// A family has too few workloads.
    FamilyUndercovered {
        family: WorkloadFamily,
        required: usize,
        actual: usize,
    },
    /// Too many behavioral divergences.
    ExcessiveDivergence {
        divergence_ratio_millionths: u64,
        threshold: u64,
    },
    /// Unpublishable licenses detected.
    UnpublishableLicenses {
        count: usize,
        specimen_ids: Vec<String>,
    },
    /// Required baseline missing from equivalence results.
    MissingBaselineResults { baseline: BaselineRuntime },
    /// Corpus is empty.
    EmptyCorpus,
    /// Equivalence confidence below threshold.
    LowEquivalenceConfidence {
        confidence_millionths: u64,
        threshold: u64,
    },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientFamilyCoverage { required, actual } => {
                write!(
                    f,
                    "insufficient family coverage: {actual}/{required} families"
                )
            }
            Self::FamilyUndercovered {
                family,
                required,
                actual,
            } => {
                write!(
                    f,
                    "family {family} undercovered: {actual}/{required} specimens"
                )
            }
            Self::ExcessiveDivergence {
                divergence_ratio_millionths,
                threshold,
            } => {
                write!(
                    f,
                    "excessive divergence: {divergence_ratio_millionths}/1M > {threshold}/1M"
                )
            }
            Self::UnpublishableLicenses { count, .. } => {
                write!(f, "{count} specimens with unpublishable licenses")
            }
            Self::MissingBaselineResults { baseline } => {
                write!(f, "missing equivalence results for baseline: {baseline}")
            }
            Self::EmptyCorpus => write!(f, "corpus is empty"),
            Self::LowEquivalenceConfidence {
                confidence_millionths,
                threshold,
            } => {
                write!(
                    f,
                    "low equivalence confidence: {confidence_millionths}/1M < {threshold}/1M"
                )
            }
        }
    }
}

/// Overall gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Corpus passes the gate — performance claims may proceed.
    Pass,
    /// Corpus fails the gate — performance claims must be suppressed.
    Fail { reasons: Vec<RejectionReason> },
    /// Insufficient data to render a verdict.
    InsufficientData { reason: String },
}

impl GateVerdict {
    /// Whether the verdict permits publication.
    pub fn permits_publication(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reasons } => {
                write!(f, "FAIL ({} reasons)", reasons.len())
            }
            Self::InsufficientData { reason } => {
                write!(f, "INSUFFICIENT_DATA: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Family summary
// ---------------------------------------------------------------------------

/// Summary statistics for a single workload family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilySummary {
    /// The family.
    pub family: WorkloadFamily,
    /// Number of specimens in this family.
    pub specimen_count: usize,
    /// Number of equivalence results for this family.
    pub equivalence_count: usize,
    /// Number of acceptable divergences.
    pub acceptable_count: usize,
    /// Number of unacceptable divergences.
    pub unacceptable_count: usize,
    /// Equivalence rate (millionths).
    pub equivalence_rate_millionths: u64,
    /// Whether this family meets the minimum coverage threshold.
    pub meets_coverage: bool,
}

// ---------------------------------------------------------------------------
// Gate report
// ---------------------------------------------------------------------------

/// Full gate evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead reference.
    pub bead_id: String,
    /// Component name.
    pub component: String,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Corpus content hash.
    pub corpus_hash: ContentHash,
    /// Total specimens evaluated.
    pub total_specimens: usize,
    /// Total families covered.
    pub families_covered: usize,
    /// Missing families.
    pub missing_families: BTreeSet<WorkloadFamily>,
    /// Per-family summaries.
    pub family_summaries: Vec<FamilySummary>,
    /// Aggregate equivalence rate (millionths).
    pub aggregate_equivalence_rate_millionths: u64,
    /// Aggregate divergence severity (millionths).
    pub aggregate_divergence_severity_millionths: u64,
    /// Unpublishable specimen IDs.
    pub unpublishable_specimen_ids: Vec<String>,
    /// Number of equivalence results evaluated.
    pub equivalence_results_evaluated: usize,
}

// ---------------------------------------------------------------------------
// Gate evaluation
// ---------------------------------------------------------------------------

/// The workload corpus gate evaluator.
#[derive(Debug, Clone)]
pub struct WorkloadCorpusGate {
    config: GateConfig,
}

impl WorkloadCorpusGate {
    /// Create a gate with the given configuration.
    pub fn new(config: GateConfig) -> Self {
        Self { config }
    }

    /// Create a gate with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(GateConfig::default())
    }

    /// Evaluate the corpus and produce a gate report.
    pub fn evaluate(&self, corpus: &WorkloadCorpus) -> GateReport {
        let mut reasons = Vec::new();

        // Check for empty corpus
        if corpus.specimens.is_empty() {
            return GateReport {
                schema_version: SCHEMA_VERSION.to_string(),
                bead_id: BEAD_ID.to_string(),
                component: COMPONENT.to_string(),
                verdict: GateVerdict::Fail {
                    reasons: vec![RejectionReason::EmptyCorpus],
                },
                corpus_hash: corpus.content_hash(),
                total_specimens: 0,
                families_covered: 0,
                missing_families: corpus.missing_families(),
                family_summaries: Vec::new(),
                aggregate_equivalence_rate_millionths: 0,
                aggregate_divergence_severity_millionths: 0,
                unpublishable_specimen_ids: Vec::new(),
                equivalence_results_evaluated: 0,
            };
        }

        // Family coverage check
        let covered = corpus.covered_family_count();
        if covered < self.config.min_families {
            reasons.push(RejectionReason::InsufficientFamilyCoverage {
                required: self.config.min_families,
                actual: covered,
            });
        }

        // Per-family undercoverage check
        for family in WorkloadFamily::ALL {
            let count = corpus.family_coverage.get(family).map_or(0, |s| s.len());
            if count < self.config.min_per_family {
                reasons.push(RejectionReason::FamilyUndercovered {
                    family: *family,
                    required: self.config.min_per_family,
                    actual: count,
                });
            }
        }

        // License check
        if self.config.require_publishable_licenses {
            let unpublishable: Vec<String> = corpus
                .unpublishable_specimens()
                .iter()
                .map(|s| s.id.clone())
                .collect();
            if !unpublishable.is_empty() {
                reasons.push(RejectionReason::UnpublishableLicenses {
                    count: unpublishable.len(),
                    specimen_ids: unpublishable,
                });
            }
        }

        // Baseline coverage check
        let baselines_present: BTreeSet<BaselineRuntime> = corpus
            .equivalence_results
            .iter()
            .map(|r| r.baseline)
            .collect();
        for baseline in &self.config.required_baselines {
            if !baselines_present.contains(baseline) && !corpus.specimens.is_empty() {
                reasons.push(RejectionReason::MissingBaselineResults {
                    baseline: *baseline,
                });
            }
        }

        // Compute family summaries
        let family_summaries = self.compute_family_summaries(corpus);

        // Aggregate equivalence metrics
        let total_equiv = corpus.equivalence_results.len();
        let acceptable_count = corpus
            .equivalence_results
            .iter()
            .filter(|r| r.divergence_class.is_acceptable())
            .count();
        let aggregate_equiv_rate = if total_equiv > 0 {
            (acceptable_count as u64)
                .saturating_mul(1_000_000)
                .checked_div(total_equiv as u64)
                .unwrap_or(0)
        } else {
            0
        };

        // Aggregate divergence severity
        let total_severity: u64 = corpus
            .equivalence_results
            .iter()
            .map(|r| r.divergence_class.severity_weight_millionths())
            .sum();
        let avg_severity = if total_equiv > 0 {
            total_severity.checked_div(total_equiv as u64).unwrap_or(0)
        } else {
            0
        };

        // Divergence ratio check
        if total_equiv > 0 && avg_severity > self.config.max_divergence_ratio {
            reasons.push(RejectionReason::ExcessiveDivergence {
                divergence_ratio_millionths: avg_severity,
                threshold: self.config.max_divergence_ratio,
            });
        }

        // Equivalence confidence check
        if total_equiv > 0 && aggregate_equiv_rate < self.config.equivalence_threshold {
            reasons.push(RejectionReason::LowEquivalenceConfidence {
                confidence_millionths: aggregate_equiv_rate,
                threshold: self.config.equivalence_threshold,
            });
        }

        let unpublishable_ids: Vec<String> = corpus
            .unpublishable_specimens()
            .iter()
            .map(|s| s.id.clone())
            .collect();

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
            corpus_hash: corpus.content_hash(),
            total_specimens: corpus.specimen_count(),
            families_covered: covered,
            missing_families: corpus.missing_families(),
            family_summaries,
            aggregate_equivalence_rate_millionths: aggregate_equiv_rate,
            aggregate_divergence_severity_millionths: avg_severity,
            unpublishable_specimen_ids: unpublishable_ids,
            equivalence_results_evaluated: total_equiv,
        }
    }

    /// Compute per-family summaries.
    fn compute_family_summaries(&self, corpus: &WorkloadCorpus) -> Vec<FamilySummary> {
        let mut summaries = Vec::new();
        for family in WorkloadFamily::ALL {
            let specimen_ids = corpus
                .family_coverage
                .get(family)
                .cloned()
                .unwrap_or_default();
            let specimen_count = specimen_ids.len();

            let family_results: Vec<&EquivalenceResult> = corpus
                .equivalence_results
                .iter()
                .filter(|r| specimen_ids.contains(&r.specimen_id))
                .collect();

            let equivalence_count = family_results.len();
            let acceptable_count = family_results
                .iter()
                .filter(|r| r.divergence_class.is_acceptable())
                .count();
            let unacceptable_count = equivalence_count - acceptable_count;

            let equiv_rate = if equivalence_count > 0 {
                (acceptable_count as u64)
                    .saturating_mul(1_000_000)
                    .checked_div(equivalence_count as u64)
                    .unwrap_or(0)
            } else {
                0
            };

            summaries.push(FamilySummary {
                family: *family,
                specimen_count,
                equivalence_count,
                acceptable_count,
                unacceptable_count,
                equivalence_rate_millionths: equiv_rate,
                meets_coverage: specimen_count >= self.config.min_per_family,
            });
        }
        summaries
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from the workload corpus gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateError {
    /// Corpus size limit exceeded.
    CorpusOverflow { max: usize, attempted: usize },
    /// Duplicate specimen ID.
    DuplicateSpecimen { id: String },
    /// Family specimen limit exceeded.
    FamilyOverflow {
        family: WorkloadFamily,
        max: usize,
        attempted: usize,
    },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorpusOverflow { max, attempted } => {
                write!(f, "corpus overflow: {attempted} > {max}")
            }
            Self::DuplicateSpecimen { id } => {
                write!(f, "duplicate specimen: {id}")
            }
            Self::FamilyOverflow {
                family,
                max,
                attempted,
            } => {
                write!(f, "family {family} overflow: {attempted} > {max}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Seed corpus builder
// ---------------------------------------------------------------------------

/// Build a seed corpus with representative specimens for testing.
pub fn build_seed_corpus() -> WorkloadCorpus {
    let mut corpus = WorkloadCorpus::new();
    let families_with_specimens = [
        (
            WorkloadFamily::RegexUnicode,
            "regex_email_validator",
            "Email validation with Unicode support",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::StringTransform,
            "string_csv_parser",
            "CSV parsing with escaping and transforms",
            InputLanguage::TypeScript,
        ),
        (
            WorkloadFamily::NpmResolutionGraph,
            "npm_deep_dep_tree",
            "Deep npm dependency resolution graph",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::AllocationChurn,
            "alloc_linked_list_ops",
            "Linked-list allocation churn stress test",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::MegamorphicDispatch,
            "mega_shape_dispatch",
            "Megamorphic method dispatch across object shapes",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::VectorizableBuiltin,
            "vec_array_map_filter",
            "Array.map/filter/reduce chains over large arrays",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::HostcallSpike,
            "hostcall_fs_burst",
            "Filesystem hostcall burst with effect tracking",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::NativeAddon,
            "native_crypto_binding",
            "N-API crypto addon binding smoke test",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::StartupStorm,
            "startup_express_app",
            "Express.js-like application cold-start storm",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::MetadataStress,
            "meta_property_lookup",
            "Deep prototype chain property lookup stress",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::ObservabilitySensitive,
            "obs_telemetry_flood",
            "High-frequency telemetry emission under budget",
            InputLanguage::TypeScript,
        ),
        (
            WorkloadFamily::ParseHeavy,
            "parse_large_bundle",
            "Parsing a large bundled JS file (50k+ lines)",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::AsyncHeavy,
            "async_promise_chain",
            "Deep promise chain with async/await resolution",
            InputLanguage::TypeScript,
        ),
        (
            WorkloadFamily::ModuleHeavy,
            "module_graph_200",
            "200-module ESM import graph resolution",
            InputLanguage::JavaScript,
        ),
        (
            WorkloadFamily::TypeScriptHeavy,
            "ts_type_erasure_generic",
            "Generic type erasure with complex type narrowing",
            InputLanguage::TypeScript,
        ),
        (
            WorkloadFamily::MixedRealWorld,
            "mixed_todo_app",
            "Full-stack TODO app with API, DB, and rendering",
            InputLanguage::TypeScript,
        ),
    ];

    for (family, id, name, language) in &families_with_specimens {
        let specimen = WorkloadSpecimen {
            id: id.to_string(),
            name: name.to_string(),
            family: *family,
            secondary_families: BTreeSet::new(),
            language: *language,
            provenance: WorkloadProvenance {
                origin: WorkloadOrigin::InternalFixture,
                source_url: format!("internal://seed/{id}"),
                license: LicenseStatus::Permissive,
                spdx_id: Some("MIT".to_string()),
                source_version: "seed-v1".to_string(),
                selection_rationale: format!(
                    "Seed specimen for {} family: {}",
                    family.as_str(),
                    family.description()
                ),
                content_hash: ContentHash::compute(id.as_bytes()),
            },
            observability_modes: {
                let mut modes = BTreeSet::new();
                modes.insert(ObservabilityMode::BudgetedDefault);
                modes
            },
            approximate_lines: 100,
            requires_native_addons: *family == WorkloadFamily::NativeAddon,
            exercises_async: matches!(
                family,
                WorkloadFamily::AsyncHeavy | WorkloadFamily::HostcallSpike
            ),
            tags: {
                let mut tags = BTreeSet::new();
                tags.insert("seed".to_string());
                tags.insert(family.as_str().to_string());
                tags
            },
        };
        // Ignore errors for seed building
        let _ = corpus.add_specimen(specimen);
    }
    corpus
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_specimen(
        id: &str,
        family: WorkloadFamily,
        language: InputLanguage,
    ) -> WorkloadSpecimen {
        WorkloadSpecimen {
            id: id.to_string(),
            name: format!("Test workload {id}"),
            family,
            secondary_families: BTreeSet::new(),
            language,
            provenance: WorkloadProvenance {
                origin: WorkloadOrigin::InternalFixture,
                source_url: format!("test://{id}"),
                license: LicenseStatus::Permissive,
                spdx_id: Some("MIT".to_string()),
                source_version: "test-v1".to_string(),
                selection_rationale: "test specimen".to_string(),
                content_hash: ContentHash::compute(id.as_bytes()),
            },
            observability_modes: {
                let mut modes = BTreeSet::new();
                modes.insert(ObservabilityMode::BudgetedDefault);
                modes
            },
            approximate_lines: 50,
            requires_native_addons: false,
            exercises_async: false,
            tags: BTreeSet::new(),
        }
    }

    fn make_equivalence(
        specimen_id: &str,
        baseline: BaselineRuntime,
        class: DivergenceClass,
    ) -> EquivalenceResult {
        EquivalenceResult {
            specimen_id: specimen_id.to_string(),
            baseline,
            divergence_class: class,
            divergence_description: String::new(),
            output_hash_matches: class == DivergenceClass::Identical,
            franken_output_hash: ContentHash::compute(b"franken"),
            baseline_output_hash: ContentHash::compute(b"baseline"),
            evidence_path: None,
        }
    }

    // --- WorkloadFamily tests ---

    #[test]
    fn family_all_has_sixteen_entries() {
        assert_eq!(WorkloadFamily::ALL.len(), 16);
    }

    #[test]
    fn family_as_str_roundtrip() {
        for family in WorkloadFamily::ALL {
            let s = family.as_str();
            assert!(!s.is_empty());
            assert_eq!(family.to_string(), s);
        }
    }

    #[test]
    fn family_description_nonempty() {
        for family in WorkloadFamily::ALL {
            assert!(!family.description().is_empty());
        }
    }

    #[test]
    fn family_all_unique_names() {
        let names: BTreeSet<&str> = WorkloadFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), WorkloadFamily::ALL.len());
    }

    #[test]
    fn family_serde_roundtrip() {
        for family in WorkloadFamily::ALL {
            let json = serde_json::to_string(family).unwrap();
            let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*family, back);
        }
    }

    // --- WorkloadOrigin tests ---

    #[test]
    fn origin_as_str() {
        assert_eq!(WorkloadOrigin::NpmPackage.as_str(), "npm_package");
        assert_eq!(WorkloadOrigin::Synthetic.as_str(), "synthetic");
    }

    #[test]
    fn origin_display() {
        assert_eq!(
            format!("{}", WorkloadOrigin::BenchmarkSuite),
            "benchmark_suite"
        );
    }

    // --- LicenseStatus tests ---

    #[test]
    fn license_publishable() {
        assert!(LicenseStatus::Permissive.is_publishable());
        assert!(!LicenseStatus::Copyleft.is_publishable());
        assert!(!LicenseStatus::Restricted.is_publishable());
        assert!(!LicenseStatus::Unknown.is_publishable());
    }

    // --- ObservabilityMode tests ---

    #[test]
    fn observability_mode_as_str() {
        assert_eq!(
            ObservabilityMode::BudgetedDefault.as_str(),
            "budgeted_default"
        );
        assert_eq!(ObservabilityMode::ExactShadow.as_str(), "exact_shadow");
    }

    // --- InputLanguage tests ---

    #[test]
    fn input_language_as_str() {
        assert_eq!(InputLanguage::JavaScript.as_str(), "javascript");
        assert_eq!(InputLanguage::TypeScript.as_str(), "typescript");
        assert_eq!(InputLanguage::Jsx.as_str(), "jsx");
        assert_eq!(InputLanguage::Tsx.as_str(), "tsx");
    }

    // --- DivergenceClass tests ---

    #[test]
    fn divergence_acceptable() {
        assert!(DivergenceClass::Identical.is_acceptable());
        assert!(DivergenceClass::CosmeticOnly.is_acceptable());
        assert!(DivergenceClass::TolerableDivergence.is_acceptable());
        assert!(!DivergenceClass::SemanticDivergence.is_acceptable());
        assert!(!DivergenceClass::CrashVsSuccess.is_acceptable());
    }

    #[test]
    fn divergence_severity_ordering() {
        assert_eq!(DivergenceClass::Identical.severity_weight_millionths(), 0);
        assert!(
            DivergenceClass::CosmeticOnly.severity_weight_millionths()
                < DivergenceClass::SemanticDivergence.severity_weight_millionths()
        );
        assert!(
            DivergenceClass::SemanticDivergence.severity_weight_millionths()
                < DivergenceClass::CrashVsSuccess.severity_weight_millionths()
        );
    }

    #[test]
    fn divergence_serde_roundtrip() {
        let class = DivergenceClass::SemanticDivergence;
        let json = serde_json::to_string(&class).unwrap();
        let back: DivergenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }

    // --- BaselineRuntime tests ---

    #[test]
    fn baseline_as_str() {
        assert_eq!(BaselineRuntime::NodeJs.as_str(), "node_js");
        assert_eq!(BaselineRuntime::Bun.as_str(), "bun");
        assert_eq!(BaselineRuntime::Deno.as_str(), "deno");
    }

    // --- WorkloadCorpus tests ---

    #[test]
    fn empty_corpus() {
        let corpus = WorkloadCorpus::new();
        assert_eq!(corpus.specimen_count(), 0);
        assert_eq!(corpus.covered_family_count(), 0);
        assert_eq!(corpus.missing_families().len(), 16);
    }

    #[test]
    fn add_and_count_specimens() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        assert_eq!(corpus.specimen_count(), 1);
        assert_eq!(corpus.covered_family_count(), 1);
    }

    #[test]
    fn duplicate_specimen_rejected() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        let err = corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::AsyncHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap_err();
        assert!(matches!(err, GateError::DuplicateSpecimen { .. }));
    }

    #[test]
    fn remove_specimen() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        let removed = corpus.remove_specimen("s1");
        assert!(removed.is_some());
        assert_eq!(corpus.specimen_count(), 0);
        assert_eq!(corpus.covered_family_count(), 0);
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut corpus = WorkloadCorpus::new();
        assert!(corpus.remove_specimen("nonexistent").is_none());
    }

    #[test]
    fn secondary_families_tracked() {
        let mut corpus = WorkloadCorpus::new();
        let mut specimen = make_specimen(
            "s1",
            WorkloadFamily::MixedRealWorld,
            InputLanguage::TypeScript,
        );
        specimen
            .secondary_families
            .insert(WorkloadFamily::AsyncHeavy);
        specimen
            .secondary_families
            .insert(WorkloadFamily::ModuleHeavy);
        corpus.add_specimen(specimen).unwrap();
        assert_eq!(corpus.covered_family_count(), 3);
        assert_eq!(
            corpus.specimens_by_family(WorkloadFamily::AsyncHeavy).len(),
            1
        );
    }

    #[test]
    fn missing_families() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        let missing = corpus.missing_families();
        assert_eq!(missing.len(), 15); // 16 - 1
        assert!(!missing.contains(&WorkloadFamily::ParseHeavy));
    }

    #[test]
    fn undercovered_families() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        let under = corpus.undercovered_families();
        // ParseHeavy has 1 specimen but min is 3, so it's undercovered
        assert!(under.contains_key(&WorkloadFamily::ParseHeavy));
        assert_eq!(under[&WorkloadFamily::ParseHeavy], 1);
    }

    #[test]
    fn corpus_content_hash_deterministic() {
        let mut c1 = WorkloadCorpus::new();
        let mut c2 = WorkloadCorpus::new();
        c1.add_specimen(make_specimen(
            "a",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
        c1.add_specimen(make_specimen(
            "b",
            WorkloadFamily::AsyncHeavy,
            InputLanguage::TypeScript,
        ))
        .unwrap();
        c2.add_specimen(make_specimen(
            "a",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
        c2.add_specimen(make_specimen(
            "b",
            WorkloadFamily::AsyncHeavy,
            InputLanguage::TypeScript,
        ))
        .unwrap();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn corpus_content_hash_changes_with_content() {
        let mut c1 = WorkloadCorpus::new();
        let mut c2 = WorkloadCorpus::new();
        c1.add_specimen(make_specimen(
            "a",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
        c2.add_specimen(make_specimen(
            "b",
            WorkloadFamily::ParseHeavy,
            InputLanguage::JavaScript,
        ))
        .unwrap();
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn unpublishable_specimens() {
        let mut corpus = WorkloadCorpus::new();
        let mut spec = make_specimen("s1", WorkloadFamily::ParseHeavy, InputLanguage::JavaScript);
        spec.provenance.license = LicenseStatus::Copyleft;
        corpus.add_specimen(spec).unwrap();
        assert_eq!(corpus.unpublishable_specimens().len(), 1);
    }

    #[test]
    fn corpus_serde_roundtrip() {
        let corpus = build_seed_corpus();
        let json = serde_json::to_string(&corpus).unwrap();
        let back: WorkloadCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(corpus.specimen_count(), back.specimen_count());
        assert_eq!(corpus.content_hash(), back.content_hash());
    }

    #[test]
    fn default_corpus_is_empty() {
        let corpus = WorkloadCorpus::default();
        assert_eq!(corpus.specimen_count(), 0);
    }

    // --- Seed corpus tests ---

    #[test]
    fn seed_corpus_has_sixteen_families() {
        let corpus = build_seed_corpus();
        assert_eq!(corpus.specimen_count(), 16);
        assert_eq!(corpus.covered_family_count(), 16);
        assert!(corpus.missing_families().is_empty());
    }

    #[test]
    fn seed_corpus_all_permissive() {
        let corpus = build_seed_corpus();
        assert!(corpus.unpublishable_specimens().is_empty());
    }

    #[test]
    fn seed_corpus_content_hash_stable() {
        let c1 = build_seed_corpus();
        let c2 = build_seed_corpus();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    // --- GateConfig tests ---

    #[test]
    fn default_config_values() {
        let config = GateConfig::default();
        assert_eq!(config.min_families, MIN_REQUIRED_FAMILIES);
        assert_eq!(config.min_per_family, MIN_WORKLOADS_PER_FAMILY);
        assert!(config.required_baselines.contains(&BaselineRuntime::NodeJs));
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- GateVerdict tests ---

    #[test]
    fn pass_verdict_permits_publication() {
        assert!(GateVerdict::Pass.permits_publication());
    }

    #[test]
    fn fail_verdict_blocks_publication() {
        let v = GateVerdict::Fail {
            reasons: vec![RejectionReason::EmptyCorpus],
        };
        assert!(!v.permits_publication());
    }

    #[test]
    fn insufficient_data_blocks_publication() {
        let v = GateVerdict::InsufficientData {
            reason: "no data".to_string(),
        };
        assert!(!v.permits_publication());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Pass), "PASS");
        let fail = GateVerdict::Fail {
            reasons: vec![RejectionReason::EmptyCorpus],
        };
        assert!(format!("{fail}").contains("FAIL"));
    }

    // --- RejectionReason display tests ---

    #[test]
    fn rejection_reason_display() {
        let r = RejectionReason::InsufficientFamilyCoverage {
            required: 10,
            actual: 5,
        };
        assert!(format!("{r}").contains("5/10"));

        let r = RejectionReason::EmptyCorpus;
        assert!(format!("{r}").contains("empty"));
    }

    // --- Gate evaluation tests ---

    #[test]
    fn empty_corpus_fails_gate() {
        let gate = WorkloadCorpusGate::with_defaults();
        let corpus = WorkloadCorpus::new();
        let report = gate.evaluate(&corpus);
        assert!(!report.verdict.permits_publication());
    }

    #[test]
    fn seed_corpus_with_equivalence_passes() {
        let mut corpus = build_seed_corpus();
        // Add equivalence results for all specimens
        for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
            corpus.record_equivalence(make_equivalence(
                &id,
                BaselineRuntime::NodeJs,
                DivergenceClass::Identical,
            ));
        }
        let config = GateConfig {
            min_per_family: 1, // Seed has only 1 per family
            ..GateConfig::default()
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        assert!(report.verdict.permits_publication());
        assert_eq!(report.aggregate_equivalence_rate_millionths, 1_000_000);
    }

    #[test]
    fn semantic_divergence_fails_gate() {
        let mut corpus = build_seed_corpus();
        // Add all-divergent equivalence results
        for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
            corpus.record_equivalence(make_equivalence(
                &id,
                BaselineRuntime::NodeJs,
                DivergenceClass::SemanticDivergence,
            ));
        }
        let config = GateConfig {
            min_per_family: 1,
            ..GateConfig::default()
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        assert!(!report.verdict.permits_publication());
    }

    #[test]
    fn missing_baseline_fails_gate() {
        let corpus = build_seed_corpus();
        // No equivalence results at all
        let config = GateConfig {
            min_per_family: 1,
            ..GateConfig::default()
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        assert!(!report.verdict.permits_publication());
    }

    #[test]
    fn family_summaries_computed() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        corpus.record_equivalence(make_equivalence(
            "s1",
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
        let gate = WorkloadCorpusGate::with_defaults();
        let report = gate.evaluate(&corpus);
        let parse_summary = report
            .family_summaries
            .iter()
            .find(|s| s.family == WorkloadFamily::ParseHeavy)
            .unwrap();
        assert_eq!(parse_summary.specimen_count, 1);
        assert_eq!(parse_summary.equivalence_count, 1);
        assert_eq!(parse_summary.acceptable_count, 1);
        assert_eq!(parse_summary.equivalence_rate_millionths, 1_000_000);
    }

    #[test]
    fn gate_report_serde_roundtrip() {
        let gate = WorkloadCorpusGate::with_defaults();
        let corpus = build_seed_corpus();
        let report = gate.evaluate(&corpus);
        let json = serde_json::to_string(&report).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_specimens, back.total_specimens);
        assert_eq!(report.families_covered, back.families_covered);
    }

    #[test]
    fn copyleft_license_fails_publishable_gate() {
        let mut corpus = WorkloadCorpus::new();
        let mut spec = make_specimen("s1", WorkloadFamily::ParseHeavy, InputLanguage::JavaScript);
        spec.provenance.license = LicenseStatus::Copyleft;
        corpus.add_specimen(spec).unwrap();
        corpus.record_equivalence(make_equivalence(
            "s1",
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
        let gate = WorkloadCorpusGate::with_defaults();
        let report = gate.evaluate(&corpus);
        assert!(!report.verdict.permits_publication());
    }

    #[test]
    fn equivalence_result_serde_roundtrip() {
        let result = make_equivalence("s1", BaselineRuntime::NodeJs, DivergenceClass::Identical);
        let json = serde_json::to_string(&result).unwrap();
        let back: EquivalenceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.specimen_id, back.specimen_id);
        assert_eq!(result.divergence_class, back.divergence_class);
    }

    #[test]
    fn workload_specimen_serde_roundtrip() {
        let specimen = make_specimen("s1", WorkloadFamily::ParseHeavy, InputLanguage::JavaScript);
        let json = serde_json::to_string(&specimen).unwrap();
        let back: WorkloadSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(specimen.id, back.id);
        assert_eq!(specimen.family, back.family);
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let prov = WorkloadProvenance {
            origin: WorkloadOrigin::NpmPackage,
            source_url: "https://npmjs.com/foo".to_string(),
            license: LicenseStatus::Permissive,
            spdx_id: Some("MIT".to_string()),
            source_version: "1.0.0".to_string(),
            selection_rationale: "popular package".to_string(),
            content_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&prov).unwrap();
        let back: WorkloadProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(prov, back);
    }

    #[test]
    fn gate_error_display() {
        let e = GateError::CorpusOverflow {
            max: 100,
            attempted: 101,
        };
        assert!(format!("{e}").contains("101"));

        let e = GateError::DuplicateSpecimen {
            id: "foo".to_string(),
        };
        assert!(format!("{e}").contains("foo"));
    }

    #[test]
    fn overflow_guard_corpus() {
        let mut corpus = WorkloadCorpus::new();
        // Can't easily test MAX_CORPUS_SIZE (5000), but test the family limit
        for i in 0..MAX_WORKLOADS_PER_FAMILY {
            corpus
                .add_specimen(make_specimen(
                    &format!("s{i}"),
                    WorkloadFamily::ParseHeavy,
                    InputLanguage::JavaScript,
                ))
                .unwrap();
        }
        let err = corpus
            .add_specimen(make_specimen(
                "overflow",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap_err();
        assert!(matches!(err, GateError::FamilyOverflow { .. }));
    }

    #[test]
    fn mixed_divergences_produce_correct_rates() {
        let mut corpus = build_seed_corpus();
        let ids: Vec<String> = corpus.specimens.keys().cloned().collect();
        // Half identical, half semantic divergence
        for (i, id) in ids.iter().enumerate() {
            let class = if i.is_multiple_of(2) {
                DivergenceClass::Identical
            } else {
                DivergenceClass::SemanticDivergence
            };
            corpus.record_equivalence(make_equivalence(id, BaselineRuntime::NodeJs, class));
        }
        let config = GateConfig {
            min_per_family: 1,
            ..GateConfig::default()
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        // 8 acceptable out of 16 = 500_000
        assert_eq!(report.aggregate_equivalence_rate_millionths, 500_000);
    }

    #[test]
    fn remove_cleans_equivalence_results() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        corpus.record_equivalence(make_equivalence(
            "s1",
            BaselineRuntime::NodeJs,
            DivergenceClass::Identical,
        ));
        assert_eq!(corpus.equivalence_results.len(), 1);
        corpus.remove_specimen("s1");
        assert!(corpus.equivalence_results.is_empty());
    }

    #[test]
    fn gate_with_custom_baselines() {
        let mut corpus = build_seed_corpus();
        for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
            corpus.record_equivalence(make_equivalence(
                &id,
                BaselineRuntime::NodeJs,
                DivergenceClass::Identical,
            ));
            corpus.record_equivalence(make_equivalence(
                &id,
                BaselineRuntime::Bun,
                DivergenceClass::Identical,
            ));
        }
        let default_cfg = GateConfig::default();
        let mut baselines = default_cfg.required_baselines.clone();
        baselines.insert(BaselineRuntime::Bun);
        let config = GateConfig {
            min_per_family: 1,
            required_baselines: baselines,
            ..default_cfg
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        assert!(report.verdict.permits_publication());
    }

    #[test]
    fn cosmetic_divergence_still_passes() {
        let mut corpus = build_seed_corpus();
        for id in corpus.specimens.keys().cloned().collect::<Vec<_>>() {
            corpus.record_equivalence(make_equivalence(
                &id,
                BaselineRuntime::NodeJs,
                DivergenceClass::CosmeticOnly,
            ));
        }
        let config = GateConfig {
            min_per_family: 1,
            ..GateConfig::default()
        };
        let gate = WorkloadCorpusGate::new(config);
        let report = gate.evaluate(&corpus);
        assert!(report.verdict.permits_publication());
    }

    #[test]
    fn specimens_by_family_returns_correct_set() {
        let mut corpus = WorkloadCorpus::new();
        corpus
            .add_specimen(make_specimen(
                "s1",
                WorkloadFamily::ParseHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        corpus
            .add_specimen(make_specimen(
                "s2",
                WorkloadFamily::ParseHeavy,
                InputLanguage::TypeScript,
            ))
            .unwrap();
        corpus
            .add_specimen(make_specimen(
                "s3",
                WorkloadFamily::AsyncHeavy,
                InputLanguage::JavaScript,
            ))
            .unwrap();
        assert_eq!(
            corpus.specimens_by_family(WorkloadFamily::ParseHeavy).len(),
            2
        );
        assert_eq!(
            corpus.specimens_by_family(WorkloadFamily::AsyncHeavy).len(),
            1
        );
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.workload-corpus-gate.v1");
    }

    #[test]
    fn bead_id_constant() {
        assert_eq!(BEAD_ID, "bd-1lsy.8.4");
    }

    #[test]
    fn component_constant() {
        assert_eq!(COMPONENT, "workload_corpus_gate");
    }
}
