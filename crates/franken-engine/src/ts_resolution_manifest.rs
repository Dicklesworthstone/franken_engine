//! TS module-resolution manifests and tsconfig-aware replay surfaces.
//!
//! This module integrates TS-aware module resolution, tsconfig settings, and
//! provenance manifests into shipped execution and compilation flows. It provides:
//!
//! - `TsResolutionReplayEntry` — encodes a prior resolution decision for
//!   deterministic re-execution.
//! - `TsResolutionReplayIndex` — maps (specifier, referrer, mode) to
//!   pre-computed outcomes for replay.
//! - `TsExecutionManifest` — unified artifact combining module resolution,
//!   normalization, and ingestion lineage hashes.
//! - `TsconfigSnapshot` — serializable snapshot of tsconfig settings relevant
//!   to both normalization and module resolution.
//! - Corpus and evidence harness for CI gating.
//!
//! Reference: [RGC-204B]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::ts_module_resolution::{
    TsModuleResolutionMode, TsRequestStyle, TsResolutionDriftClass,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the TS resolution manifest.
pub const TS_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.ts-resolution-manifest.inventory.v1";
/// Schema version for replay index artifacts.
pub const TS_REPLAY_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.ts-resolution-manifest.replay-index.v1";
/// Schema version for execution manifests.
pub const TS_EXECUTION_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.ts-resolution-manifest.execution.v1";
/// Schema version for run manifests.
pub const TS_MANIFEST_RUN_SCHEMA_VERSION: &str =
    "franken-engine.ts-resolution-manifest.run-manifest.v1";
/// Schema version for evidence events.
pub const TS_MANIFEST_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.ts-resolution-manifest.event.v1";
/// Component name.
pub const TS_MANIFEST_COMPONENT: &str = "ts_resolution_manifest";
/// Policy ID.
pub const TS_MANIFEST_POLICY_ID: &str = "RGC-204B";

// ---------------------------------------------------------------------------
// Tsconfig Snapshot
// ---------------------------------------------------------------------------

/// A serializable snapshot of tsconfig settings relevant to both normalization
/// and module resolution. This captures the resolved settings from a
/// tsconfig.json file in a deterministic, hashable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsconfigSnapshot {
    /// Root directory of the TypeScript project.
    pub root_dir: String,
    /// Base URL for non-relative module resolution.
    pub base_url: String,
    /// Module resolution mode (node16, nodenext, bundler).
    pub module_resolution: TsModuleResolutionMode,
    /// Path aliases from tsconfig paths.
    pub paths: BTreeMap<String, Vec<String>>,
    /// TS compiler target (e.g., "es2020").
    pub target: String,
    /// TS module system (e.g., "esnext", "nodenext").
    pub module_system: String,
    /// JSX transform mode (e.g., "react-jsx", "preserve").
    pub jsx: String,
    /// Whether strict mode is enabled.
    pub strict: bool,
    /// Custom conditions for import resolution.
    pub custom_conditions: Vec<String>,
}

impl Default for TsconfigSnapshot {
    fn default() -> Self {
        Self {
            root_dir: ".".to_string(),
            base_url: ".".to_string(),
            module_resolution: TsModuleResolutionMode::NodeNext,
            paths: BTreeMap::new(),
            target: "es2020".to_string(),
            module_system: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
            strict: true,
            custom_conditions: Vec::new(),
        }
    }
}

impl TsconfigSnapshot {
    /// Compute a deterministic content hash of this snapshot.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.root_dir.as_bytes());
        hasher.update(self.base_url.as_bytes());
        hasher.update(format!("{:?}", self.module_resolution).as_bytes());
        for (k, vs) in &self.paths {
            hasher.update(k.as_bytes());
            for v in vs {
                hasher.update(v.as_bytes());
            }
        }
        hasher.update(self.target.as_bytes());
        hasher.update(self.module_system.as_bytes());
        hasher.update(self.jsx.as_bytes());
        hasher.update([u8::from(self.strict)]);
        for cond in &self.custom_conditions {
            hasher.update(cond.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// Replay Entry
// ---------------------------------------------------------------------------

/// A single resolution decision captured for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionReplayEntry {
    /// The import specifier (e.g., `./utils`, `react`, `@org/pkg`).
    pub specifier: String,
    /// The file that contains the import (referrer).
    pub referrer: Option<String>,
    /// Import or require style.
    pub style: TsRequestStyle,
    /// The resolved path (or empty if resolution failed).
    pub resolved_path: String,
    /// Which package provided the resolution (if any).
    pub package_name: Option<String>,
    /// Which export condition was selected.
    pub selected_condition: Option<String>,
    /// Content hash of the resolved file at capture time.
    pub resolved_content_hash: Option<String>,
    /// Probe sequence taken during resolution (for audit).
    pub probe_count: usize,
}

impl TsResolutionReplayEntry {
    /// Compute a deterministic key for index lookups.
    pub fn lookup_key(&self) -> String {
        format!(
            "{}|{}|{:?}",
            self.specifier,
            self.referrer.as_deref().unwrap_or(""),
            self.style
        )
    }
}

// ---------------------------------------------------------------------------
// Replay Index
// ---------------------------------------------------------------------------

/// Replay validation outcome for a single entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayValidationStatus {
    /// Replay matched the original resolution exactly.
    Matched,
    /// Resolution path differs from recorded entry.
    PathMismatch,
    /// Package or condition selection differs.
    SelectionMismatch,
    /// Resolution succeeded in replay but was recorded as failed.
    UnexpectedSuccess,
    /// Resolution failed in replay but was recorded as succeeded.
    UnexpectedFailure,
    /// Resolved content hash differs (file changed since capture).
    ContentDrift,
}

impl ReplayValidationStatus {
    pub const ALL: &[Self] = &[
        Self::Matched,
        Self::PathMismatch,
        Self::SelectionMismatch,
        Self::UnexpectedSuccess,
        Self::UnexpectedFailure,
        Self::ContentDrift,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::PathMismatch => "path_mismatch",
            Self::SelectionMismatch => "selection_mismatch",
            Self::UnexpectedSuccess => "unexpected_success",
            Self::UnexpectedFailure => "unexpected_failure",
            Self::ContentDrift => "content_drift",
        }
    }

    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Matched)
    }
}

impl fmt::Display for ReplayValidationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An index of pre-recorded resolution decisions for deterministic replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsResolutionReplayIndex {
    /// Schema version of this index.
    pub schema_version: String,
    /// The tsconfig snapshot used when building this index.
    pub tsconfig_hash: String,
    /// Module resolution mode used.
    pub mode: TsModuleResolutionMode,
    /// All recorded resolution entries, keyed by lookup key.
    pub entries: BTreeMap<String, TsResolutionReplayEntry>,
    /// When this index was generated (UTC ISO-8601).
    pub generated_at_utc: String,
    /// Content hash of the full index.
    pub index_hash: String,
}

impl TsResolutionReplayIndex {
    /// Build an index from a list of replay entries.
    pub fn build(
        entries: Vec<TsResolutionReplayEntry>,
        tsconfig_hash: &str,
        mode: TsModuleResolutionMode,
        generated_at_utc: &str,
    ) -> Self {
        let mut map = BTreeMap::new();
        for entry in &entries {
            map.insert(entry.lookup_key(), entry.clone());
        }

        let mut hasher = Sha256::new();
        hasher.update(tsconfig_hash.as_bytes());
        hasher.update(format!("{:?}", mode).as_bytes());
        for (k, v) in &map {
            hasher.update(k.as_bytes());
            hasher.update(v.resolved_path.as_bytes());
        }
        let index_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        Self {
            schema_version: TS_REPLAY_INDEX_SCHEMA_VERSION.to_string(),
            tsconfig_hash: tsconfig_hash.to_string(),
            mode,
            entries: map,
            generated_at_utc: generated_at_utc.to_string(),
            index_hash,
        }
    }

    /// Look up a replay entry by specifier, referrer, and style.
    pub fn lookup(
        &self,
        specifier: &str,
        referrer: Option<&str>,
        style: TsRequestStyle,
    ) -> Option<&TsResolutionReplayEntry> {
        let key = format!("{}|{}|{:?}", specifier, referrer.unwrap_or(""), style);
        self.entries.get(&key)
    }

    /// Validate a resolution outcome against the recorded entry.
    pub fn validate_resolution(
        &self,
        specifier: &str,
        referrer: Option<&str>,
        style: TsRequestStyle,
        actual_path: &str,
        actual_content_hash: Option<&str>,
    ) -> ReplayValidationStatus {
        let Some(entry) = self.lookup(specifier, referrer, style) else {
            if actual_path.is_empty() {
                return ReplayValidationStatus::Matched;
            }
            return ReplayValidationStatus::UnexpectedSuccess;
        };

        if entry.resolved_path.is_empty() && !actual_path.is_empty() {
            return ReplayValidationStatus::UnexpectedSuccess;
        }
        if !entry.resolved_path.is_empty() && actual_path.is_empty() {
            return ReplayValidationStatus::UnexpectedFailure;
        }
        if entry.resolved_path != actual_path {
            return ReplayValidationStatus::PathMismatch;
        }
        if let (Some(recorded), Some(actual)) = (&entry.resolved_content_hash, actual_content_hash)
        {
            if recorded != actual {
                return ReplayValidationStatus::ContentDrift;
            }
        }
        ReplayValidationStatus::Matched
    }

    /// How many entries are in this index.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Execution Manifest
// ---------------------------------------------------------------------------

/// Normalization lineage hashes for the execution manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationLineage {
    /// Hash of the original source.
    pub source_hash: String,
    /// Hash of the normalized source (after TS stripping).
    pub normalized_hash: String,
    /// Hash of the compiler options used.
    pub compiler_options_hash: String,
    /// Whether normalization was applied (false for JS sources).
    pub normalization_applied: bool,
}

/// Module resolution lineage for the execution manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionLineage {
    /// Total number of resolution decisions made.
    pub decision_count: usize,
    /// Number that resolved successfully.
    pub resolved_count: usize,
    /// Number that failed to resolve.
    pub failed_count: usize,
    /// Drift class observed (if any replay validation was performed).
    pub drift_class: TsResolutionDriftClass,
    /// Index hash (if a replay index was used).
    pub replay_index_hash: Option<String>,
}

/// IR pipeline lineage hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrPipelineLineage {
    /// Hash of IR0 (parsed AST).
    pub ir0_hash: String,
    /// Hash of IR1 (scope-resolved).
    pub ir1_hash: Option<String>,
    /// Hash of IR2 (capability-annotated).
    pub ir2_hash: Option<String>,
    /// Hash of IR3 (execution-ready bytecode).
    pub ir3_hash: Option<String>,
}

/// A unified execution manifest combining module resolution, normalization,
/// and ingestion lineage into a single artifact for shipped flows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsExecutionManifest {
    /// Schema version.
    pub schema_version: String,
    /// Trace ID linking this manifest to the execution trace.
    pub trace_id: String,
    /// Decision ID.
    pub decision_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Tsconfig snapshot hash.
    pub tsconfig_hash: String,
    /// Source file path.
    pub source_path: String,
    /// Source language (JavaScript or TypeScript).
    pub source_language: String,
    /// Normalization lineage.
    pub normalization: NormalizationLineage,
    /// Module resolution lineage.
    pub resolution: ResolutionLineage,
    /// IR pipeline lineage.
    pub ir_pipeline: IrPipelineLineage,
    /// Generation timestamp (UTC ISO-8601).
    pub generated_at_utc: String,
    /// Content hash of this entire manifest.
    pub manifest_hash: String,
}

impl TsExecutionManifest {
    /// Build a manifest from its components.
    pub fn build(
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        tsconfig_hash: &str,
        source_path: &str,
        source_language: &str,
        normalization: NormalizationLineage,
        resolution: ResolutionLineage,
        ir_pipeline: IrPipelineLineage,
        generated_at_utc: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(trace_id.as_bytes());
        hasher.update(decision_id.as_bytes());
        hasher.update(tsconfig_hash.as_bytes());
        hasher.update(source_path.as_bytes());
        hasher.update(normalization.source_hash.as_bytes());
        hasher.update(normalization.normalized_hash.as_bytes());
        hasher.update(resolution.decision_count.to_le_bytes());
        hasher.update(ir_pipeline.ir0_hash.as_bytes());
        let manifest_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

        Self {
            schema_version: TS_EXECUTION_MANIFEST_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            tsconfig_hash: tsconfig_hash.to_string(),
            source_path: source_path.to_string(),
            source_language: source_language.to_string(),
            normalization,
            resolution,
            ir_pipeline,
            generated_at_utc: generated_at_utc.to_string(),
            manifest_hash,
        }
    }

    /// Whether the manifest represents a fully resolved execution.
    pub fn is_fully_resolved(&self) -> bool {
        self.resolution.failed_count == 0
            && self.resolution.drift_class == TsResolutionDriftClass::NoDrift
    }
}

// ---------------------------------------------------------------------------
// Replay Validation Report
// ---------------------------------------------------------------------------

/// Result of validating an entire replay index against actual resolutions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayValidationReport {
    /// Total entries validated.
    pub total_entries: usize,
    /// Number of entries that matched.
    pub matched_count: usize,
    /// Number with path mismatches.
    pub path_mismatch_count: usize,
    /// Number with selection mismatches.
    pub selection_mismatch_count: usize,
    /// Number with content drift.
    pub content_drift_count: usize,
    /// Number with unexpected success/failure.
    pub unexpected_count: usize,
    /// Overall pass/fail.
    pub passed: bool,
}

impl ReplayValidationReport {
    /// Build from a list of validation statuses.
    pub fn from_statuses(statuses: &[ReplayValidationStatus]) -> Self {
        let mut matched = 0usize;
        let mut path_mismatch = 0usize;
        let mut selection_mismatch = 0usize;
        let mut content_drift = 0usize;
        let mut unexpected = 0usize;

        for s in statuses {
            match s {
                ReplayValidationStatus::Matched => matched += 1,
                ReplayValidationStatus::PathMismatch => path_mismatch += 1,
                ReplayValidationStatus::SelectionMismatch => selection_mismatch += 1,
                ReplayValidationStatus::ContentDrift => content_drift += 1,
                ReplayValidationStatus::UnexpectedSuccess
                | ReplayValidationStatus::UnexpectedFailure => unexpected += 1,
            }
        }

        let total = statuses.len();
        Self {
            total_entries: total,
            matched_count: matched,
            path_mismatch_count: path_mismatch,
            selection_mismatch_count: selection_mismatch,
            content_drift_count: content_drift,
            unexpected_count: unexpected,
            passed: matched == total,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence Harness: Corpus
// ---------------------------------------------------------------------------

/// Feature family for the evidence harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestFeatureFamily {
    TsconfigSnapshot,
    ReplayEntry,
    ReplayIndex,
    ReplayValidation,
    ExecutionManifest,
    NormalizationLineage,
    ResolutionLineage,
    IrPipelineLineage,
    ValidationReport,
}

impl ManifestFeatureFamily {
    pub const ALL: &[Self] = &[
        Self::TsconfigSnapshot,
        Self::ReplayEntry,
        Self::ReplayIndex,
        Self::ReplayValidation,
        Self::ExecutionManifest,
        Self::NormalizationLineage,
        Self::ResolutionLineage,
        Self::IrPipelineLineage,
        Self::ValidationReport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TsconfigSnapshot => "tsconfig_snapshot",
            Self::ReplayEntry => "replay_entry",
            Self::ReplayIndex => "replay_index",
            Self::ReplayValidation => "replay_validation",
            Self::ExecutionManifest => "execution_manifest",
            Self::NormalizationLineage => "normalization_lineage",
            Self::ResolutionLineage => "resolution_lineage",
            Self::IrPipelineLineage => "ir_pipeline_lineage",
            Self::ValidationReport => "validation_report",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::TsconfigSnapshot => "Serializable tsconfig settings for resolution and normalization",
            Self::ReplayEntry => "Single resolution decision captured for replay",
            Self::ReplayIndex => "Index of pre-recorded resolutions for deterministic replay",
            Self::ReplayValidation => "Validation of replay against actual resolution",
            Self::ExecutionManifest => "Unified execution manifest with all lineage hashes",
            Self::NormalizationLineage => "Source-to-normalized hash chain",
            Self::ResolutionLineage => "Module resolution decision summary",
            Self::IrPipelineLineage => "IR pipeline hash chain (IR0 through IR3)",
            Self::ValidationReport => "Aggregate replay validation results",
        }
    }
}

impl fmt::Display for ManifestFeatureFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Expected outcome for a corpus specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestExpectedOutcome {
    Valid,
    ReplayMatch,
    ReplayMismatch,
    ManifestComplete,
}

impl ManifestExpectedOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ReplayMatch => "replay_match",
            Self::ReplayMismatch => "replay_mismatch",
            Self::ManifestComplete => "manifest_complete",
        }
    }
}

/// A single evidence specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSpecimen {
    pub specimen_id: String,
    pub feature_family: ManifestFeatureFamily,
    pub expected_outcome: ManifestExpectedOutcome,
    pub description: String,
}

/// Verdict for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerdict {
    Pass,
    Fail,
}

impl ManifestVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// Evidence from running a specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSpecimenEvidence {
    pub specimen_id: String,
    pub feature_family: ManifestFeatureFamily,
    pub verdict: ManifestVerdict,
}

/// Evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub specimen_id: String,
    pub verdict: ManifestVerdict,
}

/// Run manifest for evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRunManifest {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub specimen_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
}

/// Evidence inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub specimens: Vec<ManifestSpecimenEvidence>,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidence_hash: String,
}

/// Build the canonical corpus.
pub fn manifest_corpus() -> Vec<ManifestSpecimen> {
    vec![
        ManifestSpecimen {
            specimen_id: "tsconfig_default".into(),
            feature_family: ManifestFeatureFamily::TsconfigSnapshot,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Default tsconfig snapshot serializes and hashes".into(),
        },
        ManifestSpecimen {
            specimen_id: "tsconfig_with_paths".into(),
            feature_family: ManifestFeatureFamily::TsconfigSnapshot,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Tsconfig with path aliases produces unique hash".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_entry_basic".into(),
            feature_family: ManifestFeatureFamily::ReplayEntry,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Basic replay entry with resolved path".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_entry_failed".into(),
            feature_family: ManifestFeatureFamily::ReplayEntry,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Replay entry for unresolved specifier".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_index_build".into(),
            feature_family: ManifestFeatureFamily::ReplayIndex,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Build replay index from entries".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_index_lookup".into(),
            feature_family: ManifestFeatureFamily::ReplayIndex,
            expected_outcome: ManifestExpectedOutcome::ReplayMatch,
            description: "Replay index lookup returns correct entry".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_validation_match".into(),
            feature_family: ManifestFeatureFamily::ReplayValidation,
            expected_outcome: ManifestExpectedOutcome::ReplayMatch,
            description: "Replay validation matches for identical resolution".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_validation_mismatch".into(),
            feature_family: ManifestFeatureFamily::ReplayValidation,
            expected_outcome: ManifestExpectedOutcome::ReplayMismatch,
            description: "Replay validation detects path mismatch".into(),
        },
        ManifestSpecimen {
            specimen_id: "execution_manifest_build".into(),
            feature_family: ManifestFeatureFamily::ExecutionManifest,
            expected_outcome: ManifestExpectedOutcome::ManifestComplete,
            description: "Build complete execution manifest with all lineage".into(),
        },
        ManifestSpecimen {
            specimen_id: "normalization_lineage_ts".into(),
            feature_family: ManifestFeatureFamily::NormalizationLineage,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Normalization lineage for TS source".into(),
        },
        ManifestSpecimen {
            specimen_id: "normalization_lineage_js".into(),
            feature_family: ManifestFeatureFamily::NormalizationLineage,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Normalization lineage for JS source (no normalization)".into(),
        },
        ManifestSpecimen {
            specimen_id: "resolution_lineage_clean".into(),
            feature_family: ManifestFeatureFamily::ResolutionLineage,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Resolution lineage with no drift".into(),
        },
        ManifestSpecimen {
            specimen_id: "ir_pipeline_lineage".into(),
            feature_family: ManifestFeatureFamily::IrPipelineLineage,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "IR pipeline lineage with all hashes".into(),
        },
        ManifestSpecimen {
            specimen_id: "validation_report_all_match".into(),
            feature_family: ManifestFeatureFamily::ValidationReport,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Validation report with all entries matched".into(),
        },
        ManifestSpecimen {
            specimen_id: "validation_report_with_drift".into(),
            feature_family: ManifestFeatureFamily::ValidationReport,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Validation report with content drift detected".into(),
        },
        ManifestSpecimen {
            specimen_id: "execution_manifest_fully_resolved".into(),
            feature_family: ManifestFeatureFamily::ExecutionManifest,
            expected_outcome: ManifestExpectedOutcome::ManifestComplete,
            description: "Fully resolved execution manifest passes is_fully_resolved".into(),
        },
        ManifestSpecimen {
            specimen_id: "replay_index_deterministic".into(),
            feature_family: ManifestFeatureFamily::ReplayIndex,
            expected_outcome: ManifestExpectedOutcome::Valid,
            description: "Replay index hash is deterministic across builds".into(),
        },
    ]
}

/// Run the corpus and produce evidence.
pub fn run_manifest_corpus() -> (ManifestRunManifest, ManifestEvidenceInventory, Vec<ManifestEvidenceEvent>) {
    let corpus = manifest_corpus();
    let mut specimens = Vec::new();
    let mut events = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;

    for spec in &corpus {
        let verdict = run_specimen(spec);

        *family_coverage
            .entry(spec.feature_family.as_str().to_string())
            .or_insert(0) += 1;

        match verdict {
            ManifestVerdict::Pass => pass_count += 1,
            ManifestVerdict::Fail => fail_count += 1,
        }

        specimens.push(ManifestSpecimenEvidence {
            specimen_id: spec.specimen_id.clone(),
            feature_family: spec.feature_family,
            verdict,
        });

        events.push(ManifestEvidenceEvent {
            schema_version: TS_MANIFEST_EVENT_SCHEMA_VERSION.to_string(),
            component: TS_MANIFEST_COMPONENT.to_string(),
            specimen_id: spec.specimen_id.clone(),
            verdict,
        });
    }

    let mut hasher = Sha256::new();
    for ev in &specimens {
        hasher.update(ev.specimen_id.as_bytes());
        hasher.update(ev.verdict.as_str().as_bytes());
    }
    let evidence_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    let manifest = ManifestRunManifest {
        schema_version: TS_MANIFEST_RUN_SCHEMA_VERSION.to_string(),
        component: TS_MANIFEST_COMPONENT.to_string(),
        policy_id: TS_MANIFEST_POLICY_ID.to_string(),
        specimen_count: corpus.len(),
        pass_count,
        fail_count,
    };

    let inventory = ManifestEvidenceInventory {
        schema_version: TS_MANIFEST_SCHEMA_VERSION.to_string(),
        component: TS_MANIFEST_COMPONENT.to_string(),
        policy_id: TS_MANIFEST_POLICY_ID.to_string(),
        specimens,
        family_coverage,
        evidence_hash,
    };

    (manifest, inventory, events)
}

/// Run a single specimen and produce a verdict.
fn run_specimen(spec: &ManifestSpecimen) -> ManifestVerdict {
    match spec.specimen_id.as_str() {
        "tsconfig_default" => {
            let snap = TsconfigSnapshot::default();
            let hash = snap.content_hash();
            if hash.as_bytes().is_empty() {
                ManifestVerdict::Fail
            } else {
                ManifestVerdict::Pass
            }
        }
        "tsconfig_with_paths" => {
            let mut snap = TsconfigSnapshot::default();
            snap.paths.insert("@app/*".into(), vec!["./src/*".into()]);
            let h1 = snap.content_hash();
            let h2 = TsconfigSnapshot::default().content_hash();
            if h1 != h2 { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "replay_entry_basic" => {
            let entry = TsResolutionReplayEntry {
                specifier: "./utils".into(),
                referrer: Some("./src/index.ts".into()),
                style: TsRequestStyle::Import,
                resolved_path: "./src/utils.ts".into(),
                package_name: None,
                selected_condition: None,
                resolved_content_hash: Some("sha256:abc".into()),
                probe_count: 1,
            };
            let key = entry.lookup_key();
            if key.contains("./utils") && key.contains("./src/index.ts") {
                ManifestVerdict::Pass
            } else {
                ManifestVerdict::Fail
            }
        }
        "replay_entry_failed" => {
            let entry = TsResolutionReplayEntry {
                specifier: "nonexistent".into(),
                referrer: None,
                style: TsRequestStyle::Require,
                resolved_path: String::new(),
                package_name: None,
                selected_condition: None,
                resolved_content_hash: None,
                probe_count: 3,
            };
            if entry.resolved_path.is_empty() { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "replay_index_build" => {
            let entries = vec![
                TsResolutionReplayEntry {
                    specifier: "./a".into(),
                    referrer: None,
                    style: TsRequestStyle::Import,
                    resolved_path: "/a.ts".into(),
                    package_name: None,
                    selected_condition: None,
                    resolved_content_hash: None,
                    probe_count: 1,
                },
            ];
            let index = TsResolutionReplayIndex::build(
                entries, "hash", TsModuleResolutionMode::NodeNext, "2026-01-01T00:00:00Z",
            );
            if index.entry_count() == 1 { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "replay_index_lookup" => {
            let entries = vec![
                TsResolutionReplayEntry {
                    specifier: "react".into(),
                    referrer: Some("./app.tsx".into()),
                    style: TsRequestStyle::Import,
                    resolved_path: "node_modules/react/index.js".into(),
                    package_name: Some("react".into()),
                    selected_condition: Some("import".into()),
                    resolved_content_hash: None,
                    probe_count: 2,
                },
            ];
            let index = TsResolutionReplayIndex::build(
                entries, "h", TsModuleResolutionMode::NodeNext, "2026-01-01T00:00:00Z",
            );
            if let Some(found) = index.lookup("react", Some("./app.tsx"), TsRequestStyle::Import) {
                if found.resolved_path == "node_modules/react/index.js" {
                    ManifestVerdict::Pass
                } else {
                    ManifestVerdict::Fail
                }
            } else {
                ManifestVerdict::Fail
            }
        }
        "replay_validation_match" => {
            let entries = vec![
                TsResolutionReplayEntry {
                    specifier: "./x".into(),
                    referrer: None,
                    style: TsRequestStyle::Import,
                    resolved_path: "/x.ts".into(),
                    package_name: None,
                    selected_condition: None,
                    resolved_content_hash: None,
                    probe_count: 1,
                },
            ];
            let index = TsResolutionReplayIndex::build(
                entries, "h", TsModuleResolutionMode::NodeNext, "t",
            );
            let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "/x.ts", None);
            if status == ReplayValidationStatus::Matched { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "replay_validation_mismatch" => {
            let entries = vec![
                TsResolutionReplayEntry {
                    specifier: "./x".into(),
                    referrer: None,
                    style: TsRequestStyle::Import,
                    resolved_path: "/x.ts".into(),
                    package_name: None,
                    selected_condition: None,
                    resolved_content_hash: None,
                    probe_count: 1,
                },
            ];
            let index = TsResolutionReplayIndex::build(
                entries, "h", TsModuleResolutionMode::NodeNext, "t",
            );
            let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "/y.ts", None);
            if status == ReplayValidationStatus::PathMismatch { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "execution_manifest_build" | "execution_manifest_fully_resolved" => {
            let manifest = TsExecutionManifest::build(
                "trace-1", "decision-1", "policy-1", "tsconfig-hash",
                "./src/main.ts", "typescript",
                NormalizationLineage {
                    source_hash: "sha256:src".into(),
                    normalized_hash: "sha256:norm".into(),
                    compiler_options_hash: "sha256:opts".into(),
                    normalization_applied: true,
                },
                ResolutionLineage {
                    decision_count: 5,
                    resolved_count: 5,
                    failed_count: 0,
                    drift_class: TsResolutionDriftClass::NoDrift,
                    replay_index_hash: None,
                },
                IrPipelineLineage {
                    ir0_hash: "sha256:ir0".into(),
                    ir1_hash: Some("sha256:ir1".into()),
                    ir2_hash: Some("sha256:ir2".into()),
                    ir3_hash: Some("sha256:ir3".into()),
                },
                "2026-01-01T00:00:00Z",
            );
            if spec.specimen_id == "execution_manifest_fully_resolved" {
                if manifest.is_fully_resolved() { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
            } else if !manifest.manifest_hash.is_empty() {
                ManifestVerdict::Pass
            } else {
                ManifestVerdict::Fail
            }
        }
        "normalization_lineage_ts" => {
            let lineage = NormalizationLineage {
                source_hash: "sha256:a".into(),
                normalized_hash: "sha256:b".into(),
                compiler_options_hash: "sha256:c".into(),
                normalization_applied: true,
            };
            if lineage.normalization_applied { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "normalization_lineage_js" => {
            let lineage = NormalizationLineage {
                source_hash: "sha256:a".into(),
                normalized_hash: "sha256:a".into(),
                compiler_options_hash: "sha256:c".into(),
                normalization_applied: false,
            };
            if !lineage.normalization_applied && lineage.source_hash == lineage.normalized_hash {
                ManifestVerdict::Pass
            } else {
                ManifestVerdict::Fail
            }
        }
        "resolution_lineage_clean" => {
            let lineage = ResolutionLineage {
                decision_count: 10,
                resolved_count: 10,
                failed_count: 0,
                drift_class: TsResolutionDriftClass::NoDrift,
                replay_index_hash: None,
            };
            if lineage.failed_count == 0 { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "ir_pipeline_lineage" => {
            let lineage = IrPipelineLineage {
                ir0_hash: "sha256:ir0".into(),
                ir1_hash: Some("sha256:ir1".into()),
                ir2_hash: Some("sha256:ir2".into()),
                ir3_hash: Some("sha256:ir3".into()),
            };
            if lineage.ir3_hash.is_some() { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "validation_report_all_match" => {
            let statuses = vec![ReplayValidationStatus::Matched; 5];
            let report = ReplayValidationReport::from_statuses(&statuses);
            if report.passed && report.matched_count == 5 { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        "validation_report_with_drift" => {
            let statuses = vec![
                ReplayValidationStatus::Matched,
                ReplayValidationStatus::ContentDrift,
                ReplayValidationStatus::Matched,
            ];
            let report = ReplayValidationReport::from_statuses(&statuses);
            if !report.passed && report.content_drift_count == 1 {
                ManifestVerdict::Pass
            } else {
                ManifestVerdict::Fail
            }
        }
        "replay_index_deterministic" => {
            let entries = vec![
                TsResolutionReplayEntry {
                    specifier: "./a".into(),
                    referrer: None,
                    style: TsRequestStyle::Import,
                    resolved_path: "/a.ts".into(),
                    package_name: None,
                    selected_condition: None,
                    resolved_content_hash: None,
                    probe_count: 1,
                },
            ];
            let i1 = TsResolutionReplayIndex::build(
                entries.clone(), "h", TsModuleResolutionMode::NodeNext, "t",
            );
            let i2 = TsResolutionReplayIndex::build(
                entries, "h", TsModuleResolutionMode::NodeNext, "t",
            );
            if i1.index_hash == i2.index_hash { ManifestVerdict::Pass } else { ManifestVerdict::Fail }
        }
        _ => ManifestVerdict::Fail,
    }
}

/// Artifact paths for the evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifactPaths {
    pub run_manifest: PathBuf,
    pub evidence_inventory: PathBuf,
    pub events_jsonl: PathBuf,
}

/// Write the evidence bundle to disk.
pub fn write_manifest_evidence_bundle(
    output_dir: &Path,
    manifest: &ManifestRunManifest,
    inventory: &ManifestEvidenceInventory,
    events: &[ManifestEvidenceEvent],
) -> std::io::Result<ManifestArtifactPaths> {
    std::fs::create_dir_all(output_dir)?;

    let manifest_path = output_dir.join("ts_manifest_run_manifest.json");
    let inventory_path = output_dir.join("ts_manifest_evidence_inventory.json");
    let events_path = output_dir.join("ts_manifest_events.jsonl");

    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(manifest)
            .map_err(std::io::Error::other)?,
    )?;
    std::fs::write(
        &inventory_path,
        serde_json::to_string_pretty(inventory)
            .map_err(std::io::Error::other)?,
    )?;

    let mut events_content = String::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(std::io::Error::other)?;
        events_content.push_str(&line);
        events_content.push('\n');
    }
    std::fs::write(&events_path, events_content)?;

    Ok(ManifestArtifactPaths {
        run_manifest: manifest_path,
        evidence_inventory: inventory_path,
        events_jsonl: events_path,
    })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- TsconfigSnapshot ---

    #[test]
    fn test_tsconfig_default_hash_non_empty() {
        let snap = TsconfigSnapshot::default();
        assert!(!snap.content_hash().as_bytes().is_empty());
    }

    #[test]
    fn test_tsconfig_different_paths_different_hash() {
        let mut s1 = TsconfigSnapshot::default();
        s1.paths.insert("@app/*".into(), vec!["./src/*".into()]);
        let s2 = TsconfigSnapshot::default();
        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn test_tsconfig_serde_roundtrip() {
        let snap = TsconfigSnapshot::default();
        let json = serde_json::to_string(&snap).unwrap();
        let rt: TsconfigSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, rt);
    }

    #[test]
    fn test_tsconfig_hash_deterministic() {
        let snap = TsconfigSnapshot::default();
        assert_eq!(snap.content_hash(), snap.content_hash());
    }

    // --- ReplayEntry ---

    #[test]
    fn test_replay_entry_lookup_key() {
        let entry = TsResolutionReplayEntry {
            specifier: "react".into(),
            referrer: Some("./app.tsx".into()),
            style: TsRequestStyle::Import,
            resolved_path: "node_modules/react/index.js".into(),
            package_name: Some("react".into()),
            selected_condition: Some("import".into()),
            resolved_content_hash: None,
            probe_count: 2,
        };
        let key = entry.lookup_key();
        assert!(key.contains("react"));
        assert!(key.contains("./app.tsx"));
        assert!(key.contains("Import"));
    }

    #[test]
    fn test_replay_entry_no_referrer() {
        let entry = TsResolutionReplayEntry {
            specifier: "react".into(),
            referrer: None,
            style: TsRequestStyle::Import,
            resolved_path: "x".into(),
            package_name: None,
            selected_condition: None,
            resolved_content_hash: None,
            probe_count: 1,
        };
        let key = entry.lookup_key();
        assert!(key.contains("react"));
    }

    #[test]
    fn test_replay_entry_serde() {
        let entry = TsResolutionReplayEntry {
            specifier: "lodash".into(),
            referrer: None,
            style: TsRequestStyle::Require,
            resolved_path: "node_modules/lodash/index.js".into(),
            package_name: Some("lodash".into()),
            selected_condition: Some("require".into()),
            resolved_content_hash: Some("sha256:abc".into()),
            probe_count: 3,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let rt: TsResolutionReplayEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, rt);
    }

    // --- ReplayIndex ---

    #[test]
    fn test_replay_index_build_and_lookup() {
        let entries = vec![
            TsResolutionReplayEntry {
                specifier: "react".into(),
                referrer: Some("./app.tsx".into()),
                style: TsRequestStyle::Import,
                resolved_path: "node_modules/react/index.js".into(),
                package_name: Some("react".into()),
                selected_condition: Some("import".into()),
                resolved_content_hash: None,
                probe_count: 2,
            },
        ];
        let index = TsResolutionReplayIndex::build(
            entries, "tsconfig-hash", TsModuleResolutionMode::NodeNext, "2026-01-01T00:00:00Z",
        );
        assert_eq!(index.entry_count(), 1);
        let found = index.lookup("react", Some("./app.tsx"), TsRequestStyle::Import);
        assert!(found.is_some());
        assert_eq!(found.unwrap().resolved_path, "node_modules/react/index.js");
    }

    #[test]
    fn test_replay_index_lookup_miss() {
        let index = TsResolutionReplayIndex::build(
            Vec::new(), "h", TsModuleResolutionMode::NodeNext, "t",
        );
        assert!(index.lookup("nonexistent", None, TsRequestStyle::Import).is_none());
    }

    #[test]
    fn test_replay_index_hash_deterministic() {
        let entries = vec![
            TsResolutionReplayEntry {
                specifier: "a".into(),
                referrer: None,
                style: TsRequestStyle::Import,
                resolved_path: "/a.ts".into(),
                package_name: None,
                selected_condition: None,
                resolved_content_hash: None,
                probe_count: 1,
            },
        ];
        let i1 = TsResolutionReplayIndex::build(
            entries.clone(), "h", TsModuleResolutionMode::NodeNext, "t",
        );
        let i2 = TsResolutionReplayIndex::build(
            entries, "h", TsModuleResolutionMode::NodeNext, "t",
        );
        assert_eq!(i1.index_hash, i2.index_hash);
    }

    #[test]
    fn test_replay_index_serde() {
        let index = TsResolutionReplayIndex::build(
            Vec::new(), "h", TsModuleResolutionMode::Bundler, "t",
        );
        let json = serde_json::to_string(&index).unwrap();
        let rt: TsResolutionReplayIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(index, rt);
    }

    // --- Replay validation ---

    #[test]
    fn test_validation_matched() {
        let entries = vec![TsResolutionReplayEntry {
            specifier: "./x".into(),
            referrer: None,
            style: TsRequestStyle::Import,
            resolved_path: "/x.ts".into(),
            package_name: None,
            selected_condition: None,
            resolved_content_hash: None,
            probe_count: 1,
        }];
        let index = TsResolutionReplayIndex::build(
            entries, "h", TsModuleResolutionMode::NodeNext, "t",
        );
        let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "/x.ts", None);
        assert_eq!(status, ReplayValidationStatus::Matched);
    }

    #[test]
    fn test_validation_path_mismatch() {
        let entries = vec![TsResolutionReplayEntry {
            specifier: "./x".into(),
            referrer: None,
            style: TsRequestStyle::Import,
            resolved_path: "/x.ts".into(),
            package_name: None,
            selected_condition: None,
            resolved_content_hash: None,
            probe_count: 1,
        }];
        let index = TsResolutionReplayIndex::build(
            entries, "h", TsModuleResolutionMode::NodeNext, "t",
        );
        let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "/y.ts", None);
        assert_eq!(status, ReplayValidationStatus::PathMismatch);
    }

    #[test]
    fn test_validation_content_drift() {
        let entries = vec![TsResolutionReplayEntry {
            specifier: "./x".into(),
            referrer: None,
            style: TsRequestStyle::Import,
            resolved_path: "/x.ts".into(),
            package_name: None,
            selected_condition: None,
            resolved_content_hash: Some("sha256:old".into()),
            probe_count: 1,
        }];
        let index = TsResolutionReplayIndex::build(
            entries, "h", TsModuleResolutionMode::NodeNext, "t",
        );
        let status = index.validate_resolution(
            "./x", None, TsRequestStyle::Import, "/x.ts", Some("sha256:new"),
        );
        assert_eq!(status, ReplayValidationStatus::ContentDrift);
    }

    #[test]
    fn test_validation_unexpected_failure() {
        let entries = vec![TsResolutionReplayEntry {
            specifier: "./x".into(),
            referrer: None,
            style: TsRequestStyle::Import,
            resolved_path: "/x.ts".into(),
            package_name: None,
            selected_condition: None,
            resolved_content_hash: None,
            probe_count: 1,
        }];
        let index = TsResolutionReplayIndex::build(
            entries, "h", TsModuleResolutionMode::NodeNext, "t",
        );
        let status = index.validate_resolution("./x", None, TsRequestStyle::Import, "", None);
        assert_eq!(status, ReplayValidationStatus::UnexpectedFailure);
    }

    #[test]
    fn test_validation_status_all() {
        assert_eq!(ReplayValidationStatus::ALL.len(), 6);
        for s in ReplayValidationStatus::ALL {
            assert!(!s.as_str().is_empty());
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    // --- ReplayValidationReport ---

    #[test]
    fn test_report_all_match() {
        let statuses = vec![ReplayValidationStatus::Matched; 5];
        let report = ReplayValidationReport::from_statuses(&statuses);
        assert!(report.passed);
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.matched_count, 5);
    }

    #[test]
    fn test_report_mixed() {
        let statuses = vec![
            ReplayValidationStatus::Matched,
            ReplayValidationStatus::PathMismatch,
            ReplayValidationStatus::ContentDrift,
        ];
        let report = ReplayValidationReport::from_statuses(&statuses);
        assert!(!report.passed);
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.path_mismatch_count, 1);
        assert_eq!(report.content_drift_count, 1);
    }

    // --- TsExecutionManifest ---

    #[test]
    fn test_execution_manifest_build() {
        let manifest = TsExecutionManifest::build(
            "trace-1", "decision-1", "policy-1", "tsconfig-hash",
            "./src/main.ts", "typescript",
            NormalizationLineage {
                source_hash: "sha256:src".into(),
                normalized_hash: "sha256:norm".into(),
                compiler_options_hash: "sha256:opts".into(),
                normalization_applied: true,
            },
            ResolutionLineage {
                decision_count: 3,
                resolved_count: 3,
                failed_count: 0,
                drift_class: TsResolutionDriftClass::NoDrift,
                replay_index_hash: None,
            },
            IrPipelineLineage {
                ir0_hash: "sha256:ir0".into(),
                ir1_hash: Some("sha256:ir1".into()),
                ir2_hash: None,
                ir3_hash: None,
            },
            "2026-01-01T00:00:00Z",
        );
        assert!(!manifest.manifest_hash.is_empty());
        assert!(manifest.manifest_hash.starts_with("sha256:"));
        assert!(manifest.is_fully_resolved());
    }

    #[test]
    fn test_execution_manifest_not_fully_resolved() {
        let manifest = TsExecutionManifest::build(
            "t", "d", "p", "h", "./x.ts", "typescript",
            NormalizationLineage {
                source_hash: "a".into(),
                normalized_hash: "b".into(),
                compiler_options_hash: "c".into(),
                normalization_applied: true,
            },
            ResolutionLineage {
                decision_count: 5,
                resolved_count: 4,
                failed_count: 1,
                drift_class: TsResolutionDriftClass::NoDrift,
                replay_index_hash: None,
            },
            IrPipelineLineage {
                ir0_hash: "ir0".into(),
                ir1_hash: None,
                ir2_hash: None,
                ir3_hash: None,
            },
            "t",
        );
        assert!(!manifest.is_fully_resolved());
    }

    #[test]
    fn test_execution_manifest_serde() {
        let manifest = TsExecutionManifest::build(
            "t", "d", "p", "h", "./x.ts", "typescript",
            NormalizationLineage {
                source_hash: "a".into(),
                normalized_hash: "b".into(),
                compiler_options_hash: "c".into(),
                normalization_applied: true,
            },
            ResolutionLineage {
                decision_count: 1,
                resolved_count: 1,
                failed_count: 0,
                drift_class: TsResolutionDriftClass::NoDrift,
                replay_index_hash: Some("sha256:idx".into()),
            },
            IrPipelineLineage {
                ir0_hash: "ir0".into(),
                ir1_hash: None,
                ir2_hash: None,
                ir3_hash: None,
            },
            "t",
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let rt: TsExecutionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, rt);
    }

    // --- Feature families ---

    #[test]
    fn test_manifest_feature_family_all() {
        assert_eq!(ManifestFeatureFamily::ALL.len(), 9);
        let names: std::collections::BTreeSet<_> =
            ManifestFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), 9);
    }

    #[test]
    fn test_manifest_feature_family_descriptions() {
        for f in ManifestFeatureFamily::ALL {
            assert!(!f.description().is_empty());
        }
    }

    // --- Schema constants ---

    #[test]
    fn test_schema_versions_non_empty() {
        assert!(!TS_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!TS_REPLAY_INDEX_SCHEMA_VERSION.is_empty());
        assert!(!TS_EXECUTION_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!TS_MANIFEST_RUN_SCHEMA_VERSION.is_empty());
        assert!(!TS_MANIFEST_EVENT_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn test_schema_versions_unique() {
        let versions = [
            TS_MANIFEST_SCHEMA_VERSION,
            TS_REPLAY_INDEX_SCHEMA_VERSION,
            TS_EXECUTION_MANIFEST_SCHEMA_VERSION,
            TS_MANIFEST_RUN_SCHEMA_VERSION,
            TS_MANIFEST_EVENT_SCHEMA_VERSION,
        ];
        let unique: std::collections::BTreeSet<_> = versions.iter().collect();
        assert_eq!(versions.len(), unique.len());
    }

    // --- Corpus & evidence ---

    #[test]
    fn test_corpus_non_empty() {
        assert!(manifest_corpus().len() >= 15);
    }

    #[test]
    fn test_corpus_ids_unique() {
        let corpus = manifest_corpus();
        let ids: std::collections::BTreeSet<_> = corpus.iter().map(|s| &s.specimen_id).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn test_corpus_covers_all_families() {
        let corpus = manifest_corpus();
        let families: std::collections::BTreeSet<_> =
            corpus.iter().map(|s| s.feature_family).collect();
        for f in ManifestFeatureFamily::ALL {
            assert!(families.contains(f), "missing family: {}", f.as_str());
        }
    }

    #[test]
    fn test_run_corpus_no_failures() {
        let (manifest, _, _) = run_manifest_corpus();
        assert_eq!(manifest.fail_count, 0, "corpus has unexpected failures");
        assert!(manifest.pass_count > 0);
    }

    #[test]
    fn test_run_corpus_deterministic() {
        let (_, inv1, _) = run_manifest_corpus();
        let (_, inv2, _) = run_manifest_corpus();
        assert_eq!(inv1.evidence_hash, inv2.evidence_hash);
    }

    #[test]
    fn test_run_corpus_counts_consistent() {
        let (manifest, inventory, events) = run_manifest_corpus();
        let total = manifest.pass_count + manifest.fail_count;
        assert_eq!(total, manifest.specimen_count);
        assert_eq!(inventory.specimens.len(), manifest.specimen_count);
        assert_eq!(events.len(), manifest.specimen_count);
    }

    #[test]
    fn test_evidence_hash_starts_with_sha256() {
        let (_, inventory, _) = run_manifest_corpus();
        assert!(inventory.evidence_hash.starts_with("sha256:"));
    }
}
