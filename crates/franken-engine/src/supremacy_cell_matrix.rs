//! Deterministic supremacy-cell matrix contract for V8 board claims.
//!
//! This module defines the machine-readable board used by RGC-705A to
//! describe what "across the board" means for benchmark and rollout claims.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SUPREMACY_CELL_MATRIX_COMPONENT: &str = "supremacy_cell_matrix";
pub const SUPREMACY_CELL_MATRIX_SCHEMA_VERSION: &str = "franken-engine.supremacy-cell-matrix.v1";
pub const SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION: &str =
    "franken-engine.supremacy-cell-matrix.log-event.v1";

pub const REQUIRED_MATRIX_DIMENSIONS: &[&str] = &[
    "workload_family",
    "environment",
    "entry_mode",
    "warm_state",
    "measurement_family",
    "interference_profile",
];

pub const REQUIRED_BOARD_FAMILIES: &[WorkloadFamily] = &[
    WorkloadFamily::ParseCompile,
    WorkloadFamily::ColdStart,
    WorkloadFamily::WarmThroughput,
    WorkloadFamily::Async,
    WorkloadFamily::ModuleGraphs,
    WorkloadFamily::NpmCohorts,
    WorkloadFamily::ReactCompile,
    WorkloadFamily::ReactSsr,
    WorkloadFamily::ReactClient,
    WorkloadFamily::MixedPackage,
    WorkloadFamily::TailLatency,
    WorkloadFamily::MemoryPressure,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFamily {
    ParseCompile,
    ColdStart,
    WarmThroughput,
    Async,
    ModuleGraphs,
    NpmCohorts,
    ReactCompile,
    ReactSsr,
    ReactClient,
    MixedPackage,
    TailLatency,
    MemoryPressure,
}

impl WorkloadFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParseCompile => "parse_compile",
            Self::ColdStart => "cold_start",
            Self::WarmThroughput => "warm_throughput",
            Self::Async => "async",
            Self::ModuleGraphs => "module_graphs",
            Self::NpmCohorts => "npm_cohorts",
            Self::ReactCompile => "react_compile",
            Self::ReactSsr => "react_ssr",
            Self::ReactClient => "react_client",
            Self::MixedPackage => "mixed_package",
            Self::TailLatency => "tail_latency",
            Self::MemoryPressure => "memory_pressure",
        }
    }
}

impl fmt::Display for WorkloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementFamily {
    Latency,
    Throughput,
    Macro,
    Memory,
    TailLatency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryMode {
    Cli,
    Library,
    NativeReactCompile,
    NativeReactSsr,
    NativeReactClient,
    MixedPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmState {
    Cold,
    Warm,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterferenceProfile {
    Isolated,
    SharedCache,
    SchedulerContention,
    MixedBoard,
    TailStress,
    MemoryContention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedResource {
    FrontendCpu,
    ArtifactCache,
    ModuleCache,
    SchedulerQueue,
    MemoryBandwidth,
    WorkerThreads,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailAxis {
    ParseNs,
    CompileNs,
    ModuleLoadNs,
    QueueDelayNs,
    RenderNs,
    HydrationNs,
    GcPauseNs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangelogEntry {
    pub version: String,
    pub rationale: String,
    pub impact_assessment: String,
    pub compatibility_notes: String,
    pub changed_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupremacyCellFamilySpec {
    pub family: WorkloadFamily,
    pub measurement_family: MeasurementFamily,
    pub required_dimensions: Vec<String>,
    pub required_for_board: bool,
    pub shipped_surface_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupremacyCellSpec {
    pub cell_id: String,
    pub family: WorkloadFamily,
    pub workload_kind: String,
    pub environment: String,
    pub entry_mode: EntryMode,
    pub warm_state: WarmState,
    pub measurement_family: MeasurementFamily,
    pub interference_profile: InterferenceProfile,
    #[serde(default)]
    pub mixed_with: Vec<WorkloadFamily>,
    #[serde(default)]
    pub interference_rule_ids: Vec<String>,
    #[serde(default)]
    pub tail_axis_ids: Vec<TailAxis>,
    pub required_for_universal_verdict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterferenceRule {
    pub rule_id: String,
    pub primary_family: WorkloadFamily,
    pub concurrent_family: WorkloadFamily,
    pub shared_resources: Vec<SharedResource>,
    pub decomposition_label: String,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailDecompositionAxisSpec {
    pub axis: TailAxis,
    pub stage: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupremacyCellMatrixArtifact {
    pub schema_version: String,
    pub contract_version: String,
    pub log_schema_version: String,
    pub required_artifacts: Vec<String>,
    pub required_consumers: Vec<String>,
    pub changelog: Vec<ChangelogEntry>,
    pub matrix_dimensions: Vec<String>,
    pub cell_families: Vec<SupremacyCellFamilySpec>,
    pub cells: Vec<SupremacyCellSpec>,
    pub interference_rules: Vec<InterferenceRule>,
    pub tail_decomposition_axes: Vec<TailDecompositionAxisSpec>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SupremacyCellMatrixError {
    #[error("unexpected schema version `{found}`")]
    InvalidSchemaVersion { found: String },
    #[error("unexpected log schema version `{found}`")]
    InvalidLogSchemaVersion { found: String },
    #[error("missing required matrix dimension `{dimension}`")]
    MissingMatrixDimension { dimension: String },
    #[error("family `{family}` references unknown matrix dimension `{dimension}`")]
    UnknownFamilyDimension {
        family: WorkloadFamily,
        dimension: String,
    },
    #[error("duplicate family definition for `{family}`")]
    DuplicateFamily { family: WorkloadFamily },
    #[error("missing required family definition for `{family}`")]
    MissingFamily { family: WorkloadFamily },
    #[error("missing cell coverage for required family `{family}`")]
    MissingFamilyCoverage { family: WorkloadFamily },
    #[error("duplicate cell id `{cell_id}`")]
    DuplicateCellId { cell_id: String },
    #[error("duplicate interference rule id `{rule_id}`")]
    DuplicateInterferenceRule { rule_id: String },
    #[error("cell `{cell_id}` references undefined interference rule `{rule_id}`")]
    UnknownInterferenceRule { cell_id: String, rule_id: String },
    #[error("cell `{cell_id}` must declare interference metadata")]
    MissingInterferenceMetadata { cell_id: String },
    #[error("cell `{cell_id}` must declare tail decomposition axes")]
    MissingTailDecomposition { cell_id: String },
    #[error("cell `{cell_id}` references undefined tail axis `{axis:?}`")]
    UnknownTailAxis { cell_id: String, axis: TailAxis },
    #[error("cold-start cell `{cell_id}` must use warm_state=cold")]
    ColdStartMustBeCold { cell_id: String },
    #[error("react cell `{cell_id}` requires entry mode `{expected:?}`, found `{found:?}`")]
    ReactEntryModeMismatch {
        cell_id: String,
        expected: EntryMode,
        found: EntryMode,
    },
    #[error("failed to serialize supremacy cell matrix: {0}")]
    Serialization(String),
}

pub fn validate_artifact(
    artifact: &SupremacyCellMatrixArtifact,
) -> Result<(), SupremacyCellMatrixError> {
    if artifact.schema_version != SUPREMACY_CELL_MATRIX_SCHEMA_VERSION {
        return Err(SupremacyCellMatrixError::InvalidSchemaVersion {
            found: artifact.schema_version.clone(),
        });
    }
    if artifact.log_schema_version != SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION {
        return Err(SupremacyCellMatrixError::InvalidLogSchemaVersion {
            found: artifact.log_schema_version.clone(),
        });
    }

    let dimensions: BTreeSet<&str> = artifact
        .matrix_dimensions
        .iter()
        .map(String::as_str)
        .collect();
    for dimension in REQUIRED_MATRIX_DIMENSIONS {
        if !dimensions.contains(dimension) {
            return Err(SupremacyCellMatrixError::MissingMatrixDimension {
                dimension: (*dimension).to_string(),
            });
        }
    }

    let mut family_specs = BTreeMap::new();
    for family in &artifact.cell_families {
        for dimension in &family.required_dimensions {
            if !dimensions.contains(dimension.as_str()) {
                return Err(SupremacyCellMatrixError::UnknownFamilyDimension {
                    family: family.family,
                    dimension: dimension.clone(),
                });
            }
        }
        if family_specs.insert(family.family, family).is_some() {
            return Err(SupremacyCellMatrixError::DuplicateFamily {
                family: family.family,
            });
        }
    }
    for family in REQUIRED_BOARD_FAMILIES {
        if !family_specs.contains_key(family) {
            return Err(SupremacyCellMatrixError::MissingFamily { family: *family });
        }
    }

    let mut rule_ids = BTreeMap::new();
    for rule in &artifact.interference_rules {
        if rule_ids.insert(rule.rule_id.as_str(), rule).is_some() {
            return Err(SupremacyCellMatrixError::DuplicateInterferenceRule {
                rule_id: rule.rule_id.clone(),
            });
        }
    }

    let tail_axes: BTreeSet<TailAxis> = artifact
        .tail_decomposition_axes
        .iter()
        .map(|axis| axis.axis)
        .collect();
    let mut cell_ids = BTreeSet::new();
    let mut family_coverage = BTreeSet::new();

    for cell in &artifact.cells {
        if !cell_ids.insert(cell.cell_id.as_str()) {
            return Err(SupremacyCellMatrixError::DuplicateCellId {
                cell_id: cell.cell_id.clone(),
            });
        }
        family_coverage.insert(cell.family);

        if cell.family == WorkloadFamily::ColdStart && cell.warm_state != WarmState::Cold {
            return Err(SupremacyCellMatrixError::ColdStartMustBeCold {
                cell_id: cell.cell_id.clone(),
            });
        }

        let expected_react_mode = match cell.family {
            WorkloadFamily::ReactCompile => Some(EntryMode::NativeReactCompile),
            WorkloadFamily::ReactSsr => Some(EntryMode::NativeReactSsr),
            WorkloadFamily::ReactClient => Some(EntryMode::NativeReactClient),
            _ => None,
        };
        if let Some(expected) = expected_react_mode
            && cell.entry_mode != expected
        {
            return Err(SupremacyCellMatrixError::ReactEntryModeMismatch {
                cell_id: cell.cell_id.clone(),
                expected,
                found: cell.entry_mode,
            });
        }

        let requires_interference = matches!(
            cell.family,
            WorkloadFamily::ModuleGraphs
                | WorkloadFamily::NpmCohorts
                | WorkloadFamily::MixedPackage
                | WorkloadFamily::TailLatency
                | WorkloadFamily::MemoryPressure
        ) || cell.interference_profile != InterferenceProfile::Isolated;
        if requires_interference && cell.interference_rule_ids.is_empty() {
            return Err(SupremacyCellMatrixError::MissingInterferenceMetadata {
                cell_id: cell.cell_id.clone(),
            });
        }
        for rule_id in &cell.interference_rule_ids {
            if !rule_ids.contains_key(rule_id.as_str()) {
                return Err(SupremacyCellMatrixError::UnknownInterferenceRule {
                    cell_id: cell.cell_id.clone(),
                    rule_id: rule_id.clone(),
                });
            }
        }

        let requires_tail_decomposition = cell.family == WorkloadFamily::TailLatency
            || cell.measurement_family == MeasurementFamily::TailLatency;
        if requires_tail_decomposition && cell.tail_axis_ids.is_empty() {
            return Err(SupremacyCellMatrixError::MissingTailDecomposition {
                cell_id: cell.cell_id.clone(),
            });
        }
        for axis in &cell.tail_axis_ids {
            if !tail_axes.contains(axis) {
                return Err(SupremacyCellMatrixError::UnknownTailAxis {
                    cell_id: cell.cell_id.clone(),
                    axis: *axis,
                });
            }
        }
    }

    for family in REQUIRED_BOARD_FAMILIES {
        if !family_coverage.contains(family) {
            return Err(SupremacyCellMatrixError::MissingFamilyCoverage { family: *family });
        }
    }

    Ok(())
}

pub fn build_interference_index(
    artifact: &SupremacyCellMatrixArtifact,
) -> Result<BTreeMap<WorkloadFamily, Vec<WorkloadFamily>>, SupremacyCellMatrixError> {
    validate_artifact(artifact)?;

    let mut index: BTreeMap<WorkloadFamily, BTreeSet<WorkloadFamily>> = BTreeMap::new();
    for rule in &artifact.interference_rules {
        index
            .entry(rule.primary_family)
            .or_default()
            .insert(rule.concurrent_family);
        index
            .entry(rule.concurrent_family)
            .or_default()
            .insert(rule.primary_family);
    }

    Ok(index
        .into_iter()
        .map(|(family, related)| (family, related.into_iter().collect()))
        .collect())
}

pub fn artifact_hash(
    artifact: &SupremacyCellMatrixArtifact,
) -> Result<String, SupremacyCellMatrixError> {
    let bytes = serde_json::to_vec(artifact)
        .map_err(|error| SupremacyCellMatrixError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{
        EntryMode, InterferenceProfile, MeasurementFamily, SupremacyCellMatrixArtifact,
        SupremacyCellMatrixError, TailAxis, WorkloadFamily, artifact_hash, validate_artifact,
    };

    fn load_fixture() -> SupremacyCellMatrixArtifact {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/supremacy_cell_matrix_v1.json");
        let bytes = fs::read(path).expect("read supremacy cell matrix fixture");
        serde_json::from_slice(&bytes).expect("deserialize supremacy cell matrix fixture")
    }

    #[test]
    fn fixture_validates() {
        validate_artifact(&load_fixture()).expect("fixture should validate");
    }

    #[test]
    fn mixed_board_cells_require_interference_rules() {
        let mut fixture = load_fixture();
        let cell = fixture
            .cells
            .iter_mut()
            .find(|cell| cell.family == WorkloadFamily::MixedPackage)
            .expect("mixed package cell should exist");
        cell.interference_profile = InterferenceProfile::MixedBoard;
        cell.interference_rule_ids.clear();

        let error = validate_artifact(&fixture).expect_err("validation should fail");
        assert!(matches!(
            error,
            SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
        ));
    }

    #[test]
    fn tail_cells_require_axes() {
        let mut fixture = load_fixture();
        let cell = fixture
            .cells
            .iter_mut()
            .find(|cell| cell.family == WorkloadFamily::TailLatency)
            .expect("tail latency cell should exist");
        cell.measurement_family = MeasurementFamily::TailLatency;
        cell.tail_axis_ids = vec![];

        let error = validate_artifact(&fixture).expect_err("validation should fail");
        assert!(matches!(
            error,
            SupremacyCellMatrixError::MissingTailDecomposition { .. }
        ));
    }

    #[test]
    fn react_cells_enforce_native_entry_modes() {
        let mut fixture = load_fixture();
        let cell = fixture
            .cells
            .iter_mut()
            .find(|cell| cell.family == WorkloadFamily::ReactCompile)
            .expect("react compile cell should exist");
        cell.entry_mode = EntryMode::Cli;

        let error = validate_artifact(&fixture).expect_err("validation should fail");
        assert!(matches!(
            error,
            SupremacyCellMatrixError::ReactEntryModeMismatch { .. }
        ));
    }

    #[test]
    fn artifact_hash_is_deterministic() {
        let fixture = load_fixture();
        let first = artifact_hash(&fixture).expect("hash should succeed");
        let second = artifact_hash(&fixture).expect("hash should succeed");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn unknown_tail_axis_is_rejected() {
        let mut fixture = load_fixture();
        let cell = fixture
            .cells
            .iter_mut()
            .find(|cell| cell.family == WorkloadFamily::TailLatency)
            .expect("tail latency cell should exist");
        cell.tail_axis_ids.push(TailAxis::HydrationNs);
        fixture
            .tail_decomposition_axes
            .retain(|axis| axis.axis != TailAxis::HydrationNs);

        let error = validate_artifact(&fixture).expect_err("validation should fail");
        assert!(matches!(
            error,
            SupremacyCellMatrixError::UnknownTailAxis { .. }
        ));
    }
}
