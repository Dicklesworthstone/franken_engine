#![allow(dead_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const IFC_CATEGORIES: &[&str] = &["benign", "exfil", "declassify"];
const IFC_SOURCE_LABELS: &[&str] = &[
    "credential",
    "key_material",
    "privileged_env",
    "policy_protected",
];
const IFC_SINK_CLEARANCES: &[&str] = &[
    "network_egress",
    "subprocess_ipc",
    "persistence_export",
    "explicit_declassify",
];
const IFC_FLOW_PATH_TYPES: &[&str] = &["direct", "indirect", "implicit", "temporal", "covert"];
const IFC_EXPECTED_OUTCOMES: &[&str] = &["allow", "block", "declassify"];
const IFC_EXPECTED_EVIDENCE_TYPES: &[&str] =
    &["none", "flow_violation", "declassification_receipt"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn seeded(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAssetManifest {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub assets: Vec<ConformanceAssetRecord>,
}

impl ConformanceAssetManifest {
    pub const CURRENT_SCHEMA: &'static str = "franken-engine.conformance-assets.v1";

    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read(path.as_ref())?;
        let manifest: Self = serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(manifest)
    }

    fn validate_and_resolve(
        &self,
        manifest_path: &Path,
    ) -> Result<Vec<ResolvedConformanceAsset>, ConformanceManifestError> {
        if self.schema_version.trim() != Self::CURRENT_SCHEMA {
            return Err(ConformanceManifestError::UnsupportedSchema {
                expected: Self::CURRENT_SCHEMA.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.assets.is_empty() {
            return Err(ConformanceManifestError::EmptyAssetSet);
        }

        let manifest_root = manifest_path
            .parent()
            .ok_or(ConformanceManifestError::ManifestHasNoParent)?;
        let mut resolved = Vec::with_capacity(self.assets.len());

        for asset in &self.assets {
            asset.validate()?;

            let fixture_abs = manifest_root.join(&asset.fixture_path);
            let expected_abs = manifest_root.join(&asset.expected_output_path);
            let fixture_bytes =
                fs::read(&fixture_abs).map_err(|err| ConformanceManifestError::AssetIo {
                    asset_id: asset.asset_id.clone(),
                    path: fixture_abs.clone(),
                    source: err,
                })?;
            let expected_bytes =
                fs::read(&expected_abs).map_err(|err| ConformanceManifestError::AssetIo {
                    asset_id: asset.asset_id.clone(),
                    path: expected_abs.clone(),
                    source: err,
                })?;

            let fixture_hash = sha256_hex(&fixture_bytes);
            if fixture_hash != asset.fixture_hash {
                return Err(ConformanceManifestError::FixtureHashMismatch {
                    asset_id: asset.asset_id.clone(),
                    expected: asset.fixture_hash.clone(),
                    actual: fixture_hash,
                });
            }

            let expected_hash = sha256_hex(&expected_bytes);
            if expected_hash != asset.expected_output_hash {
                return Err(ConformanceManifestError::ExpectedOutputHashMismatch {
                    asset_id: asset.asset_id.clone(),
                    expected: asset.expected_output_hash.clone(),
                    actual: expected_hash,
                });
            }

            resolved.push(ResolvedConformanceAsset {
                record: asset.clone(),
                fixture_path: fixture_abs,
                expected_output_path: expected_abs,
            });
        }

        Ok(resolved)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAssetRecord {
    pub asset_id: String,
    pub source_donor: String,
    pub semantic_domain: String,
    pub normative_reference: String,
    pub fixture_path: String,
    pub fixture_hash: String,
    pub expected_output_path: String,
    pub expected_output_hash: String,
    pub import_date: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub source_labels: Vec<String>,
    #[serde(default)]
    pub sink_clearances: Vec<String>,
    #[serde(default)]
    pub flow_path_type: Option<String>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub expected_evidence_type: Option<String>,
}

impl ConformanceAssetRecord {
    fn validate(&self) -> Result<(), ConformanceManifestError> {
        if self.asset_id.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("asset_id"));
        }
        if self.source_donor.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("source_donor"));
        }
        if self.semantic_domain.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("semantic_domain"));
        }
        if self.normative_reference.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "normative_reference",
            ));
        }
        if self.fixture_path.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("fixture_path"));
        }
        if self.fixture_hash.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("fixture_hash"));
        }
        if self.expected_output_path.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "expected_output_path",
            ));
        }
        if self.expected_output_hash.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField(
                "expected_output_hash",
            ));
        }
        if self.import_date.trim().is_empty() {
            return Err(ConformanceManifestError::MissingField("import_date"));
        }
        self.validate_ifc_fields()?;
        Ok(())
    }

    fn is_ifc_asset(&self) -> bool {
        self.semantic_domain.starts_with("ifc_corpus/")
            || self.category.is_some()
            || !self.source_labels.is_empty()
            || !self.sink_clearances.is_empty()
            || self.flow_path_type.is_some()
            || self.expected_outcome.is_some()
            || self.expected_evidence_type.is_some()
    }

    fn ifc_metadata(&self) -> Option<IfcAssetMetadata> {
        let category = self.category.clone()?;
        let flow_path_type = self.flow_path_type.clone()?;
        let expected_outcome = self.expected_outcome.clone()?;
        let expected_evidence_type = self.expected_evidence_type.clone()?;

        Some(IfcAssetMetadata {
            category,
            source_labels: self.source_labels.clone(),
            sink_clearances: self.sink_clearances.clone(),
            flow_path_type,
            expected_outcome,
            expected_evidence_type,
        })
    }

    fn validate_ifc_fields(&self) -> Result<(), ConformanceManifestError> {
        if !self.is_ifc_asset() {
            return Ok(());
        }

        let category = self
            .category
            .as_deref()
            .ok_or(ConformanceManifestError::MissingField("category"))?;
        if !IFC_CATEGORIES.contains(&category) {
            return Err(ConformanceManifestError::InvalidFieldValue {
                field: "category",
                value: category.to_string(),
            });
        }

        if self.source_labels.is_empty() {
            return Err(ConformanceManifestError::MissingField("source_labels"));
        }
        for label in &self.source_labels {
            if !IFC_SOURCE_LABELS.contains(&label.as_str()) {
                return Err(ConformanceManifestError::InvalidFieldValue {
                    field: "source_labels",
                    value: label.clone(),
                });
            }
        }

        if self.sink_clearances.is_empty() {
            return Err(ConformanceManifestError::MissingField("sink_clearances"));
        }
        for clearance in &self.sink_clearances {
            if !IFC_SINK_CLEARANCES.contains(&clearance.as_str()) {
                return Err(ConformanceManifestError::InvalidFieldValue {
                    field: "sink_clearances",
                    value: clearance.clone(),
                });
            }
        }

        let flow_path_type = self
            .flow_path_type
            .as_deref()
            .ok_or(ConformanceManifestError::MissingField("flow_path_type"))?;
        if !IFC_FLOW_PATH_TYPES.contains(&flow_path_type) {
            return Err(ConformanceManifestError::InvalidFieldValue {
                field: "flow_path_type",
                value: flow_path_type.to_string(),
            });
        }

        let expected_outcome = self
            .expected_outcome
            .as_deref()
            .ok_or(ConformanceManifestError::MissingField("expected_outcome"))?;
        if !IFC_EXPECTED_OUTCOMES.contains(&expected_outcome) {
            return Err(ConformanceManifestError::InvalidFieldValue {
                field: "expected_outcome",
                value: expected_outcome.to_string(),
            });
        }

        let expected_evidence_type = self.expected_evidence_type.as_deref().ok_or(
            ConformanceManifestError::MissingField("expected_evidence_type"),
        )?;
        if !IFC_EXPECTED_EVIDENCE_TYPES.contains(&expected_evidence_type) {
            return Err(ConformanceManifestError::InvalidFieldValue {
                field: "expected_evidence_type",
                value: expected_evidence_type.to_string(),
            });
        }

        let invalid_ifc_expectation = match (category, expected_outcome, expected_evidence_type) {
            ("benign", "allow", "none")
            | ("exfil", "block", "flow_violation")
            | ("declassify", "declassify", "declassification_receipt") => false,
            ("benign", ..) | ("exfil", ..) | ("declassify", ..) => true,
            _ => false,
        };
        if invalid_ifc_expectation {
            return Err(ConformanceManifestError::InvalidIfcExpectation {
                asset_id: self.asset_id.clone(),
                category: category.to_string(),
                expected_outcome: expected_outcome.to_string(),
                expected_evidence_type: expected_evidence_type.to_string(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcAssetMetadata {
    category: String,
    source_labels: Vec<String>,
    sink_clearances: Vec<String>,
    flow_path_type: String,
    expected_outcome: String,
    expected_evidence_type: String,
}

#[derive(Debug, Clone)]
struct ResolvedConformanceAsset {
    record: ConformanceAssetRecord,
    fixture_path: PathBuf,
    expected_output_path: PathBuf,
}

#[derive(Debug)]
pub enum ConformanceManifestError {
    UnsupportedSchema {
        expected: String,
        actual: String,
    },
    EmptyAssetSet,
    ManifestHasNoParent,
    MissingField(&'static str),
    InvalidFieldValue {
        field: &'static str,
        value: String,
    },
    InvalidIfcExpectation {
        asset_id: String,
        category: String,
        expected_outcome: String,
        expected_evidence_type: String,
    },
    AssetIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    FixtureHashMismatch {
        asset_id: String,
        expected: String,
        actual: String,
    },
    ExpectedOutputHashMismatch {
        asset_id: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConformanceManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => {
                write!(
                    f,
                    "unsupported conformance manifest schema: expected `{expected}`, got `{actual}`"
                )
            }
            Self::EmptyAssetSet => write!(f, "conformance manifest contains no assets"),
            Self::ManifestHasNoParent => write!(f, "manifest path has no parent directory"),
            Self::MissingField(field) => {
                write!(f, "manifest entry is missing required field `{field}`")
            }
            Self::InvalidFieldValue { field, value } => {
                write!(f, "manifest entry has invalid `{field}` value `{value}`")
            }
            Self::InvalidIfcExpectation {
                asset_id,
                category,
                expected_outcome,
                expected_evidence_type,
            } => write!(
                f,
                "manifest entry `{asset_id}` has invalid IFC expectation for category `{category}`: outcome=`{expected_outcome}`, evidence=`{expected_evidence_type}`"
            ),
            Self::AssetIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read conformance asset `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::FixtureHashMismatch {
                asset_id,
                expected,
                actual,
            } => write!(
                f,
                "fixture hash mismatch for `{asset_id}`: expected `{expected}`, got `{actual}`"
            ),
            Self::ExpectedOutputHashMismatch {
                asset_id,
                expected,
                actual,
            } => write!(
                f,
                "expected output hash mismatch for `{asset_id}`: expected `{expected}`, got `{actual}`"
            ),
        }
    }
}

impl Error for ConformanceManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AssetIo { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DonorFixture {
    pub donor_harness: String,
    pub source: String,
    pub observed_output: String,
}

pub trait DonorHarnessApi {
    fn adapt_source(&self, source: &str) -> String;
}

#[derive(Debug, Clone, Default)]
pub struct DonorHarnessAdapter;

impl DonorHarnessApi for DonorHarnessAdapter {
    fn adapt_source(&self, source: &str) -> String {
        source
            .replace("$262.createRealm()", "__franken_create_realm()")
            .replace("$DONE", "__franken_done")
            .replace("print(", "franken_print(")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverReasonCode {
    HarnessGap,
    HostHookMissing,
    IntentionalDivergence,
    NotYetImplemented,
}

impl WaiverReasonCode {
    fn parse(input: &str) -> Option<Self> {
        match input.trim() {
            "harness_gap" => Some(Self::HarnessGap),
            "host_hook_missing" => Some(Self::HostHookMissing),
            "intentional_divergence" => Some(Self::IntentionalDivergence),
            "not_yet_implemented" => Some(Self::NotYetImplemented),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceWaiver {
    pub asset_id: String,
    pub reason_code: WaiverReasonCode,
    pub tracking_bead: String,
    pub expiry_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConformanceWaiverSet {
    pub waivers: Vec<ConformanceWaiver>,
}

impl ConformanceWaiverSet {
    pub fn load_toml(path: impl AsRef<Path>) -> io::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path.as_ref())?;
        parse_waiver_toml(&content)
    }

    fn find_active(&self, asset_id: &str, run_date: &str) -> Option<&ConformanceWaiver> {
        self.waivers
            .iter()
            .find(|waiver| waiver.asset_id == asset_id && waiver.expiry_date.as_str() >= run_date)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReproMetadata {
    pub version_combination: BTreeMap<String, String>,
    pub first_seen_commit: String,
    pub regression_commit: Option<String>,
    pub ci_run_id: Option<String>,
    pub issue_tracker_project: String,
    pub issue_tracking_bead: Option<String>,
}

impl Default for ConformanceReproMetadata {
    fn default() -> Self {
        let mut version_combination = BTreeMap::new();
        version_combination.insert(
            "franken_engine".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        Self {
            version_combination,
            first_seen_commit: "unknown".to_string(),
            regression_commit: None,
            ci_run_id: None,
            issue_tracker_project: "beads".to_string(),
            issue_tracking_bead: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceFailureClass {
    Breaking,
    Behavioral,
    Observability,
    Performance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceFailureSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDeltaKind {
    SchemaFieldAdded,
    SchemaFieldRemoved,
    SchemaFieldModified,
    BehavioralSemanticShift,
    TimingChange,
    ErrorFormatChange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDeltaClassification {
    pub kind: ConformanceDeltaKind,
    pub field: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizationSummary {
    pub strategy: String,
    pub original_source_lines: usize,
    pub minimized_source_lines: usize,
    pub original_expected_lines: usize,
    pub minimized_expected_lines: usize,
    pub original_actual_lines: usize,
    pub minimized_actual_lines: usize,
    pub preserved_failure_class: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReproEnvironment {
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub rust_toolchain: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReplayContract {
    pub deterministic_seed: u64,
    pub replay_command: String,
    pub verification_command: String,
    pub verification_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceIssueLink {
    pub tracker: String,
    pub issue_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunLinkage {
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub ci_run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizedFailingVector {
    pub asset_id: String,
    pub source_donor: String,
    pub semantic_domain: String,
    pub normative_reference: String,
    pub fixture: DonorFixture,
    pub expected_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceMinimizedReproArtifact {
    pub schema_version: String,
    pub artifact_id: String,
    pub failure_id: String,
    pub boundary_surface: String,
    pub failure_class: ConformanceFailureClass,
    pub severity: ConformanceFailureSeverity,
    pub version_combination: BTreeMap<String, String>,
    pub first_seen_commit: String,
    pub regression_commit: Option<String>,
    pub environment: ConformanceReproEnvironment,
    pub replay: ConformanceReplayContract,
    pub expected_output: String,
    pub actual_output: String,
    pub delta_classification: Vec<ConformanceDeltaClassification>,
    pub minimization: ConformanceMinimizationSummary,
    pub failing_vector: ConformanceMinimizedFailingVector,
    pub evidence_ledger_id: String,
    pub linked_run: ConformanceRunLinkage,
    pub issue_tracker: ConformanceIssueLink,
}

impl ConformanceMinimizedReproArtifact {
    pub const CURRENT_SCHEMA: &'static str = "franken-engine.conformance-min-repro.v1";

    pub fn verify_replay(&self) -> Result<(), ConformanceReplayVerificationError> {
        let expected = canonicalize_conformance_output(&self.failing_vector.expected_output);
        let actual = canonicalize_conformance_output(&self.failing_vector.fixture.observed_output);
        if expected == actual {
            return Err(ConformanceReplayVerificationError::FailureNotReproduced);
        }

        let observed_delta = classify_conformance_delta(&expected, &actual);
        let observed_class = classify_failure_class(&observed_delta);
        if observed_class != self.failure_class {
            return Err(ConformanceReplayVerificationError::FailureClassMismatch {
                expected: self.failure_class,
                actual: observed_class,
            });
        }
        if observed_delta != self.delta_classification {
            return Err(ConformanceReplayVerificationError::DeltaClassificationDrift);
        }

        let digest = repro_verification_digest(self.replay.deterministic_seed, &expected, &actual);
        if digest != self.replay.verification_digest {
            return Err(ConformanceReplayVerificationError::DigestMismatch {
                expected: self.replay.verification_digest.clone(),
                actual: digest,
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceReplayVerificationError {
    FailureNotReproduced,
    FailureClassMismatch {
        expected: ConformanceFailureClass,
        actual: ConformanceFailureClass,
    },
    DeltaClassificationDrift,
    DigestMismatch {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for ConformanceReplayVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailureNotReproduced => write!(
                f,
                "replay verification failed: expected mismatch but outputs are equal"
            ),
            Self::FailureClassMismatch { expected, actual } => write!(
                f,
                "replay verification failure class mismatch: expected {:?}, got {:?}",
                expected, actual
            ),
            Self::DeltaClassificationDrift => write!(
                f,
                "replay verification delta classification drifted from recorded artifact"
            ),
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "replay verification digest mismatch: expected `{expected}`, got `{actual}`"
            ),
        }
    }
}

impl Error for ConformanceReplayVerificationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunnerConfig {
    pub trace_prefix: String,
    pub policy_id: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub run_date: String,
    pub repro_metadata: ConformanceReproMetadata,
}

impl Default for ConformanceRunnerConfig {
    fn default() -> Self {
        Self {
            trace_prefix: "trace-conformance".to_string(),
            policy_id: "policy-conformance-v1".to_string(),
            seed: 7,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            run_date: "1970-01-01".to_string(),
            repro_metadata: ConformanceReproMetadata::default(),
        }
    }
}

impl ConformanceRunnerConfig {
    fn validate(&self) -> Result<(), ConformanceRunError> {
        if self.trace_prefix.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "trace_prefix is required".to_string(),
            ));
        }
        if self.policy_id.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "policy_id is required".to_string(),
            ));
        }
        if self.locale.as_str() != "C" {
            return Err(ConformanceRunError::InvalidConfig(
                "locale must be fixed to `C`".to_string(),
            ));
        }
        if self.timezone.as_str() != "UTC" {
            return Err(ConformanceRunError::InvalidConfig(
                "timezone must be fixed to `UTC`".to_string(),
            ));
        }
        if self.gc_schedule.as_str() != "deterministic" {
            return Err(ConformanceRunError::InvalidConfig(
                "gc_schedule must be `deterministic`".to_string(),
            ));
        }
        if self.run_date.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "run_date is required".to_string(),
            ));
        }
        if self.repro_metadata.first_seen_commit.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "repro_metadata.first_seen_commit is required".to_string(),
            ));
        }
        if self.repro_metadata.issue_tracker_project.trim().is_empty() {
            return Err(ConformanceRunError::InvalidConfig(
                "repro_metadata.issue_tracker_project is required".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub asset_id: String,
    pub workload_id: String,
    pub semantic_domain: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub source_labels: Vec<String>,
    #[serde(default)]
    pub sink_clearances: Vec<String>,
    #[serde(default)]
    pub flow_path_type: Option<String>,
    #[serde(default)]
    pub expected_outcome: Option<String>,
    #[serde(default)]
    pub actual_outcome: Option<String>,
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub evidence_id: Option<String>,
    pub duration_us: u64,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunSummary {
    pub run_id: String,
    pub asset_manifest_hash: String,
    pub total_assets: usize,
    pub passed: usize,
    pub failed: usize,
    pub waived: usize,
    pub errored: usize,
    pub env_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRunResult {
    pub run_id: String,
    pub asset_manifest_hash: String,
    pub logs: Vec<ConformanceLogEvent>,
    pub summary: ConformanceRunSummary,
    pub minimized_repros: Vec<ConformanceMinimizedReproArtifact>,
}

impl ConformanceRunResult {
    pub fn enforce_ci_gate(&self) -> Result<(), ConformanceCiGateError> {
        if self.summary.failed > 0 || self.summary.errored > 0 {
            Err(ConformanceCiGateError {
                failed: self.summary.failed,
                errored: self.summary.errored,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCiGateError {
    pub failed: usize,
    pub errored: usize,
}

impl fmt::Display for ConformanceCiGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conformance CI gate failed: failed={}, errored={}",
            self.failed, self.errored
        )
    }
}

impl Error for ConformanceCiGateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IfcObservedOutcome {
    outcome: Option<String>,
    evidence_type: Option<String>,
    evidence_id: Option<String>,
}

fn parse_ifc_observed_outcome(payload: &str) -> IfcObservedOutcome {
    let mut outcome = None;
    let mut evidence_type = None;
    let mut evidence_id = None;

    for token in payload.split_whitespace() {
        if let Some(value) = token.strip_prefix("outcome:") {
            if !value.trim().is_empty() {
                outcome = Some(value.trim().to_string());
            }
            continue;
        }
        if let Some(value) = token.strip_prefix("evidence:") {
            if !value.trim().is_empty() {
                evidence_type = Some(value.trim().to_string());
            }
            continue;
        }
        if let Some(value) = token.strip_prefix("evidence_id:")
            && !value.trim().is_empty()
        {
            evidence_id = Some(value.trim().to_string());
        }
    }

    IfcObservedOutcome {
        outcome,
        evidence_type,
        evidence_id,
    }
}

#[derive(Debug)]
pub enum ConformanceRunError {
    InvalidConfig(String),
    Manifest(ConformanceManifestError),
    FixtureIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    InvalidFixture {
        asset_id: String,
        source: io::Error,
    },
    ExpectedOutputIo {
        asset_id: String,
        path: PathBuf,
        source: io::Error,
    },
    ReproInvariant {
        asset_id: String,
        detail: String,
    },
    Io(io::Error),
}

impl fmt::Display for ConformanceRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid conformance config: {reason}"),
            Self::Manifest(err) => write!(f, "{err}"),
            Self::FixtureIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read fixture for `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::InvalidFixture { asset_id, source } => {
                write!(f, "invalid donor fixture for `{asset_id}`: {source}")
            }
            Self::ExpectedOutputIo {
                asset_id,
                path,
                source,
            } => write!(
                f,
                "failed to read expected output for `{asset_id}` at {}: {source}",
                path.display()
            ),
            Self::ReproInvariant { asset_id, detail } => {
                write!(f, "repro invariant violated for `{asset_id}`: {detail}")
            }
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ConformanceRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(err) => Some(err),
            Self::FixtureIo { source, .. } => Some(source),
            Self::InvalidFixture { source, .. } => Some(source),
            Self::ExpectedOutputIo { source, .. } => Some(source),
            Self::Io(err) => Some(err),
            Self::InvalidConfig(_) | Self::ReproInvariant { .. } => None,
        }
    }
}

impl From<ConformanceManifestError> for ConformanceRunError {
    fn from(value: ConformanceManifestError) -> Self {
        Self::Manifest(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConformanceRunner {
    pub config: ConformanceRunnerConfig,
    pub adapter: DonorHarnessAdapter,
}

impl ConformanceRunner {
    pub fn run(
        &self,
        manifest_path: impl AsRef<Path>,
        waivers: &ConformanceWaiverSet,
    ) -> Result<ConformanceRunResult, ConformanceRunError> {
        self.config.validate()?;
        let manifest_path = manifest_path.as_ref();
        let manifest =
            ConformanceAssetManifest::load(manifest_path).map_err(ConformanceRunError::Io)?;
        let resolved = manifest.validate_and_resolve(manifest_path)?;
        let asset_manifest_hash =
            sha256_hex(&canonical_json_bytes(&manifest).map_err(ConformanceRunError::Io)?);
        let run_id = format!(
            "conformance-{}",
            &digest_hex(asset_manifest_hash.as_bytes())[..12]
        );

        let mut rng = DeterministicRng::seeded(self.config.seed);
        let mut logs = Vec::with_capacity(resolved.len());
        let mut minimized_repros = Vec::new();
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut waived = 0usize;
        let errored = 0usize;

        for (idx, asset) in resolved.iter().enumerate() {
            let duration_us = 50 + (rng.next_u64() % 950);
            let trace_id = format!("{}-{}-{idx:04}", self.config.trace_prefix, run_id);
            let decision_id = format!("decision-conformance-{idx:04}");
            let expected_output =
                fs::read_to_string(&asset.expected_output_path).map_err(|source| {
                    ConformanceRunError::ExpectedOutputIo {
                        asset_id: asset.record.asset_id.clone(),
                        path: asset.expected_output_path.clone(),
                        source,
                    }
                })?;
            let fixture_bytes =
                fs::read(&asset.fixture_path).map_err(|source| ConformanceRunError::FixtureIo {
                    asset_id: asset.record.asset_id.clone(),
                    path: asset.fixture_path.clone(),
                    source,
                })?;
            let fixture: DonorFixture = serde_json::from_slice(&fixture_bytes).map_err(|err| {
                ConformanceRunError::InvalidFixture {
                    asset_id: asset.record.asset_id.clone(),
                    source: io::Error::new(io::ErrorKind::InvalidData, err),
                }
            })?;

            let _adapted_source = self.adapter.adapt_source(&fixture.source);
            let actual = canonicalize_conformance_output(&fixture.observed_output);
            let expected = canonicalize_conformance_output(&expected_output);
            let ifc_metadata = asset.record.ifc_metadata();
            let expected_signal = parse_ifc_observed_outcome(&expected);
            let actual_signal = parse_ifc_observed_outcome(&actual);

            if let Some(metadata) = ifc_metadata.as_ref()
                && (expected_signal.outcome.as_deref() != Some(metadata.expected_outcome.as_str())
                    || expected_signal.evidence_type.as_deref()
                        != Some(metadata.expected_evidence_type.as_str()))
            {
                return Err(ConformanceRunError::ReproInvariant {
                    asset_id: asset.record.asset_id.clone(),
                    detail: format!(
                        "IFC expected-output metadata mismatch: outcome=`{:?}`, evidence=`{:?}`",
                        expected_signal.outcome, expected_signal.evidence_type
                    ),
                });
            }

            let (outcome, error_code, error_detail) = if actual == expected {
                passed += 1;
                ("pass".to_string(), None, None)
            } else if let Some(waiver) = waivers.find_active(
                asset.record.asset_id.as_str(),
                self.config.run_date.as_str(),
            ) {
                waived += 1;
                (
                    "waived".to_string(),
                    Some("FE-CONFORMANCE-WAIVED".to_string()),
                    Some(format!(
                        "waived via {} (tracking {})",
                        waiver.expiry_date, waiver.tracking_bead
                    )),
                )
            } else {
                failed += 1;
                let repro = self.build_minimized_repro_artifact(
                    &run_id,
                    &trace_id,
                    &decision_id,
                    asset,
                    &fixture,
                    &expected,
                );
                repro
                    .verify_replay()
                    .map_err(|err| ConformanceRunError::ReproInvariant {
                        asset_id: asset.record.asset_id.clone(),
                        detail: err.to_string(),
                    })?;
                let failure_id = repro.failure_id.clone();
                minimized_repros.push(repro);
                (
                    "fail".to_string(),
                    Some("FE-CONFORMANCE-MISMATCH".to_string()),
                    Some(format!(
                        "canonicalized output mismatch; minimized repro `{failure_id}` generated"
                    )),
                )
            };

            let category = ifc_metadata
                .as_ref()
                .map(|metadata| metadata.category.clone());
            let source_labels = ifc_metadata
                .as_ref()
                .map(|metadata| metadata.source_labels.clone())
                .unwrap_or_default();
            let sink_clearances = ifc_metadata
                .as_ref()
                .map(|metadata| metadata.sink_clearances.clone())
                .unwrap_or_default();
            let flow_path_type = ifc_metadata
                .as_ref()
                .map(|metadata| metadata.flow_path_type.clone());
            let expected_outcome = ifc_metadata
                .as_ref()
                .map(|metadata| metadata.expected_outcome.clone())
                .or(expected_signal.outcome);

            logs.push(ConformanceLogEvent {
                trace_id,
                decision_id,
                policy_id: self.config.policy_id.clone(),
                component: "conformance_runner".to_string(),
                event: "asset_execution".to_string(),
                outcome,
                error_code,
                asset_id: asset.record.asset_id.clone(),
                workload_id: asset.record.asset_id.clone(),
                semantic_domain: asset.record.semantic_domain.clone(),
                category,
                source_labels,
                sink_clearances,
                flow_path_type,
                expected_outcome,
                actual_outcome: actual_signal.outcome,
                evidence_type: actual_signal.evidence_type,
                evidence_id: actual_signal.evidence_id,
                duration_us,
                error_detail,
            });
        }

        let summary = ConformanceRunSummary {
            run_id: run_id.clone(),
            asset_manifest_hash: asset_manifest_hash.clone(),
            total_assets: logs.len(),
            passed,
            failed,
            waived,
            errored,
            env_fingerprint: self.env_fingerprint(),
        };

        Ok(ConformanceRunResult {
            run_id,
            asset_manifest_hash,
            logs,
            summary,
            minimized_repros,
        })
    }

    fn build_minimized_repro_artifact(
        &self,
        run_id: &str,
        trace_id: &str,
        decision_id: &str,
        asset: &ResolvedConformanceAsset,
        fixture: &DonorFixture,
        expected: &str,
    ) -> ConformanceMinimizedReproArtifact {
        let actual = canonicalize_conformance_output(&fixture.observed_output);
        let original_delta = classify_conformance_delta(expected, &actual);
        let original_failure_class = classify_failure_class(&original_delta);

        let minimized =
            minimize_conformance_case(&fixture.source, expected, &actual, original_failure_class);
        let minimized_delta = classify_conformance_delta(
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );
        let minimized_failure_class = classify_failure_class(&minimized_delta);
        let severity = severity_for_failure_class(minimized_failure_class);
        let failure_id = build_failure_id(
            asset.record.asset_id.as_str(),
            self.config.seed,
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );

        let replay_relative_path = format!("minimized_repros/{failure_id}.json");
        let replay_command = format!("franken-conformance replay {replay_relative_path}");
        let verification_command = format!("{replay_command} --verify");
        let verification_digest = repro_verification_digest(
            self.config.seed,
            &minimized.minimized_expected_output,
            &minimized.minimized_actual_output,
        );

        let mut version_combination = self.config.repro_metadata.version_combination.clone();
        version_combination
            .entry("source_donor".to_string())
            .or_insert_with(|| asset.record.source_donor.clone());
        version_combination
            .entry("manifest_schema".to_string())
            .or_insert_with(|| ConformanceAssetManifest::CURRENT_SCHEMA.to_string());
        version_combination
            .entry("policy_id".to_string())
            .or_insert_with(|| self.config.policy_id.clone());

        let issue_id = self
            .config
            .repro_metadata
            .issue_tracking_bead
            .clone()
            .unwrap_or_else(|| format!("auto/{}/{}", asset.record.asset_id, failure_id));

        ConformanceMinimizedReproArtifact {
            schema_version: ConformanceMinimizedReproArtifact::CURRENT_SCHEMA.to_string(),
            artifact_id: format!("repro-{failure_id}"),
            failure_id: failure_id.clone(),
            boundary_surface: format!(
                "{}/{}",
                asset.record.source_donor, asset.record.semantic_domain
            ),
            failure_class: minimized_failure_class,
            severity,
            version_combination,
            first_seen_commit: self.config.repro_metadata.first_seen_commit.clone(),
            regression_commit: self.config.repro_metadata.regression_commit.clone(),
            environment: ConformanceReproEnvironment {
                locale: self.config.locale.clone(),
                timezone: self.config.timezone.clone(),
                gc_schedule: self.config.gc_schedule.clone(),
                rust_toolchain: std::env::var("RUSTUP_TOOLCHAIN")
                    .unwrap_or_else(|_| "unknown".to_string()),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
            },
            replay: ConformanceReplayContract {
                deterministic_seed: self.config.seed,
                replay_command,
                verification_command,
                verification_digest,
            },
            expected_output: minimized.minimized_expected_output.clone(),
            actual_output: minimized.minimized_actual_output.clone(),
            delta_classification: minimized_delta,
            minimization: ConformanceMinimizationSummary {
                preserved_failure_class: minimized_failure_class == original_failure_class,
                ..minimized.summary
            },
            failing_vector: ConformanceMinimizedFailingVector {
                asset_id: asset.record.asset_id.clone(),
                source_donor: asset.record.source_donor.clone(),
                semantic_domain: asset.record.semantic_domain.clone(),
                normative_reference: asset.record.normative_reference.clone(),
                fixture: DonorFixture {
                    donor_harness: fixture.donor_harness.clone(),
                    source: minimized.minimized_source,
                    observed_output: minimized.minimized_actual_output,
                },
                expected_output: minimized.minimized_expected_output,
            },
            evidence_ledger_id: format!("conformance-ledger/{failure_id}"),
            linked_run: ConformanceRunLinkage {
                run_id: run_id.to_string(),
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                ci_run_id: self.config.repro_metadata.ci_run_id.clone(),
            },
            issue_tracker: ConformanceIssueLink {
                tracker: self.config.repro_metadata.issue_tracker_project.clone(),
                issue_id,
            },
        }
    }

    fn env_fingerprint(&self) -> String {
        let envelope = format!(
            "locale={};timezone={};gc={};seed={}",
            self.config.locale, self.config.timezone, self.config.gc_schedule, self.config.seed
        );
        sha256_hex(envelope.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCollectedArtifacts {
    pub run_manifest_path: PathBuf,
    pub conformance_evidence_path: PathBuf,
    pub ifc_conformance_evidence_path: Option<PathBuf>,
    pub minimized_repro_index_path: Option<PathBuf>,
    pub minimized_repro_events_path: Option<PathBuf>,
    pub minimized_repro_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ConformanceEvidenceCollector {
    root: PathBuf,
}

impl ConformanceEvidenceCollector {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn collect(&self, run: &ConformanceRunResult) -> io::Result<ConformanceCollectedArtifacts> {
        let run_root = self.root.join(&run.run_id);
        fs::create_dir_all(&run_root)?;

        let run_manifest_path = run_root.join("run_manifest.json");
        write_atomic(&run_manifest_path, &canonical_json_bytes(&run.summary)?)?;

        let mut evidence_lines = String::new();
        let summary_line = serde_json::to_string(&ConformanceEvidenceSummaryLine {
            run_manifest: "run_manifest.json".to_string(),
            run_id: run.run_id.clone(),
            asset_manifest_hash: run.asset_manifest_hash.clone(),
            pass_count: run.summary.passed,
            fail_count: run.summary.failed,
            waived_count: run.summary.waived,
            error_count: run.summary.errored,
            env_fingerprint: run.summary.env_fingerprint.clone(),
            minimized_repro_count: run.minimized_repros.len(),
        })
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        evidence_lines.push_str(&summary_line);
        evidence_lines.push('\n');

        for event in &run.logs {
            let line = serde_json::to_string(event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            evidence_lines.push_str(&line);
            evidence_lines.push('\n');
        }

        let conformance_evidence_path = run_root.join("conformance_evidence.jsonl");
        write_atomic(&conformance_evidence_path, evidence_lines.as_bytes())?;

        let mut ifc_conformance_evidence_path = None;
        if let Some(ifc_summary) = build_ifc_conformance_summary(run) {
            let mut ifc_lines = String::new();
            let summary_line = serde_json::to_string(&ifc_summary)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            ifc_lines.push_str(&summary_line);
            ifc_lines.push('\n');

            for event in run.logs.iter().filter(|event| event.category.is_some()) {
                let line = serde_json::to_string(event)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                ifc_lines.push_str(&line);
                ifc_lines.push('\n');
            }

            let path = run_root.join("ifc_conformance_evidence.jsonl");
            write_atomic(&path, ifc_lines.as_bytes())?;
            ifc_conformance_evidence_path = Some(path);
        }

        let mut minimized_repro_paths = Vec::new();
        let mut minimized_repro_index_path = None;
        let mut minimized_repro_events_path = None;

        if !run.minimized_repros.is_empty() {
            let minimized_repro_root = run_root.join("minimized_repros");
            fs::create_dir_all(&minimized_repro_root)?;

            let mut repro_index = ConformanceMinimizedReproIndex {
                schema_version: "franken-engine.conformance-min-repro-index.v1".to_string(),
                run_id: run.run_id.clone(),
                entries: Vec::with_capacity(run.minimized_repros.len()),
            };
            let mut repro_events = String::new();

            for repro in &run.minimized_repros {
                repro
                    .verify_replay()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

                let relative_path = format!("minimized_repros/{}.json", repro.failure_id);
                let path = run_root.join(&relative_path);
                write_atomic(&path, &canonical_json_bytes(repro)?)?;
                minimized_repro_paths.push(path.clone());

                repro_index
                    .entries
                    .push(ConformanceMinimizedReproIndexEntry {
                        failure_id: repro.failure_id.clone(),
                        artifact_id: repro.artifact_id.clone(),
                        artifact_path: relative_path.clone(),
                        evidence_ledger_id: repro.evidence_ledger_id.clone(),
                        replay_command: repro.replay.replay_command.clone(),
                        verification_command: repro.replay.verification_command.clone(),
                        issue_tracker_id: repro.issue_tracker.issue_id.clone(),
                    });

                let policy_id = run
                    .logs
                    .iter()
                    .find(|event| {
                        event.trace_id == repro.linked_run.trace_id
                            && event.decision_id == repro.linked_run.decision_id
                    })
                    .map(|event| event.policy_id.clone())
                    .unwrap_or_else(|| "policy-conformance-v1".to_string());
                let event_line = serde_json::to_string(&ConformanceMinimizedReproEventLine {
                    trace_id: repro.linked_run.trace_id.clone(),
                    decision_id: repro.linked_run.decision_id.clone(),
                    policy_id,
                    component: "conformance_repro_collector".to_string(),
                    event: "minimized_repro_persisted".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    failure_id: repro.failure_id.clone(),
                    artifact_path: relative_path,
                    issue_tracker_id: repro.issue_tracker.issue_id.clone(),
                })
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                repro_events.push_str(&event_line);
                repro_events.push('\n');
            }

            let index_path = minimized_repro_root.join("index.json");
            write_atomic(&index_path, &canonical_json_bytes(&repro_index)?)?;
            minimized_repro_index_path = Some(index_path);

            let events_path = minimized_repro_root.join("events.jsonl");
            write_atomic(&events_path, repro_events.as_bytes())?;
            minimized_repro_events_path = Some(events_path);
        }

        Ok(ConformanceCollectedArtifacts {
            run_manifest_path,
            conformance_evidence_path,
            ifc_conformance_evidence_path,
            minimized_repro_index_path,
            minimized_repro_events_path,
            minimized_repro_paths,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceEvidenceSummaryLine {
    run_manifest: String,
    run_id: String,
    asset_manifest_hash: String,
    pass_count: usize,
    fail_count: usize,
    waived_count: usize,
    error_count: usize,
    env_fingerprint: String,
    minimized_repro_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct IfcCategoryCounts {
    total: usize,
    passed: usize,
    failed: usize,
    waived: usize,
    errored: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IfcConformanceEvidenceSummaryLine {
    run_manifest: String,
    run_id: String,
    corpus_hash: String,
    policy_snapshot_hash: String,
    ifc_label_taxonomy_hash: String,
    environment_fingerprint: String,
    category_counts: BTreeMap<String, IfcCategoryCounts>,
    false_positive_count: usize,
    false_negative_count: usize,
    false_negative_direct_indirect_count: usize,
    ci_blocking_failures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproIndex {
    schema_version: String,
    run_id: String,
    entries: Vec<ConformanceMinimizedReproIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproIndexEntry {
    failure_id: String,
    artifact_id: String,
    artifact_path: String,
    evidence_ledger_id: String,
    replay_command: String,
    verification_command: String,
    issue_tracker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConformanceMinimizedReproEventLine {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    failure_id: String,
    artifact_path: String,
    issue_tracker_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConformanceMinimizationOutcome {
    minimized_source: String,
    minimized_expected_output: String,
    minimized_actual_output: String,
    summary: ConformanceMinimizationSummary,
}

fn build_ifc_conformance_summary(
    run: &ConformanceRunResult,
) -> Option<IfcConformanceEvidenceSummaryLine> {
    let ifc_logs: Vec<&ConformanceLogEvent> = run
        .logs
        .iter()
        .filter(|event| event.category.is_some())
        .collect();
    if ifc_logs.is_empty() {
        return None;
    }

    let mut category_counts: BTreeMap<String, IfcCategoryCounts> = BTreeMap::new();
    let mut false_positive_count = 0usize;
    let mut false_negative_count = 0usize;
    let mut false_negative_direct_indirect_count = 0usize;

    for event in &ifc_logs {
        let category = event
            .category
            .as_ref()
            .expect("IFC logs always carry category");
        let counts = category_counts.entry(category.clone()).or_default();
        counts.total += 1;
        match event.outcome.as_str() {
            "pass" => counts.passed += 1,
            "fail" => counts.failed += 1,
            "waived" => counts.waived += 1,
            _ => counts.errored += 1,
        }

        if category == "benign" && event.actual_outcome.as_deref() == Some("block") {
            false_positive_count += 1;
        }
        if category == "exfil" && event.actual_outcome.as_deref() != Some("block") {
            false_negative_count += 1;
            if matches!(event.flow_path_type.as_deref(), Some("direct" | "indirect")) {
                false_negative_direct_indirect_count += 1;
            }
        }
    }

    let policy_id = ifc_logs
        .first()
        .map(|event| event.policy_id.as_str())
        .unwrap_or("policy-conformance-v1");
    let policy_snapshot_hash = sha256_hex(policy_id.as_bytes());
    let ci_blocking_failures = false_positive_count + false_negative_direct_indirect_count;

    Some(IfcConformanceEvidenceSummaryLine {
        run_manifest: "run_manifest.json".to_string(),
        run_id: run.run_id.clone(),
        corpus_hash: run.asset_manifest_hash.clone(),
        policy_snapshot_hash,
        ifc_label_taxonomy_hash: ifc_label_taxonomy_hash(),
        environment_fingerprint: run.summary.env_fingerprint.clone(),
        category_counts,
        false_positive_count,
        false_negative_count,
        false_negative_direct_indirect_count,
        ci_blocking_failures,
    })
}

fn ifc_label_taxonomy_hash() -> String {
    let taxonomy = serde_json::json!({
        "source_labels": IFC_SOURCE_LABELS,
        "sink_clearances": IFC_SINK_CLEARANCES,
    });
    sha256_hex(taxonomy.to_string().as_bytes())
}

fn build_failure_id(asset_id: &str, seed: u64, expected: &str, actual: &str) -> String {
    let material = format!("asset={asset_id};seed={seed};expected={expected};actual={actual}");
    format!("cf-{}", &digest_hex(material.as_bytes())[..16])
}

fn repro_verification_digest(seed: u64, expected: &str, actual: &str) -> String {
    let material = format!("seed={seed};expected={expected};actual={actual}");
    digest_hex(material.as_bytes())
}

pub fn classify_conformance_delta(
    expected: &str,
    actual: &str,
) -> Vec<ConformanceDeltaClassification> {
    let expected = canonicalize_conformance_output(expected);
    let actual = canonicalize_conformance_output(actual);
    if expected == actual {
        return Vec::new();
    }

    let mut deltas = Vec::new();

    if let (Some(expected_props), Some(actual_props)) =
        (parse_props_fields(&expected), parse_props_fields(&actual))
    {
        for removed in expected_props
            .iter()
            .filter(|field| !actual_props.contains(*field))
        {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldRemoved,
                field: Some(removed.clone()),
                expected: Some("present".to_string()),
                actual: Some("missing".to_string()),
                detail: format!("schema field `{removed}` removed from canonical props output"),
            });
        }
        for added in actual_props
            .iter()
            .filter(|field| !expected_props.contains(*field))
        {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldAdded,
                field: Some(added.clone()),
                expected: Some("missing".to_string()),
                actual: Some("present".to_string()),
                detail: format!("schema field `{added}` added to canonical props output"),
            });
        }
        if deltas.is_empty() {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldModified,
                field: None,
                expected: Some(expected.clone()),
                actual: Some(actual.clone()),
                detail: "props schema changed without pure add/remove diff".to_string(),
            });
        }
    }

    if deltas.is_empty() {
        let expected_error = extract_error_signature(&expected);
        let actual_error = extract_error_signature(&actual);
        if expected_error != actual_error {
            deltas.push(ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::ErrorFormatChange,
                field: None,
                expected: expected_error,
                actual: actual_error,
                detail: "error surface format changed".to_string(),
            });
        }
    }

    if deltas.is_empty() && numeric_delta_only(&expected, &actual) {
        deltas.push(ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::TimingChange,
            field: None,
            expected: Some(expected.clone()),
            actual: Some(actual.clone()),
            detail: "numeric-only delta indicates timing/performance shift".to_string(),
        });
    }

    if deltas.is_empty() {
        deltas.push(ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::BehavioralSemanticShift,
            field: None,
            expected: Some(expected),
            actual: Some(actual),
            detail: "canonical output changed in behavioral semantics".to_string(),
        });
    }

    deltas
}

pub fn classify_failure_class(
    deltas: &[ConformanceDeltaClassification],
) -> ConformanceFailureClass {
    if deltas.is_empty() {
        return ConformanceFailureClass::Behavioral;
    }
    let mut resolved = delta_kind_to_failure_class(deltas[0].kind);
    for delta in deltas.iter().skip(1) {
        let candidate = delta_kind_to_failure_class(delta.kind);
        if failure_class_priority(candidate) > failure_class_priority(resolved) {
            resolved = candidate;
        }
    }
    resolved
}

pub fn severity_for_failure_class(class: ConformanceFailureClass) -> ConformanceFailureSeverity {
    match class {
        ConformanceFailureClass::Breaking => ConformanceFailureSeverity::Critical,
        ConformanceFailureClass::Behavioral => ConformanceFailureSeverity::Error,
        ConformanceFailureClass::Observability => ConformanceFailureSeverity::Warning,
        ConformanceFailureClass::Performance => ConformanceFailureSeverity::Warning,
    }
}

fn failure_class_priority(class: ConformanceFailureClass) -> u8 {
    match class {
        ConformanceFailureClass::Breaking => 4,
        ConformanceFailureClass::Behavioral => 3,
        ConformanceFailureClass::Observability => 2,
        ConformanceFailureClass::Performance => 1,
    }
}

fn delta_kind_to_failure_class(kind: ConformanceDeltaKind) -> ConformanceFailureClass {
    match kind {
        ConformanceDeltaKind::SchemaFieldAdded
        | ConformanceDeltaKind::SchemaFieldRemoved
        | ConformanceDeltaKind::SchemaFieldModified => ConformanceFailureClass::Breaking,
        ConformanceDeltaKind::BehavioralSemanticShift => ConformanceFailureClass::Behavioral,
        ConformanceDeltaKind::TimingChange => ConformanceFailureClass::Performance,
        ConformanceDeltaKind::ErrorFormatChange => ConformanceFailureClass::Observability,
    }
}

fn parse_props_fields(payload: &str) -> Option<Vec<String>> {
    for line in payload.lines() {
        if let Some(rest) = line.strip_prefix("props:") {
            let mut values: Vec<String> = rest
                .split(',')
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .map(ToString::to_string)
                .collect();
            values.sort();
            values.dedup();
            return Some(values);
        }
    }
    None
}

fn extract_error_signature(payload: &str) -> Option<String> {
    payload
        .lines()
        .map(str::trim)
        .find(|line| line.contains("Error|"))
        .map(ToString::to_string)
}

fn numeric_delta_only(expected: &str, actual: &str) -> bool {
    let expected_tokens: Vec<&str> = expected.split_whitespace().collect();
    let actual_tokens: Vec<&str> = actual.split_whitespace().collect();
    if expected_tokens.len() != actual_tokens.len() {
        return false;
    }
    let mut saw_numeric_delta = false;
    for (lhs, rhs) in expected_tokens.iter().zip(actual_tokens.iter()) {
        match (lhs.parse::<f64>(), rhs.parse::<f64>()) {
            (Ok(lhs_num), Ok(rhs_num)) => {
                if (lhs_num - rhs_num).abs() > f64::EPSILON {
                    saw_numeric_delta = true;
                }
            }
            (Err(_), Err(_)) => {
                if lhs != rhs {
                    return false;
                }
            }
            _ => return false,
        }
    }
    saw_numeric_delta
}

fn minimize_conformance_case(
    source: &str,
    expected: &str,
    actual: &str,
    failure_class: ConformanceFailureClass,
) -> ConformanceMinimizationOutcome {
    let source_segments = split_source_segments(source);
    let expected_lines = split_output_lines(expected);
    let actual_lines = split_output_lines(actual);

    let minimized_source_segments =
        minimize_source_segments(&source_segments, failure_class, expected, actual);
    let (mut minimized_expected_lines, mut minimized_actual_lines) =
        reduce_output_lines(&expected_lines, &actual_lines, failure_class);
    minimize_lines_greedy(
        &mut minimized_expected_lines,
        &minimized_actual_lines,
        failure_class,
        true,
    );
    minimize_lines_greedy(
        &mut minimized_actual_lines,
        &minimized_expected_lines,
        failure_class,
        false,
    );

    let minimized_source = join_source_segments(&minimized_source_segments);
    let minimized_expected_output =
        canonicalize_conformance_output(&join_output_lines(&minimized_expected_lines));
    let minimized_actual_output =
        canonicalize_conformance_output(&join_output_lines(&minimized_actual_lines));

    let preserved_failure_class = preserves_failure_class(
        &minimized_expected_output,
        &minimized_actual_output,
        failure_class,
    );
    let (minimized_expected_output, minimized_actual_output) = if preserved_failure_class {
        (minimized_expected_output, minimized_actual_output)
    } else {
        (
            canonicalize_conformance_output(expected),
            canonicalize_conformance_output(actual),
        )
    };
    let minimized_source_line_count = split_source_segments(&minimized_source).len();

    ConformanceMinimizationOutcome {
        minimized_source,
        minimized_expected_output: minimized_expected_output.clone(),
        minimized_actual_output: minimized_actual_output.clone(),
        summary: ConformanceMinimizationSummary {
            strategy: "greedy-delta-debugging".to_string(),
            original_source_lines: source_segments.len(),
            minimized_source_lines: minimized_source_line_count,
            original_expected_lines: expected_lines.len(),
            minimized_expected_lines: split_output_lines(&minimized_expected_output).len(),
            original_actual_lines: actual_lines.len(),
            minimized_actual_lines: split_output_lines(&minimized_actual_output).len(),
            preserved_failure_class,
        },
    }
}

fn split_source_segments(source: &str) -> Vec<String> {
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    let mut segments = Vec::new();
    for line in normalized.lines() {
        for segment in line.split(';') {
            let trimmed = segment.trim();
            if !trimmed.is_empty() {
                segments.push(trimmed.to_string());
            }
        }
    }
    if segments.is_empty() {
        vec!["void 0".to_string()]
    } else {
        segments
    }
}

fn join_source_segments(segments: &[String]) -> String {
    segments.join(";\n")
}

fn split_output_lines(payload: &str) -> Vec<String> {
    let canonical = canonicalize_conformance_output(payload);
    let lines: Vec<String> = canonical
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect();
    if lines.is_empty() {
        vec!["<empty>".to_string()]
    } else {
        lines
    }
}

fn join_output_lines(lines: &[String]) -> String {
    lines.join("\n")
}

fn minimize_source_segments(
    original: &[String],
    _failure_class: ConformanceFailureClass,
    _expected: &str,
    _actual: &str,
) -> Vec<String> {
    // Cannot minimize source segments without re-evaluation engine
    // to generate new expected/actual outputs. Returning unminimized.
    if original.is_empty() {
        vec!["void 0".to_string()]
    } else {
        original.to_vec()
    }
}

fn reduce_output_lines(
    expected: &[String],
    actual: &[String],
    failure_class: ConformanceFailureClass,
) -> (Vec<String>, Vec<String>) {
    let mut start = 0usize;
    while start < expected.len() && start < actual.len() && expected[start] == actual[start] {
        start += 1;
    }

    let mut end_expected = expected.len();
    let mut end_actual = actual.len();
    while end_expected > start
        && end_actual > start
        && expected[end_expected - 1] == actual[end_actual - 1]
    {
        end_expected -= 1;
        end_actual -= 1;
    }

    let mut expected_reduced = expected[start..end_expected].to_vec();
    let mut actual_reduced = actual[start..end_actual].to_vec();

    if expected_reduced.is_empty() {
        expected_reduced.push(
            expected
                .first()
                .cloned()
                .unwrap_or_else(|| "<empty>".to_string()),
        );
    }
    if actual_reduced.is_empty() {
        actual_reduced.push(
            actual
                .first()
                .cloned()
                .unwrap_or_else(|| "<empty>".to_string()),
        );
    }

    let expected_payload = join_output_lines(&expected_reduced);
    let actual_payload = join_output_lines(&actual_reduced);
    if !preserves_failure_class(&expected_payload, &actual_payload, failure_class) {
        return (expected.to_vec(), actual.to_vec());
    }

    (expected_reduced, actual_reduced)
}

fn minimize_lines_greedy(
    lines: &mut Vec<String>,
    other: &[String],
    failure_class: ConformanceFailureClass,
    is_expected_side: bool,
) {
    let mut improved = true;
    while improved && lines.len() > 1 {
        improved = false;
        for idx in 0..lines.len() {
            if lines.len() <= 1 {
                break;
            }
            let candidate: Vec<String> = lines
                .iter()
                .enumerate()
                .filter(|(pos, _)| *pos != idx)
                .map(|(_, line)| line.clone())
                .collect();
            if candidate.is_empty() {
                continue;
            }
            let candidate_payload = join_output_lines(&candidate);
            let other_payload = join_output_lines(other);
            let preserved = if is_expected_side {
                preserves_failure_class(&candidate_payload, &other_payload, failure_class)
            } else {
                preserves_failure_class(&other_payload, &candidate_payload, failure_class)
            };
            if preserved {
                *lines = candidate;
                improved = true;
                break;
            }
        }
    }
}

fn preserves_failure_class(
    expected: &str,
    actual: &str,
    failure_class: ConformanceFailureClass,
) -> bool {
    let expected = canonicalize_conformance_output(expected);
    let actual = canonicalize_conformance_output(actual);
    if expected == actual {
        return false;
    }
    classify_failure_class(&classify_conformance_delta(&expected, &actual)) == failure_class
}

pub fn canonicalize_conformance_output(raw: &str) -> String {
    let mut out_lines = Vec::new();

    for line in raw.replace("\r\n", "\n").replace('\r', "\n").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let normalized = if let Some(rest) = trimmed.strip_prefix("props:") {
            let mut values: Vec<_> = rest
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            values.sort();
            format!("props:{}", values.join(","))
        } else {
            normalize_value_line(trimmed)
        };

        out_lines.push(normalized);
    }

    out_lines.join("\n")
}

fn normalize_value_line(line: &str) -> String {
    let normalized_error = line
        .replace("TypeError: ", "TypeError|")
        .replace("ReferenceError: ", "ReferenceError|")
        .replace("SyntaxError: ", "SyntaxError|");
    let mut out = Vec::new();
    for token in normalized_error.split_whitespace() {
        if let Ok(value) = token.parse::<f64>() {
            out.push(format!("{value:.6}"));
        } else {
            out.push(token.to_string());
        }
    }
    out.join(" ")
}

fn parse_waiver_toml(content: &str) -> io::Result<ConformanceWaiverSet> {
    #[derive(Default)]
    struct RawWaiver {
        asset_id: Option<String>,
        reason_code: Option<String>,
        tracking_bead: Option<String>,
        expiry_date: Option<String>,
    }

    fn parse_quoted(line_no: usize, value: &str) -> io::Result<String> {
        let trimmed = value.trim();
        if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TOML string at line {line_no}"),
            ));
        }
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    }

    fn finalize(raw: RawWaiver, line_no: usize) -> io::Result<ConformanceWaiver> {
        let asset_id = raw.asset_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver is missing asset_id before line {line_no}"),
            )
        })?;
        let reason_code_raw = raw.reason_code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing reason_code"),
            )
        })?;
        let reason_code = WaiverReasonCode::parse(reason_code_raw.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` has unknown reason_code `{reason_code_raw}`"),
            )
        })?;
        let tracking_bead = raw.tracking_bead.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing tracking_bead"),
            )
        })?;
        let expiry_date = raw.expiry_date.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{asset_id}` is missing expiry_date"),
            )
        })?;

        Ok(ConformanceWaiver {
            asset_id,
            reason_code,
            tracking_bead,
            expiry_date,
        })
    }

    let mut waivers = Vec::new();
    let mut current: Option<RawWaiver> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = raw_line.split('#').next().unwrap_or("").trim();
        if stripped.is_empty() {
            continue;
        }

        if stripped == "[[waiver]]" {
            if let Some(previous) = current.take() {
                waivers.push(finalize(previous, line_no)?);
            }
            current = Some(RawWaiver::default());
            continue;
        }

        let current_mut = current.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("key-value pair before [[waiver]] at line {line_no}"),
            )
        })?;

        let (key, value) = stripped.split_once('=').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid waiver entry at line {line_no}"),
            )
        })?;

        let value = parse_quoted(line_no, value)?;
        match key.trim() {
            "asset_id" => current_mut.asset_id = Some(value),
            "reason_code" => current_mut.reason_code = Some(value),
            "tracking_bead" => current_mut.tracking_bead = Some(value),
            "expiry_date" => current_mut.expiry_date = Some(value),
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown waiver field `{unknown}` at line {line_no}"),
                ));
            }
        }
    }

    if let Some(last) = current.take() {
        waivers.push(finalize(last, content.lines().count() + 1)?);
    }

    Ok(ConformanceWaiverSet { waivers })
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let mut tmp_name = path.file_name().unwrap_or_default().to_owned();
    tmp_name.push(".tmp");
    let tmp = parent.join(tmp_name);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DeterministicRng ───────────────────────────────────────────────

    #[test]
    fn deterministic_rng_seeded_zero_uses_fallback_state() {
        let rng = DeterministicRng::seeded(0);
        assert_eq!(rng.state, 0x9E37_79B9_7F4A_7C15);
    }

    #[test]
    fn deterministic_rng_seeded_nonzero_preserves_seed() {
        let rng = DeterministicRng::seeded(42);
        assert_eq!(rng.state, 42);
    }

    #[test]
    fn deterministic_rng_same_seed_produces_same_sequence() {
        let mut a = DeterministicRng::seeded(123);
        let mut b = DeterministicRng::seeded(123);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn deterministic_rng_different_seeds_diverge() {
        let mut a = DeterministicRng::seeded(1);
        let mut b = DeterministicRng::seeded(2);
        // At least one of the first 5 values should differ
        let differ = (0..5).any(|_| a.next_u64() != b.next_u64());
        assert!(differ);
    }

    #[test]
    fn deterministic_rng_serde_round_trip() {
        let rng = DeterministicRng::seeded(999);
        let json = serde_json::to_string(&rng).unwrap();
        let back: DeterministicRng = serde_json::from_str(&json).unwrap();
        assert_eq!(rng, back);
    }

    // ── canonicalize_conformance_output ─────────────────────────────────

    #[test]
    fn canonicalize_strips_empty_lines_and_trims() {
        let raw = "  hello  \n\n  world  \n\n";
        let result = canonicalize_conformance_output(raw);
        assert_eq!(result, "hello\nworld");
    }

    #[test]
    fn canonicalize_normalizes_crlf() {
        let raw = "line1\r\nline2\rline3";
        let result = canonicalize_conformance_output(raw);
        assert_eq!(result, "line1\nline2\nline3");
    }

    #[test]
    fn canonicalize_sorts_props_fields() {
        let raw = "props: zebra, alpha, mango";
        let result = canonicalize_conformance_output(raw);
        assert_eq!(result, "props:alpha,mango,zebra");
    }

    #[test]
    fn canonicalize_normalizes_error_formats() {
        let raw = "TypeError: is not a function";
        let result = canonicalize_conformance_output(raw);
        assert!(result.contains("TypeError|"));
        assert!(!result.contains("TypeError: "));
    }

    #[test]
    fn canonicalize_normalizes_numeric_tokens() {
        let raw = "value 42 end";
        let result = canonicalize_conformance_output(raw);
        assert_eq!(result, "value 42.000000 end");
    }

    #[test]
    fn canonicalize_empty_input() {
        assert_eq!(canonicalize_conformance_output(""), "");
        assert_eq!(canonicalize_conformance_output("  \n  \n  "), "");
    }

    // ── normalize_value_line ───────────────────────────────────────────

    #[test]
    fn normalize_value_line_replaces_all_error_prefixes() {
        let line = "TypeError: foo ReferenceError: bar SyntaxError: baz";
        let result = normalize_value_line(line);
        assert!(result.contains("TypeError|"));
        assert!(result.contains("ReferenceError|"));
        assert!(result.contains("SyntaxError|"));
    }

    #[test]
    fn normalize_value_line_formats_floats() {
        let result = normalize_value_line("result 3.14 done");
        assert_eq!(result, "result 3.140000 done");
    }

    #[test]
    fn normalize_value_line_non_numeric_passthrough() {
        let result = normalize_value_line("hello world");
        assert_eq!(result, "hello world");
    }

    // ── parse_ifc_observed_outcome ─────────────────────────────────────

    #[test]
    fn parse_ifc_observed_outcome_all_fields() {
        let result = parse_ifc_observed_outcome("outcome:allow evidence:none evidence_id:ev-001");
        assert_eq!(result.outcome.as_deref(), Some("allow"));
        assert_eq!(result.evidence_type.as_deref(), Some("none"));
        assert_eq!(result.evidence_id.as_deref(), Some("ev-001"));
    }

    #[test]
    fn parse_ifc_observed_outcome_partial() {
        let result = parse_ifc_observed_outcome("outcome:block other stuff");
        assert_eq!(result.outcome.as_deref(), Some("block"));
        assert!(result.evidence_type.is_none());
        assert!(result.evidence_id.is_none());
    }

    #[test]
    fn parse_ifc_observed_outcome_empty() {
        let result = parse_ifc_observed_outcome("");
        assert!(result.outcome.is_none());
        assert!(result.evidence_type.is_none());
        assert!(result.evidence_id.is_none());
    }

    #[test]
    fn parse_ifc_observed_outcome_empty_value_ignored() {
        let result = parse_ifc_observed_outcome("outcome: evidence:");
        assert!(result.outcome.is_none());
        assert!(result.evidence_type.is_none());
    }

    // ── WaiverReasonCode::parse ────────────────────────────────────────

    #[test]
    fn waiver_reason_code_parse_all_variants() {
        assert_eq!(
            WaiverReasonCode::parse("harness_gap"),
            Some(WaiverReasonCode::HarnessGap)
        );
        assert_eq!(
            WaiverReasonCode::parse("host_hook_missing"),
            Some(WaiverReasonCode::HostHookMissing)
        );
        assert_eq!(
            WaiverReasonCode::parse("intentional_divergence"),
            Some(WaiverReasonCode::IntentionalDivergence)
        );
        assert_eq!(
            WaiverReasonCode::parse("not_yet_implemented"),
            Some(WaiverReasonCode::NotYetImplemented)
        );
    }

    #[test]
    fn waiver_reason_code_parse_trims_whitespace() {
        assert_eq!(
            WaiverReasonCode::parse("  harness_gap  "),
            Some(WaiverReasonCode::HarnessGap)
        );
    }

    #[test]
    fn waiver_reason_code_parse_unknown_returns_none() {
        assert!(WaiverReasonCode::parse("unknown_code").is_none());
        assert!(WaiverReasonCode::parse("").is_none());
    }

    #[test]
    fn waiver_reason_code_serde_round_trip() {
        let code = WaiverReasonCode::HarnessGap;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"harness_gap\"");
        let back: WaiverReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, code);
    }

    // ── parse_waiver_toml ──────────────────────────────────────────────

    #[test]
    fn parse_waiver_toml_single_waiver() {
        let toml = r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
tracking_bead = "bd-42"
expiry_date = "2030-01-01"
"#;
        let set = parse_waiver_toml(toml).unwrap();
        assert_eq!(set.waivers.len(), 1);
        assert_eq!(set.waivers[0].asset_id, "test-001");
        assert_eq!(set.waivers[0].reason_code, WaiverReasonCode::HarnessGap);
        assert_eq!(set.waivers[0].tracking_bead, "bd-42");
        assert_eq!(set.waivers[0].expiry_date, "2030-01-01");
    }

    #[test]
    fn parse_waiver_toml_multiple_waivers() {
        let toml = r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"

[[waiver]]
asset_id = "test-002"
reason_code = "not_yet_implemented"
tracking_bead = "bd-2"
expiry_date = "2031-06-15"
"#;
        let set = parse_waiver_toml(toml).unwrap();
        assert_eq!(set.waivers.len(), 2);
        assert_eq!(set.waivers[1].asset_id, "test-002");
        assert_eq!(
            set.waivers[1].reason_code,
            WaiverReasonCode::NotYetImplemented
        );
    }

    #[test]
    fn parse_waiver_toml_comments_ignored() {
        let toml = r#"
# This is a comment
[[waiver]]
asset_id = "test-001" # inline comment
reason_code = "harness_gap"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"
"#;
        let set = parse_waiver_toml(toml).unwrap();
        assert_eq!(set.waivers.len(), 1);
        assert_eq!(set.waivers[0].asset_id, "test-001");
    }

    #[test]
    fn parse_waiver_toml_empty_content() {
        let set = parse_waiver_toml("").unwrap();
        assert!(set.waivers.is_empty());
    }

    #[test]
    fn parse_waiver_toml_missing_field_errors() {
        let toml = r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
"#;
        let result = parse_waiver_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_waiver_toml_unknown_field_errors() {
        let toml = r#"
[[waiver]]
asset_id = "test-001"
reason_code = "harness_gap"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"
unknown_field = "value"
"#;
        let result = parse_waiver_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_waiver_toml_invalid_reason_code_errors() {
        let toml = r#"
[[waiver]]
asset_id = "test-001"
reason_code = "invalid_code"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"
"#;
        let result = parse_waiver_toml(toml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_waiver_toml_kv_before_header_errors() {
        let toml = "asset_id = \"orphan\"\n";
        let result = parse_waiver_toml(toml);
        assert!(result.is_err());
    }

    // ── ConformanceWaiverSet::find_active ──────────────────────────────

    #[test]
    fn waiver_set_find_active_match() {
        let set = ConformanceWaiverSet {
            waivers: vec![ConformanceWaiver {
                asset_id: "asset-1".to_string(),
                reason_code: WaiverReasonCode::HarnessGap,
                tracking_bead: "bd-1".to_string(),
                expiry_date: "2030-01-01".to_string(),
            }],
        };
        let found = set.find_active("asset-1", "2025-06-01");
        assert!(found.is_some());
        assert_eq!(found.unwrap().asset_id, "asset-1");
    }

    #[test]
    fn waiver_set_find_active_expired() {
        let set = ConformanceWaiverSet {
            waivers: vec![ConformanceWaiver {
                asset_id: "asset-1".to_string(),
                reason_code: WaiverReasonCode::HarnessGap,
                tracking_bead: "bd-1".to_string(),
                expiry_date: "2020-01-01".to_string(),
            }],
        };
        let found = set.find_active("asset-1", "2025-06-01");
        assert!(found.is_none());
    }

    #[test]
    fn waiver_set_find_active_wrong_asset() {
        let set = ConformanceWaiverSet {
            waivers: vec![ConformanceWaiver {
                asset_id: "asset-1".to_string(),
                reason_code: WaiverReasonCode::HarnessGap,
                tracking_bead: "bd-1".to_string(),
                expiry_date: "2030-01-01".to_string(),
            }],
        };
        assert!(set.find_active("asset-99", "2025-06-01").is_none());
    }

    // ── ConformanceAssetRecord::validate ───────────────────────────────

    fn valid_asset_record() -> ConformanceAssetRecord {
        ConformanceAssetRecord {
            asset_id: "test-001".to_string(),
            source_donor: "test262".to_string(),
            semantic_domain: "evaluation".to_string(),
            normative_reference: "ECMA-262 §15.1".to_string(),
            fixture_path: "fixtures/test-001.json".to_string(),
            fixture_hash: "abc123".to_string(),
            expected_output_path: "expected/test-001.txt".to_string(),
            expected_output_hash: "def456".to_string(),
            import_date: "2025-01-01".to_string(),
            category: None,
            source_labels: vec![],
            sink_clearances: vec![],
            flow_path_type: None,
            expected_outcome: None,
            expected_evidence_type: None,
        }
    }

    #[test]
    fn asset_record_validate_valid() {
        assert!(valid_asset_record().validate().is_ok());
    }

    #[test]
    fn asset_record_validate_empty_asset_id() {
        let mut rec = valid_asset_record();
        rec.asset_id = "  ".to_string();
        let err = rec.validate().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("asset_id")
        ));
    }

    #[test]
    fn asset_record_validate_empty_source_donor() {
        let mut rec = valid_asset_record();
        rec.source_donor = "".to_string();
        let err = rec.validate().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("source_donor")
        ));
    }

    #[test]
    fn asset_record_validate_empty_fixture_hash() {
        let mut rec = valid_asset_record();
        rec.fixture_hash = "".to_string();
        let err = rec.validate().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("fixture_hash")
        ));
    }

    #[test]
    fn asset_record_validate_empty_import_date() {
        let mut rec = valid_asset_record();
        rec.import_date = " ".to_string();
        let err = rec.validate().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("import_date")
        ));
    }

    // ── ConformanceAssetRecord::is_ifc_asset ──────────────────────────

    #[test]
    fn asset_record_is_ifc_by_semantic_domain() {
        let mut rec = valid_asset_record();
        rec.semantic_domain = "ifc_corpus/benign".to_string();
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_ifc_by_category() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_not_ifc() {
        let rec = valid_asset_record();
        assert!(!rec.is_ifc_asset());
    }

    // ── ConformanceAssetRecord::ifc_metadata ──────────────────────────

    #[test]
    fn asset_record_ifc_metadata_complete() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("allow".to_string());
        rec.expected_evidence_type = Some("none".to_string());
        let meta = rec.ifc_metadata().unwrap();
        assert_eq!(meta.category, "benign");
        assert_eq!(meta.flow_path_type, "direct");
    }

    #[test]
    fn asset_record_ifc_metadata_missing_category_returns_none() {
        let rec = valid_asset_record();
        assert!(rec.ifc_metadata().is_none());
    }

    // ── validate_ifc_fields ───────────────────────────────────────────

    #[test]
    fn validate_ifc_fields_non_ifc_passes() {
        let rec = valid_asset_record();
        assert!(rec.validate_ifc_fields().is_ok());
    }

    #[test]
    fn validate_ifc_fields_valid_benign() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("allow".to_string());
        rec.expected_evidence_type = Some("none".to_string());
        assert!(rec.validate_ifc_fields().is_ok());
    }

    #[test]
    fn validate_ifc_fields_invalid_category() {
        let mut rec = valid_asset_record();
        rec.category = Some("invalid_category".to_string());
        rec.source_labels = vec!["credential".to_string()];
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "category",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_invalid_source_label() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["invalid_label".to_string()];
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "source_labels",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_benign_wrong_outcome_errors() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("block".to_string());
        rec.expected_evidence_type = Some("none".to_string());
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidIfcExpectation { .. }
        ));
    }

    #[test]
    fn validate_ifc_fields_exfil_correct() {
        let mut rec = valid_asset_record();
        rec.category = Some("exfil".to_string());
        rec.source_labels = vec!["key_material".to_string()];
        rec.sink_clearances = vec!["subprocess_ipc".to_string()];
        rec.flow_path_type = Some("indirect".to_string());
        rec.expected_outcome = Some("block".to_string());
        rec.expected_evidence_type = Some("flow_violation".to_string());
        assert!(rec.validate_ifc_fields().is_ok());
    }

    #[test]
    fn validate_ifc_fields_declassify_correct() {
        let mut rec = valid_asset_record();
        rec.category = Some("declassify".to_string());
        rec.source_labels = vec!["policy_protected".to_string()];
        rec.sink_clearances = vec!["explicit_declassify".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("declassify".to_string());
        rec.expected_evidence_type = Some("declassification_receipt".to_string());
        assert!(rec.validate_ifc_fields().is_ok());
    }

    // ── ConformanceRunnerConfig::validate ──────────────────────────────

    #[test]
    fn runner_config_default_validates() {
        assert!(ConformanceRunnerConfig::default().validate().is_ok());
    }

    #[test]
    fn runner_config_empty_trace_prefix_errors() {
        let cfg = ConformanceRunnerConfig {
            trace_prefix: "  ".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConformanceRunError::InvalidConfig(_)));
    }

    #[test]
    fn runner_config_empty_policy_id_errors() {
        let cfg = ConformanceRunnerConfig {
            policy_id: "".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConformanceRunError::InvalidConfig(_)));
    }

    #[test]
    fn runner_config_non_c_locale_errors() {
        let cfg = ConformanceRunnerConfig {
            locale: "en_US.UTF-8".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        if let ConformanceRunError::InvalidConfig(msg) = &err {
            assert!(msg.contains("locale"));
        } else {
            panic!("expected InvalidConfig");
        }
    }

    #[test]
    fn runner_config_non_utc_timezone_errors() {
        let cfg = ConformanceRunnerConfig {
            timezone: "America/New_York".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        if let ConformanceRunError::InvalidConfig(msg) = &err {
            assert!(msg.contains("timezone"));
        } else {
            panic!("expected InvalidConfig");
        }
    }

    #[test]
    fn runner_config_non_deterministic_gc_errors() {
        let cfg = ConformanceRunnerConfig {
            gc_schedule: "random".to_string(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        if let ConformanceRunError::InvalidConfig(msg) = &err {
            assert!(msg.contains("gc_schedule"));
        } else {
            panic!("expected InvalidConfig");
        }
    }

    #[test]
    fn runner_config_empty_run_date_errors() {
        let cfg = ConformanceRunnerConfig {
            run_date: " ".to_string(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    // ── classify_conformance_delta ─────────────────────────────────────

    #[test]
    fn classify_delta_identical_returns_empty() {
        let deltas = classify_conformance_delta("hello\nworld", "hello\nworld");
        assert!(deltas.is_empty());
    }

    #[test]
    fn classify_delta_props_field_removed() {
        let expected = "props: alpha, beta, gamma";
        let actual = "props: alpha, gamma";
        let deltas = classify_conformance_delta(expected, actual);
        assert!(!deltas.is_empty());
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::SchemaFieldRemoved)
        );
    }

    #[test]
    fn classify_delta_props_field_added() {
        let expected = "props: alpha";
        let actual = "props: alpha, beta";
        let deltas = classify_conformance_delta(expected, actual);
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::SchemaFieldAdded)
        );
    }

    #[test]
    fn classify_delta_error_format_change() {
        let expected = "TypeError|undefined is not a function";
        let actual = "ReferenceError|x is not defined";
        let deltas = classify_conformance_delta(expected, actual);
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::ErrorFormatChange)
        );
    }

    #[test]
    fn classify_delta_numeric_only_is_timing() {
        let expected = "latency 100 ms";
        let actual = "latency 200 ms";
        let deltas = classify_conformance_delta(expected, actual);
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::TimingChange)
        );
    }

    #[test]
    fn classify_delta_behavioral_semantic_shift() {
        let expected = "result: true";
        let actual = "result: false";
        let deltas = classify_conformance_delta(expected, actual);
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::BehavioralSemanticShift)
        );
    }

    // ── classify_failure_class ─────────────────────────────────────────

    #[test]
    fn classify_failure_class_empty_deltas_is_behavioral() {
        assert_eq!(
            classify_failure_class(&[]),
            ConformanceFailureClass::Behavioral
        );
    }

    #[test]
    fn classify_failure_class_breaking_wins() {
        let deltas = vec![
            ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::TimingChange,
                field: None,
                expected: None,
                actual: None,
                detail: String::new(),
            },
            ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::SchemaFieldRemoved,
                field: None,
                expected: None,
                actual: None,
                detail: String::new(),
            },
        ];
        assert_eq!(
            classify_failure_class(&deltas),
            ConformanceFailureClass::Breaking
        );
    }

    #[test]
    fn classify_failure_class_single_timing() {
        let deltas = vec![ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::TimingChange,
            field: None,
            expected: None,
            actual: None,
            detail: String::new(),
        }];
        assert_eq!(
            classify_failure_class(&deltas),
            ConformanceFailureClass::Performance
        );
    }

    // ── severity_for_failure_class ─────────────────────────────────────

    #[test]
    fn severity_mapping_exhaustive() {
        assert_eq!(
            severity_for_failure_class(ConformanceFailureClass::Breaking),
            ConformanceFailureSeverity::Critical
        );
        assert_eq!(
            severity_for_failure_class(ConformanceFailureClass::Behavioral),
            ConformanceFailureSeverity::Error
        );
        assert_eq!(
            severity_for_failure_class(ConformanceFailureClass::Observability),
            ConformanceFailureSeverity::Warning
        );
        assert_eq!(
            severity_for_failure_class(ConformanceFailureClass::Performance),
            ConformanceFailureSeverity::Warning
        );
    }

    // ── failure_class_priority ─────────────────────────────────────────

    #[test]
    fn failure_class_priority_ordering() {
        assert!(
            failure_class_priority(ConformanceFailureClass::Breaking)
                > failure_class_priority(ConformanceFailureClass::Behavioral)
        );
        assert!(
            failure_class_priority(ConformanceFailureClass::Behavioral)
                > failure_class_priority(ConformanceFailureClass::Observability)
        );
        assert!(
            failure_class_priority(ConformanceFailureClass::Observability)
                > failure_class_priority(ConformanceFailureClass::Performance)
        );
    }

    // ── delta_kind_to_failure_class ────────────────────────────────────

    #[test]
    fn delta_kind_to_failure_class_schema_changes_are_breaking() {
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::SchemaFieldAdded),
            ConformanceFailureClass::Breaking
        );
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::SchemaFieldRemoved),
            ConformanceFailureClass::Breaking
        );
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::SchemaFieldModified),
            ConformanceFailureClass::Breaking
        );
    }

    #[test]
    fn delta_kind_to_failure_class_behavioral_and_timing() {
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::BehavioralSemanticShift),
            ConformanceFailureClass::Behavioral
        );
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::TimingChange),
            ConformanceFailureClass::Performance
        );
        assert_eq!(
            delta_kind_to_failure_class(ConformanceDeltaKind::ErrorFormatChange),
            ConformanceFailureClass::Observability
        );
    }

    // ── numeric_delta_only ─────────────────────────────────────────────

    #[test]
    fn numeric_delta_only_true_when_only_numbers_differ() {
        assert!(numeric_delta_only("time 100 ms", "time 200 ms"));
    }

    #[test]
    fn numeric_delta_only_false_when_text_differs() {
        assert!(!numeric_delta_only("hello world", "hello earth"));
    }

    #[test]
    fn numeric_delta_only_false_when_lengths_differ() {
        assert!(!numeric_delta_only("a b", "a b c"));
    }

    #[test]
    fn numeric_delta_only_false_when_identical() {
        assert!(!numeric_delta_only("time 100 ms", "time 100 ms"));
    }

    #[test]
    fn numeric_delta_only_false_when_type_mismatch() {
        assert!(!numeric_delta_only("count 10", "count abc"));
    }

    // ── parse_props_fields ─────────────────────────────────────────────

    #[test]
    fn parse_props_fields_basic() {
        let result = parse_props_fields("props: beta, alpha, gamma").unwrap();
        assert_eq!(result, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn parse_props_fields_deduplicates() {
        let result = parse_props_fields("props: a, b, a").unwrap();
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn parse_props_fields_no_props_line() {
        assert!(parse_props_fields("no props here").is_none());
    }

    #[test]
    fn parse_props_fields_multiline_finds_first() {
        let payload = "line1\nprops: x, y\nline3";
        let result = parse_props_fields(payload).unwrap();
        assert_eq!(result, vec!["x", "y"]);
    }

    // ── extract_error_signature ────────────────────────────────────────

    #[test]
    fn extract_error_signature_found() {
        let payload = "line1\nTypeError|undefined is not a function\nline3";
        let sig = extract_error_signature(payload).unwrap();
        assert!(sig.contains("Error|"));
    }

    #[test]
    fn extract_error_signature_not_found() {
        assert!(extract_error_signature("no errors here").is_none());
    }

    // ── fnv1a64 ────────────────────────────────────────────────────────

    #[test]
    fn fnv1a64_deterministic() {
        let a = fnv1a64(b"hello");
        let b = fnv1a64(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv1a64_different_inputs_differ() {
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
    }

    #[test]
    fn fnv1a64_empty_is_offset_basis() {
        let result = fnv1a64(b"");
        assert_eq!(result, 0xcbf2_9ce4_8422_2325);
    }

    // ── sha256_hex ─────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex(b"test");
        let b = sha256_hex(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_hex_is_64_hex_chars() {
        let result = sha256_hex(b"data");
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_known_empty_hash() {
        // SHA-256 of empty string is well-known
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── digest_hex ─────────────────────────────────────────────────────

    #[test]
    fn digest_hex_is_16_hex_chars() {
        let result = digest_hex(b"test");
        assert_eq!(result.len(), 16);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── split_source_segments ──────────────────────────────────────────

    #[test]
    fn split_source_segments_by_semicolons() {
        let segments = split_source_segments("var a = 1; var b = 2;");
        assert_eq!(segments, vec!["var a = 1", "var b = 2"]);
    }

    #[test]
    fn split_source_segments_by_newlines() {
        let segments = split_source_segments("var a = 1\nvar b = 2");
        assert_eq!(segments, vec!["var a = 1", "var b = 2"]);
    }

    #[test]
    fn split_source_segments_empty_returns_void() {
        let segments = split_source_segments("");
        assert_eq!(segments, vec!["void 0"]);
    }

    #[test]
    fn split_source_segments_whitespace_only_returns_void() {
        let segments = split_source_segments("  \n  \n  ");
        assert_eq!(segments, vec!["void 0"]);
    }

    #[test]
    fn split_source_segments_normalizes_crlf() {
        let segments = split_source_segments("a\r\nb\rc");
        assert_eq!(segments, vec!["a", "b", "c"]);
    }

    // ── split_output_lines ─────────────────────────────────────────────

    #[test]
    fn split_output_lines_basic() {
        let lines = split_output_lines("line1\nline2");
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn split_output_lines_empty_returns_empty_marker() {
        let lines = split_output_lines("");
        assert_eq!(lines, vec!["<empty>"]);
    }

    // ── DonorHarnessAdapter ────────────────────────────────────────────

    #[test]
    fn donor_harness_adapter_replaces_realm() {
        let adapter = DonorHarnessAdapter;
        let result = adapter.adapt_source("$262.createRealm()");
        assert_eq!(result, "__franken_create_realm()");
    }

    #[test]
    fn donor_harness_adapter_replaces_done() {
        let adapter = DonorHarnessAdapter;
        let result = adapter.adapt_source("$DONE(error)");
        assert_eq!(result, "__franken_done(error)");
    }

    #[test]
    fn donor_harness_adapter_replaces_print() {
        let adapter = DonorHarnessAdapter;
        let result = adapter.adapt_source("print(42)");
        assert_eq!(result, "franken_print(42)");
    }

    #[test]
    fn donor_harness_adapter_all_replacements() {
        let adapter = DonorHarnessAdapter;
        let result = adapter.adapt_source("$262.createRealm(); print($DONE);");
        assert!(result.contains("__franken_create_realm()"));
        assert!(result.contains("franken_print("));
        assert!(result.contains("__franken_done"));
    }

    // ── ConformanceReproMetadata default ───────────────────────────────

    #[test]
    fn repro_metadata_default_has_engine_version() {
        let meta = ConformanceReproMetadata::default();
        assert!(meta.version_combination.contains_key("franken_engine"));
        assert_eq!(meta.issue_tracker_project, "beads");
        assert_eq!(meta.first_seen_commit, "unknown");
    }

    // ── ConformanceRunnerConfig default ────────────────────────────────

    #[test]
    fn runner_config_default_values() {
        let cfg = ConformanceRunnerConfig::default();
        assert_eq!(cfg.locale, "C");
        assert_eq!(cfg.timezone, "UTC");
        assert_eq!(cfg.gc_schedule, "deterministic");
        assert_eq!(cfg.seed, 7);
    }

    // ── ConformanceRunner::env_fingerprint ─────────────────────────────

    #[test]
    fn env_fingerprint_deterministic() {
        let runner = ConformanceRunner::default();
        let a = runner.env_fingerprint();
        let b = runner.env_fingerprint();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex
    }

    // ── ConformanceCiGateError ─────────────────────────────────────────

    #[test]
    fn ci_gate_error_display() {
        let err = ConformanceCiGateError {
            failed: 3,
            errored: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("failed=3"));
        assert!(msg.contains("errored=1"));
    }

    #[test]
    fn enforce_ci_gate_passes_on_zero_failures() {
        let result = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 5,
                passed: 5,
                failed: 0,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        assert!(result.enforce_ci_gate().is_ok());
    }

    #[test]
    fn enforce_ci_gate_fails_on_failures() {
        let result = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 5,
                passed: 3,
                failed: 2,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        let err = result.enforce_ci_gate().unwrap_err();
        assert_eq!(err.failed, 2);
    }

    #[test]
    fn enforce_ci_gate_fails_on_errors() {
        let result = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 5,
                passed: 4,
                failed: 0,
                waived: 0,
                errored: 1,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        assert!(result.enforce_ci_gate().is_err());
    }

    // ── ConformanceManifestError Display ───────────────────────────────

    #[test]
    fn manifest_error_display_unsupported_schema() {
        let err = ConformanceManifestError::UnsupportedSchema {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("v1"));
        assert!(msg.contains("v2"));
    }

    #[test]
    fn manifest_error_display_empty_asset_set() {
        let msg = ConformanceManifestError::EmptyAssetSet.to_string();
        assert!(msg.contains("no assets"));
    }

    #[test]
    fn manifest_error_display_missing_field() {
        let msg = ConformanceManifestError::MissingField("asset_id").to_string();
        assert!(msg.contains("asset_id"));
    }

    // ── ConformanceReplayVerificationError Display ─────────────────────

    #[test]
    fn replay_error_display_not_reproduced() {
        let msg = ConformanceReplayVerificationError::FailureNotReproduced.to_string();
        assert!(msg.contains("outputs are equal"));
    }

    #[test]
    fn replay_error_display_class_mismatch() {
        let err = ConformanceReplayVerificationError::FailureClassMismatch {
            expected: ConformanceFailureClass::Breaking,
            actual: ConformanceFailureClass::Performance,
        };
        let msg = err.to_string();
        assert!(msg.contains("Breaking"));
        assert!(msg.contains("Performance"));
    }

    #[test]
    fn replay_error_display_delta_drift() {
        let msg = ConformanceReplayVerificationError::DeltaClassificationDrift.to_string();
        assert!(msg.contains("drifted"));
    }

    #[test]
    fn replay_error_display_digest_mismatch() {
        let err = ConformanceReplayVerificationError::DigestMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("aaa"));
        assert!(msg.contains("bbb"));
    }

    // ── ConformanceRunError Display ────────────────────────────────────

    #[test]
    fn run_error_display_invalid_config() {
        let msg = ConformanceRunError::InvalidConfig("bad field".to_string()).to_string();
        assert!(msg.contains("bad field"));
    }

    #[test]
    fn run_error_display_repro_invariant() {
        let err = ConformanceRunError::ReproInvariant {
            asset_id: "asset-1".to_string(),
            detail: "mismatch".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("asset-1"));
        assert!(msg.contains("mismatch"));
    }

    // ── build_failure_id / repro_verification_digest ──────────────────

    #[test]
    fn build_failure_id_deterministic() {
        let a = build_failure_id("asset-1", 7, "expected", "actual");
        let b = build_failure_id("asset-1", 7, "expected", "actual");
        assert_eq!(a, b);
        assert!(a.starts_with("cf-"));
        assert_eq!(a.len(), 3 + 16); // "cf-" + 16 hex chars
    }

    #[test]
    fn build_failure_id_changes_with_input() {
        let a = build_failure_id("asset-1", 7, "expected", "actual");
        let b = build_failure_id("asset-2", 7, "expected", "actual");
        assert_ne!(a, b);
    }

    #[test]
    fn repro_verification_digest_deterministic() {
        let a = repro_verification_digest(7, "exp", "act");
        let b = repro_verification_digest(7, "exp", "act");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16); // digest_hex = 16 chars
    }

    // ── preserves_failure_class ────────────────────────────────────────

    #[test]
    fn preserves_failure_class_false_when_equal() {
        assert!(!preserves_failure_class(
            "hello",
            "hello",
            ConformanceFailureClass::Behavioral
        ));
    }

    #[test]
    fn preserves_failure_class_true_when_class_matches() {
        // Two outputs that differ only in non-props, non-error, non-numeric content
        // → BehavioralSemanticShift → Behavioral
        assert!(preserves_failure_class(
            "result: true",
            "result: false",
            ConformanceFailureClass::Behavioral
        ));
    }

    // ── ifc_label_taxonomy_hash ────────────────────────────────────────

    #[test]
    fn ifc_label_taxonomy_hash_deterministic() {
        let a = ifc_label_taxonomy_hash();
        let b = ifc_label_taxonomy_hash();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    // ── ConformanceAssetManifest ───────────────────────────────────────

    #[test]
    fn manifest_current_schema_is_v1() {
        assert_eq!(
            ConformanceAssetManifest::CURRENT_SCHEMA,
            "franken-engine.conformance-assets.v1"
        );
    }

    #[test]
    fn manifest_validate_wrong_schema_errors() {
        let manifest = ConformanceAssetManifest {
            schema_version: "wrong-version".to_string(),
            generated_at_utc: "2025-01-01T00:00:00Z".to_string(),
            assets: vec![valid_asset_record()],
        };
        let err = manifest
            .validate_and_resolve(Path::new("/fake/manifest.json"))
            .unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::UnsupportedSchema { .. }
        ));
    }

    #[test]
    fn manifest_validate_empty_assets_errors() {
        let manifest = ConformanceAssetManifest {
            schema_version: ConformanceAssetManifest::CURRENT_SCHEMA.to_string(),
            generated_at_utc: "2025-01-01T00:00:00Z".to_string(),
            assets: vec![],
        };
        let err = manifest
            .validate_and_resolve(Path::new("/fake/manifest.json"))
            .unwrap_err();
        assert!(matches!(err, ConformanceManifestError::EmptyAssetSet));
    }

    // ── ConformanceMinimizedReproArtifact ──────────────────────────────

    #[test]
    fn repro_artifact_current_schema() {
        assert_eq!(
            ConformanceMinimizedReproArtifact::CURRENT_SCHEMA,
            "franken-engine.conformance-min-repro.v1"
        );
    }

    // ── serde round-trips ──────────────────────────────────────────────

    #[test]
    fn conformance_failure_class_serde_round_trip() {
        for class in [
            ConformanceFailureClass::Breaking,
            ConformanceFailureClass::Behavioral,
            ConformanceFailureClass::Observability,
            ConformanceFailureClass::Performance,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: ConformanceFailureClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, class);
        }
    }

    #[test]
    fn conformance_failure_severity_serde_round_trip() {
        for sev in [
            ConformanceFailureSeverity::Info,
            ConformanceFailureSeverity::Warning,
            ConformanceFailureSeverity::Error,
            ConformanceFailureSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: ConformanceFailureSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, sev);
        }
    }

    #[test]
    fn conformance_delta_kind_serde_round_trip() {
        for kind in [
            ConformanceDeltaKind::SchemaFieldAdded,
            ConformanceDeltaKind::SchemaFieldRemoved,
            ConformanceDeltaKind::SchemaFieldModified,
            ConformanceDeltaKind::BehavioralSemanticShift,
            ConformanceDeltaKind::TimingChange,
            ConformanceDeltaKind::ErrorFormatChange,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ConformanceDeltaKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn conformance_waiver_serde_round_trip() {
        let waiver = ConformanceWaiver {
            asset_id: "test-001".to_string(),
            reason_code: WaiverReasonCode::HostHookMissing,
            tracking_bead: "bd-42".to_string(),
            expiry_date: "2030-12-31".to_string(),
        };
        let json = serde_json::to_string(&waiver).unwrap();
        let back: ConformanceWaiver = serde_json::from_str(&json).unwrap();
        assert_eq!(back, waiver);
    }

    #[test]
    fn conformance_delta_classification_serde_round_trip() {
        let delta = ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::SchemaFieldAdded,
            field: Some("new_field".to_string()),
            expected: Some("missing".to_string()),
            actual: Some("present".to_string()),
            detail: "field added".to_string(),
        };
        let json = serde_json::to_string(&delta).unwrap();
        let back: ConformanceDeltaClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, delta);
    }

    #[test]
    fn donor_fixture_serde_round_trip() {
        let fixture = DonorFixture {
            donor_harness: "test262".to_string(),
            source: "var x = 1;".to_string(),
            observed_output: "1".to_string(),
        };
        let json = serde_json::to_string(&fixture).unwrap();
        let back: DonorFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fixture);
    }

    // ── minimize_conformance_case ──────────────────────────────────────

    #[test]
    fn minimize_conformance_case_preserves_difference() {
        let source = "var a = 1;\nvar b = 2;\nvar c = 3;";
        let expected = "result: true";
        let actual = "result: false";
        let outcome = minimize_conformance_case(
            source,
            expected,
            actual,
            ConformanceFailureClass::Behavioral,
        );
        // The minimized outputs should still differ
        assert_ne!(
            outcome.minimized_expected_output,
            outcome.minimized_actual_output
        );
        assert_eq!(outcome.summary.strategy, "greedy-delta-debugging");
    }

    // ── reduce_output_lines ────────────────────────────────────────────

    #[test]
    fn reduce_output_lines_strips_common_prefix_and_suffix() {
        let expected = vec![
            "common1".to_string(),
            "differ_exp".to_string(),
            "common2".to_string(),
        ];
        let actual = vec![
            "common1".to_string(),
            "differ_act".to_string(),
            "common2".to_string(),
        ];
        let (red_exp, red_act) =
            reduce_output_lines(&expected, &actual, ConformanceFailureClass::Behavioral);
        // Should reduce to just the differing lines (or fallback to full if class not preserved)
        assert!(!red_exp.is_empty());
        assert!(!red_act.is_empty());
    }

    #[test]
    fn reduce_output_lines_empty_inputs() {
        let (red_exp, red_act) = reduce_output_lines(&[], &[], ConformanceFailureClass::Behavioral);
        // When both expected and actual are empty and identical, the reduced
        // "<empty>" sentinel triggers the preservation check which fails
        // (equal outputs cannot preserve a failure class), so the original
        // empty vecs are returned.  This is correct: identical empty outputs
        // have no divergence to reduce.
        assert!(red_exp.is_empty());
        assert!(red_act.is_empty());
    }

    // ── ConformanceManifestError Display (remaining variants) ────────

    #[test]
    fn manifest_error_display_manifest_has_no_parent() {
        let msg = ConformanceManifestError::ManifestHasNoParent.to_string();
        assert!(msg.contains("no parent"));
    }

    #[test]
    fn manifest_error_display_invalid_field_value() {
        let err = ConformanceManifestError::InvalidFieldValue {
            field: "category",
            value: "unknown".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("category"));
        assert!(msg.contains("unknown"));
    }

    #[test]
    fn manifest_error_display_invalid_ifc_expectation() {
        let err = ConformanceManifestError::InvalidIfcExpectation {
            asset_id: "asset-1".to_string(),
            category: "benign".to_string(),
            expected_outcome: "block".to_string(),
            expected_evidence_type: "flow_violation".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("asset-1"));
        assert!(msg.contains("benign"));
    }

    #[test]
    fn manifest_error_display_asset_io() {
        let err = ConformanceManifestError::AssetIo {
            asset_id: "asset-1".to_string(),
            path: PathBuf::from("/tmp/missing.json"),
            source: io::Error::new(io::ErrorKind::NotFound, "file not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("asset-1"));
        assert!(msg.contains("missing.json"));
    }

    #[test]
    fn manifest_error_display_fixture_hash_mismatch() {
        let err = ConformanceManifestError::FixtureHashMismatch {
            asset_id: "asset-1".to_string(),
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("fixture hash mismatch"));
        assert!(msg.contains("aaa"));
        assert!(msg.contains("bbb"));
    }

    #[test]
    fn manifest_error_display_expected_output_hash_mismatch() {
        let err = ConformanceManifestError::ExpectedOutputHashMismatch {
            asset_id: "asset-1".to_string(),
            expected: "xxx".to_string(),
            actual: "yyy".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("expected output hash mismatch"));
        assert!(msg.contains("xxx"));
    }

    // ── ConformanceManifestError::source ────────────────────────────

    #[test]
    fn manifest_error_source_asset_io_returns_some() {
        let err = ConformanceManifestError::AssetIo {
            asset_id: "a".to_string(),
            path: PathBuf::from("/tmp"),
            source: io::Error::new(io::ErrorKind::NotFound, "nf"),
        };
        assert!(err.source().is_some());
    }

    #[test]
    fn manifest_error_source_non_io_returns_none() {
        let err = ConformanceManifestError::EmptyAssetSet;
        assert!(err.source().is_none());
        let err2 = ConformanceManifestError::MissingField("x");
        assert!(err2.source().is_none());
    }

    // ── ConformanceRunError Display (remaining variants) ────────────

    #[test]
    fn run_error_display_manifest() {
        let inner = ConformanceManifestError::EmptyAssetSet;
        let err = ConformanceRunError::Manifest(inner);
        let msg = err.to_string();
        assert!(msg.contains("no assets"));
    }

    #[test]
    fn run_error_display_fixture_io() {
        let err = ConformanceRunError::FixtureIo {
            asset_id: "fix-1".to_string(),
            path: PathBuf::from("/tmp/fixture.json"),
            source: io::Error::new(io::ErrorKind::NotFound, "missing"),
        };
        let msg = err.to_string();
        assert!(msg.contains("fix-1"));
        assert!(msg.contains("fixture"));
    }

    #[test]
    fn run_error_display_invalid_fixture() {
        let err = ConformanceRunError::InvalidFixture {
            asset_id: "bad-1".to_string(),
            source: io::Error::new(io::ErrorKind::InvalidData, "parse error"),
        };
        let msg = err.to_string();
        assert!(msg.contains("bad-1"));
        assert!(msg.contains("invalid donor fixture"));
    }

    #[test]
    fn run_error_display_expected_output_io() {
        let err = ConformanceRunError::ExpectedOutputIo {
            asset_id: "exp-1".to_string(),
            path: PathBuf::from("/tmp/expected.txt"),
            source: io::Error::new(io::ErrorKind::NotFound, "not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("exp-1"));
        assert!(msg.contains("expected output"));
    }

    #[test]
    fn run_error_display_io() {
        let err = ConformanceRunError::Io(io::Error::other("oops"));
        let msg = err.to_string();
        assert!(msg.contains("oops"));
    }

    // ── ConformanceRunError::source ─────────────────────────────────

    #[test]
    fn run_error_source_manifest_returns_some() {
        let err = ConformanceRunError::Manifest(ConformanceManifestError::EmptyAssetSet);
        assert!(err.source().is_some());
    }

    #[test]
    fn run_error_source_fixture_io_returns_some() {
        let err = ConformanceRunError::FixtureIo {
            asset_id: "a".to_string(),
            path: PathBuf::from("/tmp"),
            source: io::Error::new(io::ErrorKind::NotFound, "nf"),
        };
        assert!(err.source().is_some());
    }

    #[test]
    fn run_error_source_invalid_fixture_returns_some() {
        let err = ConformanceRunError::InvalidFixture {
            asset_id: "a".to_string(),
            source: io::Error::new(io::ErrorKind::InvalidData, "bad"),
        };
        assert!(err.source().is_some());
    }

    #[test]
    fn run_error_source_expected_output_io_returns_some() {
        let err = ConformanceRunError::ExpectedOutputIo {
            asset_id: "a".to_string(),
            path: PathBuf::from("/tmp"),
            source: io::Error::new(io::ErrorKind::NotFound, "nf"),
        };
        assert!(err.source().is_some());
    }

    #[test]
    fn run_error_source_io_returns_some() {
        let err = ConformanceRunError::Io(io::Error::other("x"));
        assert!(err.source().is_some());
    }

    #[test]
    fn run_error_source_invalid_config_returns_none() {
        let err = ConformanceRunError::InvalidConfig("bad".to_string());
        assert!(err.source().is_none());
    }

    #[test]
    fn run_error_source_repro_invariant_returns_none() {
        let err = ConformanceRunError::ReproInvariant {
            asset_id: "a".to_string(),
            detail: "d".to_string(),
        };
        assert!(err.source().is_none());
    }

    // ── ConformanceRunError From<ConformanceManifestError> ──────────

    #[test]
    fn run_error_from_manifest_error() {
        let inner = ConformanceManifestError::EmptyAssetSet;
        let err: ConformanceRunError = inner.into();
        assert!(matches!(err, ConformanceRunError::Manifest(_)));
    }

    // ── ConformanceAssetRecord validate remaining fields ────────────

    #[test]
    fn asset_record_validate_empty_semantic_domain() {
        let mut rec = valid_asset_record();
        rec.semantic_domain = "".to_string();
        assert!(matches!(
            rec.validate().unwrap_err(),
            ConformanceManifestError::MissingField("semantic_domain")
        ));
    }

    #[test]
    fn asset_record_validate_empty_normative_reference() {
        let mut rec = valid_asset_record();
        rec.normative_reference = " ".to_string();
        assert!(matches!(
            rec.validate().unwrap_err(),
            ConformanceManifestError::MissingField("normative_reference")
        ));
    }

    #[test]
    fn asset_record_validate_empty_fixture_path() {
        let mut rec = valid_asset_record();
        rec.fixture_path = "".to_string();
        assert!(matches!(
            rec.validate().unwrap_err(),
            ConformanceManifestError::MissingField("fixture_path")
        ));
    }

    #[test]
    fn asset_record_validate_empty_expected_output_path() {
        let mut rec = valid_asset_record();
        rec.expected_output_path = " ".to_string();
        assert!(matches!(
            rec.validate().unwrap_err(),
            ConformanceManifestError::MissingField("expected_output_path")
        ));
    }

    #[test]
    fn asset_record_validate_empty_expected_output_hash() {
        let mut rec = valid_asset_record();
        rec.expected_output_hash = "".to_string();
        assert!(matches!(
            rec.validate().unwrap_err(),
            ConformanceManifestError::MissingField("expected_output_hash")
        ));
    }

    // ── validate_ifc_fields edge cases ──────────────────────────────

    #[test]
    fn validate_ifc_fields_empty_source_labels_errors() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        // source_labels is empty → triggers error
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("source_labels")
        ));
    }

    #[test]
    fn validate_ifc_fields_empty_sink_clearances_errors() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        // sink_clearances is empty → triggers error
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("sink_clearances")
        ));
    }

    #[test]
    fn validate_ifc_fields_invalid_sink_clearance() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["bad_clearance".to_string()];
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "sink_clearances",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_missing_flow_path_type() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        // flow_path_type is None
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("flow_path_type")
        ));
    }

    #[test]
    fn validate_ifc_fields_invalid_flow_path_type() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("invalid_flow".to_string());
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "flow_path_type",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_missing_expected_outcome() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        // expected_outcome is None
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("expected_outcome")
        ));
    }

    #[test]
    fn validate_ifc_fields_invalid_expected_outcome() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("invalid_outcome".to_string());
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "expected_outcome",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_missing_expected_evidence_type() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("allow".to_string());
        // expected_evidence_type is None
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::MissingField("expected_evidence_type")
        ));
    }

    #[test]
    fn validate_ifc_fields_invalid_expected_evidence_type() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("allow".to_string());
        rec.expected_evidence_type = Some("bad_evidence".to_string());
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidFieldValue {
                field: "expected_evidence_type",
                ..
            }
        ));
    }

    #[test]
    fn validate_ifc_fields_exfil_wrong_outcome() {
        let mut rec = valid_asset_record();
        rec.category = Some("exfil".to_string());
        rec.source_labels = vec!["key_material".to_string()];
        rec.sink_clearances = vec!["subprocess_ipc".to_string()];
        rec.flow_path_type = Some("indirect".to_string());
        rec.expected_outcome = Some("allow".to_string()); // should be block
        rec.expected_evidence_type = Some("flow_violation".to_string());
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidIfcExpectation { .. }
        ));
    }

    #[test]
    fn validate_ifc_fields_declassify_wrong_evidence() {
        let mut rec = valid_asset_record();
        rec.category = Some("declassify".to_string());
        rec.source_labels = vec!["policy_protected".to_string()];
        rec.sink_clearances = vec!["explicit_declassify".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("declassify".to_string());
        rec.expected_evidence_type = Some("none".to_string()); // should be declassification_receipt
        let err = rec.validate_ifc_fields().unwrap_err();
        assert!(matches!(
            err,
            ConformanceManifestError::InvalidIfcExpectation { .. }
        ));
    }

    // ── is_ifc_asset additional triggers ────────────────────────────

    #[test]
    fn asset_record_is_ifc_by_source_labels() {
        let mut rec = valid_asset_record();
        rec.source_labels = vec!["credential".to_string()];
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_ifc_by_sink_clearances() {
        let mut rec = valid_asset_record();
        rec.sink_clearances = vec!["network_egress".to_string()];
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_ifc_by_flow_path_type() {
        let mut rec = valid_asset_record();
        rec.flow_path_type = Some("direct".to_string());
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_ifc_by_expected_outcome() {
        let mut rec = valid_asset_record();
        rec.expected_outcome = Some("allow".to_string());
        assert!(rec.is_ifc_asset());
    }

    #[test]
    fn asset_record_is_ifc_by_expected_evidence_type() {
        let mut rec = valid_asset_record();
        rec.expected_evidence_type = Some("none".to_string());
        assert!(rec.is_ifc_asset());
    }

    // ── ConformanceRunnerConfig validate remaining branches ─────────

    #[test]
    fn runner_config_empty_first_seen_commit_errors() {
        let mut cfg = ConformanceRunnerConfig::default();
        cfg.repro_metadata.first_seen_commit = " ".to_string();
        let err = cfg.validate().unwrap_err();
        if let ConformanceRunError::InvalidConfig(msg) = &err {
            assert!(msg.contains("first_seen_commit"));
        } else {
            panic!("expected InvalidConfig");
        }
    }

    #[test]
    fn runner_config_empty_issue_tracker_project_errors() {
        let mut cfg = ConformanceRunnerConfig::default();
        cfg.repro_metadata.issue_tracker_project = "".to_string();
        let err = cfg.validate().unwrap_err();
        if let ConformanceRunError::InvalidConfig(msg) = &err {
            assert!(msg.contains("issue_tracker_project"));
        } else {
            panic!("expected InvalidConfig");
        }
    }

    // ── build_ifc_conformance_summary ───────────────────────────────

    #[test]
    fn build_ifc_conformance_summary_no_ifc_logs_returns_none() {
        let run = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![ConformanceLogEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                asset_id: "a".to_string(),
                workload_id: "w".to_string(),
                semantic_domain: "eval".to_string(),
                category: None, // not IFC
                source_labels: vec![],
                sink_clearances: vec![],
                flow_path_type: None,
                expected_outcome: None,
                actual_outcome: None,
                evidence_type: None,
                evidence_id: None,
                duration_us: 100,
                error_detail: None,
            }],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 1,
                passed: 1,
                failed: 0,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        assert!(build_ifc_conformance_summary(&run).is_none());
    }

    #[test]
    fn build_ifc_conformance_summary_with_ifc_logs() {
        let run = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![
                ConformanceLogEvent {
                    trace_id: "t1".to_string(),
                    decision_id: "d1".to_string(),
                    policy_id: "policy-v1".to_string(),
                    component: "c".to_string(),
                    event: "e".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                    asset_id: "a1".to_string(),
                    workload_id: "w1".to_string(),
                    semantic_domain: "ifc_corpus/benign".to_string(),
                    category: Some("benign".to_string()),
                    source_labels: vec!["credential".to_string()],
                    sink_clearances: vec!["network_egress".to_string()],
                    flow_path_type: Some("direct".to_string()),
                    expected_outcome: Some("allow".to_string()),
                    actual_outcome: Some("allow".to_string()),
                    evidence_type: None,
                    evidence_id: None,
                    duration_us: 100,
                    error_detail: None,
                },
                ConformanceLogEvent {
                    trace_id: "t2".to_string(),
                    decision_id: "d2".to_string(),
                    policy_id: "policy-v1".to_string(),
                    component: "c".to_string(),
                    event: "e".to_string(),
                    outcome: "fail".to_string(),
                    error_code: None,
                    asset_id: "a2".to_string(),
                    workload_id: "w2".to_string(),
                    semantic_domain: "ifc_corpus/exfil".to_string(),
                    category: Some("exfil".to_string()),
                    source_labels: vec!["key_material".to_string()],
                    sink_clearances: vec!["subprocess_ipc".to_string()],
                    flow_path_type: Some("direct".to_string()),
                    expected_outcome: Some("block".to_string()),
                    actual_outcome: Some("allow".to_string()), // false negative
                    evidence_type: None,
                    evidence_id: None,
                    duration_us: 200,
                    error_detail: None,
                },
            ],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 2,
                passed: 1,
                failed: 1,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        let summary = build_ifc_conformance_summary(&run).unwrap();
        assert_eq!(summary.run_id, "run-1");
        assert!(summary.category_counts.contains_key("benign"));
        assert!(summary.category_counts.contains_key("exfil"));
        assert_eq!(summary.false_negative_count, 1);
        assert_eq!(summary.false_negative_direct_indirect_count, 1);
        assert_eq!(summary.false_positive_count, 0);
        assert_eq!(summary.ci_blocking_failures, 1);
    }

    #[test]
    fn build_ifc_summary_false_positive_detection() {
        let run = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![ConformanceLogEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "fail".to_string(),
                error_code: None,
                asset_id: "a".to_string(),
                workload_id: "w".to_string(),
                semantic_domain: "ifc_corpus/benign".to_string(),
                category: Some("benign".to_string()),
                source_labels: vec!["credential".to_string()],
                sink_clearances: vec!["network_egress".to_string()],
                flow_path_type: Some("direct".to_string()),
                expected_outcome: Some("allow".to_string()),
                actual_outcome: Some("block".to_string()), // false positive
                evidence_type: None,
                evidence_id: None,
                duration_us: 50,
                error_detail: None,
            }],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 1,
                passed: 0,
                failed: 1,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        let summary = build_ifc_conformance_summary(&run).unwrap();
        assert_eq!(summary.false_positive_count, 1);
        assert_eq!(summary.ci_blocking_failures, 1);
    }

    #[test]
    fn build_ifc_summary_waived_outcome_counted() {
        let run = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![ConformanceLogEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "waived".to_string(),
                error_code: None,
                asset_id: "a".to_string(),
                workload_id: "w".to_string(),
                semantic_domain: "ifc".to_string(),
                category: Some("benign".to_string()),
                source_labels: vec![],
                sink_clearances: vec![],
                flow_path_type: None,
                expected_outcome: None,
                actual_outcome: None,
                evidence_type: None,
                evidence_id: None,
                duration_us: 50,
                error_detail: None,
            }],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 1,
                passed: 0,
                failed: 0,
                waived: 1,
                errored: 0,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        let summary = build_ifc_conformance_summary(&run).unwrap();
        let benign = &summary.category_counts["benign"];
        assert_eq!(benign.waived, 1);
        assert_eq!(benign.total, 1);
    }

    #[test]
    fn build_ifc_summary_errored_outcome_counted() {
        let run = ConformanceRunResult {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            logs: vec![ConformanceLogEvent {
                trace_id: "t".to_string(),
                decision_id: "d".to_string(),
                policy_id: "p".to_string(),
                component: "c".to_string(),
                event: "e".to_string(),
                outcome: "error".to_string(), // not pass/fail/waived
                error_code: None,
                asset_id: "a".to_string(),
                workload_id: "w".to_string(),
                semantic_domain: "ifc".to_string(),
                category: Some("exfil".to_string()),
                source_labels: vec![],
                sink_clearances: vec![],
                flow_path_type: None,
                expected_outcome: None,
                actual_outcome: None,
                evidence_type: None,
                evidence_id: None,
                duration_us: 50,
                error_detail: None,
            }],
            summary: ConformanceRunSummary {
                run_id: "run-1".to_string(),
                asset_manifest_hash: "hash".to_string(),
                total_assets: 1,
                passed: 0,
                failed: 0,
                waived: 0,
                errored: 1,
                env_fingerprint: "fp".to_string(),
            },
            minimized_repros: vec![],
        };
        let summary = build_ifc_conformance_summary(&run).unwrap();
        let exfil = &summary.category_counts["exfil"];
        assert_eq!(exfil.errored, 1);
    }

    // ── serde round-trips (remaining types) ─────────────────────────

    #[test]
    fn conformance_waiver_set_serde_round_trip() {
        let set = ConformanceWaiverSet {
            waivers: vec![ConformanceWaiver {
                asset_id: "a".to_string(),
                reason_code: WaiverReasonCode::IntentionalDivergence,
                tracking_bead: "bd-1".to_string(),
                expiry_date: "2030-01-01".to_string(),
            }],
        };
        let json = serde_json::to_string(&set).unwrap();
        let back: ConformanceWaiverSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn conformance_log_event_serde_round_trip() {
        let event = ConformanceLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            asset_id: "a".to_string(),
            workload_id: "w".to_string(),
            semantic_domain: "eval".to_string(),
            category: Some("benign".to_string()),
            source_labels: vec!["credential".to_string()],
            sink_clearances: vec!["network_egress".to_string()],
            flow_path_type: Some("direct".to_string()),
            expected_outcome: Some("allow".to_string()),
            actual_outcome: Some("allow".to_string()),
            evidence_type: Some("none".to_string()),
            evidence_id: Some("ev-1".to_string()),
            duration_us: 42,
            error_detail: Some("detail".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ConformanceLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn conformance_run_summary_serde_round_trip() {
        let summary = ConformanceRunSummary {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 10,
            passed: 7,
            failed: 2,
            waived: 1,
            errored: 0,
            env_fingerprint: "fp".to_string(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: ConformanceRunSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    #[test]
    fn conformance_repro_metadata_serde_round_trip() {
        let meta = ConformanceReproMetadata::default();
        let json = serde_json::to_string(&meta).unwrap();
        let back: ConformanceReproMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn conformance_runner_config_serde_round_trip() {
        let cfg = ConformanceRunnerConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ConformanceRunnerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn conformance_repro_environment_serde_round_trip() {
        let env = ConformanceReproEnvironment {
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            rust_toolchain: "stable".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: ConformanceReproEnvironment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn conformance_replay_contract_serde_round_trip() {
        let contract = ConformanceReplayContract {
            deterministic_seed: 42,
            replay_command: "cmd".to_string(),
            verification_command: "verify".to_string(),
            verification_digest: "digest".to_string(),
        };
        let json = serde_json::to_string(&contract).unwrap();
        let back: ConformanceReplayContract = serde_json::from_str(&json).unwrap();
        assert_eq!(back, contract);
    }

    #[test]
    fn conformance_issue_link_serde_round_trip() {
        let link = ConformanceIssueLink {
            tracker: "beads".to_string(),
            issue_id: "bd-42".to_string(),
        };
        let json = serde_json::to_string(&link).unwrap();
        let back: ConformanceIssueLink = serde_json::from_str(&json).unwrap();
        assert_eq!(back, link);
    }

    #[test]
    fn conformance_run_linkage_serde_round_trip() {
        let linkage = ConformanceRunLinkage {
            run_id: "r".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            ci_run_id: Some("ci-1".to_string()),
        };
        let json = serde_json::to_string(&linkage).unwrap();
        let back: ConformanceRunLinkage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, linkage);
    }

    #[test]
    fn conformance_minimization_summary_serde_round_trip() {
        let summary = ConformanceMinimizationSummary {
            strategy: "greedy".to_string(),
            original_source_lines: 10,
            minimized_source_lines: 3,
            original_expected_lines: 5,
            minimized_expected_lines: 2,
            original_actual_lines: 5,
            minimized_actual_lines: 2,
            preserved_failure_class: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: ConformanceMinimizationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    #[test]
    fn conformance_minimized_failing_vector_serde_round_trip() {
        let vector = ConformanceMinimizedFailingVector {
            asset_id: "a".to_string(),
            source_donor: "d".to_string(),
            semantic_domain: "s".to_string(),
            normative_reference: "n".to_string(),
            fixture: DonorFixture {
                donor_harness: "h".to_string(),
                source: "src".to_string(),
                observed_output: "out".to_string(),
            },
            expected_output: "exp".to_string(),
        };
        let json = serde_json::to_string(&vector).unwrap();
        let back: ConformanceMinimizedFailingVector = serde_json::from_str(&json).unwrap();
        assert_eq!(back, vector);
    }

    #[test]
    fn conformance_asset_record_serde_round_trip() {
        let rec = valid_asset_record();
        let json = serde_json::to_string(&rec).unwrap();
        let back: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn conformance_asset_manifest_serde_round_trip() {
        let manifest = ConformanceAssetManifest {
            schema_version: ConformanceAssetManifest::CURRENT_SCHEMA.to_string(),
            generated_at_utc: "2025-01-01T00:00:00Z".to_string(),
            assets: vec![valid_asset_record()],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ConformanceAssetManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    // ── ConformanceReplayVerificationError ──────────────────────────

    #[test]
    fn replay_verification_error_is_std_error() {
        let err = ConformanceReplayVerificationError::FailureNotReproduced;
        // Verify it implements std::error::Error
        let _: &dyn Error = &err;
    }

    // ── canonical_json_bytes ────────────────────────────────────────

    #[test]
    fn canonical_json_bytes_round_trip() {
        let value = serde_json::json!({"key": "value"});
        let bytes = canonical_json_bytes(&value).unwrap();
        let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, value);
    }

    // ── write_atomic ───────────────────────────────────────────────

    #[test]
    fn write_atomic_creates_file() {
        let dir = std::env::temp_dir().join("franken_test_write_atomic");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("sub/test.txt");
        write_atomic(&path, b"hello world").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_overwrites_existing() {
        let dir = std::env::temp_dir().join("franken_test_write_atomic_overwrite");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file.txt");
        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "second");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── ConformanceWaiverSet default ────────────────────────────────

    #[test]
    fn conformance_waiver_set_default_is_empty() {
        let set = ConformanceWaiverSet::default();
        assert!(set.waivers.is_empty());
    }

    // ── classify_conformance_delta: props field modified ────────────

    #[test]
    fn classify_delta_props_modified_same_fields_different_count() {
        // Same sorted fields, but values differ → SchemaFieldModified
        let expected = "props: alpha, beta";
        let actual = "props: alpha, beta, gamma";
        let deltas = classify_conformance_delta(expected, actual);
        // gamma added → SchemaFieldAdded
        assert!(
            deltas
                .iter()
                .any(|d| d.kind == ConformanceDeltaKind::SchemaFieldAdded)
        );
    }

    // ── join_source_segments / join_output_lines ────────────────────

    #[test]
    fn join_source_segments_basic() {
        let segments = vec!["var a = 1".to_string(), "var b = 2".to_string()];
        let result = join_source_segments(&segments);
        assert_eq!(result, "var a = 1;\nvar b = 2");
    }

    #[test]
    fn join_output_lines_basic() {
        let lines = vec!["line1".to_string(), "line2".to_string()];
        let result = join_output_lines(&lines);
        assert_eq!(result, "line1\nline2");
    }

    // ── IFC flow path types coverage ────────────────────────────────

    #[test]
    fn validate_ifc_all_flow_path_types_valid() {
        for flow_type in IFC_FLOW_PATH_TYPES {
            let mut rec = valid_asset_record();
            rec.category = Some("benign".to_string());
            rec.source_labels = vec!["credential".to_string()];
            rec.sink_clearances = vec!["network_egress".to_string()];
            rec.flow_path_type = Some(flow_type.to_string());
            rec.expected_outcome = Some("allow".to_string());
            rec.expected_evidence_type = Some("none".to_string());
            assert!(
                rec.validate_ifc_fields().is_ok(),
                "flow_path_type '{flow_type}' should be valid"
            );
        }
    }

    #[test]
    fn validate_ifc_all_source_labels_valid() {
        for label in IFC_SOURCE_LABELS {
            let mut rec = valid_asset_record();
            rec.category = Some("benign".to_string());
            rec.source_labels = vec![label.to_string()];
            rec.sink_clearances = vec!["network_egress".to_string()];
            rec.flow_path_type = Some("direct".to_string());
            rec.expected_outcome = Some("allow".to_string());
            rec.expected_evidence_type = Some("none".to_string());
            assert!(
                rec.validate_ifc_fields().is_ok(),
                "source_label '{label}' should be valid"
            );
        }
    }

    #[test]
    fn validate_ifc_all_sink_clearances_valid() {
        for clearance in IFC_SINK_CLEARANCES {
            let mut rec = valid_asset_record();
            rec.category = Some("benign".to_string());
            rec.source_labels = vec!["credential".to_string()];
            rec.sink_clearances = vec![clearance.to_string()];
            rec.flow_path_type = Some("direct".to_string());
            rec.expected_outcome = Some("allow".to_string());
            rec.expected_evidence_type = Some("none".to_string());
            assert!(
                rec.validate_ifc_fields().is_ok(),
                "sink_clearance '{clearance}' should be valid"
            );
        }
    }

    // ── DonorHarnessAdapter no-op ──────────────────────────────────

    #[test]
    fn donor_harness_adapter_no_match_passthrough() {
        let adapter = DonorHarnessAdapter;
        let result = adapter.adapt_source("some plain code");
        assert_eq!(result, "some plain code");
    }

    // ── ConformanceAssetRecord serde with IFC fields ────────────────

    #[test]
    fn asset_record_with_ifc_fields_serde_round_trip() {
        let mut rec = valid_asset_record();
        rec.category = Some("benign".to_string());
        rec.source_labels = vec!["credential".to_string(), "key_material".to_string()];
        rec.sink_clearances = vec!["network_egress".to_string()];
        rec.flow_path_type = Some("direct".to_string());
        rec.expected_outcome = Some("allow".to_string());
        rec.expected_evidence_type = Some("none".to_string());
        let json = serde_json::to_string(&rec).unwrap();
        let back: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    // ── IfcCategoryCounts ──────────────────────────────────────────

    #[test]
    fn ifc_category_counts_default_all_zero() {
        let counts = IfcCategoryCounts::default();
        assert_eq!(counts.total, 0);
        assert_eq!(counts.passed, 0);
        assert_eq!(counts.failed, 0);
        assert_eq!(counts.waived, 0);
        assert_eq!(counts.errored, 0);
    }

    #[test]
    fn ifc_category_counts_serde_round_trip() {
        let counts = IfcCategoryCounts {
            total: 10,
            passed: 7,
            failed: 2,
            waived: 1,
            errored: 0,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let back: IfcCategoryCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(back, counts);
    }

    // ── ConformanceRunner env_fingerprint changes with config ───────

    #[test]
    fn env_fingerprint_changes_with_seed() {
        let a = ConformanceRunner {
            config: ConformanceRunnerConfig {
                seed: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let b = ConformanceRunner {
            config: ConformanceRunnerConfig {
                seed: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(a.env_fingerprint(), b.env_fingerprint());
    }

    // ── parse_ifc_observed_outcome edge cases ──────────────────────

    #[test]
    fn parse_ifc_observed_outcome_evidence_id_only() {
        let result = parse_ifc_observed_outcome("evidence_id:ev-42");
        assert!(result.outcome.is_none());
        assert!(result.evidence_type.is_none());
        assert_eq!(result.evidence_id.as_deref(), Some("ev-42"));
    }

    #[test]
    fn parse_ifc_observed_outcome_empty_evidence_id_ignored() {
        let result = parse_ifc_observed_outcome("evidence_id:");
        assert!(result.evidence_id.is_none());
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn conformance_minimized_repro_artifact_serde_roundtrip() {
        let mut versions = BTreeMap::new();
        versions.insert("franken_engine".to_string(), "0.1.0".to_string());
        let artifact = ConformanceMinimizedReproArtifact {
            schema_version: ConformanceMinimizedReproArtifact::CURRENT_SCHEMA.to_string(),
            artifact_id: "art-001".to_string(),
            failure_id: "fail-001".to_string(),
            boundary_surface: "parser".to_string(),
            failure_class: ConformanceFailureClass::Breaking,
            severity: ConformanceFailureSeverity::Critical,
            version_combination: versions,
            first_seen_commit: "abc123".to_string(),
            regression_commit: Some("def456".to_string()),
            environment: ConformanceReproEnvironment {
                locale: "C".to_string(),
                timezone: "UTC".to_string(),
                gc_schedule: "deterministic".to_string(),
                rust_toolchain: "nightly-2026-02-20".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
            replay: ConformanceReplayContract {
                deterministic_seed: 42,
                replay_command: "cargo test".to_string(),
                verification_command: "cargo test --verify".to_string(),
                verification_digest: "digest-hex".to_string(),
            },
            expected_output: "expected".to_string(),
            actual_output: "actual".to_string(),
            delta_classification: vec![ConformanceDeltaClassification {
                kind: ConformanceDeltaKind::BehavioralSemanticShift,
                field: Some("output".to_string()),
                expected: Some("expected".to_string()),
                actual: Some("actual".to_string()),
                detail: "output differs".to_string(),
            }],
            minimization: ConformanceMinimizationSummary {
                strategy: "ddmin".to_string(),
                original_source_lines: 100,
                minimized_source_lines: 10,
                original_expected_lines: 50,
                minimized_expected_lines: 5,
                original_actual_lines: 50,
                minimized_actual_lines: 5,
                preserved_failure_class: true,
            },
            failing_vector: ConformanceMinimizedFailingVector {
                asset_id: "asset-001".to_string(),
                source_donor: "test262".to_string(),
                semantic_domain: "strict-mode".to_string(),
                normative_reference: "sec-14.6".to_string(),
                fixture: DonorFixture {
                    donor_harness: "test262".to_string(),
                    source: "var x = 1;".to_string(),
                    observed_output: "actual".to_string(),
                },
                expected_output: "expected".to_string(),
            },
            evidence_ledger_id: "ev-001".to_string(),
            linked_run: ConformanceRunLinkage {
                run_id: "run-001".to_string(),
                trace_id: "trace-001".to_string(),
                decision_id: "dec-001".to_string(),
                ci_run_id: Some("ci-001".to_string()),
            },
            issue_tracker: ConformanceIssueLink {
                tracker: "beads".to_string(),
                issue_id: "bd-test".to_string(),
            },
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: ConformanceMinimizedReproArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn conformance_run_result_serde_roundtrip() {
        let result = ConformanceRunResult {
            run_id: "run-001".to_string(),
            asset_manifest_hash: "hash-001".to_string(),
            logs: vec![ConformanceLogEvent {
                trace_id: "t-001".to_string(),
                decision_id: "d-001".to_string(),
                policy_id: "p-001".to_string(),
                component: "parser".to_string(),
                event: "eval".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                asset_id: "a-001".to_string(),
                workload_id: "w-001".to_string(),
                semantic_domain: "strict".to_string(),
                category: Some("ifc".to_string()),
                source_labels: vec!["secret".to_string()],
                sink_clearances: vec!["public".to_string()],
                flow_path_type: Some("direct".to_string()),
                expected_outcome: Some("pass".to_string()),
                actual_outcome: Some("pass".to_string()),
                evidence_type: Some("assertion".to_string()),
                evidence_id: Some("ev-01".to_string()),
                duration_us: 123,
                error_detail: None,
            }],
            summary: ConformanceRunSummary {
                run_id: "run-001".to_string(),
                asset_manifest_hash: "hash-001".to_string(),
                total_assets: 10,
                passed: 9,
                failed: 1,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp-001".to_string(),
            },
            minimized_repros: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ConformanceRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert_eq!(back.logs.len(), 1);
    }

    #[test]
    fn conformance_run_result_empty_logs_serde_roundtrip() {
        let result = ConformanceRunResult {
            run_id: "run-empty".to_string(),
            asset_manifest_hash: "hash-empty".to_string(),
            logs: vec![],
            summary: ConformanceRunSummary {
                run_id: "run-empty".to_string(),
                asset_manifest_hash: "hash-empty".to_string(),
                total_assets: 0,
                passed: 0,
                failed: 0,
                waived: 0,
                errored: 0,
                env_fingerprint: "fp-empty".to_string(),
            },
            minimized_repros: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ConformanceRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
        assert!(back.logs.is_empty());
    }
}
