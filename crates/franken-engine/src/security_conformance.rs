use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SECURITY_LABEL_FILE_NAME: &str = "workload_label.toml";
pub const SECURITY_CORPUS_MANIFEST_FILE_NAME: &str = "corpus_manifest.toml";
pub const SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.security-conformance-corpus-manifest.v1";
pub const SECURITY_CONFORMANCE_SCHEMA_VERSION: &str =
    "franken-engine.security-conformance-evidence.v1";
pub const DEFAULT_CONFIDENCE_LEVEL: f64 = 0.95;
pub const DEFAULT_TPR_MIN: f64 = 0.99;
pub const DEFAULT_FPR_MAX: f64 = 0.01;
pub const DEFAULT_MALICIOUS_LATENCY_P95_MAX_MS: u64 = 250;

pub const SECURITY_ATTACK_TAXONOMIES: &[&str] = &[
    "exfil",
    "escalation",
    "evasion",
    "dos",
    "side_channel",
    "staging",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityCorpus {
    Benign,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAttackTaxonomy {
    Exfil,
    Escalation,
    Evasion,
    Dos,
    SideChannel,
    Staging,
}

impl SecurityAttackTaxonomy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exfil => "exfil",
            Self::Escalation => "escalation",
            Self::Evasion => "evasion",
            Self::Dos => "dos",
            Self::SideChannel => "side_channel",
            Self::Staging => "staging",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityOutcome {
    Allow,
    Contain,
    Quarantine,
    Terminate,
}

impl SecurityOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Contain => "contain",
            Self::Quarantine => "quarantine",
            Self::Terminate => "terminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityWorkloadLabel {
    pub workload_id: String,
    pub corpus: SecurityCorpus,
    #[serde(default)]
    pub attack_taxonomy: Option<SecurityAttackTaxonomy>,
    pub expected_outcome: SecurityOutcome,
    pub expected_detection_latency_bound_ms: u64,
    pub hostcall_sequence_hash: String,
    pub semantic_domain: String,
}

impl SecurityWorkloadLabel {
    pub fn validate(&self) -> Result<(), SecurityConformanceError> {
        if self.workload_id.trim().is_empty() {
            return Err(SecurityConformanceError::InvalidLabelField {
                field: "workload_id",
                detail: "must not be empty".to_string(),
            });
        }
        if has_surrounding_whitespace(self.workload_id.as_str()) {
            return Err(SecurityConformanceError::InvalidLabelField {
                field: "workload_id",
                detail: "must not have leading or trailing whitespace".to_string(),
            });
        }
        if self.semantic_domain.trim().is_empty() {
            return Err(SecurityConformanceError::InvalidLabelField {
                field: "semantic_domain",
                detail: "must not be empty".to_string(),
            });
        }
        if self.expected_detection_latency_bound_ms == 0 {
            return Err(SecurityConformanceError::InvalidLabelField {
                field: "expected_detection_latency_bound_ms",
                detail: "must be greater than zero".to_string(),
            });
        }
        if !is_valid_sha256_hex(self.hostcall_sequence_hash.as_str()) {
            return Err(SecurityConformanceError::InvalidLabelField {
                field: "hostcall_sequence_hash",
                detail: "must be 64 lowercase hex characters".to_string(),
            });
        }

        match self.corpus {
            SecurityCorpus::Benign => {
                if self.attack_taxonomy.is_some() {
                    return Err(SecurityConformanceError::InvalidLabelField {
                        field: "attack_taxonomy",
                        detail: "benign workloads must not declare attack taxonomy".to_string(),
                    });
                }
                if self.expected_outcome != SecurityOutcome::Allow {
                    return Err(SecurityConformanceError::InvalidLabelField {
                        field: "expected_outcome",
                        detail: "benign workloads must have expected_outcome=allow".to_string(),
                    });
                }
            }
            SecurityCorpus::Malicious => {
                if self.attack_taxonomy.is_none() {
                    return Err(SecurityConformanceError::InvalidLabelField {
                        field: "attack_taxonomy",
                        detail: "malicious workloads must declare attack taxonomy".to_string(),
                    });
                }
                if self.expected_outcome == SecurityOutcome::Allow {
                    return Err(SecurityConformanceError::InvalidLabelField {
                        field: "expected_outcome",
                        detail: "malicious workloads cannot have expected_outcome=allow"
                            .to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityWorkloadLabelRecord {
    pub label: SecurityWorkloadLabel,
    pub label_path: PathBuf,
    pub label_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SecurityCorpusManifest {
    pub schema_version: String,
    pub corpus_version: String,
    pub generated_at_utc: String,
    pub entries: Vec<SecurityCorpusManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SecurityCorpusManifestEntry {
    pub workload_id: String,
    pub corpus: SecurityCorpus,
    pub label_path: PathBuf,
    pub label_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityWorkloadObservation {
    pub workload_id: String,
    pub actual_outcome: SecurityOutcome,
    pub detection_latency_us: u64,
    pub sentinel_posterior: f64,
    pub policy_action: String,
    pub containment_action: String,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl SecurityWorkloadObservation {
    pub fn validate(&self) -> Result<(), SecurityConformanceError> {
        if self.workload_id.trim().is_empty() {
            return Err(SecurityConformanceError::InvalidObservationField {
                field: "workload_id",
                detail: "must not be empty".to_string(),
            });
        }
        if has_surrounding_whitespace(self.workload_id.as_str()) {
            return Err(SecurityConformanceError::InvalidObservationField {
                field: "workload_id",
                detail: "must not have leading or trailing whitespace".to_string(),
            });
        }
        if self.policy_action.trim().is_empty() {
            return Err(SecurityConformanceError::InvalidObservationField {
                field: "policy_action",
                detail: "must not be empty".to_string(),
            });
        }
        if self.containment_action.trim().is_empty() {
            return Err(SecurityConformanceError::InvalidObservationField {
                field: "containment_action",
                detail: "must not be empty".to_string(),
            });
        }
        if !(0.0..=1.0).contains(&self.sentinel_posterior) {
            return Err(SecurityConformanceError::InvalidObservationField {
                field: "sentinel_posterior",
                detail: "must be in [0.0, 1.0]".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConformanceThresholds {
    pub tpr_min: String,
    pub fpr_max: String,
    pub malicious_latency_p95_max_ms: u64,
    pub confidence_level_millionths: u32,
}

impl Default for SecurityConformanceThresholds {
    fn default() -> Self {
        Self {
            tpr_min: millionths_to_string(990_000),
            fpr_max: millionths_to_string(10_000),
            malicious_latency_p95_max_ms: DEFAULT_MALICIOUS_LATENCY_P95_MAX_MS,
            confidence_level_millionths: 950_000,
        }
    }
}

impl SecurityConformanceThresholds {
    fn confidence_level(&self) -> Result<f64, SecurityConformanceError> {
        millionths_to_f64(self.confidence_level_millionths)
    }

    fn tpr_min_f64(&self) -> Result<f64, SecurityConformanceError> {
        parse_ratio_string(self.tpr_min.as_str(), "tpr_min")
    }

    fn fpr_max_f64(&self) -> Result<f64, SecurityConformanceError> {
        parse_ratio_string(self.fpr_max.as_str(), "fpr_max")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinomialConfidenceInterval {
    pub lower_millionths: u32,
    pub upper_millionths: u32,
}

impl BinomialConfidenceInterval {
    pub fn lower_f64(&self) -> Result<f64, SecurityConformanceError> {
        millionths_to_f64(self.lower_millionths)
    }

    pub fn upper_f64(&self) -> Result<f64, SecurityConformanceError> {
        millionths_to_f64(self.upper_millionths)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityConformanceSummary {
    pub corpus_manifest_hash: String,
    pub benign_total: u64,
    pub malicious_total: u64,
    pub true_positive_count: u64,
    pub false_positive_count: u64,
    pub false_negative_count: u64,
    pub tpr_millionths: u32,
    pub fpr_millionths: u32,
    pub tpr_ci: BinomialConfidenceInterval,
    pub fpr_ci: BinomialConfidenceInterval,
    pub malicious_latency_p95_us: u64,
    pub malicious_latency_p95_max_us: u64,
    pub gate_pass: bool,
    pub gate_failure_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SecurityConformanceEvaluation {
    pub summary: SecurityConformanceSummary,
    pub observations_by_workload: BTreeMap<String, SecurityWorkloadObservation>,
}

#[derive(Debug)]
pub enum SecurityConformanceError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    InvalidToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    ManifestPathMissing {
        path: PathBuf,
    },
    ManifestInvalidToml {
        path: PathBuf,
        source: toml::de::Error,
    },
    ManifestSchemaMismatch {
        expected: &'static str,
        found: String,
    },
    ManifestInvalidEntry {
        detail: String,
    },
    ManifestDuplicateWorkloadId {
        workload_id: String,
    },
    ManifestMissingWorkload {
        workload_id: String,
    },
    ManifestUnexpectedWorkload {
        workload_id: String,
    },
    ManifestLabelPathMismatch {
        workload_id: String,
        expected_path: PathBuf,
        actual_path: PathBuf,
    },
    ManifestLabelHashMismatch {
        workload_id: String,
        expected_hash: String,
        actual_hash: String,
    },
    ManifestCorpusMismatch {
        workload_id: String,
        expected: SecurityCorpus,
        actual: SecurityCorpus,
    },
    RootPathMissing {
        root: PathBuf,
    },
    NoLabelsFound {
        root: PathBuf,
    },
    DuplicateWorkloadId {
        workload_id: String,
        first_path: PathBuf,
        second_path: PathBuf,
    },
    InvalidLabelField {
        field: &'static str,
        detail: String,
    },
    InvalidObservationField {
        field: &'static str,
        detail: String,
    },
    MissingObservation {
        workload_id: String,
    },
    DuplicateObservation {
        workload_id: String,
    },
    UnexpectedObservation {
        workload_id: String,
    },
    InvalidRatioConfig {
        field: &'static str,
        value: String,
    },
    EmptyDataset,
    BinomialIntervalUnavailable {
        successes: u64,
        total: u64,
    },
}

impl fmt::Display for SecurityConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at {}: {source}", path.display())
            }
            Self::InvalidToml { path, source } => {
                write!(f, "invalid TOML at {}: {source}", path.display())
            }
            Self::ManifestPathMissing { path } => {
                write!(f, "security corpus manifest not found: {}", path.display())
            }
            Self::ManifestInvalidToml { path, source } => {
                write!(
                    f,
                    "invalid corpus manifest TOML at {}: {source}",
                    path.display()
                )
            }
            Self::ManifestSchemaMismatch { expected, found } => write!(
                f,
                "unsupported corpus manifest schema_version `{found}` (expected `{expected}`)"
            ),
            Self::ManifestInvalidEntry { detail } => {
                write!(f, "invalid corpus manifest entry: {detail}")
            }
            Self::ManifestDuplicateWorkloadId { workload_id } => {
                write!(
                    f,
                    "duplicate workload_id `{workload_id}` in corpus manifest"
                )
            }
            Self::ManifestMissingWorkload { workload_id } => write!(
                f,
                "corpus manifest missing workload_id `{workload_id}` present in labels"
            ),
            Self::ManifestUnexpectedWorkload { workload_id } => write!(
                f,
                "corpus manifest references unknown workload_id `{workload_id}`"
            ),
            Self::ManifestLabelPathMismatch {
                workload_id,
                expected_path,
                actual_path,
            } => write!(
                f,
                "corpus manifest path mismatch for `{workload_id}`: expected {}, actual {}",
                expected_path.display(),
                actual_path.display()
            ),
            Self::ManifestLabelHashMismatch {
                workload_id,
                expected_hash,
                actual_hash,
            } => write!(
                f,
                "corpus manifest hash mismatch for `{workload_id}`: expected `{expected_hash}`, actual `{actual_hash}`"
            ),
            Self::ManifestCorpusMismatch {
                workload_id,
                expected,
                actual,
            } => write!(
                f,
                "corpus manifest corpus mismatch for `{workload_id}`: expected {:?}, actual {:?}",
                expected, actual
            ),
            Self::RootPathMissing { root } => {
                write!(f, "labels root does not exist: {}", root.display())
            }
            Self::NoLabelsFound { root } => {
                write!(
                    f,
                    "no `{}` files found under {}",
                    SECURITY_LABEL_FILE_NAME,
                    root.display()
                )
            }
            Self::DuplicateWorkloadId {
                workload_id,
                first_path,
                second_path,
            } => write!(
                f,
                "duplicate workload_id `{workload_id}` in {} and {}",
                first_path.display(),
                second_path.display()
            ),
            Self::InvalidLabelField { field, detail } => {
                write!(f, "invalid label field `{field}`: {detail}")
            }
            Self::InvalidObservationField { field, detail } => {
                write!(f, "invalid observation field `{field}`: {detail}")
            }
            Self::MissingObservation { workload_id } => {
                write!(f, "missing observation for workload `{workload_id}`")
            }
            Self::DuplicateObservation { workload_id } => {
                write!(f, "duplicate observation for workload `{workload_id}`")
            }
            Self::UnexpectedObservation { workload_id } => {
                write!(
                    f,
                    "unexpected observation for unknown workload `{workload_id}`"
                )
            }
            Self::InvalidRatioConfig { field, value } => {
                write!(f, "invalid ratio config `{field}`: `{value}`")
            }
            Self::EmptyDataset => write!(f, "conformance dataset is empty"),
            Self::BinomialIntervalUnavailable { successes, total } => write!(
                f,
                "cannot compute binomial confidence interval for successes={successes}, total={total}"
            ),
        }
    }
}

impl std::error::Error for SecurityConformanceError {}

pub fn load_security_labels(
    labels_root: &Path,
) -> Result<Vec<SecurityWorkloadLabelRecord>, SecurityConformanceError> {
    if !labels_root.exists() {
        return Err(SecurityConformanceError::RootPathMissing {
            root: labels_root.to_path_buf(),
        });
    }

    let mut stack = vec![labels_root.to_path_buf()];
    let mut records = Vec::<SecurityWorkloadLabelRecord>::new();

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|source| SecurityConformanceError::Io {
            path: dir.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| SecurityConformanceError::Io {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata = entry
                .metadata()
                .map_err(|source| SecurityConformanceError::Io {
                    path: path.clone(),
                    source,
                })?;
            if metadata.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some(SECURITY_LABEL_FILE_NAME) {
                continue;
            }

            let bytes = fs::read(&path).map_err(|source| SecurityConformanceError::Io {
                path: path.clone(),
                source,
            })?;
            let text = std::str::from_utf8(&bytes).map_err(|_| SecurityConformanceError::Io {
                path: path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8"),
            })?;
            let parsed: SecurityWorkloadLabel =
                toml::from_str(text).map_err(|source| SecurityConformanceError::InvalidToml {
                    path: path.clone(),
                    source,
                })?;
            parsed.validate()?;

            records.push(SecurityWorkloadLabelRecord {
                label: parsed,
                label_path: path,
                label_hash: sha256_hex(&bytes),
            });
        }
    }

    if records.is_empty() {
        return Err(SecurityConformanceError::NoLabelsFound {
            root: labels_root.to_path_buf(),
        });
    }

    records.sort_by(|a, b| {
        a.label
            .workload_id
            .cmp(&b.label.workload_id)
            .then_with(|| a.label_path.cmp(&b.label_path))
    });

    let mut first_seen = BTreeMap::<String, PathBuf>::new();
    for record in &records {
        if let Some(first_path) =
            first_seen.insert(record.label.workload_id.clone(), record.label_path.clone())
        {
            return Err(SecurityConformanceError::DuplicateWorkloadId {
                workload_id: record.label.workload_id.clone(),
                first_path,
                second_path: record.label_path.clone(),
            });
        }
    }

    Ok(records)
}

fn normalize_relative_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::ParentDir => normalized.push(".."),
            std::path::Component::RootDir => normalized.push(std::path::MAIN_SEPARATOR.to_string()),
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }
    normalized
}

pub fn validate_corpus_manifest(
    labels_root: &Path,
    records: &[SecurityWorkloadLabelRecord],
) -> Result<SecurityCorpusManifest, SecurityConformanceError> {
    let manifest_path = labels_root.join(SECURITY_CORPUS_MANIFEST_FILE_NAME);
    if !manifest_path.exists() {
        return Err(SecurityConformanceError::ManifestPathMissing {
            path: manifest_path,
        });
    }

    let bytes = fs::read(&manifest_path).map_err(|source| SecurityConformanceError::Io {
        path: manifest_path.clone(),
        source,
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SecurityConformanceError::Io {
        path: manifest_path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid UTF-8"),
    })?;
    let manifest: SecurityCorpusManifest =
        toml::from_str(text).map_err(|source| SecurityConformanceError::ManifestInvalidToml {
            path: manifest_path.clone(),
            source,
        })?;

    if manifest.schema_version != SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION {
        return Err(SecurityConformanceError::ManifestSchemaMismatch {
            expected: SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
            found: manifest.schema_version,
        });
    }

    let mut manifest_by_workload = BTreeMap::<String, &SecurityCorpusManifestEntry>::new();
    for entry in &manifest.entries {
        if entry.workload_id.trim().is_empty() {
            return Err(SecurityConformanceError::ManifestInvalidEntry {
                detail: "workload_id must not be empty".to_string(),
            });
        }
        if has_surrounding_whitespace(entry.workload_id.as_str()) {
            return Err(SecurityConformanceError::ManifestInvalidEntry {
                detail: format!(
                    "workload_id {:?} must not have leading or trailing whitespace",
                    entry.workload_id
                ),
            });
        }
        if !is_valid_sha256_hex(entry.label_sha256.as_str()) {
            return Err(SecurityConformanceError::ManifestInvalidEntry {
                detail: format!(
                    "workload_id `{}` has invalid label_sha256",
                    entry.workload_id
                ),
            });
        }
        if manifest_by_workload
            .insert(entry.workload_id.clone(), entry)
            .is_some()
        {
            return Err(SecurityConformanceError::ManifestDuplicateWorkloadId {
                workload_id: entry.workload_id.clone(),
            });
        }
    }

    let mut labels_by_workload = BTreeMap::<String, &SecurityWorkloadLabelRecord>::new();
    for record in records {
        labels_by_workload.insert(record.label.workload_id.clone(), record);
        let entry = manifest_by_workload
            .get(record.label.workload_id.as_str())
            .ok_or(SecurityConformanceError::ManifestMissingWorkload {
                workload_id: record.label.workload_id.clone(),
            })?;

        if entry.corpus != record.label.corpus {
            return Err(SecurityConformanceError::ManifestCorpusMismatch {
                workload_id: record.label.workload_id.clone(),
                expected: entry.corpus,
                actual: record.label.corpus,
            });
        }

        if entry.label_sha256 != record.label_hash {
            return Err(SecurityConformanceError::ManifestLabelHashMismatch {
                workload_id: record.label.workload_id.clone(),
                expected_hash: entry.label_sha256.clone(),
                actual_hash: record.label_hash.clone(),
            });
        }

        let actual_relative = record.label_path.strip_prefix(labels_root).map_err(|_| {
            SecurityConformanceError::ManifestLabelPathMismatch {
                workload_id: record.label.workload_id.clone(),
                expected_path: normalize_relative_path(entry.label_path.as_path()),
                actual_path: record.label_path.clone(),
            }
        })?;
        let actual_normalized = normalize_relative_path(actual_relative);
        let expected_normalized = normalize_relative_path(entry.label_path.as_path());
        if actual_normalized != expected_normalized {
            return Err(SecurityConformanceError::ManifestLabelPathMismatch {
                workload_id: record.label.workload_id.clone(),
                expected_path: expected_normalized,
                actual_path: actual_normalized,
            });
        }
    }

    for workload_id in manifest_by_workload.keys() {
        if !labels_by_workload.contains_key(workload_id.as_str()) {
            return Err(SecurityConformanceError::ManifestUnexpectedWorkload {
                workload_id: workload_id.clone(),
            });
        }
    }

    Ok(manifest)
}

pub fn corpus_manifest_hash(records: &[SecurityWorkloadLabelRecord]) -> String {
    // Sort by workload_id for insertion-order independence.
    let mut sorted: Vec<_> = records.iter().collect();
    sorted.sort_by(|a, b| a.label.workload_id.cmp(&b.label.workload_id));
    let mut hasher = Sha256::new();
    for record in &sorted {
        hasher.update(record.label.workload_id.as_bytes());
        hasher.update(b"\n");
        hasher.update(record.label_hash.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

pub fn default_observation_from_label(
    label: &SecurityWorkloadLabel,
) -> SecurityWorkloadObservation {
    let (policy_action, containment_action) = match label.expected_outcome {
        SecurityOutcome::Allow => ("allow".to_string(), "none".to_string()),
        SecurityOutcome::Contain => ("contain".to_string(), "sandbox".to_string()),
        SecurityOutcome::Quarantine => ("quarantine".to_string(), "quarantine".to_string()),
        SecurityOutcome::Terminate => ("terminate".to_string(), "terminate".to_string()),
    };
    let posterior = match label.corpus {
        SecurityCorpus::Benign => 0.05,
        SecurityCorpus::Malicious => 0.995,
    };

    SecurityWorkloadObservation {
        workload_id: label.workload_id.clone(),
        actual_outcome: label.expected_outcome,
        detection_latency_us: label
            .expected_detection_latency_bound_ms
            .saturating_mul(1000)
            .saturating_sub(1),
        sentinel_posterior: posterior,
        policy_action,
        containment_action,
        error_code: None,
    }
}

pub fn evaluate_security_conformance(
    records: &[SecurityWorkloadLabelRecord],
    observations: &[SecurityWorkloadObservation],
    thresholds: &SecurityConformanceThresholds,
) -> Result<SecurityConformanceEvaluation, SecurityConformanceError> {
    if records.is_empty() {
        return Err(SecurityConformanceError::EmptyDataset);
    }

    let mut record_paths_by_workload = BTreeMap::<String, PathBuf>::new();
    for record in records {
        record.label.validate()?;
        if let Some(first_path) = record_paths_by_workload
            .insert(record.label.workload_id.clone(), record.label_path.clone())
        {
            return Err(SecurityConformanceError::DuplicateWorkloadId {
                workload_id: record.label.workload_id.clone(),
                first_path,
                second_path: record.label_path.clone(),
            });
        }
    }

    let mut observations_by_workload = BTreeMap::<String, SecurityWorkloadObservation>::new();
    for observation in observations {
        observation.validate()?;
        if observations_by_workload
            .insert(observation.workload_id.clone(), observation.clone())
            .is_some()
        {
            return Err(SecurityConformanceError::DuplicateObservation {
                workload_id: observation.workload_id.clone(),
            });
        }
    }
    for workload_id in observations_by_workload.keys() {
        if !record_paths_by_workload.contains_key(workload_id.as_str()) {
            return Err(SecurityConformanceError::UnexpectedObservation {
                workload_id: workload_id.clone(),
            });
        }
    }

    let mut benign_total = 0_u64;
    let mut malicious_total = 0_u64;
    let mut true_positive_count = 0_u64;
    let mut false_positive_count = 0_u64;
    let mut false_negative_count = 0_u64;
    let mut malicious_latencies = Vec::<u64>::new();

    for record in records {
        let observation = observations_by_workload
            .get(record.label.workload_id.as_str())
            .ok_or(SecurityConformanceError::MissingObservation {
                workload_id: record.label.workload_id.clone(),
            })?;

        match record.label.corpus {
            SecurityCorpus::Benign => {
                benign_total += 1;
                if observation.actual_outcome != SecurityOutcome::Allow {
                    false_positive_count += 1;
                }
            }
            SecurityCorpus::Malicious => {
                malicious_total += 1;
                malicious_latencies.push(observation.detection_latency_us);
                if observation.actual_outcome == SecurityOutcome::Allow {
                    false_negative_count += 1;
                } else {
                    true_positive_count += 1;
                }
            }
        }
    }

    let tpr_millionths = ratio_to_millionths(true_positive_count, malicious_total);
    let fpr_millionths = ratio_to_millionths(false_positive_count, benign_total);
    let confidence_level = thresholds.confidence_level()?;

    let tpr_ci = clopper_pearson_interval(true_positive_count, malicious_total, confidence_level)?;
    let fpr_ci = clopper_pearson_interval(false_positive_count, benign_total, confidence_level)?;

    let malicious_latency_p95_us =
        percentile_95_us(&mut malicious_latencies).ok_or(SecurityConformanceError::EmptyDataset)?;
    let malicious_latency_p95_max_us = thresholds.malicious_latency_p95_max_ms.saturating_mul(1000);

    let mut gate_failure_reasons = Vec::new();

    let tpr_lower = tpr_ci.lower_f64()?;
    let tpr_min = thresholds.tpr_min_f64()?;
    if tpr_lower < tpr_min {
        gate_failure_reasons.push(format!(
            "TPR lower CI bound {:.6} below threshold {:.6}",
            tpr_lower, tpr_min
        ));
    }

    let fpr_upper = fpr_ci.upper_f64()?;
    let fpr_max = thresholds.fpr_max_f64()?;
    if fpr_upper > fpr_max {
        gate_failure_reasons.push(format!(
            "FPR upper CI bound {:.6} above threshold {:.6}",
            fpr_upper, fpr_max
        ));
    }

    if malicious_latency_p95_us > malicious_latency_p95_max_us {
        gate_failure_reasons.push(format!(
            "malicious latency p95 {}us above {}us",
            malicious_latency_p95_us, malicious_latency_p95_max_us
        ));
    }

    let summary = SecurityConformanceSummary {
        corpus_manifest_hash: corpus_manifest_hash(records),
        benign_total,
        malicious_total,
        true_positive_count,
        false_positive_count,
        false_negative_count,
        tpr_millionths,
        fpr_millionths,
        tpr_ci,
        fpr_ci,
        malicious_latency_p95_us,
        malicious_latency_p95_max_us,
        gate_pass: gate_failure_reasons.is_empty(),
        gate_failure_reasons,
    };

    Ok(SecurityConformanceEvaluation {
        summary,
        observations_by_workload,
    })
}

pub fn clopper_pearson_interval(
    successes: u64,
    total: u64,
    confidence_level: f64,
) -> Result<BinomialConfidenceInterval, SecurityConformanceError> {
    if total == 0 || successes > total || !(0.0..1.0).contains(&confidence_level) {
        return Err(SecurityConformanceError::BinomialIntervalUnavailable { successes, total });
    }

    let alpha = 1.0 - confidence_level;
    let half_alpha = alpha / 2.0;

    let lower = if successes == 0 {
        0.0
    } else {
        bisection_monotonic(0.0, 1.0, half_alpha, true, |p| {
            binomial_tail_ge(successes, total, p)
        })
    };

    let upper = if successes == total {
        1.0
    } else {
        bisection_monotonic(0.0, 1.0, half_alpha, false, |p| {
            binomial_cdf_le(successes, total, p)
        })
    };

    Ok(BinomialConfidenceInterval {
        lower_millionths: f64_to_millionths(lower),
        upper_millionths: f64_to_millionths(upper),
    })
}

fn bisection_monotonic<F>(
    mut low: f64,
    mut high: f64,
    target: f64,
    increasing: bool,
    mut eval: F,
) -> f64
where
    F: FnMut(f64) -> f64,
{
    for _ in 0..90 {
        let mid = (low + high) / 2.0;
        let value = eval(mid);
        if (increasing && value < target) || (!increasing && value > target) {
            low = mid;
        } else {
            high = mid;
        }
    }
    (low + high) / 2.0
}

fn binomial_tail_ge(successes: u64, total: u64, p: f64) -> f64 {
    if successes == 0 {
        return 1.0;
    }
    1.0 - binomial_cdf_le(successes - 1, total, p)
}

fn binomial_cdf_le(max_successes: u64, total: u64, p: f64) -> f64 {
    if p <= 0.0 {
        return 1.0;
    }
    if p >= 1.0 {
        return if max_successes >= total { 1.0 } else { 0.0 };
    }

    let mut sum = 0.0_f64;
    for k in 0..=max_successes.min(total) {
        sum += binomial_pmf(k, total, p);
    }
    sum.clamp(0.0, 1.0)
}

fn binomial_pmf(successes: u64, total: u64, p: f64) -> f64 {
    if successes > total {
        return 0.0;
    }
    if p <= 0.0 {
        return if successes == 0 { 1.0 } else { 0.0 };
    }
    if p >= 1.0 {
        return if successes == total { 1.0 } else { 0.0 };
    }

    let failures = total - successes;
    let log_prob = log_choose(total, successes)
        + (successes as f64) * p.ln()
        + (failures as f64) * (1.0 - p).ln();
    log_prob.exp()
}

fn log_choose(n: u64, k: u64) -> f64 {
    if k == 0 || k == n {
        return 0.0;
    }
    let k = k.min(n - k);
    let mut acc = 0.0_f64;
    for i in 1..=k {
        acc += ((n - k + i) as f64).ln() - (i as f64).ln();
    }
    acc
}

fn percentile_95_us(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    let rank = (95 * n).div_ceil(100);
    let idx = rank.saturating_sub(1).min(n - 1);
    Some(values[idx])
}

fn ratio_to_millionths(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    ((numerator.saturating_mul(1_000_000)) / denominator) as u32
}

fn f64_to_millionths(value: f64) -> u32 {
    let scaled = (value.clamp(0.0, 1.0) * 1_000_000.0).round();
    scaled as u32
}

fn millionths_to_f64(value: u32) -> Result<f64, SecurityConformanceError> {
    if value > 1_000_000 {
        return Err(SecurityConformanceError::InvalidRatioConfig {
            field: "ratio_millionths",
            value: value.to_string(),
        });
    }
    Ok((value as f64) / 1_000_000.0)
}

fn millionths_to_string(value: u32) -> String {
    format!("{:.6}", (value as f64) / 1_000_000.0)
}

fn parse_ratio_string(value: &str, field: &'static str) -> Result<f64, SecurityConformanceError> {
    let parsed =
        value
            .parse::<f64>()
            .map_err(|_| SecurityConformanceError::InvalidRatioConfig {
                field,
                value: value.to_string(),
            })?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err(SecurityConformanceError::InvalidRatioConfig {
            field,
            value: value.to_string(),
        });
    }
    Ok(parsed)
}

fn has_surrounding_whitespace(value: &str) -> bool {
    value.trim() != value
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_temp_dir(suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("security-conformance-{suffix}-{nanos}"));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn write_label(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, body).expect("write label");
    }

    #[test]
    fn clopper_pearson_matches_99_of_100_reference() {
        let ci = clopper_pearson_interval(99, 100, DEFAULT_CONFIDENCE_LEVEL).unwrap();
        let lower = ci.lower_f64().unwrap();
        let upper = ci.upper_f64().unwrap();
        assert!((lower - 0.94554).abs() < 0.002);
        assert!((upper - 0.999746).abs() < 0.002);
    }

    #[test]
    fn benign_label_rejects_attack_taxonomy() {
        let label = SecurityWorkloadLabel {
            workload_id: "benign-1".to_string(),
            corpus: SecurityCorpus::Benign,
            attack_taxonomy: Some(SecurityAttackTaxonomy::Exfil),
            expected_outcome: SecurityOutcome::Allow,
            expected_detection_latency_bound_ms: 10,
            hostcall_sequence_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            semantic_domain: "security/benign".to_string(),
        };
        assert!(label.validate().is_err());
    }

    #[test]
    fn malicious_label_requires_taxonomy() {
        let label = SecurityWorkloadLabel {
            workload_id: "malicious-1".to_string(),
            corpus: SecurityCorpus::Malicious,
            attack_taxonomy: None,
            expected_outcome: SecurityOutcome::Contain,
            expected_detection_latency_bound_ms: 15,
            hostcall_sequence_hash:
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            semantic_domain: "security/malicious".to_string(),
        };
        assert!(label.validate().is_err());
    }

    #[test]
    fn load_labels_detects_duplicate_workload_id() {
        let root = test_temp_dir("duplicate");
        let first = root.join("benign/a/workload_label.toml");
        let second = root.join("malicious/b/workload_label.toml");
        let body = r#"
workload_id = "dup"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "security/benign"
"#;
        write_label(&first, body);
        write_label(&second, body);

        let err = load_security_labels(&root).unwrap_err();
        match err {
            SecurityConformanceError::DuplicateWorkloadId { workload_id, .. } => {
                assert_eq!(workload_id, "dup");
            }
            _ => panic!("expected duplicate workload error"),
        }
    }

    #[test]
    fn validate_manifest_accepts_matching_entries() {
        let root = test_temp_dir("manifest-ok");
        let label_path = root.join("benign/a/workload_label.toml");
        let label = r#"
workload_id = "benign-ok"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "security/benign"
"#;
        write_label(&label_path, label);

        let records = load_security_labels(&root).unwrap();
        let record = &records[0];
        let relative = record
            .label_path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");

        let manifest = format!(
            r#"schema_version = "{schema}"
corpus_version = "0.1.0-test"
generated_at_utc = "2026-02-26T00:00:00Z"

[[entries]]
workload_id = "{workload_id}"
corpus = "benign"
label_path = "{relative}"
label_sha256 = "{hash}"
"#,
            schema = SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
            workload_id = record.label.workload_id,
            hash = record.label_hash
        );
        write_label(&root.join(SECURITY_CORPUS_MANIFEST_FILE_NAME), &manifest);

        let parsed = validate_corpus_manifest(&root, &records).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].workload_id, "benign-ok");
    }

    #[test]
    fn validate_manifest_detects_label_hash_tamper() {
        let root = test_temp_dir("manifest-tamper");
        let label_path = root.join("malicious/a/workload_label.toml");
        let label = r#"
workload_id = "malicious-tamper"
corpus = "malicious"
attack_taxonomy = "exfil"
expected_outcome = "contain"
expected_detection_latency_bound_ms = 40
hostcall_sequence_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
semantic_domain = "security/malicious"
"#;
        write_label(&label_path, label);

        let records = load_security_labels(&root).unwrap();
        let record = &records[0];
        let relative = record
            .label_path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let manifest = format!(
            r#"schema_version = "{schema}"
corpus_version = "0.1.0-test"
generated_at_utc = "2026-02-26T00:00:00Z"

[[entries]]
workload_id = "{workload_id}"
corpus = "malicious"
label_path = "{relative}"
label_sha256 = "{bad_hash}"
"#,
            schema = SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
            workload_id = record.label.workload_id,
            bad_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        write_label(&root.join(SECURITY_CORPUS_MANIFEST_FILE_NAME), &manifest);

        let err = validate_corpus_manifest(&root, &records).unwrap_err();
        match err {
            SecurityConformanceError::ManifestLabelHashMismatch { workload_id, .. } => {
                assert_eq!(workload_id, "malicious-tamper");
            }
            _ => panic!("expected manifest hash mismatch"),
        }
    }

    #[test]
    fn validate_manifest_rejects_padded_workload_id() {
        let root = test_temp_dir("manifest-padded-workload-id");
        let label_path = root.join("benign/a/workload_label.toml");
        let label = r#"
workload_id = "benign-ok"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
semantic_domain = "security/benign"
"#;
        write_label(&label_path, label);

        let records = load_security_labels(&root).unwrap();
        let record = &records[0];
        let relative = record
            .label_path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let manifest = format!(
            r#"schema_version = "{schema}"
corpus_version = "0.1.0-test"
generated_at_utc = "2026-02-26T00:00:00Z"

[[entries]]
workload_id = " benign-ok "
corpus = "benign"
label_path = "{relative}"
label_sha256 = "{hash}"
"#,
            schema = SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
            hash = record.label_hash
        );
        write_label(&root.join(SECURITY_CORPUS_MANIFEST_FILE_NAME), &manifest);

        let err = validate_corpus_manifest(&root, &records).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("leading or trailing whitespace"));
    }

    #[test]
    fn evaluate_gate_detects_fp_fn_and_latency_failures() {
        let benign_label = SecurityWorkloadLabelRecord {
            label: SecurityWorkloadLabel {
                workload_id: "benign-a".to_string(),
                corpus: SecurityCorpus::Benign,
                attack_taxonomy: None,
                expected_outcome: SecurityOutcome::Allow,
                expected_detection_latency_bound_ms: 25,
                hostcall_sequence_hash:
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                semantic_domain: "security/benign/a".to_string(),
            },
            label_path: PathBuf::from("benign-a"),
            label_hash: "hash-a".to_string(),
        };
        let malicious_label = SecurityWorkloadLabelRecord {
            label: SecurityWorkloadLabel {
                workload_id: "malicious-a".to_string(),
                corpus: SecurityCorpus::Malicious,
                attack_taxonomy: Some(SecurityAttackTaxonomy::Exfil),
                expected_outcome: SecurityOutcome::Contain,
                expected_detection_latency_bound_ms: 100,
                hostcall_sequence_hash:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                semantic_domain: "security/malicious/a".to_string(),
            },
            label_path: PathBuf::from("malicious-a"),
            label_hash: "hash-b".to_string(),
        };

        let records = vec![benign_label, malicious_label];
        let observations = vec![
            SecurityWorkloadObservation {
                workload_id: "benign-a".to_string(),
                actual_outcome: SecurityOutcome::Contain,
                detection_latency_us: 2_000,
                sentinel_posterior: 0.2,
                policy_action: "contain".to_string(),
                containment_action: "sandbox".to_string(),
                error_code: Some("FE-FP".to_string()),
            },
            SecurityWorkloadObservation {
                workload_id: "malicious-a".to_string(),
                actual_outcome: SecurityOutcome::Allow,
                detection_latency_us: 600_000,
                sentinel_posterior: 0.1,
                policy_action: "allow".to_string(),
                containment_action: "none".to_string(),
                error_code: Some("FE-FN".to_string()),
            },
        ];

        let result = evaluate_security_conformance(
            &records,
            &observations,
            &SecurityConformanceThresholds::default(),
        )
        .unwrap();
        assert!(!result.summary.gate_pass);
        assert_eq!(result.summary.false_positive_count, 1);
        assert_eq!(result.summary.false_negative_count, 1);
        assert!(
            result
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("TPR lower CI"))
        );
        assert!(
            result
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("FPR upper CI"))
        );
        assert!(
            result
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("latency"))
        );
    }

    // ---- constants ----

    #[test]
    fn constants_are_expected_values() {
        assert_eq!(SECURITY_LABEL_FILE_NAME, "workload_label.toml");
        assert_eq!(SECURITY_CORPUS_MANIFEST_FILE_NAME, "corpus_manifest.toml");
        assert_eq!(
            SECURITY_CORPUS_MANIFEST_SCHEMA_VERSION,
            "franken-engine.security-conformance-corpus-manifest.v1"
        );
        assert_eq!(
            SECURITY_CONFORMANCE_SCHEMA_VERSION,
            "franken-engine.security-conformance-evidence.v1"
        );
        assert!((DEFAULT_CONFIDENCE_LEVEL - 0.95).abs() < f64::EPSILON);
        assert!((DEFAULT_TPR_MIN - 0.99).abs() < f64::EPSILON);
        assert!((DEFAULT_FPR_MAX - 0.01).abs() < f64::EPSILON);
        assert_eq!(DEFAULT_MALICIOUS_LATENCY_P95_MAX_MS, 250);
        assert_eq!(SECURITY_ATTACK_TAXONOMIES.len(), 6);
    }

    // ---- SecurityCorpus serde ----

    #[test]
    fn security_corpus_serde_roundtrip_benign() {
        let json = serde_json::to_string(&SecurityCorpus::Benign).unwrap();
        assert_eq!(json, "\"benign\"");
        let back: SecurityCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SecurityCorpus::Benign);
    }

    #[test]
    fn security_corpus_serde_roundtrip_malicious() {
        let json = serde_json::to_string(&SecurityCorpus::Malicious).unwrap();
        assert_eq!(json, "\"malicious\"");
        let back: SecurityCorpus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SecurityCorpus::Malicious);
    }

    #[test]
    fn security_corpus_rejects_unknown_variant() {
        let result = serde_json::from_str::<SecurityCorpus>("\"unknown\"");
        assert!(result.is_err());
    }

    // ---- SecurityAttackTaxonomy ----

    #[test]
    fn attack_taxonomy_as_str_all_variants() {
        assert_eq!(SecurityAttackTaxonomy::Exfil.as_str(), "exfil");
        assert_eq!(SecurityAttackTaxonomy::Escalation.as_str(), "escalation");
        assert_eq!(SecurityAttackTaxonomy::Evasion.as_str(), "evasion");
        assert_eq!(SecurityAttackTaxonomy::Dos.as_str(), "dos");
        assert_eq!(SecurityAttackTaxonomy::SideChannel.as_str(), "side_channel");
        assert_eq!(SecurityAttackTaxonomy::Staging.as_str(), "staging");
    }

    #[test]
    fn attack_taxonomy_serde_roundtrip_all() {
        let variants = [
            SecurityAttackTaxonomy::Exfil,
            SecurityAttackTaxonomy::Escalation,
            SecurityAttackTaxonomy::Evasion,
            SecurityAttackTaxonomy::Dos,
            SecurityAttackTaxonomy::SideChannel,
            SecurityAttackTaxonomy::Staging,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SecurityAttackTaxonomy = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
            assert_eq!(json.trim_matches('"'), variant.as_str());
        }
    }

    #[test]
    fn attack_taxonomy_matches_constant_list() {
        let variants = [
            SecurityAttackTaxonomy::Exfil,
            SecurityAttackTaxonomy::Escalation,
            SecurityAttackTaxonomy::Evasion,
            SecurityAttackTaxonomy::Dos,
            SecurityAttackTaxonomy::SideChannel,
            SecurityAttackTaxonomy::Staging,
        ];
        for variant in variants {
            assert!(
                SECURITY_ATTACK_TAXONOMIES.contains(&variant.as_str()),
                "missing {} in SECURITY_ATTACK_TAXONOMIES",
                variant.as_str()
            );
        }
        assert_eq!(variants.len(), SECURITY_ATTACK_TAXONOMIES.len());
    }

    // ---- SecurityOutcome ----

    #[test]
    fn security_outcome_as_str_all_variants() {
        assert_eq!(SecurityOutcome::Allow.as_str(), "allow");
        assert_eq!(SecurityOutcome::Contain.as_str(), "contain");
        assert_eq!(SecurityOutcome::Quarantine.as_str(), "quarantine");
        assert_eq!(SecurityOutcome::Terminate.as_str(), "terminate");
    }

    #[test]
    fn security_outcome_serde_roundtrip_all() {
        let variants = [
            SecurityOutcome::Allow,
            SecurityOutcome::Contain,
            SecurityOutcome::Quarantine,
            SecurityOutcome::Terminate,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SecurityOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
            assert_eq!(json.trim_matches('"'), variant.as_str());
        }
    }

    // ---- SecurityWorkloadLabel validation ----

    fn valid_sha256() -> String {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
    }

    fn valid_benign_label() -> SecurityWorkloadLabel {
        SecurityWorkloadLabel {
            workload_id: "benign-1".to_string(),
            corpus: SecurityCorpus::Benign,
            attack_taxonomy: None,
            expected_outcome: SecurityOutcome::Allow,
            expected_detection_latency_bound_ms: 10,
            hostcall_sequence_hash: valid_sha256(),
            semantic_domain: "security/benign".to_string(),
        }
    }

    fn valid_malicious_label() -> SecurityWorkloadLabel {
        SecurityWorkloadLabel {
            workload_id: "malicious-1".to_string(),
            corpus: SecurityCorpus::Malicious,
            attack_taxonomy: Some(SecurityAttackTaxonomy::Exfil),
            expected_outcome: SecurityOutcome::Contain,
            expected_detection_latency_bound_ms: 20,
            hostcall_sequence_hash: valid_sha256(),
            semantic_domain: "security/malicious".to_string(),
        }
    }

    #[test]
    fn valid_benign_label_passes_validation() {
        valid_benign_label().validate().unwrap();
    }

    #[test]
    fn valid_malicious_label_passes_validation() {
        valid_malicious_label().validate().unwrap();
    }

    #[test]
    fn label_rejects_empty_workload_id() {
        let mut label = valid_benign_label();
        label.workload_id = "".to_string();
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("workload_id"));
    }

    #[test]
    fn label_rejects_whitespace_only_workload_id() {
        let mut label = valid_benign_label();
        label.workload_id = "   ".to_string();
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("workload_id"));
    }

    #[test]
    fn label_rejects_padded_workload_id() {
        let mut label = valid_benign_label();
        label.workload_id = " wl-1 ".to_string();
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("leading or trailing whitespace"));
    }

    #[test]
    fn label_rejects_empty_semantic_domain() {
        let mut label = valid_benign_label();
        label.semantic_domain = "".to_string();
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("semantic_domain"));
    }

    #[test]
    fn label_rejects_zero_latency_bound() {
        let mut label = valid_benign_label();
        label.expected_detection_latency_bound_ms = 0;
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expected_detection_latency_bound_ms"));
    }

    #[test]
    fn label_rejects_invalid_hash_short() {
        let mut label = valid_benign_label();
        label.hostcall_sequence_hash = "aabb".to_string();
        assert!(label.validate().is_err());
    }

    #[test]
    fn label_rejects_invalid_hash_uppercase() {
        let mut label = valid_benign_label();
        label.hostcall_sequence_hash =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert!(label.validate().is_err());
    }

    #[test]
    fn label_rejects_benign_with_non_allow_outcome() {
        let mut label = valid_benign_label();
        label.expected_outcome = SecurityOutcome::Contain;
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expected_outcome"));
    }

    #[test]
    fn label_rejects_malicious_with_allow_outcome() {
        let mut label = valid_malicious_label();
        label.expected_outcome = SecurityOutcome::Allow;
        let err = label.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("expected_outcome"));
    }

    #[test]
    fn malicious_label_accepts_quarantine_outcome() {
        let mut label = valid_malicious_label();
        label.expected_outcome = SecurityOutcome::Quarantine;
        label.validate().unwrap();
    }

    #[test]
    fn malicious_label_accepts_terminate_outcome() {
        let mut label = valid_malicious_label();
        label.expected_outcome = SecurityOutcome::Terminate;
        label.validate().unwrap();
    }

    // ---- SecurityWorkloadObservation validation ----

    fn valid_observation() -> SecurityWorkloadObservation {
        SecurityWorkloadObservation {
            workload_id: "wl-1".to_string(),
            actual_outcome: SecurityOutcome::Allow,
            detection_latency_us: 5000,
            sentinel_posterior: 0.5,
            policy_action: "allow".to_string(),
            containment_action: "none".to_string(),
            error_code: None,
        }
    }

    #[test]
    fn valid_observation_passes_validation() {
        valid_observation().validate().unwrap();
    }

    #[test]
    fn observation_rejects_empty_workload_id() {
        let mut obs = valid_observation();
        obs.workload_id = "".to_string();
        let err = obs.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("workload_id"));
    }

    #[test]
    fn observation_rejects_padded_workload_id() {
        let mut obs = valid_observation();
        obs.workload_id = " wl-1 ".to_string();
        let err = obs.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("leading or trailing whitespace"));
    }

    #[test]
    fn observation_rejects_empty_policy_action() {
        let mut obs = valid_observation();
        obs.policy_action = "".to_string();
        let err = obs.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("policy_action"));
    }

    #[test]
    fn observation_rejects_empty_containment_action() {
        let mut obs = valid_observation();
        obs.containment_action = " ".to_string();
        let err = obs.validate().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("containment_action"));
    }

    #[test]
    fn observation_rejects_negative_posterior() {
        let mut obs = valid_observation();
        obs.sentinel_posterior = -0.01;
        assert!(obs.validate().is_err());
    }

    #[test]
    fn observation_rejects_posterior_above_one() {
        let mut obs = valid_observation();
        obs.sentinel_posterior = 1.001;
        assert!(obs.validate().is_err());
    }

    #[test]
    fn observation_accepts_boundary_posterior_zero() {
        let mut obs = valid_observation();
        obs.sentinel_posterior = 0.0;
        obs.validate().unwrap();
    }

    #[test]
    fn observation_accepts_boundary_posterior_one() {
        let mut obs = valid_observation();
        obs.sentinel_posterior = 1.0;
        obs.validate().unwrap();
    }

    #[test]
    fn observation_serde_roundtrip() {
        let obs = valid_observation();
        let json = serde_json::to_string(&obs).unwrap();
        let back: SecurityWorkloadObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.workload_id, obs.workload_id);
        assert_eq!(back.actual_outcome, obs.actual_outcome);
        assert_eq!(back.detection_latency_us, obs.detection_latency_us);
    }

    // ---- SecurityConformanceThresholds ----

    #[test]
    fn thresholds_default_values() {
        let t = SecurityConformanceThresholds::default();
        let cl = t.confidence_level().unwrap();
        assert!((cl - 0.95).abs() < 1e-6);
        let tpr = t.tpr_min_f64().unwrap();
        assert!((tpr - 0.99).abs() < 1e-6);
        let fpr = t.fpr_max_f64().unwrap();
        assert!((fpr - 0.01).abs() < 1e-6);
        assert_eq!(t.malicious_latency_p95_max_ms, 250);
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = SecurityConformanceThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: SecurityConformanceThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ---- BinomialConfidenceInterval ----

    #[test]
    fn binomial_ci_lower_upper_f64() {
        let ci = BinomialConfidenceInterval {
            lower_millionths: 500_000,
            upper_millionths: 950_000,
        };
        let lower = ci.lower_f64().unwrap();
        let upper = ci.upper_f64().unwrap();
        assert!((lower - 0.5).abs() < 1e-6);
        assert!((upper - 0.95).abs() < 1e-6);
    }

    #[test]
    fn binomial_ci_zero_one() {
        let ci = BinomialConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 1_000_000,
        };
        assert!((ci.lower_f64().unwrap()).abs() < 1e-9);
        assert!((ci.upper_f64().unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn binomial_ci_rejects_above_million() {
        let ci = BinomialConfidenceInterval {
            lower_millionths: 1_000_001,
            upper_millionths: 500_000,
        };
        assert!(ci.lower_f64().is_err());
    }

    #[test]
    fn binomial_ci_serde_roundtrip() {
        let ci = BinomialConfidenceInterval {
            lower_millionths: 123_456,
            upper_millionths: 789_012,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: BinomialConfidenceInterval = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ci);
    }

    // ---- Helper functions ----

    #[test]
    fn millionths_to_f64_valid_cases() {
        assert!((millionths_to_f64(0).unwrap()).abs() < 1e-9);
        assert!((millionths_to_f64(500_000).unwrap() - 0.5).abs() < 1e-6);
        assert!((millionths_to_f64(1_000_000).unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn millionths_to_f64_rejects_over_million() {
        assert!(millionths_to_f64(1_000_001).is_err());
        assert!(millionths_to_f64(u32::MAX).is_err());
    }

    #[test]
    fn millionths_to_string_format() {
        assert_eq!(millionths_to_string(990_000), "0.990000");
        assert_eq!(millionths_to_string(10_000), "0.010000");
        assert_eq!(millionths_to_string(1_000_000), "1.000000");
        assert_eq!(millionths_to_string(0), "0.000000");
    }

    #[test]
    fn ratio_to_millionths_normal() {
        assert_eq!(ratio_to_millionths(1, 2), 500_000);
        assert_eq!(ratio_to_millionths(99, 100), 990_000);
        assert_eq!(ratio_to_millionths(0, 100), 0);
        assert_eq!(ratio_to_millionths(100, 100), 1_000_000);
    }

    #[test]
    fn ratio_to_millionths_zero_denominator() {
        assert_eq!(ratio_to_millionths(0, 0), 0);
        assert_eq!(ratio_to_millionths(5, 0), 0);
    }

    #[test]
    fn f64_to_millionths_clamps() {
        assert_eq!(f64_to_millionths(0.0), 0);
        assert_eq!(f64_to_millionths(1.0), 1_000_000);
        assert_eq!(f64_to_millionths(-0.5), 0);
        assert_eq!(f64_to_millionths(1.5), 1_000_000);
        assert_eq!(f64_to_millionths(0.5), 500_000);
    }

    #[test]
    fn is_valid_sha256_hex_good() {
        assert!(is_valid_sha256_hex(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
    }

    #[test]
    fn is_valid_sha256_hex_rejects_short() {
        assert!(!is_valid_sha256_hex("abcd"));
    }

    #[test]
    fn is_valid_sha256_hex_rejects_uppercase() {
        assert!(!is_valid_sha256_hex(
            "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        ));
    }

    #[test]
    fn is_valid_sha256_hex_rejects_non_hex() {
        assert!(!is_valid_sha256_hex(
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
        ));
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert!(is_valid_sha256_hex(&a));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sha256_hex_differs_for_different_input() {
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn parse_ratio_string_valid() {
        assert!((parse_ratio_string("0.990000", "test").unwrap() - 0.99).abs() < 1e-6);
        assert!((parse_ratio_string("0.0", "test").unwrap()).abs() < 1e-9);
        assert!((parse_ratio_string("1.0", "test").unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn parse_ratio_string_rejects_out_of_range() {
        assert!(parse_ratio_string("-0.1", "test").is_err());
        assert!(parse_ratio_string("1.1", "test").is_err());
    }

    #[test]
    fn parse_ratio_string_rejects_non_numeric() {
        assert!(parse_ratio_string("abc", "test").is_err());
    }

    // ---- percentile_95_us ----

    #[test]
    fn percentile_95_empty() {
        assert_eq!(percentile_95_us(&mut []), None);
    }

    #[test]
    fn percentile_95_single() {
        assert_eq!(percentile_95_us(&mut [42]), Some(42));
    }

    #[test]
    fn percentile_95_hundred_values() {
        let mut values: Vec<u64> = (1..=100).collect();
        let p95 = percentile_95_us(&mut values).unwrap();
        assert_eq!(p95, 95);
    }

    #[test]
    fn percentile_95_twenty_values() {
        let mut values: Vec<u64> = (1..=20).collect();
        let p95 = percentile_95_us(&mut values).unwrap();
        assert_eq!(p95, 19);
    }

    // ---- clopper_pearson_interval edge cases ----

    #[test]
    fn clopper_pearson_zero_successes() {
        let ci = clopper_pearson_interval(0, 100, 0.95).unwrap();
        assert_eq!(ci.lower_millionths, 0);
        assert!(ci.upper_millionths > 0);
        assert!(ci.upper_f64().unwrap() < 0.1);
    }

    #[test]
    fn clopper_pearson_all_successes() {
        let ci = clopper_pearson_interval(100, 100, 0.95).unwrap();
        assert_eq!(ci.upper_millionths, 1_000_000);
        assert!(ci.lower_f64().unwrap() > 0.9);
    }

    #[test]
    fn clopper_pearson_rejects_zero_total() {
        assert!(clopper_pearson_interval(0, 0, 0.95).is_err());
    }

    #[test]
    fn clopper_pearson_rejects_successes_gt_total() {
        assert!(clopper_pearson_interval(101, 100, 0.95).is_err());
    }

    #[test]
    fn clopper_pearson_rejects_invalid_confidence() {
        assert!(clopper_pearson_interval(50, 100, 1.0).is_err());
        assert!(clopper_pearson_interval(50, 100, -0.1).is_err());
    }

    #[test]
    fn clopper_pearson_half_interval_reasonable() {
        let ci = clopper_pearson_interval(50, 100, 0.95).unwrap();
        let lower = ci.lower_f64().unwrap();
        let upper = ci.upper_f64().unwrap();
        assert!(lower > 0.35 && lower < 0.50);
        assert!(upper > 0.50 && upper < 0.65);
    }

    #[test]
    fn clopper_pearson_99_of_100_matches_reference_interval() {
        let ci = clopper_pearson_interval(99, 100, 0.95).unwrap();
        assert!(
            ci.lower_millionths.abs_diff(945_541) <= 1,
            "unexpected lower bound: {}",
            ci.lower_millionths
        );
        assert!(
            ci.upper_millionths.abs_diff(999_747) <= 1,
            "unexpected upper bound: {}",
            ci.upper_millionths
        );
    }

    // ---- default_observation_from_label ----

    #[test]
    fn default_observation_benign_label() {
        let label = valid_benign_label();
        let obs = default_observation_from_label(&label);
        assert_eq!(obs.workload_id, "benign-1");
        assert_eq!(obs.actual_outcome, SecurityOutcome::Allow);
        assert_eq!(obs.policy_action, "allow");
        assert_eq!(obs.containment_action, "none");
        assert!((obs.sentinel_posterior - 0.05).abs() < 1e-9);
        assert!(obs.error_code.is_none());
        assert_eq!(obs.detection_latency_us, 10 * 1000 - 1);
    }

    #[test]
    fn default_observation_malicious_label() {
        let label = valid_malicious_label();
        let obs = default_observation_from_label(&label);
        assert_eq!(obs.workload_id, "malicious-1");
        assert_eq!(obs.actual_outcome, SecurityOutcome::Contain);
        assert_eq!(obs.policy_action, "contain");
        assert_eq!(obs.containment_action, "sandbox");
        assert!((obs.sentinel_posterior - 0.995).abs() < 1e-9);
    }

    #[test]
    fn default_observation_quarantine_label() {
        let mut label = valid_malicious_label();
        label.expected_outcome = SecurityOutcome::Quarantine;
        let obs = default_observation_from_label(&label);
        assert_eq!(obs.policy_action, "quarantine");
        assert_eq!(obs.containment_action, "quarantine");
    }

    #[test]
    fn default_observation_terminate_label() {
        let mut label = valid_malicious_label();
        label.expected_outcome = SecurityOutcome::Terminate;
        let obs = default_observation_from_label(&label);
        assert_eq!(obs.policy_action, "terminate");
        assert_eq!(obs.containment_action, "terminate");
    }

    // ---- corpus_manifest_hash ----

    #[test]
    fn corpus_manifest_hash_deterministic() {
        let record = SecurityWorkloadLabelRecord {
            label: valid_benign_label(),
            label_path: PathBuf::from("test"),
            label_hash: "testhash".to_string(),
        };
        let h1 = corpus_manifest_hash(std::slice::from_ref(&record));
        let h2 = corpus_manifest_hash(std::slice::from_ref(&record));
        assert_eq!(h1, h2);
        assert!(is_valid_sha256_hex(&h1));
    }

    #[test]
    fn corpus_manifest_hash_empty_records() {
        let h = corpus_manifest_hash(&[]);
        assert!(is_valid_sha256_hex(&h));
    }

    #[test]
    fn corpus_manifest_hash_is_order_independent() {
        let r1 = SecurityWorkloadLabelRecord {
            label: valid_benign_label(),
            label_path: PathBuf::from("a"),
            label_hash: "hash-a".to_string(),
        };
        let mut r2_label = valid_malicious_label();
        r2_label.workload_id = "malicious-2".to_string();
        let r2 = SecurityWorkloadLabelRecord {
            label: r2_label,
            label_path: PathBuf::from("b"),
            label_hash: "hash-b".to_string(),
        };
        let h_ab = corpus_manifest_hash(&[r1.clone(), r2.clone()]);
        let h_ba = corpus_manifest_hash(&[r2, r1]);
        // Hash must be deterministic regardless of input order.
        assert_eq!(h_ab, h_ba);
    }

    // ---- evaluate_security_conformance ----

    fn make_record(
        workload_id: &str,
        corpus: SecurityCorpus,
        taxonomy: Option<SecurityAttackTaxonomy>,
        outcome: SecurityOutcome,
    ) -> SecurityWorkloadLabelRecord {
        SecurityWorkloadLabelRecord {
            label: SecurityWorkloadLabel {
                workload_id: workload_id.to_string(),
                corpus,
                attack_taxonomy: taxonomy,
                expected_outcome: outcome,
                expected_detection_latency_bound_ms: 100,
                hostcall_sequence_hash: valid_sha256(),
                semantic_domain: "test".to_string(),
            },
            label_path: PathBuf::from(workload_id),
            label_hash: sha256_hex(workload_id.as_bytes()),
        }
    }

    fn make_obs(
        workload_id: &str,
        outcome: SecurityOutcome,
        latency_us: u64,
    ) -> SecurityWorkloadObservation {
        SecurityWorkloadObservation {
            workload_id: workload_id.to_string(),
            actual_outcome: outcome,
            detection_latency_us: latency_us,
            sentinel_posterior: 0.5,
            policy_action: outcome.as_str().to_string(),
            containment_action: if outcome == SecurityOutcome::Allow {
                "none".to_string()
            } else {
                "sandbox".to_string()
            },
            error_code: None,
        }
    }

    #[test]
    fn evaluate_empty_records_error() {
        let err =
            evaluate_security_conformance(&[], &[], &SecurityConformanceThresholds::default())
                .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty"));
    }

    #[test]
    fn evaluate_missing_observation_error() {
        let records = vec![make_record(
            "b-1",
            SecurityCorpus::Benign,
            None,
            SecurityOutcome::Allow,
        )];
        let err =
            evaluate_security_conformance(&records, &[], &SecurityConformanceThresholds::default())
                .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing observation"));
    }

    #[test]
    fn evaluate_duplicate_observation_error() {
        let records = vec![make_record(
            "b-1",
            SecurityCorpus::Benign,
            None,
            SecurityOutcome::Allow,
        )];
        let obs1 = make_obs("b-1", SecurityOutcome::Allow, 1000);
        let obs2 = make_obs("b-1", SecurityOutcome::Allow, 2000);
        let err = evaluate_security_conformance(
            &records,
            &[obs1, obs2],
            &SecurityConformanceThresholds::default(),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("duplicate observation"));
    }

    #[test]
    fn evaluate_duplicate_record_error() {
        let mut first = make_record("b-1", SecurityCorpus::Benign, None, SecurityOutcome::Allow);
        first.label_path = PathBuf::from("first/workload_label.toml");
        let mut second = make_record("b-1", SecurityCorpus::Benign, None, SecurityOutcome::Allow);
        second.label_path = PathBuf::from("second/workload_label.toml");

        let err = evaluate_security_conformance(
            &[first, second],
            &[make_obs("b-1", SecurityOutcome::Allow, 1000)],
            &SecurityConformanceThresholds::default(),
        )
        .unwrap_err();

        match err {
            SecurityConformanceError::DuplicateWorkloadId {
                workload_id,
                first_path,
                second_path,
            } => {
                assert_eq!(workload_id, "b-1");
                assert_eq!(first_path, PathBuf::from("first/workload_label.toml"));
                assert_eq!(second_path, PathBuf::from("second/workload_label.toml"));
            }
            other => panic!("expected duplicate record error, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_invalid_record_label_error() {
        let records = vec![make_record(
            "m-1",
            SecurityCorpus::Malicious,
            None,
            SecurityOutcome::Contain,
        )];

        let err = evaluate_security_conformance(
            &records,
            &[make_obs("m-1", SecurityOutcome::Contain, 1000)],
            &SecurityConformanceThresholds::default(),
        )
        .unwrap_err();

        match err {
            SecurityConformanceError::InvalidLabelField { field, detail } => {
                assert_eq!(field, "attack_taxonomy");
                assert!(detail.contains("must declare"));
            }
            other => panic!("expected invalid label error, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_unexpected_observation_error() {
        let records = vec![make_record(
            "b-1",
            SecurityCorpus::Benign,
            None,
            SecurityOutcome::Allow,
        )];
        let observations = vec![
            make_obs("b-1", SecurityOutcome::Allow, 1000),
            make_obs("ghost", SecurityOutcome::Contain, 2000),
        ];
        let err = evaluate_security_conformance(
            &records,
            &observations,
            &SecurityConformanceThresholds::default(),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unexpected observation"));
        assert!(msg.contains("ghost"));
    }

    #[test]
    fn evaluate_perfect_pass() {
        let records = vec![
            make_record("b-1", SecurityCorpus::Benign, None, SecurityOutcome::Allow),
            make_record(
                "m-1",
                SecurityCorpus::Malicious,
                Some(SecurityAttackTaxonomy::Exfil),
                SecurityOutcome::Contain,
            ),
        ];
        let observations = vec![
            make_obs("b-1", SecurityOutcome::Allow, 1000),
            make_obs("m-1", SecurityOutcome::Contain, 5000),
        ];
        let result = evaluate_security_conformance(
            &records,
            &observations,
            &SecurityConformanceThresholds::default(),
        )
        .unwrap();
        assert_eq!(result.summary.benign_total, 1);
        assert_eq!(result.summary.malicious_total, 1);
        assert_eq!(result.summary.true_positive_count, 1);
        assert_eq!(result.summary.false_positive_count, 0);
        assert_eq!(result.summary.false_negative_count, 0);
        assert_eq!(result.summary.tpr_millionths, 1_000_000);
        assert_eq!(result.summary.fpr_millionths, 0);
        assert_eq!(result.observations_by_workload.len(), 2);
    }

    #[test]
    fn evaluate_counts_false_positive() {
        let records = vec![
            make_record("b-1", SecurityCorpus::Benign, None, SecurityOutcome::Allow),
            make_record(
                "m-1",
                SecurityCorpus::Malicious,
                Some(SecurityAttackTaxonomy::Dos),
                SecurityOutcome::Terminate,
            ),
        ];
        let observations = vec![
            make_obs("b-1", SecurityOutcome::Contain, 1000),
            make_obs("m-1", SecurityOutcome::Terminate, 5000),
        ];
        let result = evaluate_security_conformance(
            &records,
            &observations,
            &SecurityConformanceThresholds::default(),
        )
        .unwrap();
        assert_eq!(result.summary.false_positive_count, 1);
        assert_eq!(result.summary.true_positive_count, 1);
    }

    #[test]
    fn evaluate_counts_false_negative() {
        let records = vec![
            make_record("b-1", SecurityCorpus::Benign, None, SecurityOutcome::Allow),
            make_record(
                "m-1",
                SecurityCorpus::Malicious,
                Some(SecurityAttackTaxonomy::Evasion),
                SecurityOutcome::Quarantine,
            ),
        ];
        let observations = vec![
            make_obs("b-1", SecurityOutcome::Allow, 1000),
            make_obs("m-1", SecurityOutcome::Allow, 5000),
        ];
        let result = evaluate_security_conformance(
            &records,
            &observations,
            &SecurityConformanceThresholds::default(),
        )
        .unwrap();
        assert_eq!(result.summary.false_negative_count, 1);
        assert_eq!(result.summary.true_positive_count, 0);
    }

    #[test]
    fn evaluate_tpr_boundary_passes_at_exact_lower_ci_and_fails_one_tick_above() {
        let mut records = Vec::new();
        let mut observations = Vec::new();

        for i in 0..100 {
            let id = format!("b-{i}");
            records.push(make_record(
                &id,
                SecurityCorpus::Benign,
                None,
                SecurityOutcome::Allow,
            ));
            observations.push(make_obs(&id, SecurityOutcome::Allow, 1_000));
        }

        for i in 0..100 {
            let id = format!("m-{i}");
            records.push(make_record(
                &id,
                SecurityCorpus::Malicious,
                Some(SecurityAttackTaxonomy::Exfil),
                SecurityOutcome::Contain,
            ));
            let outcome = if i == 99 {
                SecurityOutcome::Allow
            } else {
                SecurityOutcome::Contain
            };
            observations.push(make_obs(&id, outcome, 5_000));
        }

        let mut thresholds = SecurityConformanceThresholds {
            tpr_min: millionths_to_string(0),
            fpr_max: millionths_to_string(1_000_000),
            ..SecurityConformanceThresholds::default()
        };
        let boundary_probe =
            evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
        let lower_bound = boundary_probe.summary.tpr_ci.lower_millionths;

        assert_eq!(boundary_probe.summary.true_positive_count, 99);
        assert_eq!(boundary_probe.summary.false_negative_count, 1);
        assert_eq!(lower_bound, 945_541);
        assert!(boundary_probe.summary.gate_pass);

        thresholds.tpr_min = millionths_to_string(lower_bound);
        let exact_boundary =
            evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
        assert!(
            exact_boundary.summary.gate_pass,
            "exact lower-CI threshold should pass: {:?}",
            exact_boundary.summary.gate_failure_reasons
        );

        thresholds.tpr_min = millionths_to_string(lower_bound + 1);
        let failing_boundary =
            evaluate_security_conformance(&records, &observations, &thresholds).unwrap();
        assert!(!failing_boundary.summary.gate_pass);
        assert!(
            failing_boundary
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("TPR lower CI bound")),
            "missing TPR failure reason: {:?}",
            failing_boundary.summary.gate_failure_reasons
        );
        assert!(
            !failing_boundary
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("FPR upper CI bound")),
            "unexpected FPR failure reason: {:?}",
            failing_boundary.summary.gate_failure_reasons
        );
        assert!(
            !failing_boundary
                .summary
                .gate_failure_reasons
                .iter()
                .any(|reason| reason.contains("latency")),
            "unexpected latency failure reason: {:?}",
            failing_boundary.summary.gate_failure_reasons
        );
    }

    // ---- normalize_relative_path ----

    #[test]
    fn normalize_relative_path_strips_curdir() {
        let p = normalize_relative_path(Path::new("./a/./b/c"));
        assert_eq!(p, PathBuf::from("a/b/c"));
    }

    #[test]
    fn normalize_relative_path_plain() {
        let p = normalize_relative_path(Path::new("a/b/c"));
        assert_eq!(p, PathBuf::from("a/b/c"));
    }

    // ---- SecurityConformanceError Display ----

    #[test]
    fn error_display_io() {
        let err = SecurityConformanceError::Io {
            path: PathBuf::from("/tmp/test"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("/tmp/test"));
    }

    #[test]
    fn error_display_root_path_missing() {
        let err = SecurityConformanceError::RootPathMissing {
            root: PathBuf::from("/nonexistent"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("labels root does not exist"));
    }

    #[test]
    fn error_display_no_labels_found() {
        let err = SecurityConformanceError::NoLabelsFound {
            root: PathBuf::from("/empty"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("workload_label.toml"));
    }

    #[test]
    fn error_display_empty_dataset() {
        let err = SecurityConformanceError::EmptyDataset;
        let msg = format!("{err}");
        assert!(msg.contains("empty"));
    }

    #[test]
    fn error_display_invalid_label_field() {
        let err = SecurityConformanceError::InvalidLabelField {
            field: "workload_id",
            detail: "must not be empty".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("workload_id"));
        assert!(msg.contains("must not be empty"));
    }

    #[test]
    fn error_display_invalid_observation_field() {
        let err = SecurityConformanceError::InvalidObservationField {
            field: "policy_action",
            detail: "must not be empty".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("policy_action"));
    }

    #[test]
    fn error_display_missing_observation() {
        let err = SecurityConformanceError::MissingObservation {
            workload_id: "w-1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("missing observation"));
        assert!(msg.contains("w-1"));
    }

    #[test]
    fn error_display_duplicate_observation() {
        let err = SecurityConformanceError::DuplicateObservation {
            workload_id: "w-1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("duplicate observation"));
    }

    #[test]
    fn error_display_unexpected_observation() {
        let err = SecurityConformanceError::UnexpectedObservation {
            workload_id: "w-404".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("unexpected observation"));
        assert!(msg.contains("w-404"));
    }

    #[test]
    fn error_display_invalid_ratio_config() {
        let err = SecurityConformanceError::InvalidRatioConfig {
            field: "tpr_min",
            value: "abc".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("tpr_min"));
    }

    #[test]
    fn error_display_binomial_interval_unavailable() {
        let err = SecurityConformanceError::BinomialIntervalUnavailable {
            successes: 5,
            total: 0,
        };
        let msg = format!("{err}");
        assert!(msg.contains("binomial"));
    }

    #[test]
    fn error_display_duplicate_workload_id() {
        let err = SecurityConformanceError::DuplicateWorkloadId {
            workload_id: "dup-1".to_string(),
            first_path: PathBuf::from("a.toml"),
            second_path: PathBuf::from("b.toml"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("dup-1"));
        assert!(msg.contains("a.toml"));
        assert!(msg.contains("b.toml"));
    }

    #[test]
    fn error_display_manifest_schema_mismatch() {
        let err = SecurityConformanceError::ManifestSchemaMismatch {
            expected: "v1",
            found: "v2".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("v2"));
    }

    #[test]
    fn error_display_manifest_invalid_entry() {
        let err = SecurityConformanceError::ManifestInvalidEntry {
            detail: "bad entry".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("bad entry"));
    }

    #[test]
    fn error_display_manifest_duplicate_workload() {
        let err = SecurityConformanceError::ManifestDuplicateWorkloadId {
            workload_id: "dup".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("dup"));
    }

    #[test]
    fn error_display_manifest_missing_workload() {
        let err = SecurityConformanceError::ManifestMissingWorkload {
            workload_id: "miss".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("miss"));
    }

    #[test]
    fn error_display_manifest_unexpected_workload() {
        let err = SecurityConformanceError::ManifestUnexpectedWorkload {
            workload_id: "extra".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("extra"));
    }

    #[test]
    fn error_display_manifest_label_path_mismatch() {
        let err = SecurityConformanceError::ManifestLabelPathMismatch {
            workload_id: "w-1".to_string(),
            expected_path: PathBuf::from("expected"),
            actual_path: PathBuf::from("actual"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("expected"));
        assert!(msg.contains("actual"));
    }

    #[test]
    fn error_display_manifest_label_hash_mismatch() {
        let err = SecurityConformanceError::ManifestLabelHashMismatch {
            workload_id: "w-1".to_string(),
            expected_hash: "aaa".to_string(),
            actual_hash: "bbb".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("aaa"));
        assert!(msg.contains("bbb"));
    }

    #[test]
    fn error_display_manifest_corpus_mismatch() {
        let err = SecurityConformanceError::ManifestCorpusMismatch {
            workload_id: "w-1".to_string(),
            expected: SecurityCorpus::Benign,
            actual: SecurityCorpus::Malicious,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Benign"));
        assert!(msg.contains("Malicious"));
    }

    #[test]
    fn error_display_manifest_path_missing() {
        let err = SecurityConformanceError::ManifestPathMissing {
            path: PathBuf::from("/missing"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("corpus manifest not found"));
    }

    #[test]
    fn error_implements_std_error() {
        let err = SecurityConformanceError::EmptyDataset;
        let _: &dyn std::error::Error = &err;
    }

    // ---- SecurityWorkloadLabel serde ----

    #[test]
    fn workload_label_serde_roundtrip_benign() {
        let label = valid_benign_label();
        let json = serde_json::to_string(&label).unwrap();
        let back: SecurityWorkloadLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, label);
    }

    #[test]
    fn workload_label_serde_roundtrip_malicious() {
        let label = valid_malicious_label();
        let json = serde_json::to_string(&label).unwrap();
        let back: SecurityWorkloadLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, label);
    }

    // ---- load_security_labels filesystem ----

    #[test]
    fn load_labels_nonexistent_root_error() {
        let root = PathBuf::from("/tmp/nonexistent-security-conformance-test-path-999");
        let err = load_security_labels(&root).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("labels root does not exist"));
    }

    #[test]
    fn load_labels_empty_dir_error() {
        let root = test_temp_dir("empty-dir");
        let err = load_security_labels(&root).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("workload_label.toml"));
    }

    #[test]
    fn load_labels_single_benign() {
        let root = test_temp_dir("single-benign");
        let label_path = root.join("benign/a/workload_label.toml");
        let body = format!(
            r#"workload_id = "benign-a"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "{}"
semantic_domain = "security/benign"
"#,
            "aa".repeat(32)
        );
        write_label(&label_path, &body);
        let records = load_security_labels(&root).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label.workload_id, "benign-a");
        assert!(is_valid_sha256_hex(&records[0].label_hash));
    }

    #[test]
    fn load_labels_sorted_by_workload_id() {
        let root = test_temp_dir("sorted-labels");
        let hash = "aa".repeat(32);
        for (idx, wid) in ["zzz", "aaa", "mmm"].iter().enumerate() {
            let label_path = root.join(format!("benign/{idx}/workload_label.toml"));
            let body = format!(
                r#"workload_id = "{wid}"
corpus = "benign"
expected_outcome = "allow"
expected_detection_latency_bound_ms = 10
hostcall_sequence_hash = "{hash}"
semantic_domain = "security/benign"
"#
            );
            write_label(&label_path, &body);
        }
        let records = load_security_labels(&root).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].label.workload_id, "aaa");
        assert_eq!(records[1].label.workload_id, "mmm");
        assert_eq!(records[2].label.workload_id, "zzz");
    }

    // ---- SecurityConformanceSummary ----

    #[test]
    fn summary_serde_roundtrip() {
        let summary = SecurityConformanceSummary {
            corpus_manifest_hash: sha256_hex(b"test"),
            benign_total: 200,
            malicious_total: 100,
            true_positive_count: 99,
            false_positive_count: 1,
            false_negative_count: 1,
            tpr_millionths: 990_000,
            fpr_millionths: 5_000,
            tpr_ci: BinomialConfidenceInterval {
                lower_millionths: 940_000,
                upper_millionths: 999_000,
            },
            fpr_ci: BinomialConfidenceInterval {
                lower_millionths: 0,
                upper_millionths: 30_000,
            },
            malicious_latency_p95_us: 50_000,
            malicious_latency_p95_max_us: 250_000,
            gate_pass: true,
            gate_failure_reasons: vec![],
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: SecurityConformanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    // ---- SecurityWorkloadLabelRecord ----

    #[test]
    fn label_record_debug_format() {
        let record = SecurityWorkloadLabelRecord {
            label: valid_benign_label(),
            label_path: PathBuf::from("test/path.toml"),
            label_hash: "abc123".to_string(),
        };
        let debug = format!("{record:?}");
        assert!(debug.contains("benign-1"));
        assert!(debug.contains("test/path.toml"));
    }
}
