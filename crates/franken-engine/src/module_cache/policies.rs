#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheWorkloadClass {
    ColdCompile,
    WarmRun,
    PackageGraph,
    ReactApp,
    ScanHeavy,
}

impl CacheWorkloadClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ColdCompile => "cold_compile",
            Self::WarmRun => "warm_run",
            Self::PackageGraph => "package_graph",
            Self::ReactApp => "react_app",
            Self::ScanHeavy => "scan_heavy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLocalityClass {
    Hot,
    #[default]
    Warm,
    Scan,
}

impl CacheLocalityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Scan => "scan",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheTraceAccess {
    pub sequence: u64,
    pub key: ModuleCacheKey,
    #[serde(default)]
    pub locality: CacheLocalityClass,
}

impl CacheTraceAccess {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert(
            "locality".to_string(),
            CanonicalValue::String(self.locality.as_str().to_string()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheTraceCase {
    pub trace_id: String,
    pub workload_class: CacheWorkloadClass,
    pub accesses: Vec<CacheTraceAccess>,
}

impl CacheTraceCase {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "workload_class".to_string(),
            CanonicalValue::String(self.workload_class.as_str().to_string()),
        );
        map.insert(
            "accesses".to_string(),
            CanonicalValue::Array(
                self.accesses
                    .iter()
                    .map(CacheTraceAccess::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }

    fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.trace_id.trim().is_empty() {
            return Err(CachePolicyReportError::EmptyTraceId);
        }
        if self.accesses.is_empty() {
            return Err(CachePolicyReportError::EmptyTrace {
                trace_id: self.trace_id.clone(),
            });
        }

        let mut previous_sequence = None;
        for access in &self.accesses {
            if let Some(previous) = previous_sequence
                && access.sequence <= previous
            {
                return Err(CachePolicyReportError::NonMonotonicTraceSequence {
                    trace_id: self.trace_id.clone(),
                    previous,
                    actual: access.sequence,
                });
            }
            previous_sequence = Some(access.sequence);
            if access.key.module_id.trim().is_empty() {
                return Err(CachePolicyReportError::EmptyModuleIdInTrace {
                    trace_id: self.trace_id.clone(),
                    sequence: access.sequence,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheTraceCorpusManifest {
    pub schema_version: String,
    pub corpus_id: String,
    pub cases: Vec<CacheTraceCase>,
    pub corpus_hash: ContentHash,
}

impl CacheTraceCorpusManifest {
    pub fn new(
        corpus_id: impl Into<String>,
        cases: Vec<CacheTraceCase>,
    ) -> Result<Self, CachePolicyReportError> {
        let corpus_id = corpus_id.into();
        if corpus_id.trim().is_empty() {
            return Err(CachePolicyReportError::EmptyCorpusId);
        }
        if cases.is_empty() {
            return Err(CachePolicyReportError::EmptyCorpusCases);
        }
        let mut trace_ids = BTreeSet::new();
        for case in &cases {
            case.validate()?;
            if !trace_ids.insert(case.trace_id.clone()) {
                return Err(CachePolicyReportError::DuplicateTraceId {
                    trace_id: case.trace_id.clone(),
                });
            }
        }
        let corpus_hash = compute_cache_trace_corpus_hash(&corpus_id, &cases);
        Ok(Self {
            schema_version: CACHE_TRACE_CORPUS_SCHEMA_VERSION.to_string(),
            corpus_id,
            cases,
            corpus_hash,
        })
    }

    pub fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.schema_version != CACHE_TRACE_CORPUS_SCHEMA_VERSION {
            return Err(CachePolicyReportError::InvalidSchemaVersion {
                expected: CACHE_TRACE_CORPUS_SCHEMA_VERSION.to_string(),
                actual: self.schema_version.clone(),
            });
        }
        if self.corpus_id.trim().is_empty() {
            return Err(CachePolicyReportError::EmptyCorpusId);
        }
        if self.cases.is_empty() {
            return Err(CachePolicyReportError::EmptyCorpusCases);
        }
        let mut trace_ids = BTreeSet::new();
        for case in &self.cases {
            case.validate()?;
            if !trace_ids.insert(case.trace_id.clone()) {
                return Err(CachePolicyReportError::DuplicateTraceId {
                    trace_id: case.trace_id.clone(),
                });
            }
        }

        let expected_hash = compute_cache_trace_corpus_hash(&self.corpus_id, &self.cases);
        if expected_hash != self.corpus_hash {
            return Err(CachePolicyReportError::CorpusHashMismatch {
                expected: expected_hash,
                actual: self.corpus_hash,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicyKind {
    SingleQueueFifo,
    S3Fifo,
}

impl CachePolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleQueueFifo => "single_queue_fifo",
            Self::S3Fifo => "s3_fifo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingleQueueFifoConfig {
    pub capacity_entries: usize,
}

impl Default for SingleQueueFifoConfig {
    fn default() -> Self {
        Self {
            capacity_entries: 4,
        }
    }
}

impl SingleQueueFifoConfig {
    fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.capacity_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "capacity_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoConfig {
    pub resident_capacity_entries: usize,
    pub small_queue_entries: usize,
    pub ghost_queue_entries: usize,
}

impl Default for S3FifoConfig {
    fn default() -> Self {
        Self {
            resident_capacity_entries: 4,
            small_queue_entries: 2,
            ghost_queue_entries: 4,
        }
    }
}

impl S3FifoConfig {
    pub fn main_queue_entries(&self) -> usize {
        self.resident_capacity_entries
            .saturating_sub(self.small_queue_entries)
    }

    fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.resident_capacity_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "resident_capacity_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        if self.small_queue_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "small_queue_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        if self.small_queue_entries >= self.resident_capacity_entries {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "small_queue_entries",
                detail: "must be smaller than resident_capacity_entries".to_string(),
            });
        }
        if self.ghost_queue_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "ghost_queue_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicyMetrics {
    pub policy_name: String,
    pub total_accesses: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub ghost_hit_count: u64,
    pub eviction_count: u64,
    pub promotion_count: u64,
    pub requeue_count: u64,
    pub hit_rate_millionths: u32,
    pub hot_retention_millionths: u32,
    pub scan_pollution_millionths: u32,
    pub final_resident_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicyCaseReport {
    pub trace_id: String,
    pub workload_class: String,
    pub baseline: CachePolicyMetrics,
    pub candidate: CachePolicyMetrics,
    pub hit_rate_delta_millionths: i64,
    pub hot_retention_delta_millionths: i64,
    pub scan_pollution_delta_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicyAggregateSummary {
    pub total_cases: u64,
    pub improved_hit_rate_cases: u64,
    pub improved_hot_retention_cases: u64,
    pub reduced_scan_pollution_cases: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoAdoptionWedgeContract {
    pub schema_version: String,
    pub incumbent_policy_name: String,
    pub replaced_surfaces: Vec<String>,
    pub untouched_surfaces: Vec<String>,
    pub win_metrics: Vec<String>,
    pub rollback_criteria: Vec<String>,
}

impl Default for S3FifoAdoptionWedgeContract {
    fn default() -> Self {
        Self {
            schema_version: S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION.to_string(),
            incumbent_policy_name: CachePolicyKind::SingleQueueFifo.as_str().to_string(),
            replaced_surfaces: vec![
                "bounded cache residency comparator".to_string(),
                "future persistent cache admission policy".to_string(),
                "future AOT artifact cache admission policy".to_string(),
            ],
            untouched_surfaces: vec![
                "module invalidation semantics".to_string(),
                "trust revocation semantics".to_string(),
                "snapshot fastpath readers".to_string(),
            ],
            win_metrics: vec![
                "hit_rate_millionths".to_string(),
                "hot_retention_millionths".to_string(),
                "scan_pollution_millionths".to_string(),
            ],
            rollback_criteria: vec![
                "candidate hit rate falls below baseline".to_string(),
                "scan pollution does not improve".to_string(),
                "ghost hit accounting is missing".to_string(),
            ],
        }
    }
}

impl S3FifoAdoptionWedgeContract {
    pub fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.schema_version != S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "schema_version",
                detail: format!(
                    "expected `{}`, got `{}`",
                    S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION, self.schema_version
                ),
            });
        }
        if self.incumbent_policy_name != CachePolicyKind::SingleQueueFifo.as_str() {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "incumbent_policy_name",
                detail: format!(
                    "expected `{}`, got `{}`",
                    CachePolicyKind::SingleQueueFifo.as_str(),
                    self.incumbent_policy_name
                ),
            });
        }
        if self.replaced_surfaces.is_empty() {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "replaced_surfaces",
                detail: "must contain at least one replaced surface".to_string(),
            });
        }
        if self.untouched_surfaces.is_empty() {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "untouched_surfaces",
                detail: "must contain at least one untouched surface".to_string(),
            });
        }
        if self.win_metrics.is_empty() {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "win_metrics",
                detail: "must contain at least one win metric".to_string(),
            });
        }
        if self.rollback_criteria.is_empty() {
            return Err(CachePolicyReportError::InvalidAdoptionWedge {
                field: "rollback_criteria",
                detail: "must contain at least one rollback criterion".to_string(),
            });
        }

        for (field, values) in [
            ("replaced_surfaces", &self.replaced_surfaces),
            ("untouched_surfaces", &self.untouched_surfaces),
            ("win_metrics", &self.win_metrics),
            ("rollback_criteria", &self.rollback_criteria),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                return Err(CachePolicyReportError::InvalidAdoptionWedge {
                    field,
                    detail: "must not contain empty strings".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicyBaselineReport {
    pub schema_version: String,
    pub corpus_id: String,
    pub corpus_hash: ContentHash,
    pub baseline_policy_name: String,
    pub candidate_policy_name: String,
    pub adoption_wedge: S3FifoAdoptionWedgeContract,
    pub cases: Vec<CachePolicyCaseReport>,
    pub aggregate: CachePolicyAggregateSummary,
}

impl CachePolicyBaselineReport {
    pub fn validate(
        &self,
        manifest: &CacheTraceCorpusManifest,
    ) -> Result<(), CachePolicyReportError> {
        manifest.validate()?;
        if self.schema_version != CACHE_POLICY_BASELINE_SCHEMA_VERSION {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "schema_version",
                detail: format!(
                    "expected `{}`, got `{}`",
                    CACHE_POLICY_BASELINE_SCHEMA_VERSION, self.schema_version
                ),
            });
        }
        if self.corpus_id != manifest.corpus_id {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "corpus_id",
                detail: format!(
                    "expected `{}`, got `{}`",
                    manifest.corpus_id, self.corpus_id
                ),
            });
        }
        if self.corpus_hash != manifest.corpus_hash {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "corpus_hash",
                detail: format!(
                    "expected `{}`, got `{}`",
                    manifest.corpus_hash.to_hex(),
                    self.corpus_hash.to_hex(),
                ),
            });
        }
        if self.baseline_policy_name != CachePolicyKind::SingleQueueFifo.as_str() {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "baseline_policy_name",
                detail: format!(
                    "expected `{}`, got `{}`",
                    CachePolicyKind::SingleQueueFifo.as_str(),
                    self.baseline_policy_name
                ),
            });
        }
        if self.candidate_policy_name != CachePolicyKind::S3Fifo.as_str() {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "candidate_policy_name",
                detail: format!(
                    "expected `{}`, got `{}`",
                    CachePolicyKind::S3Fifo.as_str(),
                    self.candidate_policy_name
                ),
            });
        }
        self.adoption_wedge.validate()?;
        if self.cases.len() != manifest.cases.len() {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "cases",
                detail: format!(
                    "expected {} case reports, got {}",
                    manifest.cases.len(),
                    self.cases.len()
                ),
            });
        }
        if self.aggregate.total_cases != self.cases.len() as u64 {
            return Err(CachePolicyReportError::InvalidBaselineReport {
                field: "aggregate.total_cases",
                detail: format!(
                    "expected {}, got {}",
                    self.cases.len(),
                    self.aggregate.total_cases
                ),
            });
        }

        for (index, (report_case, manifest_case)) in
            self.cases.iter().zip(&manifest.cases).enumerate()
        {
            if report_case.trace_id != manifest_case.trace_id {
                return Err(CachePolicyReportError::InvalidBaselineReport {
                    field: "cases.trace_id",
                    detail: format!(
                        "case {index} expected `{}`, got `{}`",
                        manifest_case.trace_id, report_case.trace_id
                    ),
                });
            }
            if report_case.workload_class != manifest_case.workload_class.as_str() {
                return Err(CachePolicyReportError::InvalidBaselineReport {
                    field: "cases.workload_class",
                    detail: format!(
                        "case {index} expected `{}`, got `{}`",
                        manifest_case.workload_class.as_str(),
                        report_case.workload_class
                    ),
                });
            }
            if report_case.baseline.policy_name != self.baseline_policy_name {
                return Err(CachePolicyReportError::InvalidBaselineReport {
                    field: "cases.baseline.policy_name",
                    detail: format!(
                        "case {index} expected `{}`, got `{}`",
                        self.baseline_policy_name, report_case.baseline.policy_name
                    ),
                });
            }
            if report_case.candidate.policy_name != self.candidate_policy_name {
                return Err(CachePolicyReportError::InvalidBaselineReport {
                    field: "cases.candidate.policy_name",
                    detail: format!(
                        "case {index} expected `{}`, got `{}`",
                        self.candidate_policy_name, report_case.candidate.policy_name
                    ),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CachePolicyReportError {
    EmptyCorpusId,
    EmptyCorpusCases,
    DuplicateTraceId {
        trace_id: String,
    },
    EmptyTraceId,
    EmptyTrace {
        trace_id: String,
    },
    NonMonotonicTraceSequence {
        trace_id: String,
        previous: u64,
        actual: u64,
    },
    EmptyModuleIdInTrace {
        trace_id: String,
        sequence: u64,
    },
    InvalidSchemaVersion {
        expected: String,
        actual: String,
    },
    CorpusHashMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
    InvalidConfig {
        field: &'static str,
        detail: String,
    },
    InvalidAdoptionWedge {
        field: &'static str,
        detail: String,
    },
    InvalidBaselineReport {
        field: &'static str,
        detail: String,
    },
}

impl fmt::Display for CachePolicyReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpusId => f.write_str("cache trace corpus id must not be empty"),
            Self::EmptyCorpusCases => {
                f.write_str("cache trace corpus must contain at least one case")
            }
            Self::DuplicateTraceId { trace_id } => {
                write!(
                    f,
                    "cache trace corpus contains duplicate trace id `{trace_id}`"
                )
            }
            Self::EmptyTraceId => f.write_str("cache trace id must not be empty"),
            Self::EmptyTrace { trace_id } => {
                write!(
                    f,
                    "cache trace `{trace_id}` must contain at least one access"
                )
            }
            Self::NonMonotonicTraceSequence {
                trace_id,
                previous,
                actual,
            } => write!(
                f,
                "cache trace `{trace_id}` contains non-monotonic sequence numbers ({previous} then {actual})"
            ),
            Self::EmptyModuleIdInTrace { trace_id, sequence } => write!(
                f,
                "cache trace `{trace_id}` contains empty module_id at sequence {sequence}"
            ),
            Self::InvalidSchemaVersion { expected, actual } => write!(
                f,
                "cache trace corpus schema mismatch (expected `{expected}`, got `{actual}`)"
            ),
            Self::CorpusHashMismatch { expected, actual } => write!(
                f,
                "cache trace corpus hash mismatch (expected `{}`, got `{}`)",
                expected.to_hex(),
                actual.to_hex(),
            ),
            Self::InvalidConfig { field, detail } => {
                write!(f, "invalid cache policy config `{field}`: {detail}")
            }
            Self::InvalidAdoptionWedge { field, detail } => {
                write!(f, "invalid S3-FIFO adoption wedge `{field}`: {detail}")
            }
            Self::InvalidBaselineReport { field, detail } => {
                write!(
                    f,
                    "invalid cache policy baseline report `{field}`: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for CachePolicyReportError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineComparatorContractFixture {
    pub schema_version: String,
    pub bead_id: String,
    pub required_artifacts: Vec<String>,
    pub baseline_policy_name: String,
    pub candidate_policy_name: String,
    pub workload_classes: Vec<String>,
    pub trace_ids: Vec<String>,
    pub win_metrics: Vec<String>,
    pub replaced_surfaces: Vec<String>,
    pub untouched_surfaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineArtifactContext {
    pub artifact_dir: PathBuf,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl S3FifoBaselineArtifactContext {
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            run_id: format!(
                "run-{}-{}",
                S3FIFO_BASELINE_COMPONENT,
                Utc::now().format("%Y%m%dT%H%M%SZ")
            ),
            trace_id: "trace.rgc.620a".to_string(),
            decision_id: "decision.rgc.620a".to_string(),
            policy_id: "policy.rgc.620a".to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN")
                .unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_s3fifo_baseline_comparator -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineArtifactReference {
    pub path: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineArtifactManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub artifacts: Vec<S3FifoBaselineArtifactReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineEnvironmentArtifact {
    pub schema_version: String,
    pub toolchain: String,
    pub os: String,
    pub arch: String,
    pub generated_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineReproLock {
    pub schema_version: String,
    pub bead_id: String,
    pub git_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
    pub expected_outputs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineRunManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub corpus_id: String,
    pub corpus_hash: ContentHash,
    pub baseline_config: SingleQueueFifoConfig,
    pub candidate_config: S3FifoConfig,
    pub baseline_policy_name: String,
    pub candidate_policy_name: String,
    pub case_count: usize,
    pub aggregate: CachePolicyAggregateSummary,
    pub required_artifacts: Vec<String>,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineTraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoBaselineBundleWriteReport {
    pub artifact_dir: PathBuf,
    pub manifest: CacheTraceCorpusManifest,
    pub report: CachePolicyBaselineReport,
    pub adoption_wedge: S3FifoAdoptionWedgeContract,
    pub run_manifest_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct S3FifoBaselineEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    workload_class: Option<String>,
    detail: String,
}

pub fn default_s3fifo_trace_corpus_manifest()
-> Result<CacheTraceCorpusManifest, CachePolicyReportError> {
    CacheTraceCorpusManifest::new(
        "corpus.s3fifo.baseline",
        vec![
            CacheTraceCase {
                trace_id: "trace.cache.cold_compile".to_string(),
                workload_class: CacheWorkloadClass::ColdCompile,
                accesses: vec![
                    default_trace_access(
                        1,
                        "mod:entry",
                        "cold-entry",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        2,
                        "mod:resolver",
                        "cold-resolver",
                        1,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        3,
                        "mod:parser",
                        "cold-parser",
                        1,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        4,
                        "mod:entry",
                        "cold-entry",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        5,
                        "mod:optimizer",
                        "cold-opt",
                        1,
                        1,
                        CacheLocalityClass::Scan,
                    ),
                    default_trace_access(
                        6,
                        "mod:entry",
                        "cold-entry",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                ],
            },
            CacheTraceCase {
                trace_id: "trace.cache.warm_run".to_string(),
                workload_class: CacheWorkloadClass::WarmRun,
                accesses: vec![
                    default_trace_access(
                        1,
                        "mod:router",
                        "warm-router",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        2,
                        "mod:router",
                        "warm-router",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        3,
                        "mod:bundle",
                        "warm-bundle",
                        1,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        4,
                        "mod:router",
                        "warm-router",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        5,
                        "mod:bundle",
                        "warm-bundle",
                        1,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        6,
                        "mod:router",
                        "warm-router",
                        1,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                ],
            },
            CacheTraceCase {
                trace_id: "trace.cache.package_graph".to_string(),
                workload_class: CacheWorkloadClass::PackageGraph,
                accesses: vec![
                    default_trace_access(1, "pkg:a", "pkg-a", 2, 1, CacheLocalityClass::Warm),
                    default_trace_access(2, "pkg:b", "pkg-b", 2, 1, CacheLocalityClass::Warm),
                    default_trace_access(3, "pkg:c", "pkg-c", 2, 1, CacheLocalityClass::Warm),
                    default_trace_access(4, "pkg:a", "pkg-a", 2, 1, CacheLocalityClass::Warm),
                    default_trace_access(5, "pkg:d", "pkg-d", 2, 1, CacheLocalityClass::Scan),
                    default_trace_access(6, "pkg:b", "pkg-b", 2, 1, CacheLocalityClass::Warm),
                    default_trace_access(7, "pkg:e", "pkg-e", 2, 1, CacheLocalityClass::Scan),
                ],
            },
            CacheTraceCase {
                trace_id: "trace.cache.react_app".to_string(),
                workload_class: CacheWorkloadClass::ReactApp,
                accesses: vec![
                    default_trace_access(
                        1,
                        "react:entry",
                        "react-entry",
                        3,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        2,
                        "react:route",
                        "react-route",
                        3,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        3,
                        "react:client-shell",
                        "react-shell",
                        3,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        4,
                        "react:entry",
                        "react-entry",
                        3,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        5,
                        "react:ssr-pass",
                        "react-ssr",
                        3,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                    default_trace_access(
                        6,
                        "react:asset-scan",
                        "react-asset",
                        3,
                        1,
                        CacheLocalityClass::Scan,
                    ),
                    default_trace_access(
                        7,
                        "react:route",
                        "react-route",
                        3,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        8,
                        "react:client-shell",
                        "react-shell",
                        3,
                        1,
                        CacheLocalityClass::Warm,
                    ),
                ],
            },
            CacheTraceCase {
                trace_id: "trace.cache.scan_heavy".to_string(),
                workload_class: CacheWorkloadClass::ScanHeavy,
                accesses: vec![
                    default_trace_access(
                        1,
                        "scan:hot-a",
                        "scan-hot-a",
                        4,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        2,
                        "scan:hot-b",
                        "scan-hot-b",
                        4,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        3,
                        "scan:catalog-1",
                        "scan-cat-1",
                        4,
                        1,
                        CacheLocalityClass::Scan,
                    ),
                    default_trace_access(
                        4,
                        "scan:catalog-2",
                        "scan-cat-2",
                        4,
                        1,
                        CacheLocalityClass::Scan,
                    ),
                    default_trace_access(
                        5,
                        "scan:catalog-3",
                        "scan-cat-3",
                        4,
                        1,
                        CacheLocalityClass::Scan,
                    ),
                    default_trace_access(
                        6,
                        "scan:hot-a",
                        "scan-hot-a",
                        4,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                    default_trace_access(
                        7,
                        "scan:hot-b",
                        "scan-hot-b",
                        4,
                        1,
                        CacheLocalityClass::Hot,
                    ),
                ],
            },
        ],
    )
}

pub fn default_s3fifo_baseline_config() -> SingleQueueFifoConfig {
    SingleQueueFifoConfig {
        capacity_entries: 4,
    }
}

pub fn default_s3fifo_candidate_config() -> S3FifoConfig {
    S3FifoConfig {
        resident_capacity_entries: 4,
        small_queue_entries: 2,
        ghost_queue_entries: 4,
    }
}

pub fn default_s3fifo_baseline_report() -> Result<CachePolicyBaselineReport, CachePolicyReportError>
{
    let manifest = default_s3fifo_trace_corpus_manifest()?;
    evaluate_s3fifo_baseline(
        &manifest,
        &default_s3fifo_baseline_config(),
        &default_s3fifo_candidate_config(),
        &S3FifoAdoptionWedgeContract::default(),
    )
}

pub fn default_s3fifo_baseline_contract_fixture() -> S3FifoBaselineComparatorContractFixture {
    let manifest =
        default_s3fifo_trace_corpus_manifest().expect("default S3-FIFO corpus should be valid");
    let adoption_wedge = S3FifoAdoptionWedgeContract::default();
    S3FifoBaselineComparatorContractFixture {
        schema_version: S3FIFO_BASELINE_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: S3FIFO_BASELINE_BEAD_ID.to_string(),
        required_artifacts: s3fifo_required_artifact_names(),
        baseline_policy_name: CachePolicyKind::SingleQueueFifo.as_str().to_string(),
        candidate_policy_name: CachePolicyKind::S3Fifo.as_str().to_string(),
        workload_classes: manifest
            .cases
            .iter()
            .map(|case| case.workload_class.as_str().to_string())
            .collect(),
        trace_ids: manifest
            .cases
            .iter()
            .map(|case| case.trace_id.clone())
            .collect(),
        win_metrics: adoption_wedge.win_metrics.clone(),
        replaced_surfaces: adoption_wedge.replaced_surfaces.clone(),
        untouched_surfaces: adoption_wedge.untouched_surfaces.clone(),
    }
}

pub fn render_s3fifo_baseline_summary(report: &CachePolicyBaselineReport) -> String {
    let mut lines = vec![
        "# S3-FIFO Baseline Comparator Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", S3FIFO_BASELINE_BEAD_ID),
        format!("- corpus_id: `{}`", report.corpus_id),
        format!("- corpus_hash: `{}`", report.corpus_hash.to_hex()),
        format!("- baseline_policy: `{}`", report.baseline_policy_name),
        format!("- candidate_policy: `{}`", report.candidate_policy_name),
        format!("- cases: `{}`", report.aggregate.total_cases),
        format!(
            "- improved_hit_rate_cases: `{}`",
            report.aggregate.improved_hit_rate_cases
        ),
        format!(
            "- improved_hot_retention_cases: `{}`",
            report.aggregate.improved_hot_retention_cases
        ),
        format!(
            "- reduced_scan_pollution_cases: `{}`",
            report.aggregate.reduced_scan_pollution_cases
        ),
        String::new(),
        "## Case Deltas".to_string(),
    ];

    lines.extend(report.cases.iter().map(|case| {
        format!(
            "- `{}` ({}) hit_rate_delta={} hot_retention_delta={} scan_pollution_delta={}",
            case.trace_id,
            case.workload_class,
            case.hit_rate_delta_millionths,
            case.hot_retention_delta_millionths,
            case.scan_pollution_delta_millionths,
        )
    }));
    lines.push(String::new());
    lines.push("## Adoption Wedge".to_string());
    lines.push(format!(
        "- replaced_surfaces: {}",
        report.adoption_wedge.replaced_surfaces.join(", ")
    ));
    lines.push(format!(
        "- untouched_surfaces: {}",
        report.adoption_wedge.untouched_surfaces.join(", ")
    ));
    lines.push(format!(
        "- win_metrics: {}",
        report.adoption_wedge.win_metrics.join(", ")
    ));
    lines.join("\n")
}

pub fn emit_default_s3fifo_baseline_bundle(
    context: &S3FifoBaselineArtifactContext,
) -> io::Result<S3FifoBaselineBundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let manifest = default_s3fifo_trace_corpus_manifest()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let baseline_config = default_s3fifo_baseline_config();
    let candidate_config = default_s3fifo_candidate_config();
    let adoption_wedge = S3FifoAdoptionWedgeContract::default();
    let report = evaluate_s3fifo_baseline(
        &manifest,
        &baseline_config,
        &candidate_config,
        &adoption_wedge,
    )
    .map_err(report_to_io_error)?;
    let summary = render_s3fifo_baseline_summary(&report);

    let trace_ids = S3FifoBaselineTraceIdsArtifact {
        schema_version: S3FIFO_BASELINE_TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: manifest
            .cases
            .iter()
            .map(|case| case.trace_id.clone())
            .collect(),
        decision_ids: vec![context.decision_id.clone()],
        policy_ids: vec![context.policy_id.clone()],
    };
    let environment = S3FifoBaselineEnvironmentArtifact {
        schema_version: S3FIFO_BASELINE_ENV_SCHEMA_VERSION.to_string(),
        toolchain: context.toolchain.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
    };
    let events = build_s3fifo_baseline_events(context, &report);
    let commands = format!("{}\n", context.command_invocation);

    let manifest_bytes = json_bytes(&manifest)?;
    let report_bytes = json_bytes(&report)?;
    let adoption_wedge_bytes = json_bytes(&adoption_wedge)?;
    let trace_ids_bytes = json_bytes(&trace_ids)?;
    let env_bytes = json_bytes(&environment)?;
    let events_bytes = jsonl_bytes(&events)?;
    let commands_bytes = commands.into_bytes();
    let summary_bytes = text_bytes(&summary);

    let mut artifact_hashes = BTreeMap::new();
    artifact_hashes.insert(
        "cache_trace_corpus_manifest.json".to_string(),
        content_hash_hex(&manifest_bytes),
    );
    artifact_hashes.insert(
        "cache_policy_baseline_report.json".to_string(),
        content_hash_hex(&report_bytes),
    );
    artifact_hashes.insert(
        "s3fifo_adoption_wedge_contract.json".to_string(),
        content_hash_hex(&adoption_wedge_bytes),
    );
    artifact_hashes.insert(
        "trace_ids.json".to_string(),
        content_hash_hex(&trace_ids_bytes),
    );
    artifact_hashes.insert("env.json".to_string(), content_hash_hex(&env_bytes));
    artifact_hashes.insert("events.jsonl".to_string(), content_hash_hex(&events_bytes));
    artifact_hashes.insert(
        "commands.txt".to_string(),
        content_hash_hex(&commands_bytes),
    );
    artifact_hashes.insert("summary.md".to_string(), content_hash_hex(&summary_bytes));

    let run_manifest = S3FifoBaselineRunManifest {
        schema_version: S3FIFO_BASELINE_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: S3FIFO_BASELINE_BEAD_ID.to_string(),
        component: S3FIFO_BASELINE_COMPONENT.to_string(),
        run_id: context.run_id.clone(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        generated_at_utc: context.generated_at_utc.clone(),
        source_commit: context.source_commit.clone(),
        toolchain: context.toolchain.clone(),
        corpus_id: manifest.corpus_id.clone(),
        corpus_hash: manifest.corpus_hash,
        baseline_config,
        candidate_config,
        baseline_policy_name: report.baseline_policy_name.clone(),
        candidate_policy_name: report.candidate_policy_name.clone(),
        case_count: report.cases.len(),
        aggregate: report.aggregate.clone(),
        required_artifacts: s3fifo_required_artifact_names(),
        artifact_hashes: artifact_hashes.clone(),
    };
    let run_manifest_bytes = json_bytes(&run_manifest)?;
    artifact_hashes.insert(
        "run_manifest.json".to_string(),
        content_hash_hex(&run_manifest_bytes),
    );

    let repro_lock = S3FifoBaselineReproLock {
        schema_version: S3FIFO_BASELINE_REPRO_LOCK_SCHEMA_VERSION.to_string(),
        bead_id: S3FIFO_BASELINE_BEAD_ID.to_string(),
        git_commit: context.source_commit.clone(),
        toolchain: context.toolchain.clone(),
        command_invocation: context.command_invocation.clone(),
        expected_outputs: s3fifo_required_artifact_names(),
    };
    let repro_lock_bytes = json_bytes(&repro_lock)?;
    artifact_hashes.insert(
        "repro.lock".to_string(),
        content_hash_hex(&repro_lock_bytes),
    );

    let artifact_manifest = S3FifoBaselineArtifactManifest {
        schema_version: S3FIFO_BASELINE_ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: S3FIFO_BASELINE_BEAD_ID.to_string(),
        component: S3FIFO_BASELINE_COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        artifacts: artifact_hashes
            .iter()
            .map(|(path, content_hash)| S3FifoBaselineArtifactReference {
                path: path.clone(),
                content_hash: content_hash.to_string(),
            })
            .collect(),
    };
    let artifact_manifest_bytes = json_bytes(&artifact_manifest)?;
    artifact_hashes.insert(
        "manifest.json".to_string(),
        content_hash_hex(&artifact_manifest_bytes),
    );

    let files = [
        ("cache_trace_corpus_manifest.json", manifest_bytes),
        ("cache_policy_baseline_report.json", report_bytes),
        ("s3fifo_adoption_wedge_contract.json", adoption_wedge_bytes),
        ("trace_ids.json", trace_ids_bytes),
        ("env.json", env_bytes),
        ("events.jsonl", events_bytes),
        ("commands.txt", commands_bytes),
        ("summary.md", summary_bytes),
        ("run_manifest.json", run_manifest_bytes),
        ("repro.lock", repro_lock_bytes),
        ("manifest.json", artifact_manifest_bytes),
    ];

    for (relative_path, bytes) in files {
        fs::write(context.artifact_dir.join(relative_path), bytes)?;
    }

    Ok(S3FifoBaselineBundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        manifest,
        report,
        adoption_wedge,
        run_manifest_path: context.artifact_dir.join("run_manifest.json"),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files: artifact_hashes,
    })
}

fn default_trace_access(
    sequence: u64,
    module_id: &str,
    source_seed: &str,
    policy_version: u64,
    trust_revision: u64,
    locality: CacheLocalityClass,
) -> CacheTraceAccess {
    CacheTraceAccess {
        sequence,
        key: ModuleCacheKey::new(
            module_id,
            ModuleVersionFingerprint::new(
                ContentHash::compute(source_seed.as_bytes()),
                policy_version,
                trust_revision,
            ),
        ),
        locality,
    }
}

fn s3fifo_required_artifact_names() -> Vec<String> {
    [
        "cache_trace_corpus_manifest.json",
        "cache_policy_baseline_report.json",
        "s3fifo_adoption_wedge_contract.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "env.json",
        "manifest.json",
        "repro.lock",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn build_s3fifo_baseline_events(
    context: &S3FifoBaselineArtifactContext,
    report: &CachePolicyBaselineReport,
) -> Vec<S3FifoBaselineEvent> {
    let mut events = report
        .cases
        .iter()
        .map(|case| S3FifoBaselineEvent {
            schema_version: S3FIFO_BASELINE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: S3FIFO_BASELINE_COMPONENT.to_string(),
            event: "baseline_case_evaluated".to_string(),
            outcome: if case.hit_rate_delta_millionths > 0 {
                "candidate_improves_hit_rate".to_string()
            } else if case.hit_rate_delta_millionths < 0 {
                "candidate_regresses_hit_rate".to_string()
            } else {
                "candidate_ties_hit_rate".to_string()
            },
            workload_class: Some(case.workload_class.clone()),
            detail: format!(
                "{}: hit_rate_delta={} hot_retention_delta={} scan_pollution_delta={}",
                case.trace_id,
                case.hit_rate_delta_millionths,
                case.hot_retention_delta_millionths,
                case.scan_pollution_delta_millionths,
            ),
        })
        .collect::<Vec<_>>();

    events.push(S3FifoBaselineEvent {
        schema_version: S3FIFO_BASELINE_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: S3FIFO_BASELINE_COMPONENT.to_string(),
        event: "bundle_published".to_string(),
        outcome: "pass".to_string(),
        workload_class: None,
        detail: format!(
            "published {} comparator artifacts for corpus `{}`",
            s3fifo_required_artifact_names().len(),
            report.corpus_id
        ),
    });
    events
}

fn json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(report_to_io_error)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn jsonl_bytes<T: Serialize>(records: &[T]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend(serde_json::to_vec(record).map_err(report_to_io_error)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn text_bytes(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes
}

fn content_hash_hex(bytes: &[u8]) -> String {
    ContentHash::compute(bytes).to_hex()
}

fn report_to_io_error(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePolicyEntry {
    label: String,
    hot: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CachePolicyCounters {
    hit_count: u64,
    miss_count: u64,
    ghost_hit_count: u64,
    eviction_count: u64,
    promotion_count: u64,
    requeue_count: u64,
}

#[derive(Debug, Default)]
struct S3FifoQueues {
    small: VecDeque<CachePolicyEntry>,
    main: VecDeque<CachePolicyEntry>,
    ghost: VecDeque<String>,
}

pub fn evaluate_s3fifo_baseline(
    manifest: &CacheTraceCorpusManifest,
    baseline_config: &SingleQueueFifoConfig,
    candidate_config: &S3FifoConfig,
    adoption_wedge: &S3FifoAdoptionWedgeContract,
) -> Result<CachePolicyBaselineReport, CachePolicyReportError> {
    manifest.validate()?;
    baseline_config.validate()?;
    candidate_config.validate()?;
    adoption_wedge.validate()?;

    let mut cases = Vec::with_capacity(manifest.cases.len());
    let mut aggregate = CachePolicyAggregateSummary {
        total_cases: manifest.cases.len() as u64,
        improved_hit_rate_cases: 0,
        improved_hot_retention_cases: 0,
        reduced_scan_pollution_cases: 0,
    };

    for case in &manifest.cases {
        let baseline = simulate_single_queue_fifo(case, baseline_config);
        let candidate = simulate_s3fifo(case, candidate_config);
        let hit_rate_delta_millionths =
            i64::from(candidate.hit_rate_millionths) - i64::from(baseline.hit_rate_millionths);
        let hot_retention_delta_millionths = i64::from(candidate.hot_retention_millionths)
            - i64::from(baseline.hot_retention_millionths);
        let scan_pollution_delta_millionths = i64::from(candidate.scan_pollution_millionths)
            - i64::from(baseline.scan_pollution_millionths);

        if hit_rate_delta_millionths > 0 {
            aggregate.improved_hit_rate_cases += 1;
        }
        if hot_retention_delta_millionths > 0 {
            aggregate.improved_hot_retention_cases += 1;
        }
        if scan_pollution_delta_millionths < 0 {
            aggregate.reduced_scan_pollution_cases += 1;
        }

        cases.push(CachePolicyCaseReport {
            trace_id: case.trace_id.clone(),
            workload_class: case.workload_class.as_str().to_string(),
            baseline,
            candidate,
            hit_rate_delta_millionths,
            hot_retention_delta_millionths,
            scan_pollution_delta_millionths,
        });
    }

    let report = CachePolicyBaselineReport {
        schema_version: CACHE_POLICY_BASELINE_SCHEMA_VERSION.to_string(),
        corpus_id: manifest.corpus_id.clone(),
        corpus_hash: manifest.corpus_hash,
        baseline_policy_name: CachePolicyKind::SingleQueueFifo.as_str().to_string(),
        candidate_policy_name: CachePolicyKind::S3Fifo.as_str().to_string(),
        adoption_wedge: adoption_wedge.clone(),
        cases,
        aggregate,
    };
    report.validate(manifest)?;
    Ok(report)
}

fn compute_cache_trace_corpus_hash(corpus_id: &str, cases: &[CacheTraceCase]) -> ContentHash {
    let mut map = BTreeMap::new();
    map.insert(
        "schema_version".to_string(),
        CanonicalValue::String(CACHE_TRACE_CORPUS_SCHEMA_VERSION.to_string()),
    );
    map.insert(
        "corpus_id".to_string(),
        CanonicalValue::String(corpus_id.to_string()),
    );
    map.insert(
        "cases".to_string(),
        CanonicalValue::Array(cases.iter().map(CacheTraceCase::canonical_value).collect()),
    );
    ContentHash::compute(&encode_value(&CanonicalValue::Map(map)))
}

fn simulate_single_queue_fifo(
    case: &CacheTraceCase,
    config: &SingleQueueFifoConfig,
) -> CachePolicyMetrics {
    let mut queue = VecDeque::new();
    let mut resident = BTreeSet::new();
    let mut counters = CachePolicyCounters::default();

    for access in &case.accesses {
        let label = cache_trace_label(&access.key);
        if resident.contains(&label) {
            counters.hit_count += 1;
            continue;
        }

        counters.miss_count += 1;
        if resident.len() >= config.capacity_entries
            && let Some(evicted) = queue.pop_front()
        {
            resident.remove(&evicted);
            counters.eviction_count += 1;
        }
        queue.push_back(label.clone());
        resident.insert(label);
    }

    build_policy_metrics(
        CachePolicyKind::SingleQueueFifo,
        case,
        counters,
        queue.into_iter().collect(),
    )
}

fn simulate_s3fifo(case: &CacheTraceCase, config: &S3FifoConfig) -> CachePolicyMetrics {
    let mut queues = S3FifoQueues::default();
    let mut counters = CachePolicyCounters::default();

    for access in &case.accesses {
        let label = cache_trace_label(&access.key);

        if let Some(entry) = find_entry_mut(&mut queues.small, &label) {
            counters.hit_count += 1;
            entry.hot = true;
            continue;
        }
        if let Some(entry) = find_entry_mut(&mut queues.main, &label) {
            counters.hit_count += 1;
            entry.hot = true;
            continue;
        }

        counters.miss_count += 1;
        if remove_label(&mut queues.ghost, &label) {
            counters.ghost_hit_count += 1;
            insert_main_entry(
                CachePolicyEntry { label, hot: false },
                &mut queues,
                config,
                &mut counters,
            );
        } else {
            insert_small_entry(
                CachePolicyEntry { label, hot: false },
                &mut queues,
                config,
                &mut counters,
            );
        }
    }

    let final_resident_keys = queues
        .small
        .iter()
        .chain(queues.main.iter())
        .map(|entry| entry.label.clone())
        .collect::<Vec<_>>();

    build_policy_metrics(CachePolicyKind::S3Fifo, case, counters, final_resident_keys)
}

fn insert_small_entry(
    entry: CachePolicyEntry,
    queues: &mut S3FifoQueues,
    config: &S3FifoConfig,
    counters: &mut CachePolicyCounters,
) {
    while queues.small.len() >= config.small_queue_entries {
        if let Some(evicted) = queues.small.pop_front() {
            if evicted.hot {
                counters.promotion_count += 1;
                insert_main_entry(
                    CachePolicyEntry {
                        label: evicted.label,
                        hot: false,
                    },
                    queues,
                    config,
                    counters,
                );
            } else {
                counters.eviction_count += 1;
                push_ghost(
                    &evicted.label,
                    &mut queues.ghost,
                    config.ghost_queue_entries,
                );
            }
        }
    }
    queues.small.push_back(entry);
}

fn insert_main_entry(
    entry: CachePolicyEntry,
    queues: &mut S3FifoQueues,
    config: &S3FifoConfig,
    counters: &mut CachePolicyCounters,
) {
    let main_capacity = config.main_queue_entries();
    while queues.main.len() >= main_capacity {
        make_room_in_main(queues, config.ghost_queue_entries, counters);
    }
    queues.main.push_back(entry);
}

fn make_room_in_main(
    queues: &mut S3FifoQueues,
    ghost_capacity: usize,
    counters: &mut CachePolicyCounters,
) {
    let mut attempts = queues.main.len();
    while attempts > 0 {
        let Some(mut candidate) = queues.main.pop_front() else {
            return;
        };

        if candidate.hot {
            candidate.hot = false;
            queues.main.push_back(candidate);
            counters.requeue_count += 1;
            attempts -= 1;
            continue;
        }

        counters.eviction_count += 1;
        push_ghost(&candidate.label, &mut queues.ghost, ghost_capacity);
        return;
    }

    if let Some(candidate) = queues.main.pop_front() {
        counters.eviction_count += 1;
        push_ghost(&candidate.label, &mut queues.ghost, ghost_capacity);
    }
}

fn push_ghost(label: &str, ghost: &mut VecDeque<String>, ghost_capacity: usize) {
    remove_label(ghost, label);
    while ghost.len() >= ghost_capacity {
        ghost.pop_front();
    }
    ghost.push_back(label.to_string());
}

fn find_entry_mut<'a>(
    queue: &'a mut VecDeque<CachePolicyEntry>,
    label: &str,
) -> Option<&'a mut CachePolicyEntry> {
    queue.iter_mut().find(|entry| entry.label == label)
}

fn remove_label(queue: &mut VecDeque<String>, label: &str) -> bool {
    let Some(index) = queue.iter().position(|value| value == label) else {
        return false;
    };
    queue.remove(index);
    true
}

fn build_policy_metrics(
    policy: CachePolicyKind,
    case: &CacheTraceCase,
    counters: CachePolicyCounters,
    final_resident_keys: Vec<String>,
) -> CachePolicyMetrics {
    let total_accesses = case.accesses.len() as u64;
    let hot_keys = case
        .accesses
        .iter()
        .filter(|access| access.locality == CacheLocalityClass::Hot)
        .map(|access| cache_trace_label(&access.key))
        .collect::<BTreeSet<_>>();
    let scan_keys = case
        .accesses
        .iter()
        .filter(|access| access.locality == CacheLocalityClass::Scan)
        .map(|access| cache_trace_label(&access.key))
        .collect::<BTreeSet<_>>();
    let resident = final_resident_keys.iter().cloned().collect::<BTreeSet<_>>();
    let retained_hot = resident.intersection(&hot_keys).count() as u64;
    let resident_scan = resident.intersection(&scan_keys).count() as u64;

    CachePolicyMetrics {
        policy_name: policy.as_str().to_string(),
        total_accesses,
        hit_count: counters.hit_count,
        miss_count: counters.miss_count,
        ghost_hit_count: counters.ghost_hit_count,
        eviction_count: counters.eviction_count,
        promotion_count: counters.promotion_count,
        requeue_count: counters.requeue_count,
        hit_rate_millionths: ratio_to_millionths(counters.hit_count, total_accesses),
        hot_retention_millionths: ratio_to_millionths(retained_hot, hot_keys.len() as u64),
        scan_pollution_millionths: ratio_to_millionths(resident_scan, resident.len() as u64),
        final_resident_keys,
    }
}

fn ratio_to_millionths(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    ((u128::from(numerator) * 1_000_000_u128) / u128::from(denominator)) as u32
}

fn cache_trace_label(key: &ModuleCacheKey) -> String {
    format!(
        "{}:{}:{}:{}",
        key.module_id,
        key.version.source_hash.to_hex(),
        key.version.policy_version,
        key.version.trust_revision
    )
}

// ---------------------------------------------------------------------------
// Adaptive S3-FIFO with value-aware admission (RGC-620B / bd-1lsy.7.20.2)
// ---------------------------------------------------------------------------

pub const S3FIFO_ADAPTIVE_SCHEMA_VERSION: &str = "franken-engine.s3fifo-adaptive.v1";
pub const S3FIFO_ADAPTIVE_BEAD_ID: &str = "bd-1lsy.7.20.2";

/// Configuration for adaptive queue split.
///
/// The adaptive split adjusts the small-queue fraction based on the observed
/// ghost-hit ratio. More ghost hits indicate entries are being evicted from the
/// small queue too early and should be given more room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveSplitConfig {
    /// Minimum small-queue fraction in millionths (0..1_000_000).
    pub min_small_fraction_millionths: u32,
    /// Maximum small-queue fraction in millionths (0..1_000_000).
    pub max_small_fraction_millionths: u32,
    /// Maximum absolute change in small-queue size per epoch.
    /// This bounds the adaptation rate for deterministic replay stability.
    pub max_step_per_epoch: usize,
    /// Number of accesses that constitute one adaptation epoch.
    pub epoch_length: u64,
}

impl Default for AdaptiveSplitConfig {
    fn default() -> Self {
        Self {
            min_small_fraction_millionths: 100_000, // 10%
            max_small_fraction_millionths: 500_000, // 50%
            max_step_per_epoch: 1,
            epoch_length: 16,
        }
    }
}

impl AdaptiveSplitConfig {
    fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.min_small_fraction_millionths >= self.max_small_fraction_millionths {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "min_small_fraction_millionths",
                detail: "must be less than max_small_fraction_millionths".to_string(),
            });
        }
        if self.max_small_fraction_millionths > 1_000_000 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "max_small_fraction_millionths",
                detail: "must be at most 1_000_000".to_string(),
            });
        }
        if self.epoch_length == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "epoch_length",
                detail: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Value-aware admission policy configuration.
///
/// Each cache entry carries an explicit value score (millionths of 1.0).
/// Admission is gated on the incoming entry's value exceeding a running
/// eviction-value threshold, preventing low-value entries from displacing
/// high-value residents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueAdmissionConfig {
    /// Initial admission threshold in value-millionths.
    pub initial_threshold_millionths: u32,
    /// Exponential moving-average weight for threshold updates (millionths).
    /// `new_threshold = (1 - alpha) * old + alpha * evicted_value`.
    pub alpha_millionths: u32,
    /// Floor value below which entries are never admitted.
    pub floor_value_millionths: u32,
}

impl Default for ValueAdmissionConfig {
    fn default() -> Self {
        Self {
            initial_threshold_millionths: 100_000, // 0.1
            alpha_millionths: 250_000,             // 0.25
            floor_value_millionths: 0,
        }
    }
}

impl ValueAdmissionConfig {
    fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.alpha_millionths > 1_000_000 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "alpha_millionths",
                detail: "must be at most 1_000_000".to_string(),
            });
        }
        Ok(())
    }
}

/// Full adaptive S3-FIFO configuration combining base queue sizes, adaptive
/// split, and value-aware admission under deterministic budgets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoAdaptiveConfig {
    /// Total resident capacity (small + main).
    pub resident_capacity_entries: usize,
    /// Initial small-queue size.
    pub initial_small_queue_entries: usize,
    /// Ghost queue capacity.
    pub ghost_queue_entries: usize,
    /// Adaptive split policy.
    pub adaptive_split: AdaptiveSplitConfig,
    /// Value-aware admission policy.
    pub value_admission: ValueAdmissionConfig,
}

impl Default for S3FifoAdaptiveConfig {
    fn default() -> Self {
        Self {
            resident_capacity_entries: 8,
            initial_small_queue_entries: 3,
            ghost_queue_entries: 8,
            adaptive_split: AdaptiveSplitConfig::default(),
            value_admission: ValueAdmissionConfig::default(),
        }
    }
}

impl S3FifoAdaptiveConfig {
    pub fn validate(&self) -> Result<(), CachePolicyReportError> {
        if self.resident_capacity_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "resident_capacity_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        if self.initial_small_queue_entries == 0
            || self.initial_small_queue_entries >= self.resident_capacity_entries
        {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "initial_small_queue_entries",
                detail: "must be in (0, resident_capacity_entries)".to_string(),
            });
        }
        if self.ghost_queue_entries == 0 {
            return Err(CachePolicyReportError::InvalidConfig {
                field: "ghost_queue_entries",
                detail: "must be greater than zero".to_string(),
            });
        }
        self.adaptive_split.validate()?;
        self.value_admission.validate()?;
        Ok(())
    }

    fn current_main_capacity(&self, current_small_capacity: usize) -> usize {
        self.resident_capacity_entries
            .saturating_sub(current_small_capacity)
    }
}

/// Mutable runtime state for the adaptive split.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdaptiveSplitState {
    current_small_capacity: usize,
    epoch_accesses: u64,
    epoch_ghost_hits: u64,
    epoch_misses: u64,
    adaptation_count: u64,
}

impl AdaptiveSplitState {
    fn new(initial_small: usize) -> Self {
        Self {
            current_small_capacity: initial_small,
            epoch_accesses: 0,
            epoch_ghost_hits: 0,
            epoch_misses: 0,
            adaptation_count: 0,
        }
    }
}

/// Mutable runtime state for value-aware admission.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueAdmissionState {
    /// Running threshold in millionths.
    threshold_millionths: u32,
    /// Count of entries denied admission due to low value.
    denied_count: u64,
    /// Count of entries admitted.
    admitted_count: u64,
}

impl ValueAdmissionState {
    fn new(initial_threshold: u32) -> Self {
        Self {
            threshold_millionths: initial_threshold,
            denied_count: 0,
            admitted_count: 0,
        }
    }
}

/// Cache entry annotated with an explicit value score.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueAnnotatedEntry {
    label: String,
    hot: bool,
    /// Value score in millionths of 1.0. Higher means more valuable.
    value_millionths: u32,
}

/// Record of an admission decision for replay and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionVerdict {
    pub sequence: u64,
    pub label: String,
    pub value_millionths: u32,
    pub threshold_millionths: u32,
    pub admitted: bool,
}

/// Extended counters for adaptive S3-FIFO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AdaptiveCachePolicyCounters {
    base: CachePolicyCounters,
    /// Number of adaptive split adjustments performed.
    adaptation_count: u64,
    /// Number of entries denied by value-aware admission.
    value_denied_count: u64,
    /// Number of entries admitted through value-aware admission.
    value_admitted_count: u64,
}

/// Extended metrics for adaptive S3-FIFO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3FifoAdaptiveMetrics {
    pub base: CachePolicyMetrics,
    /// Final small-queue capacity after adaptation.
    pub final_small_capacity: usize,
    /// Number of adaptive split adjustments.
    pub adaptation_count: u64,
    /// Number of admission denials due to value threshold.
    pub value_denied_count: u64,
    /// Number of admissions through value check.
    pub value_admitted_count: u64,
    /// Final admission threshold in millionths.
    pub final_threshold_millionths: u32,
    /// Deterministic admission verdicts for replay.
    pub admission_verdicts: Vec<AdmissionVerdict>,
}

/// Trace access extended with an explicit value score for value-aware admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueAnnotatedTraceAccess {
    pub sequence: u64,
    pub key: ModuleCacheKey,
    pub locality: CacheLocalityClass,
    /// Value score in millionths. Items with higher value should be preferentially retained.
    pub value_millionths: u32,
}

/// A workload trace with value annotations for adaptive S3-FIFO evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueAnnotatedTraceCase {
    pub trace_id: String,
    pub workload_class: CacheWorkloadClass,
    pub accesses: Vec<ValueAnnotatedTraceAccess>,
}

/// Queues for the adaptive S3-FIFO simulation with value annotations.
#[derive(Debug, Default)]
struct AdaptiveS3FifoQueues {
    small: VecDeque<ValueAnnotatedEntry>,
    main: VecDeque<ValueAnnotatedEntry>,
    ghost: VecDeque<String>,
}

/// Simulate the adaptive S3-FIFO policy with dynamic split and value-aware
/// admission under deterministic budgets.
///
/// Returns both the base-compatible `CachePolicyMetrics` (for comparison with
/// single-queue and static S3-FIFO) and the adaptive-specific metrics.
pub fn simulate_s3fifo_adaptive(
    case: &ValueAnnotatedTraceCase,
    config: &S3FifoAdaptiveConfig,
) -> S3FifoAdaptiveMetrics {
    let mut queues = AdaptiveS3FifoQueues::default();
    let mut counters = AdaptiveCachePolicyCounters::default();
    let mut split_state = AdaptiveSplitState::new(config.initial_small_queue_entries);
    let mut value_state =
        ValueAdmissionState::new(config.value_admission.initial_threshold_millionths);
    let mut verdicts = Vec::new();

    for access in &case.accesses {
        let label = cache_trace_label(&access.key);

        // Hit in small queue
        if let Some(entry) = find_value_entry_mut(&mut queues.small, &label) {
            counters.base.hit_count += 1;
            entry.hot = true;
            record_epoch_access(&mut split_state, false, false);
            maybe_adapt_split(&mut split_state, config);
            continue;
        }

        // Hit in main queue
        if let Some(entry) = find_value_entry_mut(&mut queues.main, &label) {
            counters.base.hit_count += 1;
            entry.hot = true;
            record_epoch_access(&mut split_state, false, false);
            maybe_adapt_split(&mut split_state, config);
            continue;
        }

        // Miss
        counters.base.miss_count += 1;

        // Value-aware admission check
        let admitted = access.value_millionths >= value_state.threshold_millionths
            && access.value_millionths >= config.value_admission.floor_value_millionths;

        verdicts.push(AdmissionVerdict {
            sequence: access.sequence,
            label: label.clone(),
            value_millionths: access.value_millionths,
            threshold_millionths: value_state.threshold_millionths,
            admitted,
        });

        if !admitted {
            value_state.denied_count += 1;
            counters.value_denied_count += 1;
            record_epoch_access(&mut split_state, false, true);
            maybe_adapt_split(&mut split_state, config);
            continue;
        }

        value_state.admitted_count += 1;
        counters.value_admitted_count += 1;

        let new_entry = ValueAnnotatedEntry {
            label: label.clone(),
            hot: false,
            value_millionths: access.value_millionths,
        };

        if remove_label(&mut queues.ghost, &label) {
            // Ghost hit: promote directly to main queue
            counters.base.ghost_hit_count += 1;
            record_epoch_access(&mut split_state, true, true);
            adaptive_insert_main(
                new_entry,
                &mut queues,
                config,
                split_state.current_small_capacity,
                &mut counters.base,
                &mut value_state,
            );
        } else {
            // First miss: insert into small queue
            record_epoch_access(&mut split_state, false, true);
            adaptive_insert_small(
                new_entry,
                &mut queues,
                config,
                &mut split_state,
                &mut counters.base,
                &mut value_state,
            );
        }

        maybe_adapt_split(&mut split_state, config);
    }

    counters.adaptation_count = split_state.adaptation_count;

    let final_resident_keys: Vec<String> = queues
        .small
        .iter()
        .chain(queues.main.iter())
        .map(|entry| entry.label.clone())
        .collect();

    // Build a plain CacheTraceCase for metric computation compatibility
    let plain_case = CacheTraceCase {
        trace_id: case.trace_id.clone(),
        workload_class: case.workload_class,
        accesses: case
            .accesses
            .iter()
            .map(|a| CacheTraceAccess {
                sequence: a.sequence,
                key: a.key.clone(),
                locality: a.locality,
            })
            .collect(),
    };

    let base_metrics = build_policy_metrics(
        CachePolicyKind::S3Fifo,
        &plain_case,
        counters.base,
        final_resident_keys,
    );

    S3FifoAdaptiveMetrics {
        base: base_metrics,
        final_small_capacity: split_state.current_small_capacity,
        adaptation_count: split_state.adaptation_count,
        value_denied_count: value_state.denied_count,
        value_admitted_count: value_state.admitted_count,
        final_threshold_millionths: value_state.threshold_millionths,
        admission_verdicts: verdicts,
    }
}

fn record_epoch_access(state: &mut AdaptiveSplitState, is_ghost_hit: bool, is_miss: bool) {
    state.epoch_accesses += 1;
    if is_ghost_hit {
        state.epoch_ghost_hits += 1;
    }
    if is_miss {
        state.epoch_misses += 1;
    }
}

fn maybe_adapt_split(state: &mut AdaptiveSplitState, config: &S3FifoAdaptiveConfig) {
    if state.epoch_accesses < config.adaptive_split.epoch_length {
        return;
    }

    // Ghost-hit ratio indicates how many evicted-small items turn out to be
    // needed soon. A high ratio means the small queue is too small.
    let total = state.epoch_ghost_hits + state.epoch_misses;
    let ghost_ratio_millionths = if total > 0 {
        ratio_to_millionths(state.epoch_ghost_hits, total)
    } else {
        0
    };

    let min_small = fraction_of(
        config.resident_capacity_entries,
        config.adaptive_split.min_small_fraction_millionths,
    )
    .max(1);
    let max_small = fraction_of(
        config.resident_capacity_entries,
        config.adaptive_split.max_small_fraction_millionths,
    )
    .min(config.resident_capacity_entries.saturating_sub(1));

    let target = state.current_small_capacity;

    // If ghost hits are high (>50%), increase small queue.
    // If ghost hits are low (<25%), decrease small queue.
    let new_target = if ghost_ratio_millionths > 500_000 {
        target
            .saturating_add(config.adaptive_split.max_step_per_epoch)
            .min(max_small)
    } else if ghost_ratio_millionths < 250_000 && target > min_small {
        target
            .saturating_sub(config.adaptive_split.max_step_per_epoch)
            .max(min_small)
    } else {
        target
    };

    state.current_small_capacity = new_target;
    state.adaptation_count += 1;
    state.epoch_accesses = 0;
    state.epoch_ghost_hits = 0;
    state.epoch_misses = 0;
}

fn fraction_of(total: usize, millionths: u32) -> usize {
    ((total as u64 * u64::from(millionths)) / 1_000_000) as usize
}

fn adaptive_insert_small(
    entry: ValueAnnotatedEntry,
    queues: &mut AdaptiveS3FifoQueues,
    config: &S3FifoAdaptiveConfig,
    split_state: &mut AdaptiveSplitState,
    counters: &mut CachePolicyCounters,
    value_state: &mut ValueAdmissionState,
) {
    while queues.small.len() >= split_state.current_small_capacity {
        if let Some(evicted) = queues.small.pop_front() {
            if evicted.hot {
                counters.promotion_count += 1;
                adaptive_insert_main(
                    ValueAnnotatedEntry {
                        label: evicted.label,
                        hot: false,
                        value_millionths: evicted.value_millionths,
                    },
                    queues,
                    config,
                    split_state.current_small_capacity,
                    counters,
                    value_state,
                );
            } else {
                counters.eviction_count += 1;
                update_value_threshold(value_state, evicted.value_millionths, config);
                push_ghost(
                    &evicted.label,
                    &mut queues.ghost,
                    config.ghost_queue_entries,
                );
            }
        }
    }
    queues.small.push_back(entry);
}

fn adaptive_insert_main(
    entry: ValueAnnotatedEntry,
    queues: &mut AdaptiveS3FifoQueues,
    config: &S3FifoAdaptiveConfig,
    current_small_capacity: usize,
    counters: &mut CachePolicyCounters,
    value_state: &mut ValueAdmissionState,
) {
    let main_capacity = config.current_main_capacity(current_small_capacity);
    while queues.main.len() >= main_capacity {
        adaptive_make_room_in_main(
            queues,
            config.ghost_queue_entries,
            counters,
            value_state,
            config,
        );
    }
    queues.main.push_back(entry);
}

fn adaptive_make_room_in_main(
    queues: &mut AdaptiveS3FifoQueues,
    ghost_capacity: usize,
    counters: &mut CachePolicyCounters,
    value_state: &mut ValueAdmissionState,
    config: &S3FifoAdaptiveConfig,
) {
    let mut attempts = queues.main.len();
    while attempts > 0 {
        let Some(mut candidate) = queues.main.pop_front() else {
            return;
        };

        if candidate.hot {
            candidate.hot = false;
            queues.main.push_back(candidate);
            counters.requeue_count += 1;
            attempts -= 1;
            continue;
        }

        counters.eviction_count += 1;
        update_value_threshold(value_state, candidate.value_millionths, config);
        push_ghost(&candidate.label, &mut queues.ghost, ghost_capacity);
        return;
    }

    // All entries are hot; force-evict the oldest.
    if let Some(candidate) = queues.main.pop_front() {
        counters.eviction_count += 1;
        update_value_threshold(value_state, candidate.value_millionths, config);
        push_ghost(&candidate.label, &mut queues.ghost, ghost_capacity);
    }
}

fn update_value_threshold(
    state: &mut ValueAdmissionState,
    evicted_value: u32,
    config: &S3FifoAdaptiveConfig,
) {
    // Exponential moving average update using fixed-point arithmetic.
    let alpha = u64::from(config.value_admission.alpha_millionths);
    let one_minus_alpha = 1_000_000u64.saturating_sub(alpha);
    let old = u64::from(state.threshold_millionths);
    let new_val = u64::from(evicted_value);
    let updated = (one_minus_alpha * old + alpha * new_val) / 1_000_000;
    state.threshold_millionths = updated as u32;
}

fn find_value_entry_mut<'a>(
    queue: &'a mut VecDeque<ValueAnnotatedEntry>,
    label: &str,
) -> Option<&'a mut ValueAnnotatedEntry> {
    queue.iter_mut().find(|entry| entry.label == label)
}

/// Convert a plain `CacheTraceCase` to a value-annotated trace by assigning
/// default value scores based on locality class.
pub fn annotate_trace_with_default_values(case: &CacheTraceCase) -> ValueAnnotatedTraceCase {
    ValueAnnotatedTraceCase {
        trace_id: case.trace_id.clone(),
        workload_class: case.workload_class,
        accesses: case
            .accesses
            .iter()
            .map(|a| ValueAnnotatedTraceAccess {
                sequence: a.sequence,
                key: a.key.clone(),
                locality: a.locality,
                value_millionths: locality_default_value(a.locality),
            })
            .collect(),
    }
}

fn locality_default_value(locality: CacheLocalityClass) -> u32 {
    match locality {
        CacheLocalityClass::Hot => 900_000,  // 0.9 — high value
        CacheLocalityClass::Warm => 500_000, // 0.5 — medium value
        CacheLocalityClass::Scan => 100_000, // 0.1 — low value
    }
}

/// Construct a default adaptive S3-FIFO configuration for evaluation.
pub fn default_s3fifo_adaptive_config() -> S3FifoAdaptiveConfig {
    S3FifoAdaptiveConfig::default()
}

