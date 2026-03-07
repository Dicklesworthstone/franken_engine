//! Deterministic module-cache invalidation strategy.
//!
//! Cache keys bind module identity to source hash, policy version, and trust
//! revision. Invalidation is explicit on source updates, policy changes, and
//! trust revocations.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;
use frankenengine_engine::seqlock_fastpath::{
    FastPathTelemetry, RetryBudgetPolicy, SnapshotFastPath,
};

pub type CacheResult<T> = Result<T, Box<CacheError>>;

pub const CACHE_TRACE_CORPUS_SCHEMA_VERSION: &str = "franken-engine.cache-trace-corpus.v1";
pub const CACHE_POLICY_BASELINE_SCHEMA_VERSION: &str = "franken-engine.cache-policy-baseline.v1";
pub const S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION: &str = "franken-engine.s3fifo-adoption-wedge.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleVersionFingerprint {
    pub source_hash: ContentHash,
    pub policy_version: u64,
    pub trust_revision: u64,
}

impl ModuleVersionFingerprint {
    pub fn new(source_hash: ContentHash, policy_version: u64, trust_revision: u64) -> Self {
        Self {
            source_hash,
            policy_version,
            trust_revision,
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "source_hash".to_string(),
            CanonicalValue::String(self.source_hash.to_hex()),
        );
        map.insert(
            "policy_version".to_string(),
            CanonicalValue::U64(self.policy_version),
        );
        map.insert(
            "trust_revision".to_string(),
            CanonicalValue::U64(self.trust_revision),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleCacheKey {
    pub module_id: String,
    pub version: ModuleVersionFingerprint,
}

impl ModuleCacheKey {
    pub fn new(module_id: impl Into<String>, version: ModuleVersionFingerprint) -> Self {
        Self {
            module_id: module_id.into(),
            version,
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "module_id".to_string(),
            CanonicalValue::String(self.module_id.clone()),
        );
        map.insert("version".to_string(), self.version.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCacheEntry {
    pub key: ModuleCacheKey,
    pub artifact_hash: ContentHash,
    pub resolved_specifier: String,
    pub inserted_seq: u64,
}

impl ModuleCacheEntry {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert(
            "artifact_hash".to_string(),
            CanonicalValue::String(self.artifact_hash.to_hex()),
        );
        map.insert(
            "resolved_specifier".to_string(),
            CanonicalValue::String(self.resolved_specifier.clone()),
        );
        map.insert(
            "inserted_seq".to_string(),
            CanonicalValue::U64(self.inserted_seq),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheInsertRequest {
    pub module_id: String,
    pub version: ModuleVersionFingerprint,
    pub artifact_hash: ContentHash,
    pub resolved_specifier: String,
}

impl CacheInsertRequest {
    pub fn new(
        module_id: impl Into<String>,
        version: ModuleVersionFingerprint,
        artifact_hash: ContentHash,
        resolved_specifier: impl Into<String>,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            version,
            artifact_hash,
            resolved_specifier: resolved_specifier.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl CacheContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvent {
    pub seq: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub module_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheErrorCode {
    ModuleRevoked,
    VersionRegression,
    EmptyModuleId,
}

impl CacheErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::ModuleRevoked => "FE-MODCACHE-0001",
            Self::VersionRegression => "FE-MODCACHE-0002",
            Self::EmptyModuleId => "FE-MODCACHE-0003",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheError {
    pub code: CacheErrorCode,
    pub message: String,
    pub event: CacheEvent,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.stable_code(), self.message)
    }
}

impl std::error::Error for CacheError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheSnapshot {
    pub entries: Vec<ModuleCacheEntry>,
    pub latest_versions: BTreeMap<String, ModuleVersionFingerprint>,
    pub revoked_modules: BTreeSet<String>,
    pub state_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCache {
    entries: BTreeMap<ModuleCacheKey, ModuleCacheEntry>,
    latest_versions: BTreeMap<String, ModuleVersionFingerprint>,
    revoked_modules: BTreeSet<String>,
    events: Vec<CacheEvent>,
    next_event_seq: u64,
    #[serde(skip, default = "module_cache_snapshot_fastpath")]
    snapshot_fastpath: SnapshotFastPath<CacheSnapshot>,
}

impl ModuleCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(
        &self,
        module_id: &str,
        version: &ModuleVersionFingerprint,
    ) -> Option<&ModuleCacheEntry> {
        if self.revoked_modules.contains(module_id) {
            return None;
        }

        let latest = self.latest_versions.get(module_id)?;
        if latest != version {
            return None;
        }

        let key = ModuleCacheKey::new(module_id.to_string(), version.clone());
        self.entries.get(&key)
    }

    pub fn insert(
        &mut self,
        request: CacheInsertRequest,
        context: &CacheContext,
    ) -> CacheResult<()> {
        if request.module_id.trim().is_empty() {
            return Err(self.error(
                CacheErrorCode::EmptyModuleId,
                "module_id must not be empty",
                "cache_insert",
                "deny",
                "<empty>",
                context,
            ));
        }

        if self.revoked_modules.contains(&request.module_id) {
            return Err(self.error(
                CacheErrorCode::ModuleRevoked,
                format!("module '{}' is revoked", request.module_id),
                "cache_insert",
                "deny",
                &request.module_id,
                context,
            ));
        }

        if let Some(latest) = self.latest_versions.get(&request.module_id) {
            let is_policy_regression = request.version.policy_version < latest.policy_version;
            let is_trust_regression = request.version.trust_revision < latest.trust_revision;
            if is_policy_regression || is_trust_regression {
                return Err(self.error(
                    CacheErrorCode::VersionRegression,
                    format!(
                        "version regression for module '{}' (latest policy={}, trust={}, got policy={}, trust={})",
                        request.module_id,
                        latest.policy_version,
                        latest.trust_revision,
                        request.version.policy_version,
                        request.version.trust_revision,
                    ),
                    "cache_insert",
                    "deny",
                    &request.module_id,
                    context,
                ));
            }
        }

        self.latest_versions
            .insert(request.module_id.clone(), request.version.clone());

        let key = ModuleCacheKey::new(request.module_id.clone(), request.version);
        let entry = ModuleCacheEntry {
            key: key.clone(),
            artifact_hash: request.artifact_hash,
            resolved_specifier: request.resolved_specifier,
            inserted_seq: self.next_event_seq,
        };
        self.entries.insert(key, entry);

        self.prune_stale_entries(&request.module_id);
        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_insert",
            "allow",
            "none",
            request.module_id,
            "cache entry inserted",
            context,
        );
        Ok(())
    }

    pub fn invalidate_source_update(
        &mut self,
        module_id: &str,
        new_source_hash: ContentHash,
        context: &CacheContext,
    ) {
        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| ModuleVersionFingerprint::new(new_source_hash.clone(), 0, 0));
        latest.source_hash = new_source_hash;
        let current_source_hash = latest.source_hash.clone();
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |entry| {
            entry.key.version.source_hash != current_source_hash
        });

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_invalidate_source_update",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} stale source entries"),
            context,
        );
    }

    pub fn invalidate_policy_change(
        &mut self,
        module_id: &str,
        new_policy_version: u64,
        context: &CacheContext,
    ) {
        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.policy_version = new_policy_version;
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |entry| {
            entry.key.version.policy_version != new_policy_version
        });

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_invalidate_policy_change",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} stale policy entries"),
            context,
        );
    }

    pub fn invalidate_trust_revocation(
        &mut self,
        module_id: &str,
        new_trust_revision: u64,
        context: &CacheContext,
    ) {
        self.revoked_modules.insert(module_id.to_string());

        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.trust_revision = latest.trust_revision.max(new_trust_revision);
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |_| true);

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_invalidate_trust_revocation",
            "allow",
            "none",
            module_id.to_string(),
            format!("removed {removed} entries and marked module revoked"),
            context,
        );
    }

    pub fn restore_trust(&mut self, module_id: &str, trust_revision: u64, context: &CacheContext) {
        self.revoked_modules.remove(module_id);

        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.trust_revision = latest.trust_revision.max(trust_revision);
        self.latest_versions.insert(module_id.to_string(), latest);

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_restore_trust",
            "allow",
            "none",
            module_id.to_string(),
            "trust restored for module",
            context,
        );
    }

    pub fn snapshot(&self) -> CacheSnapshot {
        if !self.snapshot_fastpath.is_initialized() {
            self.snapshot_fastpath
                .seed_if_uninitialized(self.baseline_snapshot());
        }
        self.snapshot_fastpath
            .read_clone_or_else(|| self.baseline_snapshot())
            .value
    }

    pub fn snapshot_fastpath_policy(&self) -> RetryBudgetPolicy {
        self.snapshot_fastpath.policy()
    }

    pub fn snapshot_fastpath_telemetry(&self) -> FastPathTelemetry {
        self.snapshot_fastpath.telemetry()
    }

    pub fn merge_snapshot(&mut self, snapshot: &CacheSnapshot, context: &CacheContext) {
        for (module_id, peer_version) in &snapshot.latest_versions {
            match self.latest_versions.get(module_id) {
                Some(local) if local >= peer_version => {}
                _ => {
                    self.latest_versions
                        .insert(module_id.clone(), peer_version.clone());
                }
            }
        }

        self.revoked_modules
            .extend(snapshot.revoked_modules.iter().cloned());

        for entry in &snapshot.entries {
            if self.revoked_modules.contains(&entry.key.module_id) {
                continue;
            }

            if self
                .latest_versions
                .get(&entry.key.module_id)
                .is_some_and(|latest| latest == &entry.key.version)
            {
                self.entries
                    .entry(entry.key.clone())
                    .or_insert_with(|| entry.clone());
            }
        }

        let module_ids = self.latest_versions.keys().cloned().collect::<Vec<_>>();
        for module_id in module_ids {
            self.prune_stale_entries(&module_id);
        }

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_merge_snapshot",
            "allow",
            "none",
            "<fleet>".to_string(),
            "snapshot merged and stale entries pruned",
            context,
        );
    }

    pub fn state_hash(&self) -> ContentHash {
        let mut root = BTreeMap::new();

        let entries = self
            .entries
            .values()
            .map(ModuleCacheEntry::canonical_value)
            .collect::<Vec<_>>();
        root.insert("entries".to_string(), CanonicalValue::Array(entries));

        let mut versions = BTreeMap::new();
        for (module_id, version) in &self.latest_versions {
            versions.insert(module_id.clone(), version.canonical_value());
        }
        root.insert("latest_versions".to_string(), CanonicalValue::Map(versions));

        let revoked = self
            .revoked_modules
            .iter()
            .map(|module_id| CanonicalValue::String(module_id.clone()))
            .collect::<Vec<_>>();
        root.insert(
            "revoked_modules".to_string(),
            CanonicalValue::Array(revoked),
        );

        ContentHash::compute(&encode_value(&CanonicalValue::Map(root)))
    }

    pub fn events(&self) -> &[CacheEvent] {
        &self.events
    }

    fn baseline_snapshot(&self) -> CacheSnapshot {
        CacheSnapshot {
            entries: self.entries.values().cloned().collect::<Vec<_>>(),
            latest_versions: self.latest_versions.clone(),
            revoked_modules: self.revoked_modules.clone(),
            state_hash: self.state_hash(),
        }
    }

    fn publish_snapshot_fastpath(&self) {
        self.snapshot_fastpath.publish(self.baseline_snapshot());
    }

    fn prune_stale_entries(&mut self, module_id: &str) {
        if self.revoked_modules.contains(module_id) {
            self.entries
                .retain(|key, _| key.module_id.as_str() != module_id);
            return;
        }

        let latest = match self.latest_versions.get(module_id) {
            Some(latest) => latest.clone(),
            None => return,
        };

        self.entries
            .retain(|key, _| key.module_id.as_str() != module_id || key.version == latest);
    }

    fn remove_module_entries_where<F>(&mut self, module_id: &str, mut predicate: F) -> usize
    where
        F: FnMut(&ModuleCacheEntry) -> bool,
    {
        let keys_to_remove = self
            .entries
            .iter()
            .filter_map(|(key, entry)| {
                if key.module_id.as_str() == module_id && predicate(entry) {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let removed = keys_to_remove.len();
        for key in keys_to_remove {
            self.entries.remove(&key);
        }
        removed
    }

    fn push_event(
        &mut self,
        event: impl Into<String>,
        outcome: impl Into<String>,
        error_code: impl Into<String>,
        module_id: impl Into<String>,
        detail: impl Into<String>,
        context: &CacheContext,
    ) {
        let event = CacheEvent {
            seq: self.next_event_seq,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "module_cache".to_string(),
            event: event.into(),
            outcome: outcome.into(),
            error_code: error_code.into(),
            module_id: module_id.into(),
            detail: detail.into(),
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(event);
    }

    fn error(
        &mut self,
        code: CacheErrorCode,
        message: impl Into<String>,
        event: &str,
        outcome: &str,
        module_id: &str,
        context: &CacheContext,
    ) -> Box<CacheError> {
        let message = message.into();
        self.push_event(
            event,
            outcome,
            code.stable_code(),
            module_id.to_string(),
            message.clone(),
            context,
        );
        Box::new(CacheError {
            code,
            message,
            event: self.events.last().expect("event was just pushed").clone(),
        })
    }
}

impl Default for ModuleCache {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            latest_versions: BTreeMap::new(),
            revoked_modules: BTreeSet::new(),
            events: Vec::new(),
            next_event_seq: 0,
            snapshot_fastpath: module_cache_snapshot_fastpath(),
        }
    }
}

fn module_cache_snapshot_fastpath() -> SnapshotFastPath<CacheSnapshot> {
    SnapshotFastPath::new(RetryBudgetPolicy::new(2, 2))
}

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
            if let Some(previous) = previous_sequence {
                if access.sequence <= previous {
                    return Err(CachePolicyReportError::NonMonotonicTraceSequence {
                        trace_id: self.trace_id.clone(),
                        previous,
                        actual: access.sequence,
                    });
                }
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
                actual: self.corpus_hash.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePolicyEntry {
    label: String,
    hot: bool,
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
        corpus_hash: manifest.corpus_hash.clone(),
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
    let mut hit_count = 0_u64;
    let mut miss_count = 0_u64;
    let mut eviction_count = 0_u64;

    for access in &case.accesses {
        let label = cache_trace_label(&access.key);
        if resident.contains(&label) {
            hit_count += 1;
            continue;
        }

        miss_count += 1;
        if resident.len() >= config.capacity_entries {
            if let Some(evicted) = queue.pop_front() {
                resident.remove(&evicted);
                eviction_count += 1;
            }
        }
        queue.push_back(label.clone());
        resident.insert(label);
    }

    build_policy_metrics(
        CachePolicyKind::SingleQueueFifo,
        case,
        hit_count,
        miss_count,
        0,
        eviction_count,
        0,
        0,
        queue.into_iter().collect(),
    )
}

fn simulate_s3fifo(case: &CacheTraceCase, config: &S3FifoConfig) -> CachePolicyMetrics {
    let mut small = VecDeque::new();
    let mut main = VecDeque::new();
    let mut ghost = VecDeque::new();
    let mut hit_count = 0_u64;
    let mut miss_count = 0_u64;
    let mut ghost_hit_count = 0_u64;
    let mut eviction_count = 0_u64;
    let mut promotion_count = 0_u64;
    let mut requeue_count = 0_u64;

    for access in &case.accesses {
        let label = cache_trace_label(&access.key);

        if let Some(entry) = find_entry_mut(&mut small, &label) {
            hit_count += 1;
            entry.hot = true;
            continue;
        }
        if let Some(entry) = find_entry_mut(&mut main, &label) {
            hit_count += 1;
            entry.hot = true;
            continue;
        }

        miss_count += 1;
        if remove_label(&mut ghost, &label) {
            ghost_hit_count += 1;
            insert_main_entry(
                CachePolicyEntry { label, hot: false },
                &mut main,
                &mut ghost,
                config,
                &mut eviction_count,
                &mut requeue_count,
            );
        } else {
            insert_small_entry(
                CachePolicyEntry { label, hot: false },
                &mut small,
                &mut main,
                &mut ghost,
                config,
                &mut eviction_count,
                &mut promotion_count,
                &mut requeue_count,
            );
        }
    }

    let final_resident_keys = small
        .iter()
        .chain(main.iter())
        .map(|entry| entry.label.clone())
        .collect::<Vec<_>>();

    build_policy_metrics(
        CachePolicyKind::S3Fifo,
        case,
        hit_count,
        miss_count,
        ghost_hit_count,
        eviction_count,
        promotion_count,
        requeue_count,
        final_resident_keys,
    )
}

fn insert_small_entry(
    entry: CachePolicyEntry,
    small: &mut VecDeque<CachePolicyEntry>,
    main: &mut VecDeque<CachePolicyEntry>,
    ghost: &mut VecDeque<String>,
    config: &S3FifoConfig,
    eviction_count: &mut u64,
    promotion_count: &mut u64,
    requeue_count: &mut u64,
) {
    while small.len() >= config.small_queue_entries {
        if let Some(evicted) = small.pop_front() {
            if evicted.hot {
                *promotion_count += 1;
                insert_main_entry(
                    CachePolicyEntry {
                        label: evicted.label,
                        hot: false,
                    },
                    main,
                    ghost,
                    config,
                    eviction_count,
                    requeue_count,
                );
            } else {
                *eviction_count += 1;
                push_ghost(&evicted.label, ghost, config.ghost_queue_entries);
            }
        }
    }
    small.push_back(entry);
}

fn insert_main_entry(
    entry: CachePolicyEntry,
    main: &mut VecDeque<CachePolicyEntry>,
    ghost: &mut VecDeque<String>,
    config: &S3FifoConfig,
    eviction_count: &mut u64,
    requeue_count: &mut u64,
) {
    let main_capacity = config.main_queue_entries();
    while main.len() >= main_capacity {
        make_room_in_main(
            main,
            ghost,
            config.ghost_queue_entries,
            eviction_count,
            requeue_count,
        );
    }
    main.push_back(entry);
}

fn make_room_in_main(
    main: &mut VecDeque<CachePolicyEntry>,
    ghost: &mut VecDeque<String>,
    ghost_capacity: usize,
    eviction_count: &mut u64,
    requeue_count: &mut u64,
) {
    let mut attempts = main.len();
    while attempts > 0 {
        let Some(mut candidate) = main.pop_front() else {
            return;
        };

        if candidate.hot {
            candidate.hot = false;
            main.push_back(candidate);
            *requeue_count += 1;
            attempts -= 1;
            continue;
        }

        *eviction_count += 1;
        push_ghost(&candidate.label, ghost, ghost_capacity);
        return;
    }

    if let Some(candidate) = main.pop_front() {
        *eviction_count += 1;
        push_ghost(&candidate.label, ghost, ghost_capacity);
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
    hit_count: u64,
    miss_count: u64,
    ghost_hit_count: u64,
    eviction_count: u64,
    promotion_count: u64,
    requeue_count: u64,
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
        hit_count,
        miss_count,
        ghost_hit_count,
        eviction_count,
        promotion_count,
        requeue_count,
        hit_rate_millionths: ratio_to_millionths(hit_count, total_accesses),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CacheContext {
        CacheContext::new("trace-cache", "decision-cache", "policy-cache")
    }

    fn source_hash(seed: &str) -> ContentHash {
        ContentHash::compute(seed.as_bytes())
    }

    fn trace_key(
        module_id: &str,
        source_seed: &str,
        policy_version: u64,
        trust_revision: u64,
    ) -> ModuleCacheKey {
        ModuleCacheKey::new(
            module_id,
            ModuleVersionFingerprint::new(source_hash(source_seed), policy_version, trust_revision),
        )
    }

    #[test]
    fn cache_trace_corpus_manifest_hash_is_deterministic() {
        let case = CacheTraceCase {
            trace_id: "trace-cache-corpus".to_string(),
            workload_class: CacheWorkloadClass::ColdCompile,
            accesses: vec![
                CacheTraceAccess {
                    sequence: 0,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Warm,
                },
                CacheTraceAccess {
                    sequence: 1,
                    key: trace_key("mod:b", "s2", 1, 1),
                    locality: CacheLocalityClass::Hot,
                },
            ],
        };

        let left = CacheTraceCorpusManifest::new("corpus.det", vec![case.clone()]).unwrap();
        let right = CacheTraceCorpusManifest::new("corpus.det", vec![case]).unwrap();

        assert_eq!(left.corpus_hash, right.corpus_hash);
        assert!(left.validate().is_ok());
    }

    #[test]
    fn cache_trace_corpus_manifest_rejects_duplicate_trace_ids() {
        let case = CacheTraceCase {
            trace_id: "trace-dup".to_string(),
            workload_class: CacheWorkloadClass::WarmRun,
            accesses: vec![CacheTraceAccess {
                sequence: 1,
                key: trace_key("mod:a", "s1", 1, 1),
                locality: CacheLocalityClass::Warm,
            }],
        };

        let err =
            CacheTraceCorpusManifest::new("corpus.dup", vec![case.clone(), case]).unwrap_err();
        match err {
            CachePolicyReportError::DuplicateTraceId { trace_id } => {
                assert_eq!(trace_id, "trace-dup")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn cache_trace_case_rejects_non_monotonic_sequence_numbers() {
        let err = CacheTraceCorpusManifest::new(
            "corpus.sequence",
            vec![CacheTraceCase {
                trace_id: "trace-sequence".to_string(),
                workload_class: CacheWorkloadClass::WarmRun,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                ],
            }],
        )
        .unwrap_err();

        match err {
            CachePolicyReportError::NonMonotonicTraceSequence {
                trace_id,
                previous,
                actual,
            } => {
                assert_eq!(trace_id, "trace-sequence");
                assert_eq!(previous, 2);
                assert_eq!(actual, 2);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn s3fifo_adoption_wedge_default_is_valid() {
        let wedge = S3FifoAdoptionWedgeContract::default();
        assert!(wedge.validate().is_ok());
    }

    #[test]
    fn evaluate_s3fifo_baseline_rejects_invalid_candidate_config() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.invalid",
            vec![CacheTraceCase {
                trace_id: "trace-invalid".to_string(),
                workload_class: CacheWorkloadClass::WarmRun,
                accesses: vec![CacheTraceAccess {
                    sequence: 0,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Warm,
                }],
            }],
        )
        .unwrap();

        let err = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 2,
            },
            &S3FifoConfig {
                resident_capacity_entries: 2,
                small_queue_entries: 2,
                ghost_queue_entries: 1,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .unwrap_err();

        match err {
            CachePolicyReportError::InvalidConfig { field, .. } => {
                assert_eq!(field, "small_queue_entries")
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn s3fifo_candidate_records_ghost_hits() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.ghost-hit",
            vec![CacheTraceCase {
                trace_id: "trace-ghost-hit".to_string(),
                workload_class: CacheWorkloadClass::ScanHeavy,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 0,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 1,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:c", "s3", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                    CacheTraceAccess {
                        sequence: 3,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Warm,
                    },
                ],
            }],
        )
        .unwrap();

        let report = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 2,
            },
            &S3FifoConfig {
                resident_capacity_entries: 2,
                small_queue_entries: 1,
                ghost_queue_entries: 2,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .unwrap();

        assert_eq!(report.cases.len(), 1);
        assert_eq!(report.cases[0].candidate.ghost_hit_count, 1);
        assert_eq!(report.cases[0].baseline.ghost_hit_count, 0);
        assert!(report.validate(&manifest).is_ok());
    }

    #[test]
    fn s3fifo_candidate_improves_hot_retention_and_scan_pollution() {
        let manifest = CacheTraceCorpusManifest::new(
            "corpus.hot-scan",
            vec![CacheTraceCase {
                trace_id: "trace-hot-scan".to_string(),
                workload_class: CacheWorkloadClass::ReactApp,
                accesses: vec![
                    CacheTraceAccess {
                        sequence: 0,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 1,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 2,
                        key: trace_key("mod:a", "s1", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 3,
                        key: trace_key("mod:b", "s2", 1, 1),
                        locality: CacheLocalityClass::Hot,
                    },
                    CacheTraceAccess {
                        sequence: 4,
                        key: trace_key("mod:c", "s3", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 5,
                        key: trace_key("mod:d", "s4", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 6,
                        key: trace_key("mod:e", "s5", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                    CacheTraceAccess {
                        sequence: 7,
                        key: trace_key("mod:f", "s6", 1, 1),
                        locality: CacheLocalityClass::Scan,
                    },
                ],
            }],
        )
        .unwrap();

        let report = evaluate_s3fifo_baseline(
            &manifest,
            &SingleQueueFifoConfig {
                capacity_entries: 4,
            },
            &S3FifoConfig {
                resident_capacity_entries: 4,
                small_queue_entries: 2,
                ghost_queue_entries: 4,
            },
            &S3FifoAdoptionWedgeContract::default(),
        )
        .unwrap();

        let case = &report.cases[0];
        assert_eq!(case.baseline.hot_retention_millionths, 0);
        assert_eq!(case.candidate.hot_retention_millionths, 1_000_000);
        assert!(case.candidate.scan_pollution_millionths < case.baseline.scan_pollution_millionths);
        assert_eq!(report.aggregate.improved_hot_retention_cases, 1);
        assert_eq!(report.aggregate.reduced_scan_pollution_cases, 1);
        assert!(report.validate(&manifest).is_ok());
    }

    #[test]
    fn cache_hit_then_miss_after_source_update() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v1.clone(),
                    ContentHash::compute(b"artifact-a"),
                    "/app/a.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:a", &v1).is_some());

        let v2_hash = source_hash("v2");
        cache.invalidate_source_update("mod:a", v2_hash.clone(), &context());
        assert!(cache.get("mod:a", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(v2_hash, 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:a",
                    v2.clone(),
                    ContentHash::compute(b"artifact-a-v2"),
                    "/app/a.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:a", &v2).is_some());
    }

    #[test]
    fn trust_revocation_removes_entries_and_blocks_insert() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    version.clone(),
                    ContentHash::compute(b"artifact"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap();

        cache.invalidate_trust_revocation("mod:revoked", 2, &context());
        assert!(cache.get("mod:revoked", &version).is_none());

        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    ModuleVersionFingerprint::new(source_hash("v2"), 1, 2),
                    ContentHash::compute(b"artifact2"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::ModuleRevoked);

        cache.restore_trust("mod:revoked", 3, &context());
        let restored = ModuleVersionFingerprint::new(source_hash("v2"), 1, 3);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:revoked",
                    restored.clone(),
                    ContentHash::compute(b"artifact3"),
                    "/app/revoked.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:revoked", &restored).is_some());
    }

    #[test]
    fn policy_change_invalidates_stale_entries() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("stable"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v1.clone(),
                    ContentHash::compute(b"artifact-p"),
                    "/app/p.js",
                ),
                &context(),
            )
            .unwrap();

        cache.invalidate_policy_change("mod:p", 2, &context());
        assert!(cache.get("mod:p", &v1).is_none());

        let v2 = ModuleVersionFingerprint::new(source_hash("stable"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:p",
                    v2.clone(),
                    ContentHash::compute(b"artifact-p2"),
                    "/app/p.js",
                ),
                &context(),
            )
            .unwrap();
        assert!(cache.get("mod:p", &v2).is_some());
    }

    #[test]
    fn deterministic_state_hash_for_identical_sequences() {
        let build = || {
            let mut cache = ModuleCache::new();
            let ctx = context();
            let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v1,
                        ContentHash::compute(b"artifact-x"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .unwrap();
            cache.invalidate_policy_change("mod:x", 2, &ctx);
            let v2 = ModuleVersionFingerprint::new(source_hash("s1"), 2, 1);
            cache
                .insert(
                    CacheInsertRequest::new(
                        "mod:x",
                        v2,
                        ContentHash::compute(b"artifact-x2"),
                        "/app/x.js",
                    ),
                    &ctx,
                )
                .unwrap();
            cache.state_hash()
        };

        assert_eq!(build(), build());
    }

    #[test]
    fn snapshot_merge_converges_revocation_state() {
        let ctx = context();

        let mut a = ModuleCache::new();
        let mut b = ModuleCache::new();

        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        a.insert(
            CacheInsertRequest::new(
                "mod:c",
                version,
                ContentHash::compute(b"artifact-c"),
                "/app/c.js",
            ),
            &ctx,
        )
        .unwrap();

        b.invalidate_trust_revocation("mod:c", 2, &ctx);

        let b_snapshot = b.snapshot();
        a.merge_snapshot(&b_snapshot, &ctx);

        let a_snapshot = a.snapshot();
        b.merge_snapshot(&a_snapshot, &ctx);

        assert_eq!(a.state_hash(), b.state_hash());
        assert!(a.revoked_modules.contains("mod:c"));
        assert!(b.revoked_modules.contains("mod:c"));
    }

    #[test]
    fn events_emit_required_structured_fields() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:e", 1, &ctx);

        let event = cache.events().last().unwrap();
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.trace_id, "trace-cache");
        assert_eq!(event.decision_id, "decision-cache");
        assert_eq!(event.policy_id, "policy-cache");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
        assert!(!event.error_code.is_empty());
    }

    // -----------------------------------------------------------------------
    // Empty module ID rejection
    // -----------------------------------------------------------------------

    #[test]
    fn insert_empty_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/empty.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0003");
    }

    #[test]
    fn insert_whitespace_only_module_id_returns_empty_module_id_error() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "   ",
                    version,
                    ContentHash::compute(b"artifact"),
                    "/app/ws.js",
                ),
                &context(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
    }

    // -----------------------------------------------------------------------
    // Version regression
    // -----------------------------------------------------------------------

    #[test]
    fn policy_version_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:reg", v1, ContentHash::compute(b"a1"), "/app/reg.js"),
                &ctx,
            )
            .unwrap();

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 3, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:reg",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/reg.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
        assert_eq!(err.code.stable_code(), "FE-MODCACHE-0002");
    }

    #[test]
    fn trust_revision_regression_returns_version_regression_error() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:tr", v1, ContentHash::compute(b"a1"), "/app/tr.js"),
                &ctx,
            )
            .unwrap();

        let v2_regressed = ModuleVersionFingerprint::new(source_hash("s2"), 1, 3);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:tr",
                    v2_regressed,
                    ContentHash::compute(b"a2"),
                    "/app/tr.js",
                ),
                &ctx,
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::VersionRegression);
    }

    // -----------------------------------------------------------------------
    // Get edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn get_unknown_module_returns_none() {
        let cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        assert!(cache.get("mod:unknown", &version).is_none());
    }

    #[test]
    fn get_with_stale_version_returns_none() {
        let mut cache = ModuleCache::new();
        let v1 = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v1.clone(),
                    ContentHash::compute(b"a1"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .unwrap();

        let v2 = ModuleVersionFingerprint::new(source_hash("v2"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:stale",
                    v2,
                    ContentHash::compute(b"a2"),
                    "/app/stale.js",
                ),
                &context(),
            )
            .unwrap();

        // v1 is now stale
        assert!(cache.get("mod:stale", &v1).is_none());
    }

    // -----------------------------------------------------------------------
    // Multiple modules
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_modules_coexist_independently() {
        let mut cache = ModuleCache::new();
        let ctx = context();

        let va = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("b"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:a", va.clone(), ContentHash::compute(b"aa"), "/a.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:b", vb.clone(), ContentHash::compute(b"bb"), "/b.js"),
                &ctx,
            )
            .unwrap();

        assert!(cache.get("mod:a", &va).is_some());
        assert!(cache.get("mod:b", &vb).is_some());

        // Revoke a, b should still be accessible
        cache.invalidate_trust_revocation("mod:a", 2, &ctx);
        assert!(cache.get("mod:a", &va).is_none());
        assert!(cache.get("mod:b", &vb).is_some());
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode stable codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_cache_error_codes_have_fe_modcache_prefix() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let stable = code.stable_code();
            assert!(
                stable.starts_with("FE-MODCACHE-"),
                "stable_code {} must start with FE-MODCACHE-",
                stable
            );
        }
    }

    #[test]
    fn cache_error_codes_are_unique() {
        let codes = [
            CacheErrorCode::ModuleRevoked.stable_code(),
            CacheErrorCode::VersionRegression.stable_code(),
            CacheErrorCode::EmptyModuleId.stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
    }

    // -----------------------------------------------------------------------
    // CacheError Display
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_includes_stable_code_and_message() {
        let mut cache = ModuleCache::new();
        let version = ModuleVersionFingerprint::new(source_hash("v1"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", version, ContentHash::compute(b"a"), "/app/e.js"),
                &context(),
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0003"));
        assert!(display.contains("must not be empty"));
    }

    // -----------------------------------------------------------------------
    // Snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn empty_cache_snapshot_has_deterministic_state_hash() {
        let a = ModuleCache::new();
        let b = ModuleCache::new();
        assert_eq!(a.state_hash(), b.state_hash());
        let snap = a.snapshot();
        assert!(snap.entries.is_empty());
        assert!(snap.latest_versions.is_empty());
        assert!(snap.revoked_modules.is_empty());
    }

    #[test]
    fn snapshot_contains_all_current_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 1, 1);

        cache
            .insert(
                CacheInsertRequest::new("mod:x", v1, ContentHash::compute(b"ax"), "/x.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:y", v2, ContentHash::compute(b"ay"), "/y.js"),
                &ctx,
            )
            .unwrap();

        let snap = cache.snapshot();
        assert_eq!(snap.entries.len(), 2);
        assert_eq!(snap.latest_versions.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Merge snapshot
    // -----------------------------------------------------------------------

    #[test]
    fn merge_snapshot_adopts_newer_versions() {
        let ctx = context();
        let mut local = ModuleCache::new();
        let mut remote = ModuleCache::new();

        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s"), 2, 1);

        local
            .insert(
                CacheInsertRequest::new("mod:m", v1.clone(), ContentHash::compute(b"a1"), "/m.js"),
                &ctx,
            )
            .unwrap();
        remote
            .insert(
                CacheInsertRequest::new("mod:m", v2.clone(), ContentHash::compute(b"a2"), "/m.js"),
                &ctx,
            )
            .unwrap();

        let remote_snap = remote.snapshot();
        local.merge_snapshot(&remote_snap, &ctx);

        // After merge, only v2 should be accessible (v1 is stale)
        assert!(local.get("mod:m", &v1).is_none());
        assert!(local.get("mod:m", &v2).is_some());
    }

    // -----------------------------------------------------------------------
    // Canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_canonical_value_is_deterministic() {
        let fp1 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        let fp2 = ModuleVersionFingerprint::new(source_hash("stable"), 3, 7);
        assert_eq!(
            encode_value(&fp1.canonical_value()),
            encode_value(&fp2.canonical_value())
        );
    }

    #[test]
    fn module_cache_key_canonical_value_is_deterministic() {
        let version = ModuleVersionFingerprint::new(source_hash("k"), 1, 1);
        let k1 = ModuleCacheKey::new("mod:det", version.clone());
        let k2 = ModuleCacheKey::new("mod:det", version);
        assert_eq!(
            encode_value(&k1.canonical_value()),
            encode_value(&k2.canonical_value())
        );
    }

    // -----------------------------------------------------------------------
    // Event sequence monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn event_sequences_are_monotonically_increasing() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("ev"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:ev", v1, ContentHash::compute(b"a"), "/ev.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:ev", 2, &ctx);
        cache.restore_trust("mod:ev", 3, &ctx);

        let seqs: Vec<u64> = cache.events().iter().map(|e| e.seq).collect();
        for window in seqs.windows(2) {
            assert!(
                window[1] > window[0],
                "event seq must be monotonically increasing: {:?}",
                seqs
            );
        }
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_round_trip() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: CacheErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn module_version_fingerprint_serde_round_trip() {
        let fp = ModuleVersionFingerprint::new(source_hash("serde-test"), 42, 7);
        let json = serde_json::to_string(&fp).expect("serialize");
        let decoded: ModuleVersionFingerprint = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, fp);
    }

    #[test]
    fn cache_snapshot_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("snap"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:snap", v, ContentHash::compute(b"as"), "/snap.js"),
                &ctx,
            )
            .unwrap();

        let snap = cache.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: CacheSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
    }

    // -----------------------------------------------------------------------
    // Invalidate source update on unknown module
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_source_update_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:new", source_hash("fresh"), &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:new"));
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Serde round-trips (enrichment)
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_key_serde_round_trip() {
        let key = ModuleCacheKey::new(
            "mod:serde",
            ModuleVersionFingerprint::new(source_hash("k"), 3, 7),
        );
        let json = serde_json::to_string(&key).expect("serialize");
        let decoded: ModuleCacheKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, key);
    }

    #[test]
    fn module_cache_entry_serde_round_trip() {
        let key = ModuleCacheKey::new(
            "mod:entry",
            ModuleVersionFingerprint::new(source_hash("e"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"artifact-serde"),
            resolved_specifier: "/app/entry.js".to_string(),
            inserted_seq: 42,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let decoded: ModuleCacheEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn cache_insert_request_serde_round_trip() {
        let req = CacheInsertRequest::new(
            "mod:req",
            ModuleVersionFingerprint::new(source_hash("r"), 2, 3),
            ContentHash::compute(b"art-req"),
            "/req.js",
        );
        let json = serde_json::to_string(&req).expect("serialize");
        let decoded: CacheInsertRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, req);
    }

    #[test]
    fn cache_context_serde_round_trip() {
        let ctx = CacheContext::new("t1", "d1", "p1");
        let json = serde_json::to_string(&ctx).expect("serialize");
        let decoded: CacheContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn cache_event_serde_round_trip() {
        let mut cache = ModuleCache::new();
        cache.invalidate_source_update("mod:ev-serde", source_hash("x"), &context());
        let event = cache.events().last().unwrap().clone();
        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: CacheEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, event);
    }

    #[test]
    fn cache_error_serde_round_trip() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let json = serde_json::to_string(&*err).expect("serialize");
        let decoded: CacheError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, *err);
    }

    #[test]
    fn module_cache_snapshot_captures_revoked_and_entries() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("mc"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:mc", v, ContentHash::compute(b"art"), "/mc.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:revoked", 1, &ctx);
        let snap = cache.snapshot();
        // Snapshot roundtrips through JSON (unlike ModuleCache which has non-string map keys)
        let json = serde_json::to_string(&snap).expect("serialize");
        let decoded: CacheSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, snap);
        assert_eq!(snap.entries.len(), 1);
        assert!(snap.revoked_modules.contains("mod:revoked"));
    }

    // -----------------------------------------------------------------------
    // CacheErrorCode serde uses snake_case
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_uses_snake_case() {
        let json = serde_json::to_string(&CacheErrorCode::ModuleRevoked).unwrap();
        assert_eq!(json, "\"module_revoked\"");
        let json = serde_json::to_string(&CacheErrorCode::VersionRegression).unwrap();
        assert_eq!(json, "\"version_regression\"");
        let json = serde_json::to_string(&CacheErrorCode::EmptyModuleId).unwrap();
        assert_eq!(json, "\"empty_module_id\"");
    }

    // -----------------------------------------------------------------------
    // CacheError Display for all error codes
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_module_revoked() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:rd", v, ContentHash::compute(b"a"), "/r.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:rd", 2, &ctx);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:rd",
                    ModuleVersionFingerprint::new(source_hash("s2"), 1, 2),
                    ContentHash::compute(b"a2"),
                    "/r.js",
                ),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0001"), "got: {display}");
        assert!(display.contains("revoked"), "got: {display}");
    }

    #[test]
    fn cache_error_display_version_regression() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 5, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:vr", v1, ContentHash::compute(b"a1"), "/vr.js"),
                &ctx,
            )
            .unwrap();
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 3, 5);
        let err = cache
            .insert(
                CacheInsertRequest::new("mod:vr", v2, ContentHash::compute(b"a2"), "/vr.js"),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert!(display.contains("FE-MODCACHE-0002"), "got: {display}");
        assert!(display.contains("regression"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // Default trait
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_default_equals_new() {
        let a = ModuleCache::new();
        let b = ModuleCache::default();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------------
    // Invalidation on unknown modules
    // -----------------------------------------------------------------------

    #[test]
    fn invalidate_policy_change_on_unknown_module_creates_version_entry() {
        let mut cache = ModuleCache::new();
        cache.invalidate_policy_change("mod:unknown-policy", 5, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:unknown-policy"));
        assert_eq!(snap.latest_versions["mod:unknown-policy"].policy_version, 5);
    }

    #[test]
    fn invalidate_trust_revocation_on_unknown_module_marks_revoked() {
        let mut cache = ModuleCache::new();
        cache.invalidate_trust_revocation("mod:unknown-trust", 3, &context());
        let snap = cache.snapshot();
        assert!(snap.revoked_modules.contains("mod:unknown-trust"));
        assert!(snap.latest_versions.contains_key("mod:unknown-trust"));
    }

    // -----------------------------------------------------------------------
    // restore_trust edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn restore_trust_on_non_revoked_module_is_harmless() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:nr", v.clone(), ContentHash::compute(b"a"), "/nr.js"),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        cache.restore_trust("mod:nr", 2, &ctx);
        // Module still accessible, trust_revision may advance
        assert!(cache.get("mod:nr", &v).is_none()); // version changed (trust_revision bumped)
        // But hash should differ since latest_versions changed
        assert_ne!(cache.state_hash(), hash_before);
    }

    #[test]
    fn restore_trust_on_unknown_module_creates_entry() {
        let mut cache = ModuleCache::new();
        cache.restore_trust("mod:ghost", 1, &context());
        let snap = cache.snapshot();
        assert!(snap.latest_versions.contains_key("mod:ghost"));
        assert!(!snap.revoked_modules.contains("mod:ghost"));
    }

    // -----------------------------------------------------------------------
    // Merge snapshot edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn merge_empty_remote_snapshot_is_noop() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:local",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/l.js",
                ),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        let empty_snap = ModuleCache::new().snapshot();
        cache.merge_snapshot(&empty_snap, &ctx);
        assert_eq!(cache.state_hash(), hash_before);
        assert!(cache.get("mod:local", &v).is_some());
    }

    #[test]
    fn merge_into_empty_local_adopts_remote_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("r"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new(
                    "mod:remote",
                    v.clone(),
                    ContentHash::compute(b"ar"),
                    "/r.js",
                ),
                &ctx,
            )
            .unwrap();
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.get("mod:remote", &v).is_some());
    }

    #[test]
    fn merge_does_not_import_revoked_module_entries() {
        let mut remote = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        remote
            .insert(
                CacheInsertRequest::new("mod:willrevoke", v, ContentHash::compute(b"a"), "/w.js"),
                &ctx,
            )
            .unwrap();
        remote.invalidate_trust_revocation("mod:willrevoke", 2, &ctx);
        let remote_snap = remote.snapshot();

        let mut local = ModuleCache::new();
        local.merge_snapshot(&remote_snap, &ctx);
        assert!(local.revoked_modules.contains("mod:willrevoke"));
        assert!(local.entries.is_empty());
    }

    // -----------------------------------------------------------------------
    // State hash changes after operations
    // -----------------------------------------------------------------------

    #[test]
    fn state_hash_changes_after_insert() {
        let mut cache = ModuleCache::new();
        let hash_empty = cache.state_hash();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:sh", v, ContentHash::compute(b"a"), "/sh.js"),
                &context(),
            )
            .unwrap();
        assert_ne!(cache.state_hash(), hash_empty);
    }

    #[test]
    fn state_hash_changes_after_revocation() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:hr", v, ContentHash::compute(b"a"), "/hr.js"),
                &ctx,
            )
            .unwrap();
        let hash_before = cache.state_hash();
        cache.invalidate_trust_revocation("mod:hr", 2, &ctx);
        assert_ne!(cache.state_hash(), hash_before);
    }

    // -----------------------------------------------------------------------
    // Ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_ordering() {
        let a = ModuleVersionFingerprint::new(source_hash("a"), 1, 1);
        let b = ModuleVersionFingerprint::new(source_hash("a"), 2, 1);
        let c = ModuleVersionFingerprint::new(source_hash("a"), 2, 2);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn module_cache_key_ordering() {
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let ka = ModuleCacheKey::new("aaa", v.clone());
        let kb = ModuleCacheKey::new("bbb", v);
        assert!(ka < kb);
    }

    // -----------------------------------------------------------------------
    // Error event fields
    // -----------------------------------------------------------------------

    #[test]
    fn error_event_records_correct_fields() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let _ = cache.insert(
            CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
            &context(),
        );
        let event = cache.events().last().unwrap();
        assert_eq!(event.component, "module_cache");
        assert_eq!(event.event, "cache_insert");
        assert_eq!(event.outcome, "deny");
        assert_eq!(event.error_code, "FE-MODCACHE-0003");
        assert_eq!(event.module_id, "<empty>");
    }

    // -----------------------------------------------------------------------
    // ModuleCacheEntry canonical value determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_cache_entry_canonical_value_is_deterministic() {
        let key = ModuleCacheKey::new(
            "mod:det2",
            ModuleVersionFingerprint::new(source_hash("d"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"det-artifact"),
            resolved_specifier: "/det.js".to_string(),
            inserted_seq: 99,
        };
        let bytes1 = encode_value(&entry.canonical_value());
        let bytes2 = encode_value(&entry.canonical_value());
        assert_eq!(bytes1, bytes2);
    }

    // -----------------------------------------------------------------------
    // Forward version upgrade succeeds (existing)
    // -----------------------------------------------------------------------

    #[test]
    fn forward_version_upgrade_succeeds() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:up", v1, ContentHash::compute(b"a1"), "/up.js"),
                &ctx,
            )
            .unwrap();

        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 2, 2);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:up",
                    v2.clone(),
                    ContentHash::compute(b"a2"),
                    "/up.js",
                ),
                &ctx,
            )
            .unwrap();

        assert!(cache.get("mod:up", &v2).is_some());
    }

    // -- Enrichment: Display uniqueness, edge cases, std::error --

    #[test]
    fn cache_error_code_display_uniqueness() {
        let codes = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let displays: BTreeSet<String> =
            codes.iter().map(|c| c.stable_code().to_string()).collect();
        assert_eq!(
            displays.len(),
            3,
            "all 3 error codes produce distinct stable codes"
        );
    }

    #[test]
    fn cache_error_implements_std_error() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let dyn_err: &dyn std::error::Error = &*err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn cache_context_fields_match_construction() {
        let ctx = CacheContext::new("t-abc", "d-def", "p-ghi");
        assert_eq!(ctx.trace_id, "t-abc");
        assert_eq!(ctx.decision_id, "d-def");
        assert_eq!(ctx.policy_id, "p-ghi");
    }

    #[test]
    fn insert_same_version_twice_overwrites() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("same"), 1, 1);
        let art1 = ContentHash::compute(b"artifact-1");
        let art2 = ContentHash::compute(b"artifact-2");

        cache
            .insert(
                CacheInsertRequest::new("mod:dup", v.clone(), art1, "/dup.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:dup", v.clone(), art2.clone(), "/dup.js"),
                &ctx,
            )
            .unwrap();

        let entry = cache.get("mod:dup", &v).unwrap();
        assert_eq!(
            entry.artifact_hash, art2,
            "second insert should overwrite first"
        );
    }

    #[test]
    fn empty_cache_has_no_events() {
        let cache = ModuleCache::new();
        assert!(cache.events().is_empty());
    }

    #[test]
    fn snapshot_revoked_modules_is_btree_set() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:b", 1, &ctx);
        cache.invalidate_trust_revocation("mod:a", 2, &ctx);
        let snap = cache.snapshot();
        let revoked: Vec<&str> = snap.revoked_modules.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            revoked,
            vec!["mod:a", "mod:b"],
            "revoked modules should be sorted"
        );
    }

    #[test]
    fn module_version_fingerprint_display_fields() {
        let fp = ModuleVersionFingerprint::new(source_hash("display-test"), 10, 20);
        assert_eq!(fp.policy_version, 10);
        assert_eq!(fp.trust_revision, 20);
    }

    // -----------------------------------------------------------------------
    // Copy semantics — CacheErrorCode is Copy
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_is_copy() {
        let original = CacheErrorCode::ModuleRevoked;
        let copied = original;
        assert_eq!(original, copied);
    }

    #[test]
    fn cache_error_code_copy_all_variants() {
        let a = CacheErrorCode::VersionRegression;
        let b = a;
        assert_eq!(a.stable_code(), b.stable_code());

        let c = CacheErrorCode::EmptyModuleId;
        let d = c;
        assert_eq!(c.stable_code(), d.stable_code());
    }

    // -----------------------------------------------------------------------
    // Debug distinctness — all enum variants produce distinct Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_debug_is_distinct() {
        let variants = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            3,
            "all CacheErrorCode variants have distinct Debug output"
        );
    }

    // -----------------------------------------------------------------------
    // Serde variant distinctness — all enum variants serialize to distinct JSON
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_serde_variants_distinct() {
        let variants = [
            CacheErrorCode::ModuleRevoked,
            CacheErrorCode::VersionRegression,
            CacheErrorCode::EmptyModuleId,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            3,
            "all CacheErrorCode variants serialize to distinct JSON"
        );
    }

    // -----------------------------------------------------------------------
    // Clone independence — mutating a clone doesn't affect the original
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_clone_independence() {
        let original = ModuleVersionFingerprint::new(source_hash("orig"), 3, 7);
        let mut cloned = original.clone();
        cloned.policy_version = 99;
        assert_eq!(original.policy_version, 3);
        assert_ne!(original.policy_version, cloned.policy_version);
    }

    #[test]
    fn cache_context_clone_independence() {
        let original = CacheContext::new("trace-orig", "dec-orig", "pol-orig");
        let mut cloned = original.clone();
        cloned.trace_id = "trace-mutated".to_string();
        assert_eq!(original.trace_id, "trace-orig");
        assert_eq!(cloned.trace_id, "trace-mutated");
    }

    #[test]
    fn module_cache_key_clone_independence() {
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let original = ModuleCacheKey::new("mod:clone-orig", v);
        let mut cloned = original.clone();
        cloned.module_id = "mod:clone-mutated".to_string();
        assert_eq!(original.module_id, "mod:clone-orig");
        assert_eq!(cloned.module_id, "mod:clone-mutated");
    }

    #[test]
    fn cache_insert_request_clone_independence() {
        let req = CacheInsertRequest::new(
            "mod:clone-req",
            ModuleVersionFingerprint::new(source_hash("r"), 1, 1),
            ContentHash::compute(b"art"),
            "/clone.js",
        );
        let mut cloned = req.clone();
        cloned.module_id = "mod:mutated".to_string();
        assert_eq!(req.module_id, "mod:clone-req");
        assert_eq!(cloned.module_id, "mod:mutated");
    }

    // -----------------------------------------------------------------------
    // JSON field-name stability — assert exact field names in serialized output
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_json_field_names() {
        let fp = ModuleVersionFingerprint::new(source_hash("fields"), 1, 1);
        let json = serde_json::to_string(&fp).unwrap();
        assert!(json.contains("\"source_hash\""), "got: {json}");
        assert!(json.contains("\"policy_version\""), "got: {json}");
        assert!(json.contains("\"trust_revision\""), "got: {json}");
    }

    #[test]
    fn module_cache_key_json_field_names() {
        let key = ModuleCacheKey::new(
            "mod:fields",
            ModuleVersionFingerprint::new(source_hash("f"), 1, 1),
        );
        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("\"module_id\""), "got: {json}");
        assert!(json.contains("\"version\""), "got: {json}");
    }

    #[test]
    fn module_cache_entry_json_field_names() {
        let key = ModuleCacheKey::new(
            "mod:entry-fields",
            ModuleVersionFingerprint::new(source_hash("ef"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"art-f"),
            resolved_specifier: "/entry-f.js".to_string(),
            inserted_seq: 5,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"key\""), "got: {json}");
        assert!(json.contains("\"artifact_hash\""), "got: {json}");
        assert!(json.contains("\"resolved_specifier\""), "got: {json}");
        assert!(json.contains("\"inserted_seq\""), "got: {json}");
    }

    #[test]
    fn cache_context_json_field_names() {
        let ctx = CacheContext::new("t", "d", "p");
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"trace_id\""), "got: {json}");
        assert!(json.contains("\"decision_id\""), "got: {json}");
        assert!(json.contains("\"policy_id\""), "got: {json}");
    }

    #[test]
    fn cache_error_json_field_names() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let json = serde_json::to_string(&*err).unwrap();
        assert!(json.contains("\"code\""), "got: {json}");
        assert!(json.contains("\"message\""), "got: {json}");
        assert!(json.contains("\"event\""), "got: {json}");
    }

    #[test]
    fn cache_snapshot_json_field_names() {
        let snap = ModuleCache::new().snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"entries\""), "got: {json}");
        assert!(json.contains("\"latest_versions\""), "got: {json}");
        assert!(json.contains("\"revoked_modules\""), "got: {json}");
        assert!(json.contains("\"state_hash\""), "got: {json}");
    }

    // -----------------------------------------------------------------------
    // Display format checks — exact string assertions for Display impls
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_display_format_exact_separator() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        let display = format!("{err}");
        // Format is "<stable_code>: <message>"
        assert!(
            display.contains(": "),
            "display must contain ': ' separator; got: {display}"
        );
        assert!(
            display.starts_with("FE-MODCACHE-"),
            "display must start with FE-MODCACHE-; got: {display}"
        );
    }

    #[test]
    fn cache_error_display_module_revoked_code_prefix() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_trust_revocation("mod:disp", 1, &ctx);
        let err = cache
            .insert(
                CacheInsertRequest::new(
                    "mod:disp",
                    ModuleVersionFingerprint::new(source_hash("s"), 1, 1),
                    ContentHash::compute(b"a"),
                    "/d.js",
                ),
                &ctx,
            )
            .unwrap_err();
        let display = format!("{err}");
        assert_eq!(
            display.split(": ").next().unwrap(),
            "FE-MODCACHE-0001",
            "exact code prefix; got: {display}"
        );
    }

    // -----------------------------------------------------------------------
    // Hash consistency — canonical encoding of equal values is identical
    // (types don't derive Hash; use canonical_value determinism as proxy)
    // -----------------------------------------------------------------------

    #[test]
    fn cache_error_code_equality_consistent_with_serde() {
        let a = CacheErrorCode::VersionRegression;
        let b = CacheErrorCode::VersionRegression;
        // Two equal values must serialize identically (our hash-consistency proxy)
        let ja = serde_json::to_string(&a).unwrap();
        let jb = serde_json::to_string(&b).unwrap();
        assert_eq!(ja, jb);
    }

    #[test]
    fn module_version_fingerprint_equal_values_canonical_identical() {
        let fp1 = ModuleVersionFingerprint::new(source_hash("hash-test"), 7, 13);
        let fp2 = ModuleVersionFingerprint::new(source_hash("hash-test"), 7, 13);
        // Canonical encoding acts as deterministic hash
        assert_eq!(
            encode_value(&fp1.canonical_value()),
            encode_value(&fp2.canonical_value())
        );
    }

    #[test]
    fn module_cache_key_equal_values_canonical_identical() {
        let v1 = ModuleVersionFingerprint::new(source_hash("hk"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("hk"), 1, 1);
        let k1 = ModuleCacheKey::new("mod:hash-key", v1);
        let k2 = ModuleCacheKey::new("mod:hash-key", v2);
        assert_eq!(
            encode_value(&k1.canonical_value()),
            encode_value(&k2.canonical_value())
        );
    }

    // -----------------------------------------------------------------------
    // Boundary/edge cases — zero values, u64::MAX, empty strings
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_zero_values() {
        let fp = ModuleVersionFingerprint::new(source_hash("zero"), 0, 0);
        assert_eq!(fp.policy_version, 0);
        assert_eq!(fp.trust_revision, 0);
        let json = serde_json::to_string(&fp).unwrap();
        let decoded: ModuleVersionFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, fp);
    }

    #[test]
    fn module_version_fingerprint_u64_max_values() {
        let fp = ModuleVersionFingerprint::new(source_hash("max"), u64::MAX, u64::MAX);
        assert_eq!(fp.policy_version, u64::MAX);
        assert_eq!(fp.trust_revision, u64::MAX);
        let json = serde_json::to_string(&fp).unwrap();
        let decoded: ModuleVersionFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, fp);
    }

    #[test]
    fn cache_event_empty_detail_allowed() {
        let mut cache = ModuleCache::new();
        // Trigger an event to check the event detail field type
        cache.invalidate_source_update("mod:edge", source_hash("e"), &context());
        let event = cache.events().last().unwrap();
        // detail is always a String, even if empty would be allowed
        assert!(event.detail.contains("removed"));
    }

    #[test]
    fn restore_trust_with_zero_revision_harmless() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:zero-tr",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/z.js",
                ),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:zero-tr", 1, &ctx);
        cache.restore_trust("mod:zero-tr", 0, &ctx);
        let snap = cache.snapshot();
        assert!(!snap.revoked_modules.contains("mod:zero-tr"));
    }

    #[test]
    fn insert_after_restore_with_updated_revision() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s"), 1, 5);
        cache
            .insert(
                CacheInsertRequest::new("mod:restore2", v1, ContentHash::compute(b"a1"), "/r2.js"),
                &ctx,
            )
            .unwrap();
        cache.invalidate_trust_revocation("mod:restore2", 10, &ctx);
        cache.restore_trust("mod:restore2", 10, &ctx);
        // After restore, latest trust_revision is max(5, 10) = 10; insert with 10 should succeed
        let v2 = ModuleVersionFingerprint::new(source_hash("s2"), 1, 10);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:restore2",
                    v2.clone(),
                    ContentHash::compute(b"a2"),
                    "/r2.js",
                ),
                &ctx,
            )
            .unwrap();
        assert!(cache.get("mod:restore2", &v2).is_some());
    }

    #[test]
    fn insert_with_u64_max_policy_version_succeeds() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v = ModuleVersionFingerprint::new(source_hash("max-pol"), u64::MAX, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:max-pol",
                    v.clone(),
                    ContentHash::compute(b"amax"),
                    "/max.js",
                ),
                &ctx,
            )
            .unwrap();
        assert!(cache.get("mod:max-pol", &v).is_some());
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips — complex populated structs
    // -----------------------------------------------------------------------

    #[test]
    fn cache_snapshot_with_revoked_and_entries_roundtrip() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        // Insert two modules
        let va = ModuleVersionFingerprint::new(source_hash("sa"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("sb"), 2, 3);
        cache
            .insert(
                CacheInsertRequest::new("mod:sn-a", va, ContentHash::compute(b"art-a"), "/sn-a.js"),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new("mod:sn-b", vb, ContentHash::compute(b"art-b"), "/sn-b.js"),
                &ctx,
            )
            .unwrap();
        // Revoke one
        cache.invalidate_trust_revocation("mod:sn-revoked", 1, &ctx);
        let snap = cache.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let decoded: CacheSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.entries.len(), snap.entries.len());
        assert_eq!(decoded.revoked_modules, snap.revoked_modules);
        assert_eq!(decoded.state_hash, snap.state_hash);
        assert_eq!(decoded.latest_versions, snap.latest_versions);
    }

    #[test]
    fn cache_event_serde_all_fields() {
        let mut cache = ModuleCache::new();
        let ctx = CacheContext::new("trace-ev-all", "dec-ev-all", "pol-ev-all");
        let v = ModuleVersionFingerprint::new(source_hash("ev-all"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:ev-all",
                    v,
                    ContentHash::compute(b"art-ev"),
                    "/ev-all.js",
                ),
                &ctx,
            )
            .unwrap();
        let event = cache.events().last().unwrap().clone();
        let json = serde_json::to_string(&event).unwrap();
        let decoded: CacheEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.trace_id, "trace-ev-all");
        assert_eq!(decoded.decision_id, "dec-ev-all");
        assert_eq!(decoded.policy_id, "pol-ev-all");
        assert_eq!(decoded.component, "module_cache");
    }

    // -----------------------------------------------------------------------
    // Debug nonempty — all types produce non-empty Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn module_version_fingerprint_debug_nonempty() {
        let fp = ModuleVersionFingerprint::new(source_hash("dbg"), 1, 1);
        assert!(!format!("{fp:?}").is_empty());
    }

    #[test]
    fn module_cache_key_debug_nonempty() {
        let v = ModuleVersionFingerprint::new(source_hash("dbg-k"), 1, 1);
        let key = ModuleCacheKey::new("mod:dbg", v);
        assert!(!format!("{key:?}").is_empty());
    }

    #[test]
    fn module_cache_entry_debug_nonempty() {
        let key = ModuleCacheKey::new(
            "mod:dbg-e",
            ModuleVersionFingerprint::new(source_hash("dbg-e"), 1, 1),
        );
        let entry = ModuleCacheEntry {
            key,
            artifact_hash: ContentHash::compute(b"dbg-art"),
            resolved_specifier: "/dbg.js".to_string(),
            inserted_seq: 0,
        };
        assert!(!format!("{entry:?}").is_empty());
    }

    #[test]
    fn cache_insert_request_debug_nonempty() {
        let req = CacheInsertRequest::new(
            "mod:dbg-req",
            ModuleVersionFingerprint::new(source_hash("dbg-r"), 1, 1),
            ContentHash::compute(b"dbg-r"),
            "/dbg-r.js",
        );
        assert!(!format!("{req:?}").is_empty());
    }

    #[test]
    fn cache_context_debug_nonempty() {
        let ctx = CacheContext::new("t", "d", "p");
        assert!(!format!("{ctx:?}").is_empty());
    }

    #[test]
    fn cache_event_debug_nonempty() {
        let mut cache = ModuleCache::new();
        cache.invalidate_trust_revocation("mod:dbg-ev", 1, &context());
        let event = cache.events().last().unwrap();
        assert!(!format!("{event:?}").is_empty());
    }

    #[test]
    fn cache_error_code_debug_nonempty() {
        assert!(!format!("{:?}", CacheErrorCode::ModuleRevoked).is_empty());
        assert!(!format!("{:?}", CacheErrorCode::VersionRegression).is_empty());
        assert!(!format!("{:?}", CacheErrorCode::EmptyModuleId).is_empty());
    }

    #[test]
    fn cache_error_debug_nonempty() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("s"), 1, 1);
        let err = cache
            .insert(
                CacheInsertRequest::new("", v, ContentHash::compute(b"a"), "/e.js"),
                &context(),
            )
            .unwrap_err();
        assert!(!format!("{err:?}").is_empty());
    }

    #[test]
    fn cache_snapshot_debug_nonempty() {
        let snap = ModuleCache::new().snapshot();
        assert!(!format!("{snap:?}").is_empty());
    }

    #[test]
    fn module_cache_debug_nonempty() {
        let cache = ModuleCache::new();
        assert!(!format!("{cache:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // Additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_insertions_same_module_event_count_grows() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let v1 = ModuleVersionFingerprint::new(source_hash("s1"), 1, 1);
        let v2 = ModuleVersionFingerprint::new(source_hash("s1"), 2, 1);
        cache
            .insert(
                CacheInsertRequest::new("mod:evcount", v1, ContentHash::compute(b"a1"), "/ev.js"),
                &ctx,
            )
            .unwrap();
        let count_after_1 = cache.events().len();
        cache
            .insert(
                CacheInsertRequest::new("mod:evcount", v2, ContentHash::compute(b"a2"), "/ev.js"),
                &ctx,
            )
            .unwrap();
        let count_after_2 = cache.events().len();
        assert!(count_after_2 > count_after_1);
    }

    #[test]
    fn state_hash_two_empty_caches_are_equal() {
        let a = ModuleCache::new();
        let b = ModuleCache::new();
        assert_eq!(a.state_hash(), b.state_hash());
    }

    #[test]
    fn invalidate_policy_change_preserves_other_modules() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        let va = ModuleVersionFingerprint::new(source_hash("sa"), 1, 1);
        let vb = ModuleVersionFingerprint::new(source_hash("sb"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:pol-a",
                    va.clone(),
                    ContentHash::compute(b"aa"),
                    "/a.js",
                ),
                &ctx,
            )
            .unwrap();
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:pol-b",
                    vb.clone(),
                    ContentHash::compute(b"bb"),
                    "/b.js",
                ),
                &ctx,
            )
            .unwrap();
        cache.invalidate_policy_change("mod:pol-a", 5, &ctx);
        // mod:pol-b should still be accessible at its version
        assert!(cache.get("mod:pol-b", &vb).is_some());
        // mod:pol-a with old version should be gone
        assert!(cache.get("mod:pol-a", &va).is_none());
    }

    #[test]
    fn cache_error_code_equality_reflexive() {
        let code = CacheErrorCode::EmptyModuleId;
        assert_eq!(code, code);
    }

    #[test]
    fn module_cache_entry_inserted_seq_is_zero_on_first_insert() {
        let mut cache = ModuleCache::new();
        let v = ModuleVersionFingerprint::new(source_hash("seq0"), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:seq0",
                    v.clone(),
                    ContentHash::compute(b"a"),
                    "/s0.js",
                ),
                &context(),
            )
            .unwrap();
        let entry = cache.get("mod:seq0", &v).unwrap();
        assert_eq!(entry.inserted_seq, 0);
    }

    #[test]
    fn events_field_names_present_in_event_json() {
        let mut cache = ModuleCache::new();
        let ctx = context();
        cache.invalidate_source_update("mod:field-check", source_hash("fc"), &ctx);
        let event = cache.events().last().unwrap();
        let json = serde_json::to_string(event).unwrap();
        assert!(json.contains("\"seq\""), "got: {json}");
        assert!(json.contains("\"trace_id\""), "got: {json}");
        assert!(json.contains("\"decision_id\""), "got: {json}");
        assert!(json.contains("\"policy_id\""), "got: {json}");
        assert!(json.contains("\"component\""), "got: {json}");
        assert!(json.contains("\"event\""), "got: {json}");
        assert!(json.contains("\"outcome\""), "got: {json}");
        assert!(json.contains("\"error_code\""), "got: {json}");
        assert!(json.contains("\"module_id\""), "got: {json}");
        assert!(json.contains("\"detail\""), "got: {json}");
    }
}
