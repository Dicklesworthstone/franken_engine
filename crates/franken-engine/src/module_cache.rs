//! Deterministic module-cache invalidation strategy.
//!
//! Cache keys bind module identity to source hash, policy version, and trust
//! revision. Invalidation is explicit on source updates, policy changes, and
//! trust revocations.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use chrono::{SecondsFormat, Utc};
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
pub const S3FIFO_BASELINE_COMPONENT: &str = "s3fifo_baseline_comparator";
pub const S3FIFO_BASELINE_BEAD_ID: &str = "bd-1lsy.7.20.1";
pub const S3FIFO_BASELINE_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-s3fifo-baseline-comparator-contract.v1";
pub const S3FIFO_BASELINE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.event.v1";
pub const S3FIFO_BASELINE_ENV_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.env.v1";
pub const S3FIFO_BASELINE_ARTIFACT_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.manifest.v1";
pub const S3FIFO_BASELINE_REPRO_LOCK_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.repro-lock.v1";
pub const S3FIFO_BASELINE_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.run-manifest.v1";
pub const S3FIFO_BASELINE_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.s3fifo-baseline-comparator.trace-ids.v1";

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
    #[serde(with = "module_cache_entries_serde")]
    entries: BTreeMap<ModuleCacheKey, ModuleCacheEntry>,
    latest_versions: BTreeMap<String, ModuleVersionFingerprint>,
    revoked_modules: BTreeSet<String>,
    events: Vec<CacheEvent>,
    next_event_seq: u64,
    #[serde(skip, default = "module_cache_snapshot_fastpath")]
    snapshot_fastpath: SnapshotFastPath<CacheSnapshot>,
}

mod module_cache_entries_serde {
    use std::collections::BTreeMap;

    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{ModuleCacheEntry, ModuleCacheKey};

    pub fn serialize<S>(
        entries: &BTreeMap<ModuleCacheKey, ModuleCacheEntry>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        entries.values().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<BTreeMap<ModuleCacheKey, ModuleCacheEntry>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<ModuleCacheEntry>::deserialize(deserializer)?;
        let mut map = BTreeMap::new();
        for entry in entries {
            if map.insert(entry.key.clone(), entry).is_some() {
                return Err(D::Error::custom(
                    "duplicate module cache entry key during deserialization",
                ));
            }
        }
        Ok(map)
    }
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
            .unwrap_or_else(|| ModuleVersionFingerprint::new(new_source_hash, 0, 0));
        latest.source_hash = new_source_hash;
        let current_source_hash = latest.source_hash;
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
        latest.policy_version = latest.policy_version.max(new_policy_version);
        let effective_policy_version = latest.policy_version;
        self.latest_versions.insert(module_id.to_string(), latest);

        let removed = self.remove_module_entries_where(module_id, |entry| {
            entry.key.version.policy_version != effective_policy_version
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

    /// Compatibility entry point. A denied restoration is recorded in the audit
    /// trail and leaves the module's authority unchanged. Callers that need to
    /// act on a refusal should use `try_restore_trust`.
    pub fn restore_trust(&mut self, module_id: &str, trust_revision: u64, context: &CacheContext) {
        let _ = self.try_restore_trust(module_id, trust_revision, context);
    }

    /// Restore a module only under a non-regressing trust decision.
    ///
    /// Revocation wins at an equal revision: a revoked module requires a
    /// strictly newer decision, including when its frontier is `u64::MAX`.
    /// The caller must authenticate and authorize that decision; a revision
    /// number is not itself proof of authority.
    pub fn try_restore_trust(
        &mut self,
        module_id: &str,
        trust_revision: u64,
        context: &CacheContext,
    ) -> CacheResult<()> {
        if module_id.trim().is_empty() {
            return Err(self.error(
                CacheErrorCode::EmptyModuleId,
                "module_id must not be empty",
                "cache_restore_trust",
                "deny",
                "<empty>",
                context,
            ));
        }

        let revoked = self.revoked_modules.contains(module_id);
        if let Some(latest) = self.latest_versions.get(module_id) {
            if trust_revision < latest.trust_revision
                || (revoked && trust_revision == latest.trust_revision)
            {
                return Err(self.error(
                    CacheErrorCode::VersionRegression,
                    format!(
                        "trust restoration for module '{module_id}' requires {} {} (got {trust_revision})",
                        if revoked { "a revision newer than" } else { "at least revision" },
                        latest.trust_revision,
                    ),
                    "cache_restore_trust",
                    "deny",
                    module_id,
                    context,
                ));
            }
        } else if revoked {
            // A malformed/deserialized revocation without its frontier cannot
            // be cleared by guessing a revision. A coherent state is required.
            return Err(self.error(
                CacheErrorCode::VersionRegression,
                format!("revoked module '{module_id}' has no trust frontier"),
                "cache_restore_trust",
                "deny",
                module_id,
                context,
            ));
        }

        let mut latest = self
            .latest_versions
            .get(module_id)
            .cloned()
            .unwrap_or_else(|| {
                ModuleVersionFingerprint::new(ContentHash::compute(b"unknown-source"), 0, 0)
            });
        latest.trust_revision = trust_revision;
        self.latest_versions.insert(module_id.to_string(), latest);
        self.revoked_modules.remove(module_id);
        // Advancing trust also invalidates artifacts in a non-revoked cache;
        // they must never be re-labelled with the new authority revision.
        self.prune_stale_entries(module_id);

        self.publish_snapshot_fastpath();
        self.push_event(
            "cache_restore_trust",
            "allow",
            "none",
            module_id.to_string(),
            "trust restored for module",
            context,
        );
        Ok(())
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
                Some(local) if cache_version_order(local, peer_version) != Ordering::Less => {}
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
        // Create event data before pushing to avoid unsafe expect()
        let event_data = CacheEvent {
            seq: self.next_event_seq,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "module_cache".to_string(),
            event: event.into(),
            outcome: outcome.into(),
            error_code: code.stable_code().to_string(),
            module_id: module_id.to_string(),
            detail: message.clone(),
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(event_data.clone());
        Box::new(CacheError {
            code,
            message,
            event: event_data,
        })
    }
}

fn cache_version_order(
    left: &ModuleVersionFingerprint,
    right: &ModuleVersionFingerprint,
) -> Ordering {
    left.policy_version
        .cmp(&right.policy_version)
        .then(left.trust_revision.cmp(&right.trust_revision))
        .then(left.source_hash.cmp(&right.source_hash))
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

include!("module_cache/policies.rs");
include!("module_cache/tests.rs");
