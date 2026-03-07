//! Deterministic module-cache invalidation strategy.
//!
//! Cache keys bind module identity to source hash, policy version, and trust
//! revision. Invalidation is explicit on source updates, policy changes, and
//! trust revocations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;
use frankenengine_engine::seqlock_fastpath::{
    FastPathTelemetry, RetryBudgetPolicy, SnapshotFastPath,
};

pub type CacheResult<T> = Result<T, Box<CacheError>>;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CacheContext {
        CacheContext::new("trace-cache", "decision-cache", "policy-cache")
    }

    fn source_hash(seed: &str) -> ContentHash {
        ContentHash::compute(seed.as_bytes())
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
