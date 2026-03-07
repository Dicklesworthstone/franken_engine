#![forbid(unsafe_code)]

//! Integration tests for the `module_cache` module.
//!
//! These tests exercise the public API from outside the crate, covering
//! cache construction, insert/get, invalidation (source, policy, trust),
//! trust restore, snapshot/merge, error codes, Display impls, serde
//! round-trips, event audit trail, and deterministic replay.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheError, CacheErrorCode, CacheEvent, CacheInsertRequest, CacheLocalityClass,
    CachePolicyBaselineReport, CachePolicyReportError, CacheResult, CacheSnapshot,
    CacheTraceAccess, CacheTraceCase, CacheTraceCorpusManifest, CacheWorkloadClass, ModuleCache,
    ModuleCacheEntry, ModuleCacheKey, ModuleVersionFingerprint, S3FifoAdoptionWedgeContract,
    S3FifoConfig, SingleQueueFifoConfig, evaluate_s3fifo_baseline,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> CacheContext {
    CacheContext::new("trace-int", "decision-int", "policy-int")
}

fn source_hash(seed: &str) -> ContentHash {
    ContentHash::compute(seed.as_bytes())
}

fn artifact_hash(seed: &str) -> ContentHash {
    ContentHash::compute(seed.as_bytes())
}

fn fp(source_seed: &str, policy: u64, trust: u64) -> ModuleVersionFingerprint {
    ModuleVersionFingerprint::new(source_hash(source_seed), policy, trust)
}

fn insert_module(
    cache: &mut ModuleCache,
    module_id: &str,
    version: ModuleVersionFingerprint,
    artifact_seed: &str,
    specifier: &str,
) -> CacheResult<()> {
    cache.insert(
        CacheInsertRequest::new(module_id, version, artifact_hash(artifact_seed), specifier),
        &ctx(),
    )
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

// ===========================================================================
// Section 1: Construction and defaults
// ===========================================================================

#[test]
fn new_cache_is_empty() {
    let cache = ModuleCache::new();
    let snap = cache.snapshot();
    assert!(snap.entries.is_empty());
    assert!(snap.latest_versions.is_empty());
    assert!(snap.revoked_modules.is_empty());
    assert_eq!(cache.events().len(), 0);
}

#[test]
fn default_cache_equals_new() {
    let a = ModuleCache::new();
    let b = ModuleCache::default();
    assert_eq!(a.state_hash(), b.state_hash());
}

// ===========================================================================
// Section 2: ModuleVersionFingerprint
// ===========================================================================

#[test]
fn module_version_fingerprint_construction() {
    let h = source_hash("src");
    let mvf = ModuleVersionFingerprint::new(h.clone(), 5, 3);
    assert_eq!(mvf.source_hash, h);
    assert_eq!(mvf.policy_version, 5);
    assert_eq!(mvf.trust_revision, 3);
}

#[test]
fn module_version_fingerprint_ord() {
    let a = fp("a", 1, 1);
    let b = fp("b", 1, 1);
    // Ord is derived, so it compares fields in declaration order
    // source_hash first, then policy_version, then trust_revision
    assert!(a != b);
    // Just verify ordering is total
    assert!(a < b || b < a);
}

#[test]
fn module_version_fingerprint_clone_eq() {
    let v = fp("clone", 7, 3);
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn module_version_fingerprint_debug() {
    let v = fp("dbg", 1, 2);
    let dbg = format!("{v:?}");
    assert!(dbg.contains("ModuleVersionFingerprint"), "debug: {dbg}");
}

// ===========================================================================
// Section 3: ModuleCacheKey
// ===========================================================================

#[test]
fn module_cache_key_construction() {
    let v = fp("key", 1, 1);
    let key = ModuleCacheKey::new("mod:k", v.clone());
    assert_eq!(key.module_id, "mod:k");
    assert_eq!(key.version, v);
}

#[test]
fn module_cache_key_ord() {
    let v = fp("ord", 1, 1);
    let k1 = ModuleCacheKey::new("aaa", v.clone());
    let k2 = ModuleCacheKey::new("bbb", v);
    assert!(k1 < k2);
}

#[test]
fn module_cache_key_debug() {
    let key = ModuleCacheKey::new("mod:dbg", fp("d", 1, 1));
    let dbg = format!("{key:?}");
    assert!(dbg.contains("ModuleCacheKey"), "debug: {dbg}");
}

// ===========================================================================
// Section 4: CacheInsertRequest
// ===========================================================================

#[test]
fn cache_insert_request_construction() {
    let v = fp("req", 2, 3);
    let ah = artifact_hash("art");
    let req = CacheInsertRequest::new("mod:r", v.clone(), ah.clone(), "/app/r.js");
    assert_eq!(req.module_id, "mod:r");
    assert_eq!(req.version, v);
    assert_eq!(req.artifact_hash, ah);
    assert_eq!(req.resolved_specifier, "/app/r.js");
}

// ===========================================================================
// Section 5: CacheContext
// ===========================================================================

#[test]
fn cache_context_construction() {
    let c = CacheContext::new("t1", "d1", "p1");
    assert_eq!(c.trace_id, "t1");
    assert_eq!(c.decision_id, "d1");
    assert_eq!(c.policy_id, "p1");
}

#[test]
fn cache_context_clone_eq() {
    let c = CacheContext::new("t", "d", "p");
    let cloned = c.clone();
    assert_eq!(c, cloned);
}

// ===========================================================================
// Section 6: CacheErrorCode
// ===========================================================================

#[test]
fn cache_error_code_stable_codes_unique_and_prefixed() {
    let codes = [
        CacheErrorCode::ModuleRevoked,
        CacheErrorCode::VersionRegression,
        CacheErrorCode::EmptyModuleId,
    ];
    let mut seen = BTreeSet::new();
    for code in &codes {
        let stable = code.stable_code();
        assert!(
            stable.starts_with("FE-MODCACHE-"),
            "code {stable} should start with FE-MODCACHE-"
        );
        assert!(seen.insert(stable), "duplicate stable code: {stable}");
    }
}

#[test]
fn cache_error_code_specific_values() {
    assert_eq!(
        CacheErrorCode::ModuleRevoked.stable_code(),
        "FE-MODCACHE-0001"
    );
    assert_eq!(
        CacheErrorCode::VersionRegression.stable_code(),
        "FE-MODCACHE-0002"
    );
    assert_eq!(
        CacheErrorCode::EmptyModuleId.stable_code(),
        "FE-MODCACHE-0003"
    );
}

#[test]
fn cache_error_code_copy_clone() {
    let code = CacheErrorCode::ModuleRevoked;
    let copied = code;
    let cloned = code;
    assert_eq!(code, copied);
    assert_eq!(code, cloned);
}

// ===========================================================================
// Section 7: CacheError Display
// ===========================================================================

#[test]
fn cache_error_display_includes_stable_code_and_message() {
    let mut cache = ModuleCache::new();
    let err = cache
        .insert(
            CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
            &ctx(),
        )
        .unwrap_err();
    let display = err.to_string();
    assert!(display.contains("FE-MODCACHE-0003"), "display: {display}");
    assert!(display.contains("must not be empty"), "display: {display}");
}

#[test]
fn cache_error_is_std_error() {
    let mut cache = ModuleCache::new();
    let err = cache
        .insert(
            CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
            &ctx(),
        )
        .unwrap_err();
    let _: &dyn std::error::Error = err.as_ref();
}

#[test]
fn cache_error_fields_accessible() {
    let mut cache = ModuleCache::new();
    let err = cache
        .insert(
            CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
    assert!(!err.message.is_empty());
    assert_eq!(err.event.component, "module_cache");
}

// ===========================================================================
// Section 8: Insert and get -- basic operations
// ===========================================================================

#[test]
fn insert_and_get_single_module() {
    let mut cache = ModuleCache::new();
    let v = fp("src1", 1, 1);
    insert_module(&mut cache, "mod:a", v.clone(), "art-a", "/a.js").unwrap();

    let entry = cache.get("mod:a", &v).expect("should find entry");
    assert_eq!(entry.key.module_id, "mod:a");
    assert_eq!(entry.key.version, v);
    assert_eq!(entry.artifact_hash, artifact_hash("art-a"));
    assert_eq!(entry.resolved_specifier, "/a.js");
}

#[test]
fn insert_multiple_modules() {
    let mut cache = ModuleCache::new();
    let va = fp("a", 1, 1);
    let vb = fp("b", 1, 1);
    let vc = fp("c", 1, 1);

    insert_module(&mut cache, "mod:a", va.clone(), "art-a", "/a.js").unwrap();
    insert_module(&mut cache, "mod:b", vb.clone(), "art-b", "/b.js").unwrap();
    insert_module(&mut cache, "mod:c", vc.clone(), "art-c", "/c.js").unwrap();

    assert!(cache.get("mod:a", &va).is_some());
    assert!(cache.get("mod:b", &vb).is_some());
    assert!(cache.get("mod:c", &vc).is_some());
}

#[test]
fn get_unknown_module_returns_none() {
    let cache = ModuleCache::new();
    assert!(cache.get("mod:nonexistent", &fp("x", 1, 1)).is_none());
}

#[test]
fn get_with_wrong_version_returns_none() {
    let mut cache = ModuleCache::new();
    let v1 = fp("src", 1, 1);
    insert_module(&mut cache, "mod:a", v1, "art", "/a.js").unwrap();

    let wrong_v = fp("different", 1, 1);
    assert!(cache.get("mod:a", &wrong_v).is_none());
}

#[test]
fn get_stale_version_after_upgrade_returns_none() {
    let mut cache = ModuleCache::new();
    let v1 = fp("v1", 1, 1);
    let v2 = fp("v2", 2, 1);

    insert_module(&mut cache, "mod:a", v1.clone(), "art1", "/a.js").unwrap();
    insert_module(&mut cache, "mod:a", v2.clone(), "art2", "/a.js").unwrap();

    assert!(cache.get("mod:a", &v1).is_none());
    assert!(cache.get("mod:a", &v2).is_some());
}

// ===========================================================================
// Section 9: Insert error conditions
// ===========================================================================

#[test]
fn insert_empty_module_id_fails() {
    let mut cache = ModuleCache::new();
    let err = cache
        .insert(
            CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
}

#[test]
fn insert_whitespace_only_module_id_fails() {
    let mut cache = ModuleCache::new();
    for ws in ["   ", "\t", "\n", "  \t\n  "] {
        let err = cache
            .insert(
                CacheInsertRequest::new(ws, fp("v", 1, 1), artifact_hash("a"), "/ws.js"),
                &ctx(),
            )
            .unwrap_err();
        assert_eq!(err.code, CacheErrorCode::EmptyModuleId, "ws={ws:?}");
    }
}

#[test]
fn insert_into_revoked_module_fails() {
    let mut cache = ModuleCache::new();
    let v = fp("src", 1, 1);
    insert_module(&mut cache, "mod:r", v, "art", "/r.js").unwrap();
    cache.invalidate_trust_revocation("mod:r", 2, &ctx());

    let err = cache
        .insert(
            CacheInsertRequest::new("mod:r", fp("new", 1, 2), artifact_hash("art2"), "/r.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::ModuleRevoked);
}

#[test]
fn insert_policy_version_regression_fails() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:p", fp("s", 5, 1), "a1", "/p.js").unwrap();

    let err = cache
        .insert(
            CacheInsertRequest::new("mod:p", fp("s2", 3, 1), artifact_hash("a2"), "/p.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::VersionRegression);
}

#[test]
fn insert_trust_revision_regression_fails() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:t", fp("s", 1, 5), "a1", "/t.js").unwrap();

    let err = cache
        .insert(
            CacheInsertRequest::new("mod:t", fp("s2", 1, 3), artifact_hash("a2"), "/t.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::VersionRegression);
}

#[test]
fn insert_same_policy_different_source_is_ok() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:a", fp("src1", 1, 1), "art1", "/a.js").unwrap();
    // Same policy and trust, different source = forward update (no regression)
    insert_module(&mut cache, "mod:a", fp("src2", 1, 1), "art2", "/a.js").unwrap();
    assert!(cache.get("mod:a", &fp("src2", 1, 1)).is_some());
}

#[test]
fn insert_forward_upgrade_both_fields() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:u", fp("s1", 1, 1), "a1", "/u.js").unwrap();
    insert_module(&mut cache, "mod:u", fp("s2", 2, 2), "a2", "/u.js").unwrap();
    assert!(cache.get("mod:u", &fp("s2", 2, 2)).is_some());
}

// ===========================================================================
// Section 10: Source update invalidation
// ===========================================================================

#[test]
fn invalidate_source_update_removes_old_entries() {
    let mut cache = ModuleCache::new();
    let v1 = fp("old-src", 1, 1);
    insert_module(&mut cache, "mod:s", v1.clone(), "art1", "/s.js").unwrap();
    assert!(cache.get("mod:s", &v1).is_some());

    cache.invalidate_source_update("mod:s", source_hash("new-src"), &ctx());
    assert!(cache.get("mod:s", &v1).is_none());
}

#[test]
fn invalidate_source_update_on_unknown_module_creates_version_entry() {
    let mut cache = ModuleCache::new();
    cache.invalidate_source_update("mod:unknown", source_hash("fresh"), &ctx());
    let snap = cache.snapshot();
    assert!(snap.latest_versions.contains_key("mod:unknown"));
}

#[test]
fn invalidate_source_update_then_insert_with_new_source() {
    let mut cache = ModuleCache::new();
    let v1 = fp("v1", 1, 1);
    insert_module(&mut cache, "mod:s", v1, "a1", "/s.js").unwrap();

    let new_source = source_hash("v2");
    cache.invalidate_source_update("mod:s", new_source.clone(), &ctx());

    let v2 = ModuleVersionFingerprint::new(new_source, 1, 1);
    insert_module(&mut cache, "mod:s", v2.clone(), "a2", "/s.js").unwrap();
    assert!(cache.get("mod:s", &v2).is_some());
}

// ===========================================================================
// Section 11: Policy change invalidation
// ===========================================================================

#[test]
fn invalidate_policy_change_removes_old_policy_entries() {
    let mut cache = ModuleCache::new();
    let v1 = fp("stable", 1, 1);
    insert_module(&mut cache, "mod:p", v1.clone(), "a1", "/p.js").unwrap();

    cache.invalidate_policy_change("mod:p", 2, &ctx());
    assert!(cache.get("mod:p", &v1).is_none());
}

#[test]
fn invalidate_policy_change_then_insert_new_policy() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:p", fp("stable", 1, 1), "a1", "/p.js").unwrap();
    cache.invalidate_policy_change("mod:p", 2, &ctx());

    let v2 = fp("stable", 2, 1);
    insert_module(&mut cache, "mod:p", v2.clone(), "a2", "/p.js").unwrap();
    assert!(cache.get("mod:p", &v2).is_some());
}

#[test]
fn invalidate_policy_change_on_unknown_module() {
    let mut cache = ModuleCache::new();
    cache.invalidate_policy_change("mod:new", 5, &ctx());
    let snap = cache.snapshot();
    assert!(snap.latest_versions.contains_key("mod:new"));
}

// ===========================================================================
// Section 12: Trust revocation and restoration
// ===========================================================================

#[test]
fn trust_revocation_removes_entries_and_blocks_insert() {
    let mut cache = ModuleCache::new();
    let v = fp("src", 1, 1);
    insert_module(&mut cache, "mod:r", v.clone(), "art", "/r.js").unwrap();

    cache.invalidate_trust_revocation("mod:r", 2, &ctx());
    assert!(cache.get("mod:r", &v).is_none());

    let err = cache
        .insert(
            CacheInsertRequest::new("mod:r", fp("new", 1, 2), artifact_hash("a2"), "/r.js"),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::ModuleRevoked);
}

#[test]
fn trust_restore_allows_insert_again() {
    let mut cache = ModuleCache::new();
    let v = fp("src", 1, 1);
    insert_module(&mut cache, "mod:r", v, "art", "/r.js").unwrap();
    cache.invalidate_trust_revocation("mod:r", 2, &ctx());
    cache.restore_trust("mod:r", 3, &ctx());

    let v3 = fp("new-src", 1, 3);
    insert_module(&mut cache, "mod:r", v3.clone(), "art3", "/r.js").unwrap();
    assert!(cache.get("mod:r", &v3).is_some());
}

#[test]
fn trust_restore_on_unknown_module() {
    let mut cache = ModuleCache::new();
    cache.restore_trust("mod:never", 1, &ctx());
    let snap = cache.snapshot();
    assert!(snap.latest_versions.contains_key("mod:never"));
    assert!(!snap.revoked_modules.contains("mod:never"));
}

#[test]
fn trust_revocation_is_monotonic_on_revision() {
    let mut cache = ModuleCache::new();
    cache.invalidate_trust_revocation("mod:m", 5, &ctx());
    cache.restore_trust("mod:m", 3, &ctx());
    // trust_revision should be max(5, 3) = 5
    let snap = cache.snapshot();
    let latest = snap.latest_versions.get("mod:m").unwrap();
    assert!(latest.trust_revision >= 5);
}

#[test]
fn revoke_module_without_prior_entries() {
    let mut cache = ModuleCache::new();
    cache.invalidate_trust_revocation("mod:phantom", 1, &ctx());
    let snap = cache.snapshot();
    assert!(snap.revoked_modules.contains("mod:phantom"));
    assert!(snap.entries.is_empty());
}

#[test]
fn multiple_revocations_and_restores() {
    let mut cache = ModuleCache::new();
    let c = ctx();
    let v1 = fp("s1", 1, 1);
    insert_module(&mut cache, "mod:m", v1, "a1", "/m.js").unwrap();

    cache.invalidate_trust_revocation("mod:m", 2, &c);
    assert!(cache.snapshot().revoked_modules.contains("mod:m"));

    cache.restore_trust("mod:m", 3, &c);
    assert!(!cache.snapshot().revoked_modules.contains("mod:m"));

    let v2 = fp("s2", 1, 3);
    insert_module(&mut cache, "mod:m", v2.clone(), "a2", "/m.js").unwrap();
    assert!(cache.get("mod:m", &v2).is_some());

    cache.invalidate_trust_revocation("mod:m", 4, &c);
    assert!(cache.get("mod:m", &v2).is_none());

    cache.restore_trust("mod:m", 5, &c);
    let v3 = fp("s3", 1, 5);
    insert_module(&mut cache, "mod:m", v3.clone(), "a3", "/m.js").unwrap();
    assert!(cache.get("mod:m", &v3).is_some());
}

// ===========================================================================
// Section 13: Module isolation
// ===========================================================================

#[test]
fn revocation_of_one_module_does_not_affect_others() {
    let mut cache = ModuleCache::new();
    let va = fp("a", 1, 1);
    let vb = fp("b", 1, 1);
    insert_module(&mut cache, "mod:a", va.clone(), "art-a", "/a.js").unwrap();
    insert_module(&mut cache, "mod:b", vb.clone(), "art-b", "/b.js").unwrap();

    cache.invalidate_trust_revocation("mod:a", 2, &ctx());
    assert!(cache.get("mod:a", &va).is_none());
    assert!(cache.get("mod:b", &vb).is_some());
}

#[test]
fn source_update_on_one_module_preserves_others() {
    let mut cache = ModuleCache::new();
    let va = fp("a", 1, 1);
    let vb = fp("b", 1, 1);
    insert_module(&mut cache, "mod:a", va.clone(), "art-a", "/a.js").unwrap();
    insert_module(&mut cache, "mod:b", vb.clone(), "art-b", "/b.js").unwrap();

    cache.invalidate_source_update("mod:a", source_hash("new-a"), &ctx());
    assert!(cache.get("mod:a", &va).is_none());
    assert!(cache.get("mod:b", &vb).is_some());
}

// ===========================================================================
// Section 14: Snapshot
// ===========================================================================

#[test]
fn empty_snapshot_deterministic() {
    let a = ModuleCache::new();
    let b = ModuleCache::new();
    assert_eq!(a.snapshot().state_hash, b.snapshot().state_hash);
}

#[test]
fn snapshot_contains_all_entries() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:x", fp("x", 1, 1), "ax", "/x.js").unwrap();
    insert_module(&mut cache, "mod:y", fp("y", 1, 1), "ay", "/y.js").unwrap();
    insert_module(&mut cache, "mod:z", fp("z", 1, 1), "az", "/z.js").unwrap();

    let snap = cache.snapshot();
    assert_eq!(snap.entries.len(), 3);
    assert_eq!(snap.latest_versions.len(), 3);
    assert!(snap.revoked_modules.is_empty());
}

#[test]
fn snapshot_reflects_revocations() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:r", fp("s", 1, 1), "a", "/r.js").unwrap();
    cache.invalidate_trust_revocation("mod:r", 2, &ctx());

    let snap = cache.snapshot();
    assert!(snap.revoked_modules.contains("mod:r"));
    assert!(snap.entries.is_empty());
}

#[test]
fn snapshot_state_hash_changes_with_mutations() {
    let mut cache = ModuleCache::new();
    let hash0 = cache.state_hash();

    insert_module(&mut cache, "mod:a", fp("s", 1, 1), "a", "/a.js").unwrap();
    let hash1 = cache.state_hash();
    assert_ne!(hash0, hash1);

    cache.invalidate_trust_revocation("mod:a", 2, &ctx());
    let hash2 = cache.state_hash();
    assert_ne!(hash1, hash2);
}

// ===========================================================================
// Section 15: Merge snapshot
// ===========================================================================

#[test]
fn merge_snapshot_adopts_newer_versions() {
    let c = ctx();
    let mut local = ModuleCache::new();
    let mut remote = ModuleCache::new();

    let v1 = fp("s", 1, 1);
    let v2 = fp("s", 2, 1);

    insert_module(&mut local, "mod:m", v1.clone(), "a1", "/m.js").unwrap();
    insert_module(&mut remote, "mod:m", v2.clone(), "a2", "/m.js").unwrap();

    let remote_snap = remote.snapshot();
    local.merge_snapshot(&remote_snap, &c);

    assert!(local.get("mod:m", &v1).is_none());
    assert!(local.get("mod:m", &v2).is_some());
}

#[test]
fn merge_snapshot_converges_revocation() {
    let c = ctx();
    let mut a = ModuleCache::new();
    let mut b = ModuleCache::new();

    let v = fp("s", 1, 1);
    insert_module(&mut a, "mod:c", v, "a", "/c.js").unwrap();
    b.invalidate_trust_revocation("mod:c", 2, &c);

    let b_snap = b.snapshot();
    a.merge_snapshot(&b_snap, &c);

    let a_snap = a.snapshot();
    b.merge_snapshot(&a_snap, &c);

    assert_eq!(a.state_hash(), b.state_hash());
    assert!(a.snapshot().revoked_modules.contains("mod:c"));
    assert!(b.snapshot().revoked_modules.contains("mod:c"));
}

#[test]
fn merge_preserves_local_newer_version() {
    let c = ctx();
    let mut local = ModuleCache::new();
    let mut remote = ModuleCache::new();

    let v_newer = fp("s", 5, 5);
    let v_older = fp("s", 2, 2);

    insert_module(&mut local, "mod:m", v_newer.clone(), "a-new", "/m.js").unwrap();
    insert_module(&mut remote, "mod:m", v_older, "a-old", "/m.js").unwrap();

    let remote_snap = remote.snapshot();
    local.merge_snapshot(&remote_snap, &c);

    // Local should keep its newer version
    assert!(local.get("mod:m", &v_newer).is_some());
}

#[test]
fn merge_snapshot_adds_new_modules_from_remote() {
    let c = ctx();
    let mut local = ModuleCache::new();
    let mut remote = ModuleCache::new();

    insert_module(&mut local, "mod:local", fp("l", 1, 1), "al", "/l.js").unwrap();
    insert_module(&mut remote, "mod:remote", fp("r", 1, 1), "ar", "/r.js").unwrap();

    let remote_snap = remote.snapshot();
    local.merge_snapshot(&remote_snap, &c);

    assert!(local.get("mod:local", &fp("l", 1, 1)).is_some());
    assert!(local.get("mod:remote", &fp("r", 1, 1)).is_some());
}

#[test]
fn merge_does_not_import_revoked_entries() {
    let c = ctx();
    let mut local = ModuleCache::new();
    let mut remote = ModuleCache::new();

    let v = fp("s", 1, 1);
    insert_module(&mut remote, "mod:r", v.clone(), "a", "/r.js").unwrap();

    // Revoke in local before merge
    local.invalidate_trust_revocation("mod:r", 2, &c);

    let remote_snap = remote.snapshot();
    local.merge_snapshot(&remote_snap, &c);

    // Entry should not appear because module is revoked locally
    assert!(local.get("mod:r", &v).is_none());
    assert!(local.snapshot().revoked_modules.contains("mod:r"));
}

// ===========================================================================
// Section 16: State hash determinism
// ===========================================================================

#[test]
fn identical_operation_sequences_produce_identical_state_hash() {
    let build = || {
        let mut cache = ModuleCache::new();
        let c = ctx();
        insert_module(&mut cache, "mod:x", fp("s1", 1, 1), "ax", "/x.js").unwrap();
        cache.invalidate_policy_change("mod:x", 2, &c);
        insert_module(&mut cache, "mod:x", fp("s1", 2, 1), "ax2", "/x.js").unwrap();
        cache.state_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn different_operations_produce_different_state_hash() {
    let mut cache_a = ModuleCache::new();
    let mut cache_b = ModuleCache::new();

    insert_module(&mut cache_a, "mod:a", fp("sa", 1, 1), "aa", "/a.js").unwrap();
    insert_module(&mut cache_b, "mod:b", fp("sb", 1, 1), "ab", "/b.js").unwrap();

    assert_ne!(cache_a.state_hash(), cache_b.state_hash());
}

// ===========================================================================
// Section 17: Event audit trail
// ===========================================================================

#[test]
fn events_empty_on_new_cache() {
    let cache = ModuleCache::new();
    assert!(cache.events().is_empty());
}

#[test]
fn insert_emits_event() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:e", fp("s", 1, 1), "a", "/e.js").unwrap();
    assert!(!cache.events().is_empty());

    let last = cache.events().last().unwrap();
    assert_eq!(last.component, "module_cache");
    assert_eq!(last.module_id, "mod:e");
}

#[test]
fn events_carry_context_fields() {
    let mut cache = ModuleCache::new();
    let c = CacheContext::new("my-trace", "my-decision", "my-policy");
    cache.invalidate_trust_revocation("mod:ctx", 1, &c);

    let event = cache.events().last().unwrap();
    assert_eq!(event.trace_id, "my-trace");
    assert_eq!(event.decision_id, "my-decision");
    assert_eq!(event.policy_id, "my-policy");
    assert_eq!(event.component, "module_cache");
}

#[test]
fn event_sequences_are_monotonically_increasing() {
    let mut cache = ModuleCache::new();
    let c = ctx();
    insert_module(&mut cache, "mod:e1", fp("s", 1, 1), "a", "/e1.js").unwrap();
    cache.invalidate_trust_revocation("mod:e1", 2, &c);
    cache.restore_trust("mod:e1", 3, &c);
    insert_module(&mut cache, "mod:e2", fp("s2", 1, 1), "a2", "/e2.js").unwrap();
    cache.invalidate_source_update("mod:e2", source_hash("new"), &c);
    cache.invalidate_policy_change("mod:e2", 5, &c);

    let seqs: Vec<u64> = cache.events().iter().map(|e| e.seq).collect();
    assert!(
        seqs.len() >= 4,
        "expected multiple events, got {}",
        seqs.len()
    );
    for window in seqs.windows(2) {
        assert!(
            window[1] > window[0],
            "event seqs must be monotonically increasing: {seqs:?}"
        );
    }
}

#[test]
fn error_events_are_recorded_even_on_failure() {
    let mut cache = ModuleCache::new();
    let _ = cache.insert(
        CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
        &ctx(),
    );
    // Even though insert failed, an event should have been recorded
    assert!(!cache.events().is_empty());
    let last = cache.events().last().unwrap();
    assert!(
        last.error_code.contains("MODCACHE"),
        "error_code: {}",
        last.error_code
    );
}

#[test]
fn revocation_event_records_module_id() {
    let mut cache = ModuleCache::new();
    cache.invalidate_trust_revocation("mod:tracked", 1, &ctx());
    let event = cache.events().last().unwrap();
    assert_eq!(event.module_id, "mod:tracked");
}

// ===========================================================================
// Section 18: Serde round-trips
// ===========================================================================

#[test]
fn cache_error_code_serde_round_trip() {
    let codes = [
        CacheErrorCode::ModuleRevoked,
        CacheErrorCode::VersionRegression,
        CacheErrorCode::EmptyModuleId,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let decoded: CacheErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, code);
    }
}

#[test]
fn module_version_fingerprint_serde_round_trip() {
    let v = fp("serde-test", 42, 7);
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ModuleVersionFingerprint = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn module_cache_key_serde_round_trip() {
    let key = ModuleCacheKey::new("mod:serde", fp("k", 3, 5));
    let json = serde_json::to_string(&key).unwrap();
    let decoded: ModuleCacheKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, decoded);
}

#[test]
fn cache_insert_request_serde_round_trip() {
    let req = CacheInsertRequest::new("mod:req", fp("r", 1, 2), artifact_hash("art"), "/req.js");
    let json = serde_json::to_string(&req).unwrap();
    let decoded: CacheInsertRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, decoded);
}

#[test]
fn cache_context_serde_round_trip() {
    let c = CacheContext::new("trace-serde", "decision-serde", "policy-serde");
    let json = serde_json::to_string(&c).unwrap();
    let decoded: CacheContext = serde_json::from_str(&json).unwrap();
    assert_eq!(c, decoded);
}

#[test]
fn cache_snapshot_serde_round_trip() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:snap", fp("s", 1, 1), "a", "/snap.js").unwrap();
    cache.invalidate_trust_revocation("mod:revoked", 2, &ctx());

    let snap = cache.snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let decoded: CacheSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, decoded);
}

#[test]
fn cache_event_serde_round_trip() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:ev", fp("s", 1, 1), "a", "/ev.js").unwrap();

    let event = cache.events().last().unwrap().clone();
    let json = serde_json::to_string(&event).unwrap();
    let decoded: CacheEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn module_cache_entry_serde_round_trip() {
    let mut cache = ModuleCache::new();
    let v = fp("entry", 3, 7);
    insert_module(&mut cache, "mod:ent", v.clone(), "art-ent", "/ent.js").unwrap();
    let entry = cache.get("mod:ent", &v).unwrap().clone();
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: ModuleCacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn cache_error_serde_round_trip() {
    let mut cache = ModuleCache::new();
    let err = cache
        .insert(
            CacheInsertRequest::new("", fp("v", 1, 1), artifact_hash("a"), "/e.js"),
            &ctx(),
        )
        .unwrap_err();
    let json = serde_json::to_string(err.as_ref()).unwrap();
    let decoded: CacheError = serde_json::from_str(&json).unwrap();
    assert_eq!(*err, decoded);
}

/// Note: `ModuleCache` contains `BTreeMap<ModuleCacheKey, _>` which cannot
/// round-trip through JSON because `ModuleCacheKey` is not a string key.
/// This is a known serde limitation; use `CacheSnapshot` for serialization
/// instead (tested above in `cache_snapshot_serde_round_trip`).
#[test]
fn module_cache_json_serialization_fails_due_to_non_string_key() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:a", fp("sa", 1, 1), "aa", "/a.js").unwrap();
    let result = serde_json::to_string(&cache);
    assert!(
        result.is_err(),
        "BTreeMap<ModuleCacheKey, _> cannot serialize to JSON"
    );
}

// ===========================================================================
// Section 19: Deterministic replay
// ===========================================================================

#[test]
fn replay_identical_sequences_produce_identical_state() {
    let build = || {
        let mut cache = ModuleCache::new();
        let c = ctx();
        insert_module(&mut cache, "mod:a", fp("sa", 1, 1), "aa", "/a.js").unwrap();
        insert_module(&mut cache, "mod:b", fp("sb", 1, 1), "ab", "/b.js").unwrap();
        cache.invalidate_source_update("mod:a", source_hash("sa-new"), &c);
        let v2 = ModuleVersionFingerprint::new(source_hash("sa-new"), 1, 1);
        insert_module(&mut cache, "mod:a", v2, "aa2", "/a.js").unwrap();
        cache.invalidate_trust_revocation("mod:b", 2, &c);
        cache.restore_trust("mod:b", 3, &c);
        insert_module(&mut cache, "mod:b", fp("sb2", 1, 3), "ab2", "/b.js").unwrap();
        cache
    };

    let c1 = build();
    let c2 = build();
    assert_eq!(c1.state_hash(), c2.state_hash());
    assert_eq!(c1.snapshot(), c2.snapshot());
}

#[test]
fn snapshot_merge_is_idempotent() {
    let c = ctx();
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:a", fp("s", 1, 1), "a", "/a.js").unwrap();

    let snap = cache.snapshot();
    let hash_before = cache.state_hash();

    cache.merge_snapshot(&snap, &c);
    // Merging the same snapshot should not change state hash
    assert_eq!(cache.state_hash(), hash_before);
}

// ===========================================================================
// Section 20: Complex multi-module scenarios
// ===========================================================================

#[test]
fn fleet_convergence_scenario() {
    // Simulate two fleet nodes independently inserting and then merging
    let c = ctx();
    let mut node_a = ModuleCache::new();
    let mut node_b = ModuleCache::new();

    // Node A inserts mod:x and mod:y
    insert_module(&mut node_a, "mod:x", fp("x1", 1, 1), "ax1", "/x.js").unwrap();
    insert_module(&mut node_a, "mod:y", fp("y1", 1, 1), "ay1", "/y.js").unwrap();

    // Node B inserts mod:y (newer) and mod:z
    insert_module(&mut node_b, "mod:y", fp("y2", 2, 1), "ay2", "/y.js").unwrap();
    insert_module(&mut node_b, "mod:z", fp("z1", 1, 1), "az1", "/z.js").unwrap();

    // Exchange snapshots
    let snap_a = node_a.snapshot();
    let snap_b = node_b.snapshot();

    node_a.merge_snapshot(&snap_b, &c);
    node_b.merge_snapshot(&snap_a, &c);

    // Both nodes should converge
    assert_eq!(node_a.state_hash(), node_b.state_hash());

    // Both should have mod:x, mod:y (v2), mod:z
    assert!(node_a.get("mod:x", &fp("x1", 1, 1)).is_some());
    assert!(node_a.get("mod:y", &fp("y2", 2, 1)).is_some());
    assert!(node_a.get("mod:z", &fp("z1", 1, 1)).is_some());
    assert!(node_b.get("mod:x", &fp("x1", 1, 1)).is_some());
    assert!(node_b.get("mod:y", &fp("y2", 2, 1)).is_some());
    assert!(node_b.get("mod:z", &fp("z1", 1, 1)).is_some());
}

#[test]
fn cascade_invalidation_scenario() {
    let mut cache = ModuleCache::new();
    let c = ctx();

    // Insert 5 modules
    for i in 0..5 {
        let name = format!("mod:m{i}");
        insert_module(
            &mut cache,
            &name,
            fp(&format!("s{i}"), 1, 1),
            &format!("a{i}"),
            &format!("/{i}.js"),
        )
        .unwrap();
    }
    assert_eq!(cache.snapshot().entries.len(), 5);

    // Source update on m0
    cache.invalidate_source_update("mod:m0", source_hash("s0-new"), &c);
    // Policy change on m1
    cache.invalidate_policy_change("mod:m1", 2, &c);
    // Trust revocation on m2
    cache.invalidate_trust_revocation("mod:m2", 2, &c);

    // m3, m4 should be unaffected
    assert!(cache.get("mod:m3", &fp("s3", 1, 1)).is_some());
    assert!(cache.get("mod:m4", &fp("s4", 1, 1)).is_some());

    // m0, m1, m2 should be gone
    assert!(cache.get("mod:m0", &fp("s0", 1, 1)).is_none());
    assert!(cache.get("mod:m1", &fp("s1", 1, 1)).is_none());
    assert!(cache.get("mod:m2", &fp("s2", 1, 1)).is_none());

    // Entries: m3 and m4 remain
    assert_eq!(cache.snapshot().entries.len(), 2);
}

#[test]
fn inserted_seq_advances_per_insert() {
    let mut cache = ModuleCache::new();
    insert_module(&mut cache, "mod:a", fp("a", 1, 1), "aa", "/a.js").unwrap();
    insert_module(&mut cache, "mod:b", fp("b", 1, 1), "ab", "/b.js").unwrap();
    insert_module(&mut cache, "mod:c", fp("c", 1, 1), "ac", "/c.js").unwrap();

    let snap = cache.snapshot();
    let seqs: Vec<u64> = snap.entries.iter().map(|e| e.inserted_seq).collect();
    // All insert_seq values should be unique
    let unique: BTreeSet<u64> = seqs.iter().copied().collect();
    assert_eq!(
        unique.len(),
        seqs.len(),
        "inserted_seq values must be unique"
    );
}

#[test]
fn s3fifo_baseline_report_round_trips_via_public_api() {
    let manifest = CacheTraceCorpusManifest::new(
        "corpus.integration",
        vec![CacheTraceCase {
            trace_id: "trace.integration".to_string(),
            workload_class: CacheWorkloadClass::PackageGraph,
            accesses: vec![
                CacheTraceAccess {
                    sequence: 1,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Hot,
                },
                CacheTraceAccess {
                    sequence: 2,
                    key: trace_key("mod:b", "s2", 1, 1),
                    locality: CacheLocalityClass::Warm,
                },
                CacheTraceAccess {
                    sequence: 3,
                    key: trace_key("mod:a", "s1", 1, 1),
                    locality: CacheLocalityClass::Hot,
                },
                CacheTraceAccess {
                    sequence: 4,
                    key: trace_key("mod:c", "s3", 1, 1),
                    locality: CacheLocalityClass::Scan,
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
    report.validate(&manifest).unwrap();

    let json = serde_json::to_string_pretty(&report).unwrap();
    let recovered: CachePolicyBaselineReport = serde_json::from_str(&json).unwrap();
    recovered.validate(&manifest).unwrap();
    assert_eq!(recovered.baseline_policy_name, "single_queue_fifo");
    assert_eq!(recovered.candidate_policy_name, "s3_fifo");
}

#[test]
fn s3fifo_baseline_rejects_corrupted_manifest_hash() {
    let mut manifest = CacheTraceCorpusManifest::new(
        "corpus.corrupt",
        vec![CacheTraceCase {
            trace_id: "trace.corrupt".to_string(),
            workload_class: CacheWorkloadClass::ScanHeavy,
            accesses: vec![CacheTraceAccess {
                sequence: 1,
                key: trace_key("mod:a", "s1", 1, 1),
                locality: CacheLocalityClass::Warm,
            }],
        }],
    )
    .unwrap();
    manifest.corpus_hash = ContentHash::compute(b"tampered-manifest");

    let err = evaluate_s3fifo_baseline(
        &manifest,
        &SingleQueueFifoConfig {
            capacity_entries: 1,
        },
        &S3FifoConfig {
            resident_capacity_entries: 2,
            small_queue_entries: 1,
            ghost_queue_entries: 2,
        },
        &S3FifoAdoptionWedgeContract::default(),
    )
    .unwrap_err();

    match err {
        CachePolicyReportError::CorpusHashMismatch { .. } => {}
        other => panic!("unexpected error: {other}"),
    }
}
