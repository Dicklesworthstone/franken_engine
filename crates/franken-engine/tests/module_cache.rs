#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheError, CacheErrorCode, CacheInsertRequest, CacheSnapshot, ModuleCache,
    ModuleCacheEntry, ModuleCacheKey, ModuleVersionFingerprint,
};
use frankenengine_engine::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleRequest,
    ModuleResolver, ModuleSyntax, ResolutionContext,
};

fn resolver_context() -> ResolutionContext {
    ResolutionContext::new("trace-resolve", "decision-resolve", "policy-resolve")
}

fn cache_context() -> CacheContext {
    CacheContext::new("trace-cache", "decision-cache", "policy-cache")
}

#[test]
fn revocation_invalidation_blocks_cached_execution_until_restore() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver
        .register_workspace_module(
            "/app/main.mjs",
            ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
        )
        .unwrap();

    let request = ModuleRequest::new("/app/main.mjs", ImportStyle::Import);
    let resolved = resolver
        .resolve(&request, &resolver_context(), &AllowAllPolicy)
        .unwrap();

    let module_id = resolved.module.record.id.clone();
    let source_hash = resolved.module.record.canonical_hash();

    let mut cache = ModuleCache::new();
    let v1 = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                v1.clone(),
                resolved.module.content_hash,
                resolved.module.canonical_specifier.clone(),
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get(&module_id, &v1).is_some());

    cache.invalidate_trust_revocation(&module_id, 2, &cache_context());
    assert!(cache.get(&module_id, &v1).is_none());

    let blocked = cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                ModuleVersionFingerprint::new(source_hash.clone(), 1, 2),
                ContentHash::compute(b"artifact-blocked"),
                "/app/main.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(blocked.code, CacheErrorCode::ModuleRevoked);

    cache.restore_trust(&module_id, 3, &cache_context());

    let resolved_again = resolver
        .resolve(&request, &resolver_context(), &AllowAllPolicy)
        .unwrap();
    let v3 = ModuleVersionFingerprint::new(source_hash, 1, 3);
    cache
        .insert(
            CacheInsertRequest::new(
                module_id.clone(),
                v3.clone(),
                resolved_again.module.content_hash,
                resolved_again.module.canonical_specifier,
            ),
            &cache_context(),
        )
        .unwrap();

    assert!(cache.get(&module_id, &v3).is_some());
}

#[test]
fn snapshot_merge_propagates_policy_and_revocation_changes() {
    let mut a = ModuleCache::new();
    let mut b = ModuleCache::new();

    let module_id = "mod:shared";
    let source_hash = ContentHash::compute(b"source-shared");

    a.insert(
        CacheInsertRequest::new(
            module_id,
            ModuleVersionFingerprint::new(source_hash, 1, 1),
            ContentHash::compute(b"artifact-shared"),
            "/app/shared.js",
        ),
        &cache_context(),
    )
    .unwrap();

    b.invalidate_policy_change(module_id, 2, &cache_context());
    b.invalidate_trust_revocation(module_id, 3, &cache_context());

    let b_snapshot = b.snapshot();
    a.merge_snapshot(&b_snapshot, &cache_context());

    let a_snapshot = a.snapshot();
    b.merge_snapshot(&a_snapshot, &cache_context());

    assert_eq!(a.state_hash(), b.state_hash());
    assert!(
        a.snapshot().revoked_modules.contains(module_id)
            && b.snapshot().revoked_modules.contains(module_id)
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: cache lifecycle, error paths, serde
// ────────────────────────────────────────────────────────────

#[test]
fn empty_cache_get_returns_none() {
    let cache = ModuleCache::new();
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"x"), 1, 1);
    assert!(cache.get("nonexistent-mod", &v).is_none());
}

#[test]
fn insert_and_get_round_trip() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"round-trip");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:rt",
                v.clone(),
                ContentHash::compute(b"artifact-rt"),
                "/app/rt.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    let entry = cache.get("mod:rt", &v).expect("should be cached");
    assert_eq!(entry.resolved_specifier, "/app/rt.mjs");
}

#[test]
fn invalidate_source_update_removes_entry() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"source-inv");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:inv",
                v.clone(),
                ContentHash::compute(b"artifact-inv"),
                "/app/inv.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:inv", &v).is_some());

    cache.invalidate_source_update(
        "mod:inv",
        ContentHash::compute(b"new-source"),
        &cache_context(),
    );
    assert!(cache.get("mod:inv", &v).is_none());
}

#[test]
fn invalidate_policy_change_removes_entry() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"source-pol");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:pol",
                v.clone(),
                ContentHash::compute(b"artifact-pol"),
                "/app/pol.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:pol", &v).is_some());

    cache.invalidate_policy_change("mod:pol", 2, &cache_context());
    assert!(cache.get("mod:pol", &v).is_none());
}

#[test]
fn state_hash_changes_on_insert() {
    let mut cache = ModuleCache::new();
    let h0 = cache.state_hash();

    let source_hash = ContentHash::compute(b"src-h1");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:h1",
                v,
                ContentHash::compute(b"artifact-h1"),
                "/app/h1.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    let h1 = cache.state_hash();

    assert_ne!(h0, h1);
}

#[test]
fn state_hash_is_deterministic() {
    let make_cache = || {
        let mut cache = ModuleCache::new();
        let source_hash = ContentHash::compute(b"deterministic");
        let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    "mod:det",
                    v,
                    ContentHash::compute(b"artifact-det"),
                    "/app/det.mjs",
                ),
                &cache_context(),
            )
            .unwrap();
        cache
    };

    assert_eq!(make_cache().state_hash(), make_cache().state_hash());
}

#[test]
fn events_are_recorded_on_insert() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"events");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:ev",
                v,
                ContentHash::compute(b"artifact-ev"),
                "/app/ev.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    assert!(!cache.events().is_empty());
    let event = cache.events().last().expect("event");
    assert_eq!(event.trace_id, "trace-cache");
}

#[test]
fn cache_error_code_stable_codes() {
    assert_eq!(
        CacheErrorCode::ModuleRevoked.stable_code(),
        "FE-MODCACHE-0001"
    );
    assert_eq!(
        CacheErrorCode::VersionRegression.stable_code(),
        "FE-MODCACHE-0002"
    );
}

#[test]
fn cache_serde_round_trip_via_snapshot() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"serde-snap");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:serde",
                v.clone(),
                ContentHash::compute(b"artifact-serde"),
                "/app/serde.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    let snapshot = cache.snapshot();
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    let recovered: frankenengine_engine::module_cache::CacheSnapshot =
        serde_json::from_str(&json).expect("deserialize snapshot");
    assert_eq!(snapshot.entries.len(), recovered.entries.len());
}

#[test]
fn module_version_fingerprint_serde_round_trip() {
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"fp"), 5, 3);
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: ModuleVersionFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
}

#[test]
fn restore_trust_after_revocation_allows_new_inserts() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"trust-restore");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);

    cache
        .insert(
            CacheInsertRequest::new(
                "mod:trust",
                v.clone(),
                ContentHash::compute(b"art-trust"),
                "/app/trust.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Revoke
    cache.invalidate_trust_revocation("mod:trust", 2, &cache_context());
    assert!(cache.get("mod:trust", &v).is_none());

    // Restore
    cache.restore_trust("mod:trust", 3, &cache_context());

    // New insert should succeed
    let v2 = ModuleVersionFingerprint::new(source_hash, 1, 3);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:trust",
                v2.clone(),
                ContentHash::compute(b"art-trust-2"),
                "/app/trust.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:trust", &v2).is_some());
}

// ---------- additional enrichment ----------

#[test]
fn cache_error_serde_roundtrip() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"revoke-serde");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:revoke-serde",
                v,
                ContentHash::compute(b"art"),
                "/app/r.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    cache.invalidate_trust_revocation("mod:revoke-serde", 2, &cache_context());

    let err = cache
        .insert(
            CacheInsertRequest::new(
                "mod:revoke-serde",
                ModuleVersionFingerprint::new(source_hash, 1, 2),
                ContentHash::compute(b"art2"),
                "/app/r.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::ModuleRevoked);

    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: CacheError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.code, CacheErrorCode::ModuleRevoked);
}

#[test]
fn cache_error_is_std_error() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"revoke-std");
    let v = ModuleVersionFingerprint::new(source_hash.clone(), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:revoke-std",
                v,
                ContentHash::compute(b"art"),
                "/app/s.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    cache.invalidate_trust_revocation("mod:revoke-std", 2, &cache_context());

    let err = cache
        .insert(
            CacheInsertRequest::new(
                "mod:revoke-std",
                ModuleVersionFingerprint::new(source_hash, 1, 2),
                ContentHash::compute(b"art2"),
                "/app/s.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
    assert!(dyn_err.to_string().contains("FE-MODCACHE"));
}

#[test]
fn cache_context_serde_roundtrip() {
    let ctx = cache_context();
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: CacheContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-cache");
}

#[test]
fn cache_insert_request_serde_roundtrip() {
    let req = CacheInsertRequest::new(
        "mod:serde-req",
        ModuleVersionFingerprint::new(ContentHash::compute(b"src"), 1, 1),
        ContentHash::compute(b"art"),
        "/app/serde-req.mjs",
    );
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: CacheInsertRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.module_id, "mod:serde-req");
}

#[test]
fn snapshot_empty_cache_has_no_entries() {
    let cache = ModuleCache::new();
    let snapshot = cache.snapshot();
    assert!(snapshot.entries.is_empty());
    assert!(snapshot.revoked_modules.is_empty());
}

#[test]
fn module_version_fingerprint_serde_roundtrip() {
    let fp = ModuleVersionFingerprint::new(ContentHash::compute(b"test"), 1, 2);
    let json = serde_json::to_string(&fp).expect("serialize");
    let recovered: ModuleVersionFingerprint = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.source_hash, fp.source_hash);
}

#[test]
fn cache_error_code_serde_roundtrip() {
    let code = CacheErrorCode::ModuleRevoked;
    let json = serde_json::to_string(&code).expect("serialize");
    let recovered: CacheErrorCode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, code);
}

#[test]
fn new_cache_has_no_events() {
    let cache = ModuleCache::new();
    assert!(cache.events().is_empty());
}

#[test]
fn cache_error_code_debug_is_nonempty() {
    let code = CacheErrorCode::ModuleRevoked;
    assert!(!format!("{code:?}").is_empty());
}

#[test]
fn module_version_fingerprint_debug_is_nonempty() {
    let fp = ModuleVersionFingerprint::new(ContentHash::compute(b"test"), 1, 1);
    assert!(!format!("{fp:?}").is_empty());
}

#[test]
fn cache_context_debug_is_nonempty() {
    let ctx = CacheContext::new("trace-1", "decision-1", "policy-1");
    assert!(!format!("{ctx:?}").is_empty());
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: edge-case coverage
// ────────────────────────────────────────────────────────────

#[test]
fn version_regression_detected_when_older_policy_inserted() {
    let mut cache = ModuleCache::new();
    let source_hash = ContentHash::compute(b"regression-src");

    // Insert version with policy_version=5, trust_revision=2
    let v_new = ModuleVersionFingerprint::new(source_hash.clone(), 5, 2);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:regress",
                v_new.clone(),
                ContentHash::compute(b"art-new"),
                "/app/regress.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:regress", &v_new).is_some());

    // Attempt to insert an older policy_version=3 (trust stays the same)
    let v_old_policy = ModuleVersionFingerprint::new(source_hash.clone(), 3, 2);
    let err = cache
        .insert(
            CacheInsertRequest::new(
                "mod:regress",
                v_old_policy,
                ContentHash::compute(b"art-old-pol"),
                "/app/regress.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::VersionRegression);

    // Attempt to insert an older trust_revision=1 (policy stays the same)
    let v_old_trust = ModuleVersionFingerprint::new(source_hash, 5, 1);
    let err2 = cache
        .insert(
            CacheInsertRequest::new(
                "mod:regress",
                v_old_trust,
                ContentHash::compute(b"art-old-trust"),
                "/app/regress.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err2.code, CacheErrorCode::VersionRegression);

    // Original entry should still be intact
    assert!(cache.get("mod:regress", &v_new).is_some());
}

#[test]
fn multiple_modules_independent_invalidation() {
    let mut cache = ModuleCache::new();

    // Insert two distinct modules
    let src_a = ContentHash::compute(b"src-alpha");
    let src_b = ContentHash::compute(b"src-beta");
    let va = ModuleVersionFingerprint::new(src_a.clone(), 1, 1);
    let vb = ModuleVersionFingerprint::new(src_b.clone(), 1, 1);

    cache
        .insert(
            CacheInsertRequest::new(
                "mod:alpha",
                va.clone(),
                ContentHash::compute(b"art-alpha"),
                "/app/alpha.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:beta",
                vb.clone(),
                ContentHash::compute(b"art-beta"),
                "/app/beta.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    assert!(cache.get("mod:alpha", &va).is_some());
    assert!(cache.get("mod:beta", &vb).is_some());

    // Invalidate only alpha via policy change
    cache.invalidate_policy_change("mod:alpha", 2, &cache_context());
    assert!(cache.get("mod:alpha", &va).is_none());
    // beta is unaffected
    assert!(cache.get("mod:beta", &vb).is_some());

    // Revoke beta; alpha is still just invalidated, not revoked
    cache.invalidate_trust_revocation("mod:beta", 2, &cache_context());
    assert!(cache.get("mod:beta", &vb).is_none());

    // alpha can be re-inserted with bumped policy
    let va2 = ModuleVersionFingerprint::new(src_a, 2, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:alpha",
                va2.clone(),
                ContentHash::compute(b"art-alpha-2"),
                "/app/alpha.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert!(cache.get("mod:alpha", &va2).is_some());

    // beta insert still blocked (revoked)
    let vb2 = ModuleVersionFingerprint::new(src_b, 1, 2);
    let err = cache
        .insert(
            CacheInsertRequest::new(
                "mod:beta",
                vb2,
                ContentHash::compute(b"art-beta-2"),
                "/app/beta.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::ModuleRevoked);
}

#[test]
fn snapshot_merge_both_sides_have_same_module_different_versions() {
    let mut cache_a = ModuleCache::new();
    let mut cache_b = ModuleCache::new();

    let src = ContentHash::compute(b"shared-mod-src");

    // cache_a has version (policy=1, trust=1)
    let v1 = ModuleVersionFingerprint::new(src.clone(), 1, 1);
    cache_a
        .insert(
            CacheInsertRequest::new(
                "mod:shared",
                v1.clone(),
                ContentHash::compute(b"art-v1"),
                "/app/shared.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // cache_b has a newer version (policy=2, trust=1)
    let v2 = ModuleVersionFingerprint::new(src, 2, 1);
    cache_b
        .insert(
            CacheInsertRequest::new(
                "mod:shared",
                v2.clone(),
                ContentHash::compute(b"art-v2"),
                "/app/shared.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Merge b's snapshot into a — b has a newer version so it should win
    let snap_b = cache_b.snapshot();
    cache_a.merge_snapshot(&snap_b, &cache_context());

    // After merge, cache_a should have the newer version entry from b
    // and the old v1 entry should be pruned (stale)
    assert!(cache_a.get("mod:shared", &v1).is_none());
    assert!(cache_a.get("mod:shared", &v2).is_some());

    // The snapshot should show latest_versions pointing at v2
    let snap_a = cache_a.snapshot();
    assert_eq!(snap_a.latest_versions.get("mod:shared"), Some(&v2));
}

#[test]
fn events_accumulate_across_multiple_operations() {
    let mut cache = ModuleCache::new();
    let src = ContentHash::compute(b"event-accum");
    let v1 = ModuleVersionFingerprint::new(src.clone(), 1, 1);

    assert_eq!(cache.events().len(), 0);

    // Insert -> 1 event
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:ev-accum",
                v1,
                ContentHash::compute(b"art-ev"),
                "/app/ev.mjs",
            ),
            &cache_context(),
        )
        .unwrap();
    assert_eq!(cache.events().len(), 1);

    // Source update invalidation -> 2 events
    cache.invalidate_source_update(
        "mod:ev-accum",
        ContentHash::compute(b"new-src"),
        &cache_context(),
    );
    assert_eq!(cache.events().len(), 2);

    // Policy change invalidation -> 3 events
    cache.invalidate_policy_change("mod:ev-accum", 2, &cache_context());
    assert_eq!(cache.events().len(), 3);

    // Trust revocation -> 4 events
    cache.invalidate_trust_revocation("mod:ev-accum", 3, &cache_context());
    assert_eq!(cache.events().len(), 4);

    // Restore trust -> 5 events
    cache.restore_trust("mod:ev-accum", 4, &cache_context());
    assert_eq!(cache.events().len(), 5);

    // Merge snapshot -> 6 events
    let other = ModuleCache::new();
    cache.merge_snapshot(&other.snapshot(), &cache_context());
    assert_eq!(cache.events().len(), 6);

    // Verify monotonic sequence numbers
    for pair in cache.events().windows(2) {
        assert!(pair[1].seq > pair[0].seq, "event seq must be monotonic");
    }
}

#[test]
fn state_hash_differs_for_caches_with_different_modules() {
    let mut cache_x = ModuleCache::new();
    let mut cache_y = ModuleCache::new();

    cache_x
        .insert(
            CacheInsertRequest::new(
                "mod:x-only",
                ModuleVersionFingerprint::new(ContentHash::compute(b"src-x"), 1, 1),
                ContentHash::compute(b"art-x"),
                "/app/x.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    cache_y
        .insert(
            CacheInsertRequest::new(
                "mod:y-only",
                ModuleVersionFingerprint::new(ContentHash::compute(b"src-y"), 1, 1),
                ContentHash::compute(b"art-y"),
                "/app/y.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Different modules => different state hashes
    assert_ne!(cache_x.state_hash(), cache_y.state_hash());

    // Also verify both differ from an empty cache
    let empty = ModuleCache::new();
    assert_ne!(cache_x.state_hash(), empty.state_hash());
    assert_ne!(cache_y.state_hash(), empty.state_hash());
}

#[test]
fn revoked_module_visible_in_snapshot() {
    let mut cache = ModuleCache::new();
    let src = ContentHash::compute(b"revoke-snap");
    let v = ModuleVersionFingerprint::new(src, 1, 1);

    cache
        .insert(
            CacheInsertRequest::new(
                "mod:snap-rev",
                v.clone(),
                ContentHash::compute(b"art-snap-rev"),
                "/app/snap-rev.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Before revocation, snapshot has entry and no revoked modules
    let snap_before = cache.snapshot();
    assert_eq!(snap_before.entries.len(), 1);
    assert!(!snap_before.revoked_modules.contains("mod:snap-rev"));

    // Revoke the module
    cache.invalidate_trust_revocation("mod:snap-rev", 2, &cache_context());

    // After revocation, entries are cleared and module is in revoked set
    let snap_after = cache.snapshot();
    assert!(snap_after.entries.is_empty());
    assert!(snap_after.revoked_modules.contains("mod:snap-rev"));

    // State hash should differ before and after revocation
    assert_ne!(snap_before.state_hash, snap_after.state_hash);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: additional edge-case coverage
// ────────────────────────────────────────────────────────────

#[test]
fn insert_empty_module_id_rejected() {
    let mut cache = ModuleCache::new();
    let src = ContentHash::compute(b"empty-id-src");
    let v = ModuleVersionFingerprint::new(src, 1, 1);
    let err = cache
        .insert(
            CacheInsertRequest::new(
                "",
                v.clone(),
                ContentHash::compute(b"art-empty"),
                "/app/empty.mjs",
            ),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::EmptyModuleId);
    assert_eq!(err.code.stable_code(), "FE-MODCACHE-0003");

    // Whitespace-only module_id should also be rejected
    let err2 = cache
        .insert(
            CacheInsertRequest::new("   ", v, ContentHash::compute(b"art-ws"), "/app/ws.mjs"),
            &cache_context(),
        )
        .unwrap_err();
    assert_eq!(err2.code, CacheErrorCode::EmptyModuleId);
}

#[test]
fn module_cache_key_serde_roundtrip_and_ord() {
    let key_a = ModuleCacheKey::new(
        "mod:alpha",
        ModuleVersionFingerprint::new(ContentHash::compute(b"src-a"), 1, 1),
    );
    let key_b = ModuleCacheKey::new(
        "mod:beta",
        ModuleVersionFingerprint::new(ContentHash::compute(b"src-b"), 2, 1),
    );

    // Serde roundtrip
    let json_a = serde_json::to_string(&key_a).expect("serialize key_a");
    let recovered_a: ModuleCacheKey = serde_json::from_str(&json_a).expect("deserialize key_a");
    assert_eq!(key_a, recovered_a);

    // Ord: keys are orderable (BTreeMap requirement)
    let ordering = key_a.cmp(&key_b);
    assert!(
        ordering != std::cmp::Ordering::Equal,
        "distinct keys should not be equal"
    );

    // Deterministic ordering: compare twice
    assert_eq!(key_a.cmp(&key_b), key_a.cmp(&key_b));
}

#[test]
fn module_cache_entry_serde_roundtrip() {
    let mut cache = ModuleCache::new();
    let src = ContentHash::compute(b"entry-serde");
    let v = ModuleVersionFingerprint::new(src, 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:entry-serde",
                v.clone(),
                ContentHash::compute(b"art-entry-serde"),
                "/app/entry-serde.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    let entry = cache.get("mod:entry-serde", &v).expect("entry must exist");
    let json = serde_json::to_string(entry).expect("serialize entry");
    let recovered: ModuleCacheEntry = serde_json::from_str(&json).expect("deserialize entry");
    assert_eq!(recovered.key.module_id, "mod:entry-serde");
    assert_eq!(recovered.resolved_specifier, "/app/entry-serde.mjs");
    assert_eq!(
        recovered.artifact_hash,
        ContentHash::compute(b"art-entry-serde")
    );
}

#[test]
fn cache_snapshot_full_serde_roundtrip() {
    let mut cache = ModuleCache::new();
    let src = ContentHash::compute(b"snap-full");
    let v = ModuleVersionFingerprint::new(src, 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:snap-full",
                v,
                ContentHash::compute(b"art-snap-full"),
                "/app/snap-full.mjs",
            ),
            &cache_context(),
        )
        .unwrap();

    // Revoke a different module to populate revoked_modules
    cache.invalidate_trust_revocation("mod:some-revoked", 2, &cache_context());

    let snapshot = cache.snapshot();
    let json = serde_json::to_string(&snapshot).expect("serialize full snapshot");
    let recovered: CacheSnapshot = serde_json::from_str(&json).expect("deserialize full snapshot");

    assert_eq!(recovered.entries.len(), snapshot.entries.len());
    assert_eq!(
        recovered.latest_versions.len(),
        snapshot.latest_versions.len()
    );
    assert!(recovered.revoked_modules.contains("mod:some-revoked"));
    assert_eq!(recovered.state_hash, snapshot.state_hash);
}

#[test]
fn cache_event_fields_populated_correctly() {
    let mut cache = ModuleCache::new();
    let ctx = CacheContext::new("trace-fields", "decision-fields", "policy-fields");
    let src = ContentHash::compute(b"event-fields");
    let v = ModuleVersionFingerprint::new(src, 1, 1);

    cache
        .insert(
            CacheInsertRequest::new(
                "mod:event-fields",
                v,
                ContentHash::compute(b"art-event-fields"),
                "/app/event-fields.mjs",
            ),
            &ctx,
        )
        .unwrap();

    let event = &cache.events()[0];
    assert_eq!(event.trace_id, "trace-fields");
    assert_eq!(event.decision_id, "decision-fields");
    assert_eq!(event.policy_id, "policy-fields");
    assert_eq!(event.module_id, "mod:event-fields");
    assert_eq!(event.component, "module_cache");
    assert_eq!(event.event, "cache_insert");
    assert_eq!(event.outcome, "allow");
    assert_eq!(event.error_code, "none");
    assert!(!event.detail.is_empty());

    // Serde roundtrip for CacheEvent
    let json = serde_json::to_string(event).expect("serialize event");
    let recovered: frankenengine_engine::module_cache::CacheEvent =
        serde_json::from_str(&json).expect("deserialize event");
    assert_eq!(recovered.seq, event.seq);
    assert_eq!(recovered.trace_id, event.trace_id);
    assert_eq!(recovered.module_id, event.module_id);
}
