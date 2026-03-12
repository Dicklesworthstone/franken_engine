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
    let v1 = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
                ModuleVersionFingerprint::new(source_hash, 1, 2),
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
        let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);

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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v = ModuleVersionFingerprint::new(source_hash, 1, 1);
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
    let v_new = ModuleVersionFingerprint::new(source_hash, 5, 2);
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
    let v_old_policy = ModuleVersionFingerprint::new(source_hash, 3, 2);
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
    let va = ModuleVersionFingerprint::new(src_a, 1, 1);
    let vb = ModuleVersionFingerprint::new(src_b, 1, 1);

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
    let v1 = ModuleVersionFingerprint::new(src, 1, 1);
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
    let v1 = ModuleVersionFingerprint::new(src, 1, 1);

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

// ────────────────────────────────────────────────────────────
// Enrichment: CacheWorkloadClass, CacheLocalityClass, CachePolicyKind
// ────────────────────────────────────────────────────────────

use frankenengine_engine::module_cache::{
    AdaptiveSplitConfig, AdmissionVerdict, CacheLocalityClass, CachePolicyAggregateSummary,
    CachePolicyCaseReport, CachePolicyKind, CachePolicyMetrics, CachePolicyReportError,
    CacheTraceAccess, CacheTraceCase, CacheTraceCorpusManifest, CacheWorkloadClass,
    S3FifoAdaptiveConfig, S3FifoAdaptiveMetrics, S3FifoAdoptionWedgeContract, S3FifoConfig,
    SingleQueueFifoConfig, ValueAdmissionConfig, ValueAnnotatedTraceAccess,
    ValueAnnotatedTraceCase,
};

fn make_trace_key(module_id: &str, seed: &str, pv: u64, tr: u64) -> ModuleCacheKey {
    ModuleCacheKey::new(
        module_id,
        ModuleVersionFingerprint::new(ContentHash::compute(seed.as_bytes()), pv, tr),
    )
}

#[test]
fn cache_workload_class_as_str_all_variants() {
    assert_eq!(CacheWorkloadClass::ColdCompile.as_str(), "cold_compile");
    assert_eq!(CacheWorkloadClass::WarmRun.as_str(), "warm_run");
    assert_eq!(CacheWorkloadClass::PackageGraph.as_str(), "package_graph");
    assert_eq!(CacheWorkloadClass::ReactApp.as_str(), "react_app");
    assert_eq!(CacheWorkloadClass::ScanHeavy.as_str(), "scan_heavy");
}

#[test]
fn cache_workload_class_serde_roundtrip_all_variants() {
    let variants = [
        CacheWorkloadClass::ColdCompile,
        CacheWorkloadClass::WarmRun,
        CacheWorkloadClass::PackageGraph,
        CacheWorkloadClass::ReactApp,
        CacheWorkloadClass::ScanHeavy,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let recovered: CacheWorkloadClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, v);
    }
}

#[test]
fn cache_workload_class_serde_uses_snake_case() {
    assert_eq!(
        serde_json::to_string(&CacheWorkloadClass::ColdCompile).unwrap(),
        "\"cold_compile\""
    );
    assert_eq!(
        serde_json::to_string(&CacheWorkloadClass::PackageGraph).unwrap(),
        "\"package_graph\""
    );
    assert_eq!(
        serde_json::to_string(&CacheWorkloadClass::ScanHeavy).unwrap(),
        "\"scan_heavy\""
    );
}

#[test]
fn cache_workload_class_debug_distinct() {
    let variants = [
        CacheWorkloadClass::ColdCompile,
        CacheWorkloadClass::WarmRun,
        CacheWorkloadClass::PackageGraph,
        CacheWorkloadClass::ReactApp,
        CacheWorkloadClass::ScanHeavy,
    ];
    let debugs: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn cache_locality_class_as_str_all_variants() {
    assert_eq!(CacheLocalityClass::Hot.as_str(), "hot");
    assert_eq!(CacheLocalityClass::Warm.as_str(), "warm");
    assert_eq!(CacheLocalityClass::Scan.as_str(), "scan");
}

#[test]
fn cache_locality_class_default_is_warm() {
    let default_locality = CacheLocalityClass::default();
    assert_eq!(default_locality, CacheLocalityClass::Warm);
    assert_eq!(default_locality.as_str(), "warm");
}

#[test]
fn cache_locality_class_serde_roundtrip_all_variants() {
    let variants = [
        CacheLocalityClass::Hot,
        CacheLocalityClass::Warm,
        CacheLocalityClass::Scan,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let recovered: CacheLocalityClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, v);
    }
}

#[test]
fn cache_locality_class_serde_uses_snake_case() {
    assert_eq!(
        serde_json::to_string(&CacheLocalityClass::Hot).unwrap(),
        "\"hot\""
    );
    assert_eq!(
        serde_json::to_string(&CacheLocalityClass::Warm).unwrap(),
        "\"warm\""
    );
    assert_eq!(
        serde_json::to_string(&CacheLocalityClass::Scan).unwrap(),
        "\"scan\""
    );
}

#[test]
fn cache_policy_kind_as_str_all_variants() {
    assert_eq!(
        CachePolicyKind::SingleQueueFifo.as_str(),
        "single_queue_fifo"
    );
    assert_eq!(CachePolicyKind::S3Fifo.as_str(), "s3_fifo");
}

#[test]
fn cache_policy_kind_serde_roundtrip_all_variants() {
    let variants = [CachePolicyKind::SingleQueueFifo, CachePolicyKind::S3Fifo];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let recovered: CachePolicyKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(&recovered, v);
    }
}

#[test]
fn cache_policy_kind_serde_uses_snake_case() {
    assert_eq!(
        serde_json::to_string(&CachePolicyKind::SingleQueueFifo).unwrap(),
        "\"single_queue_fifo\""
    );
    assert_eq!(
        serde_json::to_string(&CachePolicyKind::S3Fifo).unwrap(),
        "\"s3_fifo\""
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: CacheTraceAccess serde
// ────────────────────────────────────────────────────────────

#[test]
fn cache_trace_access_serde_roundtrip() {
    let access = CacheTraceAccess {
        sequence: 42,
        key: make_trace_key("mod:trace-access", "seed-ta", 3, 7),
        locality: CacheLocalityClass::Hot,
    };
    let json = serde_json::to_string(&access).expect("serialize");
    let recovered: CacheTraceAccess = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.sequence, 42);
    assert_eq!(recovered.key.module_id, "mod:trace-access");
    assert_eq!(recovered.locality, CacheLocalityClass::Hot);
}

#[test]
fn cache_trace_access_default_locality_is_warm() {
    // The serde(default) on locality means missing field defaults to Warm
    let json = r#"{"sequence":1,"key":{"module_id":"m","version":{"source_hash":"0000000000000000000000000000000000000000000000000000000000000000","policy_version":1,"trust_revision":1}}}"#;
    let access: CacheTraceAccess = serde_json::from_str(json).expect("deserialize");
    assert_eq!(access.locality, CacheLocalityClass::Warm);
}

// ────────────────────────────────────────────────────────────
// Enrichment: CacheTraceCase validation
// ────────────────────────────────────────────────────────────

#[test]
fn cache_trace_case_serde_roundtrip() {
    let case = CacheTraceCase {
        trace_id: "trace-case-serde".to_string(),
        workload_class: CacheWorkloadClass::ReactApp,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:serde-case", "seed-sc", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let json = serde_json::to_string(&case).expect("serialize");
    let recovered: CacheTraceCase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-case-serde");
    assert_eq!(recovered.workload_class, CacheWorkloadClass::ReactApp);
    assert_eq!(recovered.accesses.len(), 1);
}

// ────────────────────────────────────────────────────────────
// Enrichment: CacheTraceCorpusManifest
// ────────────────────────────────────────────────────────────

#[test]
fn corpus_manifest_rejects_empty_corpus_id() {
    let case = CacheTraceCase {
        trace_id: "t1".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:a", "s1", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let err = CacheTraceCorpusManifest::new("", vec![case]).unwrap_err();
    match err {
        CachePolicyReportError::EmptyCorpusId => {}
        other => panic!("expected EmptyCorpusId, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_empty_cases() {
    let err = CacheTraceCorpusManifest::new("corpus.empty", vec![]).unwrap_err();
    match err {
        CachePolicyReportError::EmptyCorpusCases => {}
        other => panic!("expected EmptyCorpusCases, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_empty_trace_id() {
    let case = CacheTraceCase {
        trace_id: "  ".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:a", "s1", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let err = CacheTraceCorpusManifest::new("corpus.empty-tid", vec![case]).unwrap_err();
    match err {
        CachePolicyReportError::EmptyTraceId => {}
        other => panic!("expected EmptyTraceId, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_empty_trace_accesses() {
    let case = CacheTraceCase {
        trace_id: "valid-id".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![],
    };
    let err = CacheTraceCorpusManifest::new("corpus.empty-access", vec![case]).unwrap_err();
    match err {
        CachePolicyReportError::EmptyTrace { trace_id } => {
            assert_eq!(trace_id, "valid-id");
        }
        other => panic!("expected EmptyTrace, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_non_monotonic_sequence() {
    let case = CacheTraceCase {
        trace_id: "non-mono".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![
            CacheTraceAccess {
                sequence: 5,
                key: make_trace_key("mod:a", "s1", 1, 1),
                locality: CacheLocalityClass::Warm,
            },
            CacheTraceAccess {
                sequence: 3,
                key: make_trace_key("mod:b", "s2", 1, 1),
                locality: CacheLocalityClass::Warm,
            },
        ],
    };
    let err = CacheTraceCorpusManifest::new("corpus.mono", vec![case]).unwrap_err();
    match err {
        CachePolicyReportError::NonMonotonicTraceSequence {
            trace_id,
            previous,
            actual,
        } => {
            assert_eq!(trace_id, "non-mono");
            assert_eq!(previous, 5);
            assert_eq!(actual, 3);
        }
        other => panic!("expected NonMonotonicTraceSequence, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_duplicate_trace_ids() {
    let case_a = CacheTraceCase {
        trace_id: "dup-id".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:a", "s1", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let case_b = CacheTraceCase {
        trace_id: "dup-id".to_string(),
        workload_class: CacheWorkloadClass::ColdCompile,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:b", "s2", 1, 1),
            locality: CacheLocalityClass::Hot,
        }],
    };
    let err = CacheTraceCorpusManifest::new("corpus.dup", vec![case_a, case_b]).unwrap_err();
    match err {
        CachePolicyReportError::DuplicateTraceId { trace_id } => {
            assert_eq!(trace_id, "dup-id");
        }
        other => panic!("expected DuplicateTraceId, got: {other}"),
    }
}

#[test]
fn corpus_manifest_rejects_empty_module_id_in_trace() {
    let case = CacheTraceCase {
        trace_id: "empty-mod-trace".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("  ", "s1", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let err = CacheTraceCorpusManifest::new("corpus.empty-mod", vec![case]).unwrap_err();
    match err {
        CachePolicyReportError::EmptyModuleIdInTrace { trace_id, sequence } => {
            assert_eq!(trace_id, "empty-mod-trace");
            assert_eq!(sequence, 0);
        }
        other => panic!("expected EmptyModuleIdInTrace, got: {other}"),
    }
}

#[test]
fn corpus_manifest_hash_is_deterministic() {
    let make_case = || CacheTraceCase {
        trace_id: "det-hash".to_string(),
        workload_class: CacheWorkloadClass::ColdCompile,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:det", "seed-det", 1, 1),
            locality: CacheLocalityClass::Warm,
        }],
    };
    let m1 = CacheTraceCorpusManifest::new("corpus.det", vec![make_case()]).unwrap();
    let m2 = CacheTraceCorpusManifest::new("corpus.det", vec![make_case()]).unwrap();
    assert_eq!(m1.corpus_hash, m2.corpus_hash);
}

#[test]
fn corpus_manifest_serde_roundtrip() {
    let case = CacheTraceCase {
        trace_id: "serde-corpus".to_string(),
        workload_class: CacheWorkloadClass::PackageGraph,
        accesses: vec![CacheTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:sc", "seed-sc", 2, 1),
            locality: CacheLocalityClass::Hot,
        }],
    };
    let manifest = CacheTraceCorpusManifest::new("corpus.serde", vec![case]).unwrap();
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: CacheTraceCorpusManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.corpus_id, manifest.corpus_id);
    assert_eq!(recovered.corpus_hash, manifest.corpus_hash);
    assert_eq!(recovered.cases.len(), 1);
}

// ────────────────────────────────────────────────────────────
// Enrichment: SingleQueueFifoConfig / S3FifoConfig
// ────────────────────────────────────────────────────────────

#[test]
fn single_queue_fifo_config_default() {
    let cfg = SingleQueueFifoConfig::default();
    assert_eq!(cfg.capacity_entries, 4);
}

#[test]
fn single_queue_fifo_config_serde_roundtrip() {
    let cfg = SingleQueueFifoConfig {
        capacity_entries: 16,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let recovered: SingleQueueFifoConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.capacity_entries, 16);
}

#[test]
fn s3fifo_config_default() {
    let cfg = S3FifoConfig::default();
    assert_eq!(cfg.resident_capacity_entries, 4);
    assert_eq!(cfg.small_queue_entries, 2);
    assert_eq!(cfg.ghost_queue_entries, 4);
}

#[test]
fn s3fifo_config_main_queue_entries() {
    let cfg = S3FifoConfig {
        resident_capacity_entries: 10,
        small_queue_entries: 3,
        ghost_queue_entries: 5,
    };
    assert_eq!(cfg.main_queue_entries(), 7);
}

#[test]
fn s3fifo_config_main_queue_entries_saturating() {
    let cfg = S3FifoConfig {
        resident_capacity_entries: 2,
        small_queue_entries: 5,
        ghost_queue_entries: 1,
    };
    assert_eq!(cfg.main_queue_entries(), 0);
}

#[test]
fn s3fifo_config_serde_roundtrip() {
    let cfg = S3FifoConfig {
        resident_capacity_entries: 8,
        small_queue_entries: 3,
        ghost_queue_entries: 6,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let recovered: S3FifoConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, cfg);
}

// ────────────────────────────────────────────────────────────
// Enrichment: S3FifoAdoptionWedgeContract
// ────────────────────────────────────────────────────────────

#[test]
fn adoption_wedge_default_validates() {
    let wedge = S3FifoAdoptionWedgeContract::default();
    wedge.validate().unwrap();
}

#[test]
fn adoption_wedge_serde_roundtrip() {
    let wedge = S3FifoAdoptionWedgeContract::default();
    let json = serde_json::to_string(&wedge).expect("serialize");
    let recovered: S3FifoAdoptionWedgeContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, wedge);
}

#[test]
fn adoption_wedge_rejects_wrong_schema_version() {
    let mut wedge = S3FifoAdoptionWedgeContract::default();
    wedge.schema_version = "wrong-version".to_string();
    let err = wedge.validate().unwrap_err();
    match err {
        CachePolicyReportError::InvalidAdoptionWedge { field, .. } => {
            assert_eq!(field, "schema_version");
        }
        other => panic!("expected InvalidAdoptionWedge, got: {other}"),
    }
}

#[test]
fn adoption_wedge_rejects_wrong_incumbent_policy() {
    let mut wedge = S3FifoAdoptionWedgeContract::default();
    wedge.incumbent_policy_name = "wrong_policy".to_string();
    let err = wedge.validate().unwrap_err();
    match err {
        CachePolicyReportError::InvalidAdoptionWedge { field, .. } => {
            assert_eq!(field, "incumbent_policy_name");
        }
        other => panic!("expected InvalidAdoptionWedge, got: {other}"),
    }
}

#[test]
fn adoption_wedge_rejects_empty_replaced_surfaces() {
    let mut wedge = S3FifoAdoptionWedgeContract::default();
    wedge.replaced_surfaces = vec![];
    let err = wedge.validate().unwrap_err();
    match err {
        CachePolicyReportError::InvalidAdoptionWedge { field, .. } => {
            assert_eq!(field, "replaced_surfaces");
        }
        other => panic!("expected InvalidAdoptionWedge, got: {other}"),
    }
}

#[test]
fn adoption_wedge_rejects_empty_string_in_win_metrics() {
    let mut wedge = S3FifoAdoptionWedgeContract::default();
    wedge.win_metrics.push("  ".to_string());
    let err = wedge.validate().unwrap_err();
    match err {
        CachePolicyReportError::InvalidAdoptionWedge { field, detail } => {
            assert_eq!(field, "win_metrics");
            assert!(detail.contains("empty"), "got: {detail}");
        }
        other => panic!("expected InvalidAdoptionWedge, got: {other}"),
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: CachePolicyReportError Display
// ────────────────────────────────────────────────────────────

#[test]
fn cache_policy_report_error_display_all_variants() {
    let errors: Vec<CachePolicyReportError> = vec![
        CachePolicyReportError::EmptyCorpusId,
        CachePolicyReportError::EmptyCorpusCases,
        CachePolicyReportError::DuplicateTraceId {
            trace_id: "t1".to_string(),
        },
        CachePolicyReportError::EmptyTraceId,
        CachePolicyReportError::EmptyTrace {
            trace_id: "t2".to_string(),
        },
        CachePolicyReportError::NonMonotonicTraceSequence {
            trace_id: "t3".to_string(),
            previous: 5,
            actual: 3,
        },
        CachePolicyReportError::EmptyModuleIdInTrace {
            trace_id: "t4".to_string(),
            sequence: 7,
        },
        CachePolicyReportError::InvalidSchemaVersion {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CachePolicyReportError::CorpusHashMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
        CachePolicyReportError::InvalidConfig {
            field: "capacity",
            detail: "bad".to_string(),
        },
        CachePolicyReportError::InvalidAdoptionWedge {
            field: "schema_version",
            detail: "mismatch".to_string(),
        },
        CachePolicyReportError::InvalidBaselineReport {
            field: "corpus_id",
            detail: "wrong".to_string(),
        },
    ];
    for err in &errors {
        let display = format!("{err}");
        assert!(
            !display.is_empty(),
            "Display for {err:?} should not be empty"
        );
    }
}

#[test]
fn cache_policy_report_error_is_std_error() {
    let err = CachePolicyReportError::EmptyCorpusId;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn cache_policy_report_error_serde_roundtrip_simple_variants() {
    // Only test variants without &'static str fields to avoid lifetime issues
    let errors: Vec<CachePolicyReportError> = vec![
        CachePolicyReportError::EmptyCorpusId,
        CachePolicyReportError::EmptyCorpusCases,
        CachePolicyReportError::EmptyTraceId,
        CachePolicyReportError::DuplicateTraceId {
            trace_id: "dup".to_string(),
        },
        CachePolicyReportError::EmptyTrace {
            trace_id: "empty".to_string(),
        },
        CachePolicyReportError::NonMonotonicTraceSequence {
            trace_id: "nm".to_string(),
            previous: 10,
            actual: 5,
        },
        CachePolicyReportError::EmptyModuleIdInTrace {
            trace_id: "em".to_string(),
            sequence: 3,
        },
        CachePolicyReportError::InvalidSchemaVersion {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CachePolicyReportError::CorpusHashMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        // Verify JSON is non-empty and parseable
        let value: serde_json::Value = serde_json::from_str(&json).expect("deserialize as Value");
        assert!(value.is_object() || value.is_string());
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: CachePolicyMetrics, CachePolicyCaseReport, Aggregate
// ────────────────────────────────────────────────────────────

#[test]
fn cache_policy_metrics_serde_roundtrip() {
    let metrics = CachePolicyMetrics {
        policy_name: "single_queue_fifo".to_string(),
        total_accesses: 100,
        hit_count: 60,
        miss_count: 40,
        ghost_hit_count: 5,
        eviction_count: 10,
        promotion_count: 3,
        requeue_count: 2,
        hit_rate_millionths: 600_000,
        hot_retention_millionths: 800_000,
        scan_pollution_millionths: 100_000,
        final_resident_keys: vec!["k1".to_string(), "k2".to_string()],
    };
    let json = serde_json::to_string(&metrics).expect("serialize");
    let recovered: CachePolicyMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, metrics);
}

#[test]
fn cache_policy_aggregate_summary_serde_roundtrip() {
    let agg = CachePolicyAggregateSummary {
        total_cases: 5,
        improved_hit_rate_cases: 3,
        improved_hot_retention_cases: 2,
        reduced_scan_pollution_cases: 4,
    };
    let json = serde_json::to_string(&agg).expect("serialize");
    let recovered: CachePolicyAggregateSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, agg);
}

#[test]
fn cache_policy_case_report_serde_roundtrip() {
    let baseline = CachePolicyMetrics {
        policy_name: "single_queue_fifo".to_string(),
        total_accesses: 10,
        hit_count: 3,
        miss_count: 7,
        ghost_hit_count: 0,
        eviction_count: 2,
        promotion_count: 0,
        requeue_count: 0,
        hit_rate_millionths: 300_000,
        hot_retention_millionths: 500_000,
        scan_pollution_millionths: 200_000,
        final_resident_keys: vec!["a".to_string()],
    };
    let candidate = CachePolicyMetrics {
        policy_name: "s3_fifo".to_string(),
        total_accesses: 10,
        hit_count: 5,
        miss_count: 5,
        ghost_hit_count: 1,
        eviction_count: 1,
        promotion_count: 1,
        requeue_count: 1,
        hit_rate_millionths: 500_000,
        hot_retention_millionths: 800_000,
        scan_pollution_millionths: 100_000,
        final_resident_keys: vec!["a".to_string(), "b".to_string()],
    };
    let report = CachePolicyCaseReport {
        trace_id: "trace-cr".to_string(),
        workload_class: "cold_compile".to_string(),
        baseline,
        candidate,
        hit_rate_delta_millionths: 200_000,
        hot_retention_delta_millionths: 300_000,
        scan_pollution_delta_millionths: -100_000,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: CachePolicyCaseReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-cr");
    assert_eq!(recovered.hit_rate_delta_millionths, 200_000);
}

// ────────────────────────────────────────────────────────────
// Enrichment: evaluate_s3fifo_baseline pipeline
// ────────────────────────────────────────────────────────────

#[test]
fn evaluate_s3fifo_baseline_default_succeeds() {
    use frankenengine_engine::module_cache::{
        default_s3fifo_baseline_config, default_s3fifo_candidate_config,
        default_s3fifo_trace_corpus_manifest, evaluate_s3fifo_baseline,
    };
    let manifest = default_s3fifo_trace_corpus_manifest();
    let report = evaluate_s3fifo_baseline(
        &manifest,
        &default_s3fifo_baseline_config(),
        &default_s3fifo_candidate_config(),
        &S3FifoAdoptionWedgeContract::default(),
    )
    .unwrap();
    assert_eq!(report.cases.len(), manifest.cases.len());
    assert_eq!(report.aggregate.total_cases, manifest.cases.len() as u64);
    report.validate(&manifest).unwrap();
}

#[test]
fn evaluate_s3fifo_baseline_is_deterministic() {
    use frankenengine_engine::module_cache::{
        default_s3fifo_baseline_config, default_s3fifo_candidate_config,
        default_s3fifo_trace_corpus_manifest, evaluate_s3fifo_baseline,
    };
    let manifest = default_s3fifo_trace_corpus_manifest();
    let r1 = evaluate_s3fifo_baseline(
        &manifest,
        &default_s3fifo_baseline_config(),
        &default_s3fifo_candidate_config(),
        &S3FifoAdoptionWedgeContract::default(),
    )
    .unwrap();
    let r2 = evaluate_s3fifo_baseline(
        &manifest,
        &default_s3fifo_baseline_config(),
        &default_s3fifo_candidate_config(),
        &S3FifoAdoptionWedgeContract::default(),
    )
    .unwrap();
    assert_eq!(r1, r2);
}

// ────────────────────────────────────────────────────────────
// Enrichment: default_s3fifo_baseline_report / contract fixture / summary
// ────────────────────────────────────────────────────────────

#[test]
fn default_s3fifo_baseline_report_succeeds() {
    use frankenengine_engine::module_cache::default_s3fifo_baseline_report;
    let report = default_s3fifo_baseline_report().unwrap();
    assert_eq!(report.baseline_policy_name, "single_queue_fifo");
    assert_eq!(report.candidate_policy_name, "s3_fifo");
    assert!(!report.cases.is_empty());
}

#[test]
fn default_s3fifo_baseline_contract_fixture_fields() {
    use frankenengine_engine::module_cache::default_s3fifo_baseline_contract_fixture;
    let fixture = default_s3fifo_baseline_contract_fixture();
    assert_eq!(fixture.bead_id, "bd-1lsy.7.20.1");
    assert_eq!(fixture.baseline_policy_name, "single_queue_fifo");
    assert_eq!(fixture.candidate_policy_name, "s3_fifo");
    assert!(!fixture.required_artifacts.is_empty());
    assert!(!fixture.workload_classes.is_empty());
    assert!(!fixture.trace_ids.is_empty());
    assert!(!fixture.win_metrics.is_empty());
}

#[test]
fn render_s3fifo_baseline_summary_contains_expected_sections() {
    use frankenengine_engine::module_cache::{
        default_s3fifo_baseline_report, render_s3fifo_baseline_summary,
    };
    let report = default_s3fifo_baseline_report().unwrap();
    let summary = render_s3fifo_baseline_summary(&report);
    assert!(summary.contains("S3-FIFO Baseline Comparator Summary"));
    assert!(summary.contains("bead_id"));
    assert!(summary.contains("corpus_id"));
    assert!(summary.contains("Case Deltas"));
    assert!(summary.contains("Adoption Wedge"));
}

// ────────────────────────────────────────────────────────────
// Enrichment: Constants
// ────────────────────────────────────────────────────────────

#[test]
fn schema_version_constants_are_nonempty_and_prefixed() {
    use frankenengine_engine::module_cache::{
        CACHE_POLICY_BASELINE_SCHEMA_VERSION, CACHE_TRACE_CORPUS_SCHEMA_VERSION,
        S3FIFO_ADAPTIVE_BEAD_ID, S3FIFO_ADAPTIVE_SCHEMA_VERSION,
        S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION, S3FIFO_BASELINE_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        S3FIFO_BASELINE_BEAD_ID, S3FIFO_BASELINE_COMPONENT,
        S3FIFO_BASELINE_CONTRACT_SCHEMA_VERSION, S3FIFO_BASELINE_ENV_SCHEMA_VERSION,
        S3FIFO_BASELINE_EVENT_SCHEMA_VERSION, S3FIFO_BASELINE_REPRO_LOCK_SCHEMA_VERSION,
        S3FIFO_BASELINE_RUN_MANIFEST_SCHEMA_VERSION, S3FIFO_BASELINE_TRACE_IDS_SCHEMA_VERSION,
    };
    let constants: &[&str] = &[
        CACHE_TRACE_CORPUS_SCHEMA_VERSION,
        CACHE_POLICY_BASELINE_SCHEMA_VERSION,
        S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION,
        S3FIFO_BASELINE_COMPONENT,
        S3FIFO_BASELINE_BEAD_ID,
        S3FIFO_BASELINE_CONTRACT_SCHEMA_VERSION,
        S3FIFO_BASELINE_EVENT_SCHEMA_VERSION,
        S3FIFO_BASELINE_ENV_SCHEMA_VERSION,
        S3FIFO_BASELINE_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        S3FIFO_BASELINE_REPRO_LOCK_SCHEMA_VERSION,
        S3FIFO_BASELINE_RUN_MANIFEST_SCHEMA_VERSION,
        S3FIFO_BASELINE_TRACE_IDS_SCHEMA_VERSION,
        S3FIFO_ADAPTIVE_SCHEMA_VERSION,
        S3FIFO_ADAPTIVE_BEAD_ID,
    ];
    for c in constants {
        assert!(!c.is_empty(), "constant should not be empty");
    }
    // Schema versions should contain "franken-engine" or "bd-" prefix
    assert!(CACHE_TRACE_CORPUS_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(CACHE_POLICY_BASELINE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(S3FIFO_BASELINE_BEAD_ID.starts_with("bd-"));
    assert!(S3FIFO_ADAPTIVE_BEAD_ID.starts_with("bd-"));
}

// ────────────────────────────────────────────────────────────
// Enrichment: Adaptive S3-FIFO types (integration-level)
// ────────────────────────────────────────────────────────────

#[test]
fn adaptive_split_config_default() {
    let cfg = AdaptiveSplitConfig::default();
    assert_eq!(cfg.min_small_fraction_millionths, 100_000);
    assert_eq!(cfg.max_small_fraction_millionths, 500_000);
    assert_eq!(cfg.max_step_per_epoch, 1);
    assert_eq!(cfg.epoch_length, 16);
}

#[test]
fn adaptive_split_config_serde_roundtrip() {
    let cfg = AdaptiveSplitConfig {
        min_small_fraction_millionths: 50_000,
        max_small_fraction_millionths: 600_000,
        max_step_per_epoch: 2,
        epoch_length: 32,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let recovered: AdaptiveSplitConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, cfg);
}

#[test]
fn value_admission_config_default() {
    let cfg = ValueAdmissionConfig::default();
    assert_eq!(cfg.initial_threshold_millionths, 100_000);
    assert_eq!(cfg.alpha_millionths, 250_000);
    assert_eq!(cfg.floor_value_millionths, 0);
}

#[test]
fn value_admission_config_serde_roundtrip() {
    let cfg = ValueAdmissionConfig {
        initial_threshold_millionths: 200_000,
        alpha_millionths: 500_000,
        floor_value_millionths: 50_000,
    };
    let json = serde_json::to_string(&cfg).expect("serialize");
    let recovered: ValueAdmissionConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, cfg);
}

#[test]
fn s3fifo_adaptive_config_default_validates() {
    let cfg = S3FifoAdaptiveConfig::default();
    cfg.validate().unwrap();
    assert_eq!(cfg.resident_capacity_entries, 8);
    assert_eq!(cfg.initial_small_queue_entries, 3);
    assert_eq!(cfg.ghost_queue_entries, 8);
}

#[test]
fn s3fifo_adaptive_config_serde_roundtrip() {
    let cfg = S3FifoAdaptiveConfig::default();
    let json = serde_json::to_string(&cfg).expect("serialize");
    let recovered: S3FifoAdaptiveConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, cfg);
}

#[test]
fn s3fifo_adaptive_config_validate_zero_capacity() {
    let cfg = S3FifoAdaptiveConfig {
        resident_capacity_entries: 0,
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn s3fifo_adaptive_config_validate_small_exceeds_capacity() {
    let mut cfg = S3FifoAdaptiveConfig::default();
    cfg.initial_small_queue_entries = cfg.resident_capacity_entries;
    assert!(cfg.validate().is_err());
}

#[test]
fn s3fifo_adaptive_config_validate_zero_ghost() {
    let cfg = S3FifoAdaptiveConfig {
        ghost_queue_entries: 0,
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn s3fifo_adaptive_config_validate_bad_alpha() {
    let mut cfg = S3FifoAdaptiveConfig::default();
    cfg.value_admission.alpha_millionths = 1_000_001;
    assert!(cfg.validate().is_err());
}

#[test]
fn s3fifo_adaptive_config_validate_bad_split_bounds() {
    let mut cfg = S3FifoAdaptiveConfig::default();
    cfg.adaptive_split.min_small_fraction_millionths = 700_000;
    cfg.adaptive_split.max_small_fraction_millionths = 300_000;
    assert!(cfg.validate().is_err());
}

#[test]
fn s3fifo_adaptive_config_validate_zero_epoch() {
    let mut cfg = S3FifoAdaptiveConfig::default();
    cfg.adaptive_split.epoch_length = 0;
    assert!(cfg.validate().is_err());
}

// ────────────────────────────────────────────────────────────
// Enrichment: AdmissionVerdict / S3FifoAdaptiveMetrics serde
// ────────────────────────────────────────────────────────────

#[test]
fn admission_verdict_serde_roundtrip() {
    let verdict = AdmissionVerdict {
        sequence: 99,
        label: "mod:verdict".to_string(),
        value_millionths: 750_000,
        threshold_millionths: 400_000,
        admitted: true,
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let recovered: AdmissionVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, verdict);
}

#[test]
fn admission_verdict_denied() {
    let verdict = AdmissionVerdict {
        sequence: 1,
        label: "mod:denied".to_string(),
        value_millionths: 50_000,
        threshold_millionths: 500_000,
        admitted: false,
    };
    let json = serde_json::to_string(&verdict).expect("serialize");
    let recovered: AdmissionVerdict = serde_json::from_str(&json).expect("deserialize");
    assert!(!recovered.admitted);
    assert_eq!(recovered.value_millionths, 50_000);
}

#[test]
fn value_annotated_trace_access_serde_roundtrip() {
    let access = ValueAnnotatedTraceAccess {
        sequence: 7,
        key: make_trace_key("mod:va", "seed-va", 1, 1),
        locality: CacheLocalityClass::Scan,
        value_millionths: 200_000,
    };
    let json = serde_json::to_string(&access).expect("serialize");
    let recovered: ValueAnnotatedTraceAccess = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.sequence, 7);
    assert_eq!(recovered.value_millionths, 200_000);
    assert_eq!(recovered.locality, CacheLocalityClass::Scan);
}

#[test]
fn value_annotated_trace_case_serde_roundtrip() {
    let case = ValueAnnotatedTraceCase {
        trace_id: "serde-vatc".to_string(),
        workload_class: CacheWorkloadClass::ReactApp,
        accesses: vec![ValueAnnotatedTraceAccess {
            sequence: 0,
            key: make_trace_key("mod:vatc", "seed-vatc", 2, 3),
            locality: CacheLocalityClass::Hot,
            value_millionths: 900_000,
        }],
    };
    let json = serde_json::to_string(&case).expect("serialize");
    let recovered: ValueAnnotatedTraceCase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "serde-vatc");
    assert_eq!(recovered.accesses.len(), 1);
}

// ────────────────────────────────────────────────────────────
// Enrichment: simulate_s3fifo_adaptive (integration)
// ────────────────────────────────────────────────────────────

fn make_adaptive_access(
    seq: u64,
    module_id: &str,
    seed: &str,
    locality: CacheLocalityClass,
    value: u32,
) -> ValueAnnotatedTraceAccess {
    ValueAnnotatedTraceAccess {
        sequence: seq,
        key: make_trace_key(module_id, seed, 1, 1),
        locality,
        value_millionths: value,
    }
}

#[test]
fn simulate_adaptive_empty_trace_returns_zero_metrics() {
    use frankenengine_engine::module_cache::simulate_s3fifo_adaptive;
    let case = ValueAnnotatedTraceCase {
        trace_id: "empty-integ".to_string(),
        workload_class: CacheWorkloadClass::ColdCompile,
        accesses: vec![],
    };
    let result = simulate_s3fifo_adaptive(&case, &S3FifoAdaptiveConfig::default());
    assert_eq!(result.base.total_accesses, 0);
    assert_eq!(result.base.hit_count, 0);
    assert_eq!(result.value_denied_count, 0);
    assert_eq!(result.value_admitted_count, 0);
}

#[test]
fn simulate_adaptive_deterministic() {
    use frankenengine_engine::module_cache::simulate_s3fifo_adaptive;
    let case = ValueAnnotatedTraceCase {
        trace_id: "det-integ".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![
            make_adaptive_access(0, "mod:x", "sx", CacheLocalityClass::Hot, 800_000),
            make_adaptive_access(1, "mod:y", "sy", CacheLocalityClass::Warm, 500_000),
            make_adaptive_access(2, "mod:x", "sx", CacheLocalityClass::Hot, 800_000),
        ],
    };
    let cfg = S3FifoAdaptiveConfig::default();
    let r1 = simulate_s3fifo_adaptive(&case, &cfg);
    let r2 = simulate_s3fifo_adaptive(&case, &cfg);
    assert_eq!(r1.base.hit_count, r2.base.hit_count);
    assert_eq!(r1.base.miss_count, r2.base.miss_count);
    assert_eq!(r1.final_small_capacity, r2.final_small_capacity);
    assert_eq!(r1.final_threshold_millionths, r2.final_threshold_millionths);
}

#[test]
fn simulate_adaptive_value_denial_below_floor() {
    use frankenengine_engine::module_cache::simulate_s3fifo_adaptive;
    let mut cfg = S3FifoAdaptiveConfig::default();
    cfg.value_admission.floor_value_millionths = 600_000;
    cfg.value_admission.initial_threshold_millionths = 0;
    let case = ValueAnnotatedTraceCase {
        trace_id: "floor-deny".to_string(),
        workload_class: CacheWorkloadClass::ScanHeavy,
        accesses: vec![make_adaptive_access(
            0,
            "mod:low",
            "slow",
            CacheLocalityClass::Scan,
            100_000,
        )],
    };
    let result = simulate_s3fifo_adaptive(&case, &cfg);
    assert_eq!(result.value_denied_count, 1);
    assert_eq!(result.value_admitted_count, 0);
    assert!(!result.admission_verdicts[0].admitted);
}

#[test]
fn simulate_adaptive_metrics_serde_roundtrip() {
    use frankenengine_engine::module_cache::simulate_s3fifo_adaptive;
    let case = ValueAnnotatedTraceCase {
        trace_id: "metrics-serde".to_string(),
        workload_class: CacheWorkloadClass::WarmRun,
        accesses: vec![make_adaptive_access(
            0,
            "mod:ms",
            "sms",
            CacheLocalityClass::Hot,
            900_000,
        )],
    };
    let metrics = simulate_s3fifo_adaptive(&case, &S3FifoAdaptiveConfig::default());
    let json = serde_json::to_string(&metrics).expect("serialize");
    let recovered: S3FifoAdaptiveMetrics = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.base.total_accesses, metrics.base.total_accesses);
    assert_eq!(recovered.final_small_capacity, metrics.final_small_capacity);
}

// ────────────────────────────────────────────────────────────
// Enrichment: annotate_trace_with_default_values
// ────────────────────────────────────────────────────────────

#[test]
fn annotate_trace_assigns_correct_default_values() {
    use frankenengine_engine::module_cache::annotate_trace_with_default_values;
    let plain = CacheTraceCase {
        trace_id: "annotate-integ".to_string(),
        workload_class: CacheWorkloadClass::ColdCompile,
        accesses: vec![
            CacheTraceAccess {
                sequence: 0,
                key: make_trace_key("mod:hot", "sh", 1, 1),
                locality: CacheLocalityClass::Hot,
            },
            CacheTraceAccess {
                sequence: 1,
                key: make_trace_key("mod:warm", "sw", 1, 1),
                locality: CacheLocalityClass::Warm,
            },
            CacheTraceAccess {
                sequence: 2,
                key: make_trace_key("mod:scan", "ss", 1, 1),
                locality: CacheLocalityClass::Scan,
            },
        ],
    };
    let annotated = annotate_trace_with_default_values(&plain);
    assert_eq!(annotated.trace_id, "annotate-integ");
    assert_eq!(annotated.accesses.len(), 3);
    assert_eq!(annotated.accesses[0].value_millionths, 900_000); // Hot
    assert_eq!(annotated.accesses[1].value_millionths, 500_000); // Warm
    assert_eq!(annotated.accesses[2].value_millionths, 100_000); // Scan
}

// ────────────────────────────────────────────────────────────
// Enrichment: S3FifoBaselineComparatorContractFixture serde
// ────────────────────────────────────────────────────────────

#[test]
fn s3fifo_baseline_contract_fixture_serde_roundtrip() {
    use frankenengine_engine::module_cache::{
        S3FifoBaselineComparatorContractFixture, default_s3fifo_baseline_contract_fixture,
    };
    let fixture = default_s3fifo_baseline_contract_fixture();
    let json = serde_json::to_string(&fixture).expect("serialize");
    let recovered: S3FifoBaselineComparatorContractFixture =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, fixture);
}

// ────────────────────────────────────────────────────────────
// Enrichment: default_s3fifo_adaptive_config
// ────────────────────────────────────────────────────────────

#[test]
fn default_s3fifo_adaptive_config_matches_default_trait() {
    use frankenengine_engine::module_cache::default_s3fifo_adaptive_config;
    let from_fn = default_s3fifo_adaptive_config();
    let from_default = S3FifoAdaptiveConfig::default();
    assert_eq!(from_fn, from_default);
}

// ────────────────────────────────────────────────────────────
// Enrichment: CachePolicyBaselineReport serde
// ────────────────────────────────────────────────────────────

#[test]
fn cache_policy_baseline_report_serde_roundtrip() {
    use frankenengine_engine::module_cache::{
        CachePolicyBaselineReport, default_s3fifo_baseline_report,
    };
    let report = default_s3fifo_baseline_report().unwrap();
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: CachePolicyBaselineReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.corpus_id, report.corpus_id);
    assert_eq!(recovered.corpus_hash, report.corpus_hash);
    assert_eq!(recovered.cases.len(), report.cases.len());
    assert_eq!(recovered.aggregate, report.aggregate);
}

// ────────────────────────────────────────────────────────────
// Enrichment: snapshot_fastpath_policy / telemetry
// ────────────────────────────────────────────────────────────

#[test]
fn snapshot_fastpath_policy_accessible() {
    let cache = ModuleCache::new();
    let _policy = cache.snapshot_fastpath_policy();
    // Smoke test: just verify it doesn't panic
}

#[test]
fn snapshot_fastpath_telemetry_accessible() {
    let cache = ModuleCache::new();
    let _telemetry = cache.snapshot_fastpath_telemetry();
    // Smoke test: just verify it doesn't panic
}

// ────────────────────────────────────────────────────────────
// Enrichment: edge cases on merge / state transitions
// ────────────────────────────────────────────────────────────

#[test]
fn merge_revoked_remote_blocks_local_insert() {
    let mut local = ModuleCache::new();
    let mut remote = ModuleCache::new();
    let ctx = cache_context();

    remote.invalidate_trust_revocation("mod:remote-rev", 5, &ctx);
    let remote_snap = remote.snapshot();
    local.merge_snapshot(&remote_snap, &ctx);

    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"src-rr"), 1, 5);
    let err = local
        .insert(
            CacheInsertRequest::new(
                "mod:remote-rev",
                v,
                ContentHash::compute(b"art-rr"),
                "/rr.mjs",
            ),
            &ctx,
        )
        .unwrap_err();
    assert_eq!(err.code, CacheErrorCode::ModuleRevoked);
}

#[test]
fn double_revocation_is_idempotent() {
    let mut cache = ModuleCache::new();
    let ctx = cache_context();
    let src = ContentHash::compute(b"dbl-rev");
    let v = ModuleVersionFingerprint::new(src, 1, 1);
    cache
        .insert(
            CacheInsertRequest::new("mod:dbl", v, ContentHash::compute(b"art-dbl"), "/dbl.mjs"),
            &ctx,
        )
        .unwrap();

    cache.invalidate_trust_revocation("mod:dbl", 2, &ctx);
    let hash_after_first = cache.state_hash();
    cache.invalidate_trust_revocation("mod:dbl", 2, &ctx);
    // State hash should be unchanged by idempotent revocation
    assert_eq!(cache.state_hash(), hash_after_first);
}

#[test]
fn source_update_on_nonexistent_module_creates_version() {
    let mut cache = ModuleCache::new();
    let ctx = cache_context();
    cache.invalidate_source_update("mod:phantom", ContentHash::compute(b"phantom-src"), &ctx);
    let snap = cache.snapshot();
    assert!(snap.latest_versions.contains_key("mod:phantom"));
}

#[test]
fn cache_error_code_empty_module_id_stable_code() {
    assert_eq!(
        CacheErrorCode::EmptyModuleId.stable_code(),
        "FE-MODCACHE-0003"
    );
}

#[test]
fn cache_error_display_contains_colon_separator() {
    let mut cache = ModuleCache::new();
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"disp-sep"), 1, 1);
    let err = cache
        .insert(
            CacheInsertRequest::new("", v, ContentHash::compute(b"art-disp"), "/disp.mjs"),
            &cache_context(),
        )
        .unwrap_err();
    let display = format!("{err}");
    assert!(
        display.contains(": "),
        "expected colon separator in: {display}"
    );
    assert!(display.starts_with("FE-MODCACHE-"));
}

#[test]
fn module_cache_serde_roundtrip_excludes_fastpath() {
    // ModuleCache has #[serde(skip)] on snapshot_fastpath.
    // Verify serde works (it serializes everything except the fastpath).
    let mut cache = ModuleCache::new();
    let ctx = cache_context();
    let v = ModuleVersionFingerprint::new(ContentHash::compute(b"mc-serde"), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:mc-serde",
                v,
                ContentHash::compute(b"art-mc"),
                "/mc.mjs",
            ),
            &ctx,
        )
        .unwrap();
    let json = serde_json::to_string(&cache).expect("serialize ModuleCache");
    let recovered: ModuleCache = serde_json::from_str(&json).expect("deserialize ModuleCache");
    // State hash should match after deserialization
    assert_eq!(cache.state_hash(), recovered.state_hash());
}
