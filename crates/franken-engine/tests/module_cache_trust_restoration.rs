#![forbid(unsafe_code)]

//! Trust re-admission must not turn a stale decision into fresh authority.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheErrorCode, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};

const MODULE: &str = "mod:protected";

fn context() -> CacheContext {
    CacheContext::new("trust-boundary-trace", "restore-decision", "policy-7")
}

fn version(trust: u64) -> ModuleVersionFingerprint {
    ModuleVersionFingerprint::new(ContentHash::compute(b"protected-source"), 7, trust)
}

fn insert(cache: &mut ModuleCache, trust: u64) {
    cache
        .insert(
            CacheInsertRequest::new(
                MODULE,
                version(trust),
                ContentHash::compute(b"compiled-protected-source"),
                "/protected.js",
            ),
            &context(),
        )
        .expect("insert authorized artifact");
}

#[test]
fn stale_and_equal_revision_restoration_preserve_revocation_and_fastpath() {
    for attempted_revision in [0, 1, 8, 9] {
        let mut cache = ModuleCache::new();
        insert(&mut cache, 1);
        cache.invalidate_trust_revocation(MODULE, 9, &context());
        let before = cache.snapshot(); // Initialize/read the published fast path.
        let before_events = cache.events().len();

        let error = cache
            .try_restore_trust(MODULE, attempted_revision, &context())
            .expect_err("re-admission requires a strictly newer trust revision");

        assert_eq!(error.code, CacheErrorCode::VersionRegression);
        assert_eq!(error.event.event, "cache_restore_trust");
        assert_eq!(error.event.outcome, "deny");
        assert_eq!(error.event.error_code, "FE-MODCACHE-0002");
        assert_eq!(error.event.trace_id, context().trace_id);
        assert_eq!(error.event.decision_id, context().decision_id);
        assert_eq!(error.event.policy_id, context().policy_id);
        assert_eq!(cache.events().len(), before_events + 1);
        assert_eq!(cache.events().last(), Some(&error.event));
        assert_eq!(cache.snapshot(), before);
        assert_eq!(cache.state_hash(), before.state_hash);
        assert!(cache.get(MODULE, &version(1)).is_none());
        assert!(cache.get(MODULE, &version(9)).is_none());

        let insertion = cache.insert(
            CacheInsertRequest::new(
                MODULE,
                version(9),
                ContentHash::compute(b"stale-grant-artifact"),
                "/protected.js",
            ),
            &context(),
        );
        assert_eq!(insertion.unwrap_err().code, CacheErrorCode::ModuleRevoked);
    }
}

#[test]
fn compatibility_entry_point_also_refuses_stale_restoration() {
    let mut cache = ModuleCache::new();
    cache.invalidate_trust_revocation(MODULE, 5, &context());
    let before = cache.snapshot();
    cache.restore_trust(MODULE, 4, &context());
    assert_eq!(cache.snapshot(), before);
    assert_eq!(cache.events().last().unwrap().outcome, "deny");
}

#[test]
fn fresh_restoration_allows_only_a_new_artifact() {
    let mut cache = ModuleCache::new();
    insert(&mut cache, 1);
    cache.invalidate_trust_revocation(MODULE, 2, &context());
    cache.try_restore_trust(MODULE, 3, &context()).unwrap();
    let snapshot = cache.snapshot();
    assert!(!snapshot.revoked_modules.contains(MODULE));
    assert_eq!(snapshot.latest_versions[MODULE], version(3));
    assert!(snapshot.entries.is_empty());
    assert!(cache.get(MODULE, &version(1)).is_none());
    insert(&mut cache, 3);
    assert!(cache.get(MODULE, &version(3)).is_some());
}

#[test]
fn advancing_active_trust_prunes_old_artifacts_from_replicated_state() {
    let mut cache = ModuleCache::new();
    insert(&mut cache, 3);
    cache.try_restore_trust(MODULE, 4, &context()).unwrap();
    assert!(cache.snapshot().entries.is_empty());
    assert_eq!(cache.snapshot().latest_versions[MODULE], version(4));
    assert!(cache.get(MODULE, &version(3)).is_none());
    insert(&mut cache, 4);
    assert!(cache.get(MODULE, &version(4)).is_some());
}

#[test]
fn equal_active_revision_is_idempotent_but_older_revision_is_denied() {
    let mut cache = ModuleCache::new();
    insert(&mut cache, 4);
    let before = cache.snapshot();
    cache.try_restore_trust(MODULE, 4, &context()).unwrap();
    assert_eq!(cache.snapshot(), before);
    assert_eq!(
        cache
            .try_restore_trust(MODULE, 3, &context())
            .unwrap_err()
            .code,
        CacheErrorCode::VersionRegression,
    );
    assert_eq!(cache.snapshot(), before);
}

#[test]
fn saturated_trust_frontier_cannot_wrap_or_re_admit() {
    let mut cache = ModuleCache::new();
    cache.invalidate_trust_revocation(MODULE, u64::MAX, &context());
    let before = cache.snapshot();
    for revision in [0, 1, u64::MAX - 1, u64::MAX] {
        assert_eq!(
            cache
                .try_restore_trust(MODULE, revision, &context())
                .unwrap_err()
                .code,
            CacheErrorCode::VersionRegression,
        );
        assert_eq!(cache.snapshot(), before);
    }
}

#[test]
fn empty_identity_is_not_a_trust_grant() {
    for id in ["", " ", "\t\n"] {
        let mut cache = ModuleCache::new();
        let before = cache.snapshot();
        assert_eq!(
            cache.try_restore_trust(id, 1, &context()).unwrap_err().code,
            CacheErrorCode::EmptyModuleId,
        );
        assert_eq!(cache.snapshot(), before);
    }
}

#[test]
fn first_authorized_grant_retains_unknown_module_compatibility() {
    let mut cache = ModuleCache::new();
    cache.try_restore_trust(MODULE, 0, &context()).unwrap();
    let snapshot = cache.snapshot();
    assert_eq!(snapshot.latest_versions[MODULE].trust_revision, 0);
    assert!(!snapshot.revoked_modules.contains(MODULE));
    assert!(snapshot.entries.is_empty());
}

#[test]
fn malformed_persisted_revocation_without_frontier_cannot_be_cleared() {
    let mut serialized = serde_json::to_value(ModuleCache::new()).unwrap();
    serialized["revoked_modules"] = serde_json::json!([MODULE]);
    let mut cache: ModuleCache = serde_json::from_value(serialized).unwrap();
    let before = cache.snapshot();
    assert_eq!(
        cache
            .try_restore_trust(MODULE, u64::MAX, &context())
            .unwrap_err()
            .code,
        CacheErrorCode::VersionRegression,
    );
    assert_eq!(cache.snapshot(), before);
}

#[test]
fn denial_does_not_change_other_modules_or_subsequent_event_order() {
    let mut cache = ModuleCache::new();
    cache
        .try_restore_trust("mod:other", 11, &context())
        .unwrap();
    cache.invalidate_trust_revocation(MODULE, 9, &context());
    let before = cache.snapshot();
    cache.try_restore_trust(MODULE, 8, &context()).unwrap_err();
    assert_eq!(cache.snapshot(), before);
    cache.try_restore_trust(MODULE, 10, &context()).unwrap();
    assert_eq!(
        cache.snapshot().latest_versions["mod:other"].trust_revision,
        11
    );
    assert!(
        cache
            .events()
            .windows(2)
            .all(|pair| pair[0].seq < pair[1].seq)
    );
}
