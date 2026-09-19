#![forbid(unsafe_code)]

//! Public-API replication regressions: integrity, version monotonicity,
//! remove-wins revocation, atomic publication, and deterministic provenance.

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_serde::{CanonicalValue, encode_value};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheErrorCode, CacheInsertRequest, CacheSnapshot, ModuleCache,
    ModuleVersionFingerprint,
};

fn context() -> CacheContext {
    CacheContext::new("snapshot-trace", "snapshot-decision", "snapshot-policy")
}

fn version(source: &str, policy: u64, trust: u64) -> ModuleVersionFingerprint {
    ModuleVersionFingerprint::new(ContentHash::compute(source.as_bytes()), policy, trust)
}

fn insert(cache: &mut ModuleCache, id: &str, source: &str, policy: u64, trust: u64) {
    cache
        .insert(
            CacheInsertRequest::new(
                id,
                version(source, policy, trust),
                ContentHash::compute(format!("artifact:{source}:{policy}:{trust}").as_bytes()),
                format!("/{id}.js"),
            ),
            &context(),
        )
        .unwrap();
}

fn source_snapshot() -> CacheSnapshot {
    let mut peer = ModuleCache::new();
    insert(&mut peer, "a", "source-a", 2, 3);
    insert(&mut peer, "b", "source-b", 4, 5);
    peer.snapshot()
}

// Independent encoding of the pre-change state-hash contract. Keeping this
// separate from the production helper detects an accidental digest migration
// and allows structurally invalid *correctly hashed* adversarial snapshots.
fn legacy_hash(snapshot: &CacheSnapshot) -> ContentHash {
    fn fingerprint(value: &ModuleVersionFingerprint) -> CanonicalValue {
        CanonicalValue::Map(BTreeMap::from([
            ("source_hash".into(), CanonicalValue::String(value.source_hash.to_hex())),
            ("policy_version".into(), CanonicalValue::U64(value.policy_version)),
            ("trust_revision".into(), CanonicalValue::U64(value.trust_revision)),
        ]))
    }
    let entries = snapshot.entries.iter().map(|entry| {
        let key = CanonicalValue::Map(BTreeMap::from([
            ("module_id".into(), CanonicalValue::String(entry.key.module_id.clone())),
            ("version".into(), fingerprint(&entry.key.version)),
        ]));
        CanonicalValue::Map(BTreeMap::from([
            ("key".into(), key),
            ("artifact_hash".into(), CanonicalValue::String(entry.artifact_hash.to_hex())),
            ("resolved_specifier".into(), CanonicalValue::String(entry.resolved_specifier.clone())),
            ("inserted_seq".into(), CanonicalValue::U64(entry.inserted_seq)),
        ]))
    }).collect();
    let versions = snapshot.latest_versions.iter()
        .map(|(id, value)| (id.clone(), fingerprint(value))).collect();
    let revoked = snapshot.revoked_modules.iter()
        .map(|id| CanonicalValue::String(id.clone())).collect();
    ContentHash::compute(&encode_value(&CanonicalValue::Map(BTreeMap::from([
        ("entries".into(), CanonicalValue::Array(entries)),
        ("latest_versions".into(), CanonicalValue::Map(versions)),
        ("revoked_modules".into(), CanonicalValue::Array(revoked)),
    ]))))
}

fn expect_invalid(snapshot: &CacheSnapshot) {
    let mut local = ModuleCache::new();
    insert(&mut local, "local", "local-source", 10, 10);
    let before = local.snapshot();
    let event_count = local.events().len();
    let error = local.try_merge_snapshot(snapshot, &context()).unwrap_err();
    assert_eq!(error.code, CacheErrorCode::InvalidSnapshot);
    assert_eq!(error.event.error_code, "FE-MODCACHE-0004");
    assert_eq!(error.event.event, "cache_merge_snapshot");
    assert_eq!(error.event.outcome, "deny");
    assert_eq!(error.event.trace_id, context().trace_id);
    assert_eq!(error.event.decision_id, context().decision_id);
    assert_eq!(error.event.policy_id, context().policy_id);
    assert_eq!(local.events().len(), event_count + 1);
    assert_eq!(local.events().last(), Some(&error.event));
    assert_eq!(local.snapshot(), before);
    assert_eq!(local.state_hash(), before.state_hash);
}

#[test]
fn valid_snapshot_preserves_the_existing_canonical_hash_contract() {
    let snapshot = source_snapshot();
    assert_eq!(snapshot.state_hash, legacy_hash(&snapshot));
    let mut local = ModuleCache::new();
    local.try_merge_snapshot(&snapshot, &context()).unwrap();
    assert_eq!(local.snapshot(), snapshot);
    local.try_merge_snapshot(&snapshot, &context()).unwrap();
    assert_eq!(local.snapshot(), snapshot);
}

#[test]
fn empty_snapshot_is_valid_and_does_not_remove_local_state() {
    let mut local = ModuleCache::new();
    insert(&mut local, "a", "a", 1, 1);
    let before = local.snapshot();
    local.try_merge_snapshot(&ModuleCache::new().snapshot(), &context()).unwrap();
    assert_eq!(local.snapshot(), before);
}

#[test]
fn corrupted_digest_is_rejected_before_publication() {
    let mut snapshot = source_snapshot();
    snapshot.state_hash = ContentHash::compute(b"not-the-state");
    expect_invalid(&snapshot);
}

#[test]
fn changing_artifact_without_changing_digest_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.entries[0].artifact_hash = ContentHash::compute(b"substituted-artifact");
    expect_invalid(&snapshot);
}

#[test]
fn changing_authority_without_changing_digest_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.latest_versions.get_mut("a").unwrap().trust_revision = 999;
    snapshot.entries[0].key.version.trust_revision = 999;
    expect_invalid(&snapshot);
}

#[test]
fn correctly_hashed_duplicate_entries_are_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.entries.insert(0, snapshot.entries[0].clone());
    snapshot.state_hash = legacy_hash(&snapshot);
    expect_invalid(&snapshot);
}

#[test]
fn correctly_hashed_noncanonical_entry_order_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.entries.reverse();
    snapshot.state_hash = legacy_hash(&snapshot);
    expect_invalid(&snapshot);
}

#[test]
fn correctly_hashed_orphan_and_stale_artifacts_are_rejected() {
    let mut orphan = source_snapshot();
    orphan.latest_versions.remove("a");
    orphan.state_hash = legacy_hash(&orphan);
    expect_invalid(&orphan);

    let mut stale = source_snapshot();
    stale.latest_versions.get_mut("a").unwrap().policy_version += 1;
    stale.state_hash = legacy_hash(&stale);
    expect_invalid(&stale);
}

#[test]
fn correctly_hashed_revoked_artifact_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.revoked_modules.insert("a".into());
    snapshot.state_hash = legacy_hash(&snapshot);
    expect_invalid(&snapshot);
}

#[test]
fn correctly_hashed_revocation_without_frontier_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.revoked_modules.insert("unknown".into());
    snapshot.state_hash = legacy_hash(&snapshot);
    expect_invalid(&snapshot);
}

#[test]
fn correctly_hashed_empty_identity_is_rejected() {
    let mut snapshot = source_snapshot();
    snapshot.latest_versions.insert(" \t".into(), version("bad", 1, 1));
    snapshot.state_hash = legacy_hash(&snapshot);
    expect_invalid(&snapshot);
}

#[test]
fn crossed_policy_and_trust_frontiers_cannot_roll_either_coordinate_backward() {
    for (local_policy, local_trust, peer_policy, peer_trust) in [(8, 3, 7, 10), (7, 10, 8, 3)] {
        let mut local = ModuleCache::new();
        let mut peer = ModuleCache::new();
        insert(&mut local, "protected", "local", local_policy, local_trust);
        insert(&mut peer, "protected", "peer", peer_policy, peer_trust);
        // This sorts before the conflict. Staging it must not publish it.
        insert(&mut peer, "aaa-new", "new", 100, 100);
        let before = local.snapshot();
        let error = local.try_merge_snapshot(&peer.snapshot(), &context()).unwrap_err();
        assert_eq!(error.code, CacheErrorCode::VersionRegression);
        assert!(error.message.contains("incomparable authority frontiers"));
        assert_eq!(local.snapshot(), before);
        assert_eq!(local.state_hash(), before.state_hash);
        assert!(local.get("protected", &version("peer", peer_policy, peer_trust)).is_none());
    }
}

#[test]
fn all_small_authority_pairs_either_merge_monotonically_or_refuse_atomically() {
    for lp in 0..4 {
        for lt in 0..4 {
            for pp in 0..4 {
                for pt in 0..4 {
                    let mut local = ModuleCache::new();
                    let mut peer = ModuleCache::new();
                    insert(&mut local, "m", "local", lp, lt);
                    insert(&mut peer, "m", "peer", pp, pt);
                    let before = local.snapshot();
                    let outcome = local.try_merge_snapshot(&peer.snapshot(), &context());
                    let crossed = (pp > lp && pt < lt) || (pp < lp && pt > lt);
                    if crossed {
                        assert_eq!(outcome.unwrap_err().code, CacheErrorCode::VersionRegression);
                        assert_eq!(local.snapshot(), before);
                    } else {
                        outcome.unwrap();
                        let snapshot = local.snapshot();
                        assert_eq!(snapshot.latest_versions["m"].policy_version, lp.max(pp));
                        assert_eq!(snapshot.latest_versions["m"].trust_revision, lt.max(pt));
                        assert!(snapshot.entries.iter().all(|entry| {
                            snapshot.latest_versions.get(&entry.key.module_id) == Some(&entry.key.version)
                        }));
                    }
                }
            }
        }
    }
}

#[test]
fn newer_coherent_snapshot_can_retry_after_an_incomparable_one() {
    let mut local = ModuleCache::new();
    let mut peer = ModuleCache::new();
    insert(&mut local, "m", "local", 7, 10);
    insert(&mut peer, "m", "peer", 8, 3);
    local.try_merge_snapshot(&peer.snapshot(), &context()).unwrap_err();
    insert(&mut peer, "m", "peer", 8, 10);
    local.try_merge_snapshot(&peer.snapshot(), &context()).unwrap();
    assert!(local.get("m", &version("peer", 8, 10)).is_some());
    assert!(local.get("m", &version("local", 7, 10)).is_none());
}

#[test]
fn newer_authority_beats_source_hash_order_and_old_peer_cannot_reverse_it() {
    let mut local = ModuleCache::new();
    let mut peer = ModuleCache::new();
    let old = ModuleVersionFingerprint::new(ContentHash::from_bytes([0xff; 32]), 1, 1);
    let new = ModuleVersionFingerprint::new(ContentHash::from_bytes([0x00; 32]), 2, 2);
    for (cache, value) in [(&mut local, old.clone()), (&mut peer, new.clone())] {
        cache.insert(CacheInsertRequest::new("m", value, ContentHash::compute(b"a"), "/m.js"), &context()).unwrap();
    }
    let old_snapshot = local.snapshot();
    local.try_merge_snapshot(&peer.snapshot(), &context()).unwrap();
    assert!(local.get("m", &new).is_some());
    local.try_merge_snapshot(&old_snapshot, &context()).unwrap();
    assert!(local.get("m", &new).is_some());
    assert!(local.get("m", &old).is_none());
}

#[test]
fn valid_revocation_wins_over_both_local_and_incoming_allow_cache() {
    let mut local = ModuleCache::new();
    insert(&mut local, "m", "source", 1, 1);
    let stale_allow = local.snapshot();
    let mut revoker = ModuleCache::new();
    insert(&mut revoker, "m", "source", 1, 1);
    revoker.invalidate_trust_revocation("m", 2, &context());
    local.try_merge_snapshot(&revoker.snapshot(), &context()).unwrap();
    local.try_merge_snapshot(&stale_allow, &context()).unwrap();
    assert!(local.snapshot().revoked_modules.contains("m"));
    assert!(local.snapshot().entries.is_empty());
    assert!(local.get("m", &version("source", 1, 1)).is_none());
    revoker.try_merge_snapshot(&local.snapshot(), &context()).unwrap();
    assert_eq!(local.state_hash(), revoker.state_hash());
}

#[test]
fn peer_snapshot_is_not_permission_to_clear_a_local_revocation() {
    let mut local = ModuleCache::new();
    local.invalidate_trust_revocation("m", 2, &context());
    let mut peer = ModuleCache::new();
    insert(&mut peer, "m", "source", 1, 3);
    local.try_merge_snapshot(&peer.snapshot(), &context()).unwrap();
    assert!(local.snapshot().revoked_modules.contains("m"));
    assert!(local.snapshot().entries.is_empty());
    assert_eq!(local.snapshot().latest_versions["m"].trust_revision, 3);
    local.try_restore_trust("m", 3, &context()).unwrap_err();
    local.try_restore_trust("m", 4, &context()).unwrap();
    assert!(!local.snapshot().revoked_modules.contains("m"));
}

#[test]
fn conflicting_artifact_rejects_the_entire_staged_merge() {
    for conflict_is_specifier in [false, true] {
        let mut local = ModuleCache::new();
        insert(&mut local, "z", "shared", 2, 2);
        let before = local.snapshot();
        let mut peer = ModuleCache::new();
        insert(&mut peer, "aaa-new", "new", 3, 3);
        insert(&mut peer, "z", "shared", 2, 2);
        let mut snapshot = peer.snapshot();
        if conflict_is_specifier {
            snapshot.entries[1].resolved_specifier = "/wrong.js".into();
        } else {
            snapshot.entries[1].artifact_hash = ContentHash::compute(b"wrong-compiled-artifact");
        }
        snapshot.state_hash = legacy_hash(&snapshot);
        let error = local.try_merge_snapshot(&snapshot, &context()).unwrap_err();
        assert_eq!(error.code, CacheErrorCode::ConflictingArtifact);
        assert_eq!(error.event.error_code, "FE-MODCACHE-0005");
        assert_eq!(local.snapshot(), before);
        assert_eq!(local.state_hash(), before.state_hash);
    }
}

#[test]
fn equivalent_artifacts_converge_when_insertion_sequences_differ() {
    let mut first = ModuleCache::new();
    let mut later = ModuleCache::new();
    insert(&mut first, "m", "source", 1, 1);
    // Advance only the local audit counter, not replicated state.
    later.insert(CacheInsertRequest::new("", version("bad", 0, 0), ContentHash::compute(b"bad"), "/bad"), &context()).unwrap_err();
    insert(&mut later, "m", "source", 1, 1);
    assert_ne!(first.state_hash(), later.state_hash());
    let a = first.snapshot();
    let b = later.snapshot();
    first.try_merge_snapshot(&b, &context()).unwrap();
    later.try_merge_snapshot(&a, &context()).unwrap();
    assert_eq!(first.snapshot(), later.snapshot());
    assert_eq!(first.snapshot().entries[0].inserted_seq, 0);
}

#[test]
fn compatibility_merge_entry_point_records_corruption_denial() {
    let mut local = ModuleCache::new();
    let before = local.snapshot();
    let mut snapshot = source_snapshot();
    snapshot.state_hash = ContentHash::compute(b"invalid");
    local.merge_snapshot(&snapshot, &context());
    assert_eq!(local.snapshot(), before);
    assert_eq!(local.events().last().unwrap().error_code, "FE-MODCACHE-0004");
}

#[test]
fn valid_serde_roundtrip_keeps_snapshot_importable() {
    let snapshot = source_snapshot();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    let decoded: CacheSnapshot = serde_json::from_slice(&bytes).unwrap();
    let mut cache = ModuleCache::new();
    cache.try_merge_snapshot(&decoded, &context()).unwrap();
    assert_eq!(cache.snapshot(), snapshot);
}

#[test]
fn new_error_codes_do_not_reassign_existing_public_codes() {
    let expected = [
        (CacheErrorCode::ModuleRevoked, "FE-MODCACHE-0001"),
        (CacheErrorCode::VersionRegression, "FE-MODCACHE-0002"),
        (CacheErrorCode::EmptyModuleId, "FE-MODCACHE-0003"),
        (CacheErrorCode::InvalidSnapshot, "FE-MODCACHE-0004"),
        (CacheErrorCode::ConflictingArtifact, "FE-MODCACHE-0005"),
    ];
    for (code, name) in expected {
        assert_eq!(code.stable_code(), name);
        let roundtrip: CacheErrorCode = serde_json::from_str(&serde_json::to_string(&code).unwrap()).unwrap();
        assert_eq!(roundtrip, code);
    }
}

#[test]
fn newer_revocation_with_older_policy_still_stops_execution() {
    let mut local = ModuleCache::new();
    insert(&mut local, "m", "live", 7, 3);
    let mut revoker = ModuleCache::new();
    revoker.invalidate_trust_revocation("m", 9, &context());
    local.try_merge_snapshot(&revoker.snapshot(), &context()).unwrap();
    let denied = local.snapshot();
    assert!(denied.revoked_modules.contains("m"));
    assert!(denied.entries.is_empty());
    assert_eq!(denied.latest_versions["m"].policy_version, 7);
    assert_eq!(denied.latest_versions["m"].trust_revision, 9);
    assert!(local.get("m", &version("live", 7, 3)).is_none());
    local.try_restore_trust("m", 9, &context()).unwrap_err();
    revoker.try_merge_snapshot(&denied, &context()).unwrap();
    assert_eq!(local.snapshot(), revoker.snapshot());
}

#[test]
fn deny_only_floor_cannot_be_used_to_relabel_or_reinsert_an_artifact() {
    let mut local = ModuleCache::new();
    insert(&mut local, "m", "live", 7, 3);
    let original = local.snapshot();
    let mut revoker = ModuleCache::new();
    revoker.invalidate_trust_revocation("m", 9, &context());
    local.try_merge_snapshot(&revoker.snapshot(), &context()).unwrap();
    let floor = local.snapshot().latest_versions["m"].clone();
    let request = CacheInsertRequest::new(
        "m", floor, original.entries[0].artifact_hash, "/m.js",
    );
    assert_eq!(local.insert(request, &context()).unwrap_err().code, CacheErrorCode::ModuleRevoked);
    local.try_restore_trust("m", 10, &context()).unwrap();
    assert!(local.snapshot().entries.is_empty());
    assert_eq!(
        local.insert(CacheInsertRequest::new(
            "m", version("rebuilt", 6, 10), ContentHash::compute(b"rebuilt"), "/m.js",
        ), &context()).unwrap_err().code,
        CacheErrorCode::VersionRegression,
    );
    insert(&mut local, "m", "rebuilt", 7, 10);
    assert!(local.get("m", &version("rebuilt", 7, 10)).is_some());
}

#[test]
fn every_small_revoked_pair_keeps_both_floors_and_converges_bidirectionally() {
    for lp in 0..4 {
        for lt in 0..4 {
            for pp in 0..4 {
                for pt in 0..4 {
                    for revoke_local in [false, true] {
                        let mut local = ModuleCache::new();
                        let mut peer = ModuleCache::new();
                        insert(&mut local, "m", "local", lp, lt);
                        insert(&mut peer, "m", "peer", pp, pt);
                        if revoke_local {
                            local.invalidate_trust_revocation("m", lt, &context());
                        } else {
                            peer.invalidate_trust_revocation("m", pt, &context());
                        }
                        let a = local.snapshot();
                        let b = peer.snapshot();
                        local.try_merge_snapshot(&b, &context()).unwrap();
                        peer.try_merge_snapshot(&a, &context()).unwrap();
                        let joined = local.snapshot();
                        assert_eq!(joined, peer.snapshot());
                        assert!(joined.revoked_modules.contains("m"));
                        assert!(joined.entries.is_empty());
                        assert_eq!(joined.latest_versions["m"].policy_version, lp.max(pp));
                        assert_eq!(joined.latest_versions["m"].trust_revision, lt.max(pt));
                        assert_eq!(joined.state_hash, legacy_hash(&joined));
                        local.try_merge_snapshot(&joined, &context()).unwrap();
                        assert_eq!(local.snapshot(), joined);
                    }
                }
            }
        }
    }
}

#[test]
fn revoked_floor_saturates_without_losing_the_other_coordinate() {
    let mut local = ModuleCache::new();
    insert(&mut local, "m", "live", u64::MAX, 0);
    let mut revoker = ModuleCache::new();
    revoker.invalidate_trust_revocation("m", u64::MAX, &context());
    local.try_merge_snapshot(&revoker.snapshot(), &context()).unwrap();
    let snapshot = local.snapshot();
    assert_eq!(snapshot.latest_versions["m"].policy_version, u64::MAX);
    assert_eq!(snapshot.latest_versions["m"].trust_revision, u64::MAX);
    assert!(snapshot.revoked_modules.contains("m"));
    assert!(snapshot.entries.is_empty());
    assert_eq!(
        local.try_restore_trust("m", u64::MAX, &context()).unwrap_err().code,
        CacheErrorCode::VersionRegression,
    );
    assert_eq!(local.snapshot(), snapshot);
}
