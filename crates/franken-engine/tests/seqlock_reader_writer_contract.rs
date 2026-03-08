use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceLedgerQuery, GovernanceRationale, ScorecardSnapshot,
};
use frankenengine_engine::seqlock_fastpath::{
    FastPathFallbackReason, FastPathReadSource, FastPathTelemetry, RetryBudgetPolicy,
    SnapshotFastPath,
};

fn sample_scorecard() -> ScorecardSnapshot {
    ScorecardSnapshot {
        ev_millionths: 120_000,
        confidence_millionths: 820_000,
        risk_of_harm_millionths: 90_000,
        implementation_friction_millionths: 40_000,
        cross_initiative_interference_millionths: 20_000,
        operational_burden_millionths: 30_000,
    }
}

fn automatic_input(
    decision_id: &str,
    moonshot_id: &str,
    decision_type: GovernanceDecisionType,
    timestamp_ns: u64,
) -> GovernanceLedgerInput {
    GovernanceLedgerInput {
        decision_id: decision_id.to_string(),
        moonshot_id: moonshot_id.to_string(),
        decision_type,
        actor: GovernanceActor::System("scheduler".to_string()),
        rationale: GovernanceRationale::for_automatic_decision(
            "automatic decision",
            820_000,
            90_000,
            vec!["artifact_obligations_met".to_string()],
            Vec::new(),
        ),
        scorecard_snapshot: sample_scorecard(),
        artifact_references: vec!["artifact://scorecard/1".to_string()],
        timestamp_ns,
        moonshot_started_at_ns: Some(1),
    }
}

#[test]
fn module_cache_snapshot_fastpath_contract_updates_telemetry() {
    let mut cache = ModuleCache::new();
    assert_eq!(
        cache.snapshot_fastpath_policy(),
        RetryBudgetPolicy::new(2, 2)
    );

    let empty_snapshot = cache.snapshot();
    assert!(empty_snapshot.entries.is_empty());

    let cold_telemetry = cache.snapshot_fastpath_telemetry();
    assert_eq!(cold_telemetry.fallback_reads, 0);
    assert_eq!(cold_telemetry.uninitialized_fallbacks, 0);
    assert_eq!(cold_telemetry.fast_path_reads, 1);
    assert_eq!(cold_telemetry.writes, 0);

    let ctx = CacheContext::new("trace-seqlock", "decision-seqlock", "policy-seqlock");
    let version = ModuleVersionFingerprint::new(ContentHash::compute(b"module-a"), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:a",
                version.clone(),
                ContentHash::compute(b"artifact-a"),
                "file:///mod/a.js",
            ),
            &ctx,
        )
        .expect("cache insert");

    let snapshot = cache.snapshot();
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].key.version, version);

    let telemetry = cache.snapshot_fastpath_telemetry();
    assert_eq!(telemetry.writes, 1);
    assert!(telemetry.fast_path_reads >= 1);
    assert_eq!(telemetry.fallback_reads, 0);
}

#[test]
fn seeded_fastpath_baseline_is_read_without_fallback_or_synthetic_write() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert!(fast_path.seed_if_uninitialized(41_u64));
    assert!(!fast_path.seed_if_uninitialized(99_u64));

    let result = fast_path.read_clone_or_else(|| 7_u64);

    assert_eq!(result.value, 41);
    assert_eq!(result.source, FastPathReadSource::FastPath);
    assert_eq!(result.fallback_reason, None);

    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.writes, 0);
    assert_eq!(telemetry.fast_path_reads, 1);
    assert_eq!(telemetry.fallback_reads, 0);
    assert_eq!(telemetry.uninitialized_fallbacks, 0);
}

#[test]
fn governance_head_view_fastpath_contract_tracks_checkpoint_projection() {
    let mut ledger = GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 2,
        signer_key: b"ledger-test-key".to_vec(),
        policy_id: "moonshot-governor-policy-test".to_string(),
    })
    .expect("ledger");
    assert_eq!(
        ledger.head_view_fastpath_policy(),
        RetryBudgetPolicy::new(4, 1)
    );
    assert!(ledger.latest_checkpoint_view().is_none());

    let cold_telemetry = ledger.head_view_fastpath_telemetry();
    assert_eq!(cold_telemetry.fallback_reads, 0);
    assert_eq!(cold_telemetry.uninitialized_fallbacks, 0);
    assert_eq!(cold_telemetry.fast_path_reads, 1);
    assert_eq!(cold_telemetry.writes, 0);

    ledger
        .append(automatic_input(
            "decision-1",
            "moon-1",
            GovernanceDecisionType::Promote,
            10,
        ))
        .expect("append decision-1");
    ledger
        .append(automatic_input(
            "decision-2",
            "moon-1",
            GovernanceDecisionType::Hold,
            20,
        ))
        .expect("append decision-2");

    let entries = ledger.query(&GovernanceLedgerQuery::all());
    assert_eq!(entries.len(), 2);

    let checkpoint = ledger
        .latest_checkpoint_view()
        .expect("checkpoint projection");
    assert_eq!(checkpoint.sequence, 2);
    assert_eq!(checkpoint.entry_count, 2);

    let telemetry = ledger.head_view_fastpath_telemetry();
    assert_eq!(telemetry.writes, 2);
    assert!(telemetry.fast_path_reads >= 2);
    assert_eq!(telemetry.fallback_reads, 0);
}

// ---------------------------------------------------------------------------
// SnapshotFastPath: uninitialized reads fall back
// ---------------------------------------------------------------------------

#[test]
fn uninitialized_fastpath_falls_back() {
    let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
    assert!(!fast_path.is_initialized());

    let result = fast_path.read_clone_or_else(|| 42_u64);
    assert_eq!(result.value, 42);
    assert_eq!(result.source, FastPathReadSource::Fallback);
    assert!(result.fallback_reason.is_some());

    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.uninitialized_fallbacks, 1);
    assert_eq!(telemetry.fast_path_reads, 0);
    assert_eq!(telemetry.fallback_reads, 1);
}

#[test]
fn initialized_after_seed() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert!(!fast_path.is_initialized());
    fast_path.seed_if_uninitialized(100_u64);
    assert!(fast_path.is_initialized());
}

// ---------------------------------------------------------------------------
// SnapshotFastPath: publish updates value
// ---------------------------------------------------------------------------

#[test]
fn publish_updates_readable_value() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized(10_u64);

    let r1 = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(r1.value, 10);

    fast_path.publish(20_u64);
    let r2 = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(r2.value, 20);

    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.writes, 1); // publish counts as a write
}

#[test]
fn multiple_publishes_track_writes() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized(1_u64);

    for i in 2..=5 {
        fast_path.publish(i as u64);
    }

    let result = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(result.value, 5);

    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.writes, 4);
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicy
// ---------------------------------------------------------------------------

#[test]
fn retry_budget_policy_serde_roundtrip() {
    let policy = RetryBudgetPolicy::new(3, 2);
    let json = serde_json::to_string(&policy).expect("serialize");
    let parsed: RetryBudgetPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, parsed);
}

#[test]
fn retry_budget_policy_fields() {
    let policy = RetryBudgetPolicy::new(5, 3);
    assert_eq!(policy.max_retries, 5);
    assert_eq!(policy.max_writer_pressure_observations, 3);
}

#[test]
fn retry_budget_policy_zero_retries() {
    let policy = RetryBudgetPolicy::new(0, 0);
    assert_eq!(policy.max_retries, 0);
    assert_eq!(policy.max_writer_pressure_observations, 0);
}

// ---------------------------------------------------------------------------
// FastPathReadSource
// ---------------------------------------------------------------------------

#[test]
fn fast_path_read_source_serde_roundtrip() {
    let sources = [FastPathReadSource::FastPath, FastPathReadSource::Fallback];
    for source in &sources {
        let json = serde_json::to_string(source).expect("serialize");
        let parsed: FastPathReadSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*source, parsed);
    }
}

#[test]
fn fast_path_read_source_debug_distinct() {
    let fp = format!("{:?}", FastPathReadSource::FastPath);
    let fb = format!("{:?}", FastPathReadSource::Fallback);
    assert_ne!(fp, fb);
}

// ---------------------------------------------------------------------------
// FastPathTelemetry
// ---------------------------------------------------------------------------

#[test]
fn telemetry_serde_roundtrip() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized(42_u64);
    let _ = fast_path.read_clone_or_else(|| 0_u64);
    fast_path.publish(43_u64);

    let telemetry = fast_path.telemetry();
    let json = serde_json::to_string(&telemetry).expect("serialize");
    let parsed: FastPathTelemetry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(telemetry, parsed);
}

#[test]
fn telemetry_total_reads_is_sum() {
    let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
    // First read: uninitialized fallback
    let _ = fast_path.read_clone_or_else(|| 0_u64);
    // Seed and read: fast path
    fast_path.seed_if_uninitialized(10_u64);
    let _ = fast_path.read_clone_or_else(|| 0_u64);

    let t = fast_path.telemetry();
    assert_eq!(t.total_reads, t.fast_path_reads + t.fallback_reads);
}

// ---------------------------------------------------------------------------
// FastPathFallbackReason
// ---------------------------------------------------------------------------

#[test]
fn fallback_reason_serde_roundtrip() {
    let reasons = [
        FastPathFallbackReason::Uninitialized,
        FastPathFallbackReason::RetryBudgetExceeded,
        FastPathFallbackReason::WriterPressure,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).expect("serialize");
        let parsed: FastPathFallbackReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*reason, parsed);
    }
}

// ---------------------------------------------------------------------------
// FastPathReadResult
// ---------------------------------------------------------------------------

#[test]
fn read_result_fast_path_has_zero_fallback_reason() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized(99_u64);

    let result = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(result.source, FastPathReadSource::FastPath);
    assert!(result.fallback_reason.is_none());
    // Fast path reads may have 0 retry attempts
    assert!(result.attempts <= 1);
}

#[test]
fn read_result_fallback_has_reason() {
    let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(0, 0));
    let result = fast_path.read_clone_or_else(|| 77_u64);
    assert_eq!(result.source, FastPathReadSource::Fallback);
    assert!(result.fallback_reason.is_some());
}

// ---------------------------------------------------------------------------
// SnapshotFastPath policy getter
// ---------------------------------------------------------------------------

#[test]
fn policy_getter_returns_construction_policy() {
    let policy = RetryBudgetPolicy::new(7, 3);
    let fast_path = SnapshotFastPath::<u64>::new(policy);
    assert_eq!(fast_path.policy(), policy);
}

// ---------------------------------------------------------------------------
// Module cache: multiple inserts
// ---------------------------------------------------------------------------

#[test]
fn module_cache_multiple_inserts_tracked_by_telemetry() {
    let mut cache = ModuleCache::new();
    let ctx = CacheContext::new("trace-multi", "decision-multi", "policy-multi");

    for i in 0..3 {
        let version =
            ModuleVersionFingerprint::new(ContentHash::compute(format!("mod-{i}").as_bytes()), 1, 1);
        cache
            .insert(
                CacheInsertRequest::new(
                    format!("mod:{i}"),
                    version,
                    ContentHash::compute(format!("art-{i}").as_bytes()),
                    format!("file:///mod/{i}.js"),
                ),
                &ctx,
            )
            .expect("insert");
    }

    let snapshot = cache.snapshot();
    assert_eq!(snapshot.entries.len(), 3);

    let telemetry = cache.snapshot_fastpath_telemetry();
    assert_eq!(telemetry.writes, 3);
}

// ---------------------------------------------------------------------------
// Governance ledger: multiple moonshots
// ---------------------------------------------------------------------------

#[test]
fn governance_ledger_multiple_moonshots_tracked() {
    let mut ledger = GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 3,
        signer_key: b"test-key".to_vec(),
        policy_id: "policy-multi-moon".to_string(),
    })
    .expect("ledger");

    for i in 0..3 {
        ledger
            .append(automatic_input(
                &format!("decision-{i}"),
                &format!("moon-{i}"),
                GovernanceDecisionType::Promote,
                (i + 1) * 10,
            ))
            .expect("append");
    }

    let entries = ledger.query(&GovernanceLedgerQuery::all());
    assert_eq!(entries.len(), 3);
}

// ---------------------------------------------------------------------------
// Seed idempotency
// ---------------------------------------------------------------------------

#[test]
fn seed_is_idempotent() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert!(fast_path.seed_if_uninitialized(10_u64));
    assert!(!fast_path.seed_if_uninitialized(20_u64));
    let result = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(result.value, 10); // First seed wins
}

// ---------------------------------------------------------------------------
// Multiple reads increment telemetry
// ---------------------------------------------------------------------------

#[test]
fn multiple_reads_increment_telemetry() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized(42_u64);

    for _ in 0..5 {
        let _ = fast_path.read_clone_or_else(|| 0_u64);
    }

    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.fast_path_reads, 5);
    assert_eq!(telemetry.total_reads, 5);
}

// ---------------------------------------------------------------------------
// String value in SnapshotFastPath
// ---------------------------------------------------------------------------

#[test]
fn snapshot_fastpath_with_string_values() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    fast_path.seed_if_uninitialized("hello".to_string());

    let r1 = fast_path.read_clone_or_else(|| "fallback".to_string());
    assert_eq!(r1.value, "hello");

    fast_path.publish("world".to_string());
    let r2 = fast_path.read_clone_or_else(|| "fallback".to_string());
    assert_eq!(r2.value, "world");
}

// ---------------------------------------------------------------------------
// Telemetry default state
// ---------------------------------------------------------------------------

#[test]
fn fresh_telemetry_all_zeroes() {
    let fast_path = SnapshotFastPath::<u64>::new(RetryBudgetPolicy::new(2, 1));
    let telemetry = fast_path.telemetry();
    assert_eq!(telemetry.total_reads, 0);
    assert_eq!(telemetry.fast_path_reads, 0);
    assert_eq!(telemetry.fallback_reads, 0);
    assert_eq!(telemetry.total_retries, 0);
    assert_eq!(telemetry.writes, 0);
}

// ---------------------------------------------------------------------------
// RetryBudgetPolicy equality
// ---------------------------------------------------------------------------

#[test]
fn retry_budget_policy_equality() {
    let a = RetryBudgetPolicy::new(3, 2);
    let b = RetryBudgetPolicy::new(3, 2);
    let c = RetryBudgetPolicy::new(4, 2);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Publish without seed uses publish value
// ---------------------------------------------------------------------------

#[test]
fn publish_without_prior_seed_initializes() {
    let fast_path = SnapshotFastPath::new(RetryBudgetPolicy::new(2, 1));
    assert!(!fast_path.is_initialized());
    fast_path.publish(50_u64);
    assert!(fast_path.is_initialized());

    let result = fast_path.read_clone_or_else(|| 0_u64);
    assert_eq!(result.value, 50);
    assert_eq!(result.source, FastPathReadSource::FastPath);
}

// ---------------------------------------------------------------------------
// Module cache empty snapshot
// ---------------------------------------------------------------------------

#[test]
fn module_cache_empty_snapshot_has_zero_entries() {
    let cache = ModuleCache::new();
    let snapshot = cache.snapshot();
    assert!(snapshot.entries.is_empty());
}

// ---------------------------------------------------------------------------
// FastPathReadSource and FallbackReason are distinct
// ---------------------------------------------------------------------------

#[test]
fn all_fallback_reasons_distinct_debug() {
    let reasons = [
        FastPathFallbackReason::Uninitialized,
        FastPathFallbackReason::RetryBudgetExceeded,
        FastPathFallbackReason::WriterPressure,
    ];
    let debugs: Vec<String> = reasons.iter().map(|r| format!("{r:?}")).collect();
    for (i, d1) in debugs.iter().enumerate() {
        for (j, d2) in debugs.iter().enumerate() {
            if i != j {
                assert_ne!(d1, d2, "reasons {i} and {j} have same debug");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry serde for module cache
// ---------------------------------------------------------------------------

#[test]
fn module_cache_telemetry_serde_roundtrip() {
    let mut cache = ModuleCache::new();
    let ctx = CacheContext::new("trace-tserde", "decision-tserde", "policy-tserde");
    let version = ModuleVersionFingerprint::new(ContentHash::compute(b"serde-mod"), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:serde-test",
                version,
                ContentHash::compute(b"serde-art"),
                "file:///mod/serde.js",
            ),
            &ctx,
        )
        .expect("insert");

    let telemetry = cache.snapshot_fastpath_telemetry();
    let json = serde_json::to_string(&telemetry).expect("serialize");
    let parsed: FastPathTelemetry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(telemetry, parsed);
}

// ---------------------------------------------------------------------------
// Governance ledger query filters
// ---------------------------------------------------------------------------

#[test]
fn governance_ledger_query_by_moonshot_filters_correctly() {
    let mut ledger = GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 5,
        signer_key: b"filter-key".to_vec(),
        policy_id: "policy-filter".to_string(),
    })
    .expect("ledger");

    ledger
        .append(automatic_input(
            "d1",
            "moon-alpha",
            GovernanceDecisionType::Promote,
            10,
        ))
        .expect("append");
    ledger
        .append(automatic_input(
            "d2",
            "moon-beta",
            GovernanceDecisionType::Hold,
            20,
        ))
        .expect("append");
    ledger
        .append(automatic_input(
            "d3",
            "moon-alpha",
            GovernanceDecisionType::Kill,
            30,
        ))
        .expect("append");

    let all = ledger.query(&GovernanceLedgerQuery::all());
    assert_eq!(all.len(), 3);

    let alpha_query = GovernanceLedgerQuery {
        moonshot_id: Some("moon-alpha".to_string()),
        ..GovernanceLedgerQuery::all()
    };
    let alpha_only = ledger.query(&alpha_query);
    assert_eq!(alpha_only.len(), 2);
    for entry in &alpha_only {
        assert_eq!(entry.moonshot_id, "moon-alpha");
    }
}
