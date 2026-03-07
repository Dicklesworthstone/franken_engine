use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};
use frankenengine_engine::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceLedgerQuery, GovernanceRationale, ScorecardSnapshot,
};
use frankenengine_engine::seqlock_fastpath::RetryBudgetPolicy;

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
