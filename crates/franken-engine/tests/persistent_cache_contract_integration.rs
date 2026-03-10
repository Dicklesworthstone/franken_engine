use frankenengine_engine::persistent_cache_contract::*;

// -----------------------------------------------------------------------
// PersistentCacheKeyMaterial — construction, serde, cache_key_id
// -----------------------------------------------------------------------

fn make_key_material(module_id: &str) -> PersistentCacheKeyMaterial {
    PersistentCacheKeyMaterial {
        module_id: module_id.to_string(),
        source_hash: "abc123".to_string(),
        policy_version: 1,
        trust_revision: 1,
        config_fingerprint: "cfg-fp".to_string(),
        dependency_graph_hash: "dep-hash".to_string(),
        transform_profile: "lower_ir3".to_string(),
        runtime_mode: "baseline".to_string(),
        engine_version_marker: "engine-0.1.0".to_string(),
    }
}

#[test]
fn key_material_serde_roundtrip() {
    let km = make_key_material("mod:entry");
    let json = serde_json::to_string(&km).unwrap();
    let back: PersistentCacheKeyMaterial = serde_json::from_str(&json).unwrap();
    assert_eq!(km, back);
}

#[test]
fn key_material_cache_key_id_deterministic() {
    let km = make_key_material("mod:stable");
    let id1 = km.cache_key_id();
    let id2 = km.cache_key_id();
    assert_eq!(id1, id2);
}

#[test]
fn key_material_cache_key_id_differs_by_module() {
    let a = make_key_material("mod:a");
    let b = make_key_material("mod:b");
    assert_ne!(a.cache_key_id(), b.cache_key_id());
}

#[test]
fn key_material_clone_equality() {
    let km = make_key_material("mod:clone");
    assert_eq!(km.clone(), km);
}

// -----------------------------------------------------------------------
// CacheConsumerRoute — serde
// -----------------------------------------------------------------------

#[test]
fn cache_consumer_route_serde_roundtrip() {
    let route = CacheConsumerRoute {
        consumer: "product".to_string(),
        required_fields: vec!["module_id".to_string(), "source_hash".to_string()],
        usage: "compile-cache-lookup".to_string(),
    };
    let json = serde_json::to_string(&route).unwrap();
    let back: CacheConsumerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn cache_consumer_route_clone_equality() {
    let route = CacheConsumerRoute {
        consumer: "replay".to_string(),
        required_fields: vec!["artifact_hash".to_string()],
        usage: "replay-fidelity".to_string(),
    };
    assert_eq!(route.clone(), route);
}

// -----------------------------------------------------------------------
// InvalidationRule — serde
// -----------------------------------------------------------------------

#[test]
fn invalidation_rule_serde_roundtrip() {
    let rule = InvalidationRule {
        rule_id: "rule-001".to_string(),
        trigger: "source_change".to_string(),
        fail_closed_behavior: "evict".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: InvalidationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// -----------------------------------------------------------------------
// PersistentCacheReceipt — serde, field coverage
// -----------------------------------------------------------------------

fn make_receipt(receipt_id: &str) -> PersistentCacheReceipt {
    PersistentCacheReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: receipt_id.to_string(),
        cache_key_id: "ck-001".to_string(),
        module_id: "mod:entry".to_string(),
        source_hash: "src-hash".to_string(),
        policy_version: 1,
        trust_revision: 1,
        artifact_hash: "art-hash".to_string(),
        snapshot_state_hash: "snap-hash".to_string(),
        resolved_specifier: "/app/entry.js".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        consumers: vec!["product".to_string()],
        rollback_target_receipt_id: None,
    }
}

#[test]
fn receipt_serde_roundtrip() {
    let r = make_receipt("rcpt-001");
    let json = serde_json::to_string(&r).unwrap();
    let back: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn receipt_schema_version_matches_const() {
    let r = make_receipt("rcpt-schema");
    assert_eq!(r.schema_version, RECEIPT_SCHEMA_VERSION);
}

#[test]
fn receipt_clone_equality() {
    let r = make_receipt("rcpt-clone");
    assert_eq!(r.clone(), r);
}

#[test]
fn receipt_with_rollback_target() {
    let mut r = make_receipt("rcpt-rb");
    r.rollback_target_receipt_id = Some("rcpt-old".to_string());
    let json = serde_json::to_string(&r).unwrap();
    let back: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert_eq!(
        back.rollback_target_receipt_id,
        Some("rcpt-old".to_string())
    );
}

// -----------------------------------------------------------------------
// CacheRollbackPlan — serde
// -----------------------------------------------------------------------

fn make_rollback_plan() -> CacheRollbackPlan {
    CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "policy_update".to_string(),
        rollback_receipt_id: "rcpt-target".to_string(),
        rollback_cache_key_id: "ck-target".to_string(),
        criteria: vec!["source_hash_mismatch".to_string()],
        fail_closed: true,
    }
}

#[test]
fn rollback_plan_serde_roundtrip() {
    let plan = make_rollback_plan();
    let json = serde_json::to_string(&plan).unwrap();
    let back: CacheRollbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

#[test]
fn rollback_plan_fail_closed_flag() {
    let plan = make_rollback_plan();
    assert!(plan.fail_closed);
}

// -----------------------------------------------------------------------
// ContractScenarioResult — serde
// -----------------------------------------------------------------------

#[test]
fn contract_scenario_result_serde_roundtrip() {
    let r = ContractScenarioResult {
        scenario_id: "s-001".to_string(),
        outcome: "pass".to_string(),
        detail: "cache hit verified".to_string(),
        error_code: None,
        receipt_id: Some("rcpt-001".to_string()),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ContractScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn contract_scenario_result_with_error() {
    let r = ContractScenarioResult {
        scenario_id: "s-002".to_string(),
        outcome: "fail".to_string(),
        detail: "cache miss".to_string(),
        error_code: Some("FE-PCACHE-0001".to_string()),
        receipt_id: None,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: ContractScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// -----------------------------------------------------------------------
// TraceIdsArtifact — serde
// -----------------------------------------------------------------------

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    let a = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-1".to_string(), "trace-2".to_string()],
        decision_id: "d-001".to_string(),
        policy_id: "p-001".to_string(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
}

// -----------------------------------------------------------------------
// StructuredLogEvent — serde
// -----------------------------------------------------------------------

#[test]
fn structured_log_event_serde_roundtrip() {
    let e = StructuredLogEvent {
        trace_id: "t-log".to_string(),
        decision_id: "d-log".to_string(),
        policy_id: "p-log".to_string(),
        component: COMPONENT.to_string(),
        event: "cache_hit".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        scenario_id: Some("s-001".to_string()),
        receipt_id: Some("rcpt-001".to_string()),
        detail: "lookup succeeded".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn structured_log_event_with_error_code() {
    let e = StructuredLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "test".to_string(),
        event: "cache_miss".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-PCACHE-0001".to_string()),
        scenario_id: None,
        receipt_id: None,
        detail: "no entry".to_string(),
    };
    assert_eq!(e.error_code.as_deref(), Some("FE-PCACHE-0001"));
}

// -----------------------------------------------------------------------
// PersistentCacheContractError — Display, error_code
// -----------------------------------------------------------------------

#[test]
fn error_missing_entry_display_and_code() {
    let e = PersistentCacheContractError::MissingEntry {
        module_id: "mod:test".to_string(),
        cache_key_id: "ck-123".to_string(),
    };
    assert_eq!(e.error_code(), "FE-PCACHE-0001");
    let s = e.to_string();
    assert!(s.contains("mod:test"));
    assert!(s.contains("ck-123"));
}

#[test]
fn error_receipt_field_mismatch_display_and_code() {
    let e = PersistentCacheContractError::ReceiptFieldMismatch {
        field: "source_hash",
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    assert_eq!(e.error_code(), "FE-PCACHE-0002");
    assert!(e.to_string().contains("source_hash"));
}

#[test]
fn error_rollback_target_missing_display_and_code() {
    let e = PersistentCacheContractError::RollbackTargetMissing {
        receipt_id: "rcpt-missing".to_string(),
    };
    assert_eq!(e.error_code(), "FE-PCACHE-0003");
    assert!(e.to_string().contains("rcpt-missing"));
}

#[test]
fn error_empty_rollback_criteria_display_and_code() {
    let e = PersistentCacheContractError::EmptyRollbackCriteria;
    assert_eq!(e.error_code(), "FE-PCACHE-0004");
    assert!(e.to_string().contains("empty"));
}

#[test]
fn error_serializes_missing_entry() {
    let e = PersistentCacheContractError::MissingEntry {
        module_id: "m".to_string(),
        cache_key_id: "c".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("MissingEntry"));
    assert!(json.contains("\"module_id\""));
}

#[test]
fn error_serializes_rollback_target_missing() {
    let e = PersistentCacheContractError::RollbackTargetMissing {
        receipt_id: "r".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("RollbackTargetMissing"));
}

#[test]
fn error_serializes_empty_rollback_criteria() {
    let e = PersistentCacheContractError::EmptyRollbackCriteria;
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("EmptyRollbackCriteria"));
}

#[test]
fn error_serializes_receipt_field_mismatch() {
    let e = PersistentCacheContractError::ReceiptFieldMismatch {
        field: "source_hash",
        expected: "e".to_string(),
        actual: "a".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("source_hash"));
    assert!(json.contains("ReceiptFieldMismatch"));
}

// -----------------------------------------------------------------------
// apply_rollback_plan — logic tests
// -----------------------------------------------------------------------

#[test]
fn apply_rollback_plan_empty_criteria_rejected() {
    let plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "test".to_string(),
        rollback_receipt_id: "rcpt-target".to_string(),
        rollback_cache_key_id: "ck-target".to_string(),
        criteria: vec![],
        fail_closed: true,
    };
    let result = apply_rollback_plan(&plan, &[make_receipt("rcpt-target")]);
    assert!(result.is_err());
}

#[test]
fn apply_rollback_plan_target_found() {
    let plan = make_rollback_plan();
    let receipts = vec![make_receipt("rcpt-other"), make_receipt("rcpt-target")];
    let result = apply_rollback_plan(&plan, &receipts);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().receipt_id, "rcpt-target");
}

#[test]
fn apply_rollback_plan_target_missing() {
    let plan = make_rollback_plan();
    let receipts = vec![make_receipt("rcpt-other")];
    let result = apply_rollback_plan(&plan, &receipts);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// ArtifactContext — construction
// -----------------------------------------------------------------------

#[test]
fn artifact_context_new_sets_defaults() {
    let ctx = ArtifactContext::new("/tmp/artifacts");
    assert!(ctx.run_id.starts_with("run-persistent_cache_contract-"));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
}

// -----------------------------------------------------------------------
// Schema version constants
// -----------------------------------------------------------------------

#[test]
fn schema_version_constants_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!RECEIPT_SCHEMA_VERSION.is_empty());
    assert!(!ROLLBACK_PLAN_SCHEMA_VERSION.is_empty());
    assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_versions_all_unique() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RECEIPT_SCHEMA_VERSION,
        ROLLBACK_PLAN_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for v in &versions {
        seen.insert(*v);
    }
    assert_eq!(seen.len(), versions.len());
}

// -----------------------------------------------------------------------
// render_summary — smoke test
// -----------------------------------------------------------------------

#[test]
fn render_summary_contains_key_sections() {
    let contract = PersistentCacheContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        contract_hash: "hash-abc".to_string(),
        key_fields: vec!["module_id".to_string()],
        invalidation_rules: vec![],
        consumer_routes: vec![CacheConsumerRoute {
            consumer: "product".to_string(),
            required_fields: vec!["module_id".to_string()],
            usage: "lookup".to_string(),
        }],
        key_material_examples: vec![],
        receipts: vec![make_receipt("rcpt-summary")],
        rollback_plan: make_rollback_plan(),
        scenarios: vec![ContractScenarioResult {
            scenario_id: "s-sum".to_string(),
            outcome: "pass".to_string(),
            detail: "ok".to_string(),
            error_code: None,
            receipt_id: None,
        }],
    };
    let summary = render_summary(&contract);
    assert!(summary.contains("Persistent Cache Contract Summary"));
    assert!(summary.contains("Consumer Routes"));
    assert!(summary.contains("product"));
    assert!(summary.contains("Scenario Outcomes"));
}
