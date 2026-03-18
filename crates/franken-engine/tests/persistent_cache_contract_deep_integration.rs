//! Deep integration tests for persistent_cache_contract module.
//!
//! Covers: key material derivation, receipt verification, rollback plans,
//! contract artifacts, serde roundtrips, error code stability, and
//! bundle generation determinism.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::ModuleVersionFingerprint;
use frankenengine_engine::persistent_cache_contract::{
    ArtifactContext, BEAD_ID, COMPONENT, CONTRACT_SCHEMA_VERSION, CacheConsumerRoute,
    CacheRollbackPlan, ContractScenarioResult, InvalidationRule, PersistentCacheContractArtifact,
    PersistentCacheContractError, PersistentCacheKeyMaterial, PersistentCacheReceipt,
    RECEIPT_SCHEMA_VERSION, ROLLBACK_PLAN_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION,
    StructuredLogEvent, TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact, apply_rollback_plan,
    render_summary,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!RECEIPT_SCHEMA_VERSION.is_empty());
    assert!(!ROLLBACK_PLAN_SCHEMA_VERSION.is_empty());
    assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn deep_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn deep_component_name() {
    assert_eq!(COMPONENT, "persistent_cache_contract");
}

// ---------------------------------------------------------------------------
// PersistentCacheKeyMaterial
// ---------------------------------------------------------------------------

fn make_fingerprint(version: u8) -> ModuleVersionFingerprint {
    ModuleVersionFingerprint::new(
        ContentHash::compute(format!("source:v{}", version).as_bytes()),
        version as u64,
        version as u64,
    )
}

fn make_key_material(module_id: &str, version: u8) -> PersistentCacheKeyMaterial {
    let fp = make_fingerprint(version);
    let config_hash = ContentHash::compute(b"config:test");
    let dep_hash = ContentHash::compute(b"deps:test");
    PersistentCacheKeyMaterial::from_fingerprint(
        module_id,
        &fp,
        config_hash,
        dep_hash,
        "lower_ir3",
        "deterministic",
        "engine-0.1.0",
    )
}

#[test]
fn deep_key_material_deterministic_cache_key() {
    let k1 = make_key_material("mod:test", 1);
    let k2 = make_key_material("mod:test", 1);
    assert_eq!(k1.cache_key_id(), k2.cache_key_id());
}

#[test]
fn deep_key_material_different_modules_different_keys() {
    let k1 = make_key_material("mod:a", 1);
    let k2 = make_key_material("mod:b", 1);
    assert_ne!(k1.cache_key_id(), k2.cache_key_id());
}

#[test]
fn deep_key_material_different_versions_different_keys() {
    let k1 = make_key_material("mod:test", 1);
    let k2 = make_key_material("mod:test", 2);
    assert_ne!(k1.cache_key_id(), k2.cache_key_id());
}

#[test]
fn deep_key_material_serde_roundtrip() {
    let km = make_key_material("mod:serde_test", 3);
    let json = serde_json::to_string(&km).unwrap();
    let decoded: PersistentCacheKeyMaterial = serde_json::from_str(&json).unwrap();
    assert_eq!(km, decoded);
    assert_eq!(km.cache_key_id(), decoded.cache_key_id());
}

#[test]
fn deep_key_material_fields_populated() {
    let km = make_key_material("mod:fields", 5);
    assert_eq!(km.module_id, "mod:fields");
    assert!(!km.source_hash.is_empty());
    assert_eq!(km.policy_version, 5);
    assert_eq!(km.trust_revision, 5);
    assert!(!km.config_fingerprint.is_empty());
    assert!(!km.dependency_graph_hash.is_empty());
    assert_eq!(km.transform_profile, "lower_ir3");
    assert_eq!(km.runtime_mode, "deterministic");
    assert_eq!(km.engine_version_marker, "engine-0.1.0");
}

// ---------------------------------------------------------------------------
// PersistentCacheReceipt
// ---------------------------------------------------------------------------

fn make_receipt(id: &str, module_id: &str) -> PersistentCacheReceipt {
    PersistentCacheReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: id.to_string(),
        cache_key_id: format!("key-{}", id),
        module_id: module_id.to_string(),
        source_hash: "sha256:abc".to_string(),
        policy_version: 1,
        trust_revision: 1,
        artifact_hash: "sha256:def".to_string(),
        snapshot_state_hash: "sha256:ghi".to_string(),
        resolved_specifier: "/app/entry.js".to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        consumers: vec!["product".to_string(), "benchmark".to_string()],
        rollback_target_receipt_id: None,
    }
}

#[test]
fn deep_receipt_serde_roundtrip() {
    let receipt = make_receipt("r-001", "mod:entry");
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

#[test]
fn deep_receipt_with_rollback_target() {
    let mut receipt = make_receipt("r-002", "mod:entry");
    receipt.rollback_target_receipt_id = Some("r-001".to_string());
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
    assert_eq!(
        decoded.rollback_target_receipt_id,
        Some("r-001".to_string())
    );
}

// ---------------------------------------------------------------------------
// CacheRollbackPlan
// ---------------------------------------------------------------------------

fn make_rollback_plan(target: &str) -> CacheRollbackPlan {
    CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "policy_version_mismatch".to_string(),
        rollback_receipt_id: target.to_string(),
        rollback_cache_key_id: format!("key-{}", target),
        criteria: vec!["policy_version".to_string(), "trust_revision".to_string()],
        fail_closed: true,
    }
}

#[test]
fn deep_rollback_plan_serde_roundtrip() {
    let plan = make_rollback_plan("r-001");
    let json = serde_json::to_string(&plan).unwrap();
    let decoded: CacheRollbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, decoded);
}

// ---------------------------------------------------------------------------
// apply_rollback_plan
// ---------------------------------------------------------------------------

#[test]
fn deep_rollback_finds_target() {
    let plan = make_rollback_plan("r-001");
    let receipts = vec![
        make_receipt("r-001", "mod:entry"),
        make_receipt("r-002", "mod:entry"),
    ];
    let result = apply_rollback_plan(&plan, &receipts);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().receipt_id, "r-001");
}

#[test]
fn deep_rollback_missing_target() {
    let plan = make_rollback_plan("r-999");
    let receipts = vec![make_receipt("r-001", "mod:entry")];
    let result = apply_rollback_plan(&plan, &receipts);
    assert!(result.is_err());
    match result.unwrap_err() {
        PersistentCacheContractError::RollbackTargetMissing { receipt_id } => {
            assert_eq!(receipt_id, "r-999");
        }
        other => panic!("Expected RollbackTargetMissing, got {:?}", other),
    }
}

#[test]
fn deep_rollback_empty_criteria() {
    let mut plan = make_rollback_plan("r-001");
    plan.criteria.clear();
    let receipts = vec![make_receipt("r-001", "mod:entry")];
    let result = apply_rollback_plan(&plan, &receipts);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        PersistentCacheContractError::EmptyRollbackCriteria
    ));
}

// ---------------------------------------------------------------------------
// PersistentCacheContractError
// ---------------------------------------------------------------------------

#[test]
fn deep_error_codes_stable() {
    let errors = [
        PersistentCacheContractError::MissingEntry {
            module_id: "mod:test".to_string(),
            cache_key_id: "key-test".to_string(),
        },
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "source_hash",
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: "r-001".to_string(),
        },
        PersistentCacheContractError::EmptyRollbackCriteria,
    ];

    let expected_codes = [
        "FE-PCACHE-0001",
        "FE-PCACHE-0002",
        "FE-PCACHE-0003",
        "FE-PCACHE-0004",
    ];

    for (error, expected_code) in errors.iter().zip(expected_codes.iter()) {
        assert_eq!(error.error_code(), *expected_code);
    }
}

#[test]
fn deep_error_display_includes_code() {
    let error = PersistentCacheContractError::MissingEntry {
        module_id: "mod:test".to_string(),
        cache_key_id: "key-test".to_string(),
    };
    let display = format!("{}", error);
    assert!(display.contains("FE-PCACHE-0001"));
    assert!(display.contains("mod:test"));
}

#[test]
fn deep_error_serializes_all_variants() {
    // PersistentCacheContractError has &'static str fields, so full deserialization
    // roundtrip is not possible from temporary strings. Verify serialization works.
    let errors: Vec<PersistentCacheContractError> = vec![
        PersistentCacheContractError::MissingEntry {
            module_id: "mod:test".to_string(),
            cache_key_id: "key-test".to_string(),
        },
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "source_hash",
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: "r-001".to_string(),
        },
        PersistentCacheContractError::EmptyRollbackCriteria,
    ];
    for error in &errors {
        let json = serde_json::to_string(error).unwrap();
        assert!(!json.is_empty());
        // Verify the JSON is valid by parsing as generic Value
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn deep_error_receipt_field_mismatch_serializes() {
    let error = PersistentCacheContractError::ReceiptFieldMismatch {
        field: "source_hash",
        expected: "a".to_string(),
        actual: "b".to_string(),
    };
    let json = serde_json::to_string(&error).unwrap();
    assert!(json.contains("source_hash"));
    assert!(json.contains("ReceiptFieldMismatch"));
}

// ---------------------------------------------------------------------------
// InvalidationRule
// ---------------------------------------------------------------------------

#[test]
fn deep_invalidation_rule_serde_roundtrip() {
    let rule = InvalidationRule {
        rule_id: "INV-001".to_string(),
        trigger: "source_hash_change".to_string(),
        fail_closed_behavior: "evict_and_recompute".to_string(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let decoded: InvalidationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, decoded);
}

// ---------------------------------------------------------------------------
// CacheConsumerRoute
// ---------------------------------------------------------------------------

#[test]
fn deep_consumer_route_serde_roundtrip() {
    let route = CacheConsumerRoute {
        consumer: "product".to_string(),
        required_fields: vec!["artifact_hash".to_string(), "source_hash".to_string()],
        usage: "baseline execution".to_string(),
    };
    let json = serde_json::to_string(&route).unwrap();
    let decoded: CacheConsumerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, decoded);
}

// ---------------------------------------------------------------------------
// ContractScenarioResult
// ---------------------------------------------------------------------------

#[test]
fn deep_scenario_result_serde_roundtrip() {
    let result = ContractScenarioResult {
        scenario_id: "cache-hit-v1".to_string(),
        outcome: "pass".to_string(),
        detail: "Exact match found".to_string(),
        error_code: None,
        receipt_id: Some("r-001".to_string()),
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: ContractScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

#[test]
fn deep_scenario_result_with_error() {
    let result = ContractScenarioResult {
        scenario_id: "cache-miss".to_string(),
        outcome: "fail".to_string(),
        detail: "No entry found".to_string(),
        error_code: Some("FE-PCACHE-0001".to_string()),
        receipt_id: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: ContractScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// ---------------------------------------------------------------------------
// TraceIdsArtifact
// ---------------------------------------------------------------------------

#[test]
fn deep_trace_ids_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-001".to_string(), "trace-002".to_string()],
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, decoded);
}

// ---------------------------------------------------------------------------
// StructuredLogEvent
// ---------------------------------------------------------------------------

#[test]
fn deep_log_event_serde_roundtrip() {
    let event = StructuredLogEvent {
        trace_id: "trace-001".to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        component: COMPONENT.to_string(),
        event: "cache_insert".to_string(),
        outcome: "success".to_string(),
        error_code: None,
        scenario_id: Some("cache-insert-v1".to_string()),
        receipt_id: Some("r-001".to_string()),
        detail: "Inserted module cache entry".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// ArtifactContext
// ---------------------------------------------------------------------------

#[test]
fn deep_artifact_context_new() {
    let ctx = ArtifactContext::new("/tmp/test-artifacts");
    assert_eq!(
        ctx.artifact_dir,
        std::path::PathBuf::from("/tmp/test-artifacts")
    );
    assert!(ctx.run_id.starts_with("run-persistent_cache_contract-"));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(!ctx.generated_at_utc.is_empty());
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn deep_render_summary_contains_key_fields() {
    let contract = PersistentCacheContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T00:00:00Z".to_string(),
        contract_hash: "sha256:test".to_string(),
        key_fields: vec!["source_hash".to_string()],
        invalidation_rules: vec![],
        consumer_routes: vec![CacheConsumerRoute {
            consumer: "product".to_string(),
            required_fields: vec!["artifact_hash".to_string()],
            usage: "baseline execution".to_string(),
        }],
        key_material_examples: vec![],
        receipts: vec![make_receipt("r-001", "mod:entry")],
        rollback_plan: make_rollback_plan("r-001"),
        scenarios: vec![ContractScenarioResult {
            scenario_id: "test-scenario".to_string(),
            outcome: "pass".to_string(),
            detail: "Test passed".to_string(),
            error_code: None,
            receipt_id: None,
        }],
    };

    let summary = render_summary(&contract);
    assert!(summary.contains("Persistent Cache Contract Summary"));
    assert!(summary.contains(BEAD_ID));
    assert!(summary.contains(COMPONENT));
    assert!(summary.contains("product"));
    assert!(summary.contains("test-scenario"));
}

// ---------------------------------------------------------------------------
// PersistentCacheContractArtifact serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn deep_contract_artifact_serde_roundtrip() {
    let contract = PersistentCacheContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: "2026-03-18T12:00:00Z".to_string(),
        contract_hash: "sha256:roundtrip".to_string(),
        key_fields: vec!["source_hash".to_string(), "policy_version".to_string()],
        invalidation_rules: vec![InvalidationRule {
            rule_id: "INV-001".to_string(),
            trigger: "source_change".to_string(),
            fail_closed_behavior: "evict".to_string(),
        }],
        consumer_routes: vec![CacheConsumerRoute {
            consumer: "product".to_string(),
            required_fields: vec!["artifact_hash".to_string()],
            usage: "execution".to_string(),
        }],
        key_material_examples: vec![make_key_material("mod:example", 1)],
        receipts: vec![make_receipt("r-rt-001", "mod:example")],
        rollback_plan: make_rollback_plan("r-rt-001"),
        scenarios: vec![ContractScenarioResult {
            scenario_id: "roundtrip-scenario".to_string(),
            outcome: "pass".to_string(),
            detail: "Roundtrip verification passed".to_string(),
            error_code: None,
            receipt_id: Some("r-rt-001".to_string()),
        }],
    };
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let decoded: PersistentCacheContractArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, decoded);
}

// ---------------------------------------------------------------------------
// Bundle emit determinism
// ---------------------------------------------------------------------------

#[test]
fn deep_emit_default_bundle_succeeds() {
    use frankenengine_engine::persistent_cache_contract::emit_default_contract_bundle;

    let dir = std::env::temp_dir().join(format!("deep-pcache-bundle-{}", std::process::id()));
    let ctx = ArtifactContext::new(&dir);
    let result = emit_default_contract_bundle(&ctx);
    assert!(
        result.is_ok(),
        "Bundle emit should succeed: {:?}",
        result.err()
    );

    let report = result.unwrap();
    assert!(report.run_manifest_path.exists());
    assert!(report.trace_ids_path.exists());
    assert!(!report.contract.receipts.is_empty());
    assert!(!report.contract.scenarios.is_empty());
}
