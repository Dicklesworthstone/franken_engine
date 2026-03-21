#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::{
    CacheContext, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};
use frankenengine_engine::persistent_cache_contract::{
    ArtifactContext, BEAD_ID, COMPONENT, CONTRACT_SCHEMA_VERSION, CacheConsumerRoute,
    CacheRollbackPlan, ContractScenarioResult, InvalidationRule, PersistentCacheContractError,
    PersistentCacheKeyMaterial, PersistentCacheReceipt, RECEIPT_SCHEMA_VERSION,
    ROLLBACK_PLAN_SCHEMA_VERSION, RUN_MANIFEST_SCHEMA_VERSION, StructuredLogEvent,
    TRACE_IDS_SCHEMA_VERSION, TraceIdsArtifact, apply_rollback_plan, emit_default_contract_bundle,
    render_summary, verify_receipt,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "franken-engine-pcache-enrich-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn make_key_material(module_id: &str, source: &[u8]) -> PersistentCacheKeyMaterial {
    let fp = ModuleVersionFingerprint::new(ContentHash::compute(source), 1, 1);
    PersistentCacheKeyMaterial::from_fingerprint(
        module_id,
        &fp,
        ContentHash::compute(b"cfg"),
        ContentHash::compute(b"deps"),
        "lower_ir3",
        "baseline_deterministic_profile",
        "engine-0.1.0",
    )
}

fn make_receipt(receipt_id: &str) -> PersistentCacheReceipt {
    PersistentCacheReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: receipt_id.to_string(),
        cache_key_id: "sha256:key".to_string(),
        module_id: "mod:test".to_string(),
        source_hash: "sha256:src".to_string(),
        policy_version: 1,
        trust_revision: 1,
        artifact_hash: "sha256:art".to_string(),
        snapshot_state_hash: "sha256:snap".to_string(),
        resolved_specifier: "/test.js".to_string(),
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        consumers: vec!["product".to_string()],
        rollback_target_receipt_id: None,
    }
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_roundtrip_persistent_cache_key_material() {
    let km = make_key_material("mod:test", b"source");
    let json = serde_json::to_string(&km).unwrap();
    let back: PersistentCacheKeyMaterial = serde_json::from_str(&json).unwrap();
    assert_eq!(km, back);
    assert_eq!(km.cache_key_id(), back.cache_key_id());
}

#[test]
fn serde_roundtrip_persistent_cache_receipt() {
    let receipt = make_receipt("r-1");
    let json = serde_json::to_string(&receipt).unwrap();
    let back: PersistentCacheReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn serde_roundtrip_cache_rollback_plan() {
    let plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "test".to_string(),
        rollback_receipt_id: "r-1".to_string(),
        rollback_cache_key_id: "sha256:abc".to_string(),
        criteria: vec!["test criterion".to_string()],
        fail_closed: true,
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: CacheRollbackPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

#[test]
fn serde_roundtrip_contract_scenario_result() {
    let result = ContractScenarioResult {
        scenario_id: "test-scenario".into(),
        outcome: "pass".into(),
        detail: "test".into(),
        error_code: None,
        receipt_id: Some("r-1".into()),
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: ContractScenarioResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn serde_roundtrip_trace_ids_artifact() {
    let artifact = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec!["trace-1".into(), "trace-2".into()],
        decision_id: "decision-1".into(),
        policy_id: "policy-1".into(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn serde_roundtrip_structured_log_event() {
    let event = StructuredLogEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: COMPONENT.into(),
        event: "cache_receipt_emitted".into(),
        outcome: "pass".into(),
        error_code: None,
        scenario_id: Some("cache_hit".into()),
        receipt_id: Some("r-1".into()),
        detail: "test detail".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn serde_roundtrip_invalidation_rule() {
    let rule = InvalidationRule {
        rule_id: "source_update".into(),
        trigger: "source hash changes".into(),
        fail_closed_behavior: "reject old receipt".into(),
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: InvalidationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn serde_roundtrip_cache_consumer_route() {
    let route = CacheConsumerRoute {
        consumer: "product".into(),
        required_fields: vec!["module_id".into(), "artifact_hash".into()],
        usage: "compile pipeline".into(),
    };
    let json = serde_json::to_string(&route).unwrap();
    let back: CacheConsumerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn serde_persistent_cache_contract_error_all_serialize() {
    // Note: PersistentCacheContractError contains `field: &'static str` in ReceiptFieldMismatch,
    // which prevents full deserialization roundtrip. We test serialization only.
    let variants: Vec<PersistentCacheContractError> = vec![
        PersistentCacheContractError::MissingEntry {
            module_id: "m".into(),
            cache_key_id: "k".into(),
        },
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "f",
            expected: "e".into(),
            actual: "a".into(),
        },
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: "r".into(),
        },
        PersistentCacheContractError::EmptyRollbackCriteria,
    ];
    let mut jsons = BTreeSet::new();
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        assert!(!json.is_empty());
        jsons.insert(json);
    }
    assert_eq!(
        jsons.len(),
        variants.len(),
        "all variants produce distinct JSON"
    );
}

// ---------------------------------------------------------------------------
// cache_key_id determinism
// ---------------------------------------------------------------------------

#[test]
fn cache_key_id_deterministic() {
    let m1 = make_key_material("mod:test", b"source");
    let m2 = m1.clone();
    assert_eq!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_sources() {
    let m1 = make_key_material("mod:a", b"src-a");
    let m2 = make_key_material("mod:a", b"src-b");
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_modules() {
    let m1 = make_key_material("mod:a", b"source");
    let m2 = make_key_material("mod:b", b"source");
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_policy_versions() {
    let m1 = make_key_material("mod:a", b"source");
    let mut m2 = m1.clone();
    m2.policy_version = 999;
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_trust_revision() {
    let m1 = make_key_material("mod:a", b"source");
    let mut m2 = m1.clone();
    m2.trust_revision = 999;
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_config_fingerprint() {
    let m1 = make_key_material("mod:a", b"source");
    let mut m2 = m1.clone();
    m2.config_fingerprint = "different".into();
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_differs_for_different_transform_profile() {
    let m1 = make_key_material("mod:a", b"source");
    let mut m2 = m1.clone();
    m2.transform_profile = "codegen_aot".into();
    assert_ne!(m1.cache_key_id(), m2.cache_key_id());
}

#[test]
fn cache_key_id_is_sha256_prefixed() {
    let m = make_key_material("mod:test", b"source");
    let key = m.cache_key_id();
    assert!(key.starts_with("sha256:"));
    assert_eq!(key.len(), 7 + 64);
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[test]
fn error_codes_are_distinct() {
    let codes = [
        PersistentCacheContractError::MissingEntry {
            module_id: String::new(),
            cache_key_id: String::new(),
        }
        .error_code(),
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "x",
            expected: String::new(),
            actual: String::new(),
        }
        .error_code(),
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: String::new(),
        }
        .error_code(),
        PersistentCacheContractError::EmptyRollbackCriteria.error_code(),
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn error_codes_all_start_with_fe_pcache() {
    let errors = [
        PersistentCacheContractError::MissingEntry {
            module_id: "m".into(),
            cache_key_id: "k".into(),
        },
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "f",
            expected: "e".into(),
            actual: "a".into(),
        },
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: "r".into(),
        },
        PersistentCacheContractError::EmptyRollbackCriteria,
    ];
    for err in &errors {
        assert!(err.error_code().starts_with("FE-PCACHE-"));
    }
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_include_error_code() {
    let errors = [
        PersistentCacheContractError::MissingEntry {
            module_id: "m1".into(),
            cache_key_id: "k1".into(),
        },
        PersistentCacheContractError::ReceiptFieldMismatch {
            field: "source_hash",
            expected: "aaa".into(),
            actual: "bbb".into(),
        },
        PersistentCacheContractError::RollbackTargetMissing {
            receipt_id: "r1".into(),
        },
        PersistentCacheContractError::EmptyRollbackCriteria,
    ];
    for err in &errors {
        let display = err.to_string();
        assert!(display.contains(err.error_code()));
    }
}

#[test]
fn error_is_std_error() {
    let err = PersistentCacheContractError::EmptyRollbackCriteria;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Rollback plan
// ---------------------------------------------------------------------------

#[test]
fn rollback_plan_empty_criteria_rejected() {
    let plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "manual".to_string(),
        rollback_receipt_id: "r1".to_string(),
        rollback_cache_key_id: "key1".to_string(),
        criteria: vec![],
        fail_closed: false,
    };
    let err = apply_rollback_plan(&plan, &[]).unwrap_err();
    assert_eq!(err.error_code(), "FE-PCACHE-0004");
}

#[test]
fn rollback_plan_target_missing_error() {
    let plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "corruption".to_string(),
        rollback_receipt_id: "missing".to_string(),
        rollback_cache_key_id: "sha256:none".to_string(),
        criteria: vec!["receipt verification fails".to_string()],
        fail_closed: true,
    };
    let err = apply_rollback_plan(&plan, &[]).unwrap_err();
    assert_eq!(err.error_code(), "FE-PCACHE-0003");
}

#[test]
fn rollback_plan_succeeds_when_target_present() {
    let target = make_receipt("target-r1");
    let other = PersistentCacheReceipt {
        receipt_id: "other-r2".to_string(),
        ..target.clone()
    };
    let plan = CacheRollbackPlan {
        schema_version: ROLLBACK_PLAN_SCHEMA_VERSION.to_string(),
        trigger: "corruption_detected".to_string(),
        rollback_receipt_id: "target-r1".to_string(),
        rollback_cache_key_id: "sha256:key".to_string(),
        criteria: vec!["receipt verification fails".to_string()],
        fail_closed: true,
    };
    let found = apply_rollback_plan(&plan, &[other, target.clone()]).unwrap();
    assert_eq!(found.receipt_id, "target-r1");
}

// ---------------------------------------------------------------------------
// verify_receipt
// ---------------------------------------------------------------------------

#[test]
fn verify_receipt_detects_artifact_hash_corruption() {
    let fp = ModuleVersionFingerprint::new(ContentHash::compute(b"source:v1"), 1, 1);
    let material = PersistentCacheKeyMaterial::from_fingerprint(
        "mod:test",
        &fp,
        ContentHash::compute(b"cfg"),
        ContentHash::compute(b"deps"),
        "lower_ir3",
        "profile",
        "0.1.0",
    );
    let mut cache = ModuleCache::new();
    let ctx = CacheContext::new("t", "d", "p");
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:test",
                fp.clone(),
                ContentHash::compute(b"artifact"),
                "/test.js",
            ),
            &ctx,
        )
        .unwrap();
    let snapshot = cache.snapshot();
    let entry = cache.get("mod:test", &fp).unwrap().clone();

    let receipt = PersistentCacheReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION.to_string(),
        receipt_id: "r-test".to_string(),
        cache_key_id: material.cache_key_id(),
        module_id: entry.key.module_id.clone(),
        source_hash: material.source_hash.clone(),
        policy_version: material.policy_version,
        trust_revision: material.trust_revision,
        artifact_hash: "sha256:tampered".to_string(),
        snapshot_state_hash: snapshot.state_hash.to_hex(),
        resolved_specifier: entry.resolved_specifier.clone(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        consumers: vec!["product".to_string()],
        rollback_target_receipt_id: None,
    };
    let err = verify_receipt(&receipt, &entry, &snapshot, &material).unwrap_err();
    assert_eq!(err.error_code(), "FE-PCACHE-0002");
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_constants_start_with_franken_engine() {
    assert!(CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(RECEIPT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ROLLBACK_PLAN_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn schema_version_constants_are_mutually_distinct() {
    let versions = [
        CONTRACT_SCHEMA_VERSION,
        RECEIPT_SCHEMA_VERSION,
        ROLLBACK_PLAN_SCHEMA_VERSION,
        TRACE_IDS_SCHEMA_VERSION,
        RUN_MANIFEST_SCHEMA_VERSION,
    ];
    let set: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(set.len(), versions.len());
}

#[test]
fn bead_and_component_are_non_empty() {
    assert!(!BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// ArtifactContext
// ---------------------------------------------------------------------------

#[test]
fn artifact_context_defaults_are_reasonable() {
    let ctx = ArtifactContext::new("/tmp/test-pcache-enrich");
    assert!(ctx.run_id.starts_with("run-persistent_cache_contract-"));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(!ctx.command_invocation.is_empty());
}

#[test]
fn artifact_context_generated_at_utc_is_rfc3339() {
    let ctx = ArtifactContext::new("/tmp/ctx-time-enrich");
    assert!(ctx.generated_at_utc.ends_with('Z') || ctx.generated_at_utc.contains('+'));
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_contains_header() {
    let context = ArtifactContext::new("/tmp/render-test-enrich");
    let report = emit_default_contract_bundle(&context).expect("bundle write");
    let summary = render_summary(&report.contract);
    assert!(summary.contains("# Persistent Cache Contract Summary"));
    assert!(summary.contains("## Consumer Routes"));
    assert!(summary.contains("## Scenario Outcomes"));
    let _ = std::fs::remove_dir_all(context.artifact_dir);
}

// ---------------------------------------------------------------------------
// emit_default_contract_bundle
// ---------------------------------------------------------------------------

#[test]
fn emit_default_bundle_creates_files() {
    let artifact_dir = temp_dir("emit-bundle-enrich");
    let context = ArtifactContext::new(&artifact_dir);
    let report = emit_default_contract_bundle(&context).expect("bundle write");
    assert!(report.run_manifest_path.exists());
    assert!(report.trace_ids_path.exists());
    assert!(!report.written_files.is_empty());
    for hash in report.written_files.values() {
        assert!(hash.starts_with("sha256:"));
    }
    let _ = std::fs::remove_dir_all(&artifact_dir);
}

#[test]
fn emit_default_bundle_contract_is_consistent() {
    let artifact_dir = temp_dir("emit-bundle-consist-enrich");
    let context = ArtifactContext::new(&artifact_dir);
    let report = emit_default_contract_bundle(&context).expect("bundle write");
    assert_eq!(report.contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(report.contract.bead_id, BEAD_ID);
    assert_eq!(report.contract.component, COMPONENT);
    assert!(!report.contract.invalidation_rules.is_empty());
    assert!(!report.contract.consumer_routes.is_empty());
    assert_eq!(report.contract.receipts.len(), 2);
    assert_eq!(report.contract.scenarios.len(), 5);
    let _ = std::fs::remove_dir_all(&artifact_dir);
}

#[test]
fn emit_default_bundle_all_scenarios_pass() {
    let artifact_dir = temp_dir("emit-bundle-pass-enrich");
    let context = ArtifactContext::new(&artifact_dir);
    let report = emit_default_contract_bundle(&context).expect("bundle write");
    for scenario in &report.contract.scenarios {
        assert_eq!(
            scenario.outcome, "pass",
            "scenario {} should pass",
            scenario.scenario_id
        );
    }
    let _ = std::fs::remove_dir_all(&artifact_dir);
}
