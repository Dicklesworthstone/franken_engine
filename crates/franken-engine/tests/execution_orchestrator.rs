//! Integration tests for `ExecutionOrchestrator`.

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

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
    OrchestratorError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn simple_package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn high_capability_package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "high-cap-ext".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: (0..16).map(|i| format!("cap_{i}")).collect(),
        version: "2.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

// -----------------------------------------------------------------------
// 1. End-to-end simple source
// -----------------------------------------------------------------------

#[test]
fn end_to_end_simple_source() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-42", "42");
    let result = orch.execute(&pkg).expect("execute should succeed");

    assert_eq!(result.extension_id, "ext-42");
    assert!(!result.trace_id.is_empty());
    assert!(!result.decision_id.is_empty());
    assert!(!result.source_label.is_empty());
    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
    assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
    assert!(result.instructions_executed > 0);
}

// -----------------------------------------------------------------------
// 2. High capability extension
// -----------------------------------------------------------------------

#[test]
fn high_capability_extension_produces_valid_decision() {
    let config = OrchestratorConfig {
        loss_matrix_preset: LossMatrixPreset::Conservative,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = high_capability_package();
    let result = orch.execute(&pkg).expect("execute should succeed");

    assert!(result.posterior.is_valid());
    assert!(!result.evidence_entries.is_empty());
    assert_eq!(result.extension_id, "high-cap-ext");
}

// -----------------------------------------------------------------------
// 3. Evidence entries contain required fields
// -----------------------------------------------------------------------

#[test]
fn evidence_entries_contain_required_fields() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-evidence", "42");
    let result = orch.execute(&pkg).expect("execute");

    let entry = &result.evidence_entries[0];
    assert!(!entry.entry_id.is_empty());
    assert!(!entry.trace_id.is_empty());
    assert!(!entry.decision_id.is_empty());
    assert!(!entry.evidence_hash.is_empty());
    assert!(!entry.candidates.is_empty());
    assert!(!entry.chosen_action.action_name.is_empty());
    assert!(!entry.witnesses.is_empty());
    assert!(!entry.metadata.is_empty());
}

// -----------------------------------------------------------------------
// 4. Empty source returns error
// -----------------------------------------------------------------------

#[test]
fn empty_source_returns_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "ext-empty".to_string(),
        source: "".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("empty source should fail");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

// -----------------------------------------------------------------------
// 5. Empty extension ID returns error
// -----------------------------------------------------------------------

#[test]
fn empty_extension_id_returns_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("empty id should fail");
    assert!(matches!(err, OrchestratorError::EmptyExtensionId));
}

// -----------------------------------------------------------------------
// 6. Multiple executions accumulate evidence
// -----------------------------------------------------------------------

#[test]
fn multiple_executions_accumulate_evidence() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    for i in 0..3 {
        let pkg = simple_package(&format!("ext-{i}"), "42");
        orch.execute(&pkg).expect("execute");
    }
    assert_eq!(orch.execution_count(), 3);
    assert!(orch.ledger().len() >= 3);
}

// ────────────────────────────────────────────────────────────
// Enrichment: config variants, error display, serde, determinism
// ────────────────────────────────────────────────────────────

#[test]
fn conservative_preset_produces_valid_execution() {
    let config = OrchestratorConfig {
        loss_matrix_preset: LossMatrixPreset::Conservative,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-cons", "42");
    let result = orch.execute(&pkg).expect("execute should succeed");
    assert_eq!(result.extension_id, "ext-cons");
    assert!(result.posterior.is_valid());
}

#[test]
fn permissive_preset_produces_valid_execution() {
    let config = OrchestratorConfig {
        loss_matrix_preset: LossMatrixPreset::Permissive,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-perm", "42");
    let result = orch.execute(&pkg).expect("execute should succeed");
    assert_eq!(result.extension_id, "ext-perm");
    assert!(result.posterior.is_valid());
}

#[test]
fn deterministic_execution_produces_consistent_results() {
    let mut orch1 = ExecutionOrchestrator::with_defaults();
    let mut orch2 = ExecutionOrchestrator::with_defaults();

    let pkg = simple_package("ext-det", "42");
    let r1 = orch1.execute(&pkg).expect("first");
    let r2 = orch2.execute(&pkg).expect("second");

    assert_eq!(r1.extension_id, r2.extension_id);
    assert_eq!(r1.execution_value, r2.execution_value);
    assert_eq!(r1.instructions_executed, r2.instructions_executed);
}

#[test]
fn orchestrator_error_display_is_non_empty() {
    let err = OrchestratorError::EmptySource;
    assert!(!err.to_string().is_empty());

    let err2 = OrchestratorError::EmptyExtensionId;
    assert!(!err2.to_string().is_empty());
}

#[test]
fn extension_package_serde_round_trip() {
    let pkg = simple_package("ext-serde", "1 + 2");
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pkg.extension_id, recovered.extension_id);
    assert_eq!(pkg.source, recovered.source);
    assert_eq!(pkg.version, recovered.version);
}

#[test]
fn execution_count_starts_at_zero() {
    let orch = ExecutionOrchestrator::with_defaults();
    assert_eq!(orch.execution_count(), 0);
}

#[test]
fn ledger_starts_empty() {
    let orch = ExecutionOrchestrator::with_defaults();
    assert!(orch.ledger().is_empty());
}

#[test]
fn custom_epoch_propagates_to_result() {
    let config = OrchestratorConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-epoch", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn metadata_in_package_is_preserved() {
    let mut metadata = BTreeMap::new();
    metadata.insert("author".to_string(), "test".to_string());
    metadata.insert("license".to_string(), "MIT".to_string());

    let pkg = ExtensionPackage {
        extension_id: "ext-meta".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec!["cap_a".to_string()],
        version: "1.0.0".to_string(),
        metadata: metadata.clone(),
    };

    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.metadata, metadata);
    assert_eq!(recovered.capabilities, vec!["cap_a"]);
}

#[test]
fn execute_blocks_unresolved_ifc_runtime_checkpoint_before_interpreter() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package(
        "ext-ifc-runtime-checkpoint",
        r#"let secret_token = "secret_token"; sink(secret_token);"#,
    );

    let err = orch
        .execute(&pkg)
        .expect_err("unresolved runtime checkpoint must fail closed");
    match err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("runtime checkpoints=1"));
            assert!(detail.contains("hostcall.invoke"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: serde, error paths, accessors, result fields
// ────────────────────────────────────────────────────────────

#[test]
fn loss_matrix_preset_serde_round_trip() {
    for preset in [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ] {
        let json = serde_json::to_string(&preset).expect("serialize");
        let recovered: LossMatrixPreset = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(preset, recovered);
    }
}

#[test]
fn orchestrator_config_default_values() {
    let cfg = OrchestratorConfig::default();
    assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
    assert_eq!(cfg.drain_deadline_ticks, 10_000);
    assert_eq!(cfg.max_concurrent_sagas, 4);
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
    assert!(cfg.force_lane.is_none());
    assert_eq!(cfg.trace_id_prefix, "orch");
    assert_eq!(cfg.policy_id, "default-policy");
}

#[test]
fn orchestrator_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptySource);
    assert!(!err.to_string().is_empty());
}

#[test]
fn orchestrator_error_display_all_variants_unique() {
    let errors = [
        OrchestratorError::EmptySource,
        OrchestratorError::EmptyExtensionId,
    ];
    let msgs: std::collections::BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(msgs.len(), errors.len());
}

#[test]
fn result_lowering_events_populated() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-lower", "42");
    let result = orch.execute(&pkg).expect("execute");
    // Lowering pipeline should produce at least one event and one witness
    assert!(!result.lowering_events.is_empty());
    assert!(!result.lowering_witnesses.is_empty());
}

#[test]
fn result_lane_and_reason_populated() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-lane", "42");
    let result = orch.execute(&pkg).expect("execute");
    // Lane reason should have a non-empty description
    let reason_str = format!("{:?}", result.lane_reason);
    assert!(!reason_str.is_empty());
}

#[test]
fn result_containment_action_populated() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-cont", "42");
    let result = orch.execute(&pkg).expect("execute");
    let action_str = format!("{:?}", result.containment_action);
    assert!(!action_str.is_empty());
}

#[test]
fn result_risk_state_populated() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-risk", "42");
    let result = orch.execute(&pkg).expect("execute");
    let risk_str = format!("{:?}", result.risk_state);
    assert!(!risk_str.is_empty());
}

#[test]
fn result_action_decision_populated() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-action", "42");
    let result = orch.execute(&pkg).expect("execute");
    let decision_str = format!("{:?}", result.action_decision);
    assert!(!decision_str.is_empty());
}

#[test]
fn saga_orchestrator_accessor_returns_reference() {
    let orch = ExecutionOrchestrator::with_defaults();
    let saga = orch.saga_orchestrator();
    let debug = format!("{:?}", saga);
    assert!(!debug.is_empty());
}

#[test]
fn trace_id_uses_configured_prefix() {
    let config = OrchestratorConfig {
        trace_id_prefix: "custom-prefix".to_string(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-prefix", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        result.trace_id.starts_with("custom-prefix"),
        "trace_id {} should start with custom-prefix",
        result.trace_id
    );
}

#[test]
fn balanced_preset_is_default() {
    let cfg = OrchestratorConfig::default();
    assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
    let mut orch = ExecutionOrchestrator::new(cfg);
    let pkg = simple_package("ext-bal", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(result.posterior.is_valid());
}

#[test]
fn execution_value_is_deterministic_across_configs() {
    let configs = [
        OrchestratorConfig::default(),
        OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Conservative,
            ..OrchestratorConfig::default()
        },
        OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Permissive,
            ..OrchestratorConfig::default()
        },
    ];
    let values: Vec<String> = configs
        .into_iter()
        .map(|c| {
            let mut orch = ExecutionOrchestrator::new(c);
            let pkg = simple_package("ext-val", "42");
            orch.execute(&pkg).expect("execute").execution_value
        })
        .collect();
    // Same source should produce the same execution value regardless of loss preset
    assert_eq!(values[0], values[1]);
    assert_eq!(values[1], values[2]);
}

#[test]
fn ledger_length_matches_execution_count() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    for i in 0..5 {
        let pkg = simple_package(&format!("ext-ledger-{i}"), "42");
        orch.execute(&pkg).expect("execute");
    }
    assert_eq!(orch.execution_count(), 5);
    assert!(
        orch.ledger().len() >= 5,
        "ledger should contain at least one entry per execution"
    );
}

#[test]
fn extension_package_with_many_capabilities_serde_round_trip() {
    let pkg = ExtensionPackage {
        extension_id: "ext-many-caps".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: (0..32).map(|i| format!("cap_{i}")).collect(),
        version: "3.0.0".to_string(),
        metadata: BTreeMap::from([
            ("key1".to_string(), "val1".to_string()),
            ("key2".to_string(), "val2".to_string()),
        ]),
    };
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.capabilities.len(), 32);
    assert_eq!(recovered.metadata.len(), 2);
    assert_eq!(recovered.version, "3.0.0");
}

#[test]
fn orchestrator_config_debug_is_nonempty() {
    let config = OrchestratorConfig::default();
    assert!(!format!("{config:?}").is_empty());
}

#[test]
fn loss_matrix_preset_debug_is_nonempty() {
    let preset = LossMatrixPreset::Balanced;
    assert!(!format!("{preset:?}").is_empty());
}

#[test]
fn orchestrator_error_debug_is_nonempty() {
    let err = OrchestratorError::EmptySource;
    assert!(!format!("{err:?}").is_empty());
}

// ────────────────────────────────────────────────────────────────────────────
// Enrichment batch: ~70 new tests covering gaps in existing test coverage
// ────────────────────────────────────────────────────────────────────────────

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::ts_normalization::SourceLanguage;

// -- ExtensionPackage source_file Some vs None serde roundtrips ---------------

#[test]
fn extension_package_with_source_file_some_serde_roundtrip() {
    let pkg = ExtensionPackage {
        extension_id: "ext-sf-some".to_string(),
        source: "42".to_string(),
        source_file: Some("main.js".to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.source_file, Some("main.js".to_string()));
}

#[test]
fn extension_package_with_source_file_none_serde_roundtrip() {
    let pkg = simple_package("ext-sf-none", "42");
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.source_file, None);
}

// -- source_file influences source_label in result ----------------------------

#[test]
fn source_file_js_does_not_trigger_ts_normalization() {
    let pkg = ExtensionPackage {
        extension_id: "ext-sf-js".to_string(),
        source: "42".to_string(),
        source_file: Some("app.js".to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orch = ExecutionOrchestrator::with_defaults();
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(
        result.source_ingestion.source_language,
        SourceLanguage::JavaScript
    );
    assert!(!result.source_ingestion.normalization_applied);
}

#[test]
fn source_file_ts_triggers_ts_normalization_pathway() {
    let pkg = ExtensionPackage {
        extension_id: "ext-sf-ts".to_string(),
        source: "42".to_string(),
        source_file: Some("app.ts".to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orch = ExecutionOrchestrator::with_defaults();
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(
        result.source_ingestion.source_language,
        SourceLanguage::TypeScript
    );
    assert!(result.source_ingestion.normalization_applied);
}

// -- OrchestratorResult field coverage ----------------------------------------

#[test]
fn result_source_ingestion_populated_for_js() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-si", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(
        result.source_ingestion.source_language,
        SourceLanguage::JavaScript
    );
    assert!(!result.source_ingestion.original_source_hash.is_empty());
    assert!(!result.source_ingestion.normalized_source_hash.is_empty());
}

#[test]
fn result_optimal_stopping_certificate_present() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-osc", "42");
    let result = orch.execute(&pkg).expect("execute");
    let cert = result
        .optimal_stopping_certificate
        .as_ref()
        .expect("certificate should be present");
    assert!(!cert.schema.is_empty());
    assert!(!cert.algorithm.is_empty());
    assert!(cert.observations_before_stop >= 1);
}

#[test]
fn result_ir3_schedule_cost_is_some_and_non_negative() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-cost", "42");
    let result = orch.execute(&pkg).expect("execute");
    let cost = result.ir3_schedule_cost.expect("should have schedule cost");
    assert!(cost.0 >= 0, "schedule cost should be non-negative");
}

#[test]
fn result_adaptive_router_summary_present() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-ars", "42");
    let result = orch.execute(&pkg).expect("execute");
    let summary = result
        .adaptive_router_summary
        .as_ref()
        .expect("adaptive router summary should be present");
    let debug = format!("{summary:?}");
    assert!(!debug.is_empty());
}

#[test]
fn result_expected_loss_millionths_is_non_negative() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-loss", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        result.expected_loss_millionths >= 0,
        "expected_loss should be non-negative, got {}",
        result.expected_loss_millionths
    );
}

#[test]
fn result_cell_events_nonempty_after_execution() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-ce", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        !result.cell_events.is_empty(),
        "cell close should produce at least one event"
    );
}

#[test]
fn result_finalize_result_is_some() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-fr", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(result.finalize_result.is_some());
}

#[test]
fn result_containment_receipt_absent_for_benign_execution() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-cr", "42");
    let result = orch.execute(&pkg).expect("execute");
    // Simple benign source with default config should not trigger containment
    // beyond sandbox/allow
    if result.containment_action == ContainmentAction::Allow {
        assert!(result.containment_receipt.is_none());
        assert!(result.saga_id.is_none());
    }
}

#[test]
fn result_action_decision_action_matches_containment_action_or_stopping_override() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-ad", "42");
    let result = orch.execute(&pkg).expect("execute");
    // Containment action can differ from action_decision.action due to stopping override
    let base_action = result.action_decision.action;
    assert!(
        result.containment_action == base_action
            || result.containment_action == ContainmentAction::Sandbox,
        "containment action should match decision or be Sandbox (stopping override)"
    );
}

// -- OrchestratorError Display for all variants --------------------------------

#[test]
fn orchestrator_error_display_empty_source_exact() {
    let err = OrchestratorError::EmptySource;
    assert_eq!(err.to_string(), "extension source is empty");
}

#[test]
fn orchestrator_error_display_empty_extension_id_exact() {
    let err = OrchestratorError::EmptyExtensionId;
    assert_eq!(err.to_string(), "extension_id is empty");
}

#[test]
fn orchestrator_error_display_ifc_contains_detail() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "ext-ifc-display".to_string(),
        source: r#"let secret_token = "secret_token"; sink(secret_token);"#.to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("should fail with IFC guard");
    let msg = err.to_string();
    assert!(
        msg.contains("ifc runtime guard blocked"),
        "should contain ifc message: {msg}"
    );
}

// -- OrchestratorError Debug for all variants ---------------------------------

#[test]
fn orchestrator_error_debug_empty_source() {
    let err = OrchestratorError::EmptySource;
    assert!(format!("{err:?}").contains("EmptySource"));
}

#[test]
fn orchestrator_error_debug_empty_extension_id() {
    let err = OrchestratorError::EmptyExtensionId;
    assert!(format!("{err:?}").contains("EmptyExtensionId"));
}

// -- OrchestratorError is std::error::Error -----------------------------------

#[test]
fn orchestrator_error_empty_source_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptySource);
    assert!(err.to_string().contains("empty"));
}

#[test]
fn orchestrator_error_empty_extension_id_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptyExtensionId);
    assert!(err.to_string().contains("empty"));
}

// -- LossMatrixPreset serde with invalid JSON ---------------------------------

#[test]
fn loss_matrix_preset_serde_rejects_unknown_variant() {
    let result = serde_json::from_str::<LossMatrixPreset>("\"Unknown\"");
    assert!(result.is_err());
}

#[test]
fn loss_matrix_preset_serde_rejects_number() {
    let result = serde_json::from_str::<LossMatrixPreset>("42");
    assert!(result.is_err());
}

#[test]
fn loss_matrix_preset_serde_rejects_null() {
    let result = serde_json::from_str::<LossMatrixPreset>("null");
    assert!(result.is_err());
}

// -- LossMatrixPreset Clone and Copy ------------------------------------------

#[test]
fn loss_matrix_preset_clone_all_variants() {
    let variants = [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ];
    for v in &variants {
        let cloned = *v;
        assert_eq!(*v, cloned);
    }
}

// -- OrchestratorConfig edge cases --------------------------------------------

#[test]
fn orchestrator_config_zero_drain_deadline_ticks() {
    let config = OrchestratorConfig {
        drain_deadline_ticks: 0,
        ..OrchestratorConfig::default()
    };
    assert_eq!(config.drain_deadline_ticks, 0);
}

#[test]
fn orchestrator_config_max_drain_deadline_ticks() {
    let config = OrchestratorConfig {
        drain_deadline_ticks: u64::MAX,
        ..OrchestratorConfig::default()
    };
    assert_eq!(config.drain_deadline_ticks, u64::MAX);
}

#[test]
fn orchestrator_config_zero_max_concurrent_sagas() {
    let config = OrchestratorConfig {
        max_concurrent_sagas: 0,
        ..OrchestratorConfig::default()
    };
    assert_eq!(config.max_concurrent_sagas, 0);
}

#[test]
fn orchestrator_config_empty_trace_prefix() {
    let config = OrchestratorConfig {
        trace_id_prefix: String::new(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-empty-prefix", "42");
    let result = orch.execute(&pkg).expect("execute");
    // Even empty prefix should produce a valid trace_id
    assert!(result.trace_id.contains(':'));
}

#[test]
fn orchestrator_config_debug_includes_all_fields() {
    let config = OrchestratorConfig::default();
    let debug = format!("{config:?}");
    assert!(debug.contains("loss_matrix_preset"));
    assert!(debug.contains("drain_deadline_ticks"));
    assert!(debug.contains("max_concurrent_sagas"));
    assert!(debug.contains("epoch"));
    assert!(debug.contains("trace_id_prefix"));
    assert!(debug.contains("policy_id"));
}

// -- ExtensionPackage edge cases ----------------------------------------------

#[test]
fn extension_package_empty_capabilities_serde() {
    let pkg = simple_package("ext-no-caps", "42");
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.capabilities.is_empty());
}

#[test]
fn extension_package_single_char_source_executes() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-single-char", "1");
    let result = orch.execute(&pkg).expect("execute");
    assert!(result.instructions_executed > 0);
}

#[test]
fn extension_package_numeric_expression_source_executes() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-expr", "1 + 2");
    let result = orch.execute(&pkg).expect("execute");
    assert!(result.instructions_executed > 0);
}

#[test]
fn extension_package_debug_is_nonempty() {
    let pkg = simple_package("ext-debug", "42");
    assert!(!format!("{pkg:?}").is_empty());
}

#[test]
fn extension_package_clone_preserves_all_fields() {
    let pkg = ExtensionPackage {
        extension_id: "ext-clone".to_string(),
        source: "42".to_string(),
        source_file: Some("test.js".to_string()),
        capabilities: vec!["cap_a".to_string(), "cap_b".to_string()],
        version: "2.1.0".to_string(),
        metadata: BTreeMap::from([("key".to_string(), "val".to_string())]),
    };
    let cloned = pkg.clone();
    assert_eq!(cloned.extension_id, pkg.extension_id);
    assert_eq!(cloned.source, pkg.source);
    assert_eq!(cloned.source_file, pkg.source_file);
    assert_eq!(cloned.capabilities, pkg.capabilities);
    assert_eq!(cloned.version, pkg.version);
    assert_eq!(cloned.metadata, pkg.metadata);
}

#[test]
fn extension_package_serde_with_special_chars_in_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("desc".to_string(), "hello\nworld\ttab".to_string());
    metadata.insert("emoji".to_string(), "value".to_string());
    let pkg = ExtensionPackage {
        extension_id: "ext-special".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata,
    };
    let json = serde_json::to_string(&pkg).expect("serialize");
    let recovered: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.metadata.get("desc").unwrap(), "hello\nworld\ttab");
}

#[test]
fn extension_package_serde_source_file_absent_uses_default() {
    // When source_file is missing from JSON, default should be None
    let json = r#"{"extension_id":"ext-no-sf","source":"42","capabilities":[],"version":"1.0.0","metadata":{}}"#;
    let pkg: ExtensionPackage = serde_json::from_str(json).expect("deserialize");
    assert_eq!(pkg.source_file, None);
}

// -- Determinism across identical executions ----------------------------------

#[test]
fn deterministic_posterior_across_identical_executions() {
    let mut orch1 = ExecutionOrchestrator::with_defaults();
    let mut orch2 = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-det-post", "42");

    let r1 = orch1.execute(&pkg).expect("first");
    let r2 = orch2.execute(&pkg).expect("second");

    assert_eq!(r1.posterior.p_benign, r2.posterior.p_benign);
    assert_eq!(r1.posterior.p_anomalous, r2.posterior.p_anomalous);
    assert_eq!(r1.posterior.p_malicious, r2.posterior.p_malicious);
    assert_eq!(r1.posterior.p_unknown, r2.posterior.p_unknown);
}

#[test]
fn deterministic_lane_across_identical_executions() {
    let mut orch1 = ExecutionOrchestrator::with_defaults();
    let mut orch2 = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-det-lane", "42");

    let r1 = orch1.execute(&pkg).expect("first");
    let r2 = orch2.execute(&pkg).expect("second");

    assert_eq!(r1.lane, r2.lane);
}

#[test]
fn deterministic_containment_action_across_identical_executions() {
    let mut orch1 = ExecutionOrchestrator::with_defaults();
    let mut orch2 = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-det-ca", "42");

    let r1 = orch1.execute(&pkg).expect("first");
    let r2 = orch2.execute(&pkg).expect("second");

    assert_eq!(r1.containment_action, r2.containment_action);
}

// -- Same extension ID across multiple executions -----------------------------

#[test]
fn same_extension_id_multiple_executions_increments_counter() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-same", "42");

    for i in 0..5 {
        orch.execute(&pkg).expect("execute");
        assert_eq!(orch.execution_count(), (i + 1) as u64);
    }
}

#[test]
fn same_extension_id_multiple_executions_produces_distinct_trace_ids() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-distinct-trace", "42");

    let mut trace_ids = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let result = orch.execute(&pkg).expect("execute");
        trace_ids.insert(result.trace_id);
    }
    assert_eq!(trace_ids.len(), 5, "all trace_ids should be distinct");
}

// -- Evidence entries metadata keys -------------------------------------------

#[test]
fn evidence_entry_metadata_has_extension_id_key() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-eid", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("extension_id").unwrap(), "ext-meta-eid");
}

#[test]
fn evidence_entry_metadata_has_extension_version_key() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-ver", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("extension_version").unwrap(), "1.0.0");
}

#[test]
fn evidence_entry_metadata_has_capabilities_count_key() {
    let pkg = ExtensionPackage {
        extension_id: "ext-meta-caps".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec!["fs".to_string(), "net".to_string(), "env".to_string()],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orch = ExecutionOrchestrator::with_defaults();
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("capabilities_count").unwrap(), "3");
}

#[test]
fn evidence_entry_metadata_has_ir3_schedule_cost_key() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-cost", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(
        entry.metadata.contains_key("ir3_schedule_cost"),
        "evidence should contain ir3_schedule_cost metadata"
    );
}

#[test]
fn evidence_entry_metadata_has_adaptive_router_keys() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-ar", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("adaptive_router_regime"));
    assert!(entry.metadata.contains_key("adaptive_router_exact_regret"));
    assert!(entry.metadata.contains_key("adaptive_router_regret"));
    assert!(entry.metadata.contains_key("adaptive_router_bound"));
}

#[test]
fn evidence_entry_metadata_has_optimal_stopping_keys() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-os", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("optimal_stopping_algorithm"));
    assert!(entry.metadata.contains_key("optimal_stopping_observations"));
}

#[test]
fn evidence_entry_metadata_has_entropy_keys() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-meta-entropy", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(entry.metadata.contains_key("evidence_entropy_millibits"));
    assert!(entry.metadata.contains_key("evidence_shannon_bound_bits"));
    assert!(
        entry
            .metadata
            .contains_key("evidence_overhead_ratio_millionths")
    );
}

// -- Evidence entry witnesses -------------------------------------------------

#[test]
fn evidence_entry_has_posterior_witness() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-wit-post", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    let posterior_witness = entry
        .witnesses
        .iter()
        .find(|w| w.witness_type == "bayesian_posterior");
    assert!(
        posterior_witness.is_some(),
        "should have a bayesian_posterior witness"
    );
}

#[test]
fn evidence_entry_has_execution_telemetry_witness() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-wit-exec", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    let exec_witness = entry
        .witnesses
        .iter()
        .find(|w| w.witness_type == "execution_telemetry");
    assert!(
        exec_witness.is_some(),
        "should have an execution_telemetry witness"
    );
}

// -- Evidence entry candidates ------------------------------------------------

#[test]
fn evidence_entry_candidates_cover_all_containment_actions() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-cands", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    // ContainmentAction::ALL has 6 variants
    assert!(
        entry.candidates.len() >= 6,
        "should have at least 6 candidates (one per ContainmentAction), got {}",
        entry.candidates.len()
    );
}

// -- Force lane ---------------------------------------------------------------

#[test]
fn force_lane_quickjs_produces_quickjs_result() {
    let config = OrchestratorConfig {
        force_lane: Some(LaneChoice::QuickJs),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-force-qjs", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(result.lane, LaneChoice::QuickJs);
}

#[test]
fn force_lane_v8_produces_v8_result() {
    let config = OrchestratorConfig {
        force_lane: Some(LaneChoice::V8),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-force-v8", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(result.lane, LaneChoice::V8);
}

// -- ParseGoal Module ---------------------------------------------------------

#[test]
fn parse_goal_module_does_not_panic() {
    let config = OrchestratorConfig {
        parse_goal: ParseGoal::Module,
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-module", "42");
    // Should not panic; may or may not succeed depending on parser strictness
    let _ = orch.execute(&pkg);
}

// -- Whitespace variations in validation --------------------------------------

#[test]
fn tab_only_source_rejected() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "ext-tab".to_string(),
        source: "\t\t\t".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("tab-only source");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

#[test]
fn newline_only_source_rejected() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "ext-nl".to_string(),
        source: "\n\n\n".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("newline-only source");
    assert!(matches!(err, OrchestratorError::EmptySource));
}

#[test]
fn tab_only_extension_id_rejected() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = ExtensionPackage {
        extension_id: "\t".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let err = orch.execute(&pkg).expect_err("tab-only id");
    assert!(matches!(err, OrchestratorError::EmptyExtensionId));
}

// -- Custom policy_id propagation ---------------------------------------------

#[test]
fn custom_policy_id_propagates_to_evidence() {
    let config = OrchestratorConfig {
        policy_id: "my-custom-policy-42".to_string(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-policy", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    // The evidence entry should reference the policy_id
    assert_eq!(entry.policy_id, "my-custom-policy-42");
}

// -- Execution counter does not increment on failure --------------------------

#[test]
fn execution_counter_not_incremented_on_empty_source_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let bad_pkg = ExtensionPackage {
        extension_id: "ext-fail".to_string(),
        source: "".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let _ = orch.execute(&bad_pkg);
    assert_eq!(orch.execution_count(), 0);
}

#[test]
fn execution_counter_not_incremented_on_empty_id_error() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let bad_pkg = ExtensionPackage {
        extension_id: "".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let _ = orch.execute(&bad_pkg);
    assert_eq!(orch.execution_count(), 0);
}

// -- Ledger not populated on validation failure -------------------------------

#[test]
fn ledger_empty_after_validation_failures() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let bad1 = ExtensionPackage {
        extension_id: "".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let bad2 = ExtensionPackage {
        extension_id: "ext-ok".to_string(),
        source: "".to_string(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let _ = orch.execute(&bad1);
    let _ = orch.execute(&bad2);
    assert!(
        orch.ledger().is_empty(),
        "ledger should remain empty after validation failures"
    );
}

// -- Evidence compression certificate fields ----------------------------------

#[test]
fn evidence_compression_certificate_shannon_bound_non_negative() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-shannon", "42");
    let result = orch.execute(&pkg).expect("execute");
    if let Some(cert) = &result.evidence_compression_certificate {
        assert!(cert.shannon_lower_bound_bits >= 0);
    }
}

#[test]
fn evidence_compression_certificate_overhead_ratio_non_negative() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-overhead", "42");
    let result = orch.execute(&pkg).expect("execute");
    if let Some(cert) = &result.evidence_compression_certificate {
        assert!(cert.overhead_ratio_millionths >= 0);
    }
}

// -- OrchestratorConfig cell_close_budget_ms edge case ------------------------

#[test]
fn cell_close_budget_ms_default_is_10000() {
    let config = OrchestratorConfig::default();
    assert_eq!(config.cell_close_budget_ms, 10_000);
}

// -- Saga orchestrator zero active at start -----------------------------------

#[test]
fn saga_orchestrator_zero_active_sagas_at_start() {
    let orch = ExecutionOrchestrator::with_defaults();
    assert_eq!(orch.saga_orchestrator().active_count(), 0);
}

// -- Large capabilities count -------------------------------------------------

#[test]
fn large_capabilities_count_in_evidence_metadata() {
    let pkg = ExtensionPackage {
        extension_id: "ext-big-caps".to_string(),
        source: "42".to_string(),
        source_file: None,
        capabilities: (0..100).map(|i| format!("cap_{i}")).collect(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let mut orch = ExecutionOrchestrator::with_defaults();
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert_eq!(entry.metadata.get("capabilities_count").unwrap(), "100");
}

// -- Decision id format -------------------------------------------------------

#[test]
fn decision_id_format_contains_decision_keyword() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-did", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        result.decision_id.contains("decision"),
        "decision_id should contain 'decision': {}",
        result.decision_id
    );
}

#[test]
fn decision_id_differs_from_trace_id() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-diff-ids", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_ne!(result.trace_id, result.decision_id);
}

// -- Source label format ------------------------------------------------------

#[test]
fn source_label_starts_with_ext_prefix() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("my-ext-id", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        result.source_label.starts_with("ext:"),
        "source_label should start with 'ext:': {}",
        result.source_label
    );
    assert!(result.source_label.contains("my-ext-id"));
}

// -- Execution value consistency across loss presets ---------------------------

#[test]
fn execution_value_same_across_all_presets() {
    let presets = [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ];
    let values: Vec<String> = presets
        .into_iter()
        .map(|p| {
            let config = OrchestratorConfig {
                loss_matrix_preset: p,
                ..OrchestratorConfig::default()
            };
            let mut orch = ExecutionOrchestrator::new(config);
            let pkg = simple_package("ext-val-preset", "42");
            orch.execute(&pkg).expect("execute").execution_value
        })
        .collect();
    assert_eq!(values[0], values[1]);
    assert_eq!(values[1], values[2]);
}

// -- Instructions executed positive for valid source --------------------------

#[test]
fn instructions_executed_positive_for_valid_source() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-inst", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(
        result.instructions_executed > 0,
        "should execute at least one instruction"
    );
}

// -- Lowering events and witnesses populated ----------------------------------

#[test]
fn lowering_events_nonempty_for_valid_source() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-lev", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(!result.lowering_events.is_empty());
}

#[test]
fn lowering_witnesses_nonempty_for_valid_source() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-lwit", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert!(!result.lowering_witnesses.is_empty());
}

// -- Risk state populated -----------------------------------------------------

#[test]
fn risk_state_debug_format_nonempty() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-risk-dbg", "42");
    let result = orch.execute(&pkg).expect("execute");
    let debug = format!("{:?}", result.risk_state);
    assert!(!debug.is_empty());
}

// -- ExtensionPackage serde JSON field names -----------------------------------

#[test]
fn extension_package_json_contains_source_file_when_some() {
    let pkg = ExtensionPackage {
        extension_id: "ext-sf-json".to_string(),
        source: "42".to_string(),
        source_file: Some("app.js".to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&pkg).expect("serialize");
    assert!(json.contains("\"source_file\""));
    assert!(json.contains("app.js"));
}

// -- Multiple OrchestratorError variants display distinctness ------------------

#[test]
fn orchestrator_error_empty_source_and_empty_id_display_differ() {
    let e1 = OrchestratorError::EmptySource;
    let e2 = OrchestratorError::EmptyExtensionId;
    assert_ne!(e1.to_string(), e2.to_string());
}

// -- Config parse_goal Script is default --------------------------------------

#[test]
fn orchestrator_config_default_parse_goal_is_script() {
    let config = OrchestratorConfig::default();
    assert_eq!(config.parse_goal, ParseGoal::Script);
}

// -- OrchestratorResult debug -------------------------------------------------

#[test]
fn orchestrator_result_debug_is_nonempty() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-res-dbg", "42");
    let result = orch.execute(&pkg).expect("execute");
    let debug = format!("{result:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("ext-res-dbg"));
}

// -- Epoch zero ---------------------------------------------------------------

#[test]
fn epoch_zero_propagates_to_result() {
    let config = OrchestratorConfig {
        epoch: SecurityEpoch::from_raw(0),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(config);
    let pkg = simple_package("ext-epoch-zero", "42");
    let result = orch.execute(&pkg).expect("execute");
    assert_eq!(result.epoch, SecurityEpoch::from_raw(0));
}

// -- Evidence hash nonempty ---------------------------------------------------

#[test]
fn evidence_entry_evidence_hash_nonempty() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-ehash", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(!entry.evidence_hash.is_empty());
}

// -- Chosen action name nonempty ----------------------------------------------

#[test]
fn evidence_entry_chosen_action_name_nonempty() {
    let mut orch = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-ca-name", "42");
    let result = orch.execute(&pkg).expect("execute");
    let entry = &result.evidence_entries[0];
    assert!(!entry.chosen_action.action_name.is_empty());
}

// -- LossMatrixPreset Eq trait ------------------------------------------------

#[test]
fn loss_matrix_preset_eq_reflexive() {
    assert_eq!(LossMatrixPreset::Balanced, LossMatrixPreset::Balanced);
    assert_eq!(
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Conservative
    );
    assert_eq!(LossMatrixPreset::Permissive, LossMatrixPreset::Permissive);
}

#[test]
fn loss_matrix_preset_ne_across_variants() {
    assert_ne!(LossMatrixPreset::Balanced, LossMatrixPreset::Conservative);
    assert_ne!(LossMatrixPreset::Balanced, LossMatrixPreset::Permissive);
    assert_ne!(LossMatrixPreset::Conservative, LossMatrixPreset::Permissive);
}

// -- SourceIngestionSummary hashes are deterministic ---------------------------

#[test]
fn source_ingestion_hashes_deterministic_across_runs() {
    let mut orch1 = ExecutionOrchestrator::with_defaults();
    let mut orch2 = ExecutionOrchestrator::with_defaults();
    let pkg = simple_package("ext-si-det", "42");

    let r1 = orch1.execute(&pkg).expect("first");
    let r2 = orch2.execute(&pkg).expect("second");

    assert_eq!(
        r1.source_ingestion.original_source_hash,
        r2.source_ingestion.original_source_hash
    );
    assert_eq!(
        r1.source_ingestion.normalized_source_hash,
        r2.source_ingestion.normalized_source_hash
    );
}
