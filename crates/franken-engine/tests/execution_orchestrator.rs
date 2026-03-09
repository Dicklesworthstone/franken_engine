//! Integration tests for `ExecutionOrchestrator`.

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
