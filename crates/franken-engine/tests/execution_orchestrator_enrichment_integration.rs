#![forbid(unsafe_code)]
//! Enrichment integration tests for `execution_orchestrator`.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::bayesian_posterior::RiskState;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LossMatrixPreset, OrchestratorConfig,
    OrchestratorError, OrchestratorResult,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn simple_package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.into(),
        source: source.into(),
        source_file: None,
        capabilities: vec![],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    }
}

fn default_orch() -> ExecutionOrchestrator {
    ExecutionOrchestrator::with_defaults()
}

fn execute_simple(orch: &mut ExecutionOrchestrator) -> OrchestratorResult {
    let pkg = simple_package("test-ext", "42");
    orch.execute(&pkg).expect("execute should succeed")
}

// ===========================================================================
// Copy semantics — LossMatrixPreset
// ===========================================================================

#[test]
fn enrichment_loss_matrix_preset_copy() {
    let a = LossMatrixPreset::Balanced;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

// ===========================================================================
// Clone independence
// ===========================================================================

#[test]
fn enrichment_config_clone_independent() {
    let a = OrchestratorConfig::default();
    let mut b = a.clone();
    b.trace_id_prefix = "modified".into();
    assert_ne!(a.trace_id_prefix, b.trace_id_prefix);
}

#[test]
fn enrichment_package_clone_independent() {
    let a = simple_package("ext-1", "42");
    let mut b = a.clone();
    b.extension_id = "ext-2".into();
    assert_ne!(a.extension_id, b.extension_id);
}

// ===========================================================================
// BTreeSet ordering — LossMatrixPreset
// ===========================================================================

#[test]
fn enrichment_loss_matrix_preset_btreeset() {
    let set: BTreeSet<String> = [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ]
    .iter()
    .map(|p| format!("{p:?}"))
    .collect();
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// Debug nonempty
// ===========================================================================

#[test]
fn enrichment_config_debug() {
    let d = format!("{:?}", OrchestratorConfig::default());
    assert!(d.contains("OrchestratorConfig"));
}

#[test]
fn enrichment_package_debug() {
    let d = format!("{:?}", simple_package("e", "42"));
    assert!(d.contains("ExtensionPackage"));
}

#[test]
fn enrichment_result_debug() {
    let mut orch = default_orch();
    let result = execute_simple(&mut orch);
    let d = format!("{result:?}");
    assert!(d.contains("OrchestratorResult"));
}

#[test]
fn enrichment_error_debug_empty_source() {
    let e = OrchestratorError::EmptySource;
    let d = format!("{e:?}");
    assert!(d.contains("EmptySource"));
}

#[test]
fn enrichment_error_debug_empty_extension_id() {
    let e = OrchestratorError::EmptyExtensionId;
    let d = format!("{e:?}");
    assert!(d.contains("EmptyExtensionId"));
}

// ===========================================================================
// Display coverage — OrchestratorError
// ===========================================================================

#[test]
fn enrichment_error_display_empty_source() {
    let e = OrchestratorError::EmptySource;
    let s = format!("{e}");
    assert!(s.contains("empty"));
}

#[test]
fn enrichment_error_display_empty_extension_id() {
    let e = OrchestratorError::EmptyExtensionId;
    let s = format!("{e}");
    assert!(s.contains("empty"));
}

#[test]
fn enrichment_error_display_all_unique() {
    let variants: Vec<String> = vec![
        format!("{}", OrchestratorError::EmptySource),
        format!("{}", OrchestratorError::EmptyExtensionId),
    ];
    let set: BTreeSet<_> = variants.iter().collect();
    assert_eq!(set.len(), variants.len());
}

// ===========================================================================
// std::error::Error trait
// ===========================================================================

#[test]
fn enrichment_error_implements_error() {
    fn assert_error<T: std::error::Error>() {}
    assert_error::<OrchestratorError>();
}

// ===========================================================================
// Default coverage
// ===========================================================================

#[test]
fn enrichment_config_default_fields() {
    let cfg = OrchestratorConfig::default();
    assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
    assert!(cfg.force_lane.is_none());
    assert!(cfg.drain_deadline_ticks > 0);
    assert!(cfg.cell_close_budget_ms > 0);
    assert!(cfg.max_concurrent_sagas > 0);
    assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(cfg.parse_goal, ParseGoal::Script);
    assert!(!cfg.trace_id_prefix.is_empty());
    assert!(!cfg.policy_id.is_empty());
}

// ===========================================================================
// JSON field-name stability — ExtensionPackage
// ===========================================================================

#[test]
fn enrichment_package_json_fields() {
    let pkg = simple_package("ext-1", "42");
    let json = serde_json::to_string(&pkg).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"source\""));
    assert!(json.contains("\"capabilities\""));
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"metadata\""));
}

#[test]
fn enrichment_package_source_file_json() {
    let pkg = ExtensionPackage {
        source_file: Some("app.js".into()),
        ..simple_package("ext-1", "42")
    };
    let json = serde_json::to_string(&pkg).unwrap();
    assert!(json.contains("\"source_file\""));
    assert!(json.contains("app.js"));
}

// ===========================================================================
// Serde round-trips
// ===========================================================================

#[test]
fn enrichment_package_serde_roundtrip() {
    let pkg = ExtensionPackage {
        extension_id: "ext-1".into(),
        source: "var x = 1;".into(),
        source_file: Some("index.js".into()),
        capabilities: vec!["net".into(), "fs".into()],
        version: "2.0.0".into(),
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("author".into(), "test".into());
            m
        },
    };
    let json = serde_json::to_string(&pkg).unwrap();
    let back: ExtensionPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg.extension_id, back.extension_id);
    assert_eq!(pkg.source, back.source);
    assert_eq!(pkg.source_file, back.source_file);
    assert_eq!(pkg.capabilities, back.capabilities);
    assert_eq!(pkg.version, back.version);
    assert_eq!(pkg.metadata, back.metadata);
}

#[test]
fn enrichment_loss_matrix_preset_serde_all() {
    let variants = [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ];
    let expected = ["\"Balanced\"", "\"Conservative\"", "\"Permissive\""];
    for (v, e) in variants.iter().zip(expected.iter()) {
        let json = serde_json::to_string(v).unwrap();
        assert_eq!(json, *e, "variant: {v:?}");
        let back: LossMatrixPreset = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Determinism — same input produces same output
// ===========================================================================

#[test]
fn enrichment_execute_deterministic() {
    let pkg = simple_package("det-ext", "42");

    let mut orch1 = default_orch();
    let r1 = orch1.execute(&pkg).unwrap();

    let mut orch2 = default_orch();
    let r2 = orch2.execute(&pkg).unwrap();

    assert_eq!(r1.extension_id, r2.extension_id);
    assert_eq!(r1.trace_id, r2.trace_id);
    assert_eq!(r1.decision_id, r2.decision_id);
    assert_eq!(r1.execution_value, r2.execution_value);
    assert_eq!(r1.lane, r2.lane);
    assert_eq!(r1.risk_state, r2.risk_state);
    assert_eq!(r1.containment_action, r2.containment_action);
}

// ===========================================================================
// OrchestratorResult field coverage
// ===========================================================================

#[test]
fn enrichment_result_extension_id_matches_input() {
    let mut orch = default_orch();
    let pkg = simple_package("my-ext", "42");
    let r = orch.execute(&pkg).unwrap();
    assert_eq!(r.extension_id, "my-ext");
}

#[test]
fn enrichment_result_trace_id_has_prefix() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.trace_id.starts_with("orch:"));
}

#[test]
fn enrichment_result_decision_id_has_prefix() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.decision_id.starts_with("orch:decision:"));
}

#[test]
fn enrichment_result_source_label_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.source_label.contains("test-ext"));
}

#[test]
fn enrichment_result_posterior_valid() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.posterior.is_valid());
    let sum = r.posterior.p_benign
        + r.posterior.p_anomalous
        + r.posterior.p_malicious
        + r.posterior.p_unknown;
    // Should be close to 1_000_000 (fixed-point millionths)
    assert!((sum - 1_000_000).abs() < 10);
}

#[test]
fn enrichment_result_risk_state_is_benign_for_simple() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert_eq!(r.risk_state, RiskState::Benign);
}

#[test]
fn enrichment_result_expected_loss_non_negative() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.expected_loss_millionths >= 0);
}

#[test]
fn enrichment_result_evidence_entries_nonempty() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(!r.evidence_entries.is_empty());
}

#[test]
fn enrichment_result_lowering_events_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    // Simple "42" produces at least some lowering events
    assert!(!r.lowering_events.is_empty());
}

#[test]
fn enrichment_result_cell_events_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(!r.cell_events.is_empty());
}

#[test]
fn enrichment_result_finalize_result_present() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.finalize_result.is_some());
}

#[test]
fn enrichment_result_epoch_matches_config() {
    let cfg = OrchestratorConfig {
        epoch: SecurityEpoch::from_raw(42),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let r = execute_simple(&mut orch);
    assert_eq!(r.epoch, SecurityEpoch::from_raw(42));
}

// ===========================================================================
// Lowering witnesses
// ===========================================================================

#[test]
fn enrichment_result_lowering_witnesses_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(!r.lowering_witnesses.is_empty());
}

// ===========================================================================
// Adaptive router summary
// ===========================================================================

#[test]
fn enrichment_result_adaptive_router_summary_present() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.adaptive_router_summary.is_some());
}

#[test]
fn enrichment_adaptive_router_accumulates() {
    let mut orch = default_orch();
    let _ = execute_simple(&mut orch);
    let r2 = execute_simple(&mut orch);
    let summary = r2.adaptive_router_summary.as_ref().unwrap();
    assert!(summary.rounds >= 2);
}

// ===========================================================================
// IR3 schedule cost
// ===========================================================================

#[test]
fn enrichment_result_ir3_schedule_cost_present() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.ir3_schedule_cost.is_some());
}

// ===========================================================================
// Optimal stopping certificate
// ===========================================================================

#[test]
fn enrichment_result_optimal_stopping_present() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.optimal_stopping_certificate.is_some());
    let cert = r.optimal_stopping_certificate.unwrap();
    assert!(!cert.algorithm.is_empty());
    assert!(!cert.schema.is_empty());
}

// ===========================================================================
// Evidence compression certificate
// ===========================================================================

#[test]
fn enrichment_result_compression_certificate_present() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.evidence_compression_certificate.is_some());
    let cert = r.evidence_compression_certificate.unwrap();
    assert!(cert.entropy_millibits_per_symbol > 0);
    assert!(cert.shannon_lower_bound_bits > 0);
}

// ===========================================================================
// Containment
// ===========================================================================

#[test]
fn enrichment_simple_source_allow_containment() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    // Simple "42" should not trigger containment
    assert!(
        r.containment_action == ContainmentAction::Allow
            || r.containment_action == ContainmentAction::Sandbox
    );
    if r.containment_action == ContainmentAction::Allow {
        assert!(r.containment_receipt.is_none());
        assert!(r.saga_id.is_none());
    }
}

// ===========================================================================
// Execution counter
// ===========================================================================

#[test]
fn enrichment_execution_count_starts_zero() {
    let orch = default_orch();
    assert_eq!(orch.execution_count(), 0);
}

#[test]
fn enrichment_execution_count_increments() {
    let mut orch = default_orch();
    execute_simple(&mut orch);
    assert_eq!(orch.execution_count(), 1);
    execute_simple(&mut orch);
    assert_eq!(orch.execution_count(), 2);
}

#[test]
fn enrichment_execution_count_no_increment_on_error() {
    let mut orch = default_orch();
    let bad_pkg = simple_package(" ", "42"); // empty extension_id
    assert!(orch.execute(&bad_pkg).is_err());
    assert_eq!(orch.execution_count(), 0);
}

// ===========================================================================
// Ledger accumulation
// ===========================================================================

#[test]
fn enrichment_ledger_grows() {
    let mut orch = default_orch();
    assert!(orch.ledger().entries().is_empty());
    execute_simple(&mut orch);
    assert_eq!(orch.ledger().entries().len(), 1);
    execute_simple(&mut orch);
    assert_eq!(orch.ledger().entries().len(), 2);
}

// ===========================================================================
// Trace/decision ID uniqueness across calls
// ===========================================================================

#[test]
fn enrichment_trace_ids_unique_across_calls() {
    let mut orch = default_orch();
    let r1 = execute_simple(&mut orch);
    let r2 = execute_simple(&mut orch);
    assert_ne!(r1.trace_id, r2.trace_id);
    assert_ne!(r1.decision_id, r2.decision_id);
}

// ===========================================================================
// Validation errors
// ===========================================================================

#[test]
fn enrichment_empty_source_error() {
    let mut orch = default_orch();
    let pkg = simple_package("ext-1", "");
    let err = orch.execute(&pkg).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("empty"));
}

#[test]
fn enrichment_whitespace_source_error() {
    let mut orch = default_orch();
    let pkg = simple_package("ext-1", "   ");
    let err = orch.execute(&pkg).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("empty"));
}

#[test]
fn enrichment_empty_id_error() {
    let mut orch = default_orch();
    let pkg = simple_package("", "42");
    let err = orch.execute(&pkg).unwrap_err();
    let s = format!("{err}");
    assert!(s.contains("empty"));
}

// ===========================================================================
// Multiple extensions
// ===========================================================================

#[test]
fn enrichment_multiple_extensions_interleaved() {
    let mut orch = default_orch();
    let pkg1 = simple_package("ext-a", "1");
    let pkg2 = simple_package("ext-b", "2");
    let r1 = orch.execute(&pkg1).unwrap();
    let r2 = orch.execute(&pkg2).unwrap();
    assert_eq!(r1.extension_id, "ext-a");
    assert_eq!(r2.extension_id, "ext-b");
    assert_ne!(r1.trace_id, r2.trace_id);
    assert_eq!(orch.execution_count(), 2);
    assert_eq!(orch.ledger().entries().len(), 2);
}

// ===========================================================================
// Loss matrix presets all produce valid runs
// ===========================================================================

#[test]
fn enrichment_all_presets_valid() {
    for preset in [
        LossMatrixPreset::Balanced,
        LossMatrixPreset::Conservative,
        LossMatrixPreset::Permissive,
    ] {
        let cfg = OrchestratorConfig {
            loss_matrix_preset: preset,
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let r = execute_simple(&mut orch);
        assert!(r.posterior.is_valid(), "preset {preset:?} failed");
    }
}

// ===========================================================================
// Force lane
// ===========================================================================

#[test]
fn enrichment_force_lane_quickjs() {
    let cfg = OrchestratorConfig {
        force_lane: Some(LaneChoice::QuickJs),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let r = execute_simple(&mut orch);
    assert_eq!(r.lane, LaneChoice::QuickJs);
}

#[test]
fn enrichment_force_lane_v8() {
    let cfg = OrchestratorConfig {
        force_lane: Some(LaneChoice::V8),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let r = execute_simple(&mut orch);
    assert_eq!(r.lane, LaneChoice::V8);
}

// ===========================================================================
// Custom config fields propagate
// ===========================================================================

#[test]
fn enrichment_custom_trace_prefix() {
    let cfg = OrchestratorConfig {
        trace_id_prefix: "custom-pfx".into(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let r = execute_simple(&mut orch);
    assert!(r.trace_id.starts_with("custom-pfx:"));
}

#[test]
fn enrichment_custom_policy_id_in_evidence() {
    let cfg = OrchestratorConfig {
        policy_id: "my-policy-42".into(),
        ..OrchestratorConfig::default()
    };
    let mut orch = ExecutionOrchestrator::new(cfg);
    let r = execute_simple(&mut orch);
    let entry = &r.evidence_entries[0];
    assert_eq!(entry.policy_id, "my-policy-42");
}

// ===========================================================================
// TS normalization path
// ===========================================================================

#[test]
fn enrichment_ts_source_file_triggers_normalization() {
    let mut orch = default_orch();
    let pkg = ExtensionPackage {
        extension_id: "ts-ext".into(),
        source: "const x: number = 42;".into(),
        source_file: Some("app.ts".into()),
        capabilities: vec![],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let r = orch.execute(&pkg).unwrap();
    // TS normalization should have run
    assert!(r.source_ingestion.normalization_applied);
}

#[test]
fn enrichment_js_source_file_no_normalization() {
    let mut orch = default_orch();
    let pkg = ExtensionPackage {
        extension_id: "js-ext".into(),
        source: "42".into(),
        source_file: Some("app.js".into()),
        capabilities: vec![],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let r = orch.execute(&pkg).unwrap();
    assert!(!r.source_ingestion.normalization_applied);
}

// ===========================================================================
// Source ingestion summary
// ===========================================================================

#[test]
fn enrichment_source_ingestion_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    // For plain JS, should not be TS
    assert!(!r.source_ingestion.normalization_applied);
}

// ===========================================================================
// Package with capabilities
// ===========================================================================

#[test]
fn enrichment_package_with_capabilities_executes() {
    let mut orch = default_orch();
    let pkg = ExtensionPackage {
        extension_id: "cap-ext".into(),
        source: "42".into(),
        source_file: None,
        capabilities: vec!["net".into(), "fs".into(), "crypto".into()],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let r = orch.execute(&pkg).unwrap();
    assert_eq!(r.extension_id, "cap-ext");
    // Capabilities count should be in evidence metadata
    let meta = &r.evidence_entries[0].metadata;
    assert_eq!(
        meta.get("capabilities_count").map(|s| s.as_str()),
        Some("3")
    );
}

// ===========================================================================
// Package with metadata
// ===========================================================================

#[test]
fn enrichment_package_with_metadata_executes() {
    let mut orch = default_orch();
    let mut meta = BTreeMap::new();
    meta.insert("author".into(), "test-author".into());
    meta.insert("license".into(), "MIT".into());
    let pkg = ExtensionPackage {
        extension_id: "meta-ext".into(),
        source: "42".into(),
        source_file: None,
        capabilities: vec![],
        version: "3.0.0".into(),
        metadata: meta,
    };
    let r = orch.execute(&pkg).unwrap();
    assert_eq!(r.extension_id, "meta-ext");
}

// ===========================================================================
// Saga orchestrator initially empty
// ===========================================================================

#[test]
fn enrichment_saga_orchestrator_initially_empty() {
    let orch = default_orch();
    assert!(orch.saga_orchestrator().active_count() == 0);
}

// ===========================================================================
// Lane variants
// ===========================================================================

#[test]
fn enrichment_lane_is_valid() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.lane == LaneChoice::QuickJs || r.lane == LaneChoice::V8);
}

// ===========================================================================
// Instructions executed
// ===========================================================================

#[test]
fn enrichment_instructions_executed_positive() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(r.instructions_executed > 0);
}

// ===========================================================================
// Execution value
// ===========================================================================

#[test]
fn enrichment_execution_value_populated() {
    let mut orch = default_orch();
    let r = execute_simple(&mut orch);
    assert!(!r.execution_value.is_empty());
}
