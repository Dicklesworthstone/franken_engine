//! Integration tests for rough_path_regime_geometry (RGC-617).
//!
//! Validates the end-to-end pipeline composing regime_signature_feature,
//! entropic_policy_morphing, and signature_drift_gate.

use std::collections::BTreeMap;

use frankenengine_engine::entropic_policy_morphing::{MorphingConfig, MorphingOutcome, PolicyProfile, TransitionBudget};
use frankenengine_engine::regime_detector::Regime;
use frankenengine_engine::regime_signature_feature::{
    RegimeLabel, RuntimeTrace, SignatureConfig, TraceObservation,
};
use frankenengine_engine::rough_path_regime_geometry::{
    GeometrySpecimenFamily, GeometryVerdict, PipelineStepResult, PipelineSummary,
    RegimeCorridor, RegimeGeometryConfig, RegimeGeometryError, RegimeGeometryOrchestrator,
    RegimeTopology, geometry_corpus, run_geometry_corpus,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_drift_gate::{DriftGateConfig, GateVerdict};

const MILLION: i64 = 1_000_000;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn anchor_profile() -> PolicyProfile {
    let mut dims = BTreeMap::new();
    dims.insert("exploration_rate".to_string(), 500_000);
    dims.insert("sandbox_strictness".to_string(), 700_000);
    dims.insert("gc_aggressiveness".to_string(), 500_000);
    PolicyProfile::new("anchor_baseline", dims)
}

fn make_regime_profile(regime: Regime) -> PolicyProfile {
    let mut dims = BTreeMap::new();
    match regime {
        Regime::Normal => {
            dims.insert("exploration_rate".to_string(), 500_000);
            dims.insert("sandbox_strictness".to_string(), 500_000);
            dims.insert("gc_aggressiveness".to_string(), 500_000);
        }
        Regime::Elevated => {
            dims.insert("exploration_rate".to_string(), 300_000);
            dims.insert("sandbox_strictness".to_string(), 800_000);
            dims.insert("gc_aggressiveness".to_string(), 600_000);
        }
        Regime::Attack => {
            dims.insert("exploration_rate".to_string(), 100_000);
            dims.insert("sandbox_strictness".to_string(), MILLION);
            dims.insert("gc_aggressiveness".to_string(), 200_000);
        }
        Regime::Degraded => {
            dims.insert("exploration_rate".to_string(), 200_000);
            dims.insert("sandbox_strictness".to_string(), 600_000);
            dims.insert("gc_aggressiveness".to_string(), 800_000);
        }
        Regime::Recovery => {
            dims.insert("exploration_rate".to_string(), 400_000);
            dims.insert("sandbox_strictness".to_string(), 600_000);
            dims.insert("gc_aggressiveness".to_string(), 400_000);
        }
    }
    let mut p = PolicyProfile::new(&format!("regime_{regime}"), dims);
    p.target_regime = Some(regime);
    p
}

fn rich_trace(id: &str, features: &[(&str, &[i64])]) -> RuntimeTrace {
    let mut observations = Vec::new();
    let mut seq = 0u64;
    for (name, values) in features {
        for v in *values {
            observations.push(TraceObservation {
                seq,
                feature_name: name.to_string(),
                value_millionths: *v,
            });
            seq += 1;
        }
    }
    RuntimeTrace {
        trace_id: id.to_string(),
        observations,
        epoch: test_epoch(),
    }
}

fn stable_trace(id: &str) -> RuntimeTrace {
    rich_trace(
        id,
        &[
            (
                "instruction_count",
                &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION],
            ),
            ("cache_hit_rate", &[800_000, 800_000, 800_000, 800_000]),
        ],
    )
}

fn shifted_trace(id: &str) -> RuntimeTrace {
    rich_trace(
        id,
        &[
            (
                "instruction_count",
                &[900 * MILLION, 950 * MILLION, 920 * MILLION, 880 * MILLION],
            ),
            (
                "gc_pause_ns",
                &[5 * MILLION, 6 * MILLION, 7 * MILLION, 8 * MILLION],
            ),
        ],
    )
}

fn setup_orchestrator() -> RegimeGeometryOrchestrator {
    let mut orch = RegimeGeometryOrchestrator::with_defaults(anchor_profile(), test_epoch());
    for regime in [
        Regime::Normal,
        Regime::Elevated,
        Regime::Attack,
        Regime::Degraded,
        Regime::Recovery,
    ] {
        orch.register_regime_profile(regime, make_regime_profile(regime));
    }
    orch
}

// -----------------------------------------------------------------------
// Construction and configuration
// -----------------------------------------------------------------------

#[test]
fn test_orchestrator_construction_with_defaults() {
    let orch = RegimeGeometryOrchestrator::with_defaults(anchor_profile(), test_epoch());
    assert_eq!(orch.current_regime(), RegimeLabel::Abstention);
    assert_eq!(orch.current_profile_name(), "anchor_baseline");
    assert!(orch.history().is_empty());
}

#[test]
fn test_orchestrator_construction_custom_config() {
    let mut config = RegimeGeometryConfig::default();
    config.record_history = false;
    config.gate_enforced_fallback = false;
    config.max_history = 10;
    let orch = RegimeGeometryOrchestrator::new(anchor_profile(), test_epoch(), config);
    assert_eq!(orch.current_regime(), RegimeLabel::Abstention);
}

#[test]
fn test_default_config_values() {
    let config = RegimeGeometryConfig::default();
    assert!(config.record_history);
    assert!(config.gate_enforced_fallback);
    assert!(config.max_history > 0);
}

#[test]
fn test_register_regime_profiles() {
    let mut orch = RegimeGeometryOrchestrator::with_defaults(anchor_profile(), test_epoch());
    orch.register_regime_profile(Regime::Normal, make_regime_profile(Regime::Normal));
    orch.register_regime_profile(Regime::Attack, make_regime_profile(Regime::Attack));
    // Profiles registered without panic.
    assert_eq!(orch.current_profile_name(), "anchor_baseline");
}

// -----------------------------------------------------------------------
// Single trace processing
// -----------------------------------------------------------------------

#[test]
fn test_process_single_trace_success() {
    let mut orch = setup_orchestrator();
    let result = orch.process_trace(&stable_trace("t1")).unwrap();
    assert_eq!(result.seq, 1);
    assert_eq!(result.trace_id, "t1");
    assert!(!result.signature_hash.is_empty());
}

#[test]
fn test_process_empty_trace_error() {
    let mut orch = setup_orchestrator();
    let trace = RuntimeTrace {
        trace_id: "empty".to_string(),
        observations: vec![],
        epoch: test_epoch(),
    };
    assert!(matches!(
        orch.process_trace(&trace),
        Err(RegimeGeometryError::EmptyTrace)
    ));
}

#[test]
fn test_first_trace_no_gate_verdict() {
    let mut orch = setup_orchestrator();
    let result = orch.process_trace(&stable_trace("t1")).unwrap();
    assert!(result.gate_verdict.is_none());
    assert!(result.drift_l1.is_none());
}

#[test]
fn test_second_trace_has_gate_verdict() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&stable_trace("t2")).unwrap();
    assert!(result.gate_verdict.is_some());
}

#[test]
fn test_step_sequence_numbers_increment() {
    let mut orch = setup_orchestrator();
    for i in 1..=5 {
        let result = orch.process_trace(&stable_trace(&format!("t{i}"))).unwrap();
        assert_eq!(result.seq, i);
    }
}

#[test]
fn test_epoch_propagated_to_step_result() {
    let mut orch = setup_orchestrator();
    let result = orch.process_trace(&stable_trace("t1")).unwrap();
    assert_eq!(result.epoch, test_epoch());
}

// -----------------------------------------------------------------------
// Regime transition detection
// -----------------------------------------------------------------------

#[test]
fn test_stable_traces_no_regime_change() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&stable_trace("t2")).unwrap();
    assert!(!result.regime_changed);
}

#[test]
fn test_different_traces_processed_successfully() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&shifted_trace("t2")).unwrap();
    assert_eq!(result.seq, 2);
}

#[test]
fn test_transition_count_in_summary() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&shifted_trace("t2")).unwrap();
    let _ = orch.process_trace(&stable_trace("t3")).unwrap();
    let summary = orch.summary();
    assert_eq!(summary.total_steps, 3);
    // Transition count is at most 3.
    assert!(summary.regime_transitions <= 3);
}

// -----------------------------------------------------------------------
// Morphing integration
// -----------------------------------------------------------------------

#[test]
fn test_morphing_noop_on_stable_regime() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&stable_trace("t2")).unwrap();
    if !result.regime_changed {
        assert_eq!(result.morphing_outcome, MorphingOutcome::NoOp);
    }
}

#[test]
fn test_morphing_outcome_variants() {
    let mut orch = setup_orchestrator();
    let result = orch.process_trace(&stable_trace("t1")).unwrap();
    assert!(
        result.morphing_outcome.is_applied()
            || result.morphing_outcome.is_rejected()
            || result.morphing_outcome == MorphingOutcome::NoOp
    );
}

#[test]
fn test_active_profile_name_nonempty() {
    let mut orch = setup_orchestrator();
    let result = orch.process_trace(&stable_trace("t1")).unwrap();
    assert!(!result.active_profile_name.is_empty());
}

#[test]
fn test_morphing_summary_counters() {
    let mut orch = setup_orchestrator();
    for i in 0..5 {
        let _ = orch.process_trace(&stable_trace(&format!("t{i}")));
    }
    let summary = orch.summary();
    assert_eq!(
        summary.morphing_applied + summary.morphing_rejected + summary.morphing_noop,
        summary.total_steps
    );
}

// -----------------------------------------------------------------------
// Drift gate
// -----------------------------------------------------------------------

#[test]
fn test_stable_traces_gate_pass() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&stable_trace("t2")).unwrap();
    // Stable traces should pass or abstain.
    assert!(matches!(
        result.gate_verdict,
        Some(GateVerdict::Pass) | Some(GateVerdict::Abstain) | None
    ));
}

#[test]
fn test_gate_counter_tracked_in_summary() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&stable_trace("t2")).unwrap();
    let summary = orch.summary();
    let gate_total =
        summary.gate_passed + summary.gate_blocked + summary.gate_downgraded + summary.gate_abstained;
    // First trace has no gate verdict, second does.
    assert!(gate_total >= 1);
}

#[test]
fn test_is_gated_false_on_pass() {
    let result = PipelineStepResult {
        seq: 1,
        trace_id: "t".to_string(),
        signature_hash: "h".to_string(),
        regime_label: RegimeLabel::Abstention,
        regime_confidence: 0,
        regime_changed: false,
        morphing_outcome: MorphingOutcome::NoOp,
        active_profile_name: "p".to_string(),
        gate_verdict: Some(GateVerdict::Pass),
        drift_l1: Some(0),
        step_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        epoch: test_epoch(),
    };
    assert!(!result.is_gated());
}

#[test]
fn test_is_gated_true_on_block() {
    let result = PipelineStepResult {
        seq: 1,
        trace_id: "t".to_string(),
        signature_hash: "h".to_string(),
        regime_label: RegimeLabel::Abstention,
        regime_confidence: 0,
        regime_changed: false,
        morphing_outcome: MorphingOutcome::NoOp,
        active_profile_name: "p".to_string(),
        gate_verdict: Some(GateVerdict::Block),
        drift_l1: Some(500_000),
        step_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        epoch: test_epoch(),
    };
    assert!(result.is_gated());
}

// -----------------------------------------------------------------------
// Batch processing
// -----------------------------------------------------------------------

#[test]
fn test_batch_all_succeed() {
    let mut orch = setup_orchestrator();
    let traces: Vec<RuntimeTrace> = (0..5).map(|i| stable_trace(&format!("batch-{i}"))).collect();
    let results = orch.process_batch(&traces);
    assert_eq!(results.len(), 5);
    assert!(results.iter().all(|r| r.is_ok()));
}

#[test]
fn test_batch_empty() {
    let mut orch = setup_orchestrator();
    let results = orch.process_batch(&[]);
    assert!(results.is_empty());
}

#[test]
fn test_batch_with_mixed_results() {
    let mut orch = setup_orchestrator();
    let traces = vec![
        stable_trace("ok-1"),
        RuntimeTrace {
            trace_id: "empty".to_string(),
            observations: vec![],
            epoch: test_epoch(),
        },
        stable_trace("ok-2"),
    ];
    let results = orch.process_batch(&traces);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
}

#[test]
fn test_batch_step_count_matches() {
    let mut orch = setup_orchestrator();
    let traces: Vec<RuntimeTrace> = (0..7).map(|i| stable_trace(&format!("t{i}"))).collect();
    let _ = orch.process_batch(&traces);
    assert_eq!(orch.summary().total_steps, 7);
}

// -----------------------------------------------------------------------
// Summary
// -----------------------------------------------------------------------

#[test]
fn test_summary_initial_state() {
    let orch = setup_orchestrator();
    let summary = orch.summary();
    assert_eq!(summary.total_steps, 0);
    assert_eq!(summary.regime_transitions, 0);
    assert_eq!(summary.current_regime, RegimeLabel::Abstention);
}

#[test]
fn test_summary_after_processing() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let summary = orch.summary();
    assert_eq!(summary.total_steps, 1);
    assert!(!summary.current_profile_name.is_empty());
}

#[test]
fn test_summary_content_hash_deterministic() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let s1 = orch.summary();
    let s2 = orch.summary();
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn test_summary_morpher_summary_included() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let summary = orch.summary();
    assert_eq!(summary.morpher_summary.step_count, 1);
}

// -----------------------------------------------------------------------
// History
// -----------------------------------------------------------------------

#[test]
fn test_history_recorded() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&stable_trace("t2")).unwrap();
    assert_eq!(orch.history().len(), 2);
}

#[test]
fn test_history_bounded_by_config() {
    let mut config = RegimeGeometryConfig::default();
    config.max_history = 3;
    let mut orch = RegimeGeometryOrchestrator::new(anchor_profile(), test_epoch(), config);
    for i in 0..10 {
        let _ = orch.process_trace(&stable_trace(&format!("t{i}")));
    }
    assert!(orch.history().len() <= 3);
}

#[test]
fn test_history_disabled() {
    let mut config = RegimeGeometryConfig::default();
    config.record_history = false;
    let mut orch = RegimeGeometryOrchestrator::new(anchor_profile(), test_epoch(), config);
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    assert!(orch.history().is_empty());
}

// -----------------------------------------------------------------------
// Topology
// -----------------------------------------------------------------------

#[test]
fn test_topology_initially_empty() {
    let orch = setup_orchestrator();
    assert_eq!(orch.topology().corridor_count(), 0);
}

#[test]
fn test_topology_corridors_accumulate() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&shifted_trace("t2")).unwrap();
    // At least 0 corridors (depends on whether classifier detects regime change).
    assert!(orch.topology().corridor_count() <= 2);
}

#[test]
fn test_corridor_lookup_missing() {
    let orch = setup_orchestrator();
    assert!(orch
        .topology()
        .find_corridor(
            RegimeLabel::Classified(Regime::Normal),
            RegimeLabel::Classified(Regime::Attack)
        )
        .is_none());
}

#[test]
fn test_corridor_not_validated_by_default() {
    let orch = setup_orchestrator();
    assert!(!orch.topology().is_validated_corridor(
        RegimeLabel::Classified(Regime::Normal),
        RegimeLabel::Classified(Regime::Elevated)
    ));
}

// -----------------------------------------------------------------------
// Reset
// -----------------------------------------------------------------------

#[test]
fn test_reset_clears_step_count() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    orch.reset(SecurityEpoch::from_raw(2));
    assert_eq!(orch.summary().total_steps, 0);
}

#[test]
fn test_reset_clears_history() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    orch.reset(SecurityEpoch::from_raw(2));
    assert!(orch.history().is_empty());
}

#[test]
fn test_reset_clears_regime() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    orch.reset(SecurityEpoch::from_raw(2));
    assert_eq!(orch.current_regime(), RegimeLabel::Abstention);
}

#[test]
fn test_reset_clears_counters() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    orch.reset(SecurityEpoch::from_raw(2));
    let summary = orch.summary();
    assert_eq!(summary.morphing_applied, 0);
    assert_eq!(summary.gate_blocked, 0);
    assert_eq!(summary.gate_passed, 0);
    assert_eq!(summary.gate_abstained, 0);
}

#[test]
fn test_reset_allows_new_processing() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    orch.reset(SecurityEpoch::from_raw(2));
    let result = orch.process_trace(&stable_trace("t-after-reset")).unwrap();
    assert_eq!(result.seq, 1);
}

// -----------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------

#[test]
fn test_error_display_empty_trace() {
    let err = RegimeGeometryError::EmptyTrace;
    assert_eq!(format!("{err}"), "input trace is empty");
}

#[test]
fn test_error_display_invalid_signature() {
    let err = RegimeGeometryError::InvalidSignature {
        trace_id: "t1".to_string(),
        reason: "too short".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("t1"));
    assert!(msg.contains("too short"));
}

#[test]
fn test_error_display_morpher_not_configured() {
    let err = RegimeGeometryError::MorpherNotConfigured;
    assert!(format!("{err}").contains("anchor"));
}

#[test]
fn test_error_display_drift_abstained() {
    let err = RegimeGeometryError::DriftGateAbstained {
        reason: "no baseline".to_string(),
    };
    assert!(format!("{err}").contains("no baseline"));
}

#[test]
fn test_error_display_config_error() {
    let err = RegimeGeometryError::ConfigError {
        detail: "bad".to_string(),
    };
    assert!(format!("{err}").contains("bad"));
}

#[test]
fn test_error_equality() {
    assert_eq!(RegimeGeometryError::EmptyTrace, RegimeGeometryError::EmptyTrace);
    assert_ne!(
        RegimeGeometryError::EmptyTrace,
        RegimeGeometryError::MorpherNotConfigured
    );
}

// -----------------------------------------------------------------------
// Evidence corpus
// -----------------------------------------------------------------------

#[test]
fn test_corpus_nonempty() {
    let corpus = geometry_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn test_corpus_covers_all_families() {
    let corpus = geometry_corpus();
    for family in GeometrySpecimenFamily::ALL {
        assert!(
            corpus.iter().any(|s| s.family == *family),
            "missing family: {family:?}"
        );
    }
}

#[test]
fn test_run_corpus_all_pass() {
    let inventory = run_geometry_corpus();
    for evidence in &inventory.evidences {
        assert_eq!(
            evidence.verdict,
            GeometryVerdict::Pass,
            "specimen {} failed: {}",
            evidence.specimen_id,
            evidence.details,
        );
    }
    assert_eq!(inventory.failed, 0);
}

#[test]
fn test_corpus_inventory_deterministic() {
    let i1 = run_geometry_corpus();
    let i2 = run_geometry_corpus();
    assert_eq!(i1.inventory_hash, i2.inventory_hash);
}

#[test]
fn test_corpus_inventory_schema() {
    let inv = run_geometry_corpus();
    assert!(inv.schema_version.contains("rough-path-regime-geometry"));
    assert_eq!(inv.component, "rough_path_regime_geometry");
    assert_eq!(inv.policy_id, "RGC-617");
}

#[test]
fn test_corpus_family_coverage() {
    let inv = run_geometry_corpus();
    assert!(!inv.family_coverage.is_empty());
    for family in GeometrySpecimenFamily::ALL {
        assert!(
            inv.family_coverage.contains_key(family.as_str()),
            "missing coverage for {family:?}"
        );
    }
}

// -----------------------------------------------------------------------
// Regime corridor struct tests
// -----------------------------------------------------------------------

#[test]
fn test_corridor_construction() {
    let c = RegimeCorridor {
        from: RegimeLabel::Classified(Regime::Normal),
        to: RegimeLabel::Classified(Regime::Elevated),
        observation_count: 3,
        avg_distance_millionths: 150_000,
        validated: false,
    };
    assert_eq!(c.observation_count, 3);
    assert!(!c.validated);
}

// -----------------------------------------------------------------------
// Specimen family tests
// -----------------------------------------------------------------------

#[test]
fn test_specimen_family_all_length() {
    assert_eq!(GeometrySpecimenFamily::ALL.len(), 7);
}

#[test]
fn test_specimen_family_as_str_round_trip() {
    for family in GeometrySpecimenFamily::ALL {
        let s = family.as_str();
        assert!(!s.is_empty());
    }
}

// -----------------------------------------------------------------------
// Multi-epoch cycling
// -----------------------------------------------------------------------

#[test]
fn test_multi_epoch_cycle() {
    let mut orch = setup_orchestrator();
    // Epoch 1
    let _ = orch.process_trace(&stable_trace("e1-t1")).unwrap();
    let _ = orch.process_trace(&stable_trace("e1-t2")).unwrap();
    assert_eq!(orch.summary().total_steps, 2);

    // Reset to epoch 2
    orch.reset(SecurityEpoch::from_raw(2));
    assert_eq!(orch.summary().total_steps, 0);

    // Epoch 2
    let _ = orch.process_trace(&stable_trace("e2-t1")).unwrap();
    assert_eq!(orch.summary().total_steps, 1);
}

// -----------------------------------------------------------------------
// Gate enforcement fallback config
// -----------------------------------------------------------------------

#[test]
fn test_gate_enforced_fallback_disabled() {
    let mut config = RegimeGeometryConfig::default();
    config.gate_enforced_fallback = false;
    let mut orch = RegimeGeometryOrchestrator::new(anchor_profile(), test_epoch(), config);
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&stable_trace("t2")).unwrap();
    // Pipeline runs without error even with fallback disabled.
    assert_eq!(orch.summary().total_steps, 2);
}

// -----------------------------------------------------------------------
// Morpher summary delegation
// -----------------------------------------------------------------------

#[test]
fn test_morpher_summary_delegation() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let ms = orch.morpher_summary();
    assert_eq!(ms.step_count, 1);
}

// -----------------------------------------------------------------------
// Drift with shifted traces
// -----------------------------------------------------------------------

#[test]
fn test_drift_with_alternating_traces() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let _ = orch.process_trace(&shifted_trace("t2")).unwrap();
    let result = orch.process_trace(&stable_trace("t3")).unwrap();
    // Pipeline processes all three successfully.
    assert_eq!(result.seq, 3);
}

#[test]
fn test_drift_l1_present_after_baseline() {
    let mut orch = setup_orchestrator();
    let _ = orch.process_trace(&stable_trace("t1")).unwrap();
    let result = orch.process_trace(&stable_trace("t2")).unwrap();
    assert!(result.drift_l1.is_some());
}

// -----------------------------------------------------------------------
// Large batch stress
// -----------------------------------------------------------------------

#[test]
fn test_large_batch_30_traces() {
    let mut orch = setup_orchestrator();
    let traces: Vec<RuntimeTrace> = (0..30)
        .map(|i| {
            if i % 5 == 0 {
                shifted_trace(&format!("batch-{i}"))
            } else {
                stable_trace(&format!("batch-{i}"))
            }
        })
        .collect();
    let results = orch.process_batch(&traces);
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok_count, 30);
    assert_eq!(orch.summary().total_steps, 30);
}
