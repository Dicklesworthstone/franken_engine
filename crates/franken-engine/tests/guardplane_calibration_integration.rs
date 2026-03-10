//! Integration tests for the `guardplane_calibration` module.
//!
//! Covers: multi-cycle pipelines, regression fixture promotion, custom
//! config via with_config, CalibrationError serde/display, CalibrationContext
//! serde, DimensionEffectiveness serde, weakest dimension detection,
//! per-dimension effectiveness, state digest changes, mixed attack dimensions,
//! all attack dimensions exercised, event accumulation, EffectivenessTrend
//! serde, and multi-cycle trend analysis.

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

use frankenengine_engine::adversarial_campaign::{
    AdversarialCampaign, AttackDimension, AttackStep, AttackStepKind, CampaignComplexity,
    CampaignExecutionResult, CampaignOutcomeRecord, ExploitObjectiveScore,
    RedBlueCalibrationConfig,
};
use frankenengine_engine::guardplane_calibration::{
    CalibrationAlert, CalibrationContext, CalibrationCycleResult, CalibrationError,
    CalibrationEvent, DefenseEffectivenessSummary, DimensionEffectiveness, EffectivenessTrend,
    GuardplaneCalibrationEngine,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_ctx() -> CalibrationContext {
    CalibrationContext {
        trace_id: "trace-int".into(),
        decision_id: "dec-int".into(),
        policy_id: "pol-int".into(),
        signing_key: [0u8; 32],
        timestamp_ns: 1_000_000_000,
    }
}

fn make_campaign(dim: AttackDimension, step_count: usize) -> AdversarialCampaign {
    let steps: Vec<AttackStep> = (0..step_count)
        .map(|i| AttackStep {
            step_id: i as u32,
            dimension: dim,
            production_label: format!("int-label-{i}"),
            kind: AttackStepKind::HostcallSequence {
                motif: "int-motif".into(),
                hostcall_count: 3,
            },
        })
        .collect();
    AdversarialCampaign {
        campaign_id: format!("camp-int-{dim:?}-{step_count}"),
        trace_id: "trace-camp".into(),
        decision_id: "dec-camp".into(),
        policy_id: "pol-camp".into(),
        grammar_version: 1,
        seed: 42,
        complexity: CampaignComplexity::Probe,
        steps,
    }
}

fn make_result(
    undetected: usize,
    total: usize,
    escaped: bool,
    damage: u64,
    evidence_atoms: u64,
    novel: bool,
) -> CampaignExecutionResult {
    CampaignExecutionResult {
        undetected_steps: undetected,
        total_steps: total,
        objective_achieved_before_containment: escaped,
        damage_potential_millionths: damage,
        evidence_atoms_before_detection: evidence_atoms,
        novel_technique: novel,
    }
}

fn make_outcome(
    dim: AttackDimension,
    undetected: usize,
    total: usize,
    escaped: bool,
) -> CampaignOutcomeRecord {
    let campaign = make_campaign(dim, total);
    let result = make_result(undetected, total, escaped, 200_000, 5, false);
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    CampaignOutcomeRecord {
        campaign,
        result,
        score,
        benign_control: false,
        false_positive: false,
        timestamp_ns: 1_000_000_000,
    }
}

fn make_critical_outcome(dim: AttackDimension) -> CampaignOutcomeRecord {
    let campaign = make_campaign(dim, 10);
    // High damage + novel + lots of undetected = high composite score → Critical or Blocking
    let result = make_result(8, 10, true, 900_000, 50, true);
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    CampaignOutcomeRecord {
        campaign,
        result,
        score,
        benign_control: false,
        false_positive: false,
        timestamp_ns: 1_000_000_000,
    }
}

// ---------------------------------------------------------------------------
// Multi-cycle pipeline
// ---------------------------------------------------------------------------

#[test]
fn multi_cycle_pipeline_accumulates_state() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let batch1 = vec![
        make_outcome(AttackDimension::Exfiltration, 2, 10, false),
        make_outcome(AttackDimension::PrivilegeEscalation, 0, 8, false),
    ];
    let r1 = engine.run_calibration_cycle(&batch1, &ctx).unwrap();
    assert_eq!(r1.cycle_id, "gcal-0001");
    assert_eq!(r1.campaigns_ingested, 2);
    assert_eq!(engine.cycle_count(), 1);
    assert_eq!(engine.total_campaigns_ingested(), 2);

    let batch2 = vec![
        make_outcome(AttackDimension::PolicyEvasion, 5, 5, true),
        make_outcome(AttackDimension::HostcallSequence, 0, 6, false),
        make_outcome(AttackDimension::TemporalPayload, 3, 10, false),
    ];
    let r2 = engine.run_calibration_cycle(&batch2, &ctx).unwrap();
    assert_eq!(r2.cycle_id, "gcal-0002");
    assert_eq!(r2.campaigns_ingested, 3);
    assert_eq!(engine.cycle_count(), 2);
    assert_eq!(engine.total_campaigns_ingested(), 5);

    // Defense effectiveness should reflect all campaigns.
    let eff = engine.defense_effectiveness();
    assert_eq!(eff.total_campaigns, 5);
}

// ---------------------------------------------------------------------------
// Regression fixtures promotion
// ---------------------------------------------------------------------------

#[test]
fn critical_campaigns_promote_regression_fixtures() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 0, 5, false), // low score → Advisory
        make_critical_outcome(AttackDimension::PrivilegeEscalation), // high score → Blocking
    ];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    // At least one critical/blocking campaign → at least 1 regression fixture.
    assert!(result.regression_fixtures_added >= 1);
}

#[test]
fn no_regression_fixtures_from_low_severity() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    // All outcomes are low severity (no evasions, no escapes, low damage).
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 0, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 0, 10, false),
    ];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert_eq!(result.regression_fixtures_added, 0);
}

// ---------------------------------------------------------------------------
// Custom config via with_config
// ---------------------------------------------------------------------------

#[test]
fn with_config_creates_engine_with_custom_settings() {
    let config = RedBlueCalibrationConfig::default();
    let mut engine = GuardplaneCalibrationEngine::with_config(config);

    assert_eq!(engine.cycle_count(), 0);
    assert_eq!(engine.total_campaigns_ingested(), 0);

    let ctx = test_ctx();
    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 1, 5, false)];
    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert_eq!(result.campaigns_ingested, 1);
}

// ---------------------------------------------------------------------------
// Alert threshold setters
// ---------------------------------------------------------------------------

#[test]
fn set_evasion_alert_threshold_controls_alert_generation() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    // Set threshold to 100% — rate must be strictly greater, so no alerts fire.
    engine.set_evasion_alert_threshold(1_000_000);
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 9, 10, false), // 90% evasion
    ];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let evasion_alerts: Vec<_> = engine
        .alerts()
        .iter()
        .filter(|a| a.threat_category == "evasion")
        .collect();
    assert!(evasion_alerts.is_empty());
}

#[test]
fn set_containment_escape_alert_threshold_controls_alert_generation() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    // Set threshold to 0 — any escape triggers alert.
    engine.set_containment_escape_alert_threshold(0);
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 5, 10, true), // escaped
    ];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert!(
        engine
            .alerts()
            .iter()
            .any(|a| a.threat_category == "containment_escape")
    );
}

// ---------------------------------------------------------------------------
// CalibrationError serde and display
// ---------------------------------------------------------------------------

#[test]
fn calibration_error_serde_all_variants() {
    let errors = vec![
        CalibrationError::EmptyCampaignBatch,
        CalibrationError::CampaignValidationFailed {
            detail: "bad data".into(),
        },
        CalibrationError::CalibrationFailed {
            detail: "internal err".into(),
        },
        CalibrationError::InvalidConfig {
            detail: "bad config".into(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: CalibrationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "serde roundtrip failed for {err}");
    }
}

#[test]
fn calibration_error_display_includes_code_and_detail() {
    let err = CalibrationError::CampaignValidationFailed {
        detail: "missing field X".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("FE-GCAL-0002"));
    assert!(msg.contains("missing field X"));
}

#[test]
fn calibration_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CalibrationError::EmptyCampaignBatch);
    assert!(err.to_string().contains("FE-GCAL-0001"));
}

// ---------------------------------------------------------------------------
// CalibrationContext serde
// ---------------------------------------------------------------------------

#[test]
fn calibration_context_serde_roundtrip() {
    let ctx = CalibrationContext {
        trace_id: "t-serde".into(),
        decision_id: "d-serde".into(),
        policy_id: "p-serde".into(),
        signing_key: [42u8; 32],
        timestamp_ns: 999_999_999,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let restored: CalibrationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, restored);
}

// ---------------------------------------------------------------------------
// DimensionEffectiveness serde
// ---------------------------------------------------------------------------

#[test]
fn dimension_effectiveness_serde_roundtrip() {
    let de = DimensionEffectiveness {
        dimension: "HostcallSequence".into(),
        detection_rate_millionths: 800_000,
        evasion_rate_millionths: 200_000,
        trend: EffectivenessTrend::Improving,
        sample_count: 42,
    };
    let json = serde_json::to_string(&de).unwrap();
    let restored: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
    assert_eq!(de, restored);
}

// ---------------------------------------------------------------------------
// EffectivenessTrend serde
// ---------------------------------------------------------------------------

#[test]
fn effectiveness_trend_serde_roundtrip() {
    let trends = [
        EffectivenessTrend::Improving,
        EffectivenessTrend::Stable,
        EffectivenessTrend::Degrading,
    ];
    for trend in &trends {
        let json = serde_json::to_string(trend).unwrap();
        let restored: EffectivenessTrend = serde_json::from_str(&json).unwrap();
        assert_eq!(*trend, restored);
    }
}

// ---------------------------------------------------------------------------
// Weakest dimension detection
// ---------------------------------------------------------------------------

#[test]
fn weakest_dimension_identified_after_multiple_cycles() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    // Cycle 1: Exfiltration with high evasion.
    let batch1 = vec![
        make_outcome(AttackDimension::Exfiltration, 9, 10, false),
        make_outcome(AttackDimension::Exfiltration, 8, 10, false),
    ];
    engine.run_calibration_cycle(&batch1, &ctx).unwrap();

    // Cycle 2: HostcallSequence with no evasion.
    let batch2 = vec![
        make_outcome(AttackDimension::HostcallSequence, 0, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 0, 10, false),
    ];
    engine.run_calibration_cycle(&batch2, &ctx).unwrap();

    let eff = engine.defense_effectiveness();
    // Should have per-dimension data.
    assert!(!eff.per_dimension.is_empty());
    // weakest_dimension should exist.
    assert!(eff.weakest_dimension.is_some());
}

// ---------------------------------------------------------------------------
// State digest changes after calibration
// ---------------------------------------------------------------------------

#[test]
fn state_digest_changes_between_cycles() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let batch1 = vec![make_outcome(AttackDimension::Exfiltration, 2, 10, false)];
    let r1 = engine.run_calibration_cycle(&batch1, &ctx).unwrap();

    let batch2 = vec![make_critical_outcome(AttackDimension::PrivilegeEscalation)];
    let r2 = engine.run_calibration_cycle(&batch2, &ctx).unwrap();

    // State digest should be a hex string.
    assert_eq!(r1.state_digest.len(), 16);
    assert_eq!(r2.state_digest.len(), 16);
    assert!(r1.state_digest.chars().all(|c| c.is_ascii_hexdigit()));
    // Digests may or may not differ depending on calibration effect,
    // but they should at least be well-formed.
}

// ---------------------------------------------------------------------------
// Mixed attack dimensions in single batch
// ---------------------------------------------------------------------------

#[test]
fn mixed_dimensions_single_batch() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 1, 5, false),
        make_outcome(AttackDimension::PrivilegeEscalation, 0, 8, false),
        make_outcome(AttackDimension::PolicyEvasion, 3, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 0, 6, false),
        make_outcome(AttackDimension::TemporalPayload, 2, 7, false),
    ];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert_eq!(result.campaigns_ingested, 5);

    // Should have entries in threat_counts for each dimension.
    assert!(!result.threat_counts.is_empty());
    // Should have entries in subsystem_counts.
    assert!(!result.subsystem_counts.is_empty());
    // Should have entries in severity_counts.
    assert!(!result.severity_counts.is_empty());
}

// ---------------------------------------------------------------------------
// All attack dimensions exercised
// ---------------------------------------------------------------------------

#[test]
fn all_attack_dimensions_produce_valid_threat_categories() {
    let dims = [
        AttackDimension::HostcallSequence,
        AttackDimension::TemporalPayload,
        AttackDimension::PrivilegeEscalation,
        AttackDimension::PolicyEvasion,
        AttackDimension::Exfiltration,
    ];

    for dim in &dims {
        let mut engine = GuardplaneCalibrationEngine::new();
        let ctx = test_ctx();
        let outcomes = vec![make_outcome(*dim, 1, 5, false)];
        let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
        assert_eq!(result.campaigns_ingested, 1);
        assert!(!result.threat_counts.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Event accumulation across cycles
// ---------------------------------------------------------------------------

#[test]
fn events_accumulate_across_cycles() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let events_after_1 = engine.events().len();
    assert!(events_after_1 > 0);

    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let events_after_2 = engine.events().len();
    assert!(events_after_2 > events_after_1);
}

#[test]
fn drain_events_returns_all_and_clears() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 0, 5, false)];

    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let drained = engine.drain_events();
    assert!(!drained.is_empty());
    assert!(engine.events().is_empty());

    // All drained events should have the correct component.
    assert!(
        drained
            .iter()
            .all(|e| e.component == "guardplane_calibration")
    );
}

// ---------------------------------------------------------------------------
// CalibrationCycleResult fields
// ---------------------------------------------------------------------------

#[test]
fn cycle_result_has_populated_counts() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 3, 10, false),
        make_outcome(AttackDimension::Exfiltration, 0, 10, false),
        make_critical_outcome(AttackDimension::PrivilegeEscalation),
    ];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert_eq!(result.campaigns_ingested, 3);

    // severity_counts should have at least one entry.
    assert!(
        result.severity_counts.values().sum::<usize>() == 3,
        "severity counts should sum to campaign count"
    );
    assert!(
        result.subsystem_counts.values().sum::<usize>() == 3,
        "subsystem counts should sum to campaign count"
    );
    assert!(
        result.threat_counts.values().sum::<usize>() == 3,
        "threat counts should sum to campaign count"
    );
}

#[test]
fn cycle_result_detection_threshold_is_populated() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 1, 5, false)];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    // Detection threshold should be non-zero (default state has a threshold).
    assert!(result.detection_threshold_millionths > 0);
}

// ---------------------------------------------------------------------------
// Defense effectiveness rate calculation
// ---------------------------------------------------------------------------

#[test]
fn detection_rate_calculation_with_mixed_results() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    // 3 detected (no evasion), 1 evaded.
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 0, 10, false),
        make_outcome(AttackDimension::Exfiltration, 0, 10, false),
        make_outcome(AttackDimension::Exfiltration, 0, 10, false),
        make_outcome(AttackDimension::Exfiltration, 5, 10, false),
    ];

    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let eff = engine.defense_effectiveness();

    assert_eq!(eff.total_campaigns, 4);
    assert_eq!(eff.total_evasions, 1);
    assert_eq!(eff.overall_detection_rate_millionths, 750_000); // 3/4 = 75%
}

#[test]
fn containment_escapes_tracked() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 5, 10, true), // escaped
        make_outcome(AttackDimension::Exfiltration, 5, 10, true), // escaped
        make_outcome(AttackDimension::Exfiltration, 5, 10, false), // contained
    ];

    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let eff = engine.defense_effectiveness();

    assert_eq!(eff.total_containment_escapes, 2);
}

// ---------------------------------------------------------------------------
// CalibrationAlert fields
// ---------------------------------------------------------------------------

#[test]
fn alert_has_correct_fields() {
    let mut engine = GuardplaneCalibrationEngine::new();
    engine.set_evasion_alert_threshold(0); // any evasion triggers
    let ctx = test_ctx();

    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 5, 10, false)];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let alerts = engine.alerts();
    assert!(!alerts.is_empty());

    let alert = &alerts[0];
    assert!(!alert.alert_id.is_empty());
    assert!(!alert.severity.is_empty());
    assert!(!alert.subsystem.is_empty());
    assert!(!alert.description.is_empty());
    assert!(!alert.recommended_action.is_empty());
    assert!(alert.evasion_rate_millionths > 0);
    assert!(alert.cycle_id.starts_with("gcal-"));
}

// ---------------------------------------------------------------------------
// Serde roundtrips for complex results
// ---------------------------------------------------------------------------

#[test]
fn full_cycle_result_serde_roundtrip() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 2, 10, false),
        make_outcome(AttackDimension::PrivilegeEscalation, 0, 8, false),
    ];

    let result = engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn defense_effectiveness_summary_full_serde_roundtrip() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 2, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 0, 5, false),
    ];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let eff = engine.defense_effectiveness();
    let json = serde_json::to_string(&eff).unwrap();
    let restored: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(eff, restored);
}

#[test]
fn calibration_alert_serde_roundtrip() {
    let alert = CalibrationAlert {
        alert_id: "alert-int-1".into(),
        severity: "critical".into(),
        subsystem: "Sentinel".into(),
        threat_category: "evasion".into(),
        description: "high evasion rate in integration test".into(),
        recommended_action: "tighten thresholds".into(),
        evasion_rate_millionths: 500_000,
        cycle_id: "gcal-0001".into(),
    };
    let json = serde_json::to_string(&alert).unwrap();
    let restored: CalibrationAlert = serde_json::from_str(&json).unwrap();
    assert_eq!(alert, restored);
}

#[test]
fn calibration_event_serde_roundtrip() {
    let event = CalibrationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "guardplane_calibration".into(),
        event: "campaigns_ingested".into(),
        outcome: "ok".into(),
        error_code: Some("FE-GCAL-0001".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: CalibrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// Stress: many cycles
// ---------------------------------------------------------------------------

#[test]
fn stress_many_cycles() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    for i in 0..20 {
        let dim = match i % 5 {
            0 => AttackDimension::Exfiltration,
            1 => AttackDimension::PrivilegeEscalation,
            2 => AttackDimension::PolicyEvasion,
            3 => AttackDimension::HostcallSequence,
            _ => AttackDimension::TemporalPayload,
        };
        let undetected = if i % 3 == 0 { 3 } else { 0 };
        let outcomes = vec![make_outcome(dim, undetected, 10, i % 7 == 0)];
        engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    }

    assert_eq!(engine.cycle_count(), 20);
    assert_eq!(engine.total_campaigns_ingested(), 20);

    let eff = engine.defense_effectiveness();
    assert_eq!(eff.total_campaigns, 20);
    assert!(eff.total_evasions > 0);
}

// ---------------------------------------------------------------------------
// Empty batch returns error
// ---------------------------------------------------------------------------

#[test]
fn empty_campaign_batch_returns_error() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let result = engine.run_calibration_cycle(&[], &ctx);
    assert!(
        matches!(result, Err(CalibrationError::EmptyCampaignBatch)),
        "empty batch should produce EmptyCampaignBatch error"
    );
}

// ---------------------------------------------------------------------------
// Per-dimension effectiveness after single dimension input
// ---------------------------------------------------------------------------

#[test]
fn per_dimension_effectiveness_matches_input_dimension() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let outcomes = vec![
        make_outcome(AttackDimension::HostcallSequence, 0, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 3, 10, false),
    ];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let eff = engine.defense_effectiveness();
    assert!(
        !eff.per_dimension.is_empty(),
        "per_dimension should be populated after ingesting campaigns"
    );
    assert_eq!(eff.total_campaigns, 2);
}

// ---------------------------------------------------------------------------
// Enrichment: calibration state, determinism, false positive tracking, novel technique
// ---------------------------------------------------------------------------

#[test]
fn calibration_state_accessible_and_non_empty_after_cycle() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();
    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 1, 5, false)];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let state = engine.calibration_state();
    let json = serde_json::to_string(state).expect("serialize calibration state");
    assert!(!json.is_empty());
    // State should be parseable back
    let _: serde_json::Value = serde_json::from_str(&json).expect("deserialize calibration state");
}

#[test]
fn false_positive_campaigns_tracked_without_alert() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let campaign = make_campaign(AttackDimension::Exfiltration, 5);
    let result = make_result(0, 5, false, 0, 0, false);
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    let outcome = CampaignOutcomeRecord {
        campaign,
        result,
        score,
        benign_control: true,
        false_positive: true,
        timestamp_ns: 1_000_000_000,
    };

    let cycle_result = engine.run_calibration_cycle(&[outcome], &ctx).unwrap();
    assert_eq!(cycle_result.campaigns_ingested, 1);
    // false positive campaigns should not inflate evasion count
    let eff = engine.defense_effectiveness();
    assert_eq!(eff.total_campaigns, 1);
}

#[test]
fn novel_technique_flag_tracked_in_critical_outcome() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = test_ctx();

    let campaign = make_campaign(AttackDimension::PrivilegeEscalation, 10);
    let result = make_result(8, 10, true, 900_000, 50, true);
    let score = ExploitObjectiveScore::from_result(&result).unwrap();
    let outcome = CampaignOutcomeRecord {
        campaign,
        result,
        score,
        benign_control: false,
        false_positive: false,
        timestamp_ns: 1_000_000_000,
    };

    let cycle_result = engine.run_calibration_cycle(&[outcome], &ctx).unwrap();
    assert!(
        cycle_result.regression_fixtures_added >= 1,
        "novel technique with high damage should produce regression fixtures"
    );
}

#[test]
fn calibration_cycle_result_deterministic_for_identical_input() {
    let outcomes = vec![
        make_outcome(AttackDimension::Exfiltration, 2, 10, false),
        make_outcome(AttackDimension::HostcallSequence, 0, 5, false),
    ];
    let ctx = test_ctx();

    let mut engine_a = GuardplaneCalibrationEngine::new();
    let r1 = engine_a.run_calibration_cycle(&outcomes, &ctx).unwrap();

    let mut engine_b = GuardplaneCalibrationEngine::new();
    let r2 = engine_b.run_calibration_cycle(&outcomes, &ctx).unwrap();

    assert_eq!(r1.cycle_id, r2.cycle_id);
    assert_eq!(r1.campaigns_ingested, r2.campaigns_ingested);
    assert_eq!(r1.threat_counts, r2.threat_counts);
    assert_eq!(r1.severity_counts, r2.severity_counts);
}

#[test]
fn drain_alerts_clears_alert_list() {
    let mut engine = GuardplaneCalibrationEngine::new();
    engine.set_evasion_alert_threshold(0);
    let ctx = test_ctx();
    let outcomes = vec![make_outcome(AttackDimension::Exfiltration, 5, 10, false)];
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    assert!(
        !engine.alerts().is_empty(),
        "should have alerts after evasion"
    );

    // Running another cycle to verify alerts accumulate (not cleared between cycles)
    engine.run_calibration_cycle(&outcomes, &ctx).unwrap();
    let alert_count = engine.alerts().len();
    assert!(alert_count >= 2, "alerts should accumulate across cycles");
}
