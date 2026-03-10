#![forbid(unsafe_code)]
//! Enrichment integration tests for `guardplane_calibration`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, and config/construction edge cases beyond
//! the existing 28 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::guardplane_calibration::{
    CalibrationAlert, CalibrationContext, CalibrationCycleResult, CalibrationError,
    CalibrationEvent, DefenseEffectivenessSummary, DimensionEffectiveness, EffectivenessTrend,
    GuardplaneCalibrationEngine,
};

// ===========================================================================
// 1) EffectivenessTrend — exact Display
// ===========================================================================

#[test]
fn effectiveness_trend_display_exact_improving() {
    assert_eq!(EffectivenessTrend::Improving.to_string(), "improving");
}

#[test]
fn effectiveness_trend_display_exact_stable() {
    assert_eq!(EffectivenessTrend::Stable.to_string(), "stable");
}

#[test]
fn effectiveness_trend_display_exact_degrading() {
    assert_eq!(EffectivenessTrend::Degrading.to_string(), "degrading");
}

// ===========================================================================
// 2) CalibrationError — exact Display with codes
// ===========================================================================

#[test]
fn calibration_error_display_exact_empty_campaign() {
    let e = CalibrationError::EmptyCampaignBatch;
    let s = e.to_string();
    assert!(s.contains("FE-GCAL-0001"), "should contain error code: {s}");
    assert!(
        s.contains("empty campaign batch"),
        "should describe error: {s}"
    );
}

#[test]
fn calibration_error_display_exact_validation_failed() {
    let e = CalibrationError::CampaignValidationFailed {
        detail: "missing severity".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("FE-GCAL-0002"), "should contain error code: {s}");
    assert!(s.contains("missing severity"), "should contain detail: {s}");
}

#[test]
fn calibration_error_display_exact_calibration_failed() {
    let e = CalibrationError::CalibrationFailed {
        detail: "divergence".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("FE-GCAL-0003"), "should contain error code: {s}");
    assert!(s.contains("divergence"), "should contain detail: {s}");
}

#[test]
fn calibration_error_display_exact_invalid_config() {
    let e = CalibrationError::InvalidConfig {
        detail: "negative threshold".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("FE-GCAL-0004"), "should contain error code: {s}");
    assert!(
        s.contains("negative threshold"),
        "should contain detail: {s}"
    );
}

#[test]
fn calibration_error_display_all_unique() {
    let variants: Vec<String> = vec![
        CalibrationError::EmptyCampaignBatch.to_string(),
        CalibrationError::CampaignValidationFailed { detail: "a".into() }.to_string(),
        CalibrationError::CalibrationFailed { detail: "b".into() }.to_string(),
        CalibrationError::InvalidConfig { detail: "c".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

// ===========================================================================
// 3) CalibrationError — std::error::Error
// ===========================================================================

#[test]
fn calibration_error_is_std_error() {
    let e = CalibrationError::EmptyCampaignBatch;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_effectiveness_trend() {
    let variants = [
        format!("{:?}", EffectivenessTrend::Improving),
        format!("{:?}", EffectivenessTrend::Stable),
        format!("{:?}", EffectivenessTrend::Degrading),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn debug_distinct_calibration_error() {
    let variants = [
        format!("{:?}", CalibrationError::EmptyCampaignBatch),
        format!(
            "{:?}",
            CalibrationError::CampaignValidationFailed { detail: "x".into() }
        ),
        format!(
            "{:?}",
            CalibrationError::CalibrationFailed { detail: "y".into() }
        ),
        format!(
            "{:?}",
            CalibrationError::InvalidConfig { detail: "z".into() }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 5) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_effectiveness_trend_tags() {
    let trends = [
        EffectivenessTrend::Improving,
        EffectivenessTrend::Stable,
        EffectivenessTrend::Degrading,
    ];
    let expected = ["\"Improving\"", "\"Stable\"", "\"Degrading\""];
    for (t, exp) in trends.iter().zip(expected.iter()) {
        let json = serde_json::to_string(t).unwrap();
        assert_eq!(
            json, *exp,
            "EffectivenessTrend serde tag mismatch for {t:?}"
        );
    }
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_calibration_cycle_result() {
    let cr = CalibrationCycleResult {
        cycle_id: "cycle-1".to_string(),
        campaigns_ingested: 10,
        severity_counts: Default::default(),
        subsystem_counts: Default::default(),
        threat_counts: Default::default(),
        thresholds_adjusted: false,
        detection_threshold_millionths: 500_000,
        evidence_weights_millionths: Default::default(),
        regression_fixtures_added: 0,
        calibration_epoch: 1,
        state_digest: "abc".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&cr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "cycle_id",
        "campaigns_ingested",
        "severity_counts",
        "subsystem_counts",
        "threat_counts",
        "thresholds_adjusted",
        "detection_threshold_millionths",
        "evidence_weights_millionths",
        "regression_fixtures_added",
        "calibration_epoch",
        "state_digest",
    ] {
        assert!(
            obj.contains_key(key),
            "CalibrationCycleResult missing field: {key}"
        );
    }
}

#[test]
fn json_fields_dimension_effectiveness() {
    let de = DimensionEffectiveness {
        dimension: "network".to_string(),
        detection_rate_millionths: 900_000,
        evasion_rate_millionths: 100_000,
        trend: EffectivenessTrend::Stable,
        sample_count: 50,
    };
    let v: serde_json::Value = serde_json::to_value(&de).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "dimension",
        "detection_rate_millionths",
        "evasion_rate_millionths",
        "trend",
        "sample_count",
    ] {
        assert!(
            obj.contains_key(key),
            "DimensionEffectiveness missing field: {key}"
        );
    }
}

#[test]
fn json_fields_defense_effectiveness_summary() {
    let des = DefenseEffectivenessSummary {
        total_campaigns: 100,
        total_evasions: 5,
        total_containment_escapes: 2,
        overall_detection_rate_millionths: 950_000,
        overall_trend: EffectivenessTrend::Improving,
        per_dimension: Default::default(),
        weakest_dimension: None,
    };
    let v: serde_json::Value = serde_json::to_value(&des).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "total_campaigns",
        "total_evasions",
        "total_containment_escapes",
        "overall_detection_rate_millionths",
        "overall_trend",
        "per_dimension",
        "weakest_dimension",
    ] {
        assert!(
            obj.contains_key(key),
            "DefenseEffectivenessSummary missing field: {key}"
        );
    }
}

#[test]
fn json_fields_calibration_alert() {
    let alert = CalibrationAlert {
        alert_id: "alert-1".to_string(),
        severity: "high".to_string(),
        subsystem: "network".to_string(),
        threat_category: "exfiltration".to_string(),
        description: "high evasion rate".to_string(),
        recommended_action: "increase monitoring".to_string(),
        evasion_rate_millionths: 300_000,
        cycle_id: "cycle-1".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&alert).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "alert_id",
        "severity",
        "subsystem",
        "threat_category",
        "description",
        "recommended_action",
        "evasion_rate_millionths",
        "cycle_id",
    ] {
        assert!(
            obj.contains_key(key),
            "CalibrationAlert missing field: {key}"
        );
    }
}

#[test]
fn json_fields_calibration_event() {
    let event = CalibrationEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "guardplane_calibration".to_string(),
        event: "cycle_started".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            obj.contains_key(key),
            "CalibrationEvent missing field: {key}"
        );
    }
}

#[test]
fn json_fields_calibration_context() {
    let ctx = CalibrationContext {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        signing_key: [0u8; 32],
        timestamp_ns: 1_000_000_000,
    };
    let v: serde_json::Value = serde_json::to_value(&ctx).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "signing_key",
        "timestamp_ns",
    ] {
        assert!(
            obj.contains_key(key),
            "CalibrationContext missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_calibration_cycle_result() {
    let cr = CalibrationCycleResult {
        cycle_id: "cycle-rt".to_string(),
        campaigns_ingested: 42,
        severity_counts: Default::default(),
        subsystem_counts: Default::default(),
        threat_counts: Default::default(),
        thresholds_adjusted: true,
        detection_threshold_millionths: 750_000,
        evidence_weights_millionths: Default::default(),
        regression_fixtures_added: 3,
        calibration_epoch: 99,
        state_digest: "digest".to_string(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let rt: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, rt);
}

#[test]
fn serde_roundtrip_calibration_error_all_variants() {
    let variants = vec![
        CalibrationError::EmptyCampaignBatch,
        CalibrationError::CampaignValidationFailed { detail: "a".into() },
        CalibrationError::CalibrationFailed { detail: "b".into() },
        CalibrationError::InvalidConfig { detail: "c".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: CalibrationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_defense_effectiveness_summary() {
    let des = DefenseEffectivenessSummary {
        total_campaigns: 50,
        total_evasions: 3,
        total_containment_escapes: 1,
        overall_detection_rate_millionths: 940_000,
        overall_trend: EffectivenessTrend::Degrading,
        per_dimension: Default::default(),
        weakest_dimension: Some("memory".to_string()),
    };
    let json = serde_json::to_string(&des).unwrap();
    let rt: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(des, rt);
}

// ===========================================================================
// 8) EffectivenessTrend ordering
// ===========================================================================

#[test]
fn effectiveness_trend_ordering_stable() {
    let mut trends = [
        EffectivenessTrend::Degrading,
        EffectivenessTrend::Improving,
        EffectivenessTrend::Stable,
    ];
    trends.sort();
    assert_eq!(trends[0], EffectivenessTrend::Improving);
    assert_eq!(trends[1], EffectivenessTrend::Stable);
    assert_eq!(trends[2], EffectivenessTrend::Degrading);
}

// ===========================================================================
// 9) Engine construction and initial state
// ===========================================================================

#[test]
fn engine_default_initial_state() {
    let engine = GuardplaneCalibrationEngine::new();
    assert_eq!(engine.cycle_count(), 0);
    assert_eq!(engine.total_campaigns_ingested(), 0);
    assert!(engine.alerts().is_empty());
    assert!(engine.events().is_empty());
}

#[test]
fn engine_default_trait_matches_new() {
    let e1 = GuardplaneCalibrationEngine::new();
    let e2 = GuardplaneCalibrationEngine::default();
    assert_eq!(e1.cycle_count(), e2.cycle_count());
    assert_eq!(e1.total_campaigns_ingested(), e2.total_campaigns_ingested());
}

#[test]
fn engine_empty_calibration_returns_error() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let ctx = CalibrationContext {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        signing_key: [1u8; 32],
        timestamp_ns: 100,
    };
    let result = engine.run_calibration_cycle(&[], &ctx);
    assert!(result.is_err());
}

#[test]
fn engine_defense_effectiveness_empty() {
    let engine = GuardplaneCalibrationEngine::new();
    let summary = engine.defense_effectiveness();
    assert_eq!(summary.total_campaigns, 0);
    assert_eq!(summary.total_evasions, 0);
    assert_eq!(summary.total_containment_escapes, 0);
}

// ===========================================================================
// 10) Drain events
// ===========================================================================

#[test]
fn engine_drain_events_clears() {
    let mut engine = GuardplaneCalibrationEngine::new();
    let drained = engine.drain_events();
    assert!(drained.is_empty());
    assert!(engine.events().is_empty());
}

// ===========================================================================
// 11) Threshold setters
// ===========================================================================

#[test]
fn engine_set_evasion_alert_threshold() {
    let mut engine = GuardplaneCalibrationEngine::new();
    engine.set_evasion_alert_threshold(200_000);
    let _ = format!("{:?}", engine);
}

#[test]
fn engine_set_containment_escape_alert_threshold() {
    let mut engine = GuardplaneCalibrationEngine::new();
    engine.set_containment_escape_alert_threshold(100_000);
    let _ = format!("{:?}", engine);
}

// ===========================================================================
// 12) Serde roundtrips — remaining types
// ===========================================================================

#[test]
fn serde_roundtrip_dimension_effectiveness() {
    let de = DimensionEffectiveness {
        dimension: "network".to_string(),
        detection_rate_millionths: 900_000,
        evasion_rate_millionths: 100_000,
        trend: EffectivenessTrend::Stable,
        sample_count: 50,
    };
    let json = serde_json::to_string(&de).unwrap();
    let rt: DimensionEffectiveness = serde_json::from_str(&json).unwrap();
    assert_eq!(de, rt);
}

#[test]
fn serde_roundtrip_calibration_alert() {
    let alert = CalibrationAlert {
        alert_id: "alert-rt".to_string(),
        severity: "high".to_string(),
        subsystem: "network".to_string(),
        threat_category: "exfiltration".to_string(),
        description: "high evasion rate".to_string(),
        recommended_action: "increase monitoring".to_string(),
        evasion_rate_millionths: 300_000,
        cycle_id: "cycle-rt".to_string(),
    };
    let json = serde_json::to_string(&alert).unwrap();
    let rt: CalibrationAlert = serde_json::from_str(&json).unwrap();
    assert_eq!(alert, rt);
}

#[test]
fn serde_roundtrip_calibration_event() {
    let event = CalibrationEvent {
        trace_id: "trace-rt".to_string(),
        decision_id: "dec-rt".to_string(),
        policy_id: "pol-rt".to_string(),
        component: "guardplane_calibration".to_string(),
        event: "cycle_complete".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-GCAL-0001".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: CalibrationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

#[test]
fn serde_roundtrip_calibration_context() {
    let ctx = CalibrationContext {
        trace_id: "trace-rt".to_string(),
        decision_id: "dec-rt".to_string(),
        policy_id: "pol-rt".to_string(),
        signing_key: [42u8; 32],
        timestamp_ns: 999_999_999,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let rt: CalibrationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx, rt);
}

// ===========================================================================
// 13) CalibrationError — code() exact values
// ===========================================================================

#[test]
fn calibration_error_code_empty_campaign_batch() {
    let e = CalibrationError::EmptyCampaignBatch;
    assert_eq!(e.code(), "FE-GCAL-0001");
}

#[test]
fn calibration_error_code_campaign_validation_failed() {
    let e = CalibrationError::CampaignValidationFailed { detail: "x".into() };
    assert_eq!(e.code(), "FE-GCAL-0002");
}

#[test]
fn calibration_error_code_calibration_failed() {
    let e = CalibrationError::CalibrationFailed { detail: "x".into() };
    assert_eq!(e.code(), "FE-GCAL-0003");
}

#[test]
fn calibration_error_code_invalid_config() {
    let e = CalibrationError::InvalidConfig { detail: "x".into() };
    assert_eq!(e.code(), "FE-GCAL-0004");
}

// ===========================================================================
// 14) CalibrationCycleResult — populated severity/subsystem/threat counts
// ===========================================================================

#[test]
fn calibration_cycle_result_with_populated_maps() {
    let mut severity_counts = std::collections::BTreeMap::new();
    severity_counts.insert("high".to_string(), 3_usize);
    severity_counts.insert("low".to_string(), 7_usize);

    let mut subsystem_counts = std::collections::BTreeMap::new();
    subsystem_counts.insert("network".to_string(), 5_usize);

    let mut threat_counts = std::collections::BTreeMap::new();
    threat_counts.insert("exfiltration".to_string(), 2_usize);

    let cr = CalibrationCycleResult {
        cycle_id: "cycle-populated".to_string(),
        campaigns_ingested: 10,
        severity_counts,
        subsystem_counts,
        threat_counts,
        thresholds_adjusted: true,
        detection_threshold_millionths: 600_000,
        evidence_weights_millionths: Default::default(),
        regression_fixtures_added: 2,
        calibration_epoch: 5,
        state_digest: "abc123".to_string(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let rt: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, rt);
    assert_eq!(rt.severity_counts.len(), 2);
    assert_eq!(rt.subsystem_counts.len(), 1);
    assert_eq!(rt.threat_counts.len(), 1);
}

// ===========================================================================
// 15) DefenseEffectivenessSummary with per_dimension data
// ===========================================================================

#[test]
fn defense_effectiveness_summary_with_per_dimension() {
    let dim = DimensionEffectiveness {
        dimension: "network".to_string(),
        detection_rate_millionths: 850_000,
        evasion_rate_millionths: 150_000,
        trend: EffectivenessTrend::Degrading,
        sample_count: 20,
    };
    let mut per_dimension = std::collections::BTreeMap::new();
    per_dimension.insert("network".to_string(), dim);

    let des = DefenseEffectivenessSummary {
        total_campaigns: 20,
        total_evasions: 3,
        total_containment_escapes: 1,
        overall_detection_rate_millionths: 850_000,
        overall_trend: EffectivenessTrend::Degrading,
        per_dimension,
        weakest_dimension: Some("network".to_string()),
    };
    let json = serde_json::to_string(&des).unwrap();
    let rt: DefenseEffectivenessSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(des, rt);
    assert_eq!(rt.per_dimension.len(), 1);
    assert_eq!(rt.weakest_dimension.as_deref(), Some("network"));
}

// ===========================================================================
// 16) CalibrationCycleResult with populated evidence_weights_millionths
// ===========================================================================

#[test]
fn calibration_cycle_result_with_evidence_weights() {
    let mut evidence_weights = std::collections::BTreeMap::new();
    evidence_weights.insert("hostcall_sequence".to_string(), 700_000_u64);
    evidence_weights.insert("exfiltration".to_string(), 300_000_u64);

    let cr = CalibrationCycleResult {
        cycle_id: "cycle-weights".to_string(),
        campaigns_ingested: 5,
        severity_counts: Default::default(),
        subsystem_counts: Default::default(),
        threat_counts: Default::default(),
        thresholds_adjusted: false,
        detection_threshold_millionths: 500_000,
        evidence_weights_millionths: evidence_weights,
        regression_fixtures_added: 0,
        calibration_epoch: 2,
        state_digest: "weights".to_string(),
    };
    let json = serde_json::to_string(&cr).unwrap();
    let rt: CalibrationCycleResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, rt);
    assert_eq!(rt.evidence_weights_millionths.len(), 2);
}

// ===========================================================================
// 17) Serde determinism — CalibrationCycleResult
// ===========================================================================

#[test]
fn calibration_cycle_result_serde_deterministic() {
    let cr = CalibrationCycleResult {
        cycle_id: "cycle-det".to_string(),
        campaigns_ingested: 7,
        severity_counts: Default::default(),
        subsystem_counts: Default::default(),
        threat_counts: Default::default(),
        thresholds_adjusted: false,
        detection_threshold_millionths: 500_000,
        evidence_weights_millionths: Default::default(),
        regression_fixtures_added: 0,
        calibration_epoch: 1,
        state_digest: "det".to_string(),
    };
    let json1 = serde_json::to_string(&cr).unwrap();
    let json2 = serde_json::to_string(&cr).unwrap();
    assert_eq!(json1, json2, "serde output must be deterministic");
}

// ===========================================================================
// 18) Engine with_config construction
// ===========================================================================

#[test]
fn engine_with_config_construction() {
    use frankenengine_engine::adversarial_campaign::RedBlueCalibrationConfig;

    let config = RedBlueCalibrationConfig::default();
    let engine = GuardplaneCalibrationEngine::with_config(config);
    assert_eq!(engine.cycle_count(), 0);
    assert_eq!(engine.total_campaigns_ingested(), 0);
    assert!(engine.alerts().is_empty());
}

// ===========================================================================
// 19) CalibrationContext serde with non-zero signing_key
// ===========================================================================

#[test]
fn calibration_context_nonzero_signing_key() {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let ctx = CalibrationContext {
        trace_id: "t-nz".to_string(),
        decision_id: "d-nz".to_string(),
        policy_id: "p-nz".to_string(),
        signing_key: key,
        timestamp_ns: 42,
    };
    let json = serde_json::to_string(&ctx).unwrap();
    let rt: CalibrationContext = serde_json::from_str(&json).unwrap();
    assert_eq!(ctx.signing_key, rt.signing_key);
}

// ===========================================================================
// 20) CalibrationEvent with error_code populated
// ===========================================================================

#[test]
fn calibration_event_with_error_code() {
    let event = CalibrationEvent {
        trace_id: "t-ec".to_string(),
        decision_id: "d-ec".to_string(),
        policy_id: "p-ec".to_string(),
        component: "guardplane_calibration".to_string(),
        event: "cycle_failed".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-GCAL-0001".to_string()),
    };
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert!(v["error_code"].is_string());
    assert_eq!(v["error_code"].as_str().unwrap(), "FE-GCAL-0001");
}

#[test]
fn calibration_event_without_error_code() {
    let event = CalibrationEvent {
        trace_id: "t-ne".to_string(),
        decision_id: "d-ne".to_string(),
        policy_id: "p-ne".to_string(),
        component: "guardplane_calibration".to_string(),
        event: "cycle_complete".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    assert!(v["error_code"].is_null());
}

// ===========================================================================
// 21) CalibrationAlert — serde preserves exact values
// ===========================================================================

#[test]
fn calibration_alert_serde_exact_values() {
    let alert = CalibrationAlert {
        alert_id: "alert-exact".to_string(),
        severity: "critical".to_string(),
        subsystem: "memory".to_string(),
        threat_category: "privilege_escalation".to_string(),
        description: "threshold exceeded".to_string(),
        recommended_action: "block immediately".to_string(),
        evasion_rate_millionths: 999_999,
        cycle_id: "cycle-exact".to_string(),
    };
    let json = serde_json::to_string(&alert).unwrap();
    let rt: CalibrationAlert = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.evasion_rate_millionths, 999_999);
    assert_eq!(rt.severity, "critical");
    assert_eq!(rt.threat_category, "privilege_escalation");
}

// ===========================================================================
// 22) GuardplaneCalibrationState — accessible via engine
// ===========================================================================

#[test]
fn engine_calibration_state_initial() {
    let engine = GuardplaneCalibrationEngine::new();
    let state = engine.calibration_state();
    assert_eq!(state.calibration_epoch, 0);
    assert!(!state.evidence_weights_millionths.is_empty());
}

// ===========================================================================
// 23) EffectivenessTrend Copy semantics
// ===========================================================================

#[test]
fn effectiveness_trend_copy_semantics() {
    let t = EffectivenessTrend::Improving;
    let t2 = t;
    assert_eq!(t, t2);
}

// ===========================================================================
// 24) CalibrationError serde — enum tags exact
// ===========================================================================

#[test]
fn serde_exact_calibration_error_tags() {
    let variants = [
        (CalibrationError::EmptyCampaignBatch, "EmptyCampaignBatch"),
        (
            CalibrationError::CampaignValidationFailed { detail: "a".into() },
            "CampaignValidationFailed",
        ),
        (
            CalibrationError::CalibrationFailed { detail: "b".into() },
            "CalibrationFailed",
        ),
        (
            CalibrationError::InvalidConfig { detail: "c".into() },
            "InvalidConfig",
        ),
    ];
    for (v, expected_tag) in &variants {
        let json = serde_json::to_string(v).unwrap();
        assert!(
            json.contains(expected_tag),
            "CalibrationError JSON should contain {expected_tag}: {json}"
        );
    }
}
