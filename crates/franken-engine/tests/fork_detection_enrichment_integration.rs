#![forbid(unsafe_code)]
//! Enrichment integration tests for `fork_detection`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, and edge cases beyond
//! the existing 74 integration tests.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::fork_detection::{
    CheckpointHistoryEntry, ForkDetector, ForkError, ForkIncidentReport, SAFE_MODE_ENV_FLAGS,
    SafeModeExitCheckInput, SafeModeRestrictions, SafeModeStartupError, SafeModeStartupEvent,
    SafeModeStartupInput, SafeModeStartupSource, SafeModeState,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

// ===========================================================================
// 1) SafeModeStartupSource — exact Display
// ===========================================================================

#[test]
fn safe_mode_startup_source_display_exact() {
    assert_eq!(
        SafeModeStartupSource::NotRequested.to_string(),
        "not-requested"
    );
    assert_eq!(SafeModeStartupSource::CliFlag.to_string(), "cli-flag");
    assert_eq!(
        SafeModeStartupSource::EnvironmentVariable.to_string(),
        "environment-variable"
    );
}

// ===========================================================================
// 2) ForkError — exact Display
// ===========================================================================

#[test]
fn fork_error_display_fork_detected() {
    let e = ForkError::ForkDetected {
        checkpoint_seq: 42,
        existing_id: oid(1),
        divergent_id: oid(2),
    };
    let s = e.to_string();
    assert!(s.contains("42"), "should contain checkpoint_seq: {s}");
}

#[test]
fn fork_error_display_safe_mode_active() {
    let e = ForkError::SafeModeActive {
        incident_seq: 7,
        reason: "fork detected".into(),
    };
    let s = e.to_string();
    assert!(s.contains("fork detected"), "should contain reason: {s}");
}

#[test]
fn fork_error_display_acknowledgment_required() {
    let e = ForkError::AcknowledgmentRequired { incident_count: 3 };
    let s = e.to_string();
    assert!(s.contains("3"), "should contain count: {s}");
}

#[test]
fn fork_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ForkError::ForkDetected {
            checkpoint_seq: 1,
            existing_id: oid(1),
            divergent_id: oid(2),
        }
        .to_string(),
        ForkError::SafeModeActive {
            incident_seq: 1,
            reason: "r".into(),
        }
        .to_string(),
        ForkError::AcknowledgmentRequired { incident_count: 1 }.to_string(),
        ForkError::InvalidResolution {
            fork_seq: 1,
            resolution_seq: 2,
        }
        .to_string(),
        ForkError::PersistenceFailed { detail: "d".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

// ===========================================================================
// 3) ForkError / SafeModeStartupError — std::error::Error
// ===========================================================================

#[test]
fn fork_error_is_std_error() {
    let e = ForkError::PersistenceFailed { detail: "x".into() };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn safe_mode_startup_error_is_std_error() {
    let e = SafeModeStartupError::MissingField { field: "x".into() };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_safe_mode_startup_source() {
    let variants = [
        format!("{:?}", SafeModeStartupSource::NotRequested),
        format!("{:?}", SafeModeStartupSource::CliFlag),
        format!("{:?}", SafeModeStartupSource::EnvironmentVariable),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 5) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_safe_mode_startup_source_tags() {
    let sources = [
        SafeModeStartupSource::NotRequested,
        SafeModeStartupSource::CliFlag,
        SafeModeStartupSource::EnvironmentVariable,
    ];
    let expected = ["\"NotRequested\"", "\"CliFlag\"", "\"EnvironmentVariable\""];
    for (s, exp) in sources.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(
            json, *exp,
            "SafeModeStartupSource serde tag mismatch for {s:?}"
        );
    }
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_fork_incident_report() {
    let fir = ForkIncidentReport {
        incident_id: "inc-1".into(),
        fork_seq: 1,
        existing_checkpoint_id: oid(1),
        divergent_checkpoint_id: oid(2),
        existing_epoch: SecurityEpoch::from_raw(1),
        divergent_epoch: SecurityEpoch::from_raw(2),
        zone: "default".into(),
        frontier_seq_at_detection: 10,
        frontier_epoch_at_detection: SecurityEpoch::from_raw(3),
        detected_at_tick: 100,
        trace_id: "trace-1".into(),
        existing_was_accepted: true,
        acknowledged: false,
    };
    let v: serde_json::Value = serde_json::to_value(&fir).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "incident_id",
        "fork_seq",
        "existing_checkpoint_id",
        "divergent_checkpoint_id",
        "existing_epoch",
        "divergent_epoch",
        "zone",
        "frontier_seq_at_detection",
        "frontier_epoch_at_detection",
        "detected_at_tick",
        "trace_id",
        "existing_was_accepted",
        "acknowledged",
    ] {
        assert!(
            obj.contains_key(key),
            "ForkIncidentReport missing field: {key}"
        );
    }
}

#[test]
fn json_fields_checkpoint_history_entry() {
    let che = CheckpointHistoryEntry {
        checkpoint_seq: 5,
        checkpoint_id: oid(10),
        epoch: SecurityEpoch::from_raw(1),
        accepted: true,
    };
    let v: serde_json::Value = serde_json::to_value(&che).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["checkpoint_seq", "checkpoint_id", "epoch", "accepted"] {
        assert!(
            obj.contains_key(key),
            "CheckpointHistoryEntry missing field: {key}"
        );
    }
}

#[test]
fn json_fields_safe_mode_state() {
    let sms = SafeModeState {
        active: true,
        trigger_seq: Some(5),
        unacknowledged_count: 2,
    };
    let v: serde_json::Value = serde_json::to_value(&sms).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["active", "trigger_seq", "unacknowledged_count"] {
        assert!(obj.contains_key(key), "SafeModeState missing field: {key}");
    }
}

#[test]
fn json_fields_safe_mode_restrictions() {
    let smr = SafeModeRestrictions {
        all_extensions_sandboxed: true,
        auto_promotion_disabled: true,
        conservative_policy_defaults: true,
        enhanced_telemetry: true,
        adaptive_tuning_disabled: true,
    };
    let v: serde_json::Value = serde_json::to_value(&smr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "all_extensions_sandboxed",
        "auto_promotion_disabled",
        "conservative_policy_defaults",
        "enhanced_telemetry",
        "adaptive_tuning_disabled",
    ] {
        assert!(
            obj.contains_key(key),
            "SafeModeRestrictions missing field: {key}"
        );
    }
}

#[test]
fn json_fields_safe_mode_startup_event() {
    let event = SafeModeStartupEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "fork_detection".into(),
        event: "startup".into(),
        outcome: "ok".into(),
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
            "SafeModeStartupEvent missing field: {key}"
        );
    }
}

#[test]
fn json_fields_safe_mode_startup_input() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: Default::default(),
    };
    let v: serde_json::Value = serde_json::to_value(&input).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "cli_safe_mode",
        "environment",
    ] {
        assert!(
            obj.contains_key(key),
            "SafeModeStartupInput missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) SafeModeState default
// ===========================================================================

#[test]
fn safe_mode_state_default() {
    let sms = SafeModeState::default();
    assert!(!sms.active);
    assert_eq!(sms.trigger_seq, None);
    assert_eq!(sms.unacknowledged_count, 0);
}

// ===========================================================================
// 8) Constants stability
// ===========================================================================

#[test]
fn safe_mode_env_flags_stable() {
    assert_eq!(SAFE_MODE_ENV_FLAGS.len(), 2);
    assert_eq!(SAFE_MODE_ENV_FLAGS[0], "FRANKEN_SAFE_MODE");
    assert_eq!(SAFE_MODE_ENV_FLAGS[1], "FRANKENENGINE_SAFE_MODE");
}

// ===========================================================================
// 9) ForkDetector construction and initial state
// ===========================================================================

#[test]
fn fork_detector_new_initial_state() {
    let mut fd = ForkDetector::new(100);
    assert!(fd.zones().is_empty());
    assert!(fd.drain_events().is_empty());
}

#[test]
fn fork_detector_with_defaults() {
    let fd = ForkDetector::with_defaults();
    assert!(fd.zones().is_empty());
}

#[test]
fn fork_detector_is_safe_mode_unknown_zone() {
    let fd = ForkDetector::new(100);
    assert!(!fd.is_safe_mode("nonexistent"));
}

#[test]
fn fork_detector_safe_mode_state_unknown_zone() {
    let fd = ForkDetector::new(100);
    assert!(fd.safe_mode_state("nonexistent").is_none());
}

#[test]
fn fork_detector_history_unknown_zone() {
    let fd = ForkDetector::new(100);
    assert!(fd.history("nonexistent").is_none());
}

#[test]
fn fork_detector_history_size_unknown_zone() {
    let fd = ForkDetector::new(100);
    assert_eq!(fd.history_size("nonexistent"), 0);
}

// ===========================================================================
// 10) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_fork_error_all_variants() {
    let variants = vec![
        ForkError::ForkDetected {
            checkpoint_seq: 1,
            existing_id: oid(1),
            divergent_id: oid(2),
        },
        ForkError::SafeModeActive {
            incident_seq: 1,
            reason: "r".into(),
        },
        ForkError::AcknowledgmentRequired { incident_count: 3 },
        ForkError::InvalidResolution {
            fork_seq: 1,
            resolution_seq: 2,
        },
        ForkError::PersistenceFailed { detail: "d".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ForkError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_safe_mode_state() {
    let sms = SafeModeState {
        active: true,
        trigger_seq: Some(42),
        unacknowledged_count: 3,
    };
    let json = serde_json::to_string(&sms).unwrap();
    let rt: SafeModeState = serde_json::from_str(&json).unwrap();
    assert_eq!(sms, rt);
}

#[test]
fn serde_roundtrip_fork_incident_report() {
    let fir = ForkIncidentReport {
        incident_id: "inc-rt".into(),
        fork_seq: 7,
        existing_checkpoint_id: oid(10),
        divergent_checkpoint_id: oid(11),
        existing_epoch: SecurityEpoch::from_raw(5),
        divergent_epoch: SecurityEpoch::from_raw(6),
        zone: "z".into(),
        frontier_seq_at_detection: 20,
        frontier_epoch_at_detection: SecurityEpoch::from_raw(7),
        detected_at_tick: 500,
        trace_id: "tr".into(),
        existing_was_accepted: false,
        acknowledged: true,
    };
    let json = serde_json::to_string(&fir).unwrap();
    let rt: ForkIncidentReport = serde_json::from_str(&json).unwrap();
    assert_eq!(fir, rt);
}

// ===========================================================================
// 11) evaluate_safe_mode_startup
// ===========================================================================

#[test]
fn safe_mode_startup_not_requested() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: Default::default(),
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    assert!(!result.safe_mode_active);
    assert_eq!(result.source, SafeModeStartupSource::NotRequested);
}

#[test]
fn safe_mode_startup_cli_flag() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: true,
        environment: Default::default(),
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    assert!(result.safe_mode_active);
    assert_eq!(result.source, SafeModeStartupSource::CliFlag);
}

// ===========================================================================
// 12) evaluate_safe_mode_exit
// ===========================================================================

#[test]
fn safe_mode_exit_clean_state() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    assert!(result.can_exit);
    assert!(result.blocking_reasons.is_empty());
}

#[test]
fn safe_mode_exit_blocked_by_incidents() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 2,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    assert!(!result.can_exit);
    assert!(!result.blocking_reasons.is_empty());
}

#[test]
fn safe_mode_state_debug_is_nonempty() {
    let state = SafeModeState::default();
    assert!(!format!("{state:?}").is_empty());
}

#[test]
fn fork_error_debug_is_nonempty() {
    let err = ForkError::SafeModeActive {
        incident_seq: 1,
        reason: "test".to_string(),
    };
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn safe_mode_startup_source_debug_is_nonempty() {
    let src = SafeModeStartupSource::CliFlag;
    assert!(!format!("{src:?}").is_empty());
}
