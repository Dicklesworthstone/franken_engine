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

// ===========================================================================
// 13) ForkEventType — Display exactness for all variants
// ===========================================================================

#[test]
fn fork_event_type_display_fork_detected() {
    let evt = frankenengine_engine::fork_detection::ForkEventType::ForkDetected {
        zone: "z1".into(),
        checkpoint_seq: 42,
    };
    let s = evt.to_string();
    assert!(s.contains("fork_detected"), "expected fork_detected: {s}");
    assert!(s.contains("z1"), "expected zone: {s}");
    assert!(s.contains("42"), "expected seq: {s}");
}

#[test]
fn fork_event_type_display_all_variants_unique() {
    use frankenengine_engine::fork_detection::ForkEventType;
    let variants: Vec<String> = vec![
        ForkEventType::ForkDetected {
            zone: "z".into(),
            checkpoint_seq: 1,
        }
        .to_string(),
        ForkEventType::SafeModeEntered {
            zone: "z".into(),
            trigger_seq: 1,
        }
        .to_string(),
        ForkEventType::SafeModeExited {
            zone: "z".into(),
            acknowledged_incidents: 1,
        }
        .to_string(),
        ForkEventType::CheckpointRecorded {
            zone: "z".into(),
            checkpoint_seq: 1,
        }
        .to_string(),
        ForkEventType::OperationDenied {
            zone: "z".into(),
            operation: "op".into(),
        }
        .to_string(),
        ForkEventType::HistoryTrimmed {
            zone: "z".into(),
            removed_count: 1,
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all ForkEventType Display strings must be unique"
    );
}

// ===========================================================================
// 14) ForkEvent — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_fork_event() {
    use frankenengine_engine::fork_detection::{ForkEvent, ForkEventType};
    let event = ForkEvent {
        event_type: ForkEventType::CheckpointRecorded {
            zone: "default".into(),
            checkpoint_seq: 99,
        },
        trace_id: "trace-abc".into(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: ForkEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

// ===========================================================================
// 15) SafeModeStartupArtifact — serde roundtrip and field presence
// ===========================================================================

#[test]
fn serde_roundtrip_safe_mode_startup_artifact() {
    let input = SafeModeStartupInput {
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        cli_safe_mode: true,
        environment: Default::default(),
    };
    let artifact =
        frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    let rt: frankenengine_engine::fork_detection::SafeModeStartupArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, rt);
}

#[test]
fn safe_mode_startup_artifact_field_names_stable() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: true,
        environment: Default::default(),
    };
    let artifact =
        frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    let v: serde_json::Value = serde_json::to_value(&artifact).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "safe_mode_active",
        "source",
        "restrictions",
        "startup_sequence",
        "restricted_features",
        "exit_procedure",
        "evidence_preserved",
        "logs_preserved",
        "state_preserved",
        "events",
    ] {
        assert!(
            obj.contains_key(key),
            "SafeModeStartupArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 16) SafeModeExitCheckArtifact — serde roundtrip and field presence
// ===========================================================================

#[test]
fn serde_roundtrip_safe_mode_exit_check_artifact() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 2,
        evidence_ledger_flushed: false,
    };
    let artifact = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    let json = serde_json::to_string(&artifact).unwrap();
    let rt: frankenengine_engine::fork_detection::SafeModeExitCheckArtifact =
        serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, rt);
}

#[test]
fn safe_mode_exit_check_artifact_field_names_stable() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    let artifact = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    let v: serde_json::Value = serde_json::to_value(&artifact).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["can_exit", "blocking_reasons", "event"] {
        assert!(
            obj.contains_key(key),
            "SafeModeExitCheckArtifact missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) SafeModeStartupError — Display exactness and serde roundtrip
// ===========================================================================

#[test]
fn safe_mode_startup_error_display_contains_field() {
    let e = SafeModeStartupError::MissingField {
        field: "trace_id".into(),
    };
    let s = e.to_string();
    assert!(s.contains("trace_id"), "should contain field name: {s}");
    assert!(s.contains("missing"), "should contain 'missing': {s}");
}

#[test]
fn serde_roundtrip_safe_mode_startup_error() {
    let e = SafeModeStartupError::MissingField {
        field: "decision_id".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: SafeModeStartupError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 18) evaluate_safe_mode_startup — environment variable source
// ===========================================================================

#[test]
fn safe_mode_startup_env_var_source() {
    let mut env = std::collections::BTreeMap::new();
    env.insert("FRANKEN_SAFE_MODE".into(), "1".into());
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: env,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    assert!(result.safe_mode_active);
    assert_eq!(result.source, SafeModeStartupSource::EnvironmentVariable);
}

#[test]
fn safe_mode_startup_env_var_second_flag() {
    let mut env = std::collections::BTreeMap::new();
    env.insert("FRANKENENGINE_SAFE_MODE".into(), "true".into());
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: env,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    assert!(result.safe_mode_active);
    assert_eq!(result.source, SafeModeStartupSource::EnvironmentVariable);
}

// ===========================================================================
// 19) evaluate_safe_mode_startup — validation errors
// ===========================================================================

#[test]
fn safe_mode_startup_empty_trace_id_error() {
    let input = SafeModeStartupInput {
        trace_id: "".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: Default::default(),
    };
    let err = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap_err();
    assert_eq!(
        err,
        SafeModeStartupError::MissingField {
            field: "trace_id".into()
        }
    );
}

#[test]
fn safe_mode_startup_empty_decision_id_error() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "  ".into(),
        policy_id: "p".into(),
        cli_safe_mode: false,
        environment: Default::default(),
    };
    let err = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap_err();
    assert_eq!(
        err,
        SafeModeStartupError::MissingField {
            field: "decision_id".into()
        }
    );
}

#[test]
fn safe_mode_startup_empty_policy_id_error() {
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "".into(),
        cli_safe_mode: false,
        environment: Default::default(),
    };
    let err = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap_err();
    assert_eq!(
        err,
        SafeModeStartupError::MissingField {
            field: "policy_id".into()
        }
    );
}

// ===========================================================================
// 20) evaluate_safe_mode_exit — all three blocking reasons
// ===========================================================================

#[test]
fn safe_mode_exit_blocked_by_quarantines() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 3,
        evidence_ledger_flushed: true,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    assert!(!result.can_exit);
    assert!(
        result
            .blocking_reasons
            .iter()
            .any(|r| r.contains("quarantine")),
        "should mention quarantines: {:?}",
        result.blocking_reasons
    );
}

#[test]
fn safe_mode_exit_blocked_by_unflushed_ledger() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: false,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    assert!(!result.can_exit);
    assert!(
        result.blocking_reasons.iter().any(|r| r.contains("ledger")),
        "should mention ledger: {:?}",
        result.blocking_reasons
    );
}

#[test]
fn safe_mode_exit_multiple_blocking_reasons() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 2,
        evidence_ledger_flushed: false,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap();
    assert!(!result.can_exit);
    assert_eq!(
        result.blocking_reasons.len(),
        3,
        "should have exactly 3 blocking reasons: {:?}",
        result.blocking_reasons
    );
}

// ===========================================================================
// 21) ForkError::InvalidResolution — Display content
// ===========================================================================

#[test]
fn fork_error_display_invalid_resolution() {
    let e = ForkError::InvalidResolution {
        fork_seq: 10,
        resolution_seq: 5,
    };
    let s = e.to_string();
    assert!(s.contains("10"), "should contain fork_seq: {s}");
    assert!(s.contains("5"), "should contain resolution_seq: {s}");
    assert!(
        s.contains("invalid resolution"),
        "should contain phrase: {s}"
    );
}

// ===========================================================================
// 22) ForkError::PersistenceFailed — Display content
// ===========================================================================

#[test]
fn fork_error_display_persistence_failed() {
    let e = ForkError::PersistenceFailed {
        detail: "disk full".into(),
    };
    let s = e.to_string();
    assert!(s.contains("disk full"), "should contain detail: {s}");
    assert!(
        s.contains("persistence"),
        "should contain 'persistence': {s}"
    );
}

// ===========================================================================
// 23) SafeModeRestrictions — clone and serde roundtrip
// ===========================================================================

#[test]
fn safe_mode_restrictions_clone_eq() {
    let smr = SafeModeRestrictions {
        all_extensions_sandboxed: true,
        auto_promotion_disabled: false,
        conservative_policy_defaults: true,
        enhanced_telemetry: false,
        adaptive_tuning_disabled: true,
    };
    let cloned = smr.clone();
    assert_eq!(smr, cloned);
}

#[test]
fn serde_roundtrip_safe_mode_restrictions() {
    let smr = SafeModeRestrictions {
        all_extensions_sandboxed: true,
        auto_promotion_disabled: true,
        conservative_policy_defaults: false,
        enhanced_telemetry: true,
        adaptive_tuning_disabled: false,
    };
    let json = serde_json::to_string(&smr).unwrap();
    let rt: SafeModeRestrictions = serde_json::from_str(&json).unwrap();
    assert_eq!(smr, rt);
}

// ===========================================================================
// 24) SafeModeStartupEvent — serde roundtrip and clone
// ===========================================================================

#[test]
fn serde_roundtrip_safe_mode_startup_event() {
    let event = SafeModeStartupEvent {
        trace_id: "t123".into(),
        decision_id: "d456".into(),
        policy_id: "p789".into(),
        component: "fork_detection".into(),
        event: "test_event".into(),
        outcome: "pass".into(),
        error_code: Some("ERR-001".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: SafeModeStartupEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

#[test]
fn safe_mode_startup_event_clone_eq() {
    let event = SafeModeStartupEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

// ===========================================================================
// 25) CheckpointHistoryEntry — clone and Debug
// ===========================================================================

#[test]
fn checkpoint_history_entry_clone_eq() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: 100,
        checkpoint_id: oid(42),
        epoch: SecurityEpoch::from_raw(5),
        accepted: true,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn checkpoint_history_entry_debug_contains_seq() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: 77,
        checkpoint_id: oid(1),
        epoch: SecurityEpoch::from_raw(1),
        accepted: false,
    };
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("77"), "Debug should contain seq: {dbg}");
    assert!(
        dbg.contains("false"),
        "Debug should contain accepted: {dbg}"
    );
}

// ===========================================================================
// 26) SafeModeState — clone and active state roundtrip
// ===========================================================================

#[test]
fn safe_mode_state_active_roundtrip() {
    let state = SafeModeState {
        active: true,
        trigger_seq: Some(99),
        unacknowledged_count: 5,
    };
    let json = serde_json::to_string(&state).unwrap();
    let rt: SafeModeState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, rt);
    assert!(rt.active);
    assert_eq!(rt.trigger_seq, Some(99));
    assert_eq!(rt.unacknowledged_count, 5);
}

// ===========================================================================
// 27) ForkIncidentReport — clone and Debug
// ===========================================================================

#[test]
fn fork_incident_report_clone_eq() {
    let fir = ForkIncidentReport {
        incident_id: "inc-clone".into(),
        fork_seq: 3,
        existing_checkpoint_id: oid(10),
        divergent_checkpoint_id: oid(11),
        existing_epoch: SecurityEpoch::from_raw(1),
        divergent_epoch: SecurityEpoch::from_raw(2),
        zone: "z".into(),
        frontier_seq_at_detection: 5,
        frontier_epoch_at_detection: SecurityEpoch::from_raw(3),
        detected_at_tick: 200,
        trace_id: "tr".into(),
        existing_was_accepted: true,
        acknowledged: false,
    };
    let cloned = fir.clone();
    assert_eq!(fir, cloned);
}

// ===========================================================================
// 28) ForkDetector — incidents for unknown zone
// ===========================================================================

#[test]
fn fork_detector_incidents_unknown_zone_empty() {
    let fd = ForkDetector::new(50);
    assert!(fd.incidents("no-such-zone").is_empty());
}

#[test]
fn fork_detector_unacknowledged_incidents_unknown_zone_empty() {
    let fd = ForkDetector::new(50);
    assert!(fd.unacknowledged_incidents("no-such-zone").is_empty());
}

// ===========================================================================
// 29) ForkDetector — acknowledge_incident unknown zone returns false
// ===========================================================================

#[test]
fn fork_detector_acknowledge_unknown_zone_returns_false() {
    let mut fd = ForkDetector::new(50);
    assert!(!fd.acknowledge_incident("no-zone", "inc-1"));
}

// ===========================================================================
// 30) ForkDetector — exit_safe_mode unknown zone returns Ok(0)
// ===========================================================================

#[test]
fn fork_detector_exit_safe_mode_unknown_zone() {
    let mut fd = ForkDetector::new(50);
    let result = fd.exit_safe_mode("no-zone", "trace-1");
    assert_eq!(result.unwrap(), 0);
}

// ===========================================================================
// 31) ForkDetector — event_counts initially empty
// ===========================================================================

#[test]
fn fork_detector_event_counts_initially_empty() {
    let fd = ForkDetector::new(50);
    assert!(fd.event_counts().is_empty());
}

// ===========================================================================
// 32) ForkDetector — export_state initially empty
// ===========================================================================

#[test]
fn fork_detector_export_state_initially_empty() {
    let fd = ForkDetector::new(50);
    assert!(fd.export_state().is_empty());
}

// ===========================================================================
// 33) evaluate_safe_mode_exit — validation error
// ===========================================================================

#[test]
fn safe_mode_exit_empty_trace_id_error() {
    let input = SafeModeExitCheckInput {
        trace_id: "".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    let err = frankenengine_engine::fork_detection::evaluate_safe_mode_exit(&input).unwrap_err();
    assert_eq!(
        err,
        SafeModeStartupError::MissingField {
            field: "trace_id".into()
        }
    );
}

// ===========================================================================
// 34) SafeModeStartupSource — serde roundtrip of all variants
// ===========================================================================

#[test]
fn serde_roundtrip_safe_mode_startup_source_all() {
    let variants = [
        SafeModeStartupSource::NotRequested,
        SafeModeStartupSource::CliFlag,
        SafeModeStartupSource::EnvironmentVariable,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: SafeModeStartupSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

// ===========================================================================
// 35) SafeModeStartupSource — Copy trait
// ===========================================================================

#[test]
fn safe_mode_startup_source_is_copy() {
    let src = SafeModeStartupSource::CliFlag;
    let copied = src;
    // Both are valid after copy (no move semantics).
    assert_eq!(src, copied);
}

// ===========================================================================
// 36) ForkEventType — serde roundtrip for all variants
// ===========================================================================

#[test]
fn serde_roundtrip_fork_event_type_all_variants() {
    use frankenengine_engine::fork_detection::ForkEventType;
    let variants = vec![
        ForkEventType::ForkDetected {
            zone: "z".into(),
            checkpoint_seq: 1,
        },
        ForkEventType::SafeModeEntered {
            zone: "z".into(),
            trigger_seq: 2,
        },
        ForkEventType::SafeModeExited {
            zone: "z".into(),
            acknowledged_incidents: 3,
        },
        ForkEventType::CheckpointRecorded {
            zone: "z".into(),
            checkpoint_seq: 4,
        },
        ForkEventType::OperationDenied {
            zone: "z".into(),
            operation: "op".into(),
        },
        ForkEventType::HistoryTrimmed {
            zone: "z".into(),
            removed_count: 5,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: ForkEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

// ===========================================================================
// 37) Safe mode startup — env var falsy values do not activate
// ===========================================================================

#[test]
fn safe_mode_startup_env_var_falsy_values_ignored() {
    for val in &["0", "false", "no", "off", "random", ""] {
        let mut env = std::collections::BTreeMap::new();
        env.insert("FRANKEN_SAFE_MODE".into(), (*val).to_string());
        let input = SafeModeStartupInput {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            cli_safe_mode: false,
            environment: env,
        };
        let result =
            frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
        assert!(
            !result.safe_mode_active,
            "env value '{val}' should not activate safe mode"
        );
        assert_eq!(result.source, SafeModeStartupSource::NotRequested);
    }
}

// ===========================================================================
// 38) Safe mode startup — cli_safe_mode takes precedence over env var
// ===========================================================================

#[test]
fn safe_mode_startup_cli_takes_precedence_over_env() {
    let mut env = std::collections::BTreeMap::new();
    env.insert("FRANKEN_SAFE_MODE".into(), "1".into());
    let input = SafeModeStartupInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        cli_safe_mode: true,
        environment: env,
    };
    let result = frankenengine_engine::fork_detection::evaluate_safe_mode_startup(&input).unwrap();
    assert!(result.safe_mode_active);
    // CLI flag takes precedence.
    assert_eq!(result.source, SafeModeStartupSource::CliFlag);
}
