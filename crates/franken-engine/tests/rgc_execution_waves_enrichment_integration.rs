#![forbid(unsafe_code)]
//! Enrichment integration tests for `rgc_execution_waves`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, validation edge cases, and factory
//! defaults beyond the existing 4 integration tests.

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

use frankenengine_engine::rgc_execution_waves::{
    AgentMailProtocol, AntiStallAction, AntiStallThresholds, CoordinationDryRunReport,
    CoordinationValidationError, ExecutionWave, ExecutionWaveProtocol, FileReservationProtocol,
    RGC_COORDINATION_COMPONENT, RGC_COORDINATION_EVENT_SCHEMA_VERSION,
    RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION, RGC_WAVE_HANDOFF_SCHEMA_VERSION,
    WaveHandoffPackage, WavePlanEntry, default_rgc_execution_wave_protocol,
    default_wave_handoff_package, run_coordination_dry_run, select_anti_stall_action,
    validate_execution_wave_protocol, validate_wave_handoff_package,
};

// ===========================================================================
// 1) ExecutionWave — exact as_str / ordering
// ===========================================================================

#[test]
fn execution_wave_as_str_exact() {
    assert_eq!(ExecutionWave::Wave0.as_str(), "wave_0");
    assert_eq!(ExecutionWave::Wave1.as_str(), "wave_1");
    assert_eq!(ExecutionWave::Wave2.as_str(), "wave_2");
    assert_eq!(ExecutionWave::Wave3.as_str(), "wave_3");
}

#[test]
fn execution_wave_order_index() {
    assert_eq!(ExecutionWave::Wave0.order_index(), 0);
    assert_eq!(ExecutionWave::Wave1.order_index(), 1);
    assert_eq!(ExecutionWave::Wave2.order_index(), 2);
    assert_eq!(ExecutionWave::Wave3.order_index(), 3);
}

#[test]
fn execution_wave_ordering_stable() {
    let mut waves = vec![
        ExecutionWave::Wave3,
        ExecutionWave::Wave0,
        ExecutionWave::Wave2,
        ExecutionWave::Wave1,
    ];
    waves.sort();
    assert_eq!(waves, ExecutionWave::ALL);
}

#[test]
fn execution_wave_all_has_4() {
    assert_eq!(ExecutionWave::ALL.len(), 4);
}

// ===========================================================================
// 2) AntiStallAction — exact as_str
// ===========================================================================

#[test]
fn anti_stall_action_as_str_exact() {
    assert_eq!(AntiStallAction::Healthy.as_str(), "healthy");
    assert_eq!(AntiStallAction::Warn.as_str(), "warn");
    assert_eq!(AntiStallAction::Escalate.as_str(), "escalate");
    assert_eq!(AntiStallAction::Reassign.as_str(), "reassign");
    assert_eq!(AntiStallAction::Split.as_str(), "split");
}

// ===========================================================================
// 3) CoordinationValidationError — Display uniqueness + std::error::Error
// ===========================================================================

#[test]
fn coordination_validation_error_display_all_unique() {
    let variants: Vec<String> = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "a".into(),
            expected: "b".into(),
            actual: "c".into(),
        }
        .to_string(),
        CoordinationValidationError::EmptyField { field: "d".into() }.to_string(),
        CoordinationValidationError::DuplicateWaveEntry { wave: "e".into() }.to_string(),
        CoordinationValidationError::MissingWaveEntry { wave: "f".into() }.to_string(),
        CoordinationValidationError::DuplicateBeadOwnership {
            bead_id: "g".into(),
        }
        .to_string(),
        CoordinationValidationError::InvalidPredecessor {
            wave: "h".into(),
            predecessor: "i".into(),
        }
        .to_string(),
        CoordinationValidationError::InvalidThresholdOrder.to_string(),
        CoordinationValidationError::InvalidMailPolicy.to_string(),
        CoordinationValidationError::InvalidReservationPolicy.to_string(),
        CoordinationValidationError::UnknownWaveForHandoff { wave: "j".into() }.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

#[test]
fn coordination_validation_error_is_std_error() {
    let e = CoordinationValidationError::InvalidThresholdOrder;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn coordination_validation_error_display_contains_fields() {
    let e = CoordinationValidationError::InvalidSchemaVersion {
        field: "schema_version".into(),
        expected: "v1".into(),
        actual: "v2".into(),
    };
    let s = e.to_string();
    assert!(
        s.contains("schema_version") || s.contains("v1") || s.contains("v2"),
        "should mention field/expected/actual: {s}"
    );
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_execution_wave() {
    let variants: Vec<String> = ExecutionWave::ALL
        .iter()
        .map(|w| format!("{w:?}"))
        .collect();
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_anti_stall_action() {
    let variants = [
        format!("{:?}", AntiStallAction::Healthy),
        format!("{:?}", AntiStallAction::Warn),
        format!("{:?}", AntiStallAction::Escalate),
        format!("{:?}", AntiStallAction::Reassign),
        format!("{:?}", AntiStallAction::Split),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 5) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_execution_wave_tags() {
    let waves = ExecutionWave::ALL;
    let expected = ["\"wave_0\"", "\"wave_1\"", "\"wave_2\"", "\"wave_3\""];
    for (w, exp) in waves.iter().zip(expected.iter()) {
        let json = serde_json::to_string(w).unwrap();
        assert_eq!(json, *exp, "ExecutionWave serde tag mismatch for {w:?}");
    }
}

#[test]
fn serde_exact_anti_stall_action_tags() {
    let actions = [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ];
    let expected = [
        "\"healthy\"",
        "\"warn\"",
        "\"escalate\"",
        "\"reassign\"",
        "\"split\"",
    ];
    for (a, exp) in actions.iter().zip(expected.iter()) {
        let json = serde_json::to_string(a).unwrap();
        assert_eq!(json, *exp, "AntiStallAction serde tag mismatch for {a:?}");
    }
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_file_reservation_protocol() {
    let frp = FileReservationProtocol {
        exclusive_required: true,
        min_ttl_seconds: 3600,
        renew_before_seconds: 900,
        max_paths_per_claim: 12,
    };
    let v: serde_json::Value = serde_json::to_value(&frp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "exclusive_required",
        "min_ttl_seconds",
        "renew_before_seconds",
        "max_paths_per_claim",
    ] {
        assert!(
            obj.contains_key(key),
            "FileReservationProtocol missing field: {key}"
        );
    }
}

#[test]
fn json_fields_agent_mail_protocol() {
    let amp = AgentMailProtocol {
        poll_interval_seconds: 120,
        urgent_poll_interval_seconds: 30,
        ack_required_within_seconds: 300,
    };
    let v: serde_json::Value = serde_json::to_value(&amp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "poll_interval_seconds",
        "urgent_poll_interval_seconds",
        "ack_required_within_seconds",
    ] {
        assert!(
            obj.contains_key(key),
            "AgentMailProtocol missing field: {key}"
        );
    }
}

#[test]
fn json_fields_anti_stall_thresholds() {
    let ast = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    let v: serde_json::Value = serde_json::to_value(&ast).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "warn_after_seconds",
        "escalate_after_seconds",
        "reassign_after_seconds",
        "split_after_seconds",
    ] {
        assert!(
            obj.contains_key(key),
            "AntiStallThresholds missing field: {key}"
        );
    }
}

#[test]
fn json_fields_wave_plan_entry() {
    let wpe = WavePlanEntry {
        wave: ExecutionWave::Wave0,
        parallel_bead_ids: vec!["p1".into()],
        serial_bead_ids: vec!["s1".into()],
        required_predecessor_waves: vec![],
        entry_criteria: vec!["ready".into()],
        exit_criteria: vec!["done".into()],
    };
    let v: serde_json::Value = serde_json::to_value(&wpe).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "wave",
        "parallel_bead_ids",
        "serial_bead_ids",
        "required_predecessor_waves",
        "entry_criteria",
        "exit_criteria",
    ] {
        assert!(obj.contains_key(key), "WavePlanEntry missing field: {key}");
    }
}

#[test]
fn json_fields_coordination_event() {
    // Use dry run to get a CoordinationEvent since pass() is private
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 0, "t", "d").unwrap();
    let ce = &report.events[0];
    let v: serde_json::Value = serde_json::to_value(ce).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
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
            "CoordinationEvent missing field: {key}"
        );
    }
}

#[test]
fn json_fields_wave_handoff_package() {
    let pkg = default_wave_handoff_package();
    let v: serde_json::Value = serde_json::to_value(&pkg).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "wave",
        "from_owner",
        "to_owner",
        "changed_beads",
        "artifact_links",
        "open_risks",
        "next_steps",
    ] {
        assert!(
            obj.contains_key(key),
            "WaveHandoffPackage missing field: {key}"
        );
    }
}

#[test]
fn json_fields_coordination_dry_run_report() {
    let report = CoordinationDryRunReport {
        action: AntiStallAction::Healthy,
        events: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&report).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["action", "events"] {
        assert!(
            obj.contains_key(key),
            "CoordinationDryRunReport missing field: {key}"
        );
    }
}

// ===========================================================================
// 7) Constants stability
// ===========================================================================

#[test]
fn constants_stable() {
    assert_eq!(
        RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION,
        "franken-engine.rgc-execution-wave-protocol.v1"
    );
    assert_eq!(
        RGC_WAVE_HANDOFF_SCHEMA_VERSION,
        "franken-engine.rgc-wave-handoff.v1"
    );
    assert_eq!(
        RGC_COORDINATION_EVENT_SCHEMA_VERSION,
        "franken-engine.rgc-coordination.event.v1"
    );
    assert_eq!(RGC_COORDINATION_COMPONENT, "rgc_execution_waves");
}

// ===========================================================================
// 8) CoordinationEvent::pass factory
// ===========================================================================

#[test]
fn coordination_event_from_dry_run_has_correct_fields() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 0, "trace-1", "dec-1").unwrap();
    let ce = &report.events[0];
    assert_eq!(ce.outcome, "pass");
    assert!(ce.error_code.is_none());
    assert_eq!(ce.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
    assert_eq!(ce.component, RGC_COORDINATION_COMPONENT);
    assert_eq!(ce.trace_id, "trace-1");
    assert_eq!(ce.decision_id, "dec-1");
}

// ===========================================================================
// 9) Default factories are valid
// ===========================================================================

#[test]
fn default_protocol_is_valid() {
    let protocol = default_rgc_execution_wave_protocol();
    assert!(validate_execution_wave_protocol(&protocol).is_ok());
    assert_eq!(
        protocol.schema_version,
        RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION
    );
    assert_eq!(protocol.wave_order.len(), 4);
    assert_eq!(protocol.waves.len(), 4);
}

#[test]
fn default_handoff_is_valid() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    assert!(validate_wave_handoff_package(&protocol, &pkg).is_ok());
    assert_eq!(pkg.schema_version, RGC_WAVE_HANDOFF_SCHEMA_VERSION);
}

// ===========================================================================
// 10) select_anti_stall_action boundary cases
// ===========================================================================

#[test]
fn anti_stall_action_healthy_below_warn() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 0),
        AntiStallAction::Healthy
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 899),
        AntiStallAction::Healthy
    );
}

#[test]
fn anti_stall_action_warn_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 900),
        AntiStallAction::Warn
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 1799),
        AntiStallAction::Warn
    );
}

#[test]
fn anti_stall_action_escalate_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 1800),
        AntiStallAction::Escalate
    );
}

#[test]
fn anti_stall_action_reassign_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 2700),
        AntiStallAction::Reassign
    );
}

#[test]
fn anti_stall_action_split_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 900,
        escalate_after_seconds: 1800,
        reassign_after_seconds: 2700,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 3600),
        AntiStallAction::Split
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, u64::MAX),
        AntiStallAction::Split
    );
}

// ===========================================================================
// 11) Validation error cases
// ===========================================================================

#[test]
fn validate_protocol_rejects_wrong_schema_version() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.schema_version = "wrong".into();
    let err = validate_execution_wave_protocol(&protocol).unwrap_err();
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn validate_protocol_rejects_empty_policy_id() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.policy_id = "".into();
    let err = validate_execution_wave_protocol(&protocol).unwrap_err();
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn validate_handoff_rejects_wrong_schema_version() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut pkg = default_wave_handoff_package();
    pkg.schema_version = "wrong".into();
    let err = validate_wave_handoff_package(&protocol, &pkg).unwrap_err();
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidSchemaVersion { .. }
    ));
}

// ===========================================================================
// 12) Dry run produces correct events
// ===========================================================================

#[test]
fn dry_run_produces_4_events_on_success() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 0, "t", "d").unwrap();
    assert_eq!(report.action, AntiStallAction::Healthy);
    assert_eq!(report.events.len(), 4);
    assert_eq!(report.events[0].event, "protocol_validated");
    assert_eq!(report.events[1].event, "handoff_validated");
    assert!(report.events[2].event.starts_with("anti_stall_"));
    assert_eq!(report.events[3].event, "dry_run_completed");
    for ev in &report.events {
        assert_eq!(ev.outcome, "pass");
        assert!(ev.error_code.is_none());
        assert_eq!(ev.trace_id, "t");
        assert_eq!(ev.decision_id, "d");
    }
}

#[test]
fn dry_run_with_idle_selects_correct_action() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 2000, "t", "d").unwrap();
    assert_eq!(report.action, AntiStallAction::Escalate);
}

#[test]
fn dry_run_propagates_validation_error() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.schema_version = "wrong".into();
    let pkg = default_wave_handoff_package();
    assert!(run_coordination_dry_run(&protocol, &pkg, 0, "t", "d").is_err());
}

// ===========================================================================
// 13) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_execution_wave() {
    for w in &ExecutionWave::ALL {
        let json = serde_json::to_string(w).unwrap();
        let rt: ExecutionWave = serde_json::from_str(&json).unwrap();
        assert_eq!(*w, rt);
    }
}

#[test]
fn serde_roundtrip_anti_stall_action() {
    let actions = [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ];
    for a in &actions {
        let json = serde_json::to_string(a).unwrap();
        let rt: AntiStallAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*a, rt);
    }
}

#[test]
fn serde_roundtrip_coordination_validation_error_all_variants() {
    let variants = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "a".into(),
            expected: "b".into(),
            actual: "c".into(),
        },
        CoordinationValidationError::EmptyField { field: "d".into() },
        CoordinationValidationError::DuplicateWaveEntry { wave: "e".into() },
        CoordinationValidationError::MissingWaveEntry { wave: "f".into() },
        CoordinationValidationError::DuplicateBeadOwnership {
            bead_id: "g".into(),
        },
        CoordinationValidationError::InvalidPredecessor {
            wave: "h".into(),
            predecessor: "i".into(),
        },
        CoordinationValidationError::InvalidThresholdOrder,
        CoordinationValidationError::InvalidMailPolicy,
        CoordinationValidationError::InvalidReservationPolicy,
        CoordinationValidationError::UnknownWaveForHandoff { wave: "j".into() },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: CoordinationValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_execution_wave_protocol() {
    let protocol = default_rgc_execution_wave_protocol();
    let json = serde_json::to_string(&protocol).unwrap();
    let rt: ExecutionWaveProtocol = serde_json::from_str(&json).unwrap();
    assert_eq!(protocol, rt);
}

#[test]
fn serde_roundtrip_wave_handoff_package() {
    let pkg = default_wave_handoff_package();
    let json = serde_json::to_string(&pkg).unwrap();
    let rt: WaveHandoffPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, rt);
}

#[test]
fn serde_roundtrip_coordination_dry_run_report() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 0, "t", "d").unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let rt: CoordinationDryRunReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, rt);
}

// ===========================================================================
// Enrichment: ExecutionWave — order_index values
// ===========================================================================

#[test]
fn enrichment_execution_wave_order_index_distinct() {
    let mut indices = BTreeSet::new();
    for wave in &ExecutionWave::ALL {
        indices.insert(wave.order_index());
    }
    assert_eq!(indices.len(), 4);
}

#[test]
fn enrichment_execution_wave_order_matches_all_array() {
    for (i, wave) in ExecutionWave::ALL.iter().enumerate() {
        assert_eq!(wave.order_index(), i);
    }
}

// ===========================================================================
// Enrichment: ExecutionWave — Display strings unique
// ===========================================================================

#[test]
fn enrichment_execution_wave_as_str_unique() {
    let displays: BTreeSet<&str> = ExecutionWave::ALL.iter().map(|w| w.as_str()).collect();
    assert_eq!(displays.len(), 4);
}

// ===========================================================================
// Enrichment: ExecutionWave — Clone/Copy
// ===========================================================================

#[test]
fn enrichment_execution_wave_copy() {
    let w = ExecutionWave::Wave0;
    let w2 = w;
    assert_eq!(w, w2);
}

// ===========================================================================
// Enrichment: AntiStallAction — as_str exact
// ===========================================================================

#[test]
fn enrichment_anti_stall_action_as_str_exact() {
    assert_eq!(AntiStallAction::Healthy.as_str(), "healthy");
    assert_eq!(AntiStallAction::Warn.as_str(), "warn");
    assert_eq!(AntiStallAction::Escalate.as_str(), "escalate");
    assert_eq!(AntiStallAction::Reassign.as_str(), "reassign");
    assert_eq!(AntiStallAction::Split.as_str(), "split");
}

// ===========================================================================
// Enrichment: select_anti_stall_action — boundary cases
// ===========================================================================

#[test]
fn enrichment_select_anti_stall_zero_elapsed_healthy() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 60,
        escalate_after_seconds: 120,
        reassign_after_seconds: 300,
        split_after_seconds: 600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 0),
        AntiStallAction::Healthy
    );
}

#[test]
fn enrichment_select_anti_stall_at_warn_boundary() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 60,
        escalate_after_seconds: 120,
        reassign_after_seconds: 300,
        split_after_seconds: 600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 60),
        AntiStallAction::Warn
    );
}

#[test]
fn enrichment_select_anti_stall_at_split_boundary() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 60,
        escalate_after_seconds: 120,
        reassign_after_seconds: 300,
        split_after_seconds: 600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 600),
        AntiStallAction::Split
    );
}

#[test]
fn enrichment_select_anti_stall_above_split() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 60,
        escalate_after_seconds: 120,
        reassign_after_seconds: 300,
        split_after_seconds: 600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 9999),
        AntiStallAction::Split
    );
}

// ===========================================================================
// Enrichment: default protocol — validation passes
// ===========================================================================

#[test]
fn enrichment_default_protocol_validates_clean() {
    let protocol = default_rgc_execution_wave_protocol();
    assert!(
        validate_execution_wave_protocol(&protocol).is_ok(),
        "default protocol should validate clean"
    );
}

// ===========================================================================
// Enrichment: default handoff — validation passes
// ===========================================================================

#[test]
fn enrichment_default_handoff_validates_clean() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    assert!(
        validate_wave_handoff_package(&protocol, &pkg).is_ok(),
        "default handoff should validate clean"
    );
}

// ===========================================================================
// Enrichment: dry run report — fields populated
// ===========================================================================

#[test]
fn enrichment_dry_run_report_fields_populated() {
    let protocol = default_rgc_execution_wave_protocol();
    let pkg = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &pkg, 42, "t-1", "d-1").unwrap();
    // CoordinationDryRunReport has `action` and `events` fields.
    assert_eq!(report.action, AntiStallAction::Healthy);
    assert!(!report.events.is_empty());
}

// ===========================================================================
// Enrichment: constants — nonempty
// ===========================================================================

#[test]
fn enrichment_constants_nonempty() {
    assert!(!RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION.is_empty());
    assert!(!RGC_WAVE_HANDOFF_SCHEMA_VERSION.is_empty());
    assert!(!RGC_COORDINATION_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!RGC_COORDINATION_COMPONENT.is_empty());
}

// ===========================================================================
// Enrichment: WavePlanEntry — clone + Debug
// ===========================================================================

#[test]
fn enrichment_wave_plan_entry_clone_debug() {
    let entry = WavePlanEntry {
        wave: ExecutionWave::Wave1,
        parallel_bead_ids: vec!["bd-1".into()],
        serial_bead_ids: vec!["bd-2".into()],
        required_predecessor_waves: vec![ExecutionWave::Wave0],
        entry_criteria: vec!["criterion".into()],
        exit_criteria: vec!["exit".into()],
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
    assert!(!format!("{:?}", entry).is_empty());
}

// ===========================================================================
// Enrichment: FileReservationProtocol — serde
// ===========================================================================

#[test]
fn enrichment_file_reservation_protocol_serde() {
    let p = FileReservationProtocol {
        exclusive_required: true,
        min_ttl_seconds: 3600,
        renew_before_seconds: 900,
        max_paths_per_claim: 12,
    };
    let json = serde_json::to_string(&p).unwrap();
    let rt: FileReservationProtocol = serde_json::from_str(&json).unwrap();
    assert_eq!(p, rt);
}

// ===========================================================================
// Enrichment: AgentMailProtocol — serde
// ===========================================================================

#[test]
fn enrichment_agent_mail_protocol_serde() {
    let p = AgentMailProtocol {
        poll_interval_seconds: 120,
        urgent_poll_interval_seconds: 30,
        ack_required_within_seconds: 300,
    };
    let json = serde_json::to_string(&p).unwrap();
    let rt: AgentMailProtocol = serde_json::from_str(&json).unwrap();
    assert_eq!(p, rt);
}

// ===========================================================================
// Enrichment: AntiStallThresholds — serde
// ===========================================================================

#[test]
fn enrichment_anti_stall_thresholds_serde() {
    let t = AntiStallThresholds {
        warn_after_seconds: 60,
        escalate_after_seconds: 120,
        reassign_after_seconds: 300,
        split_after_seconds: 600,
    };
    let json = serde_json::to_string(&t).unwrap();
    let rt: AntiStallThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, rt);
}

// ===========================================================================
// Enrichment: CoordinationValidationError — Display unique
// ===========================================================================

#[test]
fn enrichment_coordination_validation_error_display_unique() {
    let errors = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "a".into(),
            expected: "b".into(),
            actual: "c".into(),
        },
        CoordinationValidationError::EmptyField { field: "d".into() },
        CoordinationValidationError::DuplicateWaveEntry { wave: "e".into() },
        CoordinationValidationError::MissingWaveEntry { wave: "f".into() },
        CoordinationValidationError::DuplicateBeadOwnership {
            bead_id: "g".into(),
        },
        CoordinationValidationError::InvalidPredecessor {
            wave: "h".into(),
            predecessor: "i".into(),
        },
        CoordinationValidationError::InvalidThresholdOrder,
        CoordinationValidationError::InvalidMailPolicy,
        CoordinationValidationError::InvalidReservationPolicy,
        CoordinationValidationError::UnknownWaveForHandoff { wave: "j".into() },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}
