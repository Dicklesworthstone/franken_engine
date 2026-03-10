#![forbid(unsafe_code)]
//! Integration tests for RGC execution-wave coordination protocol.

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

use frankenengine_engine::rgc_execution_waves::{
    AgentMailProtocol, AntiStallAction, AntiStallThresholds, CoordinationDryRunReport,
    CoordinationEvent, CoordinationValidationError, ExecutionWave, ExecutionWaveProtocol,
    FileReservationProtocol, RGC_COORDINATION_COMPONENT, RGC_COORDINATION_EVENT_SCHEMA_VERSION,
    RGC_EXECUTION_WAVE_PROTOCOL_SCHEMA_VERSION, RGC_WAVE_HANDOFF_SCHEMA_VERSION,
    WaveHandoffPackage, WavePlanEntry, default_rgc_execution_wave_protocol,
    default_wave_handoff_package, run_coordination_dry_run, select_anti_stall_action,
    validate_execution_wave_protocol, validate_wave_handoff_package,
};

#[test]
fn rgc_execution_waves_default_contract_versions_are_stable() {
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
}

#[test]
fn rgc_execution_waves_serde_tags_are_stable() {
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave0).unwrap(),
        "\"wave_0\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave1).unwrap(),
        "\"wave_1\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave2).unwrap(),
        "\"wave_2\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionWave::Wave3).unwrap(),
        "\"wave_3\""
    );
}

#[test]
fn rgc_execution_waves_protocol_and_handoff_validate() {
    let protocol = default_rgc_execution_wave_protocol();
    validate_execution_wave_protocol(&protocol).expect("default protocol must validate");

    let handoff = default_wave_handoff_package();
    validate_wave_handoff_package(&protocol, &handoff).expect("default handoff must validate");
}

#[test]
fn rgc_execution_waves_handoff_rejects_unknown_wave() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.waves.pop(); // remove wave_3 entry

    let mut handoff = default_wave_handoff_package();
    handoff.wave = frankenengine_engine::rgc_execution_waves::ExecutionWave::Wave3;

    let error = validate_wave_handoff_package(&protocol, &handoff)
        .expect_err("handoff with missing wave should fail");
    assert!(matches!(
        error,
        CoordinationValidationError::UnknownWaveForHandoff { .. }
    ));
}

#[test]
fn rgc_execution_waves_handoff_rejects_missing_artifact_triad_member() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.artifact_links = vec![
        "artifacts/rgc_execution_waves_coordination/demo/run_manifest.json".to_string(),
        "artifacts/rgc_execution_waves_coordination/demo/events.jsonl".to_string(),
    ];

    let error = validate_wave_handoff_package(&protocol, &handoff)
        .expect_err("handoff without commands.txt artifact should fail");
    assert!(matches!(
        error,
        CoordinationValidationError::MissingRequiredArtifactLink { .. }
    ));
}

#[test]
fn rgc_execution_waves_handoff_rejects_next_steps_without_target_bead_reference() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.next_steps = vec![
        "notify wave lead".to_string(),
        "prepare reservation request".to_string(),
    ];

    let error = validate_wave_handoff_package(&protocol, &handoff).expect_err(
        "handoff next steps must reference at least one target wave bead id for automation",
    );
    assert!(matches!(
        error,
        CoordinationValidationError::MissingTargetWaveNextStep { .. }
    ));
}

#[test]
fn rgc_execution_waves_dry_run_emits_required_coordination_events() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();

    let report = run_coordination_dry_run(
        &protocol,
        &handoff,
        3_700,
        "trace-rgc-e2e-01",
        "decision-rgc-e2e-01",
    )
    .expect("dry run should succeed");

    assert_eq!(report.action, AntiStallAction::Split);
    assert_eq!(report.events.len(), 4);

    let required_events = [
        "protocol_validated",
        "handoff_validated",
        "anti_stall_split",
        "dry_run_completed",
    ];

    for (index, expected) in required_events.iter().enumerate() {
        let event = &report.events[index];
        assert_eq!(event.event, *expected);
        assert_eq!(event.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
        assert_eq!(event.trace_id, "trace-rgc-e2e-01");
        assert_eq!(event.decision_id, "decision-rgc-e2e-01");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, defaults, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn execution_wave_all_const_covers_four_waves() {
    assert_eq!(ExecutionWave::ALL.len(), 4);
    for wave in ExecutionWave::ALL {
        let json = serde_json::to_string(&wave).expect("serialize");
        let recovered: ExecutionWave = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(wave, recovered);
    }
}

#[test]
fn anti_stall_action_serde_round_trip_all_variants() {
    for action in [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ] {
        let json = serde_json::to_string(&action).expect("serialize");
        let recovered: AntiStallAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(action, recovered);
    }
}

#[test]
fn anti_stall_action_as_str_is_non_empty() {
    for action in [
        AntiStallAction::Healthy,
        AntiStallAction::Warn,
        AntiStallAction::Escalate,
        AntiStallAction::Reassign,
        AntiStallAction::Split,
    ] {
        assert!(!action.as_str().is_empty());
    }
}

#[test]
fn coordination_validation_error_display_is_non_empty() {
    let errors: Vec<CoordinationValidationError> = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "schema".to_string(),
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CoordinationValidationError::EmptyField {
            field: "from_owner".to_string(),
        },
        CoordinationValidationError::DuplicateWaveEntry {
            wave: "wave_0".to_string(),
        },
        CoordinationValidationError::MissingWaveEntry {
            wave: "wave_3".to_string(),
        },
        CoordinationValidationError::UnknownWaveForHandoff {
            wave: "wave_5".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "error display must not be empty: {err:?}");
    }
}

#[test]
fn wave_handoff_package_serde_round_trip() {
    let handoff = default_wave_handoff_package();
    let json = serde_json::to_string(&handoff).expect("serialize");
    let recovered: WaveHandoffPackage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(handoff, recovered);
}

#[test]
fn default_protocol_has_entries_for_all_waves() {
    let protocol = default_rgc_execution_wave_protocol();
    assert_eq!(protocol.waves.len(), 4);
    let json = serde_json::to_string(&protocol).expect("serialize");
    assert!(json.contains("wave_0"));
    assert!(json.contains("wave_3"));
}

// ────────────────────────────────────────────────────────────
// Enrichment session 2: validation edge cases, anti-stall, structs
// ────────────────────────────────────────────────────────────

#[test]
fn execution_wave_as_str_is_non_empty_for_all() {
    for wave in ExecutionWave::ALL {
        assert!(!wave.as_str().is_empty());
    }
}

#[test]
fn execution_wave_order_index_is_sequential() {
    assert_eq!(ExecutionWave::Wave0.order_index(), 0);
    assert_eq!(ExecutionWave::Wave1.order_index(), 1);
    assert_eq!(ExecutionWave::Wave2.order_index(), 2);
    assert_eq!(ExecutionWave::Wave3.order_index(), 3);
}

#[test]
fn execution_wave_ordering_matches_index() {
    assert!(ExecutionWave::Wave0 < ExecutionWave::Wave1);
    assert!(ExecutionWave::Wave1 < ExecutionWave::Wave2);
    assert!(ExecutionWave::Wave2 < ExecutionWave::Wave3);
}

#[test]
fn coordination_component_constant_is_stable() {
    assert_eq!(RGC_COORDINATION_COMPONENT, "rgc_execution_waves");
}

#[test]
fn select_anti_stall_healthy_below_warn() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 300,
        escalate_after_seconds: 600,
        reassign_after_seconds: 1800,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 0),
        AntiStallAction::Healthy
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 299),
        AntiStallAction::Healthy
    );
}

#[test]
fn select_anti_stall_warn_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 300,
        escalate_after_seconds: 600,
        reassign_after_seconds: 1800,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 300),
        AntiStallAction::Warn
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 599),
        AntiStallAction::Warn
    );
}

#[test]
fn select_anti_stall_escalate_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 300,
        escalate_after_seconds: 600,
        reassign_after_seconds: 1800,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 600),
        AntiStallAction::Escalate
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 1799),
        AntiStallAction::Escalate
    );
}

#[test]
fn select_anti_stall_reassign_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 300,
        escalate_after_seconds: 600,
        reassign_after_seconds: 1800,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 1800),
        AntiStallAction::Reassign
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 3599),
        AntiStallAction::Reassign
    );
}

#[test]
fn select_anti_stall_split_at_threshold() {
    let thresholds = AntiStallThresholds {
        warn_after_seconds: 300,
        escalate_after_seconds: 600,
        reassign_after_seconds: 1800,
        split_after_seconds: 3600,
    };
    assert_eq!(
        select_anti_stall_action(&thresholds, 3600),
        AntiStallAction::Split
    );
    assert_eq!(
        select_anti_stall_action(&thresholds, 999_999),
        AntiStallAction::Split
    );
}

#[test]
fn protocol_rejects_invalid_schema_version() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.schema_version = "wrong-version".to_string();
    let err = validate_execution_wave_protocol(&protocol).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn protocol_rejects_empty_policy_id() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.policy_id = "   ".to_string();
    let err = validate_execution_wave_protocol(&protocol).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn protocol_rejects_invalid_threshold_order() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.anti_stall.warn_after_seconds = 9999;
    let err = validate_execution_wave_protocol(&protocol).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidThresholdOrder
    ));
}

#[test]
fn protocol_rejects_invalid_mail_policy() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.agent_mail.urgent_poll_interval_seconds = 0;
    let err = validate_execution_wave_protocol(&protocol).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidMailPolicy
    ));
}

#[test]
fn protocol_rejects_invalid_reservation_policy_low_ttl() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.file_reservation.min_ttl_seconds = 10; // must be >= 60
    let err = validate_execution_wave_protocol(&protocol).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidReservationPolicy
    ));
}

#[test]
fn handoff_rejects_invalid_schema_version() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.schema_version = "wrong".to_string();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn handoff_rejects_empty_from_owner() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.from_owner = String::new();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn handoff_rejects_empty_to_owner() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.to_owner = "  ".to_string();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn handoff_rejects_same_from_and_to_owner() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.from_owner = "SameAgent".to_string();
    handoff.to_owner = "SameAgent".to_string();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::HandoffOwnersMustDiffer
    ));
}

#[test]
fn handoff_rejects_empty_changed_beads() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.changed_beads = Vec::new();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn handoff_rejects_empty_artifact_links() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.artifact_links = Vec::new();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn handoff_rejects_empty_next_steps() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    handoff.next_steps = Vec::new();
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::EmptyField { .. }
    ));
}

#[test]
fn handoff_rejects_duplicate_changed_beads() {
    let protocol = default_rgc_execution_wave_protocol();
    let mut handoff = default_wave_handoff_package();
    let dup = handoff.changed_beads[0].clone();
    handoff.changed_beads.push(dup);
    let err = validate_wave_handoff_package(&protocol, &handoff).expect_err("should reject");
    assert!(matches!(
        err,
        CoordinationValidationError::DuplicateHandoffFieldValue { .. }
    ));
}

#[test]
fn dry_run_healthy_at_zero_idle() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let report =
        run_coordination_dry_run(&protocol, &handoff, 0, "t1", "d1").expect("should succeed");
    assert_eq!(report.action, AntiStallAction::Healthy);
    assert!(!report.events.is_empty());
}

#[test]
fn dry_run_rejects_invalid_protocol() {
    let mut protocol = default_rgc_execution_wave_protocol();
    protocol.schema_version = "bad".to_string();
    let handoff = default_wave_handoff_package();
    let err =
        run_coordination_dry_run(&protocol, &handoff, 0, "t1", "d1").expect_err("should fail");
    assert!(matches!(
        err,
        CoordinationValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn dry_run_events_have_consistent_schema_version() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &handoff, 100, "t-schema", "d-schema")
        .expect("should succeed");
    for event in &report.events {
        assert_eq!(event.schema_version, RGC_COORDINATION_EVENT_SCHEMA_VERSION);
    }
}

#[test]
fn dry_run_events_propagate_trace_and_decision_ids() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let report = run_coordination_dry_run(&protocol, &handoff, 50, "my-trace", "my-decision")
        .expect("should succeed");
    for event in &report.events {
        assert_eq!(event.trace_id, "my-trace");
        assert_eq!(event.decision_id, "my-decision");
    }
}

#[test]
fn protocol_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let json = serde_json::to_string(&protocol).expect("serialize");
    let recovered: ExecutionWaveProtocol = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(protocol, recovered);
}

#[test]
fn wave_plan_entry_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let entry = &protocol.waves[0];
    let json = serde_json::to_string(entry).expect("serialize");
    let recovered: WavePlanEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*entry, recovered);
}

#[test]
fn file_reservation_protocol_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let json = serde_json::to_string(&protocol.file_reservation).expect("serialize");
    let recovered: FileReservationProtocol = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(protocol.file_reservation, recovered);
}

#[test]
fn agent_mail_protocol_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let json = serde_json::to_string(&protocol.agent_mail).expect("serialize");
    let recovered: AgentMailProtocol = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(protocol.agent_mail, recovered);
}

#[test]
fn anti_stall_thresholds_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let json = serde_json::to_string(&protocol.anti_stall).expect("serialize");
    let recovered: AntiStallThresholds = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(protocol.anti_stall, recovered);
}

#[test]
fn coordination_event_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let report =
        run_coordination_dry_run(&protocol, &handoff, 0, "t1", "d1").expect("should succeed");
    for event in &report.events {
        let json = serde_json::to_string(event).expect("serialize");
        let recovered: CoordinationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, recovered);
    }
}

#[test]
fn dry_run_report_serde_round_trip() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let report =
        run_coordination_dry_run(&protocol, &handoff, 1000, "t1", "d1").expect("should succeed");
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: CoordinationDryRunReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, recovered);
}

#[test]
fn coordination_validation_error_all_variants_display() {
    let errors: Vec<CoordinationValidationError> = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "f".to_string(),
            expected: "e".to_string(),
            actual: "a".to_string(),
        },
        CoordinationValidationError::EmptyField {
            field: "f".to_string(),
        },
        CoordinationValidationError::DuplicateWaveEntry {
            wave: "w".to_string(),
        },
        CoordinationValidationError::MissingWaveEntry {
            wave: "w".to_string(),
        },
        CoordinationValidationError::DuplicateBeadOwnership {
            bead_id: "b".to_string(),
        },
        CoordinationValidationError::InvalidPredecessor {
            wave: "w".to_string(),
            predecessor: "p".to_string(),
        },
        CoordinationValidationError::InvalidThresholdOrder,
        CoordinationValidationError::InvalidMailPolicy,
        CoordinationValidationError::InvalidReservationPolicy,
        CoordinationValidationError::UnknownWaveForHandoff {
            wave: "w".to_string(),
        },
        CoordinationValidationError::MissingWaveEntryForHandoffSource {
            wave: "w".to_string(),
        },
        CoordinationValidationError::DuplicateHandoffFieldValue {
            field: "f".to_string(),
            value: "v".to_string(),
        },
        CoordinationValidationError::ChangedBeadOutsideSourceWave {
            bead_id: "b".to_string(),
            source_wave: "w".to_string(),
        },
        CoordinationValidationError::MissingRequiredArtifactLink {
            required_suffix: "s".to_string(),
        },
        CoordinationValidationError::MissingTargetWaveNextStep {
            wave: "w".to_string(),
        },
        CoordinationValidationError::HandoffOwnersMustDiffer,
    ];
    for err in &errors {
        assert!(!err.to_string().is_empty(), "empty display for {err:?}");
    }
}

#[test]
fn coordination_validation_error_is_std_error() {
    let err = CoordinationValidationError::InvalidThresholdOrder;
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn coordination_validation_error_serde_round_trip_all_variants() {
    let errors: Vec<CoordinationValidationError> = vec![
        CoordinationValidationError::InvalidSchemaVersion {
            field: "schema".to_string(),
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CoordinationValidationError::EmptyField {
            field: "policy_id".to_string(),
        },
        CoordinationValidationError::DuplicateWaveEntry {
            wave: "wave_0".to_string(),
        },
        CoordinationValidationError::InvalidThresholdOrder,
        CoordinationValidationError::InvalidMailPolicy,
        CoordinationValidationError::InvalidReservationPolicy,
        CoordinationValidationError::HandoffOwnersMustDiffer,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: CoordinationValidationError =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

#[test]
fn default_protocol_determinism() {
    let p1 = default_rgc_execution_wave_protocol();
    let p2 = default_rgc_execution_wave_protocol();
    assert_eq!(p1, p2);
}

#[test]
fn default_handoff_determinism() {
    let h1 = default_wave_handoff_package();
    let h2 = default_wave_handoff_package();
    assert_eq!(h1, h2);
}

#[test]
fn dry_run_determinism() {
    let protocol = default_rgc_execution_wave_protocol();
    let handoff = default_wave_handoff_package();
    let r1 = run_coordination_dry_run(&protocol, &handoff, 500, "t1", "d1").expect("ok");
    let r2 = run_coordination_dry_run(&protocol, &handoff, 500, "t1", "d1").expect("ok");
    assert_eq!(r1, r2);
}

#[test]
fn protocol_wave_entries_have_non_empty_criteria() {
    let protocol = default_rgc_execution_wave_protocol();
    for entry in &protocol.waves {
        assert!(
            !entry.entry_criteria.is_empty(),
            "empty entry_criteria for {:?}",
            entry.wave
        );
        assert!(
            !entry.exit_criteria.is_empty(),
            "empty exit_criteria for {:?}",
            entry.wave
        );
    }
}

#[test]
fn default_handoff_has_valid_artifact_triad() {
    let handoff = default_wave_handoff_package();
    let suffixes = ["run_manifest.json", "events.jsonl", "commands.txt"];
    for suffix in &suffixes {
        assert!(
            handoff.artifact_links.iter().any(|l| l.ends_with(suffix)),
            "missing artifact suffix: {suffix}"
        );
    }
}
