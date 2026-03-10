//! Integration tests for the `fork_detection` module.
//!
//! Covers: ForkError Display for all 5 variants, ForkEventType Display for all 6
//! variants, SafeModeStartupSource Display, SafeModeState Default, SafeModeRestrictions
//! via artifact, ForkDetector lifecycle (multi-zone, multi-fork, acknowledgment,
//! exit, enforcement), history trimming, checkpoint duplication, import/export
//! persistence, evaluate_safe_mode_startup (CLI flag, env flags, env parsing,
//! normal mode, missing metadata), evaluate_safe_mode_exit (blocked, clear,
//! partial), serde round-trips for all public types.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::fork_detection::{
    CheckpointHistoryEntry, ForkDetector, ForkError, ForkEvent, ForkEventType, ForkIncidentReport,
    RecordCheckpointInput, SAFE_MODE_ENV_FLAGS, SafeModeExitCheckArtifact, SafeModeExitCheckInput,
    SafeModeStartupArtifact, SafeModeStartupError, SafeModeStartupInput, SafeModeStartupSource,
    SafeModeState, evaluate_safe_mode_exit, evaluate_safe_mode_startup,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::{
    CheckpointBuilder, DeterministicTimestamp, PolicyCheckpoint, PolicyHead, PolicyType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn policy_head(version: u64) -> PolicyHead {
    PolicyHead {
        policy_type: PolicyType::RuntimeExecution,
        policy_hash: ContentHash::compute(format!("rt-v{version}").as_bytes()),
        policy_version: version,
    }
}

fn genesis(zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
        .add_policy_head(policy_head(1))
        .build(&[sk(1)])
        .unwrap()
}

fn after(prev: &PolicyCheckpoint, seq: u64, tick: u64, zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::after(
        prev,
        seq,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(tick),
        zone,
    )
    .add_policy_head(policy_head(seq + 1))
    .build(&[sk(1)])
    .unwrap()
}

fn divergent(prev: &PolicyCheckpoint, seq: u64, tick: u64, zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::after(
        prev,
        seq,
        SecurityEpoch::GENESIS,
        DeterministicTimestamp(tick),
        zone,
    )
    .add_policy_head(policy_head(seq + 1000))
    .build(&[sk(1)])
    .unwrap()
}

fn record(
    detector: &mut ForkDetector,
    zone: &str,
    cp: &PolicyCheckpoint,
    accepted: bool,
    frontier_seq: u64,
    tick: u64,
    trace: &str,
) -> Result<(), Box<ForkIncidentReport>> {
    detector.record_checkpoint(&RecordCheckpointInput {
        zone,
        checkpoint: cp,
        accepted,
        frontier_seq,
        frontier_epoch: SecurityEpoch::GENESIS,
        tick,
        trace_id: trace,
    })
}

/// Set up a detector with a fork already triggered in the given zone.
/// Returns (detector, incident_report).
fn detector_with_fork(zone: &str) -> (ForkDetector, Box<ForkIncidentReport>) {
    let g = genesis(zone);
    let cp_a = after(&g, 1, 200, zone);
    let cp_b = divergent(&g, 1, 250, zone);
    let mut d = ForkDetector::with_defaults();
    record(&mut d, zone, &g, true, 0, 100, "t0").unwrap();
    record(&mut d, zone, &cp_a, true, 1, 200, "t1").unwrap();
    let report = record(&mut d, zone, &cp_b, false, 1, 250, "t-fork").unwrap_err();
    (d, report)
}

// ---------------------------------------------------------------------------
// ForkError Display — all 5 variants
// ---------------------------------------------------------------------------

#[test]
fn fork_error_display_fork_detected() {
    let e = ForkError::ForkDetected {
        checkpoint_seq: 7,
        existing_id: EngineObjectId([0xAA; 32]),
        divergent_id: EngineObjectId([0xBB; 32]),
    };
    let s = e.to_string();
    assert!(s.contains("fork detected"));
    assert!(s.contains("seq=7"));
}

#[test]
fn fork_error_display_safe_mode_active() {
    let e = ForkError::SafeModeActive {
        incident_seq: 3,
        reason: "zone locked".into(),
    };
    let s = e.to_string();
    assert!(s.contains("safe mode active"));
    assert!(s.contains("seq=3"));
    assert!(s.contains("zone locked"));
}

#[test]
fn fork_error_display_acknowledgment_required() {
    let e = ForkError::AcknowledgmentRequired { incident_count: 5 };
    assert!(e.to_string().contains("5 fork incident(s)"));
}

#[test]
fn fork_error_display_invalid_resolution() {
    let e = ForkError::InvalidResolution {
        fork_seq: 10,
        resolution_seq: 5,
    };
    let s = e.to_string();
    assert!(s.contains("fork at seq=10"));
    assert!(s.contains("resolution at seq=5"));
}

#[test]
fn fork_error_display_persistence_failed() {
    let e = ForkError::PersistenceFailed {
        detail: "io error".into(),
    };
    assert!(e.to_string().contains("persistence failed: io error"));
}

// ---------------------------------------------------------------------------
// ForkEventType Display — all 6 variants
// ---------------------------------------------------------------------------

#[test]
fn fork_event_type_display_fork_detected() {
    let et = ForkEventType::ForkDetected {
        zone: "z".into(),
        checkpoint_seq: 3,
    };
    assert_eq!(et.to_string(), "fork_detected(z, seq=3)");
}

#[test]
fn fork_event_type_display_safe_mode_entered() {
    let et = ForkEventType::SafeModeEntered {
        zone: "z".into(),
        trigger_seq: 5,
    };
    assert_eq!(et.to_string(), "safe_mode_entered(z, trigger_seq=5)");
}

#[test]
fn fork_event_type_display_safe_mode_exited() {
    let et = ForkEventType::SafeModeExited {
        zone: "z".into(),
        acknowledged_incidents: 2,
    };
    assert_eq!(et.to_string(), "safe_mode_exited(z, acked=2)");
}

#[test]
fn fork_event_type_display_checkpoint_recorded() {
    let et = ForkEventType::CheckpointRecorded {
        zone: "z".into(),
        checkpoint_seq: 9,
    };
    assert_eq!(et.to_string(), "checkpoint_recorded(z, seq=9)");
}

#[test]
fn fork_event_type_display_operation_denied() {
    let et = ForkEventType::OperationDenied {
        zone: "z".into(),
        operation: "promote".into(),
    };
    assert_eq!(et.to_string(), "operation_denied(z, op=promote)");
}

#[test]
fn fork_event_type_display_history_trimmed() {
    let et = ForkEventType::HistoryTrimmed {
        zone: "z".into(),
        removed_count: 4,
    };
    assert_eq!(et.to_string(), "history_trimmed(z, removed=4)");
}

// ---------------------------------------------------------------------------
// SafeModeStartupSource Display
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_startup_source_display() {
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

// ---------------------------------------------------------------------------
// SafeModeState Default
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_state_default_is_inactive() {
    let d = SafeModeState::default();
    assert!(!d.active);
    assert_eq!(d.trigger_seq, None);
    assert_eq!(d.unacknowledged_count, 0);
}

// ---------------------------------------------------------------------------
// SafeModeStartupError Display
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_startup_error_display_missing_field() {
    let e = SafeModeStartupError::MissingField {
        field: "trace_id".into(),
    };
    assert!(e.to_string().contains("missing required field: trace_id"));
}

// ---------------------------------------------------------------------------
// SAFE_MODE_ENV_FLAGS constant
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_env_flags_values() {
    assert_eq!(SAFE_MODE_ENV_FLAGS.len(), 2);
    assert!(SAFE_MODE_ENV_FLAGS.contains(&"FRANKEN_SAFE_MODE"));
    assert!(SAFE_MODE_ENV_FLAGS.contains(&"FRANKENENGINE_SAFE_MODE"));
}

// ---------------------------------------------------------------------------
// ForkDetector — basic lifecycle
// ---------------------------------------------------------------------------

#[test]
fn new_detector_has_no_zones() {
    let d = ForkDetector::new(100);
    assert!(d.zones().is_empty());
    assert_eq!(d.history_size("nonexistent"), 0);
    assert!(!d.is_safe_mode("nonexistent"));
    assert!(d.safe_mode_state("nonexistent").is_none());
    assert!(d.incidents("nonexistent").is_empty());
    assert!(d.unacknowledged_incidents("nonexistent").is_empty());
}

#[test]
fn with_defaults_creates_detector() {
    let d = ForkDetector::with_defaults();
    assert!(d.zones().is_empty());
}

#[test]
fn record_checkpoint_creates_zone() {
    let g = genesis("zone-1");
    let mut d = ForkDetector::new(100);
    record(&mut d, "zone-1", &g, true, 0, 100, "t0").unwrap();
    assert_eq!(d.zones().len(), 1);
    assert!(d.zones().contains(&"zone-1"));
    assert_eq!(d.history_size("zone-1"), 1);
}

#[test]
fn duplicate_checkpoint_does_not_increase_history() {
    let g = genesis("zone-1");
    let mut d = ForkDetector::new(100);
    record(&mut d, "zone-1", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-1", &g, false, 0, 200, "t1").unwrap();
    assert_eq!(d.history_size("zone-1"), 1);
}

#[test]
fn history_accessible_via_public_api() {
    let g = genesis("zone-1");
    let cp1 = after(&g, 1, 200, "zone-1");
    let mut d = ForkDetector::new(100);
    record(&mut d, "zone-1", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-1", &cp1, true, 1, 200, "t1").unwrap();

    let history = d.history("zone-1").expect("zone exists");
    assert_eq!(history.len(), 2);
    let entry0 = history.get(&g.checkpoint_seq).unwrap();
    assert_eq!(entry0.checkpoint_id, g.checkpoint_id);
    assert!(entry0.accepted);
}

// ---------------------------------------------------------------------------
// Fork detection and safe mode entry
// ---------------------------------------------------------------------------

#[test]
fn fork_detected_enters_safe_mode() {
    let (d, report) = detector_with_fork("zone-a");
    assert!(d.is_safe_mode("zone-a"));
    let sm = d.safe_mode_state("zone-a").unwrap();
    assert!(sm.active);
    assert_eq!(sm.trigger_seq, Some(1));
    assert_eq!(sm.unacknowledged_count, 1);
    assert_eq!(report.fork_seq, 1);
    assert!(!report.acknowledged);
    assert!(report.existing_was_accepted);
    assert_eq!(report.zone, "zone-a");
}

#[test]
fn fork_report_contains_correct_checkpoint_ids() {
    let g = genesis("zone-a");
    let cp_a = after(&g, 1, 200, "zone-a");
    let cp_b = divergent(&g, 1, 250, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp_a, true, 1, 200, "t1").unwrap();
    let report = record(&mut d, "zone-a", &cp_b, false, 1, 250, "t-f").unwrap_err();
    assert_eq!(report.existing_checkpoint_id, cp_a.checkpoint_id);
    assert_eq!(report.divergent_checkpoint_id, cp_b.checkpoint_id);
}

#[test]
fn fork_report_captures_frontier_state() {
    let g = genesis("zone-a");
    let cp_a = after(&g, 1, 200, "zone-a");
    let cp_b = divergent(&g, 1, 300, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp_a, true, 1, 200, "t1").unwrap();
    let report = record(&mut d, "zone-a", &cp_b, false, 1, 300, "t-f").unwrap_err();
    assert_eq!(report.frontier_seq_at_detection, 1);
    assert_eq!(report.detected_at_tick, 300);
    assert_eq!(report.frontier_epoch_at_detection, SecurityEpoch::GENESIS);
}

// ---------------------------------------------------------------------------
// Multiple forks in the same zone
// ---------------------------------------------------------------------------

#[test]
fn multiple_forks_accumulate_incidents() {
    let g = genesis("zone-a");
    let cp1a = after(&g, 1, 200, "zone-a");
    let cp1b = divergent(&g, 1, 250, "zone-a");
    let cp2a = after(&cp1a, 2, 300, "zone-a");
    let cp2b = divergent(&cp1a, 2, 350, "zone-a");

    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1a, true, 1, 200, "t1").unwrap();
    let _ = record(&mut d, "zone-a", &cp1b, false, 1, 250, "t-f1");
    record(&mut d, "zone-a", &cp2a, true, 2, 300, "t2").unwrap();
    let _ = record(&mut d, "zone-a", &cp2b, false, 2, 350, "t-f2");

    assert_eq!(d.incidents("zone-a").len(), 2);
    assert_eq!(d.unacknowledged_incidents("zone-a").len(), 2);
    let sm = d.safe_mode_state("zone-a").unwrap();
    assert_eq!(sm.unacknowledged_count, 2);
}

// ---------------------------------------------------------------------------
// Safe mode enforcement
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_denies_operations() {
    let (mut d, _) = detector_with_fork("zone-a");
    let err = d
        .enforce_safe_mode("zone-a", "promote_extension", "t-deny")
        .unwrap_err();
    assert!(matches!(err, ForkError::SafeModeActive { .. }));
}

#[test]
fn non_safe_mode_zone_allows_operations() {
    let mut d = ForkDetector::with_defaults();
    d.enforce_safe_mode("zone-clean", "promote_extension", "t-ok")
        .unwrap();
}

#[test]
fn safe_mode_in_one_zone_does_not_block_other_zones() {
    let (mut d, _) = detector_with_fork("zone-a");

    // Record something in zone-b (no fork).
    let g_b = genesis("zone-b");
    record(&mut d, "zone-b", &g_b, true, 0, 100, "t-b0").unwrap();

    d.enforce_safe_mode("zone-b", "grant", "t-b-ok").unwrap();
    assert!(!d.is_safe_mode("zone-b"));
}

// ---------------------------------------------------------------------------
// Acknowledgment and safe-mode exit
// ---------------------------------------------------------------------------

#[test]
fn acknowledge_incident_returns_true() {
    let (mut d, report) = detector_with_fork("zone-a");
    assert!(d.acknowledge_incident("zone-a", &report.incident_id));
}

#[test]
fn acknowledge_nonexistent_incident_returns_false() {
    let (mut d, _) = detector_with_fork("zone-a");
    assert!(!d.acknowledge_incident("zone-a", "does-not-exist"));
}

#[test]
fn acknowledge_nonexistent_zone_returns_false() {
    let d = ForkDetector::with_defaults();
    // ForkDetector requires &mut for acknowledge_incident
    let mut d = d;
    assert!(!d.acknowledge_incident("no-such-zone", "id"));
}

#[test]
fn double_acknowledge_same_incident_returns_false() {
    let (mut d, report) = detector_with_fork("zone-a");
    assert!(d.acknowledge_incident("zone-a", &report.incident_id));
    assert!(!d.acknowledge_incident("zone-a", &report.incident_id));
}

#[test]
fn exit_safe_mode_requires_all_incidents_acknowledged() {
    let (mut d, _) = detector_with_fork("zone-a");
    let err = d.exit_safe_mode("zone-a", "t-exit").unwrap_err();
    assert!(matches!(
        err,
        ForkError::AcknowledgmentRequired { incident_count: 1 }
    ));
    assert!(d.is_safe_mode("zone-a"));
}

#[test]
fn exit_safe_mode_succeeds_after_acknowledgment() {
    let (mut d, report) = detector_with_fork("zone-a");
    d.acknowledge_incident("zone-a", &report.incident_id);
    let acked = d.exit_safe_mode("zone-a", "t-exit").unwrap();
    assert_eq!(acked, 1);
    assert!(!d.is_safe_mode("zone-a"));
}

#[test]
fn exit_safe_mode_on_non_safe_mode_zone_returns_zero() {
    let mut d = ForkDetector::with_defaults();
    let g = genesis("zone-a");
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    let result = d.exit_safe_mode("zone-a", "t-exit").unwrap();
    assert_eq!(result, 0);
}

#[test]
fn exit_safe_mode_on_nonexistent_zone_returns_zero() {
    let mut d = ForkDetector::with_defaults();
    let result = d.exit_safe_mode("ghost", "t-exit").unwrap();
    assert_eq!(result, 0);
}

#[test]
fn operations_allowed_after_safe_mode_exit() {
    let (mut d, report) = detector_with_fork("zone-a");
    d.acknowledge_incident("zone-a", &report.incident_id);
    d.exit_safe_mode("zone-a", "t-exit").unwrap();
    d.enforce_safe_mode("zone-a", "promote", "t-ok").unwrap();
}

#[test]
fn exit_safe_mode_with_multiple_forks_needs_all_acknowledged() {
    let g = genesis("zone-a");
    let cp1a = after(&g, 1, 200, "zone-a");
    let cp1b = divergent(&g, 1, 250, "zone-a");
    let cp2a = after(&cp1a, 2, 300, "zone-a");
    let cp2b = divergent(&cp1a, 2, 350, "zone-a");

    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1a, true, 1, 200, "t1").unwrap();
    let r1 = record(&mut d, "zone-a", &cp1b, false, 1, 250, "t-f1").unwrap_err();
    record(&mut d, "zone-a", &cp2a, true, 2, 300, "t2").unwrap();
    let r2 = record(&mut d, "zone-a", &cp2b, false, 2, 350, "t-f2").unwrap_err();

    // Acknowledge only first — exit should fail.
    d.acknowledge_incident("zone-a", &r1.incident_id);
    let err = d.exit_safe_mode("zone-a", "t-exit").unwrap_err();
    assert!(matches!(
        err,
        ForkError::AcknowledgmentRequired { incident_count: 1 }
    ));

    // Acknowledge second — exit should succeed.
    d.acknowledge_incident("zone-a", &r2.incident_id);
    let acked = d.exit_safe_mode("zone-a", "t-exit").unwrap();
    assert_eq!(acked, 2);
    assert!(!d.is_safe_mode("zone-a"));
}

// ---------------------------------------------------------------------------
// History trimming
// ---------------------------------------------------------------------------

#[test]
fn history_trimmed_to_max_window() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::new(3);
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();

    let mut prev = g;
    for i in 1..=10u64 {
        let cp = after(&prev, i, 100 + i * 100, "zone-a");
        record(
            &mut d,
            "zone-a",
            &cp,
            true,
            i,
            100 + i * 100,
            &format!("t{i}"),
        )
        .unwrap();
        prev = cp;
    }

    assert!(d.history_size("zone-a") <= 3);

    // Oldest entries should have been removed; newest should remain.
    let history = d.history("zone-a").unwrap();
    let max_seq = *history.keys().max().unwrap();
    assert_eq!(max_seq, 10);
}

#[test]
fn history_trim_events_emitted() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::new(2);
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();

    let cp1 = after(&g, 1, 200, "zone-a");
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();

    let cp2 = after(&cp1, 2, 300, "zone-a");
    record(&mut d, "zone-a", &cp2, true, 2, 300, "t2").unwrap();

    let counts = d.event_counts();
    assert!(counts.get("history_trimmed").copied().unwrap_or(0) > 0);
}

// ---------------------------------------------------------------------------
// Events — drain and counts
// ---------------------------------------------------------------------------

#[test]
fn drain_events_returns_and_clears() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();

    let events = d.drain_events();
    assert!(!events.is_empty());
    let events2 = d.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn event_counts_reflect_fork_lifecycle() {
    let (mut d, report) = detector_with_fork("zone-a");

    // Deny an operation.
    let _ = d.enforce_safe_mode("zone-a", "grant", "t-deny");

    let counts = d.event_counts();
    assert_eq!(counts["checkpoint_recorded"], 2); // genesis + cp1a
    assert_eq!(counts["fork_detected"], 1);
    assert_eq!(counts["safe_mode_entered"], 1);
    assert_eq!(counts["operation_denied"], 1);

    // Acknowledge + exit
    d.acknowledge_incident("zone-a", &report.incident_id);
    d.exit_safe_mode("zone-a", "t-exit").unwrap();

    let counts = d.event_counts();
    assert_eq!(counts["safe_mode_exited"], 1);
}

#[test]
fn events_carry_trace_ids() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "my-trace").unwrap();

    let events = d.drain_events();
    assert!(events.iter().all(|e| e.trace_id == "my-trace"));
}

// ---------------------------------------------------------------------------
// Multi-zone scenarios
// ---------------------------------------------------------------------------

#[test]
fn multiple_zones_tracked_independently() {
    let g_a = genesis("zone-a");
    let g_b = genesis("zone-b");
    let g_c = genesis("zone-c");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g_a, true, 0, 100, "t-a").unwrap();
    record(&mut d, "zone-b", &g_b, true, 0, 100, "t-b").unwrap();
    record(&mut d, "zone-c", &g_c, true, 0, 100, "t-c").unwrap();

    let mut zones = d.zones();
    zones.sort();
    assert_eq!(zones, vec!["zone-a", "zone-b", "zone-c"]);
}

// ---------------------------------------------------------------------------
// Export / import state persistence
// ---------------------------------------------------------------------------

#[test]
fn export_import_preserves_history() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();

    let exported = d.export_state().clone();
    let mut d2 = ForkDetector::new(50);
    d2.import_state(exported);

    assert_eq!(d2.history_size("zone-a"), 2);
    assert!(d2.zones().contains(&"zone-a"));
}

#[test]
fn export_import_preserves_safe_mode() {
    let (d, _) = detector_with_fork("zone-a");
    assert!(d.is_safe_mode("zone-a"));

    let exported = d.export_state().clone();
    let mut d2 = ForkDetector::with_defaults();
    d2.import_state(exported);

    assert!(d2.is_safe_mode("zone-a"));
    assert_eq!(d2.incidents("zone-a").len(), 1);
    let sm = d2.safe_mode_state("zone-a").unwrap();
    assert!(sm.active);
}

#[test]
fn import_replaces_all_state() {
    let g = genesis("zone-old");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-old", &g, true, 0, 100, "t0").unwrap();
    assert!(d.zones().contains(&"zone-old"));

    // Import state from another detector that has zone-new.
    let g2 = genesis("zone-new");
    let mut d2 = ForkDetector::with_defaults();
    record(&mut d2, "zone-new", &g2, true, 0, 100, "t0").unwrap();
    let exported = d2.export_state().clone();

    d.import_state(exported);
    assert!(!d.zones().contains(&"zone-old"));
    assert!(d.zones().contains(&"zone-new"));
}

// ---------------------------------------------------------------------------
// evaluate_safe_mode_startup
// ---------------------------------------------------------------------------

fn startup_input(cli_safe_mode: bool, env: Vec<(&str, &str)>) -> SafeModeStartupInput {
    let environment: BTreeMap<String, String> = env
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    SafeModeStartupInput {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        cli_safe_mode,
        environment,
    }
}

#[test]
fn startup_normal_mode() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![])).unwrap();
    assert!(!art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::NotRequested);
    assert!(!art.restrictions.all_extensions_sandboxed);
    assert!(!art.restrictions.auto_promotion_disabled);
    assert!(art.restricted_features.is_empty());
    assert!(art.evidence_preserved);
    assert!(art.logs_preserved);
    assert!(art.state_preserved);
}

#[test]
fn startup_cli_flag_activates_safe_mode() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    assert!(art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::CliFlag);
    assert!(art.restrictions.all_extensions_sandboxed);
    assert!(art.restrictions.auto_promotion_disabled);
    assert!(art.restrictions.conservative_policy_defaults);
    assert!(art.restrictions.enhanced_telemetry);
    assert!(art.restrictions.adaptive_tuning_disabled);
    assert!(!art.restricted_features.is_empty());
    assert!(!art.exit_procedure.is_empty());
}

#[test]
fn startup_env_flag_franken_safe_mode() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![("FRANKEN_SAFE_MODE", "1")]))
        .unwrap();
    assert!(art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::EnvironmentVariable);
}

#[test]
fn startup_env_flag_frankenengine_safe_mode() {
    let art = evaluate_safe_mode_startup(&startup_input(
        false,
        vec![("FRANKENENGINE_SAFE_MODE", "true")],
    ))
    .unwrap();
    assert!(art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::EnvironmentVariable);
}

#[test]
fn startup_env_flag_case_insensitive_values() {
    for val in &["1", "true", "True", "TRUE", "yes", "Yes", "on", "ON"] {
        let art =
            evaluate_safe_mode_startup(&startup_input(false, vec![("FRANKEN_SAFE_MODE", val)]))
                .unwrap();
        assert!(art.safe_mode_active, "expected safe mode for value '{val}'");
    }
}

#[test]
fn startup_env_flag_disabled_values_do_not_activate() {
    for val in &["0", "false", "no", "off", ""] {
        let art =
            evaluate_safe_mode_startup(&startup_input(false, vec![("FRANKEN_SAFE_MODE", val)]))
                .unwrap();
        assert!(
            !art.safe_mode_active,
            "expected normal mode for value '{val}'"
        );
    }
}

#[test]
fn startup_cli_takes_precedence_over_env() {
    // CLI flag is checked first, so source should be CliFlag.
    let art =
        evaluate_safe_mode_startup(&startup_input(true, vec![("FRANKEN_SAFE_MODE", "1")])).unwrap();
    assert!(art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::CliFlag);
}

#[test]
fn startup_events_have_stable_fields() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    for event in &art.events {
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.decision_id, "dec-1");
        assert_eq!(event.policy_id, "pol-1");
        assert_eq!(event.component, "safe_mode_startup");
        assert!(!event.event.is_empty());
        assert!(!event.outcome.is_empty());
    }
}

#[test]
fn startup_is_deterministic() {
    let input = startup_input(true, vec![("FRANKEN_SAFE_MODE", "1")]);
    let a = evaluate_safe_mode_startup(&input).unwrap();
    let b = evaluate_safe_mode_startup(&input).unwrap();
    assert_eq!(a, b);
}

#[test]
fn startup_rejects_empty_trace_id() {
    let mut input = startup_input(false, vec![]);
    input.trace_id = "".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "trace_id"
    ));
}

#[test]
fn startup_rejects_empty_decision_id() {
    let mut input = startup_input(false, vec![]);
    input.decision_id = "".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "decision_id"
    ));
}

#[test]
fn startup_rejects_empty_policy_id() {
    let mut input = startup_input(false, vec![]);
    input.policy_id = "".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "policy_id"
    ));
}

#[test]
fn startup_rejects_whitespace_only_trace_id() {
    let mut input = startup_input(false, vec![]);
    input.trace_id = "   ".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(err, SafeModeStartupError::MissingField { .. }));
}

// ---------------------------------------------------------------------------
// evaluate_safe_mode_exit
// ---------------------------------------------------------------------------

#[test]
fn exit_check_all_clear() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    assert!(art.can_exit);
    assert!(art.blocking_reasons.is_empty());
    assert_eq!(art.event.outcome, "pass");
    assert!(art.event.error_code.is_none());
}

#[test]
fn exit_check_blocked_by_active_incidents() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 3,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert!(
        art.blocking_reasons
            .iter()
            .any(|r| r.contains("active_incidents_remaining:3"))
    );
}

#[test]
fn exit_check_blocked_by_pending_quarantines() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 2,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert!(
        art.blocking_reasons
            .iter()
            .any(|r| r.contains("pending_quarantines_remaining:2"))
    );
}

#[test]
fn exit_check_blocked_by_unflushed_ledger() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: false,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert!(
        art.blocking_reasons
            .iter()
            .any(|r| r.contains("evidence_ledger_not_flushed"))
    );
}

#[test]
fn exit_check_all_three_blockers() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert_eq!(art.blocking_reasons.len(), 3);
    assert_eq!(
        art.event.error_code.as_deref(),
        Some("FE-SAFE-MODE-EXIT-BLOCKED")
    );
}

#[test]
fn exit_check_rejects_empty_trace_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(err, SafeModeStartupError::MissingField { .. }));
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn fork_error_serde_round_trip_all_variants() {
    let errors = vec![
        ForkError::ForkDetected {
            checkpoint_seq: 5,
            existing_id: EngineObjectId([1; 32]),
            divergent_id: EngineObjectId([2; 32]),
        },
        ForkError::SafeModeActive {
            incident_seq: 5,
            reason: "test".into(),
        },
        ForkError::AcknowledgmentRequired { incident_count: 2 },
        ForkError::InvalidResolution {
            fork_seq: 10,
            resolution_seq: 5,
        },
        ForkError::PersistenceFailed {
            detail: "disk full".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let rt: ForkError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, rt);
    }
}

#[test]
fn fork_incident_report_serde_round_trip() {
    let report = ForkIncidentReport {
        incident_id: "fork-z-seq1-1".into(),
        fork_seq: 1,
        existing_checkpoint_id: EngineObjectId([0xAA; 32]),
        divergent_checkpoint_id: EngineObjectId([0xBB; 32]),
        existing_epoch: SecurityEpoch::GENESIS,
        divergent_epoch: SecurityEpoch::from_raw(5),
        zone: "zone-a".into(),
        frontier_seq_at_detection: 1,
        frontier_epoch_at_detection: SecurityEpoch::GENESIS,
        detected_at_tick: 250,
        trace_id: "trace-fork".into(),
        existing_was_accepted: true,
        acknowledged: false,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let rt: ForkIncidentReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, rt);
}

#[test]
fn checkpoint_history_entry_serde_round_trip() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: 42,
        checkpoint_id: EngineObjectId([0xCC; 32]),
        epoch: SecurityEpoch::from_raw(3),
        accepted: true,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let rt: CheckpointHistoryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, rt);
}

#[test]
fn safe_mode_state_serde_round_trip() {
    for state in [
        SafeModeState::default(),
        SafeModeState {
            active: true,
            trigger_seq: Some(5),
            unacknowledged_count: 2,
        },
    ] {
        let json = serde_json::to_string(&state).expect("serialize");
        let rt: SafeModeState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(state, rt);
    }
}

#[test]
fn safe_mode_startup_source_serde_round_trip() {
    for source in [
        SafeModeStartupSource::NotRequested,
        SafeModeStartupSource::CliFlag,
        SafeModeStartupSource::EnvironmentVariable,
    ] {
        let json = serde_json::to_string(&source).expect("serialize");
        let rt: SafeModeStartupSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(source, rt);
    }
}

#[test]
fn fork_event_serde_round_trip_all_variants() {
    let events = vec![
        ForkEvent {
            event_type: ForkEventType::ForkDetected {
                zone: "z".into(),
                checkpoint_seq: 1,
            },
            trace_id: "t".into(),
        },
        ForkEvent {
            event_type: ForkEventType::SafeModeEntered {
                zone: "z".into(),
                trigger_seq: 2,
            },
            trace_id: "t".into(),
        },
        ForkEvent {
            event_type: ForkEventType::SafeModeExited {
                zone: "z".into(),
                acknowledged_incidents: 3,
            },
            trace_id: "t".into(),
        },
        ForkEvent {
            event_type: ForkEventType::CheckpointRecorded {
                zone: "z".into(),
                checkpoint_seq: 4,
            },
            trace_id: "t".into(),
        },
        ForkEvent {
            event_type: ForkEventType::OperationDenied {
                zone: "z".into(),
                operation: "op".into(),
            },
            trace_id: "t".into(),
        },
        ForkEvent {
            event_type: ForkEventType::HistoryTrimmed {
                zone: "z".into(),
                removed_count: 5,
            },
            trace_id: "t".into(),
        },
    ];
    for event in &events {
        let json = serde_json::to_string(event).expect("serialize");
        let rt: ForkEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, rt);
    }
}

#[test]
fn safe_mode_startup_artifact_serde_round_trip() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    let json = serde_json::to_string(&art).expect("serialize");
    let rt: SafeModeStartupArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(art, rt);
}

#[test]
fn safe_mode_exit_check_artifact_serde_round_trip() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    let json = serde_json::to_string(&art).expect("serialize");
    let rt: SafeModeExitCheckArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(art, rt);
}

#[test]
fn safe_mode_startup_error_serde_round_trip() {
    let err = SafeModeStartupError::MissingField {
        field: "trace_id".into(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let rt: SafeModeStartupError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, rt);
}
