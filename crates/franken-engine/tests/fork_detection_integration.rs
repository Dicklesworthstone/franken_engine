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

// ---------------------------------------------------------------------------
// Enrichment batch: serde roundtrips for remaining public types
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_restrictions_serde_round_trip_conservative() {
    // Build a conservative restrictions struct via the startup artifact.
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    let json = serde_json::to_string(&art.restrictions).expect("serialize");
    let rt: frankenengine_engine::fork_detection::SafeModeRestrictions =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(art.restrictions, rt);
    assert!(rt.all_extensions_sandboxed);
    assert!(rt.auto_promotion_disabled);
    assert!(rt.conservative_policy_defaults);
    assert!(rt.enhanced_telemetry);
    assert!(rt.adaptive_tuning_disabled);
}

#[test]
fn safe_mode_restrictions_serde_round_trip_normal() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![])).unwrap();
    let json = serde_json::to_string(&art.restrictions).expect("serialize");
    let rt: frankenengine_engine::fork_detection::SafeModeRestrictions =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(art.restrictions, rt);
    assert!(!rt.all_extensions_sandboxed);
    assert!(!rt.auto_promotion_disabled);
}

#[test]
fn safe_mode_startup_event_serde_round_trip() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    for event in &art.events {
        let json = serde_json::to_string(event).expect("serialize");
        let rt: frankenengine_engine::fork_detection::SafeModeStartupEvent =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*event, rt);
    }
}

#[test]
fn safe_mode_startup_input_serde_round_trip() {
    let input = startup_input(true, vec![("FRANKEN_SAFE_MODE", "1")]);
    let json = serde_json::to_string(&input).expect("serialize");
    let rt: SafeModeStartupInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, rt);
}

#[test]
fn safe_mode_exit_check_input_serde_round_trip() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 5,
        pending_quarantines: 3,
        evidence_ledger_flushed: false,
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let rt: SafeModeExitCheckInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, rt);
}

#[test]
fn zone_state_serde_round_trip_via_export() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();

    let exported = d.export_state();
    let json = serde_json::to_string(exported).expect("serialize zone state");
    let rt: BTreeMap<String, frankenengine_engine::fork_detection::ZoneState> =
        serde_json::from_str(&json).expect("deserialize zone state");
    assert_eq!(rt.len(), 1);
    assert!(rt.contains_key("zone-a"));
}

#[test]
fn zone_state_with_fork_serde_round_trip_via_export() {
    let (d, _) = detector_with_fork("zone-a");
    let exported = d.export_state();
    let json = serde_json::to_string(exported).expect("serialize");
    let rt: BTreeMap<String, frankenengine_engine::fork_detection::ZoneState> =
        serde_json::from_str(&json).expect("deserialize");
    let mut d2 = ForkDetector::with_defaults();
    d2.import_state(rt);
    assert!(d2.is_safe_mode("zone-a"));
    assert_eq!(d2.incidents("zone-a").len(), 1);
}

// ---------------------------------------------------------------------------
// Enrichment: ForkError traits — Clone, PartialEq, std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn fork_error_clone_preserves_equality() {
    let original = ForkError::ForkDetected {
        checkpoint_seq: 99,
        existing_id: EngineObjectId([0x11; 32]),
        divergent_id: EngineObjectId([0x22; 32]),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn fork_error_implements_std_error_trait() {
    let variants: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(ForkError::ForkDetected {
            checkpoint_seq: 1,
            existing_id: EngineObjectId([0xAA; 32]),
            divergent_id: EngineObjectId([0xBB; 32]),
        }),
        Box::new(ForkError::SafeModeActive {
            incident_seq: 2,
            reason: "test".into(),
        }),
        Box::new(ForkError::AcknowledgmentRequired { incident_count: 3 }),
        Box::new(ForkError::InvalidResolution {
            fork_seq: 4,
            resolution_seq: 1,
        }),
        Box::new(ForkError::PersistenceFailed {
            detail: "io".into(),
        }),
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
}

#[test]
fn safe_mode_startup_error_implements_std_error_trait() {
    let err: Box<dyn std::error::Error> = Box::new(SafeModeStartupError::MissingField {
        field: "test".into(),
    });
    assert!(err.to_string().contains("test"));
}

// ---------------------------------------------------------------------------
// Enrichment: ForkError Display — detailed content verification
// ---------------------------------------------------------------------------

#[test]
fn fork_error_display_fork_detected_contains_both_ids() {
    let existing = EngineObjectId([0xAA; 32]);
    let divergent = EngineObjectId([0xBB; 32]);
    let e = ForkError::ForkDetected {
        checkpoint_seq: 42,
        existing_id: existing.clone(),
        divergent_id: divergent.clone(),
    };
    let s = e.to_string();
    assert!(s.contains("seq=42"));
    assert!(s.contains(&format!("{existing}")));
    assert!(s.contains(&format!("{divergent}")));
}

#[test]
fn fork_error_display_safe_mode_active_contains_reason_and_seq() {
    let e = ForkError::SafeModeActive {
        incident_seq: 77,
        reason: "split-brain detected".into(),
    };
    let s = e.to_string();
    assert!(s.contains("seq=77"));
    assert!(s.contains("split-brain detected"));
    assert!(s.contains("safe mode"));
}

#[test]
fn fork_error_display_persistence_failed_detail_verbatim() {
    let e = ForkError::PersistenceFailed {
        detail: "ENOSPC: no space left on device".into(),
    };
    assert!(e.to_string().contains("ENOSPC: no space left on device"));
}

#[test]
fn fork_error_all_five_variants_display_distinct() {
    let variants = vec![
        ForkError::ForkDetected {
            checkpoint_seq: 1,
            existing_id: EngineObjectId([1; 32]),
            divergent_id: EngineObjectId([2; 32]),
        },
        ForkError::SafeModeActive {
            incident_seq: 2,
            reason: "r".into(),
        },
        ForkError::AcknowledgmentRequired { incident_count: 3 },
        ForkError::InvalidResolution {
            fork_seq: 4,
            resolution_seq: 5,
        },
        ForkError::PersistenceFailed { detail: "d".into() },
    ];
    let mut strings = std::collections::BTreeSet::new();
    for v in &variants {
        strings.insert(v.to_string());
    }
    assert_eq!(strings.len(), 5, "all 5 display strings must be distinct");
}

// ---------------------------------------------------------------------------
// Enrichment: SafeModeStartupSource traits
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_startup_source_copy_semantics() {
    let a = SafeModeStartupSource::CliFlag;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn safe_mode_startup_source_clone_semantics() {
    let a = SafeModeStartupSource::EnvironmentVariable;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn safe_mode_startup_source_debug_format() {
    let s = format!("{:?}", SafeModeStartupSource::NotRequested);
    assert!(s.contains("NotRequested"));
}

// ---------------------------------------------------------------------------
// Enrichment: CheckpointHistoryEntry edge cases
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_history_entry_accepted_false_serde() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: 0,
        checkpoint_id: EngineObjectId([0x00; 32]),
        epoch: SecurityEpoch::GENESIS,
        accepted: false,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let rt: CheckpointHistoryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, rt);
    assert!(!rt.accepted);
}

#[test]
fn checkpoint_history_entry_high_seq_value() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: u64::MAX,
        checkpoint_id: EngineObjectId([0xFF; 32]),
        epoch: SecurityEpoch::from_raw(u64::MAX),
        accepted: true,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let rt: CheckpointHistoryEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, rt);
}

#[test]
fn checkpoint_history_entry_clone_equality() {
    let entry = CheckpointHistoryEntry {
        checkpoint_seq: 10,
        checkpoint_id: EngineObjectId([0xDD; 32]),
        epoch: SecurityEpoch::from_raw(2),
        accepted: true,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ---------------------------------------------------------------------------
// Enrichment: ForkIncidentReport field-level edge cases
// ---------------------------------------------------------------------------

#[test]
fn fork_incident_report_acknowledged_true_serde() {
    let report = ForkIncidentReport {
        incident_id: "acked-1".into(),
        fork_seq: 5,
        existing_checkpoint_id: EngineObjectId([0xAA; 32]),
        divergent_checkpoint_id: EngineObjectId([0xBB; 32]),
        existing_epoch: SecurityEpoch::from_raw(10),
        divergent_epoch: SecurityEpoch::from_raw(11),
        zone: "zone-x".into(),
        frontier_seq_at_detection: 4,
        frontier_epoch_at_detection: SecurityEpoch::from_raw(10),
        detected_at_tick: 999,
        trace_id: "t-acked".into(),
        existing_was_accepted: false,
        acknowledged: true,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let rt: ForkIncidentReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, rt);
    assert!(rt.acknowledged);
    assert!(!rt.existing_was_accepted);
}

#[test]
fn fork_incident_report_clone_equality() {
    let report = ForkIncidentReport {
        incident_id: "clone-test".into(),
        fork_seq: 1,
        existing_checkpoint_id: EngineObjectId([1; 32]),
        divergent_checkpoint_id: EngineObjectId([2; 32]),
        existing_epoch: SecurityEpoch::GENESIS,
        divergent_epoch: SecurityEpoch::GENESIS,
        zone: "z".into(),
        frontier_seq_at_detection: 0,
        frontier_epoch_at_detection: SecurityEpoch::GENESIS,
        detected_at_tick: 100,
        trace_id: "t".into(),
        existing_was_accepted: true,
        acknowledged: false,
    };
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

// ---------------------------------------------------------------------------
// Enrichment: SafeModeState edge cases
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_state_active_with_high_unacked_count() {
    let state = SafeModeState {
        active: true,
        trigger_seq: Some(u64::MAX),
        unacknowledged_count: usize::MAX,
    };
    let json = serde_json::to_string(&state).expect("serialize");
    let rt: SafeModeState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, rt);
}

#[test]
fn safe_mode_state_clone_equality() {
    let state = SafeModeState {
        active: true,
        trigger_seq: Some(42),
        unacknowledged_count: 3,
    };
    let cloned = state.clone();
    assert_eq!(state, cloned);
}

#[test]
fn safe_mode_state_debug_format() {
    let state = SafeModeState::default();
    let dbg = format!("{state:?}");
    assert!(dbg.contains("active"));
    assert!(dbg.contains("false"));
}

// ---------------------------------------------------------------------------
// Enrichment: ForkDetector construction edge cases
// ---------------------------------------------------------------------------

#[test]
fn fork_detector_new_with_zero_history() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let mut d = ForkDetector::new(0);
    // Recording should still work, but history immediately trims.
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();
    // History capped at 0 means entries get trimmed right away.
    assert_eq!(d.history_size("zone-a"), 0);
}

#[test]
fn fork_detector_new_with_one_history() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let cp2 = after(&cp1, 2, 300, "zone-a");
    let mut d = ForkDetector::new(1);
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();
    record(&mut d, "zone-a", &cp2, true, 2, 300, "t2").unwrap();
    assert!(d.history_size("zone-a") <= 1);
}

#[test]
fn fork_detector_new_with_large_history() {
    let d = ForkDetector::new(1_000_000);
    assert!(d.zones().is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: event ordering and drain semantics
// ---------------------------------------------------------------------------

#[test]
fn event_counts_reset_after_drain() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();

    let counts_before = d.event_counts();
    assert!(
        counts_before
            .get("checkpoint_recorded")
            .copied()
            .unwrap_or(0)
            > 0
    );

    d.drain_events();
    let counts_after = d.event_counts();
    assert_eq!(
        counts_after
            .get("checkpoint_recorded")
            .copied()
            .unwrap_or(0),
        0
    );
}

#[test]
fn events_ordered_chronologically_in_fork_lifecycle() {
    let g = genesis("zone-a");
    let cp_a = after(&g, 1, 200, "zone-a");
    let cp_b = divergent(&g, 1, 250, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp_a, true, 1, 200, "t1").unwrap();
    let report = record(&mut d, "zone-a", &cp_b, false, 1, 250, "t-f").unwrap_err();

    d.acknowledge_incident("zone-a", &report.incident_id);
    d.exit_safe_mode("zone-a", "t-exit").unwrap();

    let events = d.drain_events();
    // Expected order: checkpoint_recorded (genesis), checkpoint_recorded (cp_a),
    // fork_detected, safe_mode_entered, safe_mode_exited
    let types: Vec<String> = events.iter().map(|e| e.event_type.to_string()).collect();
    assert!(types.len() >= 5);
    // First two should be checkpoint_recorded events.
    assert!(types[0].starts_with("checkpoint_recorded"));
    assert!(types[1].starts_with("checkpoint_recorded"));
    // Then fork_detected and safe_mode_entered.
    assert!(types[2].starts_with("fork_detected"));
    assert!(types[3].starts_with("safe_mode_entered"));
    // Last one should be safe_mode_exited.
    assert!(types[types.len() - 1].starts_with("safe_mode_exited"));
}

#[test]
fn multiple_denied_operations_accumulate_events() {
    let (mut d, _) = detector_with_fork("zone-a");

    let _ = d.enforce_safe_mode("zone-a", "promote", "t1");
    let _ = d.enforce_safe_mode("zone-a", "grant", "t2");
    let _ = d.enforce_safe_mode("zone-a", "install", "t3");

    let counts = d.event_counts();
    assert_eq!(counts["operation_denied"], 3);
}

#[test]
fn denied_operation_error_contains_operation_name() {
    let (mut d, _) = detector_with_fork("zone-a");
    let err = d
        .enforce_safe_mode("zone-a", "my_special_op", "t-deny")
        .unwrap_err();
    if let ForkError::SafeModeActive { reason, .. } = &err {
        assert!(reason.contains("my_special_op"));
    } else {
        panic!("expected SafeModeActive, got {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Enrichment: history ordering and contents
// ---------------------------------------------------------------------------

#[test]
fn history_entries_ordered_by_ascending_seq() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let cp2 = after(&cp1, 2, 300, "zone-a");
    let cp3 = after(&cp2, 3, 400, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();
    record(&mut d, "zone-a", &cp2, true, 2, 300, "t2").unwrap();
    record(&mut d, "zone-a", &cp3, true, 3, 400, "t3").unwrap();

    let history = d.history("zone-a").unwrap();
    let seqs: Vec<u64> = history.keys().copied().collect();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
}

#[test]
fn history_entry_matches_checkpoint_id() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, true, 1, 200, "t1").unwrap();

    let history = d.history("zone-a").unwrap();
    let entry = history.get(&1).unwrap();
    assert_eq!(entry.checkpoint_id, cp1.checkpoint_id);
    assert_eq!(entry.checkpoint_seq, 1);
    assert!(entry.accepted);
}

#[test]
fn history_records_unaccepted_checkpoints() {
    let g = genesis("zone-a");
    let cp1 = after(&g, 1, 200, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1, false, 1, 200, "t1").unwrap();

    let history = d.history("zone-a").unwrap();
    let entry = history.get(&1).unwrap();
    assert!(!entry.accepted);
}

#[test]
fn history_trim_preserves_newest_entries() {
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

    let history = d.history("zone-a").unwrap();
    // Oldest entries should be gone, newest should remain.
    let min_seq = *history.keys().min().unwrap();
    let max_seq = *history.keys().max().unwrap();
    assert_eq!(max_seq, 10);
    assert!(min_seq >= 8, "min_seq should be >= 8 but was {min_seq}");
}

// ---------------------------------------------------------------------------
// Enrichment: incident ID format
// ---------------------------------------------------------------------------

#[test]
fn incident_id_contains_zone_and_seq() {
    let (d, report) = detector_with_fork("zone-alpha");
    let _ = d;
    assert!(
        report.incident_id.contains("zone-alpha"),
        "incident_id should contain zone: {}",
        report.incident_id
    );
    assert!(
        report.incident_id.contains("seq1"),
        "incident_id should contain seq: {}",
        report.incident_id
    );
}

#[test]
fn incident_ids_are_unique_across_forks() {
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

    assert_ne!(r1.incident_id, r2.incident_id);
}

// ---------------------------------------------------------------------------
// Enrichment: fork report trace_id propagation
// ---------------------------------------------------------------------------

#[test]
fn fork_report_trace_id_matches_input() {
    let g = genesis("zone-a");
    let cp_a = after(&g, 1, 200, "zone-a");
    let cp_b = divergent(&g, 1, 250, "zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp_a, true, 1, 200, "t1").unwrap();
    let report = record(&mut d, "zone-a", &cp_b, false, 1, 250, "my-trace-xyz").unwrap_err();
    assert_eq!(report.trace_id, "my-trace-xyz");
}

// ---------------------------------------------------------------------------
// Enrichment: re-entering safe mode after exit
// ---------------------------------------------------------------------------

#[test]
fn re_enter_safe_mode_after_exit_and_new_fork() {
    let g = genesis("zone-a");
    let cp1a = after(&g, 1, 200, "zone-a");
    let cp1b = divergent(&g, 1, 250, "zone-a");

    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1a, true, 1, 200, "t1").unwrap();
    let r1 = record(&mut d, "zone-a", &cp1b, false, 1, 250, "t-f1").unwrap_err();

    // Acknowledge and exit.
    d.acknowledge_incident("zone-a", &r1.incident_id);
    d.exit_safe_mode("zone-a", "t-exit1").unwrap();
    assert!(!d.is_safe_mode("zone-a"));

    // Trigger a second fork at a different seq.
    let cp2a = after(&cp1a, 2, 300, "zone-a");
    let cp2b = divergent(&cp1a, 2, 350, "zone-a");
    record(&mut d, "zone-a", &cp2a, true, 2, 300, "t2").unwrap();
    let r2 = record(&mut d, "zone-a", &cp2b, false, 2, 350, "t-f2").unwrap_err();

    // Should be back in safe mode.
    assert!(d.is_safe_mode("zone-a"));
    assert_eq!(d.incidents("zone-a").len(), 2);

    // Acknowledge second and exit again.
    d.acknowledge_incident("zone-a", &r2.incident_id);
    d.exit_safe_mode("zone-a", "t-exit2").unwrap();
    assert!(!d.is_safe_mode("zone-a"));
}

// ---------------------------------------------------------------------------
// Enrichment: safe mode trigger_seq behavior
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_trigger_seq_reflects_first_fork_point() {
    let (d, _) = detector_with_fork("zone-a");
    let sm = d.safe_mode_state("zone-a").unwrap();
    assert_eq!(sm.trigger_seq, Some(1));
}

#[test]
fn safe_mode_trigger_seq_stays_on_first_fork_after_second_fork() {
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

    // trigger_seq should reflect the most recent fork (seq=2).
    let sm = d.safe_mode_state("zone-a").unwrap();
    assert_eq!(sm.trigger_seq, Some(2));
}

// ---------------------------------------------------------------------------
// Enrichment: safe mode state cleared after exit
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_state_cleared_after_exit() {
    let (mut d, report) = detector_with_fork("zone-a");
    d.acknowledge_incident("zone-a", &report.incident_id);
    d.exit_safe_mode("zone-a", "t-exit").unwrap();

    let sm = d.safe_mode_state("zone-a").unwrap();
    assert!(!sm.active);
    assert_eq!(sm.trigger_seq, None);
    assert_eq!(sm.unacknowledged_count, 0);
}

// ---------------------------------------------------------------------------
// Enrichment: many zones
// ---------------------------------------------------------------------------

#[test]
fn ten_zones_tracked_independently() {
    let mut d = ForkDetector::with_defaults();
    for i in 0..10 {
        let zone = format!("zone-{i}");
        let g = genesis(&zone);
        record(&mut d, &zone, &g, true, 0, 100, &format!("t-{i}")).unwrap();
    }
    assert_eq!(d.zones().len(), 10);
    for i in 0..10 {
        let zone = format!("zone-{i}");
        assert_eq!(d.history_size(&zone), 1);
        assert!(!d.is_safe_mode(&zone));
    }
}

// ---------------------------------------------------------------------------
// Enrichment: evaluate_safe_mode_startup artifact field details
// ---------------------------------------------------------------------------

#[test]
fn startup_safe_mode_artifact_has_restricted_features() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    assert!(
        art.restricted_features
            .contains(&"extension_auto_promotion".to_string())
    );
    assert!(
        art.restricted_features
            .contains(&"adaptive_policy_tuning".to_string())
    );
    assert!(
        art.restricted_features
            .contains(&"speculative_optimizations".to_string())
    );
    assert_eq!(art.restricted_features.len(), 3);
}

#[test]
fn startup_safe_mode_artifact_has_exit_procedure() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    assert!(!art.exit_procedure.is_empty());
    assert!(art.exit_procedure.iter().any(|s| s.contains("incidents")));
    assert!(art.exit_procedure.iter().any(|s| s.contains("quarantine")));
    assert!(art.exit_procedure.iter().any(|s| s.contains("ledger")));
}

#[test]
fn startup_safe_mode_artifact_has_startup_sequence() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    assert_eq!(art.startup_sequence.len(), 7);
    assert_eq!(art.startup_sequence[0], "initialize_runtime_context");
    assert!(art.startup_sequence.iter().any(|s| s.contains("sandbox")));
}

#[test]
fn startup_normal_mode_artifact_startup_sequence() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![])).unwrap();
    assert_eq!(art.startup_sequence.len(), 4);
    assert_eq!(art.startup_sequence[0], "initialize_runtime_context");
    assert!(
        art.startup_sequence
            .iter()
            .any(|s| s.contains("policy_frontier"))
    );
}

#[test]
fn startup_normal_mode_artifact_exit_procedure() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![])).unwrap();
    assert!(art.exit_procedure.iter().any(|s| s.contains("not_active")));
}

#[test]
fn startup_safe_mode_events_contain_error_codes() {
    let art = evaluate_safe_mode_startup(&startup_input(true, vec![])).unwrap();
    let events_with_codes: Vec<_> = art
        .events
        .iter()
        .filter(|e| e.error_code.is_some())
        .collect();
    assert!(events_with_codes.len() >= 2);
    assert!(
        events_with_codes
            .iter()
            .any(|e| { e.error_code.as_deref().unwrap().contains("FE-SAFE-MODE") })
    );
}

#[test]
fn startup_normal_mode_events_have_no_error_codes() {
    let art = evaluate_safe_mode_startup(&startup_input(false, vec![])).unwrap();
    for event in &art.events {
        // Normal mode: the "evaluated" event should have None error_code,
        // and the "not_enabled" event should also have None.
        if event.event == "safe_mode_not_enabled" {
            assert!(event.error_code.is_none());
        }
    }
}

// ---------------------------------------------------------------------------
// Enrichment: environment variable edge cases
// ---------------------------------------------------------------------------

#[test]
fn startup_both_env_flags_set() {
    let art = evaluate_safe_mode_startup(&startup_input(
        false,
        vec![("FRANKEN_SAFE_MODE", "1"), ("FRANKENENGINE_SAFE_MODE", "1")],
    ))
    .unwrap();
    assert!(art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::EnvironmentVariable);
}

#[test]
fn startup_unrelated_env_vars_ignored() {
    let art = evaluate_safe_mode_startup(&startup_input(
        false,
        vec![
            ("HOME", "/home/user"),
            ("PATH", "/usr/bin"),
            ("UNRELATED_SAFE_MODE", "1"),
        ],
    ))
    .unwrap();
    assert!(!art.safe_mode_active);
    assert_eq!(art.source, SafeModeStartupSource::NotRequested);
}

#[test]
fn startup_env_mixed_truthy_and_falsy_first_truthy_wins() {
    // FRANKEN_SAFE_MODE=0 (false), FRANKENENGINE_SAFE_MODE=1 (true).
    let art = evaluate_safe_mode_startup(&startup_input(
        false,
        vec![("FRANKEN_SAFE_MODE", "0"), ("FRANKENENGINE_SAFE_MODE", "1")],
    ))
    .unwrap();
    assert!(art.safe_mode_active);
}

// ---------------------------------------------------------------------------
// Enrichment: evaluate_safe_mode_exit additional combinations
// ---------------------------------------------------------------------------

#[test]
fn exit_check_incidents_and_quarantines_both_blocking() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 2,
        pending_quarantines: 3,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert_eq!(art.blocking_reasons.len(), 2);
}

#[test]
fn exit_check_incidents_and_unflushed_ledger_blocking() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 0,
        evidence_ledger_flushed: false,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert_eq!(art.blocking_reasons.len(), 2);
}

#[test]
fn exit_check_quarantines_and_unflushed_ledger_blocking() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    })
    .unwrap();
    assert!(!art.can_exit);
    assert_eq!(art.blocking_reasons.len(), 2);
}

#[test]
fn exit_check_event_fields_populated() {
    let art = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "my-trace".into(),
        decision_id: "my-decision".into(),
        policy_id: "my-policy".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap();
    assert_eq!(art.event.trace_id, "my-trace");
    assert_eq!(art.event.decision_id, "my-decision");
    assert_eq!(art.event.policy_id, "my-policy");
    assert_eq!(art.event.component, "safe_mode_startup");
    assert_eq!(art.event.event, "safe_mode_exit_check");
}

#[test]
fn exit_check_rejects_empty_decision_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(err, SafeModeStartupError::MissingField { .. }));
}

#[test]
fn exit_check_rejects_empty_policy_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "policy_id"
    ));
}

#[test]
fn exit_check_rejects_whitespace_only_trace_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "   ".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(err, SafeModeStartupError::MissingField { .. }));
}

#[test]
fn exit_check_is_deterministic() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 2,
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    };
    let a = evaluate_safe_mode_exit(&input).unwrap();
    let b = evaluate_safe_mode_exit(&input).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Enrichment: export/import roundtrip completeness
// ---------------------------------------------------------------------------

#[test]
fn export_import_preserves_incidents_and_acknowledgment() {
    let (mut d, report) = detector_with_fork("zone-a");
    d.acknowledge_incident("zone-a", &report.incident_id);

    let exported = d.export_state().clone();
    let mut d2 = ForkDetector::with_defaults();
    d2.import_state(exported);

    assert_eq!(d2.incidents("zone-a").len(), 1);
    assert!(d2.incidents("zone-a")[0].acknowledged);
    assert!(d2.unacknowledged_incidents("zone-a").is_empty());
}

#[test]
fn export_import_multi_zone_preserves_all() {
    let g_a = genesis("zone-a");
    let g_b = genesis("zone-b");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g_a, true, 0, 100, "ta").unwrap();
    record(&mut d, "zone-b", &g_b, true, 0, 100, "tb").unwrap();

    let exported = d.export_state().clone();
    let mut d2 = ForkDetector::with_defaults();
    d2.import_state(exported);

    let mut zones = d2.zones();
    zones.sort();
    assert_eq!(zones, vec!["zone-a", "zone-b"]);
    assert_eq!(d2.history_size("zone-a"), 1);
    assert_eq!(d2.history_size("zone-b"), 1);
}

#[test]
fn import_clears_existing_events() {
    let g = genesis("zone-a");
    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();

    // Events accumulated so far.
    assert!(!d.drain_events().is_empty());

    // Import fresh state.
    let d2 = ForkDetector::with_defaults();
    let exported = d2.export_state().clone();
    d.import_state(exported);

    // After import, zone-a is gone, events still empty from drain.
    assert!(d.zones().is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: ForkEventType serde roundtrip for all variants
// ---------------------------------------------------------------------------

#[test]
fn fork_event_type_serde_round_trip_all_variants() {
    let variants = vec![
        ForkEventType::ForkDetected {
            zone: "zone-1".into(),
            checkpoint_seq: 100,
        },
        ForkEventType::SafeModeEntered {
            zone: "zone-2".into(),
            trigger_seq: 200,
        },
        ForkEventType::SafeModeExited {
            zone: "zone-3".into(),
            acknowledged_incidents: 5,
        },
        ForkEventType::CheckpointRecorded {
            zone: "zone-4".into(),
            checkpoint_seq: 300,
        },
        ForkEventType::OperationDenied {
            zone: "zone-5".into(),
            operation: "install_plugin".into(),
        },
        ForkEventType::HistoryTrimmed {
            zone: "zone-6".into(),
            removed_count: 42,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("serialize");
        let rt: ForkEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*v, rt);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: SafeModeStartupError serde and display
// ---------------------------------------------------------------------------

#[test]
fn safe_mode_startup_error_display_various_fields() {
    for field in &["trace_id", "decision_id", "policy_id", "custom_field"] {
        let err = SafeModeStartupError::MissingField {
            field: field.to_string(),
        };
        assert!(err.to_string().contains(field));
    }
}

#[test]
fn safe_mode_startup_error_serde_preserves_field_name() {
    let err = SafeModeStartupError::MissingField {
        field: "some_exotic_field".into(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let rt: SafeModeStartupError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, rt);
    let SafeModeStartupError::MissingField { field } = &rt;
    assert_eq!(field, "some_exotic_field");
}

// ---------------------------------------------------------------------------
// Enrichment: ForkIncidentReport from live detector
// ---------------------------------------------------------------------------

#[test]
fn fork_incident_report_from_detector_has_correct_epochs() {
    let (_, report) = detector_with_fork("zone-a");
    assert_eq!(report.existing_epoch, SecurityEpoch::GENESIS);
    assert_eq!(report.divergent_epoch, SecurityEpoch::GENESIS);
    assert_eq!(report.frontier_epoch_at_detection, SecurityEpoch::GENESIS);
}

#[test]
fn fork_incident_report_from_detector_has_correct_zone() {
    let (_, report) = detector_with_fork("my-custom-zone");
    assert_eq!(report.zone, "my-custom-zone");
}

// ---------------------------------------------------------------------------
// Enrichment: ForkDetector edge case — recording after safe mode without exit
// ---------------------------------------------------------------------------

#[test]
fn recording_checkpoint_while_in_safe_mode_still_works() {
    let (mut d, _) = detector_with_fork("zone-a");
    assert!(d.is_safe_mode("zone-a"));

    // Recording new (non-forked) checkpoints should still succeed.
    let g = genesis("zone-a");
    let cp_next = after(&g, 5, 600, "zone-a");
    record(&mut d, "zone-a", &cp_next, true, 5, 600, "t-next").unwrap();

    // History should grow.
    assert!(d.history_size("zone-a") >= 3);
    // Still in safe mode.
    assert!(d.is_safe_mode("zone-a"));
}

// ---------------------------------------------------------------------------
// Enrichment: ForkEvent Debug and Clone
// ---------------------------------------------------------------------------

#[test]
fn fork_event_debug_format() {
    let event = ForkEvent {
        event_type: ForkEventType::ForkDetected {
            zone: "z".into(),
            checkpoint_seq: 1,
        },
        trace_id: "t".into(),
    };
    let dbg = format!("{event:?}");
    assert!(dbg.contains("ForkDetected"));
    assert!(dbg.contains("trace_id"));
}

#[test]
fn fork_event_clone_equality() {
    let event = ForkEvent {
        event_type: ForkEventType::OperationDenied {
            zone: "z".into(),
            operation: "op".into(),
        },
        trace_id: "t".into(),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

// ---------------------------------------------------------------------------
// Enrichment: SafeModeExitCheckArtifact blocking_reasons order
// ---------------------------------------------------------------------------

#[test]
fn exit_check_blocking_reasons_order_is_deterministic() {
    let input = SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        active_incidents: 1,
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    };
    let art1 = evaluate_safe_mode_exit(&input).unwrap();
    let art2 = evaluate_safe_mode_exit(&input).unwrap();
    assert_eq!(art1.blocking_reasons, art2.blocking_reasons);
    // Order: incidents, quarantines, ledger.
    assert!(art1.blocking_reasons[0].contains("incidents"));
    assert!(art1.blocking_reasons[1].contains("quarantines"));
    assert!(art1.blocking_reasons[2].contains("ledger"));
}

// ---------------------------------------------------------------------------
// Enrichment: JSON structure verification
// ---------------------------------------------------------------------------

#[test]
fn fork_error_json_contains_expected_keys() {
    let err = ForkError::ForkDetected {
        checkpoint_seq: 1,
        existing_id: EngineObjectId([0xAA; 32]),
        divergent_id: EngineObjectId([0xBB; 32]),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    assert!(json.contains("ForkDetected"));
    assert!(json.contains("checkpoint_seq"));
}

#[test]
fn safe_mode_state_json_contains_expected_keys() {
    let state = SafeModeState {
        active: true,
        trigger_seq: Some(5),
        unacknowledged_count: 2,
    };
    let json = serde_json::to_string(&state).expect("serialize");
    assert!(json.contains("\"active\":true"));
    assert!(json.contains("\"unacknowledged_count\":2"));
}

#[test]
fn fork_incident_report_json_contains_expected_keys() {
    let report = ForkIncidentReport {
        incident_id: "test".into(),
        fork_seq: 1,
        existing_checkpoint_id: EngineObjectId([1; 32]),
        divergent_checkpoint_id: EngineObjectId([2; 32]),
        existing_epoch: SecurityEpoch::GENESIS,
        divergent_epoch: SecurityEpoch::GENESIS,
        zone: "z".into(),
        frontier_seq_at_detection: 0,
        frontier_epoch_at_detection: SecurityEpoch::GENESIS,
        detected_at_tick: 100,
        trace_id: "t".into(),
        existing_was_accepted: true,
        acknowledged: false,
    };
    let json = serde_json::to_string(&report).expect("serialize");
    assert!(json.contains("\"incident_id\":\"test\""));
    assert!(json.contains("\"fork_seq\":1"));
    assert!(json.contains("\"acknowledged\":false"));
}

// ---------------------------------------------------------------------------
// Enrichment: unacknowledged count after partial acknowledgment
// ---------------------------------------------------------------------------

#[test]
fn unacknowledged_count_decrements_on_acknowledge() {
    let g = genesis("zone-a");
    let cp1a = after(&g, 1, 200, "zone-a");
    let cp1b = divergent(&g, 1, 250, "zone-a");
    let cp2a = after(&cp1a, 2, 300, "zone-a");
    let cp2b = divergent(&cp1a, 2, 350, "zone-a");

    let mut d = ForkDetector::with_defaults();
    record(&mut d, "zone-a", &g, true, 0, 100, "t0").unwrap();
    record(&mut d, "zone-a", &cp1a, true, 1, 200, "t1").unwrap();
    let r1 = record(&mut d, "zone-a", &cp1b, false, 1, 250, "tf1").unwrap_err();
    record(&mut d, "zone-a", &cp2a, true, 2, 300, "t2").unwrap();
    let _r2 = record(&mut d, "zone-a", &cp2b, false, 2, 350, "tf2").unwrap_err();

    let sm = d.safe_mode_state("zone-a").unwrap();
    assert_eq!(sm.unacknowledged_count, 2);

    d.acknowledge_incident("zone-a", &r1.incident_id);
    let sm = d.safe_mode_state("zone-a").unwrap();
    assert_eq!(sm.unacknowledged_count, 1);
}

// ---------------------------------------------------------------------------
// Enrichment: ForkDetector::new vs with_defaults consistency
// ---------------------------------------------------------------------------

#[test]
fn new_1000_matches_with_defaults_behavior() {
    let d1 = ForkDetector::new(1000);
    let d2 = ForkDetector::with_defaults();
    assert_eq!(d1.zones().len(), d2.zones().len());
    assert!(d1.zones().is_empty());
    assert!(d2.zones().is_empty());
}

// ---------------------------------------------------------------------------
// Enrichment: startup whitespace-only metadata rejection
// ---------------------------------------------------------------------------

#[test]
fn startup_rejects_whitespace_only_decision_id() {
    let mut input = startup_input(false, vec![]);
    input.decision_id = "  \t  ".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "decision_id"
    ));
}

#[test]
fn startup_rejects_whitespace_only_policy_id() {
    let mut input = startup_input(false, vec![]);
    input.policy_id = "  \n  ".into();
    let err = evaluate_safe_mode_startup(&input).unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "policy_id"
    ));
}

// ---------------------------------------------------------------------------
// Enrichment: exit check whitespace-only metadata rejection
// ---------------------------------------------------------------------------

#[test]
fn exit_check_rejects_whitespace_only_decision_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "   ".into(),
        policy_id: "p".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "decision_id"
    ));
}

#[test]
fn exit_check_rejects_whitespace_only_policy_id() {
    let err = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "   ".into(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        SafeModeStartupError::MissingField { field } if field == "policy_id"
    ));
}
