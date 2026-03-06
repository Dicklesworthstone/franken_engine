use std::collections::BTreeMap;

use frankenengine_engine::fork_detection::{
    ForkDetector, RecordCheckpointInput, SafeModeExitCheckInput, SafeModeStartupInput,
    SafeModeStartupSource, evaluate_safe_mode_exit, evaluate_safe_mode_startup,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::{
    CheckpointBuilder, DeterministicTimestamp, PolicyCheckpoint, PolicyHead, PolicyType,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes([seed; 32])
}

fn make_policy_head(policy_type: PolicyType, version: u64) -> PolicyHead {
    let hash_input = format!("{policy_type}-v{version}");
    PolicyHead {
        policy_type,
        policy_hash: ContentHash::compute(hash_input.as_bytes()),
        policy_version: version,
    }
}

fn genesis(keys: &[SigningKey], zone: &str) -> PolicyCheckpoint {
    CheckpointBuilder::genesis(SecurityEpoch::GENESIS, DeterministicTimestamp(100), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, 1))
        .build(keys)
        .expect("genesis checkpoint")
}

fn checkpoint_after(
    prev: &PolicyCheckpoint,
    seq: u64,
    epoch: SecurityEpoch,
    tick: u64,
    keys: &[SigningKey],
    zone: &str,
    version: u64,
) -> PolicyCheckpoint {
    CheckpointBuilder::after(prev, seq, epoch, DeterministicTimestamp(tick), zone)
        .add_policy_head(make_policy_head(PolicyType::RuntimeExecution, version))
        .build(keys)
        .expect("checkpoint")
}

#[test]
fn startup_cli_flag_has_precedence_over_environment() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKEN_SAFE_MODE".to_string(), "0".to_string());
    environment.insert("FRANKENENGINE_SAFE_MODE".to_string(), "false".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-safe-startup-precedence".to_string(),
        decision_id: "decision-safe-startup-precedence".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
    assert_eq!(artifact.source, SafeModeStartupSource::CliFlag);
}

#[test]
fn startup_artifact_preserves_evidence_logs_and_state() {
    let input = SafeModeStartupInput {
        trace_id: "trace-safe-startup-preservation".to_string(),
        decision_id: "decision-safe-startup-preservation".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.evidence_preserved);
    assert!(artifact.logs_preserved);
    assert!(artifact.state_preserved);
    assert!(
        artifact
            .restricted_features
            .contains(&"extension_auto_promotion".to_string())
    );
    assert!(
        artifact
            .exit_procedure
            .contains(&"switch_runtime_to_normal_mode".to_string())
    );
}

#[test]
fn incident_recovery_flow_enters_safe_mode_and_exits_after_checks() {
    let startup = evaluate_safe_mode_startup(&SafeModeStartupInput {
        trace_id: "trace-safe-startup-incident".to_string(),
        decision_id: "decision-safe-startup-incident".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    })
    .expect("startup artifact");
    assert!(startup.safe_mode_active);

    let signing_key = make_signing_key(7);
    let base = genesis(std::slice::from_ref(&signing_key), "zone-a");
    let cp1 = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        200,
        std::slice::from_ref(&signing_key),
        "zone-a",
        2,
    );
    let cp1_divergent = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        220,
        std::slice::from_ref(&signing_key),
        "zone-a",
        99,
    );

    let mut detector = ForkDetector::with_defaults();
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &base,
            accepted: true,
            frontier_seq: 0,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 100,
            trace_id: "trace-checkpoint-genesis",
        })
        .expect("record genesis");
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1,
            accepted: true,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 200,
            trace_id: "trace-checkpoint-cp1",
        })
        .expect("record cp1");
    let report = detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-a",
            checkpoint: &cp1_divergent,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 220,
            trace_id: "trace-checkpoint-divergent",
        })
        .expect_err("divergent checkpoint must trigger safe mode");
    assert!(detector.is_safe_mode("zone-a"));

    let blocked_exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-safe-exit-blocked".to_string(),
        decision_id: "decision-safe-exit-blocked".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: detector.unacknowledged_incidents("zone-a").len(),
        pending_quarantines: 1,
        evidence_ledger_flushed: false,
    })
    .expect("blocked exit artifact");
    assert!(!blocked_exit.can_exit);
    assert_eq!(blocked_exit.event.outcome, "fail");

    assert!(detector.acknowledge_incident("zone-a", &report.incident_id));
    let pass_exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-safe-exit-pass".to_string(),
        decision_id: "decision-safe-exit-pass".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: detector.unacknowledged_incidents("zone-a").len(),
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("pass exit artifact");
    assert!(pass_exit.can_exit);
    detector
        .exit_safe_mode("zone-a", "trace-safe-exit-pass")
        .expect("exit safe mode");
    assert!(!detector.is_safe_mode("zone-a"));
}

// ---------- startup source selection ----------

#[test]
fn startup_env_franken_safe_mode_triggers_safe_mode() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKEN_SAFE_MODE".to_string(), "1".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-env-trigger".to_string(),
        decision_id: "decision-env-trigger".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
    assert_eq!(artifact.source, SafeModeStartupSource::EnvironmentVariable);
}

#[test]
fn startup_frankenengine_safe_mode_env_triggers_safe_mode() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKENENGINE_SAFE_MODE".to_string(), "true".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-env-trigger-2".to_string(),
        decision_id: "decision-env-trigger-2".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
}

#[test]
fn startup_no_flags_results_in_normal_mode() {
    let input = SafeModeStartupInput {
        trace_id: "trace-normal".to_string(),
        decision_id: "decision-normal".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(!artifact.safe_mode_active);
    assert_eq!(artifact.source, SafeModeStartupSource::NotRequested);
}

// ---------- restricted features ----------

#[test]
fn safe_mode_restricts_extension_auto_promotion() {
    let input = SafeModeStartupInput {
        trace_id: "trace-restrict".to_string(),
        decision_id: "decision-restrict".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
    assert!(
        artifact
            .restricted_features
            .contains(&"extension_auto_promotion".to_string()),
        "safe mode should restrict extension auto-promotion"
    );
}

// ---------- exit checks ----------

#[test]
fn exit_blocked_when_incidents_unacknowledged() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-incidents".to_string(),
        decision_id: "decision-exit-incidents".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: 2,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
    assert!(!exit.blocking_reasons.is_empty());
}

#[test]
fn exit_blocked_when_quarantines_pending() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-quarantine".to_string(),
        decision_id: "decision-exit-quarantine".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: 0,
        pending_quarantines: 1,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
}

#[test]
fn exit_blocked_when_ledger_not_flushed() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-ledger".to_string(),
        decision_id: "decision-exit-ledger".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: false,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
}

#[test]
fn exit_passes_when_all_conditions_met() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-pass".to_string(),
        decision_id: "decision-exit-pass".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    assert!(exit.can_exit);
    assert_eq!(exit.event.outcome, "pass");
}

// ---------- fork detector ----------

#[test]
fn fork_detector_starts_not_in_safe_mode() {
    let detector = ForkDetector::with_defaults();
    assert!(!detector.is_safe_mode("zone-a"));
}

#[test]
fn fork_detector_accepts_sequential_checkpoints() {
    let signing_key = make_signing_key(20);
    let base = genesis(std::slice::from_ref(&signing_key), "zone-b");
    let cp1 = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        200,
        std::slice::from_ref(&signing_key),
        "zone-b",
        2,
    );

    let mut detector = ForkDetector::with_defaults();
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-b",
            checkpoint: &base,
            accepted: true,
            frontier_seq: 0,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 100,
            trace_id: "trace-genesis-b",
        })
        .expect("record genesis");
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-b",
            checkpoint: &cp1,
            accepted: true,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 200,
            trace_id: "trace-cp1-b",
        })
        .expect("record cp1");
    assert!(!detector.is_safe_mode("zone-b"));
}

#[test]
fn fork_detector_incidents_start_empty() {
    let detector = ForkDetector::with_defaults();
    assert!(detector.incidents("zone-a").is_empty());
}

#[test]
fn fork_detector_safe_mode_sticky_across_zones() {
    let signing_key = make_signing_key(21);
    let base = genesis(std::slice::from_ref(&signing_key), "zone-c");
    let cp1 = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        200,
        std::slice::from_ref(&signing_key),
        "zone-c",
        2,
    );
    let cp1_fork = checkpoint_after(
        &base,
        1,
        SecurityEpoch::GENESIS,
        210,
        std::slice::from_ref(&signing_key),
        "zone-c",
        3,
    );

    let mut detector = ForkDetector::with_defaults();
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-c",
            checkpoint: &base,
            accepted: true,
            frontier_seq: 0,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 100,
            trace_id: "trace-genesis-c",
        })
        .expect("record");
    detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-c",
            checkpoint: &cp1,
            accepted: true,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 200,
            trace_id: "trace-cp1-c",
        })
        .expect("record");
    let _report = detector
        .record_checkpoint(&RecordCheckpointInput {
            zone: "zone-c",
            checkpoint: &cp1_fork,
            accepted: false,
            frontier_seq: 1,
            frontier_epoch: SecurityEpoch::GENESIS,
            tick: 210,
            trace_id: "trace-fork-c",
        })
        .expect_err("fork must trigger safe mode");

    assert!(detector.is_safe_mode("zone-c"));
    assert!(!detector.is_safe_mode("zone-d"));
}

// ---------- serde roundtrip ----------

#[test]
fn safe_mode_startup_input_serde_roundtrip() {
    let input = SafeModeStartupInput {
        trace_id: "trace-serde".to_string(),
        decision_id: "decision-serde".to_string(),
        policy_id: "policy-serde".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::from([("KEY".to_string(), "VALUE".to_string())]),
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: SafeModeStartupInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, input.trace_id);
    assert_eq!(recovered.cli_safe_mode, input.cli_safe_mode);
}

#[test]
fn safe_mode_exit_check_input_serde_roundtrip() {
    let input = SafeModeExitCheckInput {
        trace_id: "trace-exit-serde".to_string(),
        decision_id: "decision-exit-serde".to_string(),
        policy_id: "policy-exit-serde".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: SafeModeExitCheckInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, input.trace_id);
    assert_eq!(recovered.active_incidents, 0);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn safe_mode_startup_source_serde_round_trip() {
    for source in [
        SafeModeStartupSource::CliFlag,
        SafeModeStartupSource::EnvironmentVariable,
        SafeModeStartupSource::NotRequested,
    ] {
        let json = serde_json::to_string(&source).expect("serialize");
        let recovered: SafeModeStartupSource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(source, recovered);
    }
}

#[test]
fn safe_mode_startup_artifact_serde_round_trip() {
    let input = SafeModeStartupInput {
        trace_id: "trace-serde-art".to_string(),
        decision_id: "decision-serde-art".to_string(),
        policy_id: "policy-serde-art".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("artifact");
    let json = serde_json::to_string(&artifact).expect("serialize");
    assert!(json.contains("trace-serde-art"));
}

#[test]
fn exit_artifact_has_structured_event() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-event".to_string(),
        decision_id: "decision-exit-event".to_string(),
        policy_id: "policy-exit-event".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    assert_eq!(exit.event.trace_id, "trace-exit-event");
    assert_eq!(exit.event.decision_id, "decision-exit-event");
    assert!(!exit.event.component.is_empty());
}

#[test]
fn multiple_blocking_reasons_accumulate() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-multi-block".to_string(),
        decision_id: "decision-multi-block".to_string(),
        policy_id: "policy-multi-block".to_string(),
        active_incidents: 2,
        pending_quarantines: 3,
        evidence_ledger_flushed: false,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
    assert!(
        exit.blocking_reasons.len() >= 3,
        "all 3 blockers should be reported"
    );
}

#[test]
fn safe_mode_startup_source_debug_is_nonempty() {
    for source in [
        SafeModeStartupSource::CliFlag,
        SafeModeStartupSource::EnvironmentVariable,
        SafeModeStartupSource::NotRequested,
    ] {
        assert!(!format!("{source:?}").is_empty());
    }
}

#[test]
fn safe_mode_startup_input_debug_is_nonempty() {
    let input = SafeModeStartupInput {
        trace_id: "trace-dbg".to_string(),
        decision_id: "decision-dbg".to_string(),
        policy_id: "policy-dbg".to_string(),
        cli_safe_mode: false,
        environment: BTreeMap::new(),
    };
    assert!(!format!("{input:?}").is_empty());
}

#[test]
fn safe_mode_exit_check_input_debug_is_nonempty() {
    let input = SafeModeExitCheckInput {
        trace_id: "trace-dbg-exit".to_string(),
        decision_id: "decision-dbg-exit".to_string(),
        policy_id: "policy-dbg-exit".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    };
    assert!(!format!("{input:?}").is_empty());
}

#[test]
fn startup_env_false_value_does_not_trigger_safe_mode() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKEN_SAFE_MODE".to_string(), "0".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-env-false".to_string(),
        decision_id: "decision-env-false".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(!artifact.safe_mode_active);
}

#[test]
fn exit_artifact_serde_roundtrip() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-exit-rt".to_string(),
        decision_id: "decision-exit-rt".to_string(),
        policy_id: "policy-exit-rt".to_string(),
        active_incidents: 0,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    let json = serde_json::to_string(&exit).expect("serialize");
    let recovered: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered["event"]["trace_id"].as_str(),
        Some("trace-exit-rt")
    );
}

#[test]
fn startup_artifact_exit_procedure_is_nonempty_in_safe_mode() {
    let input = SafeModeStartupInput {
        trace_id: "trace-exit-proc".to_string(),
        decision_id: "decision-exit-proc".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(
        !artifact.exit_procedure.is_empty(),
        "exit_procedure should list steps when safe mode is active"
    );
}

#[test]
fn startup_artifact_restricted_features_nonempty_when_safe() {
    let input = SafeModeStartupInput {
        trace_id: "trace-restrict-nonempty".to_string(),
        decision_id: "decision-restrict-nonempty".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("artifact");
    assert!(
        !artifact.restricted_features.is_empty(),
        "safe mode must restrict at least one feature"
    );
}

#[test]
fn exit_blocked_with_all_three_blockers_has_fail_outcome() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-all-block".to_string(),
        decision_id: "decision-all-block".to_string(),
        policy_id: "policy-all-block".to_string(),
        active_incidents: 5,
        pending_quarantines: 3,
        evidence_ledger_flushed: false,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
    assert_eq!(exit.event.outcome, "fail");
}

#[test]
fn startup_normal_mode_has_empty_restricted_features() {
    let input = SafeModeStartupInput {
        trace_id: "trace-normal-restrict".to_string(),
        decision_id: "decision-normal-restrict".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment: BTreeMap::new(),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("artifact");
    assert!(
        artifact.restricted_features.is_empty(),
        "normal mode should not restrict any features"
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: fork detector edge cases, startup artifact serde, env values
// ────────────────────────────────────────────────────────────

#[test]
fn fork_detector_acknowledge_nonexistent_incident_returns_false() {
    let mut detector = ForkDetector::with_defaults();
    assert!(
        !detector.acknowledge_incident("zone-nonexistent", "fake-incident-id"),
        "acknowledging a nonexistent incident should return false"
    );
}

#[test]
fn safe_mode_startup_artifact_full_serde_roundtrip() {
    let input = SafeModeStartupInput {
        trace_id: "trace-full-rt".to_string(),
        decision_id: "decision-full-rt".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: true,
        environment: BTreeMap::from([("FRANKEN_SAFE_MODE".to_string(), "1".to_string())]),
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("artifact");

    let json = serde_json::to_string(&artifact).expect("serialize");
    let value: serde_json::Value = serde_json::from_str(&json).expect("deserialize");

    // Verify key fields are present in the serialized form
    assert_eq!(value["safe_mode_active"], true);
    assert!(value["restricted_features"].is_array());
    assert!(value["exit_procedure"].is_array());
    assert!(value["evidence_preserved"].as_bool().unwrap());
}

#[test]
fn exit_artifact_blocking_reasons_include_descriptive_text() {
    let exit = evaluate_safe_mode_exit(&SafeModeExitCheckInput {
        trace_id: "trace-descriptive".to_string(),
        decision_id: "decision-descriptive".to_string(),
        policy_id: "policy-descriptive".to_string(),
        active_incidents: 1,
        pending_quarantines: 0,
        evidence_ledger_flushed: true,
    })
    .expect("exit artifact");
    assert!(!exit.can_exit);
    // Each blocking reason should be a non-empty descriptive string
    for reason in &exit.blocking_reasons {
        assert!(
            !reason.trim().is_empty(),
            "blocking reasons should contain descriptive text"
        );
    }
}

#[test]
fn fork_detector_exit_safe_mode_is_noop_when_not_in_safe_mode() {
    let mut detector = ForkDetector::with_defaults();
    let exited = detector
        .exit_safe_mode("zone-never-forked", "trace-exit-attempt")
        .expect("exiting safe mode on an unknown zone should be a no-op");
    assert_eq!(exited, 0);
}

#[test]
fn startup_env_both_flags_set_to_true_still_activates_safe_mode() {
    let mut environment = BTreeMap::new();
    environment.insert("FRANKEN_SAFE_MODE".to_string(), "1".to_string());
    environment.insert("FRANKENENGINE_SAFE_MODE".to_string(), "true".to_string());
    let input = SafeModeStartupInput {
        trace_id: "trace-both-env".to_string(),
        decision_id: "decision-both-env".to_string(),
        policy_id: "policy-safe-startup-v1".to_string(),
        cli_safe_mode: false,
        environment,
    };
    let artifact = evaluate_safe_mode_startup(&input).expect("startup artifact");
    assert!(artifact.safe_mode_active);
    assert_eq!(artifact.source, SafeModeStartupSource::EnvironmentVariable);
}
