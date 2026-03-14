//! Enrichment integration tests for `fleet_convergence` module.
//!
//! Covers: Clone independence, serde roundtrips, Display coverage,
//! Debug nonempty, Default coverage, threshold evaluation, partition mode,
//! action registry, convergence engine lifecycle, escalation, receipt signing,
//! JSON field-name stability, determinism, error coverage.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::fleet_convergence::{
    ActionRegistry, ContainmentReceipt, ContainmentThresholds, ConvergenceConfig,
    ConvergenceDecision, ConvergenceEngine, ConvergenceError, ConvergenceEvent,
    ConvergenceEventType, ConvergenceVerification, HealingInfo, PartitionInfo, PartitionMode,
};
use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, FleetProtocolState, GossipConfig, NodeId,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_node(name: &str) -> NodeId {
    NodeId::new(name)
}

fn test_config() -> ConvergenceConfig {
    ConvergenceConfig {
        thresholds: ContainmentThresholds {
            sandbox_threshold: 200_000,
            suspend_threshold: 500_000,
            terminate_threshold: 800_000,
            quarantine_threshold: 950_000,
        },
        degraded_tightening_factor: 750_000,
        convergence_timeout_ns: 1_000_000_000,
        signing_key: b"test-key".to_vec(),
        max_escalation_depth: 3,
    }
}

fn test_engine(name: &str) -> ConvergenceEngine {
    ConvergenceEngine::new(test_node(name), test_config())
}

fn test_fleet_state(node: &str) -> FleetProtocolState {
    FleetProtocolState::new(NodeId::new(node), GossipConfig::default())
}

// =========================================================================
// Clone independence
// =========================================================================

#[test]
fn enrichment_thresholds_clone_independence() {
    let original = ContainmentThresholds::default();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_convergence_config_clone_independence() {
    let original = ConvergenceConfig::default();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_action_registry_clone_independence() {
    let mut reg = ActionRegistry::new();
    let receipt = make_receipt("ext-1", ContainmentAction::Sandbox);
    reg.record(receipt);
    let cloned = reg.clone();
    assert_eq!(cloned.total_actions(), 1);
    assert_eq!(reg.total_actions(), 1);
}

// =========================================================================
// Serde roundtrips
// =========================================================================

#[test]
fn enrichment_thresholds_serde_roundtrip() {
    let t = ContainmentThresholds::default();
    let json = serde_json::to_string(&t).unwrap();
    let back: ContainmentThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_convergence_config_serde_roundtrip() {
    let cfg = ConvergenceConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ConvergenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_partition_mode_normal_serde() {
    let mode = PartitionMode::Normal;
    let json = serde_json::to_string(&mode).unwrap();
    let back: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back);
}

#[test]
fn enrichment_partition_mode_degraded_serde() {
    let mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 42,
        unreachable_nodes: BTreeSet::from([NodeId::new("n1")]),
        local_partition_size: 3,
        total_fleet_size: 5,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let back: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back);
}

#[test]
fn enrichment_partition_mode_healing_serde() {
    let mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 100,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let back: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back);
}

#[test]
fn enrichment_convergence_decision_serde_roundtrip() {
    let d = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: ConvergenceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_convergence_error_serde_all() {
    let errors = [
        ConvergenceError::MaxEscalationReached {
            extension_id: "ext-1".to_string(),
            depth: 3,
        },
        ConvergenceError::AlreadyAtMaxSeverity {
            extension_id: "ext-2".to_string(),
        },
        ConvergenceError::ActionAlreadyExecuted {
            extension_id: "ext-3".to_string(),
            action: ContainmentAction::Terminate,
        },
        ConvergenceError::InvalidThresholds,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ConvergenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &back);
    }
}

#[test]
fn enrichment_convergence_verification_converged_serde() {
    let v = ConvergenceVerification::Converged { checkpoint_seq: 42 };
    let json = serde_json::to_string(&v).unwrap();
    let back: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_convergence_verification_diverged_serde() {
    let v = ConvergenceVerification::Diverged {
        checkpoint_seq: 42,
        local_summary_hash: ContentHash::compute(b"local"),
        checkpoint_summary_hash: ContentHash::compute(b"remote"),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_containment_receipt_serde_roundtrip() {
    let receipt = make_receipt("ext-1", ContainmentAction::Sandbox);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_action_registry_serde_roundtrip() {
    let mut reg = ActionRegistry::new();
    reg.record(make_receipt("ext-1", ContainmentAction::Sandbox));
    let json = serde_json::to_string(&reg).unwrap();
    let back: ActionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_actions(), 1);
}

#[test]
fn enrichment_convergence_event_serde_roundtrip() {
    let event = ConvergenceEvent {
        event_type: ConvergenceEventType::ThresholdCrossed,
        trace_id: "tr-1".to_string(),
        node_id: test_node("n1"),
        timestamp_ns: 1000,
        epoch: SecurityEpoch::from_raw(1),
        fields: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ConvergenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// =========================================================================
// Display coverage
// =========================================================================

#[test]
fn enrichment_convergence_event_type_display_all() {
    let variants = [
        (ConvergenceEventType::ThresholdCrossed, "threshold_crossed"),
        (ConvergenceEventType::ActionExecuted, "action_executed"),
        (ConvergenceEventType::PartitionEntered, "partition_entered"),
        (ConvergenceEventType::PartitionExited, "partition_exited"),
        (
            ConvergenceEventType::ReconciliationConflict,
            "reconciliation_conflict",
        ),
        (
            ConvergenceEventType::ConvergenceVerified,
            "convergence_verified",
        ),
        (
            ConvergenceEventType::ConvergenceDiverged,
            "convergence_diverged",
        ),
        (
            ConvergenceEventType::EscalationTriggered,
            "escalation_triggered",
        ),
        (ConvergenceEventType::EvidenceLag, "evidence_lag"),
        (
            ConvergenceEventType::SpectralHealthComputed,
            "spectral_health_computed",
        ),
    ];
    for (variant, expected) in variants {
        assert_eq!(variant.to_string(), expected);
    }
}

#[test]
fn enrichment_convergence_error_display_all() {
    let err = ConvergenceError::MaxEscalationReached {
        extension_id: "ext-1".to_string(),
        depth: 3,
    };
    let s = err.to_string();
    assert!(s.contains("ext-1"));
    assert!(s.contains("3"));

    let err = ConvergenceError::AlreadyAtMaxSeverity {
        extension_id: "ext-2".to_string(),
    };
    assert!(err.to_string().contains("ext-2"));

    let err = ConvergenceError::ActionAlreadyExecuted {
        extension_id: "ext-3".to_string(),
        action: ContainmentAction::Terminate,
    };
    let s = err.to_string();
    assert!(s.contains("ext-3"));

    let err = ConvergenceError::InvalidThresholds;
    assert!(err.to_string().contains("invalid"));
}

// =========================================================================
// std::error::Error
// =========================================================================

#[test]
fn enrichment_convergence_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ConvergenceError::InvalidThresholds);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_convergence_error_source_is_none() {
    let err = ConvergenceError::InvalidThresholds;
    assert!(std::error::Error::source(&err).is_none());
}

// =========================================================================
// Debug nonempty
// =========================================================================

#[test]
fn enrichment_thresholds_debug() {
    let d = format!("{:?}", ContainmentThresholds::default());
    assert!(d.contains("ContainmentThresholds"));
}

#[test]
fn enrichment_engine_debug() {
    let d = format!("{:?}", test_engine("n1"));
    assert!(d.contains("ConvergenceEngine"));
}

#[test]
fn enrichment_action_registry_debug() {
    let d = format!("{:?}", ActionRegistry::new());
    assert!(d.contains("ActionRegistry"));
}

#[test]
fn enrichment_partition_info_debug() {
    let info = PartitionInfo {
        detected_at_ns: 42,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    let d = format!("{:?}", info);
    assert!(d.contains("PartitionInfo"));
}

// =========================================================================
// Default coverage
// =========================================================================

#[test]
fn enrichment_thresholds_default() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.sandbox_threshold, 200_000);
    assert_eq!(t.suspend_threshold, 500_000);
    assert_eq!(t.terminate_threshold, 800_000);
    assert_eq!(t.quarantine_threshold, 950_000);
}

#[test]
fn enrichment_convergence_config_default() {
    let cfg = ConvergenceConfig::default();
    assert_eq!(cfg.degraded_tightening_factor, 750_000);
    assert_eq!(cfg.convergence_timeout_ns, 1_000_000_000);
    assert_eq!(cfg.max_escalation_depth, 3);
    assert!(cfg.thresholds.is_valid());
}

#[test]
fn enrichment_action_registry_default() {
    let reg = ActionRegistry::default();
    assert_eq!(reg.total_actions(), 0);
}

// =========================================================================
// ContainmentThresholds
// =========================================================================

#[test]
fn enrichment_thresholds_is_valid() {
    assert!(ContainmentThresholds::default().is_valid());
}

#[test]
fn enrichment_thresholds_invalid() {
    let bad = ContainmentThresholds {
        sandbox_threshold: 500_000,
        suspend_threshold: 200_000,
        terminate_threshold: 800_000,
        quarantine_threshold: 950_000,
    };
    assert!(!bad.is_valid());
}

#[test]
fn enrichment_thresholds_evaluate_allow() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(100_000), ContainmentAction::Allow);
}

#[test]
fn enrichment_thresholds_evaluate_sandbox() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(200_000), ContainmentAction::Sandbox);
    assert_eq!(t.evaluate(300_000), ContainmentAction::Sandbox);
}

#[test]
fn enrichment_thresholds_evaluate_suspend() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(500_000), ContainmentAction::Suspend);
    assert_eq!(t.evaluate(700_000), ContainmentAction::Suspend);
}

#[test]
fn enrichment_thresholds_evaluate_terminate() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(800_000), ContainmentAction::Terminate);
    assert_eq!(t.evaluate(940_000), ContainmentAction::Terminate);
}

#[test]
fn enrichment_thresholds_evaluate_quarantine() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(950_000), ContainmentAction::Quarantine);
    assert_eq!(t.evaluate(1_000_000), ContainmentAction::Quarantine);
}

#[test]
fn enrichment_thresholds_tighten() {
    let t = ContainmentThresholds::default();
    let tightened = t.tighten(750_000); // 75%
    assert_eq!(tightened.sandbox_threshold, 150_000);
    assert_eq!(tightened.suspend_threshold, 375_000);
    assert_eq!(tightened.terminate_threshold, 600_000);
    assert_eq!(tightened.quarantine_threshold, 712_500);
}

// =========================================================================
// PartitionInfo
// =========================================================================

#[test]
fn enrichment_partition_info_minority() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 2,
        total_fleet_size: 5,
    };
    // quorum = 50% of 5 = ceil(2.5) = 3, local=2 < 3 → minority
    assert!(info.is_minority(500_000));
}

#[test]
fn enrichment_partition_info_majority() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    assert!(!info.is_minority(500_000));
}

#[test]
fn enrichment_partition_info_zero_fleet() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 0,
        total_fleet_size: 0,
    };
    assert!(info.is_minority(500_000));
}

// =========================================================================
// ActionRegistry
// =========================================================================

fn make_receipt(ext: &str, action: ContainmentAction) -> ContainmentReceipt {
    ContainmentReceipt {
        action_id: format!("action-{ext}-{}", action.severity()),
        extension_id: ext.to_string(),
        action_type: action,
        evidence_ids: vec![],
        posterior_snapshot: 300_000,
        policy_version: 1,
        node_id: test_node("n1"),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 1000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"test-key", b"preimage"),
    }
}

#[test]
fn enrichment_registry_new_empty() {
    let reg = ActionRegistry::new();
    assert_eq!(reg.total_actions(), 0);
    assert!(!reg.is_executed("ext-1", ContainmentAction::Sandbox));
}

#[test]
fn enrichment_registry_record_and_query() {
    let mut reg = ActionRegistry::new();
    reg.record(make_receipt("ext-1", ContainmentAction::Sandbox));
    assert!(reg.is_executed("ext-1", ContainmentAction::Sandbox));
    assert!(!reg.is_executed("ext-1", ContainmentAction::Terminate));
    assert_eq!(reg.total_actions(), 1);
}

#[test]
fn enrichment_registry_get_receipt() {
    let mut reg = ActionRegistry::new();
    let receipt = make_receipt("ext-1", ContainmentAction::Suspend);
    reg.record(receipt.clone());
    let got = reg.get_receipt("ext-1", ContainmentAction::Suspend);
    assert!(got.is_some());
    assert_eq!(got.unwrap(), &receipt);
    assert!(
        reg.get_receipt("ext-1", ContainmentAction::Sandbox)
            .is_none()
    );
}

#[test]
fn enrichment_registry_highest_executed() {
    let mut reg = ActionRegistry::new();
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Allow
    );
    reg.record(make_receipt("ext-1", ContainmentAction::Sandbox));
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Sandbox
    );
    reg.record(make_receipt("ext-1", ContainmentAction::Terminate));
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Terminate
    );
}

#[test]
fn enrichment_registry_escalation_depth() {
    let mut reg = ActionRegistry::new();
    assert_eq!(reg.escalation_depth("ext-1"), 0);
    let d1 = reg.increment_escalation("ext-1");
    assert_eq!(d1, 1);
    let d2 = reg.increment_escalation("ext-1");
    assert_eq!(d2, 2);
}

#[test]
fn enrichment_registry_receipts_for_extension() {
    let mut reg = ActionRegistry::new();
    reg.record(make_receipt("ext-1", ContainmentAction::Sandbox));
    reg.record(make_receipt("ext-1", ContainmentAction::Terminate));
    let receipts = reg.receipts_for_extension("ext-1");
    assert_eq!(receipts.len(), 2);
    assert!(reg.receipts_for_extension("ext-2").is_empty());
}

// =========================================================================
// ContainmentReceipt signing
// =========================================================================

#[test]
fn enrichment_receipt_signing_preimage_deterministic() {
    let r = make_receipt("ext-1", ContainmentAction::Sandbox);
    let p1 = r.signing_preimage();
    let p2 = r.signing_preimage();
    assert_eq!(p1, p2);
}

#[test]
fn enrichment_receipt_verify_signature() {
    let key = b"test-key";
    let mut receipt = make_receipt("ext-1", ContainmentAction::Sandbox);
    receipt.signature = AuthenticityHash::compute_keyed(key, &receipt.signing_preimage());
    assert!(receipt.verify_signature(key));
    assert!(!receipt.verify_signature(b"wrong-key"));
}

// =========================================================================
// ConvergenceEngine lifecycle
// =========================================================================

#[test]
fn enrichment_engine_new_normal_mode() {
    let engine = test_engine("n1");
    assert_eq!(engine.partition_mode, PartitionMode::Normal);
    assert_eq!(engine.action_registry.total_actions(), 0);
    assert!(engine.events.is_empty());
}

#[test]
fn enrichment_engine_effective_thresholds_normal() {
    let engine = test_engine("n1");
    let t = engine.effective_thresholds();
    assert_eq!(t.sandbox_threshold, 200_000);
}

#[test]
fn enrichment_engine_effective_thresholds_degraded_minority() {
    let mut engine = test_engine("n1");
    engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::from([
            NodeId::new("n2"),
            NodeId::new("n3"),
            NodeId::new("n4"),
        ]),
        local_partition_size: 1,
        total_fleet_size: 4,
    });
    let t = engine.effective_thresholds();
    // Tightened by 75%: 200_000 * 750_000 / 1_000_000 = 150_000
    assert_eq!(t.sandbox_threshold, 150_000);
}

#[test]
fn enrichment_engine_evaluate_extension_allow() {
    let engine = test_engine("n1");
    let d = engine.evaluate_extension("ext-1", 100_000, 5);
    assert_eq!(d.action, ContainmentAction::Allow);
    assert!(d.crossed_threshold.is_none());
    assert!(!d.degraded_mode);
}

#[test]
fn enrichment_engine_evaluate_extension_sandbox() {
    let engine = test_engine("n1");
    let d = engine.evaluate_extension("ext-1", 300_000, 5);
    assert_eq!(d.action, ContainmentAction::Sandbox);
    assert_eq!(d.crossed_threshold, Some(200_000));
}

#[test]
fn enrichment_engine_evaluate_extension_quarantine() {
    let engine = test_engine("n1");
    let d = engine.evaluate_extension("ext-1", 1_000_000, 10);
    assert_eq!(d.action, ContainmentAction::Quarantine);
    assert_eq!(d.crossed_threshold, Some(950_000));
}

#[test]
fn enrichment_engine_execute_decision_allow_noop() {
    let mut engine = test_engine("n1");
    let decision = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Allow,
        posterior_delta: 50_000,
        crossed_threshold: None,
        degraded_mode: false,
        evidence_count: 1,
    };
    assert!(engine.execute_decision(&decision, 1000).is_none());
}

#[test]
fn enrichment_engine_execute_decision_produces_receipt() {
    let mut engine = test_engine("n1");
    let decision = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let receipt = engine.execute_decision(&decision, 1000);
    assert!(receipt.is_some());
    let r = receipt.unwrap();
    assert_eq!(r.action_type, ContainmentAction::Sandbox);
    assert_eq!(r.extension_id, "ext-1");
    assert!(r.verify_signature(b"test-key"));
}

#[test]
fn enrichment_engine_execute_idempotent() {
    let mut engine = test_engine("n1");
    let decision = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let first = engine.execute_decision(&decision, 1000);
    assert!(first.is_some());
    let second = engine.execute_decision(&decision, 2000);
    assert!(second.is_none());
}

#[test]
fn enrichment_engine_monotonic_escalation() {
    let mut engine = test_engine("n1");
    // Execute terminate first
    let d_term = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Terminate,
        posterior_delta: 800_000,
        crossed_threshold: Some(800_000),
        degraded_mode: false,
        evidence_count: 10,
    };
    assert!(engine.execute_decision(&d_term, 1000).is_some());

    // Try sandbox (lower) — should be rejected
    let d_sandbox = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    assert!(engine.execute_decision(&d_sandbox, 2000).is_none());
}

// =========================================================================
// Escalation
// =========================================================================

#[test]
fn enrichment_engine_escalate_sandbox_to_suspend() {
    let mut engine = test_engine("n1");
    let d = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    engine.execute_decision(&d, 1000);

    let result = engine.escalate("ext-1", 600_000, 10, 2000);
    assert!(result.is_ok());
    let receipt = result.unwrap();
    assert_eq!(receipt.action_type, ContainmentAction::Suspend);
}

#[test]
fn enrichment_engine_escalate_max_depth_error() {
    let mut engine = test_engine("n1");
    engine.config.max_escalation_depth = 1;
    // Execute sandbox
    let d = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    engine.execute_decision(&d, 1000);
    // First escalation OK
    assert!(engine.escalate("ext-1", 600_000, 10, 2000).is_ok());
    // Second escalation should fail
    let err = engine.escalate("ext-1", 900_000, 15, 3000);
    assert!(matches!(
        err,
        Err(ConvergenceError::MaxEscalationReached { .. })
    ));
}

// =========================================================================
// Process fleet state (basic smoke)
// =========================================================================

#[test]
fn enrichment_engine_process_fleet_state_empty() {
    let mut engine = test_engine("n1");
    let fleet = test_fleet_state("n1");
    let receipts = engine.process_fleet_state(&fleet, 2_000);
    assert!(receipts.is_empty());
}

// =========================================================================
// Partition mode direct manipulation
// =========================================================================

#[test]
fn enrichment_engine_set_degraded_mode() {
    let mut engine = test_engine("n1");
    engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 42,
        unreachable_nodes: BTreeSet::from([NodeId::new("n2")]),
        local_partition_size: 1,
        total_fleet_size: 3,
    });
    assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));
    // Effective thresholds should be tightened in minority partition
    let t = engine.effective_thresholds();
    assert!(t.sandbox_threshold < 200_000);
}

#[test]
fn enrichment_engine_healing_mode_tightens() {
    let mut engine = test_engine("n1");
    engine.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 100,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let t = engine.effective_thresholds();
    // Healing always tightens
    assert!(t.sandbox_threshold < 200_000);
}

// =========================================================================
// Events
// =========================================================================

#[test]
fn enrichment_engine_events_of_type() {
    let mut engine = test_engine("n1");
    let d = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    engine.execute_decision(&d, 1000);
    let action_events = engine.events_of_type(&ConvergenceEventType::ActionExecuted);
    assert_eq!(action_events.len(), 1);
}

// =========================================================================
// JSON field-name stability
// =========================================================================

#[test]
fn enrichment_json_fields_thresholds() {
    let json = serde_json::to_string(&ContainmentThresholds::default()).unwrap();
    assert!(json.contains("\"sandbox_threshold\""));
    assert!(json.contains("\"suspend_threshold\""));
    assert!(json.contains("\"terminate_threshold\""));
    assert!(json.contains("\"quarantine_threshold\""));
}

#[test]
fn enrichment_json_fields_config() {
    let json = serde_json::to_string(&ConvergenceConfig::default()).unwrap();
    assert!(json.contains("\"thresholds\""));
    assert!(json.contains("\"degraded_tightening_factor\""));
    assert!(json.contains("\"convergence_timeout_ns\""));
    assert!(json.contains("\"signing_key\""));
    assert!(json.contains("\"max_escalation_depth\""));
}

#[test]
fn enrichment_json_fields_receipt() {
    let receipt = make_receipt("ext-1", ContainmentAction::Sandbox);
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"action_id\""));
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"action_type\""));
    assert!(json.contains("\"posterior_snapshot\""));
    assert!(json.contains("\"policy_version\""));
    assert!(json.contains("\"node_id\""));
    assert!(json.contains("\"degraded_mode\""));
    assert!(json.contains("\"escalation_depth\""));
    assert!(json.contains("\"signature\""));
}

#[test]
fn enrichment_json_fields_convergence_decision() {
    let d = ConvergenceDecision {
        extension_id: "ext-1".to_string(),
        action: ContainmentAction::Allow,
        posterior_delta: 0,
        crossed_threshold: None,
        degraded_mode: false,
        evidence_count: 0,
    };
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"action\""));
    assert!(json.contains("\"posterior_delta\""));
    assert!(json.contains("\"crossed_threshold\""));
    assert!(json.contains("\"degraded_mode\""));
    assert!(json.contains("\"evidence_count\""));
}

#[test]
fn enrichment_json_fields_convergence_event() {
    let event = ConvergenceEvent {
        event_type: ConvergenceEventType::ThresholdCrossed,
        trace_id: "tr".to_string(),
        node_id: test_node("n1"),
        timestamp_ns: 0,
        epoch: SecurityEpoch::from_raw(1),
        fields: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"event_type\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"node_id\""));
    assert!(json.contains("\"timestamp_ns\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"fields\""));
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn enrichment_thresholds_evaluate_deterministic() {
    let t = ContainmentThresholds::default();
    for _ in 0..100 {
        assert_eq!(t.evaluate(300_000), ContainmentAction::Sandbox);
        assert_eq!(t.evaluate(600_000), ContainmentAction::Suspend);
        assert_eq!(t.evaluate(850_000), ContainmentAction::Terminate);
        assert_eq!(t.evaluate(999_000), ContainmentAction::Quarantine);
    }
}

#[test]
fn enrichment_tighten_deterministic() {
    let t = ContainmentThresholds::default();
    let t1 = t.tighten(750_000);
    let t2 = t.tighten(750_000);
    assert_eq!(t1, t2);
}
