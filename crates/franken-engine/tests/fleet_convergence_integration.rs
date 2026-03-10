#![forbid(unsafe_code)]
//! Comprehensive integration tests for `fleet_convergence`.
//!
//! Covers: ContainmentThresholds, PartitionInfo, PartitionMode, HealingInfo,
//! ConvergenceConfig, ContainmentReceipt, ConvergenceDecision,
//! ConvergenceEvent, ConvergenceEventType, ActionRegistry, ConvergenceEngine,
//! ConvergenceVerification, ConvergenceError, plus serde round-trips,
//! Display impls, deterministic replay, state transitions, and error paths.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::fleet_convergence::{
    ActionRegistry, ContainmentReceipt, ContainmentThresholds, ConvergenceConfig,
    ConvergenceDecision, ConvergenceEngine, ConvergenceError, ConvergenceEvent,
    ConvergenceEventType, ConvergenceVerification, HealingInfo, PartitionInfo, PartitionMode,
};
use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, EvidencePacket, FleetProtocolState, GossipConfig, HeartbeatLiveness,
    MessageSignature, NodeId, ProtocolError, ProtocolVersion, QuorumCheckpoint,
    ResolvedContainmentDecision,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn mk_node(name: &str) -> NodeId {
    NodeId::new(name)
}

fn mk_sig(name: &str) -> MessageSignature {
    MessageSignature {
        signer: NodeId::new(name),
        hash: AuthenticityHash::compute_keyed(name.as_bytes(), b"integration-test"),
    }
}

fn mk_config() -> ConvergenceConfig {
    ConvergenceConfig::default()
}

fn mk_engine(name: &str) -> ConvergenceEngine {
    ConvergenceEngine::new(mk_node(name), mk_config())
}

fn mk_fleet(name: &str) -> FleetProtocolState {
    FleetProtocolState::new(NodeId::new(name), GossipConfig::default())
}

fn mk_evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
    EvidencePacket {
        trace_id: format!("itrace-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        evidence_hash: ContentHash::compute(format!("iev-{node}-{ext}-{seq}").as_bytes()),
        posterior_delta_millionths: delta,
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(1),
        node_id: NodeId::new(node),
        sequence: seq,
        timestamp_ns: 1_000_000_000 * seq,
        signature: mk_sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn mk_heartbeat(node: &str, seq: u64, ts_ns: u64) -> HeartbeatLiveness {
    HeartbeatLiveness {
        node_id: NodeId::new(node),
        policy_version: 1,
        evidence_frontier_hash: ContentHash::compute(format!("ifrontier-{node}-{seq}").as_bytes()),
        local_health: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: seq,
        timestamp_ns: ts_ns,
        signature: mk_sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn mk_checkpoint(
    seq: u64,
    summary_hash: ContentHash,
    decisions: Vec<ResolvedContainmentDecision>,
) -> QuorumCheckpoint {
    QuorumCheckpoint {
        checkpoint_seq: seq,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: BTreeSet::new(),
        evidence_summary_hash: summary_hash,
        containment_decisions: decisions,
        quorum_signatures: BTreeMap::new(),
        timestamp_ns: 10_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn mk_receipt(
    action_id: &str,
    ext: &str,
    action: ContainmentAction,
    node: &str,
) -> ContainmentReceipt {
    ContainmentReceipt {
        action_id: action_id.into(),
        extension_id: ext.into(),
        action_type: action,
        evidence_ids: vec![],
        posterior_snapshot: 0,
        policy_version: 1,
        node_id: mk_node(node),
        epoch: SecurityEpoch::GENESIS,
        timestamp_ns: 1_000_000_000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"k", b"v"),
    }
}

// =========================================================================
// Section 1: ContainmentThresholds
// =========================================================================

#[test]
fn thresholds_default_values_are_strictly_ordered() {
    let t = ContainmentThresholds::default();
    assert!(t.is_valid());
    assert_eq!(t.sandbox_threshold, 200_000);
    assert_eq!(t.suspend_threshold, 500_000);
    assert_eq!(t.terminate_threshold, 800_000);
    assert_eq!(t.quarantine_threshold, 950_000);
}

#[test]
fn thresholds_invalid_when_equal() {
    let t = ContainmentThresholds {
        sandbox_threshold: 500_000,
        suspend_threshold: 500_000,
        terminate_threshold: 800_000,
        quarantine_threshold: 950_000,
    };
    assert!(!t.is_valid());
}

#[test]
fn thresholds_invalid_when_reversed() {
    let t = ContainmentThresholds {
        sandbox_threshold: 950_000,
        suspend_threshold: 800_000,
        terminate_threshold: 500_000,
        quarantine_threshold: 200_000,
    };
    assert!(!t.is_valid());
}

#[test]
fn thresholds_evaluate_all_bands() {
    let t = ContainmentThresholds::default();
    // Below sandbox
    assert_eq!(t.evaluate(0), ContainmentAction::Allow);
    assert_eq!(t.evaluate(199_999), ContainmentAction::Allow);
    // Sandbox band
    assert_eq!(t.evaluate(200_000), ContainmentAction::Sandbox);
    assert_eq!(t.evaluate(499_999), ContainmentAction::Sandbox);
    // Suspend band
    assert_eq!(t.evaluate(500_000), ContainmentAction::Suspend);
    assert_eq!(t.evaluate(799_999), ContainmentAction::Suspend);
    // Terminate band
    assert_eq!(t.evaluate(800_000), ContainmentAction::Terminate);
    assert_eq!(t.evaluate(949_999), ContainmentAction::Terminate);
    // Quarantine band
    assert_eq!(t.evaluate(950_000), ContainmentAction::Quarantine);
    assert_eq!(t.evaluate(2_000_000), ContainmentAction::Quarantine);
}

#[test]
fn thresholds_evaluate_negative_always_allow() {
    let t = ContainmentThresholds::default();
    assert_eq!(t.evaluate(-1), ContainmentAction::Allow);
    assert_eq!(t.evaluate(i64::MIN), ContainmentAction::Allow);
}

#[test]
fn thresholds_tighten_zero_factor() {
    let t = ContainmentThresholds::default();
    let zero = t.tighten(0);
    assert_eq!(zero.sandbox_threshold, 0);
    assert_eq!(zero.suspend_threshold, 0);
    assert_eq!(zero.terminate_threshold, 0);
    assert_eq!(zero.quarantine_threshold, 0);
}

#[test]
fn thresholds_tighten_double_factor() {
    let t = ContainmentThresholds::default();
    let doubled = t.tighten(2_000_000);
    assert_eq!(doubled.sandbox_threshold, 400_000);
    assert_eq!(doubled.suspend_threshold, 1_000_000);
    assert_eq!(doubled.terminate_threshold, 1_600_000);
    assert_eq!(doubled.quarantine_threshold, 1_900_000);
}

#[test]
fn thresholds_serde_roundtrip() {
    let t = ContainmentThresholds {
        sandbox_threshold: 100_000,
        suspend_threshold: 200_000,
        terminate_threshold: 300_000,
        quarantine_threshold: 400_000,
    };
    let json = serde_json::to_string(&t).unwrap();
    let decoded: ContainmentThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, decoded);
}

#[test]
fn thresholds_tighten_preserves_ordering_at_75_percent() {
    let t = ContainmentThresholds::default();
    let tightened = t.tighten(750_000);
    assert!(tightened.is_valid());
}

// =========================================================================
// Section 2: PartitionInfo
// =========================================================================

#[test]
fn partition_info_minority_with_zero_fleet() {
    let info = PartitionInfo {
        detected_at_ns: 100,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 0,
        total_fleet_size: 0,
    };
    assert!(info.is_minority(500_000));
}

#[test]
fn partition_info_minority_boundary_values() {
    // Fleet of 10, quorum 50% → need 5
    let minority = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 4,
        total_fleet_size: 10,
    };
    assert!(minority.is_minority(500_000));

    let exactly_at = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 5,
        total_fleet_size: 10,
    };
    assert!(!exactly_at.is_minority(500_000));
}

#[test]
fn partition_info_minority_with_high_quorum() {
    // Fleet of 5, quorum 80% → need ceil(4.0) = 4
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    assert!(info.is_minority(800_000));
}

#[test]
fn partition_info_majority_with_full_fleet() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 10,
        total_fleet_size: 10,
    };
    assert!(!info.is_minority(500_000));
}

#[test]
fn partition_info_serde_roundtrip() {
    let mut unreachable = BTreeSet::new();
    unreachable.insert(mk_node("n1"));
    unreachable.insert(mk_node("n2"));
    let info = PartitionInfo {
        detected_at_ns: 12345,
        unreachable_nodes: unreachable,
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    let json = serde_json::to_string(&info).unwrap();
    let decoded: PartitionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, decoded);
}

// =========================================================================
// Section 3: HealingInfo
// =========================================================================

#[test]
fn healing_info_construction_and_serde() {
    let mut reconciling = BTreeSet::new();
    reconciling.insert(mk_node("r1"));
    let info = HealingInfo {
        heal_started_ns: 5_000_000_000,
        reconciling_nodes: reconciling,
        conflict_count: 3,
        merged_evidence_count: 42,
    };
    let json = serde_json::to_string(&info).unwrap();
    let decoded: HealingInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, decoded);
}

// =========================================================================
// Section 4: PartitionMode
// =========================================================================

#[test]
fn partition_mode_normal_serde() {
    let mode = PartitionMode::Normal;
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

#[test]
fn partition_mode_degraded_serde() {
    let mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 1000,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 2,
        total_fleet_size: 5,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

#[test]
fn partition_mode_healing_serde() {
    let mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 2000,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

// =========================================================================
// Section 5: ConvergenceConfig
// =========================================================================

#[test]
fn convergence_config_defaults() {
    let cfg = ConvergenceConfig::default();
    assert!(cfg.thresholds.is_valid());
    assert_eq!(cfg.degraded_tightening_factor, 750_000);
    assert_eq!(cfg.convergence_timeout_ns, 1_000_000_000);
    assert_eq!(cfg.max_escalation_depth, 3);
    assert_eq!(cfg.signing_key, b"default-convergence-key");
}

#[test]
fn convergence_config_serde_roundtrip() {
    let cfg = ConvergenceConfig {
        thresholds: ContainmentThresholds {
            sandbox_threshold: 100,
            suspend_threshold: 200,
            terminate_threshold: 300,
            quarantine_threshold: 400,
        },
        degraded_tightening_factor: 500_000,
        convergence_timeout_ns: 2_000_000_000,
        signing_key: b"custom-key".to_vec(),
        max_escalation_depth: 5,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ConvergenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg.thresholds, decoded.thresholds);
    assert_eq!(
        cfg.degraded_tightening_factor,
        decoded.degraded_tightening_factor
    );
    assert_eq!(cfg.convergence_timeout_ns, decoded.convergence_timeout_ns);
    assert_eq!(cfg.max_escalation_depth, decoded.max_escalation_depth);
}

// =========================================================================
// Section 6: ContainmentReceipt
// =========================================================================

#[test]
fn receipt_signing_preimage_deterministic() {
    let receipt = ContainmentReceipt {
        action_id: "a-1".into(),
        extension_id: "ext-1".into(),
        action_type: ContainmentAction::Sandbox,
        evidence_ids: vec!["t1".into()],
        posterior_snapshot: 300_000,
        policy_version: 1,
        node_id: mk_node("local"),
        epoch: SecurityEpoch::from_raw(2),
        timestamp_ns: 5_000_000_000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"x", b"y"),
    };
    let p1 = receipt.signing_preimage();
    let p2 = receipt.signing_preimage();
    assert_eq!(p1, p2);
}

#[test]
fn receipt_verify_correct_key() {
    let key = b"my-signing-key";
    let mut receipt = ContainmentReceipt {
        action_id: "a-1".into(),
        extension_id: "ext-1".into(),
        action_type: ContainmentAction::Terminate,
        evidence_ids: vec![],
        posterior_snapshot: 850_000,
        policy_version: 2,
        node_id: mk_node("local"),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 3_000_000_000,
        degraded_mode: true,
        escalation_depth: 1,
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    };
    receipt.signature = AuthenticityHash::compute_keyed(key, &receipt.signing_preimage());

    assert!(receipt.verify_signature(key));
    assert!(!receipt.verify_signature(b"wrong-key"));
}

#[test]
fn receipt_different_fields_different_preimage() {
    let r1 = ContainmentReceipt {
        action_id: "a-1".into(),
        extension_id: "ext-1".into(),
        action_type: ContainmentAction::Sandbox,
        evidence_ids: vec![],
        posterior_snapshot: 300_000,
        policy_version: 1,
        node_id: mk_node("local"),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 1_000_000_000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"k", b"v"),
    };
    let r2 = ContainmentReceipt {
        action_id: "a-2".into(), // different
        ..r1.clone()
    };
    assert_ne!(r1.signing_preimage(), r2.signing_preimage());
}

#[test]
fn receipt_serde_roundtrip() {
    let receipt = ContainmentReceipt {
        action_id: "act-99".into(),
        extension_id: "ext-abc".into(),
        action_type: ContainmentAction::Quarantine,
        evidence_ids: vec!["e1".into(), "e2".into(), "e3".into()],
        posterior_snapshot: 999_000,
        policy_version: 5,
        node_id: mk_node("node-z"),
        epoch: SecurityEpoch::from_raw(10),
        timestamp_ns: 42_000_000_000,
        degraded_mode: true,
        escalation_depth: 3,
        signature: AuthenticityHash::compute_keyed(b"key", b"data"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let decoded: ContainmentReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, decoded);
}

#[test]
fn receipt_degraded_mode_in_preimage() {
    let base = ContainmentReceipt {
        action_id: "a-1".into(),
        extension_id: "ext-1".into(),
        action_type: ContainmentAction::Sandbox,
        evidence_ids: vec![],
        posterior_snapshot: 300_000,
        policy_version: 1,
        node_id: mk_node("local"),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 1_000_000_000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"k", b"v"),
    };
    let degraded = ContainmentReceipt {
        degraded_mode: true,
        ..base.clone()
    };
    assert_ne!(base.signing_preimage(), degraded.signing_preimage());
}

// =========================================================================
// Section 7: ConvergenceDecision
// =========================================================================

#[test]
fn convergence_decision_serde_roundtrip() {
    let decision = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Suspend,
        posterior_delta: 600_000,
        crossed_threshold: Some(500_000),
        degraded_mode: false,
        evidence_count: 10,
    };
    let json = serde_json::to_string(&decision).unwrap();
    let decoded: ConvergenceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, decoded);
}

// =========================================================================
// Section 8: ConvergenceEventType Display
// =========================================================================

#[test]
fn event_type_display_all_variants() {
    let cases = vec![
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
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
    }
}

// =========================================================================
// Section 9: ConvergenceEvent
// =========================================================================

#[test]
fn convergence_event_serde_roundtrip() {
    let mut fields = BTreeMap::new();
    fields.insert("key1".into(), "val1".into());
    fields.insert("key2".into(), "val2".into());

    let event = ConvergenceEvent {
        event_type: ConvergenceEventType::EvidenceLag,
        trace_id: "tr-42".into(),
        node_id: mk_node("local"),
        timestamp_ns: 7_000_000_000,
        epoch: SecurityEpoch::from_raw(3),
        fields,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ConvergenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// =========================================================================
// Section 10: ActionRegistry
// =========================================================================

#[test]
fn action_registry_new_is_empty() {
    let reg = ActionRegistry::new();
    assert_eq!(reg.total_actions(), 0);
    assert_eq!(reg.escalation_depth("anything"), 0);
}

#[test]
fn action_registry_default_is_new() {
    let a = ActionRegistry::new();
    let b = ActionRegistry::default();
    assert_eq!(a.total_actions(), b.total_actions());
}

#[test]
fn action_registry_record_multiple_extensions() {
    let mut reg = ActionRegistry::new();
    reg.record(mk_receipt("a1", "ext-1", ContainmentAction::Sandbox, "n"));
    reg.record(mk_receipt("a2", "ext-2", ContainmentAction::Terminate, "n"));

    assert_eq!(reg.total_actions(), 2);
    assert!(reg.is_executed("ext-1", ContainmentAction::Sandbox));
    assert!(reg.is_executed("ext-2", ContainmentAction::Terminate));
    assert!(!reg.is_executed("ext-1", ContainmentAction::Terminate));
    assert!(!reg.is_executed("ext-2", ContainmentAction::Sandbox));
}

#[test]
fn action_registry_record_replaces_at_same_severity() {
    let mut reg = ActionRegistry::new();
    reg.record(mk_receipt("a1", "ext-1", ContainmentAction::Sandbox, "n"));
    reg.record(mk_receipt("a2", "ext-1", ContainmentAction::Sandbox, "n"));
    // Still 1 action (replaced)
    assert_eq!(reg.total_actions(), 1);
    let receipt = reg
        .get_receipt("ext-1", ContainmentAction::Sandbox)
        .unwrap();
    assert_eq!(receipt.action_id, "a2");
}

#[test]
fn action_registry_highest_executed_no_actions() {
    let reg = ActionRegistry::new();
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Allow
    );
}

#[test]
fn action_registry_highest_executed_multiple_severities() {
    let mut reg = ActionRegistry::new();
    reg.record(mk_receipt("a1", "ext-1", ContainmentAction::Sandbox, "n"));
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Sandbox
    );

    reg.record(mk_receipt("a2", "ext-1", ContainmentAction::Terminate, "n"));
    assert_eq!(
        reg.highest_executed_action("ext-1"),
        ContainmentAction::Terminate
    );
}

#[test]
fn action_registry_escalation_increment_saturating() {
    let mut reg = ActionRegistry::new();
    for _ in 0..10 {
        reg.increment_escalation("ext-1");
    }
    assert_eq!(reg.escalation_depth("ext-1"), 10);
}

#[test]
fn action_registry_receipts_for_extension_sorted_by_severity() {
    let mut reg = ActionRegistry::new();
    // Register out of order: Terminate before Sandbox
    reg.record(mk_receipt("a2", "ext-1", ContainmentAction::Terminate, "n"));
    reg.record(mk_receipt("a1", "ext-1", ContainmentAction::Sandbox, "n"));
    reg.record(mk_receipt(
        "a3",
        "ext-1",
        ContainmentAction::Quarantine,
        "n",
    ));

    let receipts = reg.receipts_for_extension("ext-1");
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
    assert_eq!(receipts[1].action_type, ContainmentAction::Terminate);
    assert_eq!(receipts[2].action_type, ContainmentAction::Quarantine);
}

#[test]
fn action_registry_receipts_empty_for_unknown_extension() {
    let reg = ActionRegistry::new();
    assert!(reg.receipts_for_extension("unknown").is_empty());
}

#[test]
fn action_registry_get_receipt_returns_none_for_unexecuted() {
    let reg = ActionRegistry::new();
    assert!(
        reg.get_receipt("ext-1", ContainmentAction::Sandbox)
            .is_none()
    );
}

#[test]
fn action_registry_serde_roundtrip() {
    let mut reg = ActionRegistry::new();
    reg.record(mk_receipt("a1", "ext-1", ContainmentAction::Sandbox, "n"));
    reg.increment_escalation("ext-1");

    let json = serde_json::to_string(&reg).unwrap();
    let decoded: ActionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_actions(), 1);
    assert!(decoded.is_executed("ext-1", ContainmentAction::Sandbox));
    assert_eq!(decoded.escalation_depth("ext-1"), 1);
}

// =========================================================================
// Section 11: ConvergenceEngine — construction and config
// =========================================================================

#[test]
fn engine_new_starts_in_normal_mode() {
    let engine = mk_engine("local");
    assert!(matches!(engine.partition_mode, PartitionMode::Normal));
    assert_eq!(engine.policy_version, 1);
    assert_eq!(engine.current_epoch, SecurityEpoch::GENESIS);
    assert_eq!(engine.action_registry.total_actions(), 0);
    assert!(engine.events.is_empty());
}

#[test]
fn engine_effective_thresholds_normal_mode() {
    let engine = mk_engine("local");
    let effective = engine.effective_thresholds();
    assert_eq!(effective, engine.config.thresholds);
}

#[test]
fn engine_effective_thresholds_degraded_minority() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: {
            let mut s = BTreeSet::new();
            s.insert(mk_node("a"));
            s.insert(mk_node("b"));
            s.insert(mk_node("c"));
            s
        },
        local_partition_size: 1,
        total_fleet_size: 4,
    });
    let effective = engine.effective_thresholds();
    // 200_000 * 750_000 / 1_000_000 = 150_000
    assert_eq!(effective.sandbox_threshold, 150_000);
    assert_eq!(effective.suspend_threshold, 375_000);
}

#[test]
fn engine_effective_thresholds_degraded_majority_uses_base() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: {
            let mut s = BTreeSet::new();
            s.insert(mk_node("a"));
            s
        },
        local_partition_size: 4,
        total_fleet_size: 5,
    });
    // Majority partition: 4 out of 5 with 50% quorum → not minority
    let effective = engine.effective_thresholds();
    assert_eq!(effective, engine.config.thresholds);
}

#[test]
fn engine_effective_thresholds_healing_always_tightened() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let effective = engine.effective_thresholds();
    assert_eq!(effective.sandbox_threshold, 150_000);
}

// =========================================================================
// Section 12: ConvergenceEngine — evaluate_extension
// =========================================================================

#[test]
fn engine_evaluate_extension_allow() {
    let engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 50_000, 3);
    assert_eq!(d.action, ContainmentAction::Allow);
    assert!(d.crossed_threshold.is_none());
    assert!(!d.degraded_mode);
    assert_eq!(d.evidence_count, 3);
}

#[test]
fn engine_evaluate_extension_sandbox() {
    let engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 250_000, 5);
    assert_eq!(d.action, ContainmentAction::Sandbox);
    assert_eq!(d.crossed_threshold, Some(200_000));
}

#[test]
fn engine_evaluate_extension_suspend() {
    let engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 600_000, 10);
    assert_eq!(d.action, ContainmentAction::Suspend);
    assert_eq!(d.crossed_threshold, Some(500_000));
}

#[test]
fn engine_evaluate_extension_terminate() {
    let engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 850_000, 20);
    assert_eq!(d.action, ContainmentAction::Terminate);
    assert_eq!(d.crossed_threshold, Some(800_000));
}

#[test]
fn engine_evaluate_extension_quarantine() {
    let engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 999_000, 50);
    assert_eq!(d.action, ContainmentAction::Quarantine);
    assert_eq!(d.crossed_threshold, Some(950_000));
}

#[test]
fn engine_evaluate_extension_degraded_flag() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let d = engine.evaluate_extension("ext-1", 200_000, 5);
    assert!(d.degraded_mode);
}

// =========================================================================
// Section 13: ConvergenceEngine — execute_decision
// =========================================================================

#[test]
fn engine_execute_allow_returns_none() {
    let mut engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 50_000, 1);
    assert!(engine.execute_decision(&d, 1_000_000_000).is_none());
}

#[test]
fn engine_execute_sandbox_returns_receipt() {
    let mut engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 300_000, 5);
    let receipt = engine.execute_decision(&d, 1_000_000_000).unwrap();
    assert_eq!(receipt.action_type, ContainmentAction::Sandbox);
    assert_eq!(receipt.extension_id, "ext-1");
    assert_eq!(receipt.posterior_snapshot, 300_000);
    assert!(receipt.verify_signature(&engine.config.signing_key));
    assert!(!receipt.degraded_mode);
    assert_eq!(receipt.escalation_depth, 0);
}

#[test]
fn engine_execute_idempotent() {
    let mut engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 300_000, 5);
    assert!(engine.execute_decision(&d, 1_000_000_000).is_some());
    assert!(engine.execute_decision(&d, 2_000_000_000).is_none());
}

#[test]
fn engine_execute_monotonic_no_downgrade() {
    let mut engine = mk_engine("local");

    let terminate = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Terminate,
        posterior_delta: 850_000,
        crossed_threshold: Some(800_000),
        degraded_mode: false,
        evidence_count: 20,
    };
    engine.execute_decision(&terminate, 1_000_000_000).unwrap();

    let sandbox = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 250_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 3,
    };
    assert!(engine.execute_decision(&sandbox, 2_000_000_000).is_none());
}

#[test]
fn engine_execute_emits_action_event() {
    let mut engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 300_000, 5);
    engine.execute_decision(&d, 1_000_000_000);

    let events = engine.events_of_type(&ConvergenceEventType::ActionExecuted);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.get("extension_id").unwrap(), "ext-1");
    assert_eq!(events[0].fields.get("action").unwrap(), "sandbox");
}

#[test]
fn engine_execute_unique_action_ids() {
    let mut engine = mk_engine("local");

    let d1 = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let r1 = engine.execute_decision(&d1, 1_000_000_000).unwrap();

    let d2 = ConvergenceDecision {
        extension_id: "ext-2".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let r2 = engine.execute_decision(&d2, 2_000_000_000).unwrap();

    assert_ne!(r1.action_id, r2.action_id);
}

// =========================================================================
// Section 14: ConvergenceEngine — evaluate_all + process_fleet_state
// =========================================================================

#[test]
fn engine_evaluate_all_empty_fleet() {
    let engine = mk_engine("local");
    let fleet = mk_fleet("local");
    let decisions = engine.evaluate_all(&fleet);
    assert!(decisions.is_empty());
}

#[test]
fn engine_evaluate_all_multiple_extensions() {
    let engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_evidence(&mk_evidence("r1", "ext-a", 1, 300_000))
        .unwrap();
    fleet
        .process_evidence(&mk_evidence("r1", "ext-b", 2, 600_000))
        .unwrap();

    let decisions = engine.evaluate_all(&fleet);
    assert_eq!(decisions.len(), 2);

    let actions: BTreeSet<_> = decisions.iter().map(|d| d.action).collect();
    assert!(actions.contains(&ContainmentAction::Sandbox));
    assert!(actions.contains(&ContainmentAction::Suspend));
}

#[test]
fn engine_process_fleet_state_produces_receipts() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 850_000))
        .unwrap();

    let receipts = engine.process_fleet_state(&fleet, 1_000_000_000);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].action_type, ContainmentAction::Terminate);
}

#[test]
fn engine_process_fleet_state_idempotent() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 300_000))
        .unwrap();

    let first = engine.process_fleet_state(&fleet, 1_000_000_000);
    assert_eq!(first.len(), 1);

    let second = engine.process_fleet_state(&fleet, 2_000_000_000);
    assert!(second.is_empty());
}

// =========================================================================
// Section 15: ConvergenceEngine — partition state transitions
// =========================================================================

#[test]
fn engine_partition_normal_stays_normal_if_no_partitioned_nodes() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_heartbeat(&mk_heartbeat("r1", 1, 5_000_000_000))
        .unwrap();

    // All healthy
    engine.update_partition_state(&fleet, 6_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Normal));
}

#[test]
fn engine_partition_normal_to_degraded() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_heartbeat(&mk_heartbeat("r1", 1, 1_000_000_000))
        .unwrap();
    fleet
        .process_heartbeat(&mk_heartbeat("r2", 1, 1_000_000_000))
        .unwrap();

    // 20s with 15s timeout
    engine.update_partition_state(&fleet, 20_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

    let entered = engine.events_of_type(&ConvergenceEventType::PartitionEntered);
    assert_eq!(entered.len(), 1);
}

#[test]
fn engine_partition_degraded_to_healing() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_heartbeat(&mk_heartbeat("r1", 1, 1_000_000_000))
        .unwrap();
    engine.update_partition_state(&fleet, 20_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

    // Fresh heartbeat
    fleet
        .process_heartbeat(&mk_heartbeat("r1", 2, 19_000_000_000))
        .unwrap();
    engine.update_partition_state(&fleet, 20_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Healing(_)));
}

#[test]
fn engine_partition_healing_to_normal() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_heartbeat(&mk_heartbeat("r1", 1, 1_000_000_000))
        .unwrap();

    // Normal → Degraded
    engine.update_partition_state(&fleet, 20_000_000_000);
    // Degraded → Healing
    fleet
        .process_heartbeat(&mk_heartbeat("r1", 2, 19_000_000_000))
        .unwrap();
    engine.update_partition_state(&fleet, 20_000_000_000);
    // Healing → Normal
    engine.update_partition_state(&fleet, 20_000_000_001);
    assert!(matches!(engine.partition_mode, PartitionMode::Normal));

    let exited = engine.events_of_type(&ConvergenceEventType::PartitionExited);
    assert_eq!(exited.len(), 1);
}

#[test]
fn engine_partition_healing_back_to_degraded_on_repartition() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_heartbeat(&mk_heartbeat("r1", 1, 1_000_000_000))
        .unwrap();
    fleet
        .process_heartbeat(&mk_heartbeat("r2", 1, 1_000_000_000))
        .unwrap();

    // Normal → Degraded
    engine.update_partition_state(&fleet, 20_000_000_000);
    // Degraded → Healing (r1 healed)
    fleet
        .process_heartbeat(&mk_heartbeat("r1", 2, 19_000_000_000))
        .unwrap();
    fleet
        .process_heartbeat(&mk_heartbeat("r2", 2, 19_000_000_000))
        .unwrap();
    engine.update_partition_state(&fleet, 20_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Healing(_)));

    // r2 goes stale again → re-partition during healing
    engine.update_partition_state(&fleet, 40_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));
}

// =========================================================================
// Section 16: ConvergenceEngine — escalation
// =========================================================================

#[test]
fn engine_escalation_from_allow_to_sandbox() {
    let mut engine = mk_engine("local");
    // No initial action
    let receipt = engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();
    assert_eq!(receipt.action_type, ContainmentAction::Sandbox);
}

#[test]
fn engine_escalation_full_chain() {
    let mut engine = mk_engine("local");
    engine.config.max_escalation_depth = 10;

    // sandbox
    let r1 = engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();
    assert_eq!(r1.action_type, ContainmentAction::Sandbox);
    // suspend
    let r2 = engine.escalate("ext-1", 300_000, 5, 2_000_000_000).unwrap();
    assert_eq!(r2.action_type, ContainmentAction::Suspend);
    // terminate
    let r3 = engine.escalate("ext-1", 300_000, 5, 3_000_000_000).unwrap();
    assert_eq!(r3.action_type, ContainmentAction::Terminate);
    // quarantine
    let r4 = engine.escalate("ext-1", 300_000, 5, 4_000_000_000).unwrap();
    assert_eq!(r4.action_type, ContainmentAction::Quarantine);
    // no further escalation
    let err = engine
        .escalate("ext-1", 300_000, 5, 5_000_000_000)
        .unwrap_err();
    assert!(matches!(err, ConvergenceError::AlreadyAtMaxSeverity { .. }));
}

#[test]
fn engine_escalation_max_depth_error() {
    let mut engine = mk_engine("local");
    engine.config.max_escalation_depth = 1;

    engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();
    // depth = 1 after first escalation
    let err = engine
        .escalate("ext-1", 300_000, 5, 2_000_000_000)
        .unwrap_err();
    assert!(matches!(err, ConvergenceError::MaxEscalationReached { .. }));
}

#[test]
fn engine_escalation_emits_events() {
    let mut engine = mk_engine("local");
    engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();

    let events = engine.events_of_type(&ConvergenceEventType::EscalationTriggered);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.get("to_action").unwrap(), "sandbox");
}

#[test]
fn engine_escalation_independent_per_extension() {
    let mut engine = mk_engine("local");
    engine.config.max_escalation_depth = 10;

    engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();
    engine.escalate("ext-2", 300_000, 5, 2_000_000_000).unwrap();

    assert_eq!(engine.action_registry.escalation_depth("ext-1"), 1);
    assert_eq!(engine.action_registry.escalation_depth("ext-2"), 1);
}

// =========================================================================
// Section 17: ConvergenceEngine — checkpoint verification
// =========================================================================

#[test]
fn engine_verify_converged_checkpoint() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    fleet
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 300_000))
        .unwrap();

    let hash = fleet.evidence.summary_hash();
    let checkpoint = mk_checkpoint(1, hash, vec![]);

    let result = engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);
    assert!(matches!(
        result,
        ConvergenceVerification::Converged { checkpoint_seq: 1 }
    ));

    let verified = engine.events_of_type(&ConvergenceEventType::ConvergenceVerified);
    assert_eq!(verified.len(), 1);
}

#[test]
fn engine_verify_diverged_checkpoint() {
    let mut engine = mk_engine("local");
    let fleet = mk_fleet("local");

    let different_hash = ContentHash::compute(b"different");
    let checkpoint = mk_checkpoint(5, different_hash, vec![]);

    let result = engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);
    assert!(matches!(result, ConvergenceVerification::Diverged { .. }));

    let diverged = engine.events_of_type(&ConvergenceEventType::ConvergenceDiverged);
    assert_eq!(diverged.len(), 1);
}

// =========================================================================
// Section 18: ConvergenceEngine — apply_checkpoint_decisions
// =========================================================================

#[test]
fn engine_apply_checkpoint_decisions_creates_receipts() {
    let mut engine = mk_engine("local");
    let decisions = vec![
        ResolvedContainmentDecision {
            extension_id: "ext-1".into(),
            resolved_action: ContainmentAction::Terminate,
            contributing_intent_ids: vec!["i1".into()],
            epoch: SecurityEpoch::from_raw(1),
        },
        ResolvedContainmentDecision {
            extension_id: "ext-2".into(),
            resolved_action: ContainmentAction::Sandbox,
            contributing_intent_ids: vec!["i2".into()],
            epoch: SecurityEpoch::from_raw(1),
        },
    ];

    let receipts = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
    assert_eq!(receipts.len(), 2);
    assert!(
        engine
            .action_registry
            .is_executed("ext-1", ContainmentAction::Terminate)
    );
    assert!(
        engine
            .action_registry
            .is_executed("ext-2", ContainmentAction::Sandbox)
    );
}

#[test]
fn engine_apply_checkpoint_decisions_no_downgrade() {
    let mut engine = mk_engine("local");

    // Execute quarantine locally
    let q = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Quarantine,
        posterior_delta: 1_000_000,
        crossed_threshold: Some(950_000),
        degraded_mode: false,
        evidence_count: 50,
    };
    engine.execute_decision(&q, 1_000_000_000).unwrap();

    // Checkpoint says sandbox — should not downgrade
    let decisions = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Sandbox,
        contributing_intent_ids: vec!["i1".into()],
        epoch: SecurityEpoch::from_raw(1),
    }];

    let receipts = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
    assert!(receipts.is_empty());
    assert_eq!(
        engine.action_registry.highest_executed_action("ext-1"),
        ContainmentAction::Quarantine
    );
}

#[test]
fn engine_apply_checkpoint_decisions_idempotent() {
    let mut engine = mk_engine("local");
    let decisions = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Sandbox,
        contributing_intent_ids: vec!["i1".into()],
        epoch: SecurityEpoch::from_raw(1),
    }];

    let first = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
    assert_eq!(first.len(), 1);

    let second = engine.apply_checkpoint_decisions(&decisions, 6_000_000_000);
    assert!(second.is_empty());
}

// =========================================================================
// Section 19: ConvergenceEngine — reconciliation
// =========================================================================

#[test]
fn engine_reconciliation_conflict_increments_count() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });

    engine.record_reconciliation_conflict(
        "ext-1",
        ContainmentAction::Sandbox,
        ContainmentAction::Terminate,
        1_000_000_000,
    );

    if let PartitionMode::Healing(ref info) = engine.partition_mode {
        assert_eq!(info.conflict_count, 1);
    } else {
        panic!("expected Healing mode");
    }
}

#[test]
fn engine_reconciliation_conflict_emits_event() {
    let mut engine = mk_engine("local");
    engine.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });

    engine.record_reconciliation_conflict(
        "ext-1",
        ContainmentAction::Sandbox,
        ContainmentAction::Quarantine,
        1_000_000_000,
    );

    let events = engine.events_of_type(&ConvergenceEventType::ReconciliationConflict);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].fields.get("resolved_action").unwrap(),
        "quarantine"
    );
}

#[test]
fn engine_reconciliation_conflict_not_healing_still_emits() {
    let mut engine = mk_engine("local");
    // Normal mode — conflict_count won't be incremented but event should still fire
    engine.record_reconciliation_conflict(
        "ext-1",
        ContainmentAction::Sandbox,
        ContainmentAction::Terminate,
        1_000_000_000,
    );
    let events = engine.events_of_type(&ConvergenceEventType::ReconciliationConflict);
    assert_eq!(events.len(), 1);
}

// =========================================================================
// Section 20: ConvergenceEngine — telemetry event ring buffer
// =========================================================================

#[test]
fn engine_events_of_type_filters_correctly() {
    let mut engine = mk_engine("local");

    // Execute two decisions for two extensions
    let d1 = engine.evaluate_extension("ext-1", 300_000, 5);
    engine.execute_decision(&d1, 1_000_000_000);
    let d2 = engine.evaluate_extension("ext-2", 600_000, 10);
    engine.execute_decision(&d2, 2_000_000_000);

    let action_events = engine.events_of_type(&ConvergenceEventType::ActionExecuted);
    assert_eq!(action_events.len(), 2);

    let threshold_events = engine.events_of_type(&ConvergenceEventType::ThresholdCrossed);
    assert!(threshold_events.is_empty());
}

// =========================================================================
// Section 21: ConvergenceVerification
// =========================================================================

#[test]
fn convergence_verification_converged_serde() {
    let v = ConvergenceVerification::Converged { checkpoint_seq: 42 };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn convergence_verification_diverged_serde() {
    let v = ConvergenceVerification::Diverged {
        checkpoint_seq: 7,
        local_summary_hash: ContentHash::compute(b"local"),
        checkpoint_summary_hash: ContentHash::compute(b"remote"),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// =========================================================================
// Section 22: ConvergenceError Display and serde
// =========================================================================

#[test]
fn convergence_error_max_escalation_display() {
    let err = ConvergenceError::MaxEscalationReached {
        extension_id: "ext-xyz".into(),
        depth: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("max escalation depth"));
    assert!(msg.contains("5"));
    assert!(msg.contains("ext-xyz"));
}

#[test]
fn convergence_error_already_max_severity_display() {
    let err = ConvergenceError::AlreadyAtMaxSeverity {
        extension_id: "ext-1".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("quarantine"));
    assert!(msg.contains("ext-1"));
}

#[test]
fn convergence_error_action_already_executed_display() {
    let err = ConvergenceError::ActionAlreadyExecuted {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Sandbox,
    };
    let msg = err.to_string();
    assert!(msg.contains("sandbox"));
    assert!(msg.contains("ext-1"));
}

#[test]
fn convergence_error_invalid_thresholds_display() {
    let err = ConvergenceError::InvalidThresholds;
    assert_eq!(err.to_string(), "invalid threshold configuration");
}

#[test]
fn convergence_error_protocol_display() {
    let proto = ProtocolError::EmptyIntents;
    let err = ConvergenceError::Protocol(proto);
    let msg = err.to_string();
    assert!(msg.contains("protocol error"));
    assert!(msg.contains("no intents"));
}

#[test]
fn convergence_error_from_protocol_error() {
    let proto = ProtocolError::QuorumNotReached {
        required: 3,
        actual: 1,
    };
    let conv: ConvergenceError = proto.into();
    assert!(matches!(conv, ConvergenceError::Protocol(_)));
}

#[test]
fn convergence_error_serde_roundtrip_all_variants() {
    let variants: Vec<ConvergenceError> = vec![
        ConvergenceError::MaxEscalationReached {
            extension_id: "e1".into(),
            depth: 3,
        },
        ConvergenceError::AlreadyAtMaxSeverity {
            extension_id: "e2".into(),
        },
        ConvergenceError::ActionAlreadyExecuted {
            extension_id: "e3".into(),
            action: ContainmentAction::Terminate,
        },
        ConvergenceError::InvalidThresholds,
        ConvergenceError::Protocol(ProtocolError::EmptyIntents),
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let decoded: ConvergenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &decoded);
    }
}

#[test]
fn convergence_error_is_std_error() {
    let err = ConvergenceError::InvalidThresholds;
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// Section 23: ConvergenceEngine serde roundtrip
// =========================================================================

#[test]
fn engine_serde_roundtrip_with_state() {
    let mut engine = mk_engine("local");
    let d = engine.evaluate_extension("ext-1", 300_000, 5);
    engine.execute_decision(&d, 1_000_000_000);

    let json = serde_json::to_string(&engine).unwrap();
    let decoded: ConvergenceEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.node_id, mk_node("local"));
    assert_eq!(decoded.action_registry.total_actions(), 1);
    assert!(
        decoded
            .action_registry
            .is_executed("ext-1", ContainmentAction::Sandbox)
    );
}

// =========================================================================
// Section 24: Deterministic replay — two engines same evidence same result
// =========================================================================

#[test]
fn deterministic_replay_two_engines_same_result() {
    let config = mk_config();
    let engine_a = ConvergenceEngine::new(mk_node("node-a"), config.clone());
    let engine_b = ConvergenceEngine::new(mk_node("node-b"), config);

    let mut fleet_a = mk_fleet("node-a");
    let mut fleet_b = mk_fleet("node-b");

    // Same evidence stream
    let evidence = vec![
        mk_evidence("r1", "ext-1", 1, 200_000),
        mk_evidence("r2", "ext-1", 1, 150_000),
        mk_evidence("r1", "ext-2", 2, 900_000),
    ];

    for ev in &evidence {
        fleet_a.process_evidence(ev).unwrap();
        fleet_b.process_evidence(ev).unwrap();
    }

    let decisions_a = engine_a.evaluate_all(&fleet_a);
    let decisions_b = engine_b.evaluate_all(&fleet_b);

    assert_eq!(decisions_a.len(), decisions_b.len());
    for (da, db) in decisions_a.iter().zip(decisions_b.iter()) {
        assert_eq!(da.action, db.action);
        assert_eq!(da.posterior_delta, db.posterior_delta);
    }
}

#[test]
fn deterministic_replay_same_evidence_same_summary_hash() {
    let mut fleet_a = mk_fleet("node-a");
    let mut fleet_b = mk_fleet("node-b");

    let evidence = vec![
        mk_evidence("r1", "ext-1", 1, 300_000),
        mk_evidence("r2", "ext-1", 1, 200_000),
    ];

    for ev in &evidence {
        fleet_a.process_evidence(ev).unwrap();
        fleet_b.process_evidence(ev).unwrap();
    }

    assert_eq!(
        fleet_a.evidence.summary_hash(),
        fleet_b.evidence.summary_hash()
    );
}

// =========================================================================
// Section 25: Full end-to-end integration
// =========================================================================

#[test]
fn e2e_evidence_to_receipt_to_checkpoint_verification() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    // Accumulate evidence past suspend threshold
    fleet
        .process_evidence(&mk_evidence("a", "ext-1", 1, 300_000))
        .unwrap();
    fleet
        .process_evidence(&mk_evidence("b", "ext-1", 1, 250_000))
        .unwrap();

    let receipts = engine.process_fleet_state(&fleet, 5_000_000_000);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].action_type, ContainmentAction::Suspend);
    assert!(receipts[0].verify_signature(&engine.config.signing_key));

    // Build checkpoint and verify convergence
    let hash = fleet.evidence.summary_hash();
    let checkpoint = mk_checkpoint(1, hash, vec![]);
    let result = engine.verify_against_checkpoint(&fleet, &checkpoint, 6_000_000_000);
    assert!(matches!(result, ConvergenceVerification::Converged { .. }));

    // Idempotent reprocessing
    let again = engine.process_fleet_state(&fleet, 7_000_000_000);
    assert!(again.is_empty());
}

#[test]
fn e2e_partition_tightening_with_evidence() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    // Register heartbeats
    for (i, name) in ["n1", "n2", "n3"].iter().enumerate() {
        fleet
            .process_heartbeat(&mk_heartbeat(name, (i + 1) as u64, 1_000_000_000))
            .unwrap();
    }

    // Only n1 alive at 20s
    fleet
        .process_heartbeat(&mk_heartbeat("n1", 4, 19_000_000_000))
        .unwrap();
    engine.update_partition_state(&fleet, 20_000_000_000);
    assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

    // 170_000 triggers sandbox under tightened thresholds (150_000) but not normal (200_000)
    fleet
        .process_evidence(&mk_evidence("n1", "ext-1", 5, 170_000))
        .unwrap();
    let receipts = engine.process_fleet_state(&fleet, 20_000_000_001);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
    assert!(receipts[0].degraded_mode);
}

#[test]
fn e2e_escalation_then_checkpoint_decisions() {
    let mut engine = mk_engine("local");
    engine.config.max_escalation_depth = 10;

    // Initial sandbox via escalation
    engine.escalate("ext-1", 300_000, 5, 1_000_000_000).unwrap();

    // Checkpoint resolves terminate — should upgrade
    let decisions = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Terminate,
        contributing_intent_ids: vec!["i1".into()],
        epoch: SecurityEpoch::from_raw(1),
    }];

    let receipts = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].action_type, ContainmentAction::Terminate);
}

#[test]
fn e2e_multiple_extensions_different_severities() {
    let mut engine = mk_engine("local");
    let mut fleet = mk_fleet("local");

    // ext-1: just above sandbox
    fleet
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 250_000))
        .unwrap();
    // ext-2: above terminate
    fleet
        .process_evidence(&mk_evidence("r1", "ext-2", 2, 850_000))
        .unwrap();
    // ext-3: below any threshold
    fleet
        .process_evidence(&mk_evidence("r1", "ext-3", 3, 50_000))
        .unwrap();

    let receipts = engine.process_fleet_state(&fleet, 1_000_000_000);
    assert_eq!(receipts.len(), 2); // ext-1 and ext-2

    let types: BTreeMap<_, _> = receipts
        .iter()
        .map(|r| (r.extension_id.clone(), r.action_type))
        .collect();
    assert_eq!(types["ext-1"], ContainmentAction::Sandbox);
    assert_eq!(types["ext-2"], ContainmentAction::Terminate);
}
