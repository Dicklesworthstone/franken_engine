//! Integration tests for `fleet_convergence` — thresholds, partitions, action
//! registry, convergence engine, receipts, and error handling.

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
    ContainmentAction, EvidencePacket, GossipConfig, HeartbeatLiveness, MessageSignature, NodeId,
    ProtocolError, ProtocolVersion, QuorumCheckpoint, ResolvedContainmentDecision,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn node(name: &str) -> NodeId {
    NodeId::new(name)
}

fn default_config() -> ConvergenceConfig {
    ConvergenceConfig::default()
}

fn engine(name: &str) -> ConvergenceEngine {
    ConvergenceEngine::new(node(name), default_config())
}

fn custom_engine(name: &str, key: &[u8]) -> ConvergenceEngine {
    let mut cfg = default_config();
    cfg.signing_key = key.to_vec();
    ConvergenceEngine::new(node(name), cfg)
}

fn make_signature(n: &str) -> MessageSignature {
    MessageSignature {
        signer: node(n),
        hash: AuthenticityHash::compute_keyed(n.as_bytes(), b"test"),
    }
}

fn evidence(n: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
    EvidencePacket {
        trace_id: format!("trace-{n}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        evidence_hash: ContentHash::compute(format!("ev-{n}-{ext}-{seq}").as_bytes()),
        posterior_delta_millionths: delta,
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(1),
        node_id: node(n),
        sequence: seq,
        timestamp_ns: 1_000_000_000 * seq,
        signature: make_signature(n),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn heartbeat(n: &str, seq: u64, ts_ns: u64) -> HeartbeatLiveness {
    HeartbeatLiveness {
        node_id: node(n),
        policy_version: 1,
        evidence_frontier_hash: ContentHash::compute(format!("frontier-{n}-{seq}").as_bytes()),
        local_health: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: seq,
        timestamp_ns: ts_ns,
        signature: make_signature(n),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn make_receipt(ext: &str, action: ContainmentAction, n: &str, key: &[u8]) -> ContainmentReceipt {
    let mut receipt = ContainmentReceipt {
        action_id: format!("act-{ext}-{}", action.severity()),
        extension_id: ext.into(),
        action_type: action,
        evidence_ids: vec![],
        posterior_snapshot: 300_000,
        policy_version: 1,
        node_id: node(n),
        epoch: SecurityEpoch::from_raw(1),
        timestamp_ns: 1_000_000_000,
        degraded_mode: false,
        escalation_depth: 0,
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    };
    receipt.signature = AuthenticityHash::compute_keyed(key, &receipt.signing_preimage());
    receipt
}

fn checkpoint(
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

use frankenengine_engine::fleet_immune_protocol::FleetProtocolState;

fn fleet(n: &str) -> FleetProtocolState {
    FleetProtocolState::new(node(n), GossipConfig::default())
}

// ═══════════════════════════════════════════════════════════════════════════
// ContainmentThresholds — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn thresholds_tighten_zero_factor_zeros_all() {
    let t = ContainmentThresholds::default();
    let zeroed = t.tighten(0);
    assert_eq!(zeroed.sandbox_threshold, 0);
    assert_eq!(zeroed.suspend_threshold, 0);
    assert_eq!(zeroed.terminate_threshold, 0);
    assert_eq!(zeroed.quarantine_threshold, 0);
}

#[test]
fn thresholds_tighten_double_loosens() {
    let t = ContainmentThresholds::default();
    let doubled = t.tighten(2_000_000); // 2x
    assert_eq!(doubled.sandbox_threshold, 400_000);
    assert_eq!(doubled.suspend_threshold, 1_000_000);
    assert_eq!(doubled.terminate_threshold, 1_600_000);
    assert_eq!(doubled.quarantine_threshold, 1_900_000);
}

#[test]
fn thresholds_evaluate_exact_boundaries() {
    let t = ContainmentThresholds::default();
    // Exactly at thresholds
    assert_eq!(t.evaluate(200_000), ContainmentAction::Sandbox);
    assert_eq!(t.evaluate(199_999), ContainmentAction::Allow);
    assert_eq!(t.evaluate(500_000), ContainmentAction::Suspend);
    assert_eq!(t.evaluate(499_999), ContainmentAction::Sandbox);
    assert_eq!(t.evaluate(800_000), ContainmentAction::Terminate);
    assert_eq!(t.evaluate(799_999), ContainmentAction::Suspend);
    assert_eq!(t.evaluate(950_000), ContainmentAction::Quarantine);
    assert_eq!(t.evaluate(949_999), ContainmentAction::Terminate);
}

#[test]
fn thresholds_all_equal_is_invalid() {
    let t = ContainmentThresholds {
        sandbox_threshold: 500_000,
        suspend_threshold: 500_000,
        terminate_threshold: 500_000,
        quarantine_threshold: 500_000,
    };
    assert!(!t.is_valid());
}

#[test]
fn thresholds_negative_values_are_valid_if_ordered() {
    let t = ContainmentThresholds {
        sandbox_threshold: -300_000,
        suspend_threshold: -200_000,
        terminate_threshold: -100_000,
        quarantine_threshold: 0,
    };
    assert!(t.is_valid());
}

#[test]
fn thresholds_custom_serde() {
    let t = ContainmentThresholds {
        sandbox_threshold: 100_000,
        suspend_threshold: 400_000,
        terminate_threshold: 700_000,
        quarantine_threshold: 999_999,
    };
    let json = serde_json::to_string(&t).unwrap();
    let decoded: ContainmentThresholds = serde_json::from_str(&json).unwrap();
    assert_eq!(t, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// PartitionInfo — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn partition_info_serde() {
    let info = PartitionInfo {
        detected_at_ns: 123_456_789,
        unreachable_nodes: [node("n1"), node("n2")].into_iter().collect(),
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    let json = serde_json::to_string(&info).unwrap();
    let decoded: PartitionInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, decoded);
}

#[test]
fn partition_info_single_node_fleet_is_minority() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 1,
        total_fleet_size: 1,
    };
    // 50% quorum: need 1, have 1 → not minority
    assert!(!info.is_minority(500_000));
}

#[test]
fn partition_info_high_quorum_threshold() {
    let info = PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: BTreeSet::new(),
        local_partition_size: 3,
        total_fleet_size: 5,
    };
    // 80% quorum: need ceil(0.8*5)=4, have 3 → minority
    assert!(info.is_minority(800_000));
}

// ═══════════════════════════════════════════════════════════════════════════
// HealingInfo — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn healing_info_serde() {
    let info = HealingInfo {
        heal_started_ns: 999_999_999,
        reconciling_nodes: [node("n1"), node("n3")].into_iter().collect(),
        conflict_count: 42,
        merged_evidence_count: 100,
    };
    let json = serde_json::to_string(&info).unwrap();
    let decoded: HealingInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(info, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// PartitionMode — serde all variants
// ═══════════════════════════════════════════════════════════════════════════

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
        detected_at_ns: 100,
        unreachable_nodes: [node("n2")].into_iter().collect(),
        local_partition_size: 2,
        total_fleet_size: 3,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

#[test]
fn partition_mode_healing_serde() {
    let mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 200,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let json = serde_json::to_string(&mode).unwrap();
    let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceConfig — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn config_default_values() {
    let cfg = ConvergenceConfig::default();
    assert!(cfg.thresholds.is_valid());
    assert_eq!(cfg.degraded_tightening_factor, 750_000);
    assert_eq!(cfg.convergence_timeout_ns, 1_000_000_000);
    assert_eq!(cfg.max_escalation_depth, 3);
    assert_eq!(cfg.signing_key, b"default-convergence-key");
}

#[test]
fn config_custom_serde() {
    let cfg = ConvergenceConfig {
        thresholds: ContainmentThresholds {
            sandbox_threshold: 100_000,
            suspend_threshold: 300_000,
            terminate_threshold: 600_000,
            quarantine_threshold: 900_000,
        },
        degraded_tightening_factor: 500_000,
        convergence_timeout_ns: 5_000_000_000,
        signing_key: b"custom-key-123".to_vec(),
        max_escalation_depth: 5,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ConvergenceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ContainmentReceipt — preimage & tamper detection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn receipt_preimage_changes_with_action_id() {
    let key = b"key";
    let r1 = make_receipt("ext-1", ContainmentAction::Sandbox, "n1", key);
    let mut r2 = r1.clone();
    r2.action_id = "different-id".into();
    r2.signature = AuthenticityHash::compute_keyed(key, &r2.signing_preimage());
    assert_ne!(r1.signature, r2.signature);
}

#[test]
fn receipt_tampered_extension_fails_verify() {
    let key = b"key";
    let mut r = make_receipt("ext-1", ContainmentAction::Sandbox, "n1", key);
    assert!(r.verify_signature(key));
    r.extension_id = "tampered".into();
    assert!(!r.verify_signature(key));
}

#[test]
fn receipt_tampered_posterior_fails_verify() {
    let key = b"key";
    let mut r = make_receipt("ext-1", ContainmentAction::Terminate, "n1", key);
    assert!(r.verify_signature(key));
    r.posterior_snapshot = 999_999;
    assert!(!r.verify_signature(key));
}

#[test]
fn receipt_tampered_timestamp_fails_verify() {
    let key = b"key";
    let mut r = make_receipt("ext-1", ContainmentAction::Suspend, "n1", key);
    assert!(r.verify_signature(key));
    r.timestamp_ns = 0;
    assert!(!r.verify_signature(key));
}

#[test]
fn receipt_tampered_degraded_mode_fails_verify() {
    let key = b"key";
    let mut r = make_receipt("ext-1", ContainmentAction::Sandbox, "n1", key);
    assert!(r.verify_signature(key));
    r.degraded_mode = true;
    assert!(!r.verify_signature(key));
}

#[test]
fn receipt_serde_all_actions() {
    for action in [
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ] {
        let r = make_receipt("ext-x", action, "n1", b"k");
        let json = serde_json::to_string(&r).unwrap();
        let decoded: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceDecision — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decision_serde_with_crossed_threshold() {
    let d = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Suspend,
        posterior_delta: 600_000,
        crossed_threshold: Some(500_000),
        degraded_mode: false,
        evidence_count: 10,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: ConvergenceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn decision_serde_allow_no_threshold() {
    let d = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Allow,
        posterior_delta: 50_000,
        crossed_threshold: None,
        degraded_mode: true,
        evidence_count: 3,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: ConvergenceDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
    assert!(decoded.crossed_threshold.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEventType — serde all variants, Display
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn event_type_serde_all_variants() {
    let types = [
        ConvergenceEventType::ThresholdCrossed,
        ConvergenceEventType::ActionExecuted,
        ConvergenceEventType::PartitionEntered,
        ConvergenceEventType::PartitionExited,
        ConvergenceEventType::ReconciliationConflict,
        ConvergenceEventType::ConvergenceVerified,
        ConvergenceEventType::ConvergenceDiverged,
        ConvergenceEventType::EscalationTriggered,
        ConvergenceEventType::EvidenceLag,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let decoded: ConvergenceEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, decoded);
    }
}

#[test]
fn event_type_display_all_variants() {
    let expected = [
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
    for (variant, text) in expected {
        assert_eq!(variant.to_string(), text);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEvent — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn event_serde_with_fields() {
    let event = ConvergenceEvent {
        event_type: ConvergenceEventType::EvidenceLag,
        trace_id: "t-99".into(),
        node_id: node("worker-3"),
        timestamp_ns: 42_000_000_000,
        epoch: SecurityEpoch::from_raw(7),
        fields: {
            let mut m = BTreeMap::new();
            m.insert("lag_ms".into(), "500".into());
            m.insert("extension".into(), "ext-7".into());
            m
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ConvergenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

#[test]
fn event_serde_empty_fields() {
    let event = ConvergenceEvent {
        event_type: ConvergenceEventType::PartitionExited,
        trace_id: "t-0".into(),
        node_id: node("n1"),
        timestamp_ns: 0,
        epoch: SecurityEpoch::GENESIS,
        fields: BTreeMap::new(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: ConvergenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ActionRegistry — edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn registry_multiple_extensions() {
    let mut reg = ActionRegistry::new();
    reg.record(make_receipt(
        "ext-1",
        ContainmentAction::Sandbox,
        "n1",
        b"k",
    ));
    reg.record(make_receipt(
        "ext-2",
        ContainmentAction::Terminate,
        "n1",
        b"k",
    ));
    reg.record(make_receipt(
        "ext-3",
        ContainmentAction::Quarantine,
        "n1",
        b"k",
    ));
    assert_eq!(reg.total_actions(), 3);
    assert!(reg.is_executed("ext-1", ContainmentAction::Sandbox));
    assert!(!reg.is_executed("ext-1", ContainmentAction::Terminate));
    assert!(reg.is_executed("ext-2", ContainmentAction::Terminate));
    assert!(reg.is_executed("ext-3", ContainmentAction::Quarantine));
}

#[test]
fn registry_overwrite_same_key() {
    let mut reg = ActionRegistry::new();
    let r1 = make_receipt("ext-1", ContainmentAction::Sandbox, "n1", b"k");
    let mut r2 = r1.clone();
    r2.posterior_snapshot = 999_999;
    r2.signature = AuthenticityHash::compute_keyed(b"k", &r2.signing_preimage());
    reg.record(r1);
    reg.record(r2.clone());
    assert_eq!(reg.total_actions(), 1);
    let got = reg
        .get_receipt("ext-1", ContainmentAction::Sandbox)
        .unwrap();
    assert_eq!(got.posterior_snapshot, 999_999);
}

#[test]
fn registry_get_receipt_returns_none_for_missing() {
    let reg = ActionRegistry::new();
    assert!(
        reg.get_receipt("ext-1", ContainmentAction::Sandbox)
            .is_none()
    );
}

#[test]
fn registry_receipts_for_extension_empty() {
    let reg = ActionRegistry::new();
    assert!(reg.receipts_for_extension("ext-1").is_empty());
}

#[test]
fn registry_receipts_for_extension_sorted_by_severity() {
    let mut reg = ActionRegistry::new();
    // Insert in reverse severity order
    reg.record(make_receipt(
        "ext-1",
        ContainmentAction::Quarantine,
        "n1",
        b"k",
    ));
    reg.record(make_receipt(
        "ext-1",
        ContainmentAction::Sandbox,
        "n1",
        b"k",
    ));
    reg.record(make_receipt(
        "ext-1",
        ContainmentAction::Suspend,
        "n1",
        b"k",
    ));

    let receipts = reg.receipts_for_extension("ext-1");
    assert_eq!(receipts.len(), 3);
    // Should be ordered by severity (Sandbox=1, Suspend=2, Quarantine=4)
    assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
    assert_eq!(receipts[1].action_type, ContainmentAction::Suspend);
    assert_eq!(receipts[2].action_type, ContainmentAction::Quarantine);
}

#[test]
fn registry_escalation_depth_saturates() {
    let mut reg = ActionRegistry::new();
    for _ in 0..100 {
        reg.increment_escalation("ext-1");
    }
    assert_eq!(reg.escalation_depth("ext-1"), 100);
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = ActionRegistry::new();
    reg.record(make_receipt(
        "ext-1",
        ContainmentAction::Sandbox,
        "n1",
        b"k",
    ));
    reg.increment_escalation("ext-1");
    let json = serde_json::to_string(&reg).unwrap();
    let decoded: ActionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_actions(), 1);
    assert_eq!(decoded.escalation_depth("ext-1"), 1);
    assert!(decoded.is_executed("ext-1", ContainmentAction::Sandbox));
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — construction & thresholds
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_new_is_normal_mode() {
    let e = engine("local");
    assert!(matches!(e.partition_mode, PartitionMode::Normal));
    assert_eq!(e.policy_version, 1);
    assert!(e.events.is_empty());
}

#[test]
fn engine_healing_mode_uses_tightened_thresholds() {
    let mut e = engine("local");
    e.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });
    let effective = e.effective_thresholds();
    assert_eq!(effective.sandbox_threshold, 150_000); // 200_000 * 0.75
}

#[test]
fn engine_degraded_majority_uses_base_thresholds() {
    let mut e = engine("local");
    // Local partition is majority (3 of 4)
    e.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: [node("n1")].into_iter().collect(),
        local_partition_size: 3,
        total_fleet_size: 4,
    });
    // 50% quorum: need 2, have 3 → NOT minority → base thresholds
    let effective = e.effective_thresholds();
    assert_eq!(effective, e.config.thresholds);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — execution edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_execute_signs_with_config_key() {
    let key = b"my-signing-key-42";
    let mut e = custom_engine("local", key);
    let decision = e.evaluate_extension("ext-1", 300_000, 5);
    let receipt = e.execute_decision(&decision, 1_000_000_000).unwrap();
    assert!(receipt.verify_signature(key));
    assert!(!receipt.verify_signature(b"wrong-key"));
}

#[test]
fn engine_execute_unique_action_ids() {
    let mut e = engine("local");
    let d1 = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let d2 = ConvergenceDecision {
        extension_id: "ext-2".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    let r1 = e.execute_decision(&d1, 1_000).unwrap();
    let r2 = e.execute_decision(&d2, 2_000).unwrap();
    assert_ne!(r1.action_id, r2.action_id);
}

#[test]
fn engine_execute_in_degraded_mode_sets_flag() {
    let mut e = engine("local");
    e.partition_mode = PartitionMode::Degraded(PartitionInfo {
        detected_at_ns: 0,
        unreachable_nodes: [node("n1"), node("n2"), node("n3")].into_iter().collect(),
        local_partition_size: 1,
        total_fleet_size: 4,
    });
    let decision = e.evaluate_extension("ext-1", 300_000, 5);
    let receipt = e.execute_decision(&decision, 1_000).unwrap();
    assert!(receipt.degraded_mode);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — escalation edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_escalate_from_allow_to_sandbox() {
    let mut e = engine("local");
    // No prior action → escalate from Allow → Sandbox
    let receipt = e.escalate("ext-1", 100_000, 2, 1_000).unwrap();
    assert_eq!(receipt.action_type, ContainmentAction::Sandbox);
}

#[test]
fn engine_escalate_emits_event() {
    let mut e = engine("local");
    let d = ConvergenceDecision {
        extension_id: "ext-1".into(),
        action: ContainmentAction::Sandbox,
        posterior_delta: 300_000,
        crossed_threshold: Some(200_000),
        degraded_mode: false,
        evidence_count: 5,
    };
    e.execute_decision(&d, 1_000);
    e.escalate("ext-1", 300_000, 5, 2_000).unwrap();
    let events = e.events_of_type(&ConvergenceEventType::EscalationTriggered);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.get("from_action").unwrap(), "sandbox");
    assert_eq!(events[0].fields.get("to_action").unwrap(), "suspend");
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — partition state machine edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_healing_re_partition_goes_back_to_degraded() {
    let mut e = engine("local");
    let mut f = fleet("local");

    // Register heartbeat from one remote node
    f.process_heartbeat(&heartbeat("n1", 1, 1_000_000_000))
        .unwrap();

    // Partition (n1 stale)
    e.update_partition_state(&f, 20_000_000_000);
    assert!(matches!(e.partition_mode, PartitionMode::Degraded(_)));

    // n1 comes back → healing (all partitioned nodes reachable)
    f.process_heartbeat(&heartbeat("n1", 2, 19_000_000_000))
        .unwrap();
    e.update_partition_state(&f, 20_000_000_000);
    assert!(matches!(e.partition_mode, PartitionMode::Healing(_)));

    // n1 goes stale again → back to degraded
    e.update_partition_state(&f, 40_000_000_000);
    assert!(matches!(e.partition_mode, PartitionMode::Degraded(_)));
}

#[test]
fn engine_multiple_reconciliation_conflicts() {
    let mut e = engine("local");
    e.partition_mode = PartitionMode::Healing(HealingInfo {
        heal_started_ns: 0,
        reconciling_nodes: BTreeSet::new(),
        conflict_count: 0,
        merged_evidence_count: 0,
    });

    e.record_reconciliation_conflict(
        "ext-1",
        ContainmentAction::Sandbox,
        ContainmentAction::Terminate,
        1_000,
    );
    e.record_reconciliation_conflict(
        "ext-2",
        ContainmentAction::Allow,
        ContainmentAction::Quarantine,
        2_000,
    );

    if let PartitionMode::Healing(info) = &e.partition_mode {
        assert_eq!(info.conflict_count, 2);
    } else {
        panic!("expected healing");
    }
    let conflicts = e.events_of_type(&ConvergenceEventType::ReconciliationConflict);
    assert_eq!(conflicts.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — checkpoint edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_checkpoint_decisions_idempotent() {
    let mut e = engine("local");
    let decisions = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Sandbox,
        contributing_intent_ids: vec!["i1".into()],
        epoch: SecurityEpoch::from_raw(1),
    }];
    let r1 = e.apply_checkpoint_decisions(&decisions, 1_000);
    assert_eq!(r1.len(), 1);
    let r2 = e.apply_checkpoint_decisions(&decisions, 2_000);
    assert!(r2.is_empty()); // Idempotent
}

#[test]
fn engine_checkpoint_can_escalate_but_not_downgrade() {
    let mut e = engine("local");

    // Initial sandbox
    let sandbox = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Sandbox,
        contributing_intent_ids: vec![],
        epoch: SecurityEpoch::from_raw(1),
    }];
    e.apply_checkpoint_decisions(&sandbox, 1_000);

    // Checkpoint says terminate (escalation) → should work
    let terminate = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Terminate,
        contributing_intent_ids: vec![],
        epoch: SecurityEpoch::from_raw(1),
    }];
    let receipts = e.apply_checkpoint_decisions(&terminate, 2_000);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].action_type, ContainmentAction::Terminate);

    // Checkpoint says suspend (downgrade from terminate) → should not produce receipt
    let suspend = vec![ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Suspend,
        contributing_intent_ids: vec![],
        epoch: SecurityEpoch::from_raw(1),
    }];
    let receipts = e.apply_checkpoint_decisions(&suspend, 3_000);
    assert!(receipts.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceEngine — serde
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn engine_serde_roundtrip() {
    let mut e = engine("local");
    e.current_epoch = SecurityEpoch::from_raw(42);
    e.policy_version = 5;
    let d = e.evaluate_extension("ext-1", 300_000, 5);
    e.execute_decision(&d, 1_000);

    let json = serde_json::to_string(&e).unwrap();
    let decoded: ConvergenceEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.node_id, node("local"));
    assert_eq!(decoded.current_epoch, SecurityEpoch::from_raw(42));
    assert_eq!(decoded.policy_version, 5);
    assert!(
        decoded
            .action_registry
            .is_executed("ext-1", ContainmentAction::Sandbox)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceVerification — serde both variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn verification_converged_serde() {
    let v = ConvergenceVerification::Converged {
        checkpoint_seq: 100,
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn verification_diverged_serde() {
    let v = ConvergenceVerification::Diverged {
        checkpoint_seq: 50,
        local_summary_hash: ContentHash::compute(b"local"),
        checkpoint_summary_hash: ContentHash::compute(b"checkpoint"),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConvergenceError — all variants, Display, std::error::Error
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_all_variants() {
    let errors: Vec<ConvergenceError> = vec![
        ConvergenceError::MaxEscalationReached {
            extension_id: "ext-1".into(),
            depth: 3,
        },
        ConvergenceError::AlreadyAtMaxSeverity {
            extension_id: "ext-2".into(),
        },
        ConvergenceError::ActionAlreadyExecuted {
            extension_id: "ext-3".into(),
            action: ContainmentAction::Terminate,
        },
        ConvergenceError::InvalidThresholds,
        ConvergenceError::Protocol(ProtocolError::EmptyIntents),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }
}

#[test]
fn error_std_error_trait() {
    let err = ConvergenceError::InvalidThresholds;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn error_serde_all_variants() {
    let errors: Vec<ConvergenceError> = vec![
        ConvergenceError::MaxEscalationReached {
            extension_id: "ext-1".into(),
            depth: 5,
        },
        ConvergenceError::AlreadyAtMaxSeverity {
            extension_id: "ext-2".into(),
        },
        ConvergenceError::ActionAlreadyExecuted {
            extension_id: "ext-3".into(),
            action: ContainmentAction::Quarantine,
        },
        ConvergenceError::InvalidThresholds,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: ConvergenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn error_from_protocol_error() {
    let proto = ProtocolError::EmptyIntents;
    let conv: ConvergenceError = proto.into();
    assert!(matches!(conv, ConvergenceError::Protocol(_)));
    assert!(conv.to_string().contains("protocol error"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Full integration scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_two_engines_same_evidence_same_decisions() {
    // Deterministic convergence: two engines given identical evidence
    // produce identical decisions.
    let cfg = ConvergenceConfig {
        signing_key: b"shared-key".to_vec(),
        ..ConvergenceConfig::default()
    };
    let e1 = ConvergenceEngine::new(node("node-1"), cfg.clone());
    let e2 = ConvergenceEngine::new(node("node-2"), cfg);

    // Same evidence, same posterior
    let d1 = e1.evaluate_extension("ext-1", 600_000, 10);
    let d2 = e2.evaluate_extension("ext-1", 600_000, 10);
    assert_eq!(d1.action, d2.action);
    assert_eq!(d1.crossed_threshold, d2.crossed_threshold);
}

#[test]
fn integration_full_lifecycle_evidence_to_quarantine() {
    let mut e = custom_engine("local", b"test-key");
    let mut f = fleet("local");

    // Posterior deltas are cumulative. Thresholds:
    // sandbox=200k, suspend=500k, terminate=800k, quarantine=950k

    // Phase 1: 250k → sandbox (250k >= 200k)
    f.process_evidence(&evidence("remote-1", "ext-1", 1, 250_000))
        .unwrap();
    let r = e.process_fleet_state(&f, 1_000);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].action_type, ContainmentAction::Sandbox);

    // Phase 2: +300k = 550k → suspend (550k >= 500k)
    f.process_evidence(&evidence("remote-2", "ext-1", 1, 300_000))
        .unwrap();
    let r = e.process_fleet_state(&f, 2_000);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].action_type, ContainmentAction::Suspend);

    // Phase 3: +300k = 850k → terminate (850k >= 800k)
    f.process_evidence(&evidence("remote-3", "ext-1", 1, 300_000))
        .unwrap();
    let r = e.process_fleet_state(&f, 3_000);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].action_type, ContainmentAction::Terminate);

    // Phase 4: +200k = 1050k → quarantine (1050k >= 950k)
    f.process_evidence(&evidence("remote-4", "ext-1", 1, 200_000))
        .unwrap();
    let r = e.process_fleet_state(&f, 4_000);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].action_type, ContainmentAction::Quarantine);

    // Phase 5: more evidence → no new receipts (already quarantined)
    f.process_evidence(&evidence("remote-5", "ext-1", 1, 500_000))
        .unwrap();
    let r = e.process_fleet_state(&f, 5_000);
    assert!(r.is_empty());

    // Verify all receipts
    let all = e.action_registry.receipts_for_extension("ext-1");
    assert_eq!(all.len(), 4);
    for receipt in all {
        assert!(receipt.verify_signature(b"test-key"));
    }
}

#[test]
fn integration_convergence_verified_then_diverged() {
    let mut e = engine("local");
    let f = fleet("local");

    // Checkpoint matching empty fleet → converged
    let summary = f.evidence.summary_hash();
    let cp1 = checkpoint(1, summary, vec![]);
    let v1 = e.verify_against_checkpoint(&f, &cp1, 1_000);
    assert!(matches!(v1, ConvergenceVerification::Converged { .. }));

    // Different hash → diverged
    let cp2 = checkpoint(2, ContentHash::compute(b"wrong"), vec![]);
    let v2 = e.verify_against_checkpoint(&f, &cp2, 2_000);
    assert!(matches!(v2, ConvergenceVerification::Diverged { .. }));

    // Events should be recorded
    let verified = e.events_of_type(&ConvergenceEventType::ConvergenceVerified);
    let diverged = e.events_of_type(&ConvergenceEventType::ConvergenceDiverged);
    assert_eq!(verified.len(), 1);
    assert_eq!(diverged.len(), 1);
}

#[test]
fn integration_partition_with_reconciliation_and_healing() {
    let mut e = engine("local");
    let mut f = fleet("local");

    // Register remote nodes
    for n in ["n1", "n2", "n3"] {
        f.process_heartbeat(&heartbeat(n, 1, 1_000_000_000))
            .unwrap();
    }

    // Partition
    e.update_partition_state(&f, 20_000_000_000);
    assert!(matches!(e.partition_mode, PartitionMode::Degraded(_)));

    // All nodes come back → healing
    for n in ["n1", "n2", "n3"] {
        f.process_heartbeat(&heartbeat(n, 2, 19_000_000_000))
            .unwrap();
    }
    e.update_partition_state(&f, 20_000_000_000);
    assert!(matches!(e.partition_mode, PartitionMode::Healing(_)));

    // Record conflicts during healing
    e.record_reconciliation_conflict(
        "ext-1",
        ContainmentAction::Sandbox,
        ContainmentAction::Terminate,
        20_500_000_000,
    );

    // Complete healing
    e.update_partition_state(&f, 20_000_000_001);
    assert!(matches!(e.partition_mode, PartitionMode::Normal));

    // Verify events: entered + reconciliation + exited
    assert_eq!(
        e.events_of_type(&ConvergenceEventType::PartitionEntered)
            .len(),
        1
    );
    assert_eq!(
        e.events_of_type(&ConvergenceEventType::ReconciliationConflict)
            .len(),
        1
    );
    assert_eq!(
        e.events_of_type(&ConvergenceEventType::PartitionExited)
            .len(),
        1
    );
}
