#![forbid(unsafe_code)]
//! Comprehensive integration tests for `fleet_immune_protocol`.
//!
//! Covers: ContainmentAction, ProtocolVersion, NodeId, MessageSignature,
//! SequenceRange, EvidencePacket, ContainmentIntent, QuorumCheckpoint,
//! HeartbeatLiveness, ReconciliationRequest, FleetMessage,
//! GossipConfig, DeterministicPrecedence, NodeSequenceTracker,
//! EvidenceAccumulator, NodeHealthTracker, ProtocolError,
//! ResolvedContainmentDecision, FleetProtocolState.
//! Plus serde round-trips, Display impls, deterministic replay, state
//! transitions, and error paths.

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

use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, ContainmentIntent, DeterministicPrecedence, EvidenceAccumulator,
    EvidencePacket, FleetMessage, FleetProtocolState, GossipConfig, HeartbeatLiveness,
    MessageSignature, NodeHealthTracker, NodeId, NodeSequenceTracker, ProtocolError,
    ProtocolVersion, QuorumCheckpoint, ReconciliationRequest, ResolvedContainmentDecision,
    SequenceRange,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── helpers ──────────────────────────────────────────────────────────────

fn mk_sig(node: &str) -> MessageSignature {
    MessageSignature {
        signer: NodeId::new(node),
        hash: AuthenticityHash::compute_keyed(node.as_bytes(), b"integ-test"),
    }
}

fn mk_evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
    EvidencePacket {
        trace_id: format!("ptrace-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        evidence_hash: ContentHash::compute(format!("pev-{node}-{ext}-{seq}").as_bytes()),
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

fn mk_intent(
    node: &str,
    ext: &str,
    action: ContainmentAction,
    seq: u64,
    epoch: u64,
) -> ContainmentIntent {
    ContainmentIntent {
        intent_id: format!("pintent-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        proposed_action: action,
        confidence_millionths: 900_000,
        supporting_evidence_ids: vec![format!("ptrace-{node}-{ext}-1")],
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(epoch),
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
        evidence_frontier_hash: ContentHash::compute(format!("pfrontier-{node}-{seq}").as_bytes()),
        local_health: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: seq,
        timestamp_ns: ts_ns,
        signature: mk_sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn mk_fleet(node: &str) -> FleetProtocolState {
    FleetProtocolState::new(NodeId::new(node), GossipConfig::default())
}

// =========================================================================
// Section 1: ContainmentAction
// =========================================================================

#[test]
fn containment_action_severity_values() {
    assert_eq!(ContainmentAction::Allow.severity(), 0);
    assert_eq!(ContainmentAction::Sandbox.severity(), 1);
    assert_eq!(ContainmentAction::Suspend.severity(), 2);
    assert_eq!(ContainmentAction::Terminate.severity(), 3);
    assert_eq!(ContainmentAction::Quarantine.severity(), 4);
}

#[test]
fn containment_action_severity_ordering() {
    assert!(ContainmentAction::Allow.severity() < ContainmentAction::Sandbox.severity());
    assert!(ContainmentAction::Sandbox.severity() < ContainmentAction::Suspend.severity());
    assert!(ContainmentAction::Suspend.severity() < ContainmentAction::Terminate.severity());
    assert!(ContainmentAction::Terminate.severity() < ContainmentAction::Quarantine.severity());
}

#[test]
fn containment_action_at_least_as_severe() {
    // Every action is at least as severe as itself
    for action in [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ] {
        assert!(action.at_least_as_severe_as(action));
    }
    // Higher severity
    assert!(ContainmentAction::Quarantine.at_least_as_severe_as(ContainmentAction::Allow));
    assert!(ContainmentAction::Terminate.at_least_as_severe_as(ContainmentAction::Suspend));
    // Lower severity
    assert!(!ContainmentAction::Allow.at_least_as_severe_as(ContainmentAction::Sandbox));
    assert!(!ContainmentAction::Sandbox.at_least_as_severe_as(ContainmentAction::Terminate));
}

#[test]
fn containment_action_display_all_variants() {
    assert_eq!(ContainmentAction::Allow.to_string(), "allow");
    assert_eq!(ContainmentAction::Sandbox.to_string(), "sandbox");
    assert_eq!(ContainmentAction::Suspend.to_string(), "suspend");
    assert_eq!(ContainmentAction::Terminate.to_string(), "terminate");
    assert_eq!(ContainmentAction::Quarantine.to_string(), "quarantine");
}

#[test]
fn containment_action_serde_roundtrip() {
    for action in [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ] {
        let json = serde_json::to_string(&action).unwrap();
        let decoded: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }
}

#[test]
fn containment_action_ord_matches_severity() {
    let mut actions = vec![
        ContainmentAction::Quarantine,
        ContainmentAction::Allow,
        ContainmentAction::Terminate,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
    ];
    actions.sort();
    assert_eq!(
        actions,
        vec![
            ContainmentAction::Allow,
            ContainmentAction::Sandbox,
            ContainmentAction::Suspend,
            ContainmentAction::Terminate,
            ContainmentAction::Quarantine,
        ]
    );
}

// =========================================================================
// Section 2: ProtocolVersion
// =========================================================================

#[test]
fn protocol_version_current() {
    assert_eq!(ProtocolVersion::CURRENT.major, 1);
    assert_eq!(ProtocolVersion::CURRENT.minor, 0);
}

#[test]
fn protocol_version_display() {
    assert_eq!(ProtocolVersion::CURRENT.to_string(), "1.0");
    let v = ProtocolVersion {
        major: 3,
        minor: 14,
    };
    assert_eq!(v.to_string(), "3.14");
}

#[test]
fn protocol_version_compatibility_same_major() {
    let v1_0 = ProtocolVersion { major: 1, minor: 0 };
    let v1_1 = ProtocolVersion { major: 1, minor: 1 };
    let v1_5 = ProtocolVersion { major: 1, minor: 5 };

    assert!(v1_0.is_compatible_with(&v1_0));
    assert!(v1_1.is_compatible_with(&v1_0));
    assert!(v1_5.is_compatible_with(&v1_0));
    assert!(v1_5.is_compatible_with(&v1_1));
    // Reader minor < writer minor
    assert!(!v1_0.is_compatible_with(&v1_1));
}

#[test]
fn protocol_version_incompatible_different_major() {
    let v1 = ProtocolVersion { major: 1, minor: 0 };
    let v2 = ProtocolVersion { major: 2, minor: 0 };
    assert!(!v1.is_compatible_with(&v2));
    assert!(!v2.is_compatible_with(&v1));
}

#[test]
fn protocol_version_serde_roundtrip() {
    let v = ProtocolVersion {
        major: 42,
        minor: 7,
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ProtocolVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// =========================================================================
// Section 3: NodeId
// =========================================================================

#[test]
fn node_id_construction_and_access() {
    let n = NodeId::new("test-node");
    assert_eq!(n.as_str(), "test-node");
}

#[test]
fn node_id_display() {
    let n = NodeId::new("alpha-1");
    assert_eq!(n.to_string(), "alpha-1");
}

#[test]
fn node_id_ordering() {
    let a = NodeId::new("alpha");
    let b = NodeId::new("beta");
    let c = NodeId::new("charlie");
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn node_id_equality() {
    assert_eq!(NodeId::new("same"), NodeId::new("same"));
    assert_ne!(NodeId::new("a"), NodeId::new("b"));
}

#[test]
fn node_id_serde_roundtrip() {
    let n = NodeId::new("node-xyz-123");
    let json = serde_json::to_string(&n).unwrap();
    let decoded: NodeId = serde_json::from_str(&json).unwrap();
    assert_eq!(n, decoded);
}

#[test]
fn node_id_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(NodeId::new("c"));
    set.insert(NodeId::new("a"));
    set.insert(NodeId::new("b"));
    let ordered: Vec<_> = set.iter().map(|n| n.as_str()).collect();
    assert_eq!(ordered, vec!["a", "b", "c"]);
}

// =========================================================================
// Section 4: MessageSignature
// =========================================================================

#[test]
fn message_signature_serde_roundtrip() {
    let sig = MessageSignature {
        signer: NodeId::new("node-1"),
        hash: AuthenticityHash::compute_keyed(b"key", b"data"),
    };
    let json = serde_json::to_string(&sig).unwrap();
    let decoded: MessageSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, decoded);
}

// =========================================================================
// Section 5: SequenceRange
// =========================================================================

#[test]
fn sequence_range_normal() {
    let r = SequenceRange::new(1, 5);
    assert_eq!(r.start, 1);
    assert_eq!(r.end, 5);
    assert_eq!(r.len(), 5);
    assert!(!r.is_empty());
}

#[test]
fn sequence_range_single_element() {
    let r = SequenceRange::new(3, 3);
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn sequence_range_inverted_is_empty() {
    let r = SequenceRange::new(10, 5);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
}

#[test]
fn sequence_range_zero_start() {
    let r = SequenceRange::new(0, 0);
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn sequence_range_serde_roundtrip() {
    let r = SequenceRange::new(42, 100);
    let json = serde_json::to_string(&r).unwrap();
    let decoded: SequenceRange = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

// =========================================================================
// Section 6: EvidencePacket
// =========================================================================

#[test]
fn evidence_packet_construction() {
    let packet = mk_evidence("node-1", "ext-1", 1, 500_000);
    assert_eq!(packet.extension_id, "ext-1");
    assert_eq!(packet.posterior_delta_millionths, 500_000);
    assert_eq!(packet.node_id, NodeId::new("node-1"));
    assert_eq!(packet.sequence, 1);
}

#[test]
fn evidence_packet_serde_roundtrip() {
    let mut packet = mk_evidence("node-1", "ext-1", 1, 500_000);
    packet
        .extensions
        .insert("custom-key".into(), "custom-val".into());

    let json = serde_json::to_string(&packet).unwrap();
    let decoded: EvidencePacket = serde_json::from_str(&json).unwrap();
    assert_eq!(packet, decoded);
    assert_eq!(decoded.extensions.get("custom-key").unwrap(), "custom-val");
}

#[test]
fn evidence_packet_negative_delta() {
    let packet = mk_evidence("node-1", "ext-1", 1, -300_000);
    assert_eq!(packet.posterior_delta_millionths, -300_000);
}

// =========================================================================
// Section 7: ContainmentIntent
// =========================================================================

#[test]
fn containment_intent_construction() {
    let intent = mk_intent("node-1", "ext-1", ContainmentAction::Suspend, 1, 1);
    assert_eq!(intent.proposed_action, ContainmentAction::Suspend);
    assert_eq!(intent.extension_id, "ext-1");
    assert_eq!(intent.confidence_millionths, 900_000);
}

#[test]
fn containment_intent_serde_roundtrip() {
    let intent = mk_intent("node-1", "ext-1", ContainmentAction::Quarantine, 5, 3);
    let json = serde_json::to_string(&intent).unwrap();
    let decoded: ContainmentIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(intent, decoded);
}

// =========================================================================
// Section 8: HeartbeatLiveness
// =========================================================================

#[test]
fn heartbeat_construction() {
    let hb = mk_heartbeat("node-1", 1, 5_000_000_000);
    assert_eq!(hb.node_id, NodeId::new("node-1"));
    assert_eq!(hb.sequence, 1);
    assert_eq!(hb.timestamp_ns, 5_000_000_000);
}

#[test]
fn heartbeat_serde_roundtrip() {
    let mut hb = mk_heartbeat("node-1", 10, 50_000_000_000);
    hb.local_health.insert("cpu_pct".into(), "42".into());
    hb.extensions.insert("region".into(), "us-east-1".into());

    let json = serde_json::to_string(&hb).unwrap();
    let decoded: HeartbeatLiveness = serde_json::from_str(&json).unwrap();
    assert_eq!(hb, decoded);
}

// =========================================================================
// Section 9: ReconciliationRequest
// =========================================================================

#[test]
fn reconciliation_request_construction() {
    let mut ranges = BTreeMap::new();
    ranges.insert(NodeId::new("node-1"), SequenceRange::new(5, 10));
    ranges.insert(NodeId::new("node-2"), SequenceRange::new(1, 3));

    let req = ReconciliationRequest {
        node_id: NodeId::new("local"),
        known_frontier_hash: ContentHash::compute(b"frontier"),
        requested_ranges: ranges.clone(),
        epoch: SecurityEpoch::from_raw(2),
        sequence: 1,
        timestamp_ns: 10_000_000_000,
        signature: mk_sig("local"),
        protocol_version: ProtocolVersion::CURRENT,
    };

    assert_eq!(req.requested_ranges.len(), 2);
    assert_eq!(req.requested_ranges[&NodeId::new("node-1")].len(), 6);
}

#[test]
fn reconciliation_request_serde_roundtrip() {
    let mut ranges = BTreeMap::new();
    ranges.insert(NodeId::new("node-1"), SequenceRange::new(5, 10));

    let req = ReconciliationRequest {
        node_id: NodeId::new("local"),
        known_frontier_hash: ContentHash::compute(b"frontier"),
        requested_ranges: ranges,
        epoch: SecurityEpoch::from_raw(2),
        sequence: 1,
        timestamp_ns: 10_000_000_000,
        signature: mk_sig("local"),
        protocol_version: ProtocolVersion::CURRENT,
    };

    let json = serde_json::to_string(&req).unwrap();
    let decoded: ReconciliationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, decoded);
}

// =========================================================================
// Section 10: QuorumCheckpoint
// =========================================================================

#[test]
fn quorum_checkpoint_construction() {
    let mut nodes = BTreeSet::new();
    nodes.insert(NodeId::new("n1"));
    nodes.insert(NodeId::new("n2"));
    nodes.insert(NodeId::new("n3"));

    let checkpoint = QuorumCheckpoint {
        checkpoint_seq: 42,
        epoch: SecurityEpoch::from_raw(5),
        participating_nodes: nodes.clone(),
        evidence_summary_hash: ContentHash::compute(b"summary"),
        containment_decisions: vec![],
        quorum_signatures: BTreeMap::new(),
        timestamp_ns: 100_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };

    assert_eq!(checkpoint.checkpoint_seq, 42);
    assert_eq!(checkpoint.participating_nodes.len(), 3);
}

#[test]
fn quorum_checkpoint_with_decisions_serde_roundtrip() {
    let mut sigs = BTreeMap::new();
    sigs.insert(NodeId::new("n1"), mk_sig("n1"));
    sigs.insert(NodeId::new("n2"), mk_sig("n2"));

    let checkpoint = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: {
            let mut s = BTreeSet::new();
            s.insert(NodeId::new("n1"));
            s.insert(NodeId::new("n2"));
            s
        },
        evidence_summary_hash: ContentHash::compute(b"sum"),
        containment_decisions: vec![ResolvedContainmentDecision {
            extension_id: "ext-1".into(),
            resolved_action: ContainmentAction::Terminate,
            contributing_intent_ids: vec!["i1".into(), "i2".into()],
            epoch: SecurityEpoch::from_raw(1),
        }],
        quorum_signatures: sigs,
        timestamp_ns: 10_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };

    let json = serde_json::to_string(&checkpoint).unwrap();
    let decoded: QuorumCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(checkpoint, decoded);
}

// =========================================================================
// Section 11: ResolvedContainmentDecision
// =========================================================================

#[test]
fn resolved_decision_serde_roundtrip() {
    let d = ResolvedContainmentDecision {
        extension_id: "ext-1".into(),
        resolved_action: ContainmentAction::Suspend,
        contributing_intent_ids: vec!["i-a".into(), "i-b".into()],
        epoch: SecurityEpoch::from_raw(7),
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: ResolvedContainmentDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

// =========================================================================
// Section 12: FleetMessage
// =========================================================================

#[test]
fn fleet_message_evidence_node_id_and_sequence() {
    let packet = mk_evidence("node-1", "ext-1", 3, 500_000);
    let msg = FleetMessage::Evidence(packet);
    assert_eq!(msg.node_id(), &NodeId::new("node-1"));
    assert_eq!(msg.sequence(), Some(3));
}

#[test]
fn fleet_message_intent_node_id_and_sequence() {
    let intent = mk_intent("node-2", "ext-1", ContainmentAction::Sandbox, 7, 1);
    let msg = FleetMessage::Intent(intent);
    assert_eq!(msg.node_id(), &NodeId::new("node-2"));
    assert_eq!(msg.sequence(), Some(7));
}

#[test]
fn fleet_message_heartbeat_node_id_and_sequence() {
    let hb = mk_heartbeat("node-3", 10, 50_000_000_000);
    let msg = FleetMessage::Heartbeat(hb);
    assert_eq!(msg.node_id(), &NodeId::new("node-3"));
    assert_eq!(msg.sequence(), Some(10));
}

#[test]
fn fleet_message_reconciliation_node_id_and_sequence() {
    let req = ReconciliationRequest {
        node_id: NodeId::new("node-4"),
        known_frontier_hash: ContentHash::compute(b"f"),
        requested_ranges: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: 99,
        timestamp_ns: 1_000_000_000,
        signature: mk_sig("node-4"),
        protocol_version: ProtocolVersion::CURRENT,
    };
    let msg = FleetMessage::Reconciliation(req);
    assert_eq!(msg.node_id(), &NodeId::new("node-4"));
    assert_eq!(msg.sequence(), Some(99));
}

#[test]
fn fleet_message_checkpoint_has_no_sequence() {
    let checkpoint = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: BTreeSet::new(),
        evidence_summary_hash: ContentHash::compute(b"s"),
        containment_decisions: vec![],
        quorum_signatures: BTreeMap::new(),
        timestamp_ns: 1_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let msg = FleetMessage::Checkpoint(checkpoint);
    assert_eq!(msg.sequence(), None);
}

#[test]
#[should_panic(expected = "checkpoints have no single originator")]
fn fleet_message_checkpoint_node_id_panics() {
    let checkpoint = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: BTreeSet::new(),
        evidence_summary_hash: ContentHash::compute(b"s"),
        containment_decisions: vec![],
        quorum_signatures: BTreeMap::new(),
        timestamp_ns: 1_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let msg = FleetMessage::Checkpoint(checkpoint);
    let _ = msg.node_id(); // should panic
}

#[test]
fn fleet_message_evidence_serde_roundtrip() {
    let msg = FleetMessage::Evidence(mk_evidence("n1", "ext-1", 1, 100_000));
    let json = serde_json::to_string(&msg).unwrap();
    let decoded: FleetMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn fleet_message_intent_serde_roundtrip() {
    let msg = FleetMessage::Intent(mk_intent(
        "n1",
        "ext-1",
        ContainmentAction::Quarantine,
        1,
        1,
    ));
    let json = serde_json::to_string(&msg).unwrap();
    let decoded: FleetMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(msg, decoded);
}

// =========================================================================
// Section 13: GossipConfig
// =========================================================================

#[test]
fn gossip_config_defaults() {
    let cfg = GossipConfig::default();
    assert_eq!(cfg.fanout, 3);
    assert_eq!(cfg.max_ttl, 10);
    assert_eq!(cfg.heartbeat_interval_ns, 5_000_000_000);
    assert_eq!(cfg.partition_timeout_ns, 15_000_000_000);
    assert_eq!(cfg.bandwidth_ceiling_bytes_per_sec, 1_048_576);
    assert_eq!(cfg.checkpoint_interval_ns, 10_000_000_000);
    assert_eq!(cfg.quorum_threshold_millionths, 500_000);
}

#[test]
fn gossip_config_serde_roundtrip() {
    let cfg = GossipConfig {
        fanout: 5,
        max_ttl: 20,
        heartbeat_interval_ns: 10_000_000_000,
        partition_timeout_ns: 30_000_000_000,
        bandwidth_ceiling_bytes_per_sec: 2_097_152,
        checkpoint_interval_ns: 20_000_000_000,
        quorum_threshold_millionths: 666_666,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: GossipConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// =========================================================================
// Section 14: DeterministicPrecedence
// =========================================================================

#[test]
fn precedence_higher_severity_wins() {
    let a = mk_intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 1);
    let b = mk_intent("node-b", "ext-1", ContainmentAction::Terminate, 1, 1);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
}

#[test]
fn precedence_higher_epoch_wins_on_severity_tie() {
    let a = mk_intent("node-a", "ext-1", ContainmentAction::Suspend, 1, 1);
    let b = mk_intent("node-b", "ext-1", ContainmentAction::Suspend, 1, 5);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    assert_eq!(winner.epoch, SecurityEpoch::from_raw(5));
}

#[test]
fn precedence_smaller_node_id_wins_on_full_tie() {
    let a = mk_intent("alpha", "ext-1", ContainmentAction::Suspend, 1, 1);
    let b = mk_intent("beta", "ext-1", ContainmentAction::Suspend, 1, 1);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    assert_eq!(winner.node_id, NodeId::new("alpha"));
}

#[test]
fn precedence_stable_tiebreak_first_arg_wins() {
    let a = mk_intent("same", "ext-1", ContainmentAction::Sandbox, 1, 1);
    let b = mk_intent("same", "ext-1", ContainmentAction::Sandbox, 1, 1);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    // First argument wins on complete tie
    assert_eq!(winner.intent_id, a.intent_id);
}

#[test]
fn precedence_deterministic_regardless_of_argument_order() {
    let a = mk_intent("alpha", "ext-1", ContainmentAction::Suspend, 1, 1);
    let b = mk_intent("beta", "ext-1", ContainmentAction::Suspend, 1, 1);

    let ab = DeterministicPrecedence::resolve(&a, &b);
    let ba = DeterministicPrecedence::resolve(&b, &a);
    assert_eq!(ab.node_id, ba.node_id);
}

#[test]
fn precedence_resolve_all_empty() {
    assert!(DeterministicPrecedence::resolve_all(&[]).is_none());
}

#[test]
fn precedence_resolve_all_single() {
    let intents = vec![mk_intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1)];
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Sandbox);
}

#[test]
fn precedence_resolve_all_picks_highest_severity() {
    let intents = vec![
        mk_intent("n1", "ext-1", ContainmentAction::Allow, 1, 1),
        mk_intent("n2", "ext-1", ContainmentAction::Quarantine, 1, 1),
        mk_intent("n3", "ext-1", ContainmentAction::Sandbox, 1, 1),
        mk_intent("n4", "ext-1", ContainmentAction::Terminate, 1, 1),
    ];
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
}

#[test]
fn precedence_resolve_all_many_same_severity_picks_smallest_node() {
    let intents = vec![
        mk_intent("charlie", "ext-1", ContainmentAction::Suspend, 1, 1),
        mk_intent("alpha", "ext-1", ContainmentAction::Suspend, 1, 1),
        mk_intent("bravo", "ext-1", ContainmentAction::Suspend, 1, 1),
    ];
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.node_id, NodeId::new("alpha"));
}

// =========================================================================
// Section 15: NodeSequenceTracker
// =========================================================================

#[test]
fn sequence_tracker_new_is_empty() {
    let tracker = NodeSequenceTracker::new();
    assert!(tracker.known_nodes().is_empty());
    assert_eq!(tracker.last_sequence(&NodeId::new("any")), 0);
}

#[test]
fn sequence_tracker_default_same_as_new() {
    let a = NodeSequenceTracker::new();
    let b = NodeSequenceTracker::default();
    assert_eq!(a.known_nodes(), b.known_nodes());
}

#[test]
fn sequence_tracker_accepts_strictly_increasing() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("n1");

    assert!(tracker.accept(&node, 1).is_ok());
    assert!(tracker.accept(&node, 2).is_ok());
    assert!(tracker.accept(&node, 100).is_ok()); // gaps allowed
    assert_eq!(tracker.last_sequence(&node), 100);
}

#[test]
fn sequence_tracker_rejects_replay() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("n1");
    tracker.accept(&node, 5).unwrap();

    let err = tracker.accept(&node, 3).unwrap_err();
    match err {
        ProtocolError::ReplayDetected {
            received_seq,
            last_accepted_seq,
            ..
        } => {
            assert_eq!(received_seq, 3);
            assert_eq!(last_accepted_seq, 5);
        }
        other => panic!("expected ReplayDetected, got {other:?}"),
    }
}

#[test]
fn sequence_tracker_rejects_duplicate() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("n1");
    tracker.accept(&node, 1).unwrap();

    let err = tracker.accept(&node, 1).unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}

#[test]
fn sequence_tracker_independent_per_node() {
    let mut tracker = NodeSequenceTracker::new();
    let a = NodeId::new("a");
    let b = NodeId::new("b");

    tracker.accept(&a, 10).unwrap();
    tracker.accept(&b, 1).unwrap();

    assert_eq!(tracker.last_sequence(&a), 10);
    assert_eq!(tracker.last_sequence(&b), 1);
}

#[test]
fn sequence_tracker_known_nodes() {
    let mut tracker = NodeSequenceTracker::new();
    tracker.accept(&NodeId::new("x"), 1).unwrap();
    tracker.accept(&NodeId::new("y"), 1).unwrap();
    tracker.accept(&NodeId::new("z"), 1).unwrap();

    let known = tracker.known_nodes();
    assert_eq!(known.len(), 3);
    assert!(known.contains(&NodeId::new("x")));
    assert!(known.contains(&NodeId::new("y")));
    assert!(known.contains(&NodeId::new("z")));
}

#[test]
fn sequence_tracker_serde_roundtrip() {
    let mut tracker = NodeSequenceTracker::new();
    tracker.accept(&NodeId::new("n1"), 5).unwrap();
    tracker.accept(&NodeId::new("n2"), 10).unwrap();

    let json = serde_json::to_string(&tracker).unwrap();
    let decoded: NodeSequenceTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.last_sequence(&NodeId::new("n1")), 5);
    assert_eq!(decoded.last_sequence(&NodeId::new("n2")), 10);
}

// =========================================================================
// Section 16: EvidenceAccumulator
// =========================================================================

#[test]
fn accumulator_new_is_empty() {
    let acc = EvidenceAccumulator::new();
    assert!(acc.extensions().is_empty());
    assert_eq!(acc.posterior_delta("any"), 0);
    assert_eq!(acc.evidence_count("any"), 0);
}

#[test]
fn accumulator_default_same_as_new() {
    let a = EvidenceAccumulator::new();
    let b = EvidenceAccumulator::default();
    assert_eq!(a.extensions(), b.extensions());
}

#[test]
fn accumulator_ingest_single() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-1", 1, 500_000)).unwrap();
    assert_eq!(acc.posterior_delta("ext-1"), 500_000);
    assert_eq!(acc.evidence_count("ext-1"), 1);
}

#[test]
fn accumulator_additive_deltas() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-1", 1, 300_000)).unwrap();
    acc.ingest(&mk_evidence("n2", "ext-1", 1, 200_000)).unwrap();

    assert_eq!(acc.posterior_delta("ext-1"), 500_000);
    assert_eq!(acc.evidence_count("ext-1"), 2);
}

#[test]
fn accumulator_negative_deltas() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-1", 1, 500_000)).unwrap();
    acc.ingest(&mk_evidence("n2", "ext-1", 1, -200_000))
        .unwrap();
    assert_eq!(acc.posterior_delta("ext-1"), 300_000);
}

#[test]
fn accumulator_deduplicates_by_trace_id() {
    let mut acc = EvidenceAccumulator::new();
    let packet = mk_evidence("n1", "ext-1", 1, 500_000);
    acc.ingest(&packet).unwrap();

    let err = acc.ingest(&packet).unwrap_err();
    match err {
        ProtocolError::DuplicateEvidence {
            trace_id,
            extension_id,
        } => {
            assert_eq!(trace_id, packet.trace_id);
            assert_eq!(extension_id, "ext-1");
        }
        other => panic!("expected DuplicateEvidence, got {other:?}"),
    }
    // Value not doubled
    assert_eq!(acc.posterior_delta("ext-1"), 500_000);
}

#[test]
fn accumulator_per_extension_isolation() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-a", 1, 100_000)).unwrap();
    acc.ingest(&mk_evidence("n1", "ext-b", 2, 700_000)).unwrap();

    assert_eq!(acc.posterior_delta("ext-a"), 100_000);
    assert_eq!(acc.posterior_delta("ext-b"), 700_000);
    assert_eq!(acc.extensions().len(), 2);
}

#[test]
fn accumulator_summary_hash_deterministic() {
    let mut acc1 = EvidenceAccumulator::new();
    let mut acc2 = EvidenceAccumulator::new();

    for acc in [&mut acc1, &mut acc2] {
        acc.ingest(&mk_evidence("n1", "ext-1", 1, 300_000)).unwrap();
        acc.ingest(&mk_evidence("n2", "ext-1", 1, 200_000)).unwrap();
    }

    assert_eq!(acc1.summary_hash(), acc2.summary_hash());
}

#[test]
fn accumulator_summary_hash_different_state_different_hash() {
    let mut acc1 = EvidenceAccumulator::new();
    acc1.ingest(&mk_evidence("n1", "ext-1", 1, 300_000))
        .unwrap();

    let mut acc2 = EvidenceAccumulator::new();
    acc2.ingest(&mk_evidence("n1", "ext-1", 1, 400_000))
        .unwrap();

    assert_ne!(acc1.summary_hash(), acc2.summary_hash());
}

#[test]
fn accumulator_empty_summary_hash() {
    let acc = EvidenceAccumulator::new();
    // Should produce a valid hash even with no data
    let hash = acc.summary_hash();
    // Two empty accumulators should have the same hash
    let acc2 = EvidenceAccumulator::new();
    assert_eq!(hash, acc2.summary_hash());
}

#[test]
fn accumulator_saturating_add_no_overflow() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-1", 1, i64::MAX))
        .unwrap();
    acc.ingest(&mk_evidence("n2", "ext-1", 1, 1_000_000))
        .unwrap();
    assert_eq!(acc.posterior_delta("ext-1"), i64::MAX);
}

#[test]
fn accumulator_extensions_returns_all() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-z", 1, 100)).unwrap();
    acc.ingest(&mk_evidence("n1", "ext-a", 2, 200)).unwrap();
    acc.ingest(&mk_evidence("n1", "ext-m", 3, 300)).unwrap();

    let exts = acc.extensions();
    assert_eq!(exts.len(), 3);
    // BTreeSet is sorted
    let ordered: Vec<_> = exts.iter().cloned().collect();
    assert_eq!(ordered, vec!["ext-a", "ext-m", "ext-z"]);
}

#[test]
fn accumulator_serde_roundtrip() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&mk_evidence("n1", "ext-1", 1, 500_000)).unwrap();
    acc.ingest(&mk_evidence("n2", "ext-1", 1, 300_000)).unwrap();

    let json = serde_json::to_string(&acc).unwrap();
    let decoded: EvidenceAccumulator = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.posterior_delta("ext-1"), 800_000);
    assert_eq!(decoded.evidence_count("ext-1"), 2);
}

#[test]
fn accumulator_deterministic_serialization() {
    let mut acc1 = EvidenceAccumulator::new();
    let mut acc2 = EvidenceAccumulator::new();

    for acc in [&mut acc1, &mut acc2] {
        acc.ingest(&mk_evidence("n1", "ext-b", 1, 100)).unwrap();
        acc.ingest(&mk_evidence("n1", "ext-a", 2, 200)).unwrap();
    }

    let json1 = serde_json::to_string(&acc1).unwrap();
    let json2 = serde_json::to_string(&acc2).unwrap();
    assert_eq!(json1, json2);
}

// =========================================================================
// Section 17: NodeHealthTracker
// =========================================================================

#[test]
fn health_tracker_new_is_empty() {
    let tracker = NodeHealthTracker::new();
    assert_eq!(tracker.known_node_count(), 0);
}

#[test]
fn health_tracker_records_heartbeat() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000));

    assert_eq!(tracker.known_node_count(), 1);
    assert_eq!(
        tracker.last_heartbeat_ns(&NodeId::new("n1")),
        Some(5_000_000_000)
    );
}

#[test]
fn health_tracker_updates_timestamp_on_new_heartbeat() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 1_000_000_000));
    tracker.record_heartbeat(&mk_heartbeat("n1", 2, 10_000_000_000));

    assert_eq!(
        tracker.last_heartbeat_ns(&NodeId::new("n1")),
        Some(10_000_000_000)
    );
    assert_eq!(tracker.known_node_count(), 1);
}

#[test]
fn health_tracker_partition_detection() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 1_000_000_000));
    tracker.record_heartbeat(&mk_heartbeat("n2", 1, 1_000_000_000));

    // At 20s with 15s timeout: both partitioned
    let partitioned = tracker.suspected_partitioned(20_000_000_000, 15_000_000_000);
    assert_eq!(partitioned.len(), 2);

    // At 10s with 15s timeout: neither partitioned
    let healthy_time = tracker.suspected_partitioned(10_000_000_000, 15_000_000_000);
    assert!(healthy_time.is_empty());
}

#[test]
fn health_tracker_partial_partition() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 10_000_000_000));
    tracker.record_heartbeat(&mk_heartbeat("n2", 1, 1_000_000_000));

    // At 12s, 5s timeout: n1 healthy (12-10=2 < 5), n2 partitioned (12-1=11 > 5)
    let partitioned = tracker.suspected_partitioned(12_000_000_000, 5_000_000_000);
    assert_eq!(partitioned.len(), 1);
    assert!(partitioned.contains(&NodeId::new("n2")));
}

#[test]
fn health_tracker_healthy_nodes() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 10_000_000_000));
    tracker.record_heartbeat(&mk_heartbeat("n2", 1, 1_000_000_000));

    let healthy = tracker.healthy_nodes(12_000_000_000, 5_000_000_000);
    assert!(healthy.contains(&NodeId::new("n1")));
    assert!(!healthy.contains(&NodeId::new("n2")));
}

#[test]
fn health_tracker_unknown_node_heartbeat_none() {
    let tracker = NodeHealthTracker::new();
    assert!(tracker.last_heartbeat_ns(&NodeId::new("unknown")).is_none());
}

#[test]
fn health_tracker_serde_roundtrip() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000));
    tracker.record_heartbeat(&mk_heartbeat("n2", 1, 7_000_000_000));

    let json = serde_json::to_string(&tracker).unwrap();
    let decoded: NodeHealthTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.known_node_count(), 2);
    assert_eq!(
        decoded.last_heartbeat_ns(&NodeId::new("n1")),
        Some(5_000_000_000)
    );
}

// =========================================================================
// Section 18: ProtocolError Display and serde
// =========================================================================

#[test]
fn protocol_error_replay_display() {
    let err = ProtocolError::ReplayDetected {
        node_id: NodeId::new("n1"),
        received_seq: 3,
        last_accepted_seq: 5,
    };
    let msg = err.to_string();
    assert!(msg.contains("replay detected"));
    assert!(msg.contains("n1"));
    assert!(msg.contains("3"));
    assert!(msg.contains("5"));
}

#[test]
fn protocol_error_duplicate_evidence_display() {
    let err = ProtocolError::DuplicateEvidence {
        trace_id: "tr-1".into(),
        extension_id: "ext-1".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("duplicate evidence"));
    assert!(msg.contains("tr-1"));
}

#[test]
fn protocol_error_incompatible_version_display() {
    let err = ProtocolError::IncompatibleVersion {
        local: ProtocolVersion { major: 1, minor: 0 },
        remote: ProtocolVersion { major: 2, minor: 0 },
    };
    let msg = err.to_string();
    assert!(msg.contains("incompatible protocol version"));
}

#[test]
fn protocol_error_invalid_signature_display() {
    let err = ProtocolError::InvalidSignature {
        node_id: NodeId::new("n1"),
        message_type: "evidence".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("invalid signature"));
    assert!(msg.contains("evidence"));
}

#[test]
fn protocol_error_quorum_not_reached_display() {
    let err = ProtocolError::QuorumNotReached {
        required: 5,
        actual: 2,
    };
    let msg = err.to_string();
    assert!(msg.contains("quorum not reached"));
    assert!(msg.contains("5"));
    assert!(msg.contains("2"));
}

#[test]
fn protocol_error_partitioned_node_display() {
    let err = ProtocolError::PartitionedNode {
        node_id: NodeId::new("n1"),
    };
    let msg = err.to_string();
    assert!(msg.contains("partitioned node"));
}

#[test]
fn protocol_error_empty_intents_display() {
    let err = ProtocolError::EmptyIntents;
    assert_eq!(err.to_string(), "no intents to resolve");
}

#[test]
fn protocol_error_is_std_error() {
    let err = ProtocolError::EmptyIntents;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn protocol_error_serde_roundtrip_all_variants() {
    let variants: Vec<ProtocolError> = vec![
        ProtocolError::ReplayDetected {
            node_id: NodeId::new("n1"),
            received_seq: 3,
            last_accepted_seq: 5,
        },
        ProtocolError::DuplicateEvidence {
            trace_id: "tr-1".into(),
            extension_id: "ext-1".into(),
        },
        ProtocolError::IncompatibleVersion {
            local: ProtocolVersion::CURRENT,
            remote: ProtocolVersion { major: 2, minor: 0 },
        },
        ProtocolError::InvalidSignature {
            node_id: NodeId::new("n1"),
            message_type: "heartbeat".into(),
        },
        ProtocolError::QuorumNotReached {
            required: 5,
            actual: 2,
        },
        ProtocolError::PartitionedNode {
            node_id: NodeId::new("n1"),
        },
        ProtocolError::EmptyIntents,
    ];

    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let decoded: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &decoded);
    }
}

// =========================================================================
// Section 19: FleetProtocolState — construction
// =========================================================================

#[test]
fn fleet_state_construction() {
    let state = mk_fleet("local");
    assert_eq!(state.local_node_id, NodeId::new("local"));
    assert_eq!(state.protocol_version, ProtocolVersion::CURRENT);
    assert_eq!(state.current_epoch, SecurityEpoch::GENESIS);
    assert_eq!(state.last_checkpoint_seq, 0);
    assert_eq!(state.local_sequence, 0);
}

// =========================================================================
// Section 20: FleetProtocolState — next_sequence
// =========================================================================

#[test]
fn fleet_state_next_sequence_monotonic() {
    let mut state = mk_fleet("local");
    assert_eq!(state.next_sequence(), 1);
    assert_eq!(state.next_sequence(), 2);
    assert_eq!(state.next_sequence(), 3);
}

// =========================================================================
// Section 21: FleetProtocolState — process_evidence
// =========================================================================

#[test]
fn fleet_state_process_evidence_success() {
    let mut state = mk_fleet("local");
    state
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 500_000))
        .unwrap();
    assert_eq!(state.evidence.posterior_delta("ext-1"), 500_000);
}

#[test]
fn fleet_state_process_evidence_replay_rejected() {
    let mut state = mk_fleet("local");
    state
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 500_000))
        .unwrap();

    // Same node, same seq
    let err = state
        .process_evidence(&mk_evidence("r1", "ext-2", 1, 100_000))
        .unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}

#[test]
fn fleet_state_process_evidence_incompatible_version() {
    let mut state = mk_fleet("local");
    let mut packet = mk_evidence("r1", "ext-1", 1, 500_000);
    packet.protocol_version = ProtocolVersion { major: 2, minor: 0 };

    let err = state.process_evidence(&packet).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

#[test]
fn fleet_state_process_evidence_higher_minor_version_rejected() {
    let mut state = mk_fleet("local");
    let mut packet = mk_evidence("r1", "ext-1", 1, 500_000);
    // Local is 1.0, remote is 1.1 → local cannot read messages with features it doesn't know
    packet.protocol_version = ProtocolVersion { major: 1, minor: 1 };

    let err = state.process_evidence(&packet).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

// =========================================================================
// Section 22: FleetProtocolState — process_intent
// =========================================================================

#[test]
fn fleet_state_process_intent_success() {
    let mut state = mk_fleet("local");
    let intent = mk_intent("r1", "ext-1", ContainmentAction::Sandbox, 1, 1);
    state.process_intent(&intent).unwrap();

    assert_eq!(state.pending_intents.len(), 1);
    assert_eq!(state.pending_intents["ext-1"].len(), 1);
}

#[test]
fn fleet_state_process_intent_replay_rejected() {
    let mut state = mk_fleet("local");
    let i1 = mk_intent("r1", "ext-1", ContainmentAction::Sandbox, 1, 1);
    state.process_intent(&i1).unwrap();

    let i2 = mk_intent("r1", "ext-1", ContainmentAction::Terminate, 1, 1); // same seq
    let err = state.process_intent(&i2).unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}

#[test]
fn fleet_state_process_multiple_intents_same_extension() {
    let mut state = mk_fleet("local");
    state
        .process_intent(&mk_intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1))
        .unwrap();
    state
        .process_intent(&mk_intent(
            "n2",
            "ext-1",
            ContainmentAction::Terminate,
            1,
            1,
        ))
        .unwrap();

    assert_eq!(state.pending_intents["ext-1"].len(), 2);
}

// =========================================================================
// Section 23: FleetProtocolState — process_heartbeat
// =========================================================================

#[test]
fn fleet_state_process_heartbeat_success() {
    let mut state = mk_fleet("local");
    state
        .process_heartbeat(&mk_heartbeat("r1", 1, 5_000_000_000))
        .unwrap();
    assert_eq!(state.health.known_node_count(), 1);
}

#[test]
fn fleet_state_process_heartbeat_replay_rejected() {
    let mut state = mk_fleet("local");
    state
        .process_heartbeat(&mk_heartbeat("r1", 1, 5_000_000_000))
        .unwrap();

    let err = state
        .process_heartbeat(&mk_heartbeat("r1", 1, 6_000_000_000))
        .unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}

#[test]
fn fleet_state_process_heartbeat_incompatible_version() {
    let mut state = mk_fleet("local");
    let mut hb = mk_heartbeat("r1", 1, 5_000_000_000);
    hb.protocol_version = ProtocolVersion {
        major: 99,
        minor: 0,
    };

    let err = state.process_heartbeat(&hb).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

// =========================================================================
// Section 24: FleetProtocolState — resolve_intents
// =========================================================================

#[test]
fn fleet_state_resolve_intents_picks_highest_severity() {
    let mut state = mk_fleet("local");
    state
        .process_intent(&mk_intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1))
        .unwrap();
    state
        .process_intent(&mk_intent(
            "n2",
            "ext-1",
            ContainmentAction::Terminate,
            1,
            1,
        ))
        .unwrap();

    let winner = state.resolve_intents("ext-1").unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
}

#[test]
fn fleet_state_resolve_intents_none_for_unknown() {
    let state = mk_fleet("local");
    assert!(state.resolve_intents("nonexistent").is_none());
}

// =========================================================================
// Section 25: FleetProtocolState — build_checkpoint
// =========================================================================

#[test]
fn fleet_state_build_checkpoint_success() {
    let mut state = mk_fleet("local");

    // Need healthy nodes for quorum
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000))
        .unwrap();
    state
        .process_heartbeat(&mk_heartbeat("n2", 2, 5_000_000_000))
        .unwrap();

    // Add some evidence and intents
    state
        .process_evidence(&mk_evidence("n1", "ext-1", 2, 300_000))
        .unwrap();
    state
        .process_intent(&mk_intent("n2", "ext-1", ContainmentAction::Sandbox, 3, 1))
        .unwrap();

    let sig = mk_sig("local");
    let checkpoint = state.build_checkpoint(6_000_000_000, sig).unwrap();

    assert_eq!(checkpoint.checkpoint_seq, 1);
    assert_eq!(checkpoint.participating_nodes.len(), 2);
    assert_eq!(checkpoint.containment_decisions.len(), 1);
    assert_eq!(
        checkpoint.containment_decisions[0].resolved_action,
        ContainmentAction::Sandbox
    );
}

#[test]
fn fleet_state_build_checkpoint_quorum_not_reached() {
    let mut state = mk_fleet("local");

    // Register nodes with old heartbeat
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 1_000_000_000))
        .unwrap();

    // At time 20s with 15s timeout, node is partitioned → 0 healthy < 1 required
    let sig = mk_sig("local");
    let err = state.build_checkpoint(20_000_000_000, sig).unwrap_err();
    assert!(matches!(err, ProtocolError::QuorumNotReached { .. }));
}

#[test]
fn fleet_state_build_checkpoint_increments_seq() {
    let mut state = mk_fleet("local");

    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000))
        .unwrap();

    let sig1 = mk_sig("local");
    let c1 = state.build_checkpoint(6_000_000_000, sig1).unwrap();

    state
        .process_heartbeat(&mk_heartbeat("n1", 2, 7_000_000_000))
        .unwrap();
    let sig2 = mk_sig("local");
    let c2 = state.build_checkpoint(8_000_000_000, sig2).unwrap();

    assert_eq!(c1.checkpoint_seq, 1);
    assert_eq!(c2.checkpoint_seq, 2);
}

// =========================================================================
// Section 26: FleetProtocolState — partitioned_nodes
// =========================================================================

#[test]
fn fleet_state_partitioned_nodes_empty_when_all_healthy() {
    let mut state = mk_fleet("local");
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 10_000_000_000))
        .unwrap();

    let partitioned = state.partitioned_nodes(11_000_000_000);
    assert!(partitioned.is_empty());
}

#[test]
fn fleet_state_partitioned_nodes_detected() {
    let mut state = mk_fleet("local");
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 1_000_000_000))
        .unwrap();

    // 20s with default 15s timeout
    let partitioned = state.partitioned_nodes(20_000_000_000);
    assert!(partitioned.contains(&NodeId::new("n1")));
}

// =========================================================================
// Section 27: FleetProtocolState — serde roundtrip
// =========================================================================

#[test]
fn fleet_state_serde_roundtrip() {
    let mut state = mk_fleet("local");
    state
        .process_evidence(&mk_evidence("r1", "ext-1", 1, 500_000))
        .unwrap();
    state
        .process_heartbeat(&mk_heartbeat("r2", 1, 5_000_000_000))
        .unwrap();

    let json = serde_json::to_string(&state).unwrap();
    let decoded: FleetProtocolState = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.evidence.posterior_delta("ext-1"), 500_000);
    assert_eq!(decoded.health.known_node_count(), 1);
}

// =========================================================================
// Section 28: Deterministic replay — two states same evidence same hash
// =========================================================================

#[test]
fn deterministic_replay_same_evidence_same_hash() {
    let mut state_a = mk_fleet("node-a");
    let mut state_b = mk_fleet("node-b");

    let evidence = vec![
        mk_evidence("r1", "ext-1", 1, 300_000),
        mk_evidence("r2", "ext-1", 1, 200_000),
        mk_evidence("r1", "ext-2", 2, 400_000),
    ];

    for ev in &evidence {
        state_a.process_evidence(ev).unwrap();
        state_b.process_evidence(ev).unwrap();
    }

    assert_eq!(
        state_a.evidence.summary_hash(),
        state_b.evidence.summary_hash()
    );
}

#[test]
fn deterministic_replay_intent_resolution_same_winner() {
    let mut state_a = mk_fleet("node-a");
    let mut state_b = mk_fleet("node-b");

    let intents = [
        mk_intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1),
        mk_intent("n2", "ext-1", ContainmentAction::Terminate, 1, 1),
        mk_intent("n3", "ext-1", ContainmentAction::Suspend, 1, 1),
    ];

    for (i, intent) in intents.iter().enumerate() {
        // Need different node names so sequences don't conflict
        let mut intent_a = intent.clone();
        intent_a.sequence = (i + 1) as u64;
        let mut intent_b = intent.clone();
        intent_b.sequence = (i + 1) as u64;
        state_a.process_intent(&intent_a).unwrap();
        state_b.process_intent(&intent_b).unwrap();
    }

    let winner_a = state_a.resolve_intents("ext-1").unwrap();
    let winner_b = state_b.resolve_intents("ext-1").unwrap();
    assert_eq!(winner_a.proposed_action, winner_b.proposed_action);
    assert_eq!(winner_a.node_id, winner_b.node_id);
}

// =========================================================================
// Section 29: Full end-to-end integration
// =========================================================================

#[test]
fn e2e_evidence_accumulation_to_checkpoint() {
    let mut state = mk_fleet("local");

    // Register healthy nodes
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000))
        .unwrap();
    state
        .process_heartbeat(&mk_heartbeat("n2", 2, 5_000_000_000))
        .unwrap();

    // Accumulate evidence
    state
        .process_evidence(&mk_evidence("n1", "ext-1", 2, 300_000))
        .unwrap();
    state
        .process_evidence(&mk_evidence("n2", "ext-1", 3, 250_000))
        .unwrap();

    // Submit intents
    state
        .process_intent(&mk_intent("n1", "ext-1", ContainmentAction::Suspend, 3, 1))
        .unwrap();
    state
        .process_intent(&mk_intent("n2", "ext-1", ContainmentAction::Sandbox, 4, 1))
        .unwrap();

    // Build checkpoint
    let sig = mk_sig("local");
    let checkpoint = state.build_checkpoint(6_000_000_000, sig).unwrap();

    assert_eq!(checkpoint.checkpoint_seq, 1);
    assert!(!checkpoint.participating_nodes.is_empty());
    assert_eq!(checkpoint.containment_decisions.len(), 1);
    // Suspend wins over Sandbox
    assert_eq!(
        checkpoint.containment_decisions[0].resolved_action,
        ContainmentAction::Suspend
    );
    // Evidence hash should match accumulator
    assert_eq!(
        checkpoint.evidence_summary_hash,
        state.evidence.summary_hash()
    );
}

#[test]
fn e2e_partition_detection_via_stale_heartbeats() {
    let mut state = mk_fleet("local");

    // Fresh heartbeats from n1, n2
    state
        .process_heartbeat(&mk_heartbeat("n1", 1, 5_000_000_000))
        .unwrap();
    state
        .process_heartbeat(&mk_heartbeat("n2", 1, 5_000_000_000))
        .unwrap();

    // At 6s: all healthy
    let partitioned = state.partitioned_nodes(6_000_000_000);
    assert!(partitioned.is_empty());

    // At 25s: both stale (25-5=20 > 15s timeout)
    let partitioned = state.partitioned_nodes(25_000_000_000);
    assert_eq!(partitioned.len(), 2);

    // n1 sends fresh heartbeat, n2 stays stale
    state
        .process_heartbeat(&mk_heartbeat("n1", 2, 24_000_000_000))
        .unwrap();
    let partitioned = state.partitioned_nodes(25_000_000_000);
    assert_eq!(partitioned.len(), 1);
    assert!(partitioned.contains(&NodeId::new("n2")));
}

#[test]
fn e2e_multiple_extensions_independent_accumulation() {
    let mut state = mk_fleet("local");

    state
        .process_evidence(&mk_evidence("n1", "ext-a", 1, 100_000))
        .unwrap();
    state
        .process_evidence(&mk_evidence("n1", "ext-b", 2, 200_000))
        .unwrap();
    state
        .process_evidence(&mk_evidence("n2", "ext-a", 1, 50_000))
        .unwrap();
    state
        .process_evidence(&mk_evidence("n2", "ext-b", 2, -100_000))
        .unwrap();

    assert_eq!(state.evidence.posterior_delta("ext-a"), 150_000);
    assert_eq!(state.evidence.posterior_delta("ext-b"), 100_000);
    assert_eq!(state.evidence.evidence_count("ext-a"), 2);
    assert_eq!(state.evidence.evidence_count("ext-b"), 2);
}

#[test]
fn e2e_sequence_tracking_across_message_types() {
    let mut state = mk_fleet("local");

    // evidence at seq 1
    state
        .process_evidence(&mk_evidence("n1", "ext-1", 1, 100_000))
        .unwrap();

    // heartbeat at seq 2 (same node)
    state
        .process_heartbeat(&mk_heartbeat("n1", 2, 5_000_000_000))
        .unwrap();

    // intent at seq 3 (same node)
    state
        .process_intent(&mk_intent("n1", "ext-1", ContainmentAction::Sandbox, 3, 1))
        .unwrap();

    // Replay at seq 2 should fail
    let err = state
        .process_evidence(&mk_evidence("n1", "ext-2", 2, 50_000))
        .unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}
