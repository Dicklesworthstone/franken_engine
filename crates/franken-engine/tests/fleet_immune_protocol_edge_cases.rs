//! Edge-case integration tests for `fleet_immune_protocol`.
//!
//! Covers: ContainmentAction, ProtocolVersion, NodeId, MessageSignature,
//! SequenceRange, EvidencePacket, ContainmentIntent, QuorumCheckpoint,
//! HeartbeatLiveness, ReconciliationRequest, FleetMessage,
//! GossipConfig, DeterministicPrecedence, NodeSequenceTracker,
//! EvidenceAccumulator, NodeHealthTracker, ProtocolError,
//! ResolvedContainmentDecision, FleetProtocolState.

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
use std::hash::{DefaultHasher, Hash, Hasher};

use frankenengine_engine::fleet_immune_protocol::{
    ContainmentAction, ContainmentIntent, DeterministicPrecedence, EvidenceAccumulator,
    EvidencePacket, FleetMessage, FleetProtocolState, GossipConfig, HeartbeatLiveness,
    MessageSignature, NodeHealthTracker, NodeId, NodeSequenceTracker, ProtocolError,
    ProtocolVersion, QuorumCheckpoint, ReconciliationRequest, ResolvedContainmentDecision,
    SequenceRange,
};
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Test helpers ────────────────────────────────────────────────────────────

fn sig(node: &str) -> MessageSignature {
    MessageSignature {
        signer: NodeId::new(node),
        hash: AuthenticityHash::compute_keyed(node.as_bytes(), b"test-msg"),
    }
}

fn evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
    EvidencePacket {
        trace_id: format!("t-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        evidence_hash: ContentHash::compute(format!("ev-{node}-{ext}-{seq}").as_bytes()),
        posterior_delta_millionths: delta,
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(1),
        node_id: NodeId::new(node),
        sequence: seq,
        timestamp_ns: 1_000_000_000 * seq,
        signature: sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn intent(
    node: &str,
    ext: &str,
    action: ContainmentAction,
    seq: u64,
    epoch: u64,
) -> ContainmentIntent {
    ContainmentIntent {
        intent_id: format!("i-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        proposed_action: action,
        confidence_millionths: 900_000,
        supporting_evidence_ids: vec![format!("t-{node}-{ext}-1")],
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(epoch),
        node_id: NodeId::new(node),
        sequence: seq,
        timestamp_ns: 1_000_000_000 * seq,
        signature: sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

fn heartbeat(node: &str, seq: u64, ts_ns: u64) -> HeartbeatLiveness {
    HeartbeatLiveness {
        node_id: NodeId::new(node),
        policy_version: 1,
        evidence_frontier_hash: ContentHash::compute(format!("fr-{node}-{seq}").as_bytes()),
        local_health: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: seq,
        timestamp_ns: ts_ns,
        signature: sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

// ── ContainmentAction ───────────────────────────────────────────────────────

#[test]
fn containment_action_severity_exact_values() {
    assert_eq!(ContainmentAction::Allow.severity(), 0);
    assert_eq!(ContainmentAction::Sandbox.severity(), 1);
    assert_eq!(ContainmentAction::Suspend.severity(), 2);
    assert_eq!(ContainmentAction::Terminate.severity(), 3);
    assert_eq!(ContainmentAction::Quarantine.severity(), 4);
}

#[test]
fn containment_action_display_all_five() {
    let pairs = [
        (ContainmentAction::Allow, "allow"),
        (ContainmentAction::Sandbox, "sandbox"),
        (ContainmentAction::Suspend, "suspend"),
        (ContainmentAction::Terminate, "terminate"),
        (ContainmentAction::Quarantine, "quarantine"),
    ];
    for (action, expected) in &pairs {
        assert_eq!(action.to_string(), *expected);
    }
}

#[test]
fn containment_action_serde_all_five_stable() {
    let pairs = [
        (ContainmentAction::Allow, "\"Allow\""),
        (ContainmentAction::Sandbox, "\"Sandbox\""),
        (ContainmentAction::Suspend, "\"Suspend\""),
        (ContainmentAction::Terminate, "\"Terminate\""),
        (ContainmentAction::Quarantine, "\"Quarantine\""),
    ];
    for (action, expected) in &pairs {
        let json = serde_json::to_string(action).unwrap();
        assert_eq!(&json, expected);
        let back: ContainmentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *action);
    }
}

#[test]
fn containment_action_copy_semantics() {
    let a = ContainmentAction::Quarantine;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn containment_action_hash_all_five_distinct() {
    fn h(a: ContainmentAction) -> u64 {
        let mut hasher = DefaultHasher::new();
        a.hash(&mut hasher);
        hasher.finish()
    }
    let hashes: BTreeSet<u64> = [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ]
    .iter()
    .map(|a| h(*a))
    .collect();
    assert_eq!(hashes.len(), 5);
}

#[test]
fn containment_action_ordering_exhaustive() {
    let sorted = [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ];
    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            assert!(sorted[i] < sorted[j]);
        }
    }
}

#[test]
fn containment_action_at_least_as_severe_reflexive() {
    for action in [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ] {
        assert!(action.at_least_as_severe_as(action));
    }
}

#[test]
fn containment_action_at_least_as_severe_transitive() {
    assert!(ContainmentAction::Quarantine.at_least_as_severe_as(ContainmentAction::Allow));
    assert!(ContainmentAction::Terminate.at_least_as_severe_as(ContainmentAction::Sandbox));
    assert!(!ContainmentAction::Allow.at_least_as_severe_as(ContainmentAction::Quarantine));
}

// ── ProtocolVersion ─────────────────────────────────────────────────────────

#[test]
fn protocol_version_current_constant() {
    let current = ProtocolVersion::CURRENT;
    assert_eq!(current.major, 1);
    assert_eq!(current.minor, 0);
}

#[test]
fn protocol_version_serde_round_trip() {
    let v = ProtocolVersion { major: 3, minor: 7 };
    let json = serde_json::to_string(&v).unwrap();
    let back: ProtocolVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn protocol_version_display() {
    assert_eq!(ProtocolVersion { major: 2, minor: 5 }.to_string(), "2.5");
    assert_eq!(ProtocolVersion { major: 0, minor: 0 }.to_string(), "0.0");
}

#[test]
fn protocol_version_compatibility_same_version() {
    let v = ProtocolVersion { major: 1, minor: 3 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn protocol_version_compatibility_reader_newer_minor() {
    let reader = ProtocolVersion { major: 1, minor: 5 };
    let writer = ProtocolVersion { major: 1, minor: 3 };
    assert!(reader.is_compatible_with(&writer));
}

#[test]
fn protocol_version_compatibility_reader_older_minor_fails() {
    let reader = ProtocolVersion { major: 1, minor: 2 };
    let writer = ProtocolVersion { major: 1, minor: 3 };
    assert!(!reader.is_compatible_with(&writer));
}

#[test]
fn protocol_version_compatibility_different_major_fails() {
    let a = ProtocolVersion { major: 1, minor: 0 };
    let b = ProtocolVersion { major: 2, minor: 0 };
    assert!(!a.is_compatible_with(&b));
    assert!(!b.is_compatible_with(&a));
}

#[test]
fn protocol_version_ordering() {
    let v1_0 = ProtocolVersion { major: 1, minor: 0 };
    let v1_1 = ProtocolVersion { major: 1, minor: 1 };
    let v2_0 = ProtocolVersion { major: 2, minor: 0 };
    assert!(v1_0 < v1_1);
    assert!(v1_1 < v2_0);
}

// ── NodeId ──────────────────────────────────────────────────────────────────

#[test]
fn node_id_as_str() {
    let n = NodeId::new("my-node");
    assert_eq!(n.as_str(), "my-node");
}

#[test]
fn node_id_display() {
    assert_eq!(NodeId::new("test").to_string(), "test");
}

#[test]
fn node_id_serde() {
    let n = NodeId::new("serde-node");
    let json = serde_json::to_string(&n).unwrap();
    let back: NodeId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, n);
}

#[test]
fn node_id_hash_distinct() {
    fn h(n: &NodeId) -> u64 {
        let mut hasher = DefaultHasher::new();
        n.hash(&mut hasher);
        hasher.finish()
    }
    let a = NodeId::new("alpha");
    let b = NodeId::new("beta");
    assert_ne!(h(&a), h(&b));
}

#[test]
fn node_id_ordering_lexicographic() {
    assert!(NodeId::new("a") < NodeId::new("b"));
    assert!(NodeId::new("abc") < NodeId::new("abd"));
    assert!(NodeId::new("z") > NodeId::new("a"));
}

#[test]
fn node_id_from_string() {
    let s = String::from("owned-string");
    let n = NodeId::new(s);
    assert_eq!(n.as_str(), "owned-string");
}

#[test]
fn node_id_empty() {
    let n = NodeId::new("");
    assert_eq!(n.as_str(), "");
    assert_eq!(n.to_string(), "");
}

// ── MessageSignature ────────────────────────────────────────────────────────

#[test]
fn message_signature_serde() {
    let s = sig("test-node");
    let json = serde_json::to_string(&s).unwrap();
    let back: MessageSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ── SequenceRange ───────────────────────────────────────────────────────────

#[test]
fn sequence_range_copy_semantics() {
    let a = SequenceRange::new(1, 10);
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn sequence_range_serde() {
    let r = SequenceRange::new(5, 20);
    let json = serde_json::to_string(&r).unwrap();
    let back: SequenceRange = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn sequence_range_zero_to_zero() {
    let r = SequenceRange::new(0, 0);
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn sequence_range_single_element() {
    let r = SequenceRange::new(42, 42);
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
#[should_panic(expected = "overflow")]
fn sequence_range_large_overflows() {
    let r = SequenceRange::new(0, u64::MAX);
    // u64::MAX - 0 + 1 overflows in debug mode
    let _ = r.len();
}

// ── EvidencePacket ──────────────────────────────────────────────────────────

#[test]
fn evidence_packet_with_extensions() {
    let mut p = evidence("node-1", "ext-1", 1, 100_000);
    p.extensions
        .insert("custom_key".to_string(), "custom_value".to_string());
    let json = serde_json::to_string(&p).unwrap();
    let back: EvidencePacket = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extensions["custom_key"], "custom_value");
}

#[test]
fn evidence_packet_negative_delta() {
    let p = evidence("node-1", "ext-1", 1, -500_000);
    assert_eq!(p.posterior_delta_millionths, -500_000);
    let json = serde_json::to_string(&p).unwrap();
    let back: EvidencePacket = serde_json::from_str(&json).unwrap();
    assert_eq!(back.posterior_delta_millionths, -500_000);
}

#[test]
fn evidence_packet_zero_delta() {
    let p = evidence("node-1", "ext-1", 1, 0);
    assert_eq!(p.posterior_delta_millionths, 0);
}

// ── ContainmentIntent ───────────────────────────────────────────────────────

#[test]
fn containment_intent_with_extensions() {
    let mut i = intent("node-1", "ext-1", ContainmentAction::Sandbox, 1, 1);
    i.extensions
        .insert("reason".to_string(), "policy_violation".to_string());
    let json = serde_json::to_string(&i).unwrap();
    let back: ContainmentIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.extensions["reason"], "policy_violation");
}

#[test]
fn containment_intent_multiple_evidence_ids() {
    let mut i = intent("node-1", "ext-1", ContainmentAction::Terminate, 1, 1);
    i.supporting_evidence_ids = vec!["ev-1".to_string(), "ev-2".to_string(), "ev-3".to_string()];
    let json = serde_json::to_string(&i).unwrap();
    let back: ContainmentIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.supporting_evidence_ids.len(), 3);
}

// ── HeartbeatLiveness ───────────────────────────────────────────────────────

#[test]
fn heartbeat_with_local_health() {
    let mut hb = heartbeat("node-1", 1, 5_000_000_000);
    hb.local_health
        .insert("cpu_pct".to_string(), "45".to_string());
    hb.local_health
        .insert("mem_mb".to_string(), "2048".to_string());
    let json = serde_json::to_string(&hb).unwrap();
    let back: HeartbeatLiveness = serde_json::from_str(&json).unwrap();
    assert_eq!(back.local_health.len(), 2);
    assert_eq!(back.local_health["cpu_pct"], "45");
}

#[test]
fn heartbeat_serde_round_trip() {
    let hb = heartbeat("node-1", 1, 5_000_000_000);
    let json = serde_json::to_string(&hb).unwrap();
    let back: HeartbeatLiveness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, hb);
}

// ── ResolvedContainmentDecision ─────────────────────────────────────────────

#[test]
fn resolved_decision_empty_contributing_intents() {
    let d = ResolvedContainmentDecision {
        extension_id: "ext-1".to_string(),
        resolved_action: ContainmentAction::Allow,
        contributing_intent_ids: Vec::new(),
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: ResolvedContainmentDecision = serde_json::from_str(&json).unwrap();
    assert!(back.contributing_intent_ids.is_empty());
}

// ── QuorumCheckpoint ────────────────────────────────────────────────────────

#[test]
fn quorum_checkpoint_empty_decisions() {
    let mut nodes = BTreeSet::new();
    nodes.insert(NodeId::new("n1"));
    let mut sigs = BTreeMap::new();
    sigs.insert(NodeId::new("n1"), sig("n1"));
    let cp = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: nodes,
        evidence_summary_hash: ContentHash::compute(b"empty"),
        containment_decisions: Vec::new(),
        quorum_signatures: sigs,
        timestamp_ns: 1_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let json = serde_json::to_string(&cp).unwrap();
    let back: QuorumCheckpoint = serde_json::from_str(&json).unwrap();
    assert!(back.containment_decisions.is_empty());
    assert_eq!(back.checkpoint_seq, 1);
}

#[test]
fn quorum_checkpoint_multiple_decisions() {
    let mut nodes = BTreeSet::new();
    nodes.insert(NodeId::new("n1"));
    nodes.insert(NodeId::new("n2"));
    let mut sigs = BTreeMap::new();
    sigs.insert(NodeId::new("n1"), sig("n1"));
    sigs.insert(NodeId::new("n2"), sig("n2"));
    let cp = QuorumCheckpoint {
        checkpoint_seq: 5,
        epoch: SecurityEpoch::from_raw(2),
        participating_nodes: nodes,
        evidence_summary_hash: ContentHash::compute(b"multi"),
        containment_decisions: vec![
            ResolvedContainmentDecision {
                extension_id: "ext-1".to_string(),
                resolved_action: ContainmentAction::Terminate,
                contributing_intent_ids: vec!["i-1".to_string()],
                epoch: SecurityEpoch::from_raw(2),
            },
            ResolvedContainmentDecision {
                extension_id: "ext-2".to_string(),
                resolved_action: ContainmentAction::Sandbox,
                contributing_intent_ids: vec!["i-2".to_string(), "i-3".to_string()],
                epoch: SecurityEpoch::from_raw(2),
            },
        ],
        quorum_signatures: sigs,
        timestamp_ns: 10_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let json = serde_json::to_string(&cp).unwrap();
    let back: QuorumCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.containment_decisions.len(), 2);
}

// ── FleetMessage ────────────────────────────────────────────────────────────

#[test]
fn fleet_message_evidence_node_id_and_sequence() {
    let p = evidence("node-x", "ext-1", 7, 100);
    let msg = FleetMessage::Evidence(p);
    assert_eq!(msg.node_id().as_str(), "node-x");
    assert_eq!(msg.sequence(), Some(7));
}

#[test]
fn fleet_message_intent_node_id_and_sequence() {
    let i = intent("node-y", "ext-1", ContainmentAction::Suspend, 3, 1);
    let msg = FleetMessage::Intent(i);
    assert_eq!(msg.node_id().as_str(), "node-y");
    assert_eq!(msg.sequence(), Some(3));
}

#[test]
fn fleet_message_heartbeat_node_id_and_sequence() {
    let hb = heartbeat("node-z", 5, 1_000_000_000);
    let msg = FleetMessage::Heartbeat(hb);
    assert_eq!(msg.node_id().as_str(), "node-z");
    assert_eq!(msg.sequence(), Some(5));
}

#[test]
fn fleet_message_reconciliation_node_id_and_sequence() {
    let req = ReconciliationRequest {
        node_id: NodeId::new("node-r"),
        known_frontier_hash: ContentHash::compute(b"fr"),
        requested_ranges: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: 9,
        timestamp_ns: 1_000_000_000,
        signature: sig("node-r"),
        protocol_version: ProtocolVersion::CURRENT,
    };
    let msg = FleetMessage::Reconciliation(req);
    assert_eq!(msg.node_id().as_str(), "node-r");
    assert_eq!(msg.sequence(), Some(9));
}

#[test]
fn fleet_message_checkpoint_sequence_is_none() {
    let mut nodes = BTreeSet::new();
    nodes.insert(NodeId::new("n1"));
    let mut sigs = BTreeMap::new();
    sigs.insert(NodeId::new("n1"), sig("n1"));
    let cp = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: nodes,
        evidence_summary_hash: ContentHash::compute(b"s"),
        containment_decisions: Vec::new(),
        quorum_signatures: sigs,
        timestamp_ns: 1_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let msg = FleetMessage::Checkpoint(cp);
    assert_eq!(msg.sequence(), None);
}

#[test]
#[should_panic(expected = "checkpoints have no single originator")]
fn fleet_message_checkpoint_node_id_panics() {
    let mut nodes = BTreeSet::new();
    nodes.insert(NodeId::new("n1"));
    let mut sigs = BTreeMap::new();
    sigs.insert(NodeId::new("n1"), sig("n1"));
    let cp = QuorumCheckpoint {
        checkpoint_seq: 1,
        epoch: SecurityEpoch::from_raw(1),
        participating_nodes: nodes,
        evidence_summary_hash: ContentHash::compute(b"s"),
        containment_decisions: Vec::new(),
        quorum_signatures: sigs,
        timestamp_ns: 1_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };
    let msg = FleetMessage::Checkpoint(cp);
    let _ = msg.node_id(); // should panic
}

#[test]
fn fleet_message_serde_all_variants() {
    let msgs: Vec<FleetMessage> = vec![
        FleetMessage::Evidence(evidence("n1", "e1", 1, 100)),
        FleetMessage::Intent(intent("n1", "e1", ContainmentAction::Allow, 2, 1)),
        FleetMessage::Heartbeat(heartbeat("n1", 3, 1_000)),
        FleetMessage::Reconciliation(ReconciliationRequest {
            node_id: NodeId::new("n1"),
            known_frontier_hash: ContentHash::compute(b"f"),
            requested_ranges: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(1),
            sequence: 4,
            timestamp_ns: 1_000,
            signature: sig("n1"),
            protocol_version: ProtocolVersion::CURRENT,
        }),
    ];
    for msg in &msgs {
        let json = serde_json::to_string(msg).unwrap();
        let back: FleetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, msg);
    }
}

// ── GossipConfig ────────────────────────────────────────────────────────────

#[test]
fn gossip_config_default_timing_relationships() {
    let config = GossipConfig::default();
    // Partition timeout should be >= heartbeat interval
    assert!(config.partition_timeout_ns >= config.heartbeat_interval_ns);
    // Default: partition timeout = 3x heartbeat
    assert_eq!(
        config.partition_timeout_ns,
        3 * config.heartbeat_interval_ns
    );
    // Checkpoint interval > heartbeat interval
    assert!(config.checkpoint_interval_ns > config.heartbeat_interval_ns);
}

#[test]
fn gossip_config_quorum_threshold_is_majority() {
    let config = GossipConfig::default();
    assert_eq!(config.quorum_threshold_millionths, 500_000);
}

#[test]
fn gossip_config_custom_values_serde() {
    let config = GossipConfig {
        fanout: 5,
        max_ttl: 20,
        heartbeat_interval_ns: 1_000_000_000,
        partition_timeout_ns: 3_000_000_000,
        bandwidth_ceiling_bytes_per_sec: 10_000_000,
        checkpoint_interval_ns: 5_000_000_000,
        quorum_threshold_millionths: 666_667,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: GossipConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ── DeterministicPrecedence ─────────────────────────────────────────────────

#[test]
fn precedence_first_arg_wins_on_full_tie() {
    // When both intents have identical severity, epoch, and node_id,
    // the first argument wins (stable tiebreak via <=).
    let a = intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 1);
    let b = intent("node-a", "ext-1", ContainmentAction::Sandbox, 2, 1);
    // Same node, same action, same epoch → first arg wins
    let winner = DeterministicPrecedence::resolve(&a, &b);
    assert_eq!(winner.intent_id, a.intent_id);
}

#[test]
fn precedence_severity_trumps_epoch() {
    // Lower severity with higher epoch should lose to higher severity with lower epoch
    let low_sev_high_epoch = intent("node-a", "ext-1", ContainmentAction::Sandbox, 1, 10);
    let high_sev_low_epoch = intent("node-b", "ext-1", ContainmentAction::Quarantine, 1, 1);
    let winner = DeterministicPrecedence::resolve(&low_sev_high_epoch, &high_sev_low_epoch);
    assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
}

#[test]
fn precedence_epoch_trumps_node_id() {
    // Same severity, higher epoch should win even with lexicographically larger node_id
    let low_epoch_small_id = intent("aaa", "ext-1", ContainmentAction::Suspend, 1, 1);
    let high_epoch_large_id = intent("zzz", "ext-1", ContainmentAction::Suspend, 1, 5);
    let winner = DeterministicPrecedence::resolve(&low_epoch_small_id, &high_epoch_large_id);
    assert_eq!(winner.node_id, NodeId::new("zzz"));
}

#[test]
fn precedence_resolve_all_single() {
    let intents = vec![intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1)];
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Sandbox);
}

#[test]
fn precedence_resolve_all_order_independent() {
    let a = intent("node-a", "ext-1", ContainmentAction::Suspend, 1, 1);
    let b = intent("node-b", "ext-1", ContainmentAction::Terminate, 1, 1);
    let c = intent("node-c", "ext-1", ContainmentAction::Sandbox, 1, 1);

    let winner_abc = DeterministicPrecedence::resolve_all(&[a.clone(), b.clone(), c.clone()])
        .unwrap()
        .proposed_action;
    let winner_cab = DeterministicPrecedence::resolve_all(&[c.clone(), a.clone(), b.clone()])
        .unwrap()
        .proposed_action;
    let winner_bca = DeterministicPrecedence::resolve_all(&[b, c, a])
        .unwrap()
        .proposed_action;
    assert_eq!(winner_abc, winner_cab);
    assert_eq!(winner_abc, winner_bca);
    assert_eq!(winner_abc, ContainmentAction::Terminate);
}

// ── NodeSequenceTracker ─────────────────────────────────────────────────────

#[test]
fn sequence_tracker_first_message_seq_zero_rejected() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("n1");
    // Sequence 0 is <= the default 0, so it's rejected
    let err = tracker.accept(&node, 0).unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
}

#[test]
fn sequence_tracker_gaps_allowed() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("n1");
    tracker.accept(&node, 1).unwrap();
    tracker.accept(&node, 100).unwrap(); // gap from 2-99
    assert_eq!(tracker.last_sequence(&node), 100);
}

#[test]
fn sequence_tracker_unknown_node_returns_zero() {
    let tracker = NodeSequenceTracker::new();
    assert_eq!(tracker.last_sequence(&NodeId::new("unknown")), 0);
}

#[test]
fn sequence_tracker_serde() {
    let mut tracker = NodeSequenceTracker::new();
    tracker.accept(&NodeId::new("a"), 5).unwrap();
    tracker.accept(&NodeId::new("b"), 10).unwrap();
    let json = serde_json::to_string(&tracker).unwrap();
    let back: NodeSequenceTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(back.last_sequence(&NodeId::new("a")), 5);
    assert_eq!(back.last_sequence(&NodeId::new("b")), 10);
}

// ── EvidenceAccumulator ─────────────────────────────────────────────────────

#[test]
fn accumulator_empty_summary_hash_deterministic() {
    let a = EvidenceAccumulator::new();
    let b = EvidenceAccumulator::new();
    assert_eq!(a.summary_hash(), b.summary_hash());
}

#[test]
fn accumulator_summary_hash_changes_with_data() {
    let empty = EvidenceAccumulator::new();
    let mut filled = EvidenceAccumulator::new();
    filled.ingest(&evidence("n1", "ext-1", 1, 100_000)).unwrap();
    assert_ne!(empty.summary_hash(), filled.summary_hash());
}

#[test]
fn accumulator_multiple_extensions_summary() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext-a", 1, 100_000)).unwrap();
    acc.ingest(&evidence("n1", "ext-b", 2, 200_000)).unwrap();
    acc.ingest(&evidence("n1", "ext-c", 3, 300_000)).unwrap();
    let exts = acc.extensions();
    assert_eq!(exts.len(), 3);
    assert_eq!(acc.posterior_delta("ext-a"), 100_000);
    assert_eq!(acc.posterior_delta("ext-b"), 200_000);
    assert_eq!(acc.posterior_delta("ext-c"), 300_000);
}

#[test]
fn accumulator_negative_below_zero() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext-1", 1, -500_000)).unwrap();
    assert_eq!(acc.posterior_delta("ext-1"), -500_000);
    acc.ingest(&evidence("n2", "ext-1", 1, -300_000)).unwrap();
    assert_eq!(acc.posterior_delta("ext-1"), -800_000);
}

#[test]
fn accumulator_serde() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext-1", 1, 100_000)).unwrap();
    acc.ingest(&evidence("n2", "ext-1", 1, 200_000)).unwrap();
    let json = serde_json::to_string(&acc).unwrap();
    let back: EvidenceAccumulator = serde_json::from_str(&json).unwrap();
    assert_eq!(back.posterior_delta("ext-1"), 300_000);
    assert_eq!(back.evidence_count("ext-1"), 2);
}

// ── NodeHealthTracker ───────────────────────────────────────────────────────

#[test]
fn health_tracker_unknown_node_heartbeat_none() {
    let tracker = NodeHealthTracker::new();
    assert_eq!(tracker.last_heartbeat_ns(&NodeId::new("unknown")), None);
}

#[test]
fn health_tracker_exact_timeout_boundary() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&heartbeat("n1", 1, 1_000));
    // current - last = timeout exactly → not partitioned (> not >=)
    let partitioned = tracker.suspected_partitioned(1_000 + 5_000, 5_000);
    assert!(partitioned.is_empty());
    // current - last = timeout + 1 → partitioned
    let partitioned = tracker.suspected_partitioned(1_000 + 5_001, 5_000);
    assert_eq!(partitioned.len(), 1);
}

#[test]
fn health_tracker_heartbeat_update_resets_timer() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&heartbeat("n1", 1, 1_000));
    tracker.record_heartbeat(&heartbeat("n1", 2, 10_000)); // later heartbeat
    // At time 14_000 with timeout 5_000: 14000-10000=4000 < 5000 → healthy
    let partitioned = tracker.suspected_partitioned(14_000, 5_000);
    assert!(partitioned.is_empty());
}

#[test]
fn health_tracker_multiple_nodes_mixed_health() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&heartbeat("alive", 1, 10_000));
    tracker.record_heartbeat(&heartbeat("dead", 1, 1_000));
    // At 12_000 with 5_000 timeout: alive(2000) < 5000=healthy, dead(11000) > 5000=partitioned
    let healthy = tracker.healthy_nodes(12_000, 5_000);
    assert!(healthy.contains(&NodeId::new("alive")));
    assert!(!healthy.contains(&NodeId::new("dead")));
    let partitioned = tracker.suspected_partitioned(12_000, 5_000);
    assert!(partitioned.contains(&NodeId::new("dead")));
    assert!(!partitioned.contains(&NodeId::new("alive")));
}

#[test]
fn health_tracker_empty_returns_empty() {
    let tracker = NodeHealthTracker::new();
    assert_eq!(tracker.known_node_count(), 0);
    assert!(tracker.healthy_nodes(100_000, 5_000).is_empty());
    assert!(tracker.suspected_partitioned(100_000, 5_000).is_empty());
}

// ── ProtocolError ───────────────────────────────────────────────────────────

#[test]
fn protocol_error_display_all_variants() {
    let errors = [
        ProtocolError::ReplayDetected {
            node_id: NodeId::new("n1"),
            received_seq: 3,
            last_accepted_seq: 5,
        },
        ProtocolError::DuplicateEvidence {
            trace_id: "t1".to_string(),
            extension_id: "e1".to_string(),
        },
        ProtocolError::IncompatibleVersion {
            local: ProtocolVersion::CURRENT,
            remote: ProtocolVersion { major: 2, minor: 0 },
        },
        ProtocolError::InvalidSignature {
            node_id: NodeId::new("n1"),
            message_type: "Evidence".to_string(),
        },
        ProtocolError::QuorumNotReached {
            required: 3,
            actual: 1,
        },
        ProtocolError::PartitionedNode {
            node_id: NodeId::new("n1"),
        },
        ProtocolError::EmptyIntents,
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn protocol_error_display_contents() {
    let err = ProtocolError::DuplicateEvidence {
        trace_id: "trace-42".to_string(),
        extension_id: "ext-99".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("trace-42"));
    assert!(s.contains("ext-99"));

    let err = ProtocolError::IncompatibleVersion {
        local: ProtocolVersion { major: 1, minor: 0 },
        remote: ProtocolVersion { major: 2, minor: 3 },
    };
    let s = err.to_string();
    assert!(s.contains("1.0"));
    assert!(s.contains("2.3"));

    let err = ProtocolError::QuorumNotReached {
        required: 5,
        actual: 2,
    };
    let s = err.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("2"));
}

#[test]
fn protocol_error_implements_std_error() {
    let err = ProtocolError::EmptyIntents;
    let _: &dyn std::error::Error = &err;
}

#[test]
fn protocol_error_serde_all_variants() {
    let errors = [
        ProtocolError::ReplayDetected {
            node_id: NodeId::new("n1"),
            received_seq: 1,
            last_accepted_seq: 5,
        },
        ProtocolError::DuplicateEvidence {
            trace_id: "t".to_string(),
            extension_id: "e".to_string(),
        },
        ProtocolError::IncompatibleVersion {
            local: ProtocolVersion::CURRENT,
            remote: ProtocolVersion { major: 9, minor: 9 },
        },
        ProtocolError::InvalidSignature {
            node_id: NodeId::new("n"),
            message_type: "Intent".to_string(),
        },
        ProtocolError::QuorumNotReached {
            required: 10,
            actual: 0,
        },
        ProtocolError::PartitionedNode {
            node_id: NodeId::new("p"),
        },
        ProtocolError::EmptyIntents,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ── FleetProtocolState ──────────────────────────────────────────────────────

#[test]
fn state_initial_values() {
    let state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    assert_eq!(state.local_node_id, NodeId::new("local"));
    assert_eq!(state.protocol_version, ProtocolVersion::CURRENT);
    assert_eq!(state.current_epoch, SecurityEpoch::GENESIS);
    assert_eq!(state.last_checkpoint_seq, 0);
    assert_eq!(state.local_sequence, 0);
    assert!(state.pending_intents.is_empty());
}

#[test]
fn state_next_sequence_starts_at_one() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    assert_eq!(state.next_sequence(), 1);
    assert_eq!(state.next_sequence(), 2);
    assert_eq!(state.next_sequence(), 3);
}

#[test]
fn state_process_evidence_version_mismatch() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let mut p = evidence("remote", "ext-1", 1, 100);
    p.protocol_version = ProtocolVersion {
        major: 99,
        minor: 0,
    };
    let err = state.process_evidence(&p).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

#[test]
fn state_process_intent_version_mismatch() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let mut i = intent("remote", "ext-1", ContainmentAction::Allow, 1, 1);
    i.protocol_version = ProtocolVersion {
        major: 99,
        minor: 0,
    };
    let err = state.process_intent(&i).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

#[test]
fn state_process_heartbeat_version_mismatch() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let mut hb = heartbeat("remote", 1, 1_000);
    hb.protocol_version = ProtocolVersion {
        major: 99,
        minor: 0,
    };
    let err = state.process_heartbeat(&hb).unwrap_err();
    assert!(matches!(err, ProtocolError::IncompatibleVersion { .. }));
}

#[test]
fn state_resolve_intents_unknown_extension() {
    let state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    assert!(state.resolve_intents("nonexistent").is_none());
}

#[test]
fn state_resolve_intents_multiple_extensions() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    state
        .process_intent(&intent("n1", "ext-1", ContainmentAction::Sandbox, 1, 1))
        .unwrap();
    state
        .process_intent(&intent("n2", "ext-2", ContainmentAction::Quarantine, 1, 1))
        .unwrap();
    let w1 = state.resolve_intents("ext-1").unwrap();
    assert_eq!(w1.proposed_action, ContainmentAction::Sandbox);
    let w2 = state.resolve_intents("ext-2").unwrap();
    assert_eq!(w2.proposed_action, ContainmentAction::Quarantine);
}

#[test]
fn state_build_checkpoint_quorum_failure() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    // Register one node at old timestamp
    state.process_heartbeat(&heartbeat("n1", 1, 1_000)).unwrap();
    // Try to build checkpoint at much later time → n1 is partitioned
    let err = state
        .build_checkpoint(100_000_000_000, sig("local"))
        .unwrap_err();
    assert!(matches!(err, ProtocolError::QuorumNotReached { .. }));
}

#[test]
fn state_build_checkpoint_success() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let current_time = 10_000_000_000u64;
    // Register nodes with recent heartbeats
    state
        .process_heartbeat(&heartbeat("n1", 1, current_time - 1_000))
        .unwrap();
    state
        .process_heartbeat(&heartbeat("n2", 1, current_time - 2_000))
        .unwrap();
    // Add some intents
    state
        .process_intent(&intent("n1", "ext-1", ContainmentAction::Terminate, 2, 1))
        .unwrap();

    let cp = state.build_checkpoint(current_time, sig("local")).unwrap();
    assert_eq!(cp.checkpoint_seq, 1);
    assert_eq!(cp.participating_nodes.len(), 2);
    assert_eq!(cp.containment_decisions.len(), 1);
    assert_eq!(
        cp.containment_decisions[0].resolved_action,
        ContainmentAction::Terminate
    );
}

#[test]
fn state_build_checkpoint_increments_seq() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let current_time = 10_000_000_000u64;
    state
        .process_heartbeat(&heartbeat("n1", 1, current_time - 1_000))
        .unwrap();

    let cp1 = state.build_checkpoint(current_time, sig("local")).unwrap();
    assert_eq!(cp1.checkpoint_seq, 1);

    // Need to update heartbeat for n1 to keep it healthy for next checkpoint
    state
        .process_heartbeat(&heartbeat("n1", 2, current_time + 1_000))
        .unwrap();
    let cp2 = state
        .build_checkpoint(current_time + 2_000, sig("local"))
        .unwrap();
    assert_eq!(cp2.checkpoint_seq, 2);
}

#[test]
fn state_partitioned_nodes_empty_when_all_healthy() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let now = 10_000_000_000u64;
    state
        .process_heartbeat(&heartbeat("n1", 1, now - 1_000))
        .unwrap();
    state
        .process_heartbeat(&heartbeat("n2", 1, now - 2_000))
        .unwrap();
    let partitioned = state.partitioned_nodes(now);
    assert!(partitioned.is_empty());
}

// ── Integration: full lifecycle ─────────────────────────────────────────────

#[test]
fn integration_evidence_accumulation_and_intent_resolution() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

    // Multiple nodes submit evidence about ext-1
    state
        .process_evidence(&evidence("n1", "ext-1", 1, 300_000))
        .unwrap();
    state
        .process_evidence(&evidence("n2", "ext-1", 1, 400_000))
        .unwrap();
    state
        .process_evidence(&evidence("n3", "ext-1", 1, -100_000))
        .unwrap();
    assert_eq!(state.evidence.posterior_delta("ext-1"), 600_000);
    assert_eq!(state.evidence.evidence_count("ext-1"), 3);

    // Nodes submit intents
    state
        .process_intent(&intent("n1", "ext-1", ContainmentAction::Sandbox, 2, 1))
        .unwrap();
    state
        .process_intent(&intent("n2", "ext-1", ContainmentAction::Terminate, 2, 1))
        .unwrap();
    state
        .process_intent(&intent("n3", "ext-1", ContainmentAction::Suspend, 2, 1))
        .unwrap();

    // Resolve: Terminate wins (highest severity)
    let winner = state.resolve_intents("ext-1").unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Terminate);
    assert_eq!(winner.node_id, NodeId::new("n2"));
}

#[test]
fn integration_full_checkpoint_lifecycle() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let t0 = 10_000_000_000u64;

    // Register healthy nodes
    state.process_heartbeat(&heartbeat("n1", 1, t0)).unwrap();
    state.process_heartbeat(&heartbeat("n2", 1, t0)).unwrap();
    state.process_heartbeat(&heartbeat("n3", 1, t0)).unwrap();

    // Evidence
    state
        .process_evidence(&evidence("n1", "ext-a", 2, 500_000))
        .unwrap();
    state
        .process_evidence(&evidence("n2", "ext-a", 2, 300_000))
        .unwrap();

    // Intents
    state
        .process_intent(&intent("n1", "ext-a", ContainmentAction::Quarantine, 3, 1))
        .unwrap();
    state
        .process_intent(&intent("n3", "ext-a", ContainmentAction::Suspend, 2, 1))
        .unwrap();

    // Build checkpoint just after heartbeats
    let cp = state
        .build_checkpoint(t0 + 1_000_000, sig("local"))
        .unwrap();
    assert_eq!(cp.checkpoint_seq, 1);
    assert_eq!(cp.participating_nodes.len(), 3);
    assert_eq!(cp.containment_decisions.len(), 1);
    assert_eq!(
        cp.containment_decisions[0].resolved_action,
        ContainmentAction::Quarantine
    );
    // Verify it's deterministically serializable
    let json1 = serde_json::to_string(&cp).unwrap();
    let json2 = serde_json::to_string(&cp).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn integration_replay_protection_across_message_types() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

    // Same node sends evidence seq=1, then intent seq=2 → ok
    state
        .process_evidence(&evidence("n1", "ext-1", 1, 100))
        .unwrap();
    state
        .process_intent(&intent("n1", "ext-1", ContainmentAction::Allow, 2, 1))
        .unwrap();
    // Now heartbeat with seq=1 from same node → replay
    let err = state
        .process_heartbeat(&heartbeat("n1", 1, 1_000))
        .unwrap_err();
    assert!(matches!(err, ProtocolError::ReplayDetected { .. }));
    // seq=3 → ok
    state.process_heartbeat(&heartbeat("n1", 3, 2_000)).unwrap();
}

// ── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn determinism_state_100x() {
    for _ in 0..100 {
        let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
        state
            .process_evidence(&evidence("n1", "ext-1", 1, 100_000))
            .unwrap();
        state
            .process_evidence(&evidence("n2", "ext-1", 1, 200_000))
            .unwrap();
        assert_eq!(state.evidence.posterior_delta("ext-1"), 300_000);
        assert_eq!(state.evidence.evidence_count("ext-1"), 2);

        let json = serde_json::to_string(&state).unwrap();
        let back: FleetProtocolState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evidence.posterior_delta("ext-1"), 300_000);
    }
}
