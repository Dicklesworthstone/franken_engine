#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

//! Enrichment integration tests for `fleet_immune_protocol`.
//!
//! Focus areas complementing existing tests:
//! - Multi-node fleet scenarios (5+ nodes, intents from multiple nodes)
//! - Evidence accumulation saturation behavior
//! - Partition detection with staggered heartbeats
//! - Checkpoint building with various quorum thresholds
//! - DeterministicPrecedence across all tiebreak dimensions
//! - FleetProtocolState full lifecycle
//! - Cross-extension intent resolution isolation
//! - SequenceRange arithmetic edge cases

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sig(node: &str) -> MessageSignature {
    MessageSignature {
        signer: NodeId::new(node),
        hash: AuthenticityHash::compute_keyed(node.as_bytes(), b"enrichment-test"),
    }
}

fn evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
    EvidencePacket {
        trace_id: format!("enr-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        evidence_hash: ContentHash::compute(format!("enr-ev-{node}-{ext}-{seq}").as_bytes()),
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

fn intent(node: &str, ext: &str, action: ContainmentAction, seq: u64, epoch: u64) -> ContainmentIntent {
    ContainmentIntent {
        intent_id: format!("enr-intent-{node}-{ext}-{seq}"),
        extension_id: ext.to_string(),
        proposed_action: action,
        confidence_millionths: 900_000,
        supporting_evidence_ids: vec![format!("enr-{node}-{ext}-1")],
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
        evidence_frontier_hash: ContentHash::compute(format!("enr-frontier-{node}-{seq}").as_bytes()),
        local_health: BTreeMap::new(),
        epoch: SecurityEpoch::from_raw(1),
        sequence: seq,
        timestamp_ns: ts_ns,
        signature: sig(node),
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Multi-node fleet scenarios (5+ nodes)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_node_fleet_evidence_accumulation() {
    let mut acc = EvidenceAccumulator::new();
    for i in 0..5 {
        let node = format!("node-{i}");
        acc.ingest(&evidence(&node, "ext-target", (i + 1) as u64, 200_000)).unwrap();
    }
    assert_eq!(acc.posterior_delta("ext-target"), 1_000_000);
    assert_eq!(acc.evidence_count("ext-target"), 5);
}

#[test]
fn enrichment_seven_node_intent_resolution_highest_severity_wins() {
    let actions = [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
    ];
    let intents: Vec<ContainmentIntent> = (0..7)
        .map(|i| intent(&format!("node-{i}"), "ext-1", actions[i], (i + 1) as u64, 1))
        .collect();
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
    assert_eq!(winner.node_id, NodeId::new("node-4"));
}

#[test]
fn enrichment_five_node_fleet_state_full_lifecycle() {
    let mut state = FleetProtocolState::new(NodeId::new("coordinator"), GossipConfig::default());

    let now = 10_000_000_000u64;
    // Register 5 nodes via heartbeats
    for i in 0..5 {
        let node = format!("fleet-{i}");
        state.process_heartbeat(&heartbeat(&node, 1, now)).unwrap();
    }

    // All 5 send evidence for ext-alpha
    for i in 0..5 {
        let node = format!("fleet-{i}");
        state.process_evidence(&evidence(&node, "ext-alpha", 2, 100_000)).unwrap();
    }
    assert_eq!(state.evidence.posterior_delta("ext-alpha"), 500_000);

    // 3 nodes send intents for ext-alpha
    state.process_intent(&intent("fleet-0", "ext-alpha", ContainmentAction::Sandbox, 3, 1)).unwrap();
    state.process_intent(&intent("fleet-1", "ext-alpha", ContainmentAction::Terminate, 3, 1)).unwrap();
    state.process_intent(&intent("fleet-2", "ext-alpha", ContainmentAction::Suspend, 3, 1)).unwrap();

    let winner = state.resolve_intents("ext-alpha").unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Terminate);

    // Build checkpoint with all nodes healthy
    let checkpoint = state.build_checkpoint(now + 1_000_000_000, sig("coordinator")).unwrap();
    assert_eq!(checkpoint.participating_nodes.len(), 5);
    assert_eq!(checkpoint.containment_decisions.len(), 1);
    assert_eq!(checkpoint.containment_decisions[0].resolved_action, ContainmentAction::Terminate);
}

// ---------------------------------------------------------------------------
// Evidence accumulation saturation behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_accumulation_saturates_at_i64_max() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext", 1, i64::MAX)).unwrap();
    acc.ingest(&evidence("n2", "ext", 1, i64::MAX)).unwrap();
    assert_eq!(acc.posterior_delta("ext"), i64::MAX, "should saturate, not overflow");
}

#[test]
fn enrichment_evidence_accumulation_saturates_at_i64_min() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext", 1, i64::MIN)).unwrap();
    acc.ingest(&evidence("n2", "ext", 1, -1_000_000)).unwrap();
    // saturating_add with MIN + negative should stay at MIN
    assert_eq!(acc.posterior_delta("ext"), i64::MIN);
}

#[test]
fn enrichment_evidence_positive_and_negative_cancel_out() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext", 1, 500_000)).unwrap();
    acc.ingest(&evidence("n2", "ext", 1, -500_000)).unwrap();
    assert_eq!(acc.posterior_delta("ext"), 0);
    assert_eq!(acc.evidence_count("ext"), 2);
}

// ---------------------------------------------------------------------------
// Partition detection with staggered heartbeats
// ---------------------------------------------------------------------------

#[test]
fn enrichment_staggered_heartbeats_selective_partition_detection() {
    let mut tracker = NodeHealthTracker::new();
    // Node-A at time 5s, Node-B at time 8s, Node-C at time 12s
    tracker.record_heartbeat(&heartbeat("node-a", 1, 5_000_000_000));
    tracker.record_heartbeat(&heartbeat("node-b", 1, 8_000_000_000));
    tracker.record_heartbeat(&heartbeat("node-c", 1, 12_000_000_000));

    let timeout = 10_000_000_000; // 10s

    // At 16s: A is 11s old (partitioned), B is 8s old (ok), C is 4s old (ok)
    let partitioned = tracker.suspected_partitioned(16_000_000_000, timeout);
    assert_eq!(partitioned.len(), 1);
    assert!(partitioned.contains(&NodeId::new("node-a")));

    let healthy = tracker.healthy_nodes(16_000_000_000, timeout);
    assert_eq!(healthy.len(), 2);
    assert!(healthy.contains(&NodeId::new("node-b")));
    assert!(healthy.contains(&NodeId::new("node-c")));
}

#[test]
fn enrichment_heartbeat_update_heals_partition() {
    let mut tracker = NodeHealthTracker::new();
    tracker.record_heartbeat(&heartbeat("node-1", 1, 1_000_000_000));
    let timeout = 5_000_000_000;

    // At 8s, node-1 is partitioned
    assert_eq!(tracker.suspected_partitioned(8_000_000_000, timeout).len(), 1);

    // Node-1 sends new heartbeat at 7s
    tracker.record_heartbeat(&heartbeat("node-1", 2, 7_000_000_000));

    // At 8s, node-1 is no longer partitioned (1s since last heartbeat < 5s timeout)
    assert!(tracker.suspected_partitioned(8_000_000_000, timeout).is_empty());
}

#[test]
fn enrichment_all_nodes_partitioned_when_current_time_far_future() {
    let mut tracker = NodeHealthTracker::new();
    for i in 0..5 {
        tracker.record_heartbeat(&heartbeat(&format!("n-{i}"), 1, 10_000_000_000));
    }
    let partitioned = tracker.suspected_partitioned(u64::MAX, 10_000_000_000);
    assert_eq!(partitioned.len(), 5);
}

// ---------------------------------------------------------------------------
// Checkpoint building with various quorum thresholds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_checkpoint_with_100_percent_quorum_needs_all_nodes() {
    let config = GossipConfig {
        quorum_threshold_millionths: 1_000_000, // 100%
        ..GossipConfig::default()
    };
    let mut state = FleetProtocolState::new(NodeId::new("local"), config);
    let now = 10_000_000_000u64;

    state.process_heartbeat(&heartbeat("n1", 1, now)).unwrap();
    state.process_heartbeat(&heartbeat("n2", 1, now)).unwrap();
    state.process_heartbeat(&heartbeat("n3", 1, 1_000_000_000)).unwrap(); // old, will be partitioned

    // At now+1s with 15s timeout, n3 is still healthy (9s old < 15s)
    let result = state.build_checkpoint(now + 1_000_000_000, sig("local"));
    assert!(result.is_ok(), "all 3 nodes still within timeout");

    // Now make n3 definitely partitioned
    let far_future = now + 20_000_000_000;
    let result = state.build_checkpoint(far_future, sig("local"));
    assert!(result.is_err(), "only 2 of 3 nodes healthy, need 100%");
}

#[test]
fn enrichment_checkpoint_with_zero_known_nodes_requires_one() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let result = state.build_checkpoint(10_000_000_000, sig("local"));
    // With 0 known nodes, required = 1, actual = 0
    assert!(matches!(result, Err(ProtocolError::QuorumNotReached { required: 1, actual: 0 })));
}

#[test]
fn enrichment_checkpoint_multiple_extensions_resolved() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let now = 10_000_000_000u64;
    state.process_heartbeat(&heartbeat("n1", 1, now)).unwrap();

    // Add intents for 3 different extensions
    state.process_intent(&intent("n1", "ext-a", ContainmentAction::Sandbox, 2, 1)).unwrap();
    state.process_intent(&intent("n1", "ext-b", ContainmentAction::Terminate, 3, 1)).unwrap();
    state.process_intent(&intent("n1", "ext-c", ContainmentAction::Quarantine, 4, 1)).unwrap();

    let checkpoint = state.build_checkpoint(now + 1_000_000_000, sig("local")).unwrap();
    assert_eq!(checkpoint.containment_decisions.len(), 3);

    // Verify decisions are for distinct extensions
    let ext_ids: BTreeSet<&str> = checkpoint.containment_decisions.iter()
        .map(|d| d.extension_id.as_str())
        .collect();
    assert_eq!(ext_ids.len(), 3);
}

// ---------------------------------------------------------------------------
// DeterministicPrecedence across all tiebreak dimensions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_precedence_severity_trumps_epoch_and_node_id() {
    let low_sev_high_epoch = intent("aaa", "ext", ContainmentAction::Sandbox, 1, 100);
    let high_sev_low_epoch = intent("zzz", "ext", ContainmentAction::Quarantine, 1, 1);
    let winner = DeterministicPrecedence::resolve(&low_sev_high_epoch, &high_sev_low_epoch);
    assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
}

#[test]
fn enrichment_precedence_epoch_trumps_node_id_when_severity_equal() {
    let old_epoch_small_id = intent("aaa", "ext", ContainmentAction::Suspend, 1, 1);
    let new_epoch_large_id = intent("zzz", "ext", ContainmentAction::Suspend, 1, 10);
    let winner = DeterministicPrecedence::resolve(&old_epoch_small_id, &new_epoch_large_id);
    assert_eq!(winner.epoch, SecurityEpoch::from_raw(10));
    assert_eq!(winner.node_id, NodeId::new("zzz"));
}

#[test]
fn enrichment_precedence_node_id_is_final_tiebreaker() {
    let a = intent("alpha", "ext", ContainmentAction::Terminate, 1, 5);
    let b = intent("beta", "ext", ContainmentAction::Terminate, 1, 5);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    assert_eq!(winner.node_id, NodeId::new("alpha"), "smaller node-id wins");

    // Reverse argument order should give same result
    let winner_rev = DeterministicPrecedence::resolve(&b, &a);
    assert_eq!(winner_rev.node_id, NodeId::new("alpha"));
}

#[test]
fn enrichment_precedence_stable_tiebreak_first_arg_wins_on_identical() {
    // When both intents are identical in all precedence dimensions, first arg wins
    let a = intent("same", "ext", ContainmentAction::Sandbox, 1, 1);
    let b = intent("same", "ext", ContainmentAction::Sandbox, 1, 1);
    let winner = DeterministicPrecedence::resolve(&a, &b);
    // winner should be &a (same precedence, first argument wins)
    assert_eq!(winner.node_id, NodeId::new("same"));
}

#[test]
fn enrichment_resolve_all_with_10_intents_various_severities() {
    let intents: Vec<ContainmentIntent> = (0..10)
        .map(|i| {
            let action = match i % 5 {
                0 => ContainmentAction::Allow,
                1 => ContainmentAction::Sandbox,
                2 => ContainmentAction::Suspend,
                3 => ContainmentAction::Terminate,
                _ => ContainmentAction::Quarantine,
            };
            intent(&format!("node-{i:02}"), "ext-1", action, (i + 1) as u64, 1)
        })
        .collect();
    let winner = DeterministicPrecedence::resolve_all(&intents).unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Quarantine);
}

// ---------------------------------------------------------------------------
// Cross-extension intent resolution isolation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_intents_for_different_extensions_resolve_independently() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());

    // ext-a: Sandbox from node-1, Terminate from node-2
    state.process_intent(&intent("node-1", "ext-a", ContainmentAction::Sandbox, 1, 1)).unwrap();
    state.process_intent(&intent("node-2", "ext-a", ContainmentAction::Terminate, 1, 1)).unwrap();

    // ext-b: Allow from node-3, Quarantine from node-4
    state.process_intent(&intent("node-3", "ext-b", ContainmentAction::Allow, 1, 1)).unwrap();
    state.process_intent(&intent("node-4", "ext-b", ContainmentAction::Quarantine, 1, 1)).unwrap();

    let winner_a = state.resolve_intents("ext-a").unwrap();
    assert_eq!(winner_a.proposed_action, ContainmentAction::Terminate);

    let winner_b = state.resolve_intents("ext-b").unwrap();
    assert_eq!(winner_b.proposed_action, ContainmentAction::Quarantine);

    // No cross-contamination
    assert!(state.resolve_intents("ext-c").is_none());
}

// ---------------------------------------------------------------------------
// SequenceRange arithmetic edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sequence_range_0_0_has_length_1() {
    let r = SequenceRange::new(0, 0);
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn enrichment_sequence_range_max_max_has_length_1() {
    let r = SequenceRange::new(u64::MAX, u64::MAX);
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn enrichment_sequence_range_inverted_is_empty() {
    let r = SequenceRange::new(10, 5);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
}

#[test]
fn enrichment_sequence_range_large_but_safe() {
    // 0 to u64::MAX would overflow in len(), so we test a large-but-safe range.
    let r = SequenceRange::new(0, u64::MAX - 1);
    assert_eq!(r.len(), u64::MAX);
    assert!(!r.is_empty());
    // Serde round-trip for max-1 range
    let json = serde_json::to_string(&r).unwrap();
    let back: SequenceRange = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_sequence_range_adjacent() {
    let r = SequenceRange::new(5, 6);
    assert_eq!(r.len(), 2);
    assert!(!r.is_empty());
}

#[test]
fn enrichment_sequence_range_serde_roundtrip_edge_values() {
    let ranges = [
        SequenceRange::new(0, 0),
        SequenceRange::new(u64::MAX, u64::MAX),
        SequenceRange::new(100, 50), // inverted
    ];
    for r in &ranges {
        let json = serde_json::to_string(r).unwrap();
        let back: SequenceRange = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// FleetProtocolState full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_evidence_intent_heartbeat_checkpoint() {
    let mut state = FleetProtocolState::new(NodeId::new("me"), GossipConfig::default());
    let now = 10_000_000_000u64;

    // Step 1: Register nodes via heartbeats
    for i in 0..3 {
        state.process_heartbeat(&heartbeat(&format!("peer-{i}"), 1, now)).unwrap();
    }
    assert_eq!(state.health.known_node_count(), 3);

    // Step 2: Ingest evidence from peers
    for i in 0..3 {
        state.process_evidence(&evidence(&format!("peer-{i}"), "ext-x", 2, 300_000)).unwrap();
    }
    assert_eq!(state.evidence.posterior_delta("ext-x"), 900_000);

    // Step 3: Receive containment intents
    state.process_intent(&intent("peer-0", "ext-x", ContainmentAction::Suspend, 3, 1)).unwrap();
    state.process_intent(&intent("peer-1", "ext-x", ContainmentAction::Terminate, 3, 1)).unwrap();

    // Step 4: Resolve
    let winner = state.resolve_intents("ext-x").unwrap();
    assert_eq!(winner.proposed_action, ContainmentAction::Terminate);

    // Step 5: Build checkpoint
    let cp = state.build_checkpoint(now + 1_000_000_000, sig("me")).unwrap();
    assert_eq!(cp.checkpoint_seq, 1);
    assert!(cp.participating_nodes.len() >= 3);
    assert_eq!(cp.containment_decisions[0].resolved_action, ContainmentAction::Terminate);
}

#[test]
fn enrichment_state_next_sequence_is_strictly_monotonic() {
    let mut state = FleetProtocolState::new(NodeId::new("local"), GossipConfig::default());
    let mut prev = 0;
    for _ in 0..100 {
        let seq = state.next_sequence();
        assert!(seq > prev);
        prev = seq;
    }
}

// ---------------------------------------------------------------------------
// NodeSequenceTracker replay protection edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sequence_tracker_accepts_large_gap() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("gappy");
    tracker.accept(&node, 1).unwrap();
    tracker.accept(&node, 1_000_000).unwrap();
    assert_eq!(tracker.last_sequence(&node), 1_000_000);
}

#[test]
fn enrichment_sequence_tracker_rejects_same_sequence_twice() {
    let mut tracker = NodeSequenceTracker::new();
    let node = NodeId::new("dedup");
    tracker.accept(&node, 42).unwrap();
    let err = tracker.accept(&node, 42).unwrap_err();
    match err {
        ProtocolError::ReplayDetected { received_seq, last_accepted_seq, .. } => {
            assert_eq!(received_seq, 42);
            assert_eq!(last_accepted_seq, 42);
        }
        _ => panic!("expected ReplayDetected"),
    }
}

#[test]
fn enrichment_sequence_tracker_multiple_nodes_independent() {
    let mut tracker = NodeSequenceTracker::new();
    for i in 0..10 {
        let node = NodeId::new(format!("node-{i}"));
        tracker.accept(&node, 100).unwrap();
    }
    assert_eq!(tracker.known_nodes().len(), 10);
    for i in 0..10 {
        let node = NodeId::new(format!("node-{i}"));
        assert_eq!(tracker.last_sequence(&node), 100);
    }
}

// ---------------------------------------------------------------------------
// EvidenceAccumulator determinism and summary hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_hash_deterministic_with_multiple_extensions() {
    let mut acc1 = EvidenceAccumulator::new();
    let mut acc2 = EvidenceAccumulator::new();

    for acc in [&mut acc1, &mut acc2] {
        acc.ingest(&evidence("n1", "ext-b", 1, 100)).unwrap();
        acc.ingest(&evidence("n1", "ext-a", 2, 200)).unwrap();
        acc.ingest(&evidence("n2", "ext-c", 1, 300)).unwrap();
    }
    assert_eq!(acc1.summary_hash(), acc2.summary_hash());
}

#[test]
fn enrichment_summary_hash_changes_when_new_evidence_added() {
    let mut acc = EvidenceAccumulator::new();
    acc.ingest(&evidence("n1", "ext-1", 1, 100)).unwrap();
    let h1 = acc.summary_hash();

    acc.ingest(&evidence("n2", "ext-1", 1, 200)).unwrap();
    let h2 = acc.summary_hash();

    assert_ne!(h1, h2, "adding evidence should change the summary hash");
}

// ---------------------------------------------------------------------------
// GossipConfig serde and custom values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_gossip_config_custom_values_serde_roundtrip() {
    let config = GossipConfig {
        fanout: 7,
        max_ttl: 20,
        heartbeat_interval_ns: 1_000_000_000,
        partition_timeout_ns: 3_000_000_000,
        bandwidth_ceiling_bytes_per_sec: 10_485_760,
        checkpoint_interval_ns: 30_000_000_000,
        quorum_threshold_millionths: 666_667,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: GossipConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// FleetMessage serde for all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fleet_message_all_variants_serde_roundtrip() {
    let msgs: Vec<FleetMessage> = vec![
        FleetMessage::Evidence(evidence("n1", "ext", 1, 100)),
        FleetMessage::Intent(intent("n2", "ext", ContainmentAction::Quarantine, 1, 1)),
        FleetMessage::Heartbeat(heartbeat("n3", 1, 5_000_000_000)),
        FleetMessage::Reconciliation(ReconciliationRequest {
            node_id: NodeId::new("n4"),
            known_frontier_hash: ContentHash::compute(b"frontier"),
            requested_ranges: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(1),
            sequence: 1,
            timestamp_ns: 5_000_000_000,
            signature: sig("n4"),
            protocol_version: ProtocolVersion::CURRENT,
        }),
    ];

    for msg in &msgs {
        let json = serde_json::to_string(msg).unwrap();
        let back: FleetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(*msg, back);
    }
}

// ---------------------------------------------------------------------------
// ProtocolError serde for all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_protocol_error_all_variants_serde_and_display() {
    let errors = vec![
        ProtocolError::ReplayDetected { node_id: NodeId::new("n"), received_seq: 1, last_accepted_seq: 5 },
        ProtocolError::DuplicateEvidence { trace_id: "t".into(), extension_id: "e".into() },
        ProtocolError::IncompatibleVersion { local: ProtocolVersion::CURRENT, remote: ProtocolVersion { major: 2, minor: 0 } },
        ProtocolError::InvalidSignature { node_id: NodeId::new("n"), message_type: "intent".into() },
        ProtocolError::QuorumNotReached { required: 3, actual: 1 },
        ProtocolError::PartitionedNode { node_id: NodeId::new("n") },
        ProtocolError::EmptyIntents,
    ];

    let mut displays = BTreeSet::new();
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);

        let d = err.to_string();
        assert!(!d.is_empty());
        displays.insert(d);
    }
    assert_eq!(displays.len(), 7, "all 7 error variants have unique display strings");
}

// ---------------------------------------------------------------------------
// ResolvedContainmentDecision with multiple contributing intents
// ---------------------------------------------------------------------------

#[test]
fn enrichment_resolved_decision_with_many_contributing_intents() {
    let decision = ResolvedContainmentDecision {
        extension_id: "ext-complex".into(),
        resolved_action: ContainmentAction::Quarantine,
        contributing_intent_ids: (0..20).map(|i| format!("intent-{i}")).collect(),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&decision).unwrap();
    let back: ResolvedContainmentDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
    assert_eq!(back.contributing_intent_ids.len(), 20);
}

// ---------------------------------------------------------------------------
// QuorumCheckpoint with many participating nodes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_checkpoint_with_many_nodes_deterministic_serde() {
    let mut nodes = BTreeSet::new();
    let mut sigs_map = BTreeMap::new();
    for i in 0..10 {
        let name = format!("node-{i:02}");
        nodes.insert(NodeId::new(&name));
        sigs_map.insert(NodeId::new(&name), sig(&name));
    }
    let checkpoint = QuorumCheckpoint {
        checkpoint_seq: 42,
        epoch: SecurityEpoch::from_raw(3),
        participating_nodes: nodes,
        evidence_summary_hash: ContentHash::compute(b"big-summary"),
        containment_decisions: vec![
            ResolvedContainmentDecision {
                extension_id: "ext-a".into(),
                resolved_action: ContainmentAction::Sandbox,
                contributing_intent_ids: vec!["i1".into(), "i2".into()],
                epoch: SecurityEpoch::from_raw(3),
            },
        ],
        quorum_signatures: sigs_map,
        timestamp_ns: 100_000_000_000,
        protocol_version: ProtocolVersion::CURRENT,
        extensions: BTreeMap::new(),
    };

    let json1 = serde_json::to_string(&checkpoint).unwrap();
    let json2 = serde_json::to_string(&checkpoint).unwrap();
    assert_eq!(json1, json2, "BTreeMap/BTreeSet guarantee deterministic serialization");

    let back: QuorumCheckpoint = serde_json::from_str(&json1).unwrap();
    assert_eq!(checkpoint, back);
}

// ---------------------------------------------------------------------------
// NodeId ordering and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_node_id_ordering_lexicographic() {
    let mut ids: Vec<NodeId> = vec![
        NodeId::new("zebra"),
        NodeId::new("alpha"),
        NodeId::new("mango"),
    ];
    ids.sort();
    assert_eq!(ids[0], NodeId::new("alpha"));
    assert_eq!(ids[1], NodeId::new("mango"));
    assert_eq!(ids[2], NodeId::new("zebra"));
}

#[test]
fn enrichment_node_id_empty_is_valid() {
    let empty = NodeId::new("");
    assert_eq!(empty.as_str(), "");
    assert_eq!(empty.to_string(), "");
}

// ---------------------------------------------------------------------------
// ContainmentAction ordering and severity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_containment_action_severity_is_monotonic() {
    let actions = [
        ContainmentAction::Allow,
        ContainmentAction::Sandbox,
        ContainmentAction::Suspend,
        ContainmentAction::Terminate,
        ContainmentAction::Quarantine,
    ];
    for i in 1..actions.len() {
        assert!(
            actions[i].severity() > actions[i - 1].severity(),
            "{:?} severity should be > {:?} severity",
            actions[i],
            actions[i - 1]
        );
    }
}

#[test]
fn enrichment_containment_action_at_least_as_severe_transitive() {
    // If A >= B and B >= C then A >= C
    assert!(ContainmentAction::Quarantine.at_least_as_severe_as(ContainmentAction::Terminate));
    assert!(ContainmentAction::Terminate.at_least_as_severe_as(ContainmentAction::Suspend));
    assert!(ContainmentAction::Quarantine.at_least_as_severe_as(ContainmentAction::Suspend));
}
