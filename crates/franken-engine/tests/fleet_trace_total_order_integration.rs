// Integration tests for Track DD.4 (bd-cixqu.30.4): fleet-trace
// total-order assembly. Exercises the public bridge API as an external
// consumer — the same surface `frankenctl replay run --fleet-trace`
// drives — proving per-node traces stitch into ONE globally-consistent
// Lamport order rather than a node-blind per-node-sequence sort.

use frankenengine_engine::deterministic_replay::{
    DeterministicEventWitness, NondeterminismSource, NondeterminismTrace, ReplayEngine,
    ReplayError, ReplayMode,
};
use frankenengine_engine::fleet_trace_total_order::{
    FleetMergeError, FleetTraceNode, assemble_fleet_trace, flatten_to_events, merge_fleet_traces,
    node_id_from_session, verify_global_order,
};
use frankenengine_engine::lamport_evidence_annotation::NodeId;

/// Build a finalised per-node trace from `(virtual_ts, value)` tuples.
fn node_trace(session: &str, events: &[(u64, &str)]) -> NondeterminismTrace {
    let mut t = NondeterminismTrace::new(session);
    for (vts, value) in events {
        t.capture(
            NondeterminismSource::TimerRead,
            value.as_bytes().to_vec(),
            *vts,
            "fleet-node",
        );
    }
    t.finalise(events.last().map(|(v, _)| *v).unwrap_or(0));
    t
}

fn node(id: &str, t: NondeterminismTrace) -> FleetTraceNode {
    FleetTraceNode::new(NodeId::try_new(id).unwrap(), t)
}

fn values(events: &[frankenengine_engine::deterministic_replay::TraceEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| String::from_utf8(e.value.clone()).unwrap())
        .collect()
}

#[test]
fn three_node_fleet_replays_in_global_lamport_order() {
    let a = node_trace("alpha", &[(1, "a1"), (4, "a4"), (7, "a7")]);
    let b = node_trace("beta", &[(2, "b2"), (5, "b5")]);
    let c = node_trace("gamma", &[(3, "c3"), (6, "c6")]);

    let assembled = assemble_fleet_trace(
        "fleet",
        &[node("alpha", a), node("beta", b), node("gamma", c)],
    )
    .unwrap();
    assembled.trace.validate_for_replay().unwrap();
    verify_global_order(&assembled.ordered_events).unwrap();
    assert_eq!(
        values(&assembled.trace.events),
        vec!["a1", "b2", "c3", "a4", "b5", "c6", "a7"]
    );
    assert_eq!(assembled.trace.next_sequence, 7);
    assert_eq!(
        assembled
            .trace
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5, 6]
    );
    let origins: Vec<_> = assembled
        .ordered_events
        .iter()
        .map(|event| (event.node_id.as_str(), event.event.sequence))
        .collect();
    assert_eq!(
        origins,
        vec![
            ("alpha", 0),
            ("beta", 0),
            ("gamma", 0),
            ("alpha", 1),
            ("beta", 1),
            ("gamma", 1),
            ("alpha", 2),
        ]
    );

    let witness = assembled.trace.deterministic_witness;
    let mut replay = ReplayEngine::new(assembled.trace, ReplayMode::Strict);
    for expected in ["a1", "b2", "c3", "a4", "b5", "c6", "a7"] {
        assert_eq!(
            replay
                .replay_next(NondeterminismSource::TimerRead, expected.as_bytes())
                .unwrap(),
            expected.as_bytes()
        );
    }
    replay.verify_deterministic_witness(&witness).unwrap();
    assert!(replay.is_complete());
    assert_eq!(replay.divergence_count(), 0);
}

#[test]
fn merge_is_deterministic_regardless_of_node_presentation_order() {
    let a = node_trace("alpha", &[(1, "a1"), (4, "a4")]);
    let b = node_trace("beta", &[(2, "b2"), (4, "b4")]);
    let c = node_trace("gamma", &[(3, "c3")]);

    let forward = merge_fleet_traces(&[
        node("alpha", a.clone()),
        node("beta", b.clone()),
        node("gamma", c.clone()),
    ]);
    let shuffled = merge_fleet_traces(&[node("gamma", c), node("alpha", a), node("beta", b)]);
    assert_eq!(forward, shuffled);
}

#[test]
fn equal_clock_across_nodes_breaks_ties_by_node_id() {
    // Both nodes have an event at virtual_ts == 9.
    let a = node_trace("alpha", &[(9, "tie")]);
    let z = node_trace("zeta", &[(9, "tie")]);
    // Present zeta first; alpha must still sort first (alpha < zeta lex).
    let merged = merge_fleet_traces(&[node("zeta", z), node("alpha", a)]);
    let nodes: Vec<&str> = merged.iter().map(|o| o.node_id.as_str()).collect();
    assert_eq!(nodes, vec!["alpha", "zeta"]);
}

#[test]
fn node_id_falls_back_to_file_stem_when_session_blank() {
    let blank = node_id_from_session("", "node-7.json").unwrap();
    assert_eq!(blank.as_str(), "node-7.json");
    let from_session = node_id_from_session("sess-A", "ignored").unwrap();
    assert_eq!(from_session.as_str(), "sess-A");
}

#[test]
fn single_node_is_pure_clock_sort() {
    let solo = node_trace("solo", &[(30, "c"), (10, "a"), (20, "b")]);
    let merged = merge_fleet_traces(&[node("solo", solo)]);
    let events = flatten_to_events(merged);
    assert_eq!(values(&events), vec!["a", "b", "c"]);
}

#[test]
fn empty_fleet_yields_empty_order() {
    let merged = merge_fleet_traces(&[]);
    assert!(merged.is_empty());
    assert!(flatten_to_events(merged).is_empty());
}

#[test]
fn checked_assembly_preserves_local_order_when_virtual_timestamps_tie() {
    // The payload-hash evidence order puts these alpha events in reverse
    // sequence. Replay must keep first -> second -> third for that node.
    let alpha = node_trace("alpha", &[(5, "first"), (5, "second"), (5, "third")]);
    let beta = node_trace("beta", &[(5, "last")]);
    let assembled =
        assemble_fleet_trace("fleet", &[node("beta", beta), node("alpha", alpha)]).unwrap();
    assert_eq!(
        values(&assembled.trace.events),
        vec!["first", "second", "third", "last"]
    );
    let mut replay = ReplayEngine::new(assembled.trace, ReplayMode::Strict);
    for expected in ["first", "second", "third", "last"] {
        replay
            .replay_next(NondeterminismSource::TimerRead, expected.as_bytes())
            .unwrap();
    }
    assert!(replay.is_complete());
}

#[test]
fn checked_assembly_rejects_local_sequence_corruption_before_renumbering() {
    let good = node_trace("alpha", &[(10, "a"), (20, "b")]);
    let mut duplicate = good.clone();
    duplicate.events[1].sequence = 0;
    let mut gap = good.clone();
    gap.events[1].sequence = 3;
    let mut reordered = good.clone();
    reordered.events.swap(0, 1);
    for malformed in [duplicate, gap, reordered] {
        assert!(matches!(
            assemble_fleet_trace("fleet", &[node("alpha", malformed)]),
            Err(FleetMergeError::InvalidTrace {
                error: ReplayError::NonContiguousSequence { .. },
                ..
            })
        ));
    }
    let mut bad_count = good;
    bad_count.next_sequence = 1;
    assert!(matches!(
        assemble_fleet_trace("fleet", &[node("alpha", bad_count)]),
        Err(FleetMergeError::InvalidTrace {
            error: ReplayError::NextSequenceMismatch { .. },
            ..
        })
    ));
}

#[test]
fn checked_assembly_rejects_regressing_clocks_before_sorting() {
    let mut malformed = node_trace("alpha", &[(30, "c"), (10, "a"), (20, "b")]);
    malformed.finalise(30);
    assert!(matches!(
        assemble_fleet_trace("fleet", &[node("alpha", malformed)]),
        Err(FleetMergeError::InvalidTrace {
            error: ReplayError::NonMonotonicVirtualTimestamp { .. },
            ..
        })
    ));
}

#[test]
fn checked_assembly_rejects_unfinalized_and_out_of_window_sources() {
    let mut unfinished = node_trace("alpha", &[(10, "a")]);
    unfinished.capture_ended_vts = None;
    assert!(matches!(
        assemble_fleet_trace("fleet", &[node("alpha", unfinished)]),
        Err(FleetMergeError::InvalidTrace {
            error: ReplayError::TraceNotFinalised,
            ..
        })
    ));
    let mut out_of_window = node_trace("alpha", &[(10, "a")]);
    out_of_window.finalise(5);
    assert!(matches!(
        assemble_fleet_trace("fleet", &[node("alpha", out_of_window)]),
        Err(FleetMergeError::InvalidTrace {
            error: ReplayError::VirtualTimestampOutOfBounds { .. },
            ..
        })
    ));
}

#[test]
fn checked_assembly_rejects_duplicate_node_identity() {
    let source = node_trace("alpha", &[(10, "a")]);
    let error = assemble_fleet_trace(
        "fleet",
        &[node("alpha", source.clone()), node("alpha", source)],
    )
    .unwrap_err();
    assert_eq!(
        error,
        FleetMergeError::DuplicateNodeId {
            node_id: NodeId::try_new("alpha").unwrap(),
        }
    );
    assert!(error.to_string().contains("alpha"));
}

#[test]
fn capture_union_includes_other_nodes_and_empty_capture_windows() {
    let mut anchor = node_trace("anchor", &[(60, "middle")]);
    anchor.capture_started_vts = 50;
    anchor.finalise(70);
    let mut other = node_trace("other", &[(30, "early"), (90, "late")]);
    other.capture_started_vts = 20;
    other.finalise(100);
    let mut empty = node_trace("empty", &[]);
    empty.capture_started_vts = 10;
    empty.finalise(200);
    let assembled = assemble_fleet_trace(
        "fleet",
        &[
            node("anchor", anchor),
            node("other", other),
            node("empty", empty),
        ],
    )
    .unwrap();
    assert_eq!(assembled.trace.capture_started_vts, 10);
    assert_eq!(assembled.trace.capture_ended_vts, Some(200));
    assert_eq!(assembled.nodes[1].node_id.as_str(), "empty");
    assert_eq!(assembled.nodes[1].event_count, 0);
    assert_eq!(assembled.nodes[1].capture_started_vts, 10);
    assert_eq!(assembled.nodes[1].capture_ended_vts, 200);
    let mut replay = ReplayEngine::new(assembled.trace, ReplayMode::Strict);
    for expected in ["early", "middle", "late"] {
        replay
            .replay_next(NondeterminismSource::TimerRead, expected.as_bytes())
            .unwrap();
    }
    assert!(replay.is_complete());
}

fn witnessed_nodes() -> Vec<FleetTraceNode> {
    let mut alpha = node_trace("session-alpha", &[(1, "a")]);
    alpha.witness_deterministic(NondeterminismSource::PropertyResolution, b"alpha.x");
    let mut beta = node_trace("session-beta", &[(2, "b")]);
    for field in [b"beta.x", b"beta.y", b"beta.z"] {
        beta.witness_deterministic(NondeterminismSource::PropertyResolution, field);
    }
    let empty = node_trace("session-empty", &[]);
    vec![
        node("alpha", alpha),
        node("beta", beta),
        node("empty", empty),
    ]
}

#[test]
fn fleet_witness_and_provenance_are_independent_of_input_presentation_order() {
    let nodes = witnessed_nodes();
    let forward = assemble_fleet_trace("fleet", &nodes).unwrap();
    let shuffled = assemble_fleet_trace(
        "fleet",
        &[nodes[2].clone(), nodes[0].clone(), nodes[1].clone()],
    )
    .unwrap();
    assert_eq!(forward, shuffled);
    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&shuffled).unwrap()
    );
    assert_eq!(forward.trace.deterministic_witness.event_count, 3);
    for (source, provenance) in nodes.iter().zip(&forward.nodes) {
        assert_eq!(source.trace.session_id, provenance.session_id);
        assert_eq!(
            source.trace.deterministic_witness,
            provenance.deterministic_witness
        );
    }
    let mut replay = ReplayEngine::new(forward.trace, ReplayMode::Strict);
    replay
        .verify_deterministic_witness(&shuffled.trace.deterministic_witness)
        .unwrap();
    assert_eq!(replay.divergence_count(), 0);
}

#[test]
fn fleet_replay_detects_witness_only_changes_and_missing_empty_nodes() {
    let sources = witnessed_nodes();
    let original = assemble_fleet_trace("fleet", &sources).unwrap();
    let mut changed_witness = sources.clone();
    changed_witness[0].trace.deterministic_witness = DeterministicEventWitness::default();
    changed_witness[0]
        .trace
        .witness_deterministic(NondeterminismSource::PropertyResolution, b"alpha.y");
    let missing_empty = sources[..2].to_vec();
    let mut changed_identity = sources.clone();
    changed_identity[2].node_id = NodeId::try_new("renamed-empty").unwrap();
    let mut changed_session = sources.clone();
    changed_session[2].trace.session_id = "changed-empty-session".to_string();
    let mut changed_bounds = sources;
    changed_bounds[2].trace.finalise(1);
    for changed in [
        changed_witness,
        missing_empty,
        changed_identity,
        changed_session,
        changed_bounds,
    ] {
        let changed = assemble_fleet_trace("fleet", &changed).unwrap();
        assert_eq!(original.trace.events, changed.trace.events);
        let mut replay = ReplayEngine::new(original.trace.clone(), ReplayMode::Strict);
        assert!(matches!(
            replay.verify_deterministic_witness(&changed.trace.deterministic_witness),
            Err(ReplayError::DeterministicWitnessMismatch { .. })
        ));
        assert_eq!(replay.critical_divergences(), 1);
        assert_ne!(original.trace.derive_id(), changed.trace.derive_id());
    }
}

#[test]
fn fleet_witness_binds_source_event_membership_even_when_replay_values_match() {
    let mut alpha = node_trace("alpha", &[(10, "first"), (30, "third")]);
    let mut beta = node_trace("beta", &[(20, "second"), (40, "fourth")]);
    alpha.finalise(50);
    beta.finalise(50);
    let original = assemble_fleet_trace(
        "fleet",
        &[node("alpha", alpha.clone()), node("beta", beta.clone())],
    )
    .unwrap();

    // Move the first event of each source to the other node. Both traces stay
    // valid with the same counts, windows, sessions, and folded witnesses;
    // global timestamp order still produces exactly the same replay values.
    std::mem::swap(&mut alpha.events[0], &mut beta.events[0]);
    let reassigned =
        assemble_fleet_trace("fleet", &[node("alpha", alpha), node("beta", beta)]).unwrap();
    assert_eq!(original.trace.events, reassigned.trace.events);
    assert_ne!(original.nodes[0].trace_hash, reassigned.nodes[0].trace_hash);
    assert_ne!(original.ordered_events, reassigned.ordered_events);
    let mut replay = ReplayEngine::new(original.trace, ReplayMode::Strict);
    assert!(matches!(
        replay.verify_deterministic_witness(&reassigned.trace.deterministic_witness),
        Err(ReplayError::DeterministicWitnessMismatch { .. })
    ));
}

#[test]
fn single_node_keeps_ordinary_trace_and_witness_semantics() {
    let mut source = node_trace("solo", &[(5, "first"), (5, "second")]);
    source.capture_started_vts = 3;
    source.finalise(7);
    source.witness_deterministic(NondeterminismSource::PropertyResolution, b"key");
    let assembled = assemble_fleet_trace("solo", &[node("solo", source.clone())]).unwrap();
    assert_eq!(assembled.trace, source);
    let mut replay = ReplayEngine::new(assembled.trace, ReplayMode::Strict);
    replay
        .verify_deterministic_witness(&source.deterministic_witness)
        .unwrap();
    for value in [b"first".as_slice(), b"second".as_slice()] {
        replay
            .replay_next(NondeterminismSource::TimerRead, value)
            .unwrap();
    }
    assert!(replay.is_complete());
}

#[test]
fn empty_assembly_is_a_valid_completed_trace() {
    let assembled = assemble_fleet_trace("empty-fleet", &[]).unwrap();
    assembled.trace.validate_for_replay().unwrap();
    assert!(assembled.ordered_events.is_empty());
    assert!(assembled.nodes.is_empty());
    assert_eq!(assembled.trace.capture_started_vts, 0);
    assert_eq!(assembled.trace.capture_ended_vts, Some(0));
    assert_eq!(
        assembled.trace.deterministic_witness,
        DeterministicEventWitness::default()
    );
    assert!(ReplayEngine::new(assembled.trace, ReplayMode::Strict).is_complete());
}
