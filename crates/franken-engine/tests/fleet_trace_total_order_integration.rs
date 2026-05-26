// Integration tests for Track DD.4 (bd-cixqu.30.4): fleet-trace
// total-order assembly. Exercises the public bridge API as an external
// consumer — the same surface `frankenctl replay run --fleet-trace`
// drives — proving per-node traces stitch into ONE globally-consistent
// Lamport order rather than a node-blind per-node-sequence sort.

use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use frankenengine_engine::fleet_trace_total_order::{
    FleetTraceNode, flatten_to_events, merge_fleet_traces, node_id_from_session,
    verify_global_order,
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

    let merged = merge_fleet_traces(&[node("alpha", a), node("beta", b), node("gamma", c)]);
    verify_global_order(&merged).unwrap();

    let events = flatten_to_events(merged);
    assert_eq!(
        values(&events),
        vec!["a1", "b2", "c3", "a4", "b5", "c6", "a7"]
    );
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
