// Fleet-Trace Total-Order Assembly — Track DD.4 (bd-cixqu.30.4).
//
// Bridges the per-node nondeterminism traces (`deterministic_replay`)
// to the DD.1 Lamport substrate (`lamport_evidence_annotation`) and the
// DD.2 total-order merger (`lamport_total_order_merger`), so the
// `frankenctl replay run --fleet-trace <dir>` command can stitch a set
// of per-node traces into ONE globally-consistent replay order.
//
// Why this module exists
// ----------------------
// DD.3 shipped the `--fleet-trace` flag but merged events by
// `TraceEvent.sequence` — a *per-node-local* ordinal. Every node emits
// sequence 0, 1, 2, ...; sorting the union by that ordinal discards node
// identity and is not a global order at all (two nodes' "sequence 3"
// events are unrelated). That defeats Track DD's core promise:
// Lamport-clock-anchored evidence stitching with deterministic
// tie-breaking. DD.4 routes the merge through the DD.2 total-order key.
//
// Ordering contract (inherited verbatim from DD.2's `MergeAtom`):
//
//   1. `lamport_clock` (u64, ascending) — Lamport's primary key. We use
//      each `TraceEvent.virtual_ts` as the node's logical clock for that
//      event: it is documented as a "monotonic counter, not wall clock",
//      i.e. a logical timestamp, which is exactly what a Lamport clock is.
//   2. `node_id` (UTF-8 lex, ascending) — tie-break across nodes that
//      share a logical clock.
//   3. `payload_hash` (32-byte lex, ascending) — tie-break when an event
//      shares BOTH clock and node id (operationally possible via
//      backfills / recovery), so replay stays byte-identical.
//
// The merge is a pure function: the same set of per-node traces produces
// the same global order on every run and every machine, regardless of
// the order the nodes are presented in (node ids are unique per node, so
// only genuine same-node duplicates can tie, and those preserve their
// in-trace order via a stable sort).
//
// Anchoring beads:
//   * bd-cixqu.30.1 (DD.1, CLOSED) — `EvidenceClock`/`NodeId`/`LamportClock`.
//   * bd-cixqu.30.2 (DD.2, CLOSED) — `MergeAtom` total-order key.
//   * bd-cixqu.30.3 (DD.3, CLOSED) — `frankenctl replay run --fleet-trace`.
//   * bd-cixqu.30.4 (DD.4, THIS)   — wires DD.1/DD.2 into the replay path.
//
// Reference: Lamport, "Time, Clocks, and the Ordering of Events in a
// Distributed System" (CACM 21:7, 1978).

use crate::deterministic_replay::{NondeterminismTrace, TraceEvent};
use crate::hash_tiers::ContentHash;
use crate::lamport_evidence_annotation::{EvidenceClock, LamportClock, LamportError, NodeId};
use crate::lamport_total_order_merger::MergeAtom;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// Inputs / outputs
// ---------------------------------------------------------------------------

/// One per-node trace participating in a fleet replay merge. The
/// `node_id` is the participant's distributed identity; the merger uses
/// it as the secondary total-order key. Callers derive it from the
/// trace's session id or the per-node file name (see
/// [`node_id_from_session`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetTraceNode {
    pub node_id: NodeId,
    pub trace: NondeterminismTrace,
}

impl FleetTraceNode {
    pub fn new(node_id: NodeId, trace: NondeterminismTrace) -> Self {
        Self { node_id, trace }
    }
}

/// A `TraceEvent` placed in the global fleet order, tagged with the node
/// it came from and the Lamport clock used to order it. Replay consumes
/// the inner `event`; the `node_id`/`lamport_clock` are retained so the
/// global order is self-describing and re-verifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderedFleetEvent {
    pub node_id: NodeId,
    pub lamport_clock: LamportClock,
    pub event: TraceEvent,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetMergeError {
    /// A node id could not be constructed (empty/too long).
    Node(LamportError),
    /// A merged sequence was not in non-decreasing global order; carries
    /// the index of the later element of the offending pair.
    OutOfOrder { index: usize },
}

impl fmt::Display for FleetMergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(err) => write!(f, "fleet node id error: {err}"),
            Self::OutOfOrder { index } => {
                write!(f, "fleet replay order violated at index {index}")
            }
        }
    }
}

impl std::error::Error for FleetMergeError {}

// ---------------------------------------------------------------------------
// Hashing / atom construction
// ---------------------------------------------------------------------------

/// Canonical content hash of a trace event, scoped to its node. Used
/// ONLY as the tertiary tie-break key (clock + node id already equal).
///
/// The preimage is prefix-free: every variable-length field is preceded
/// by its big-endian `u64` length so no two distinct `(node, event)`
/// pairs can collide by field-boundary ambiguity.
pub fn event_payload_hash(node_id: &NodeId, event: &TraceEvent) -> ContentHash {
    let node = node_id.as_str().as_bytes();
    let source = event.source.as_str().as_bytes();
    let component = event.component.as_bytes();

    let mut preimage = Vec::with_capacity(
        8 * 5 + node.len() + source.len() + component.len() + event.value.len() + 16,
    );
    push_lp(&mut preimage, node);
    push_lp(&mut preimage, source);
    preimage.extend_from_slice(&event.sequence.to_be_bytes());
    preimage.extend_from_slice(&event.virtual_ts.to_be_bytes());
    push_lp(&mut preimage, component);
    push_lp(&mut preimage, &event.value);
    ContentHash::compute(&preimage)
}

/// Append a length-prefixed (BE u64) byte field.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Build the DD.2 `MergeAtom` for one event: clock = `virtual_ts`,
/// node id from the owning node, payload hash for tertiary tie-break.
fn atom_for(node_id: &NodeId, event: &TraceEvent) -> MergeAtom {
    let clock = LamportClock::from_raw(event.virtual_ts);
    MergeAtom::new(
        EvidenceClock::new(node_id.clone(), clock),
        event_payload_hash(node_id, event),
    )
}

// ---------------------------------------------------------------------------
// Node-id derivation helper (used by the CLI)
// ---------------------------------------------------------------------------

/// Derive a `NodeId` for a trace: prefer the trace's `session_id`; fall
/// back to a caller-supplied label (e.g. the per-node file stem) when the
/// session id is empty.
pub fn node_id_from_session(session_id: &str, fallback: &str) -> Result<NodeId, FleetMergeError> {
    let raw = if session_id.is_empty() {
        fallback
    } else {
        session_id
    };
    NodeId::try_new(raw).map_err(FleetMergeError::Node)
}

// ---------------------------------------------------------------------------
// The merge
// ---------------------------------------------------------------------------

/// Merge per-node traces into one globally-consistent replay order.
///
/// Ordering uses the DD.2 total-order key via `MergeAtom`'s `Ord`
/// (`lamport_clock` asc, `node_id` lex asc, `payload_hash` lex asc). The
/// sort is **stable**, so genuine duplicates — identical key AND payload,
/// which can only arise within a single node — preserve their in-trace
/// order deterministically.
pub fn merge_fleet_traces(nodes: &[FleetTraceNode]) -> Vec<OrderedFleetEvent> {
    let mut entries: Vec<(MergeAtom, OrderedFleetEvent)> = Vec::new();
    for node in nodes {
        for event in &node.trace.events {
            let atom = atom_for(&node.node_id, event);
            let lamport_clock = atom.lamport_clock();
            entries.push((
                atom,
                OrderedFleetEvent {
                    node_id: node.node_id.clone(),
                    lamport_clock,
                    event: event.clone(),
                },
            ));
        }
    }
    // Stable sort by the DD.2 total-order key.
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.into_iter().map(|(_, ordered)| ordered).collect()
}

/// Flatten a global order back into a plain replay event sequence (the
/// shape `ReplayEngine` consumes).
pub fn flatten_to_events(ordered: Vec<OrderedFleetEvent>) -> Vec<TraceEvent> {
    ordered.into_iter().map(|o| o.event).collect()
}

/// Verify that a produced order is non-decreasing under the DD.2 key.
/// Recomputes each event's atom from `(node_id, event)` so the check is
/// independent of the `lamport_clock` cached on `OrderedFleetEvent`.
pub fn verify_global_order(ordered: &[OrderedFleetEvent]) -> Result<(), FleetMergeError> {
    for (i, window) in ordered.windows(2).enumerate() {
        let lhs = atom_for(&window[0].node_id, &window[0].event);
        let rhs = atom_for(&window[1].node_id, &window[1].event);
        if lhs.cmp(&rhs) == Ordering::Greater {
            return Err(FleetMergeError::OutOfOrder { index: i + 1 });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deterministic_replay::NondeterminismSource;

    fn nid(s: &str) -> NodeId {
        NodeId::try_new(s).unwrap()
    }

    /// Build a finalised trace from `(virtual_ts, source, value)` tuples.
    fn trace(session: &str, events: &[(u64, NondeterminismSource, &str)]) -> NondeterminismTrace {
        let mut t = NondeterminismTrace::new(session);
        for (vts, source, value) in events {
            t.capture(source.clone(), value.as_bytes().to_vec(), *vts, "test");
        }
        t.finalise(events.last().map(|(v, _, _)| *v).unwrap_or(0));
        t
    }

    fn node(id: &str, t: NondeterminismTrace) -> FleetTraceNode {
        FleetTraceNode::new(nid(id), t)
    }

    fn clocks(ordered: &[OrderedFleetEvent]) -> Vec<u64> {
        ordered.iter().map(|o| o.lamport_clock.as_u64()).collect()
    }

    fn nodes_of(ordered: &[OrderedFleetEvent]) -> Vec<String> {
        ordered
            .iter()
            .map(|o| o.node_id.as_str().to_string())
            .collect()
    }

    // ----- payload hash -----

    #[test]
    fn payload_hash_is_deterministic() {
        let t = trace("n", &[(1, NondeterminismSource::TimerRead, "v")]);
        let e = &t.events[0];
        assert_eq!(
            event_payload_hash(&nid("n"), e),
            event_payload_hash(&nid("n"), e)
        );
    }

    #[test]
    fn payload_hash_distinguishes_value() {
        let t = trace(
            "n",
            &[
                (1, NondeterminismSource::TimerRead, "a"),
                (1, NondeterminismSource::TimerRead, "b"),
            ],
        );
        assert_ne!(
            event_payload_hash(&nid("n"), &t.events[0]),
            event_payload_hash(&nid("n"), &t.events[1])
        );
    }

    #[test]
    fn payload_hash_distinguishes_node() {
        let t = trace("n", &[(1, NondeterminismSource::TimerRead, "v")]);
        assert_ne!(
            event_payload_hash(&nid("alpha"), &t.events[0]),
            event_payload_hash(&nid("beta"), &t.events[0])
        );
    }

    #[test]
    fn payload_hash_is_prefix_free_across_field_boundary() {
        // "ab" + "c"  vs  "a" + "bc" in the (source-ish) value field must
        // not collide. Use the value field via two events; the lengths
        // differ so the length prefix separates them.
        let t1 = trace("n", &[(1, NondeterminismSource::TimerRead, "ab")]);
        let t2 = trace("n", &[(1, NondeterminismSource::TimerRead, "a")]);
        assert_ne!(
            event_payload_hash(&nid("n"), &t1.events[0]),
            event_payload_hash(&nid("n"), &t2.events[0])
        );
    }

    // ----- node id derivation -----

    #[test]
    fn node_id_prefers_session_id() {
        assert_eq!(
            node_id_from_session("sess-7", "stem").unwrap(),
            nid("sess-7")
        );
    }

    #[test]
    fn node_id_falls_back_to_stem_when_session_empty() {
        assert_eq!(node_id_from_session("", "node-a").unwrap(), nid("node-a"));
    }

    #[test]
    fn node_id_rejects_empty_fallback() {
        assert!(matches!(
            node_id_from_session("", ""),
            Err(FleetMergeError::Node(_))
        ));
    }

    // ----- merge ordering -----

    #[test]
    fn empty_fleet_merges_to_empty() {
        assert!(merge_fleet_traces(&[]).is_empty());
    }

    #[test]
    fn single_node_preserves_clock_order() {
        let t = trace(
            "solo",
            &[
                (5, NondeterminismSource::TimerRead, "c"),
                (1, NondeterminismSource::TimerRead, "a"),
                (3, NondeterminismSource::TimerRead, "b"),
            ],
        );
        let merged = merge_fleet_traces(&[node("solo", t)]);
        assert_eq!(clocks(&merged), vec![1, 3, 5]);
    }

    #[test]
    fn two_nodes_interleave_by_lamport_clock() {
        let a = trace(
            "alpha",
            &[
                (1, NondeterminismSource::TimerRead, "a1"),
                (3, NondeterminismSource::TimerRead, "a3"),
                (5, NondeterminismSource::TimerRead, "a5"),
            ],
        );
        let b = trace(
            "beta",
            &[
                (2, NondeterminismSource::TimerRead, "b2"),
                (4, NondeterminismSource::TimerRead, "b4"),
                (6, NondeterminismSource::TimerRead, "b6"),
            ],
        );
        let merged = merge_fleet_traces(&[node("alpha", a), node("beta", b)]);
        assert_eq!(clocks(&merged), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(
            nodes_of(&merged),
            vec!["alpha", "beta", "alpha", "beta", "alpha", "beta"]
        );
    }

    #[test]
    fn equal_clock_ties_break_by_node_id() {
        // Both nodes have an event at virtual_ts == 5; alpha < beta lex.
        let a = trace("alpha", &[(5, NondeterminismSource::TimerRead, "x")]);
        let b = trace("beta", &[(5, NondeterminismSource::TimerRead, "x")]);
        // Present beta FIRST to prove node input order does not matter.
        let merged = merge_fleet_traces(&[node("beta", b), node("alpha", a)]);
        assert_eq!(nodes_of(&merged), vec!["alpha", "beta"]);
    }

    #[test]
    fn merge_is_independent_of_node_input_order() {
        let a = trace(
            "alpha",
            &[
                (1, NondeterminismSource::TimerRead, "a1"),
                (4, NondeterminismSource::TimerRead, "a4"),
            ],
        );
        let b = trace(
            "beta",
            &[
                (2, NondeterminismSource::TimerRead, "b2"),
                (4, NondeterminismSource::TimerRead, "b4"),
            ],
        );
        let m1 = merge_fleet_traces(&[node("alpha", a.clone()), node("beta", b.clone())]);
        let m2 = merge_fleet_traces(&[node("beta", b), node("alpha", a)]);
        assert_eq!(m1, m2);
    }

    #[test]
    fn local_sequence_sort_would_disagree_with_global_order() {
        // This is the bug DD.4 fixes. Sorting the union by per-node
        // `sequence` (every node starts at 0) is NOT the global order.
        let a = trace(
            "alpha",
            &[
                (10, NondeterminismSource::TimerRead, "a-late"), // seq 0
            ],
        );
        let b = trace(
            "beta",
            &[
                (2, NondeterminismSource::TimerRead, "b-early"), // seq 0
            ],
        );
        let merged = merge_fleet_traces(&[node("alpha", a), node("beta", b)]);
        // Lamport order: beta(2) before alpha(10).
        assert_eq!(nodes_of(&merged), vec!["beta", "alpha"]);
        // A naive sequence sort would tie both at sequence 0 and keep
        // input order (alpha first) — the wrong, node-blind answer.
        let by_seq_first = {
            let mut all: Vec<&TraceEvent> = Vec::new();
            let a2 = trace("alpha", &[(10, NondeterminismSource::TimerRead, "a-late")]);
            let b2 = trace("beta", &[(2, NondeterminismSource::TimerRead, "b-early")]);
            all.push(&a2.events[0]);
            all.push(&b2.events[0]);
            all.sort_by_key(|e| e.sequence);
            // both seq 0 -> stable -> alpha first (WRONG global order)
            String::from_utf8(all[0].value.clone()).unwrap()
        };
        assert_eq!(by_seq_first, "a-late");
        // ...whereas our Lamport merge correctly puts beta first.
        assert_eq!(
            String::from_utf8(merged[0].event.value.clone()).unwrap(),
            "b-early"
        );
    }

    // ----- determinism / verification -----

    #[test]
    fn merge_is_byte_identical_across_runs() {
        let mk = || {
            vec![
                node(
                    "alpha",
                    trace(
                        "alpha",
                        &[
                            (1, NondeterminismSource::TimerRead, "a1"),
                            (4, NondeterminismSource::TimerRead, "a4"),
                            (7, NondeterminismSource::TimerRead, "a7"),
                        ],
                    ),
                ),
                node(
                    "beta",
                    trace(
                        "beta",
                        &[
                            (2, NondeterminismSource::TimerRead, "b2"),
                            (4, NondeterminismSource::TimerRead, "b4"),
                            (8, NondeterminismSource::TimerRead, "b8"),
                        ],
                    ),
                ),
                node(
                    "gamma",
                    trace(
                        "gamma",
                        &[
                            (3, NondeterminismSource::TimerRead, "g3"),
                            (5, NondeterminismSource::TimerRead, "g5"),
                            (6, NondeterminismSource::TimerRead, "g6"),
                        ],
                    ),
                ),
            ]
        };
        let r1 = merge_fleet_traces(&mk());
        let r2 = merge_fleet_traces(&mk());
        assert_eq!(r1, r2);
        verify_global_order(&r1).unwrap();
        // Clocks non-decreasing.
        let cs = clocks(&r1);
        assert!(cs.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn flatten_preserves_global_order_events() {
        let a = trace(
            "alpha",
            &[
                (1, NondeterminismSource::TimerRead, "a1"),
                (3, NondeterminismSource::TimerRead, "a3"),
            ],
        );
        let b = trace("beta", &[(2, NondeterminismSource::TimerRead, "b2")]);
        let merged = merge_fleet_traces(&[node("alpha", a), node("beta", b)]);
        let events = flatten_to_events(merged);
        let values: Vec<String> = events
            .iter()
            .map(|e| String::from_utf8(e.value.clone()).unwrap())
            .collect();
        assert_eq!(values, vec!["a1", "b2", "a3"]);
    }

    #[test]
    fn verify_catches_out_of_order() {
        // Hand-build a deliberately reversed sequence.
        let a = trace("alpha", &[(5, NondeterminismSource::TimerRead, "hi")]);
        let b = trace("alpha", &[(1, NondeterminismSource::TimerRead, "lo")]);
        let bad = vec![
            OrderedFleetEvent {
                node_id: nid("alpha"),
                lamport_clock: LamportClock::from_raw(5),
                event: a.events[0].clone(),
            },
            OrderedFleetEvent {
                node_id: nid("alpha"),
                lamport_clock: LamportClock::from_raw(1),
                event: b.events[0].clone(),
            },
        ];
        assert_eq!(
            verify_global_order(&bad),
            Err(FleetMergeError::OutOfOrder { index: 1 })
        );
    }

    #[test]
    fn ordered_event_serde_round_trip() {
        let t = trace("n", &[(9, NondeterminismSource::FloatingPointResult, "p")]);
        let merged = merge_fleet_traces(&[node("n", t)]);
        let json = serde_json::to_string(&merged[0]).unwrap();
        let restored: OrderedFleetEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(merged[0], restored);
    }

    #[test]
    fn larger_fleet_is_total_ordered_and_complete() {
        let names = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let mut nodes = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let evs: Vec<(u64, NondeterminismSource, String)> = (0..10)
                .map(|k| {
                    (
                        (k as u64) * 5 + i as u64,
                        NondeterminismSource::TimerRead,
                        format!("{name}-{k}"),
                    )
                })
                .collect();
            let mut t = NondeterminismTrace::new(*name);
            for (vts, src, val) in &evs {
                t.capture(src.clone(), val.as_bytes().to_vec(), *vts, "test");
            }
            t.finalise(100);
            nodes.push(node(name, t));
        }
        let merged = merge_fleet_traces(&nodes);
        assert_eq!(merged.len(), 50);
        verify_global_order(&merged).unwrap();
        let cs = clocks(&merged);
        assert!(cs.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn error_display_mentions_index() {
        let err = FleetMergeError::OutOfOrder { index: 4 };
        assert!(format!("{err}").contains('4'));
    }
}
