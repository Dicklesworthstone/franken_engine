// Lamport Total-Order Merger — Track DD.2 substrate (bd-cixqu.30.2).
//
// Given evidence atoms tagged with `EvidenceClock` (from DD.1's
// `lamport_evidence_annotation`), merge their streams into a single
// deterministic total order. The merger is a pure function: same
// inputs → same output across runs and across machines.
//
// Total-order key (LEX order, descending precedence):
//
//   1. `lamport_clock` (u64, ascending) — Lamport's primary key.
//   2. `node_id` (UTF-8 lex, ascending) — secondary key for events
//      with equal Lamport clocks across nodes.
//   3. `content_hash` (32-byte lex, ascending) — tertiary key for
//      events that share BOTH a clock and a node id. Per Lamport
//      semantics this should not happen (a node's `tick` is strictly
//      monotone), but operational reality may produce ties through
//      backfills, recoveries, or clock-imports; we need a deterministic
//      tie-breaker to make replay byte-identical regardless.
//
// The merger does NOT validate the underlying Lamport invariants
// (that's the producer's job). It assumes inputs are well-formed and
// focuses on the *merge*: stable, deterministic, replay-anchored.
//
// Anchoring beads:
//   * bd-cixqu.30.1 (DD.1, CLOSED) — `EvidenceClock`, `NodeId`,
//     `LamportClock` substrate.
//   * bd-cixqu.30.3 (DD.3) — `frankenctl replay run --fleet-trace
//     <dir>`; consumes this merger to assemble a single deterministic
//     replay trace from a fleet directory of per-node traces.

use crate::hash_tiers::ContentHash;
use crate::lamport_evidence_annotation::{EvidenceClock, LamportClock, NodeId};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// MergeAtom — the unit the merger operates on
// ---------------------------------------------------------------------------

/// One evidence atom in a merge stream. The `payload_hash` is the
/// content hash of the underlying evidence payload; the merger uses
/// it ONLY for tertiary tie-breaking. Payload data itself is opaque
/// to this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeAtom {
    /// (node_id, lamport_clock) per DD.1.
    pub clock: EvidenceClock,
    /// Content-addressed digest of the evidence payload. Tertiary
    /// tie-break key.
    pub payload_hash: ContentHash,
}

impl MergeAtom {
    pub fn new(clock: EvidenceClock, payload_hash: ContentHash) -> Self {
        Self {
            clock,
            payload_hash,
        }
    }

    pub fn clock(&self) -> &EvidenceClock {
        &self.clock
    }

    pub fn lamport_clock(&self) -> LamportClock {
        self.clock.clock
    }

    pub fn node_id(&self) -> &NodeId {
        &self.clock.node_id
    }

    pub fn payload_hash(&self) -> &ContentHash {
        &self.payload_hash
    }

    /// Total-order key. `(lamport_clock, node_id, payload_hash)`.
    pub fn total_order_key(&self) -> (LamportClock, &NodeId, &ContentHash) {
        (self.clock.clock, &self.clock.node_id, &self.payload_hash)
    }
}

impl PartialOrd for MergeAtom {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MergeAtom {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare (clock, node_id, payload_hash) lexicographically.
        match self.clock.clock.cmp(&other.clock.clock) {
            Ordering::Equal => match self.clock.node_id.cmp(&other.clock.node_id) {
                Ordering::Equal => self
                    .payload_hash
                    .as_bytes()
                    .cmp(other.payload_hash.as_bytes()),
                other_node => other_node,
            },
            other_clock => other_clock,
        }
    }
}

// ---------------------------------------------------------------------------
// Merger — the pure-function entry points
// ---------------------------------------------------------------------------

/// Merge multiple per-stream `Vec<MergeAtom>`s into a single
/// total-ordered `Vec`. Inputs are NOT required to be sorted; the
/// merger sorts the union. Duplicates (atoms with identical total-
/// order keys AND identical payload-hashes) are PRESERVED — this is
/// a merge, not a dedup pass.
///
/// The output is deterministic: same multiset of inputs → same
/// output sequence, regardless of input stream order.
pub fn merge_streams(streams: Vec<Vec<MergeAtom>>) -> Vec<MergeAtom> {
    let total: usize = streams.iter().map(|s| s.len()).sum();
    let mut out = Vec::with_capacity(total);
    for stream in streams {
        out.extend(stream);
    }
    out.sort();
    out
}

/// Merge with explicit deduplication: atoms with identical total-
/// order keys (same clock, node_id, payload_hash) collapse to a
/// single occurrence. Useful when the same atom arrives via two
/// gossip paths.
pub fn merge_streams_dedup(streams: Vec<Vec<MergeAtom>>) -> Vec<MergeAtom> {
    let mut out = merge_streams(streams);
    out.dedup();
    out
}

/// Validate that a merged sequence is in strict total order (no
/// adjacent equal-key duplicates, every pair is strictly ordered).
/// Returns the index of the first violation, or `Ok(())` if the
/// sequence is well-ordered.
pub fn verify_strict_total_order(sequence: &[MergeAtom]) -> Result<(), MergerError> {
    for (i, window) in sequence.windows(2).enumerate() {
        match window[0].cmp(&window[1]) {
            Ordering::Less => continue,
            Ordering::Equal => {
                return Err(MergerError::DuplicateKey { index: i + 1 });
            }
            Ordering::Greater => {
                return Err(MergerError::OutOfOrder { index: i + 1 });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergerError {
    /// Two adjacent atoms had identical total-order keys.
    DuplicateKey { index: usize },
    /// Atoms were not in ascending total order.
    OutOfOrder { index: usize },
}

impl fmt::Display for MergerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey { index } => {
                write!(f, "duplicate total-order key at index {index}")
            }
            Self::OutOfOrder { index } => {
                write!(f, "out-of-order pair at index {index}")
            }
        }
    }
}

impl std::error::Error for MergerError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(s: &str) -> NodeId {
        NodeId::try_new(s).unwrap()
    }

    fn clk(v: u64) -> LamportClock {
        LamportClock::from_raw(v)
    }

    fn h(s: &str) -> ContentHash {
        ContentHash::compute(s.as_bytes())
    }

    fn atom(node: &str, lc: u64, payload: &str) -> MergeAtom {
        MergeAtom::new(EvidenceClock::new(nid(node), clk(lc)), h(payload))
    }

    // ----- MergeAtom basics -----

    #[test]
    fn atom_accessors() {
        let a = atom("alpha", 5, "p1");
        assert_eq!(a.lamport_clock(), clk(5));
        assert_eq!(a.node_id(), &nid("alpha"));
        assert_eq!(a.payload_hash(), &h("p1"));
        let (c, n, ph) = a.total_order_key();
        assert_eq!(c, clk(5));
        assert_eq!(n, &nid("alpha"));
        assert_eq!(ph, &h("p1"));
    }

    // ----- Ord precedence -----

    #[test]
    fn ord_primary_is_lamport_clock() {
        let earlier = atom("zeta", 3, "p");
        let later = atom("alpha", 10, "p");
        // Even though zeta > alpha lex, clock 3 < 10 wins.
        assert!(earlier < later);
    }

    #[test]
    fn ord_secondary_is_node_id_when_clock_equal() {
        let a = atom("alpha", 5, "p_same");
        let b = atom("beta", 5, "p_same");
        // Clock equal; alpha < beta lex.
        assert!(a < b);
    }

    #[test]
    fn ord_tertiary_is_payload_hash_when_clock_and_node_equal() {
        // Two atoms with the same node_id AND same clock — operational
        // reality (backfill / recovery). Tertiary key is content hash.
        let p_aaa = h("aaa");
        let p_bbb = h("bbb");
        // Determine lex order of the SHA256 hashes.
        let (lo, hi) = if p_aaa.as_bytes() <= p_bbb.as_bytes() {
            (p_aaa, p_bbb)
        } else {
            (p_bbb, p_aaa)
        };
        let a = MergeAtom::new(EvidenceClock::new(nid("alpha"), clk(5)), lo);
        let b = MergeAtom::new(EvidenceClock::new(nid("alpha"), clk(5)), hi);
        assert!(a < b);
    }

    #[test]
    fn ord_is_consistent_with_eq() {
        let a = atom("alpha", 5, "p");
        let b = atom("alpha", 5, "p");
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }

    // ----- merge_streams basic semantics -----

    #[test]
    fn empty_input_returns_empty() {
        let merged: Vec<MergeAtom> = merge_streams(vec![]);
        assert!(merged.is_empty());
    }

    #[test]
    fn single_empty_stream_returns_empty() {
        let merged = merge_streams(vec![vec![]]);
        assert!(merged.is_empty());
    }

    #[test]
    fn single_stream_pass_through_with_sort() {
        let stream = vec![
            atom("alpha", 5, "p1"),
            atom("alpha", 3, "p2"),
            atom("alpha", 7, "p3"),
        ];
        let merged = merge_streams(vec![stream]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].lamport_clock(), clk(3));
        assert_eq!(merged[1].lamport_clock(), clk(5));
        assert_eq!(merged[2].lamport_clock(), clk(7));
    }

    #[test]
    fn merge_two_streams_interleaves_by_clock() {
        let s1 = vec![
            atom("alpha", 1, "a1"),
            atom("alpha", 3, "a3"),
            atom("alpha", 5, "a5"),
        ];
        let s2 = vec![
            atom("beta", 2, "b2"),
            atom("beta", 4, "b4"),
            atom("beta", 6, "b6"),
        ];
        let merged = merge_streams(vec![s1, s2]);
        let clocks: Vec<u64> = merged.iter().map(|a| a.lamport_clock().as_u64()).collect();
        assert_eq!(clocks, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn merge_breaks_ties_by_node_id_then_payload_hash() {
        let s1 = vec![atom("beta", 5, "x"), atom("alpha", 5, "x")];
        let s2 = vec![atom("alpha", 5, "y")];
        let merged = merge_streams(vec![s1, s2]);
        // All have clock 5. Order should be (alpha, h(x)), (alpha, h(y)),
        // (beta, h(x)) — but x/y hash order depends on SHA. So we just
        // verify alpha < beta and that all 3 entries are present.
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].node_id(), &nid("alpha"));
        assert_eq!(merged[1].node_id(), &nid("alpha"));
        assert_eq!(merged[2].node_id(), &nid("beta"));
    }

    // ----- Determinism -----

    #[test]
    fn merge_is_deterministic_regardless_of_input_stream_order() {
        let a = atom("alpha", 3, "x");
        let b = atom("beta", 5, "y");
        let c = atom("gamma", 4, "z");
        // Three different orderings of the same multiset of streams.
        let m1 = merge_streams(vec![vec![a.clone()], vec![b.clone()], vec![c.clone()]]);
        let m2 = merge_streams(vec![vec![c.clone()], vec![a.clone()], vec![b.clone()]]);
        let m3 = merge_streams(vec![vec![b.clone()], vec![c.clone()], vec![a.clone()]]);
        assert_eq!(m1, m2);
        assert_eq!(m2, m3);
    }

    #[test]
    fn merge_is_deterministic_regardless_of_intra_stream_order() {
        // Same atoms, different intra-stream orderings → same output.
        let m1 = merge_streams(vec![
            vec![atom("alpha", 3, "x"), atom("alpha", 1, "y")],
            vec![atom("beta", 2, "z")],
        ]);
        let m2 = merge_streams(vec![
            vec![atom("alpha", 1, "y"), atom("alpha", 3, "x")],
            vec![atom("beta", 2, "z")],
        ]);
        assert_eq!(m1, m2);
    }

    // ----- Duplicate handling -----

    #[test]
    fn merge_streams_preserves_duplicates() {
        let m = merge_streams(vec![
            vec![atom("alpha", 5, "x")],
            vec![atom("alpha", 5, "x")],
        ]);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0], m[1]);
    }

    #[test]
    fn merge_streams_dedup_collapses_duplicates() {
        let m = merge_streams_dedup(vec![
            vec![atom("alpha", 5, "x"), atom("beta", 5, "y")],
            vec![atom("alpha", 5, "x"), atom("beta", 6, "z")],
        ]);
        assert_eq!(m.len(), 3); // (alpha,5,x) + (beta,5,y) + (beta,6,z)
        // Verify the dedup'd (alpha,5,x) appears exactly once.
        let alpha_count = m.iter().filter(|a| a == &&atom("alpha", 5, "x")).count();
        assert_eq!(alpha_count, 1);
    }

    // ----- verify_strict_total_order -----

    #[test]
    fn verify_passes_on_sorted_sequence() {
        let m = merge_streams(vec![vec![
            atom("alpha", 1, "a"),
            atom("beta", 2, "b"),
            atom("gamma", 3, "c"),
        ]]);
        // Dedup the merged output before verify (which rejects dupes).
        verify_strict_total_order(&m).unwrap();
    }

    #[test]
    fn verify_catches_duplicate_key() {
        let dup = vec![atom("alpha", 5, "x"), atom("alpha", 5, "x")];
        let err = verify_strict_total_order(&dup).unwrap_err();
        assert_eq!(err, MergerError::DuplicateKey { index: 1 });
    }

    #[test]
    fn verify_catches_out_of_order() {
        let bad = vec![atom("alpha", 5, "x"), atom("alpha", 3, "y")];
        let err = verify_strict_total_order(&bad).unwrap_err();
        assert_eq!(err, MergerError::OutOfOrder { index: 1 });
    }

    #[test]
    fn verify_empty_sequence_is_ok() {
        verify_strict_total_order(&[]).unwrap();
    }

    #[test]
    fn verify_single_element_sequence_is_ok() {
        verify_strict_total_order(&[atom("alpha", 5, "x")]).unwrap();
    }

    // ----- Replay byte-identity -----

    #[test]
    fn replay_produces_identical_merged_order_across_runs() {
        let make_streams = || {
            vec![
                vec![
                    atom("alpha", 1, "a1"),
                    atom("alpha", 4, "a4"),
                    atom("alpha", 7, "a7"),
                ],
                vec![
                    atom("beta", 2, "b2"),
                    atom("beta", 4, "b4"),
                    atom("beta", 8, "b8"),
                ],
                vec![
                    atom("gamma", 3, "g3"),
                    atom("gamma", 5, "g5"),
                    atom("gamma", 6, "g6"),
                ],
            ]
        };
        let r1 = merge_streams(make_streams());
        let r2 = merge_streams(make_streams());
        let r3 = merge_streams(make_streams());
        assert_eq!(r1, r2);
        assert_eq!(r2, r3);
        // Spot check: every adjacent pair is strictly ordered.
        verify_strict_total_order(&merge_streams_dedup(make_streams())).unwrap();
    }

    // ----- Larger fleet-trace simulation -----

    #[test]
    fn large_multi_node_merge_is_total_ordered() {
        // 5 nodes, 10 atoms each, randomly-interleaved clocks (but
        // deterministic in source).
        let nodes = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let mut streams = Vec::new();
        for (node_idx, node) in nodes.iter().enumerate() {
            let mut stream = Vec::new();
            for i in 0..10 {
                // Each node's clocks: 1+node_idx, 2+node_idx, ...
                let clock_v = (i as u64) * 5 + (node_idx as u64);
                stream.push(atom(node, clock_v, &format!("{node}-e{i}")));
            }
            streams.push(stream);
        }
        let merged = merge_streams(streams);
        assert_eq!(merged.len(), 50);
        // Verify clocks are non-decreasing.
        for w in merged.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    // ----- Serde -----

    #[test]
    fn merge_atom_serde_round_trip() {
        let a = atom("alpha", 42, "payload");
        let json = serde_json::to_string(&a).unwrap();
        let restored: MergeAtom = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }

    // ----- Error Display -----

    #[test]
    fn error_display_includes_index() {
        assert!(format!("{}", MergerError::DuplicateKey { index: 7 }).contains("7"));
        assert!(format!("{}", MergerError::OutOfOrder { index: 9 }).contains("9"));
    }
}
