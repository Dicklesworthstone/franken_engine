// Lamport Evidence Annotation — Track DD.1 substrate (bd-cixqu.30.1).
//
// Each evidence record carries a `(node_id, lamport_clock)` pair so a
// downstream merger (Track DD.2) can replay distributed evidence
// streams in a total order. This module defines the substrate:
//
//   * `NodeId` — a canonical node identifier (length-bounded UTF-8
//     name; opaque to merger semantics).
//   * `LamportClock(u64)` — Lamport's logical clock (1978). Supports
//     `tick` (advance on local event), `observe` (max-then-tick on
//     receiving an event), and `merge` (max of two clocks; used by the
//     merger to maintain causal-respecting order).
//   * `EvidenceClock { node_id, clock }` — the paired tuple. This is
//     the "(node_id, lamport_clock) pair" the bead requires; downstream
//     evidence types embed this field directly.
//   * `LamportAnnotated` — trait for evidence types that carry a
//     `EvidenceClock`. Implementing it is opt-in; this DD.1 substrate
//     does not modify existing evidence types (that wide-fan migration
//     lands under DD.2 / DD.3).
//
// Existing chained-hash invariants are preserved: this module adds a
// new field where downstream callers integrate it; it does not change
// hashing semantics anywhere.
//
// Total-order requirement (deferred to DD.2):
//   * Strict total order = lex(`clock`, `node_id`). Two events with
//     identical clocks tie-break on the lexicographically smaller
//     `NodeId`. The `total_order_key` helper here exposes that key so
//     DD.2's merger can sort by it without re-deriving the rule.
//
// Reference: Lamport, "Time, Clocks, and the Ordering of Events in a
// Distributed System" (CACM 21:7, 1978).

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// NodeId — canonical node identifier
// ---------------------------------------------------------------------------

const NODE_ID_MAX_LEN: usize = 256;

/// Canonical node identifier for a participant in a distributed
/// evidence stream. UTF-8, non-empty, max 256 bytes. The merger
/// uses byte-lexicographic order on the inner string for total-order
/// tie-breaking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(String);

impl NodeId {
    /// Build a `NodeId`. Rejects empty strings and strings exceeding
    /// 256 bytes.
    pub fn try_new(value: impl Into<String>) -> Result<Self, LamportError> {
        let value: String = value.into();
        if value.is_empty() {
            return Err(LamportError::EmptyNodeId);
        }
        if value.len() > NODE_ID_MAX_LEN {
            return Err(LamportError::NodeIdTooLong {
                len: value.len(),
                max: NODE_ID_MAX_LEN,
            });
        }
        Ok(Self(value))
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// LamportClock — Lamport's logical clock primitive
// ---------------------------------------------------------------------------

/// Lamport logical clock value. Monotone-non-decreasing under `tick`,
/// `observe`, and `merge`. Stored as a `u64`; `tick` returns an error
/// on overflow rather than wrapping (we treat clock overflow as an
/// operational incident, not a wraparound).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct LamportClock(u64);

impl LamportClock {
    /// Initial clock (`0`). The first local event ticks it to `1`.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Construct from a raw `u64`.
    pub const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Access the raw `u64`.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Advance on a LOCAL event. The post-tick clock is `self + 1`.
    /// Returns `LamportError::ClockOverflow` if the clock would
    /// overflow `u64`.
    pub fn tick(self) -> Result<Self, LamportError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(LamportError::ClockOverflow)
    }

    /// Advance on a RECEIVED event with `observed` clock. The
    /// post-observation clock is `max(self, observed) + 1`. Returns
    /// `LamportError::ClockOverflow` if the result would overflow.
    pub fn observe(self, observed: Self) -> Result<Self, LamportError> {
        let max = self.0.max(observed.0);
        max.checked_add(1)
            .map(Self)
            .ok_or(LamportError::ClockOverflow)
    }

    /// Pure max of two clocks (used by the merger). Does NOT tick.
    pub fn merge(self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }
}

impl fmt::Display for LamportClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lc:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// EvidenceClock — the (node_id, lamport_clock) pair
// ---------------------------------------------------------------------------

/// The `(node_id, lamport_clock)` pair the bead requires each evidence
/// record to carry. Embed this directly in any evidence type that
/// wants Track DD total-order replay.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceClock {
    pub node_id: NodeId,
    pub clock: LamportClock,
}

impl EvidenceClock {
    /// Construct from raw parts.
    pub fn new(node_id: NodeId, clock: LamportClock) -> Self {
        Self { node_id, clock }
    }

    /// Total-order key for the merger: `(clock, node_id)`. Two events
    /// with identical clocks tie-break on the lexicographically smaller
    /// `node_id`. This is the canonical Lamport total order.
    pub fn total_order_key(&self) -> (LamportClock, &NodeId) {
        (self.clock, &self.node_id)
    }
}

impl PartialOrd for EvidenceClock {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvidenceClock {
    fn cmp(&self, other: &Self) -> Ordering {
        self.total_order_key().cmp(&other.total_order_key())
    }
}

impl fmt::Display for EvidenceClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}@{}]", self.node_id, self.clock)
    }
}

// ---------------------------------------------------------------------------
// LamportAnnotated — opt-in trait for evidence types
// ---------------------------------------------------------------------------

/// Evidence types implement this trait to expose their attached
/// `EvidenceClock`. The trait is opt-in; this DD.1 substrate does not
/// modify any existing evidence type (DD.2 / DD.3 are the migration
/// beads).
pub trait LamportAnnotated {
    /// The clock attached to this evidence atom.
    fn evidence_clock(&self) -> &EvidenceClock;
}

impl LamportAnnotated for EvidenceClock {
    fn evidence_clock(&self) -> &EvidenceClock {
        self
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LamportError {
    /// `NodeId::try_new` was called with an empty string.
    EmptyNodeId,
    /// `NodeId::try_new` was called with a string exceeding 256 bytes.
    NodeIdTooLong { len: usize, max: usize },
    /// `tick` / `observe` would overflow `u64`.
    ClockOverflow,
}

impl fmt::Display for LamportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNodeId => f.write_str("node id must be non-empty"),
            Self::NodeIdTooLong { len, max } => {
                write!(f, "node id length {len} exceeds max {max}")
            }
            Self::ClockOverflow => f.write_str("lamport clock would overflow u64"),
        }
    }
}

impl std::error::Error for LamportError {}

// ---------------------------------------------------------------------------
// Tests — Lamport semantics + total-order tie-breaking
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> NodeId {
        NodeId::try_new(s).unwrap()
    }

    fn c(v: u64) -> LamportClock {
        LamportClock::from_raw(v)
    }

    // ----- NodeId -----

    #[test]
    fn node_id_rejects_empty() {
        assert_eq!(NodeId::try_new("").unwrap_err(), LamportError::EmptyNodeId);
    }

    #[test]
    fn node_id_rejects_too_long() {
        let s = "a".repeat(257);
        let err = NodeId::try_new(s).unwrap_err();
        match err {
            LamportError::NodeIdTooLong { len, max } => {
                assert_eq!(len, 257);
                assert_eq!(max, 256);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_id_accepts_max_length() {
        let s = "a".repeat(256);
        assert!(NodeId::try_new(s).is_ok());
    }

    #[test]
    fn node_id_byte_lexicographic_order() {
        assert!(n("a") < n("b"));
        assert!(n("aa") < n("ab"));
        assert!(n("a") < n("aa"));
    }

    // ----- LamportClock basics -----

    #[test]
    fn lamport_zero_is_zero() {
        assert_eq!(LamportClock::zero().as_u64(), 0);
        assert_eq!(LamportClock::default(), LamportClock::zero());
    }

    #[test]
    fn tick_advances_by_one() {
        let lc = c(5);
        assert_eq!(lc.tick().unwrap(), c(6));
    }

    #[test]
    fn observe_advances_to_max_plus_one() {
        // self < observed
        assert_eq!(c(3).observe(c(10)).unwrap(), c(11));
        // self > observed
        assert_eq!(c(20).observe(c(5)).unwrap(), c(21));
        // self == observed
        assert_eq!(c(7).observe(c(7)).unwrap(), c(8));
    }

    #[test]
    fn merge_is_pure_max_no_tick() {
        assert_eq!(c(3).merge(c(10)), c(10));
        assert_eq!(c(20).merge(c(5)), c(20));
        assert_eq!(c(7).merge(c(7)), c(7));
    }

    // ----- LamportClock overflow protection -----

    #[test]
    fn tick_overflow_returns_error() {
        let err = LamportClock::from_raw(u64::MAX).tick().unwrap_err();
        assert_eq!(err, LamportError::ClockOverflow);
    }

    #[test]
    fn observe_overflow_returns_error() {
        let err = c(0).observe(LamportClock::from_raw(u64::MAX)).unwrap_err();
        assert_eq!(err, LamportError::ClockOverflow);
    }

    // ----- LamportClock causal-respecting property -----

    #[test]
    fn tick_is_monotone() {
        let mut clock = LamportClock::zero();
        for _ in 0..100 {
            let next = clock.tick().unwrap();
            assert!(next > clock);
            clock = next;
        }
    }

    #[test]
    fn observe_respects_happens_before() {
        // If A observes a clock from B, A's clock > B's previous clock.
        // (This is the core Lamport invariant: if event X happens before
        // event Y, then clock(X) < clock(Y).)
        let b_local_clock = c(7);
        let a_after_observing_b = c(2).observe(b_local_clock).unwrap();
        assert!(a_after_observing_b > b_local_clock);
    }

    // ----- EvidenceClock -----

    #[test]
    fn evidence_clock_construction() {
        let ec = EvidenceClock::new(n("alpha"), c(42));
        assert_eq!(ec.node_id.as_str(), "alpha");
        assert_eq!(ec.clock.as_u64(), 42);
    }

    #[test]
    fn evidence_clock_total_order_key_is_clock_then_node() {
        let ec = EvidenceClock::new(n("beta"), c(5));
        let (clock, node) = ec.total_order_key();
        assert_eq!(clock, c(5));
        assert_eq!(node, &n("beta"));
    }

    #[test]
    fn evidence_clock_ord_breaks_tie_on_node_id() {
        let e1 = EvidenceClock::new(n("alpha"), c(10));
        let e2 = EvidenceClock::new(n("beta"), c(10));
        // alpha < beta lexicographically.
        assert!(e1 < e2);
    }

    #[test]
    fn evidence_clock_ord_dominated_by_clock() {
        // Even though "zeta" > "alpha" lex, clock 5 < clock 10 wins.
        let early = EvidenceClock::new(n("zeta"), c(5));
        let late = EvidenceClock::new(n("alpha"), c(10));
        assert!(early < late);
    }

    #[test]
    fn evidence_clock_equality_requires_both_fields() {
        let e1 = EvidenceClock::new(n("alpha"), c(5));
        let e2 = EvidenceClock::new(n("alpha"), c(5));
        let e3 = EvidenceClock::new(n("alpha"), c(6));
        let e4 = EvidenceClock::new(n("beta"), c(5));
        assert_eq!(e1, e2);
        assert_ne!(e1, e3);
        assert_ne!(e1, e4);
    }

    // ----- Total-order merge (the canonical use-case) -----

    #[test]
    fn sorted_event_stream_respects_lamport_total_order() {
        let mut events = vec![
            EvidenceClock::new(n("alpha"), c(5)),
            EvidenceClock::new(n("beta"), c(3)),
            EvidenceClock::new(n("alpha"), c(3)),
            EvidenceClock::new(n("gamma"), c(5)),
            EvidenceClock::new(n("beta"), c(7)),
        ];
        events.sort();
        // Expected order by (clock, node_id):
        // (3, alpha), (3, beta), (5, alpha), (5, gamma), (7, beta)
        assert_eq!(
            events,
            vec![
                EvidenceClock::new(n("alpha"), c(3)),
                EvidenceClock::new(n("beta"), c(3)),
                EvidenceClock::new(n("alpha"), c(5)),
                EvidenceClock::new(n("gamma"), c(5)),
                EvidenceClock::new(n("beta"), c(7)),
            ]
        );
    }

    #[test]
    fn merger_total_order_is_a_strict_total_order() {
        // Antisymmetric + transitive + total on a small fixture set.
        let fixtures = vec![
            EvidenceClock::new(n("a"), c(1)),
            EvidenceClock::new(n("a"), c(2)),
            EvidenceClock::new(n("b"), c(1)),
            EvidenceClock::new(n("b"), c(2)),
            EvidenceClock::new(n("c"), c(2)),
        ];
        // For every pair, exactly one of `<`, `==`, `>` holds.
        for a in &fixtures {
            for b in &fixtures {
                let lt = a < b;
                let eq = a == b;
                let gt = a > b;
                assert_eq!(
                    (lt as u8) + (eq as u8) + (gt as u8),
                    1,
                    "trichotomy failed on a={a}, b={b}"
                );
            }
        }
        // Transitivity check.
        for a in &fixtures {
            for b in &fixtures {
                for c_inner in &fixtures {
                    if a < b && b < c_inner {
                        assert!(
                            a < c_inner,
                            "transitivity violated: a={a}, b={b}, c={c_inner}"
                        );
                    }
                }
            }
        }
    }

    // ----- LamportAnnotated trait -----

    #[test]
    fn evidence_clock_implements_lamport_annotated() {
        let ec = EvidenceClock::new(n("alpha"), c(5));
        let r = ec.evidence_clock();
        assert_eq!(r, &ec);
    }

    // ----- Serde round-trips -----

    #[test]
    fn lamport_clock_serde_round_trip() {
        let lc = c(123_456_789);
        let json = serde_json::to_string(&lc).unwrap();
        let restored: LamportClock = serde_json::from_str(&json).unwrap();
        assert_eq!(lc, restored);
    }

    #[test]
    fn node_id_serde_round_trip() {
        let nid = n("alpha-node-12");
        let json = serde_json::to_string(&nid).unwrap();
        let restored: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(nid, restored);
    }

    #[test]
    fn evidence_clock_serde_round_trip() {
        let ec = EvidenceClock::new(n("alpha"), c(42));
        let json = serde_json::to_string(&ec).unwrap();
        let restored: EvidenceClock = serde_json::from_str(&json).unwrap();
        assert_eq!(ec, restored);
    }

    // ----- Display formatting -----

    #[test]
    fn display_strings_are_concise() {
        assert_eq!(format!("{}", c(7)), "lc:7");
        assert_eq!(format!("{}", n("alpha")), "alpha");
        assert_eq!(
            format!("{}", EvidenceClock::new(n("alpha"), c(42))),
            "[alpha@lc:42]"
        );
    }

    #[test]
    fn error_display_messages() {
        assert!(format!("{}", LamportError::EmptyNodeId).contains("non-empty"));
        assert!(format!("{}", LamportError::ClockOverflow).contains("overflow"));
        let s = format!("{}", LamportError::NodeIdTooLong { len: 999, max: 256 });
        assert!(s.contains("999"));
        assert!(s.contains("256"));
    }
}
