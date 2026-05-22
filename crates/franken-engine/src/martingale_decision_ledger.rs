// Martingale Decision Ledger — anytime-valid stopping substrate (bd-cixqu.27.1).
//
// Each evidence event extends a non-negative martingale M_n (an
// "e-process" in the Howard / Ramdas / Koolen / Grünwald terminology).
// Concretely, we track log(M_n) in fixed-point millionths and update it
// additively: `log_m_{n+1} = log_m_n + log_likelihood_ratio_n`. The
// stopping rule is DERIVED from the threshold — `M_n >= 1 / α`
// (equivalently `log_m >= -log α`) — rather than being separately
// encoded by the caller. The whole ledger is an append-only,
// content-addressed, replayable artifact.
//
// Why this substrate (Lai 1995, Tartakovsky 2014, Ramdas et al. 2020):
//
//   * An e-process supports anytime-valid testing: by Ville's
//     inequality, `P(sup_n M_n >= 1/α) <= α` for any (random) stopping
//     time. The operator may inspect M_n at any point — including
//     after data-dependent stopping decisions — without invalidating
//     the false-positive guarantee. (This is what "anytime-valid"
//     means: it composes under optional stopping.)
//   * The log-space representation keeps the math numerically stable
//     even when the likelihood ratio compounds across hundreds of
//     events; we never multiply M itself.
//   * Storing the FULL trajectory (every event's likelihood-ratio
//     contribution + the resulting state) is what makes the ledger
//     replayable. A consumer can re-derive every intermediate state
//     and the stopping verdict by replaying the events in order.
//
// Non-goals for this bead:
//
//   * Wiring into specific guardplane decisions (e-process vs
//     expected-loss unification lands under bd-cixqu.27.2).
//   * Conformal-prediction layering (bd-cixqu.33.1, GG.1).
//   * Cross-axis composition with the unified authority algebra
//     (bd-cixqu.26.3, Z.3).
//
// This file is the contract definition + the algebraic / numerical
// laws (proven via unit tests). Downstream beads consume the
// `MartingaleLedger::append` / `current_state` / `replay` /
// `is_stopped` surface.

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Convention: 1.0 in millionths.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// MartingaleState — the running state of the process
// ---------------------------------------------------------------------------

/// State of the martingale process after appending `n` events.
///
/// We store `log(M_n)` in fixed-point millionths rather than `M_n`
/// itself for numerical stability. `M_0 = 1`, so the initial
/// `log_m_millionths` is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MartingaleState {
    /// Number of events incorporated.
    pub event_count: u64,
    /// `log(M_n)` in millionths (1_000_000 = 1.0).
    pub log_m_millionths: i64,
    /// Log of the most recent likelihood-ratio contribution, in
    /// millionths. Set to zero for the initial state.
    pub last_log_likelihood_ratio_millionths: i64,
}

impl MartingaleState {
    /// Initial state (`M_0 = 1`, no events).
    pub const fn initial() -> Self {
        Self {
            event_count: 0,
            log_m_millionths: 0,
            last_log_likelihood_ratio_millionths: 0,
        }
    }

    /// Whether `M_n >= e^{log_threshold_millionths / 1_000_000}` — i.e.
    /// the stopping boundary has been crossed for the supplied
    /// threshold.
    pub fn crosses_threshold(&self, log_threshold_millionths: i64) -> bool {
        self.log_m_millionths >= log_threshold_millionths
    }
}

// ---------------------------------------------------------------------------
// StoppingRuleKind / StoppingThreshold — the derived stopping rule
// ---------------------------------------------------------------------------

/// Reason category for a stop verdict.
///
/// `Reject` — the martingale crossed the upper boundary
/// `(M_n >= 1/α)`, sufficient evidence to reject the null hypothesis.
/// `Boundary` — the boundary was hit exactly (within the millionths
/// quantum); the operator decides whether to treat this as Reject or
/// Continue. We surface it as a distinct verdict so callers don't
/// accidentally treat a tie as "no signal".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoppingRuleKind {
    Reject,
    Boundary,
}

impl fmt::Display for StoppingRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reject => f.write_str("reject"),
            Self::Boundary => f.write_str("boundary"),
        }
    }
}

/// Stopping threshold for the ledger.
///
/// `log_threshold_millionths` is `log(1/α) * 1_000_000`. For the
/// common case `α = 0.05`, that is `-log(0.05) ~= 2.995732`, so
/// `log_threshold_millionths = 2_995_732`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoppingThreshold {
    pub log_threshold_millionths: i64,
}

impl StoppingThreshold {
    /// Threshold built directly from `log(1/α)` in millionths. Must be
    /// strictly positive: an α >= 1 makes the test trivially fire on
    /// initialization.
    pub fn try_from_log_millionths(log_threshold_millionths: i64) -> Result<Self, MartingaleError> {
        if log_threshold_millionths <= 0 {
            return Err(MartingaleError::NonPositiveThreshold);
        }
        Ok(Self {
            log_threshold_millionths,
        })
    }
}

// ---------------------------------------------------------------------------
// MartingaleEvent — one appended record
// ---------------------------------------------------------------------------

/// A single event appended to the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MartingaleEvent {
    /// 1-indexed sequence position in the ledger.
    pub sequence: u64,
    /// Wall-clock-ish timestamp in nanoseconds, opaque to this module.
    pub timestamp_ns: u64,
    /// `log(likelihood_ratio)` contribution for this event, in
    /// millionths. May be negative (evidence against the alternative).
    pub log_likelihood_ratio_millionths: i64,
    /// Content-addressed digest of the originating event payload.
    /// Lets a replay verifier confirm the same payloads produced the
    /// same trajectory.
    pub payload_digest: ContentHash,
    /// State AFTER incorporating this event.
    pub state_after: MartingaleState,
    /// Security epoch at the time the event was appended.
    pub epoch: SecurityEpoch,
    /// Verdict emitted when this event was processed.
    pub verdict: MartingaleVerdict,
}

// ---------------------------------------------------------------------------
// MartingaleVerdict — the per-event verdict surfaced to callers
// ---------------------------------------------------------------------------

/// Verdict surfaced after each `append`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MartingaleVerdict {
    /// `M_n` is strictly below `1/α`; keep collecting evidence.
    Continue,
    /// `M_n` has reached the stopping boundary; emit a stop receipt.
    Stop { reason: StoppingRuleKind },
}

impl MartingaleVerdict {
    pub fn is_stop(&self) -> bool {
        matches!(self, Self::Stop { .. })
    }
}

// ---------------------------------------------------------------------------
// MartingaleLedger — the append-only ledger
// ---------------------------------------------------------------------------

/// Append-only martingale ledger.
///
/// `append` extends the martingale; the stopping rule is derived from
/// the configured threshold. Once a stop verdict is emitted, the
/// ledger is "stopped" — subsequent `append` calls return
/// `MartingaleError::AlreadyStopped` without mutating state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MartingaleLedger {
    threshold: StoppingThreshold,
    epoch: SecurityEpoch,
    state: MartingaleState,
    events: Vec<MartingaleEvent>,
    stopped_at_sequence: Option<u64>,
}

impl MartingaleLedger {
    /// Create a fresh ledger anchored to the given threshold + epoch.
    pub fn new(threshold: StoppingThreshold, epoch: SecurityEpoch) -> Self {
        Self {
            threshold,
            epoch,
            state: MartingaleState::initial(),
            events: Vec::new(),
            stopped_at_sequence: None,
        }
    }

    /// Configured threshold.
    pub fn threshold(&self) -> StoppingThreshold {
        self.threshold
    }

    /// Anchoring security epoch.
    pub fn epoch(&self) -> SecurityEpoch {
        self.epoch
    }

    /// Current `(event_count, log_m_millionths, last_log_lr_millionths)` triple.
    pub fn current_state(&self) -> MartingaleState {
        self.state
    }

    /// Read-only access to the appended event history.
    pub fn events(&self) -> &[MartingaleEvent] {
        &self.events
    }

    /// Total events appended so far.
    pub fn event_count(&self) -> u64 {
        self.state.event_count
    }

    /// Whether the ledger has fired a Stop verdict.
    pub fn is_stopped(&self) -> bool {
        self.stopped_at_sequence.is_some()
    }

    /// Sequence number at which the ledger stopped, if any.
    pub fn stopped_at_sequence(&self) -> Option<u64> {
        self.stopped_at_sequence
    }

    /// Append an event. Returns the verdict that fired.
    ///
    /// On overflow of the `log_m_millionths` accumulator, returns
    /// `MartingaleError::LogAccumulatorOverflow`. On attempting to
    /// extend a stopped ledger, returns
    /// `MartingaleError::AlreadyStopped`.
    pub fn append(
        &mut self,
        log_likelihood_ratio_millionths: i64,
        payload_digest: ContentHash,
        timestamp_ns: u64,
    ) -> Result<MartingaleVerdict, MartingaleError> {
        if self.is_stopped() {
            return Err(MartingaleError::AlreadyStopped);
        }

        // Update log(M_n) additively with overflow detection.
        let next_log_m = self
            .state
            .log_m_millionths
            .checked_add(log_likelihood_ratio_millionths)
            .ok_or(MartingaleError::LogAccumulatorOverflow)?;

        let next_sequence = self
            .state
            .event_count
            .checked_add(1)
            .ok_or(MartingaleError::SequenceOverflow)?;

        let next_state = MartingaleState {
            event_count: next_sequence,
            log_m_millionths: next_log_m,
            last_log_likelihood_ratio_millionths: log_likelihood_ratio_millionths,
        };

        let verdict = derive_verdict(&next_state, &self.threshold);

        self.state = next_state;

        let event = MartingaleEvent {
            sequence: next_sequence,
            timestamp_ns,
            log_likelihood_ratio_millionths,
            payload_digest,
            state_after: next_state,
            epoch: self.epoch,
            verdict,
        };
        self.events.push(event);

        if let MartingaleVerdict::Stop { .. } = verdict {
            self.stopped_at_sequence = Some(next_sequence);
        }

        Ok(verdict)
    }

    /// Deterministic replay: reconstruct every intermediate state from
    /// the recorded events, returning the trajectory. The returned
    /// `Vec` has length `events.len() + 1` (initial state plus one
    /// per event). The final element MUST equal `self.state`.
    pub fn replay(&self) -> Vec<MartingaleState> {
        let mut states = Vec::with_capacity(self.events.len() + 1);
        let mut current = MartingaleState::initial();
        states.push(current);
        for event in &self.events {
            let next_log_m = current
                .log_m_millionths
                .saturating_add(event.log_likelihood_ratio_millionths);
            current = MartingaleState {
                event_count: event.sequence,
                log_m_millionths: next_log_m,
                last_log_likelihood_ratio_millionths: event.log_likelihood_ratio_millionths,
            };
            states.push(current);
        }
        states
    }
}

// ---------------------------------------------------------------------------
// Derived stopping rule — the WHOLE POINT of "derived, not separately encoded"
// ---------------------------------------------------------------------------

/// Pure function: given a state and a threshold, what verdict does the
/// stopping rule fire? Exposed publicly so callers can dry-run a
/// hypothetical state without appending it.
pub fn derive_verdict(state: &MartingaleState, threshold: &StoppingThreshold) -> MartingaleVerdict {
    if state.log_m_millionths == threshold.log_threshold_millionths {
        MartingaleVerdict::Stop {
            reason: StoppingRuleKind::Boundary,
        }
    } else if state.log_m_millionths > threshold.log_threshold_millionths {
        MartingaleVerdict::Stop {
            reason: StoppingRuleKind::Reject,
        }
    } else {
        MartingaleVerdict::Continue
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MartingaleError {
    /// `StoppingThreshold::try_from_log_millionths` was called with a
    /// non-positive value.
    NonPositiveThreshold,
    /// `append` was called after a Stop verdict.
    AlreadyStopped,
    /// `log_m_millionths` would overflow `i64` if extended.
    LogAccumulatorOverflow,
    /// `event_count` would overflow `u64` if extended.
    SequenceOverflow,
}

impl fmt::Display for MartingaleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositiveThreshold => {
                f.write_str("stopping threshold log(1/α) must be strictly positive")
            }
            Self::AlreadyStopped => f.write_str("cannot append to a stopped martingale ledger"),
            Self::LogAccumulatorOverflow => f.write_str("log(M_n) accumulator would overflow i64"),
            Self::SequenceOverflow => f.write_str("event sequence would overflow u64"),
        }
    }
}

impl std::error::Error for MartingaleError {}

// ---------------------------------------------------------------------------
// Tests — contract laws and stopping behaviour
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn digest(tag: &str) -> ContentHash {
        ContentHash::compute(tag.as_bytes())
    }

    fn small_threshold() -> StoppingThreshold {
        // α = 0.05 → log(1/α) ≈ 2.995732 → 2_995_732 millionths.
        StoppingThreshold::try_from_log_millionths(2_995_732).unwrap()
    }

    // ----- Initial state -----

    #[test]
    fn initial_state_is_unit_martingale() {
        let s = MartingaleState::initial();
        assert_eq!(s.event_count, 0);
        assert_eq!(s.log_m_millionths, 0);
        assert_eq!(s.last_log_likelihood_ratio_millionths, 0);
    }

    #[test]
    fn fresh_ledger_is_not_stopped() {
        let l = MartingaleLedger::new(small_threshold(), epoch());
        assert!(!l.is_stopped());
        assert_eq!(l.event_count(), 0);
        assert_eq!(l.stopped_at_sequence(), None);
        assert_eq!(l.current_state(), MartingaleState::initial());
    }

    // ----- Threshold validation -----

    #[test]
    fn threshold_rejects_zero() {
        let err = StoppingThreshold::try_from_log_millionths(0).unwrap_err();
        assert_eq!(err, MartingaleError::NonPositiveThreshold);
    }

    #[test]
    fn threshold_rejects_negative() {
        let err = StoppingThreshold::try_from_log_millionths(-1).unwrap_err();
        assert_eq!(err, MartingaleError::NonPositiveThreshold);
    }

    // ----- Append: additive log-update -----

    #[test]
    fn append_adds_log_lr_to_log_m() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let _ = l.append(500_000, digest("e1"), 100).unwrap();
        assert_eq!(l.current_state().log_m_millionths, 500_000);
        assert_eq!(l.current_state().event_count, 1);
    }

    #[test]
    fn multiple_appends_compound_additively_in_log_space() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        l.append(100_000, digest("a"), 1).unwrap();
        l.append(200_000, digest("b"), 2).unwrap();
        l.append(-50_000, digest("c"), 3).unwrap();
        // 0 + 100k + 200k - 50k = 250k
        assert_eq!(l.current_state().log_m_millionths, 250_000);
        assert_eq!(l.event_count(), 3);
    }

    // ----- Stopping rule derivation -----

    #[test]
    fn continue_verdict_when_log_m_below_threshold() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let v = l.append(1_000_000, digest("e"), 1).unwrap();
        assert_eq!(v, MartingaleVerdict::Continue);
        assert!(!l.is_stopped());
    }

    #[test]
    fn reject_verdict_when_log_m_above_threshold() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let v = l.append(3_000_000, digest("e"), 1).unwrap();
        assert!(matches!(
            v,
            MartingaleVerdict::Stop {
                reason: StoppingRuleKind::Reject
            }
        ));
        assert!(l.is_stopped());
        assert_eq!(l.stopped_at_sequence(), Some(1));
    }

    #[test]
    fn boundary_verdict_when_log_m_equals_threshold() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let v = l.append(2_995_732, digest("e"), 1).unwrap();
        assert!(matches!(
            v,
            MartingaleVerdict::Stop {
                reason: StoppingRuleKind::Boundary
            }
        ));
        assert!(l.is_stopped());
    }

    #[test]
    fn cannot_append_after_stop() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let _ = l.append(3_000_000, digest("e"), 1).unwrap();
        let err = l.append(1, digest("e2"), 2).unwrap_err();
        assert_eq!(err, MartingaleError::AlreadyStopped);
    }

    #[test]
    fn stopping_rule_is_derived_not_encoded_separately() {
        // The exact same state produces the same verdict via the pure
        // helper as via the ledger — i.e. the verdict is a function of
        // (state, threshold), not stored state.
        let state = MartingaleState {
            event_count: 1,
            log_m_millionths: 3_000_000,
            last_log_likelihood_ratio_millionths: 3_000_000,
        };
        let t = small_threshold();
        let v = derive_verdict(&state, &t);
        assert!(v.is_stop());
        let mut l = MartingaleLedger::new(t, epoch());
        let v2 = l.append(3_000_000, digest("e"), 1).unwrap();
        assert_eq!(v, v2);
    }

    // ----- Anytime-validity prerequisite: log_m can decrease but never
    // crosses below itself for a fixed prior. We don't claim Ville's
    // bound here (that's a probabilistic property of the LR stream), but
    // the LEDGER must correctly handle non-monotone trajectories.

    #[test]
    fn log_m_can_decrease_without_stopping_logic_firing() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        l.append(500_000, digest("a"), 1).unwrap();
        l.append(-300_000, digest("b"), 2).unwrap();
        assert_eq!(l.current_state().log_m_millionths, 200_000);
        assert!(!l.is_stopped());
    }

    #[test]
    fn log_m_can_recover_after_dipping_below_zero() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        l.append(-MILLION, digest("a"), 1).unwrap();
        assert_eq!(l.current_state().log_m_millionths, -MILLION);
        l.append(2 * MILLION, digest("b"), 2).unwrap();
        assert_eq!(l.current_state().log_m_millionths, MILLION);
        assert!(!l.is_stopped());
    }

    // ----- Replay determinism -----

    #[test]
    fn replay_reconstructs_every_state_in_order() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        l.append(100_000, digest("a"), 1).unwrap();
        l.append(200_000, digest("b"), 2).unwrap();
        l.append(50_000, digest("c"), 3).unwrap();
        let trajectory = l.replay();
        assert_eq!(trajectory.len(), 4); // initial + 3 events
        assert_eq!(trajectory[0], MartingaleState::initial());
        assert_eq!(trajectory[1].log_m_millionths, 100_000);
        assert_eq!(trajectory[2].log_m_millionths, 300_000);
        assert_eq!(trajectory[3].log_m_millionths, 350_000);
        assert_eq!(trajectory[3], l.current_state());
    }

    #[test]
    fn replay_is_deterministic_across_calls() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        for i in 0..10 {
            l.append(50_000, digest(&format!("e{i}")), i as u64)
                .unwrap();
        }
        let r1 = l.replay();
        let r2 = l.replay();
        assert_eq!(r1, r2);
    }

    #[test]
    fn replay_final_state_equals_live_state() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        l.append(123_456, digest("a"), 1).unwrap();
        l.append(-7_890, digest("b"), 2).unwrap();
        let final_state = l.replay().last().copied().unwrap();
        assert_eq!(final_state, l.current_state());
    }

    // ----- Event history shape -----

    #[test]
    fn event_history_carries_full_record() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let d = digest("hello");
        l.append(500_000, d, 42).unwrap();
        let e = &l.events()[0];
        assert_eq!(e.sequence, 1);
        assert_eq!(e.timestamp_ns, 42);
        assert_eq!(e.log_likelihood_ratio_millionths, 500_000);
        assert_eq!(e.payload_digest, d);
        assert_eq!(e.state_after, l.current_state());
        assert_eq!(e.verdict, MartingaleVerdict::Continue);
    }

    #[test]
    fn sequence_numbers_are_one_indexed_and_monotone() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        for i in 0..5 {
            l.append(10_000, digest(&format!("e{i}")), i as u64)
                .unwrap();
        }
        for (i, e) in l.events().iter().enumerate() {
            assert_eq!(e.sequence, (i as u64) + 1);
        }
    }

    // ----- crosses_threshold accessor -----

    #[test]
    fn state_crosses_threshold_matches_verdict() {
        let t = small_threshold();
        let below = MartingaleState {
            event_count: 1,
            log_m_millionths: 1_000_000,
            last_log_likelihood_ratio_millionths: 0,
        };
        let exact = MartingaleState {
            event_count: 1,
            log_m_millionths: t.log_threshold_millionths,
            last_log_likelihood_ratio_millionths: 0,
        };
        let above = MartingaleState {
            event_count: 1,
            log_m_millionths: t.log_threshold_millionths + 1,
            last_log_likelihood_ratio_millionths: 0,
        };
        assert!(!below.crosses_threshold(t.log_threshold_millionths));
        assert!(exact.crosses_threshold(t.log_threshold_millionths));
        assert!(above.crosses_threshold(t.log_threshold_millionths));
    }

    // ----- Overflow protection -----

    #[test]
    fn append_overflow_returns_error() {
        let huge = StoppingThreshold::try_from_log_millionths(i64::MAX - 1).unwrap();
        let mut l = MartingaleLedger::new(huge, epoch());
        l.append(i64::MAX - 10, digest("a"), 1).unwrap();
        let err = l.append(i64::MAX, digest("b"), 2).unwrap_err();
        assert_eq!(err, MartingaleError::LogAccumulatorOverflow);
        // State is unchanged on overflow.
        assert_eq!(l.current_state().event_count, 1);
        assert_eq!(l.current_state().log_m_millionths, i64::MAX - 10);
    }

    // ----- Serde round-trip -----

    #[test]
    fn ledger_serde_round_trip() {
        let mut original = MartingaleLedger::new(small_threshold(), epoch());
        original.append(123, digest("a"), 1).unwrap();
        original.append(456, digest("b"), 2).unwrap();
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: MartingaleLedger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, restored);
    }

    #[test]
    fn verdict_serde_round_trip() {
        let v = MartingaleVerdict::Stop {
            reason: StoppingRuleKind::Boundary,
        };
        let s = serde_json::to_string(&v).unwrap();
        let r: MartingaleVerdict = serde_json::from_str(&s).unwrap();
        assert_eq!(v, r);
    }

    // ----- Display -----

    #[test]
    fn stopping_rule_display_strings() {
        assert_eq!(format!("{}", StoppingRuleKind::Reject), "reject");
        assert_eq!(format!("{}", StoppingRuleKind::Boundary), "boundary");
    }

    #[test]
    fn error_display_non_positive_threshold() {
        let s = format!("{}", MartingaleError::NonPositiveThreshold);
        assert!(s.contains("strictly positive"));
    }

    #[test]
    fn error_display_already_stopped() {
        let s = format!("{}", MartingaleError::AlreadyStopped);
        assert!(s.contains("stopped"));
    }

    // ----- is_stop helper -----

    #[test]
    fn verdict_is_stop_classifier() {
        assert!(!MartingaleVerdict::Continue.is_stop());
        assert!(
            MartingaleVerdict::Stop {
                reason: StoppingRuleKind::Reject
            }
            .is_stop()
        );
        assert!(
            MartingaleVerdict::Stop {
                reason: StoppingRuleKind::Boundary
            }
            .is_stop()
        );
    }

    // ----- Long-run sanity -----

    #[test]
    fn many_small_increments_eventually_cross_threshold() {
        let mut l = MartingaleLedger::new(small_threshold(), epoch());
        let mut fired = None;
        for i in 0..100 {
            let v = l
                .append(50_000, digest(&format!("e{i}")), i as u64)
                .unwrap();
            if v.is_stop() {
                fired = Some(i);
                break;
            }
        }
        assert!(fired.is_some(), "boundary should fire within 100 events");
        // 50_000 per event; threshold 2_995_732 → crosses at event 60 (50_000 * 60 = 3_000_000).
        assert_eq!(fired.unwrap(), 59);
        assert!(l.is_stopped());
        // Subsequent appends are rejected.
        let err = l.append(0, digest("x"), 1000).unwrap_err();
        assert_eq!(err, MartingaleError::AlreadyStopped);
    }
}
