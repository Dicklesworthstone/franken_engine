#![forbid(unsafe_code)]

//! Program acceptance ledger for release-readiness gates.
//!
//! Scores use fixed-point millionths where `1_000_000` is 100%. Gate maps use
//! `BTreeMap` so serialized ledgers and replay comparisons have deterministic
//! ordering.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Fixed-point scale for acceptance scores.
pub const MILLIONTHS: u32 = 1_000_000;

/// A single release acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceGate {
    /// Required score in fixed-point millionths.
    pub required_score_millionths: u32,
    /// Current observed score in fixed-point millionths.
    pub current_score_millionths: u32,
}

impl AcceptanceGate {
    /// Create a gate with explicit required and current fixed-point scores.
    pub const fn new(required_score_millionths: u32, current_score_millionths: u32) -> Self {
        Self {
            required_score_millionths,
            current_score_millionths,
        }
    }

    /// Return true when this gate satisfies its release threshold.
    pub const fn ready(&self) -> bool {
        self.current_score_millionths >= self.required_score_millionths
    }
}

/// Deterministic ledger of program acceptance gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceLedger {
    /// Program identifier for the acceptance ledger.
    pub program_id: String,
    /// Gates keyed by stable gate identifier.
    pub gates: BTreeMap<String, AcceptanceGate>,
}

impl AcceptanceLedger {
    /// Create an empty acceptance ledger.
    pub fn new(program_id: impl Into<String>) -> Self {
        Self {
            program_id: program_id.into(),
            gates: BTreeMap::new(),
        }
    }

    /// Return true iff every gate's current score meets or exceeds its required score.
    pub fn ready_for_release(&self) -> bool {
        self.gates.values().all(AcceptanceGate::ready)
    }

    /// Count gates that currently meet or exceed their required score.
    pub fn ready_count(&self) -> usize {
        self.gates.values().filter(|gate| gate.ready()).count()
    }

    /// Record a current score for an existing gate.
    ///
    /// Returns `true` if the gate existed and was updated; returns `false`
    /// without mutating the ledger when `gate_id` is unknown.
    pub fn record_score(&mut self, gate_id: &str, score: u32) -> bool {
        match self.gates.get_mut(gate_id) {
            Some(gate) => {
                gate.current_score_millionths = score;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(required: u32, current: u32) -> AcceptanceGate {
        AcceptanceGate::new(required, current)
    }

    fn sample_ledger() -> AcceptanceLedger {
        let mut gates = BTreeMap::new();
        gates.insert("conformance".to_string(), gate(900_000, 900_000));
        gates.insert("determinism".to_string(), gate(MILLIONTHS, MILLIONTHS));
        gates.insert("security".to_string(), gate(950_000, 960_000));
        AcceptanceLedger {
            program_id: "rgc".to_string(),
            gates,
        }
    }

    #[test]
    fn gate_is_ready_when_current_equals_required() {
        assert!(gate(500_000, 500_000).ready());
    }

    #[test]
    fn gate_is_ready_when_current_exceeds_required() {
        assert!(gate(500_000, 500_001).ready());
    }

    #[test]
    fn gate_is_not_ready_when_current_is_below_required() {
        assert!(!gate(500_000, 499_999).ready());
    }

    #[test]
    fn zero_required_gate_is_ready_at_zero() {
        assert!(gate(0, 0).ready());
    }

    #[test]
    fn millionths_constant_represents_full_score() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn new_ledger_stores_program_id() {
        let ledger = AcceptanceLedger::new("program-a");
        assert_eq!(ledger.program_id, "program-a");
    }

    #[test]
    fn new_ledger_starts_empty() {
        let ledger = AcceptanceLedger::new("program-a");
        assert!(ledger.gates.is_empty());
    }

    #[test]
    fn empty_ledger_is_vacuously_ready() {
        let ledger = AcceptanceLedger::new("program-a");
        assert!(ledger.ready_for_release());
    }

    #[test]
    fn ready_for_release_true_when_all_gates_ready() {
        assert!(sample_ledger().ready_for_release());
    }

    #[test]
    fn ready_for_release_false_when_any_gate_is_under_threshold() {
        let mut ledger = sample_ledger();
        ledger
            .gates
            .insert("performance".to_string(), gate(800_000, 799_999));
        assert!(!ledger.ready_for_release());
    }

    #[test]
    fn ready_count_counts_all_ready_gates() {
        assert_eq!(sample_ledger().ready_count(), 3);
    }

    #[test]
    fn ready_count_excludes_unready_gates() {
        let mut ledger = sample_ledger();
        ledger
            .gates
            .insert("performance".to_string(), gate(800_000, 1));
        assert_eq!(ledger.ready_count(), 3);
    }

    #[test]
    fn ready_count_is_zero_for_empty_ledger() {
        assert_eq!(AcceptanceLedger::new("program-a").ready_count(), 0);
    }

    #[test]
    fn record_score_updates_existing_gate() {
        let mut ledger = sample_ledger();
        assert!(ledger.record_score("conformance", 901_000));
        assert_eq!(
            ledger.gates["conformance"].current_score_millionths,
            901_000
        );
    }

    #[test]
    fn record_score_returns_false_for_unknown_gate() {
        let mut ledger = sample_ledger();
        assert!(!ledger.record_score("unknown", 1));
    }

    #[test]
    fn record_score_does_not_insert_unknown_gate() {
        let mut ledger = sample_ledger();
        ledger.record_score("unknown", 1);
        assert!(!ledger.gates.contains_key("unknown"));
    }

    #[test]
    fn record_score_can_make_gate_ready() {
        let mut ledger = sample_ledger();
        ledger.gates.insert("docs".to_string(), gate(750_000, 0));
        assert!(!ledger.ready_for_release());
        assert!(ledger.record_score("docs", 750_000));
        assert!(ledger.ready_for_release());
    }

    #[test]
    fn record_score_can_make_gate_unready() {
        let mut ledger = sample_ledger();
        assert!(ledger.ready_for_release());
        assert!(ledger.record_score("security", 949_999));
        assert!(!ledger.ready_for_release());
    }

    #[test]
    fn gate_derives_clone_and_eq() {
        let left = gate(1, 2);
        let right = left.clone();
        assert_eq!(left, right);
    }

    #[test]
    fn ledger_derives_clone_and_eq() {
        let left = sample_ledger();
        let right = left.clone();
        assert_eq!(left, right);
    }

    #[test]
    fn gate_debug_includes_scores() {
        let rendered = format!("{:?}", gate(11, 22));
        assert!(rendered.contains("required_score_millionths"));
        assert!(rendered.contains("current_score_millionths"));
    }

    #[test]
    fn ledger_debug_includes_program_id() {
        let rendered = format!("{:?}", sample_ledger());
        assert!(rendered.contains("program_id"));
        assert!(rendered.contains("rgc"));
    }

    #[test]
    fn ledger_serializes_with_deterministic_gate_order() {
        let json = serde_json::to_string(&sample_ledger()).expect("ledger should serialize");
        let conformance = json.find("conformance").expect("conformance key exists");
        let determinism = json.find("determinism").expect("determinism key exists");
        let security = json.find("security").expect("security key exists");
        assert!(conformance < determinism);
        assert!(determinism < security);
    }

    #[test]
    fn ledger_roundtrips_through_json() {
        let ledger = sample_ledger();
        let json = serde_json::to_string(&ledger).expect("ledger should serialize");
        let decoded: AcceptanceLedger =
            serde_json::from_str(&json).expect("ledger should deserialize");
        assert_eq!(decoded, ledger);
    }

    #[test]
    fn gate_roundtrips_through_json() {
        let original = gate(123, 456);
        let json = serde_json::to_string(&original).expect("gate should serialize");
        let decoded: AcceptanceGate = serde_json::from_str(&json).expect("gate should deserialize");
        assert_eq!(decoded, original);
    }

    #[test]
    fn btree_gate_order_is_deterministic() {
        let mut ledger = AcceptanceLedger::new("program-a");
        ledger.gates.insert("z".to_string(), gate(1, 1));
        ledger.gates.insert("a".to_string(), gate(1, 1));
        ledger.gates.insert("m".to_string(), gate(1, 1));
        let keys: Vec<&str> = ledger.gates.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }
}
