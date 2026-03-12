//! Enrichment integration tests for quickening_feedback_lattice module.
//!
//! Covers: Display uniqueness, serde roundtrips, method behavior, edge cases,
//! deterministic hashing, builder/factory patterns, policy evaluation,
//! superinstruction catalog management, and profile lifecycle.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::quickening_feedback_lattice::*;

// ---------------------------------------------------------------------------
// QuickeningLevel — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_display_uniqueness() {
    let variants = [
        QuickeningLevel::Cold,
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(
        displays.len(),
        4,
        "all QuickeningLevel Display strings must be unique"
    );
}

// ---------------------------------------------------------------------------
// QuickeningLevel — serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_serde_cold() {
    let val = QuickeningLevel::Cold;
    let json = serde_json::to_string(&val).unwrap();
    let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_quickening_level_serde_warm() {
    let val = QuickeningLevel::Warm;
    let json = serde_json::to_string(&val).unwrap();
    let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_quickening_level_serde_hot() {
    let val = QuickeningLevel::Hot;
    let json = serde_json::to_string(&val).unwrap();
    let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

#[test]
fn enrichment_quickening_level_serde_quickened() {
    let val = QuickeningLevel::Quickened;
    let json = serde_json::to_string(&val).unwrap();
    let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(val, back);
}

// ---------------------------------------------------------------------------
// QuickeningLevel — advance chain
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_advance_full_chain() {
    let mut level = QuickeningLevel::Cold;
    let mut steps = 0;
    while let Some(next) = level.advance() {
        level = next;
        steps += 1;
    }
    assert_eq!(steps, 3);
    assert_eq!(level, QuickeningLevel::Quickened);
}

#[test]
fn enrichment_quickening_level_advance_returns_none_at_max() {
    assert_eq!(QuickeningLevel::Quickened.advance(), None);
}

// ---------------------------------------------------------------------------
// QuickeningLevel — is_quickened / is_quickening_eligible
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_is_quickened_only_for_quickened() {
    assert!(!QuickeningLevel::Cold.is_quickened());
    assert!(!QuickeningLevel::Warm.is_quickened());
    assert!(!QuickeningLevel::Hot.is_quickened());
    assert!(QuickeningLevel::Quickened.is_quickened());
}

#[test]
fn enrichment_quickening_level_eligibility_hot_and_quickened() {
    assert!(!QuickeningLevel::Cold.is_quickening_eligible());
    assert!(!QuickeningLevel::Warm.is_quickening_eligible());
    assert!(QuickeningLevel::Hot.is_quickening_eligible());
    assert!(QuickeningLevel::Quickened.is_quickening_eligible());
}

// ---------------------------------------------------------------------------
// QuickeningLevel — reset always returns Cold
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_reset_always_cold() {
    for level in [
        QuickeningLevel::Cold,
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ] {
        assert_eq!(level.reset(), QuickeningLevel::Cold);
    }
}

// ---------------------------------------------------------------------------
// QuickeningLevel — rank monotonicity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_rank_monotone() {
    let levels = [
        QuickeningLevel::Cold,
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ];
    for i in 0..levels.len() - 1 {
        assert!(levels[i].rank() < levels[i + 1].rank());
    }
}

// ---------------------------------------------------------------------------
// QuickeningLevel — Ord consistency with rank
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_level_ord_agrees_with_rank() {
    let levels = [
        QuickeningLevel::Cold,
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ];
    for i in 0..levels.len() {
        for j in 0..levels.len() {
            assert_eq!(
                levels[i].cmp(&levels[j]),
                levels[i].rank().cmp(&levels[j].rank()),
                "Ord must agree with rank for {:?} vs {:?}",
                levels[i],
                levels[j]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ObservedType — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observed_type_display_uniqueness() {
    let variants = [
        ObservedType::Undefined,
        ObservedType::Null,
        ObservedType::Boolean,
        ObservedType::Integer,
        ObservedType::Float,
        ObservedType::String,
        ObservedType::Object,
        ObservedType::Symbol,
        ObservedType::BigInt,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(
        displays.len(),
        9,
        "all ObservedType Display strings must be unique"
    );
}

// ---------------------------------------------------------------------------
// ObservedType — serde roundtrip for every variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observed_type_serde_all_variants() {
    let variants = [
        ObservedType::Undefined,
        ObservedType::Null,
        ObservedType::Boolean,
        ObservedType::Integer,
        ObservedType::Float,
        ObservedType::String,
        ObservedType::Object,
        ObservedType::Symbol,
        ObservedType::BigInt,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ObservedType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// ObservedType — Ord determinism (BTreeSet insertion order)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_observed_type_btreeset_deterministic_ordering() {
    let mut set = BTreeSet::new();
    set.insert(ObservedType::BigInt);
    set.insert(ObservedType::Integer);
    set.insert(ObservedType::Undefined);
    set.insert(ObservedType::Null);

    let ordered: Vec<ObservedType> = set.iter().copied().collect();
    // Must always produce the same order
    let mut set2 = BTreeSet::new();
    set2.insert(ObservedType::Null);
    set2.insert(ObservedType::Undefined);
    set2.insert(ObservedType::BigInt);
    set2.insert(ObservedType::Integer);

    let ordered2: Vec<ObservedType> = set2.iter().copied().collect();
    assert_eq!(ordered, ordered2);
}

// ---------------------------------------------------------------------------
// TypeFeedbackSlot — construction and observation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_type_feedback_slot_new_is_unobserved() {
    let slot = TypeFeedbackSlot::new(0, 0);
    assert!(slot.is_unobserved());
    assert!(!slot.is_monomorphic());
    assert!(!slot.is_polymorphic());
    assert_eq!(slot.observation_count, 0);
    assert_eq!(slot.monomorphic_type(), None);
}

#[test]
fn enrichment_type_feedback_slot_single_record_monomorphic() {
    let mut slot = TypeFeedbackSlot::new(10, 2);
    slot.record(ObservedType::Float);
    assert!(slot.is_monomorphic());
    assert!(!slot.is_polymorphic());
    assert_eq!(slot.monomorphic_type(), Some(ObservedType::Float));
    assert_eq!(slot.observation_count, 1);
}

#[test]
fn enrichment_type_feedback_slot_duplicate_record_stays_monomorphic() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Integer);
    assert!(slot.is_monomorphic());
    assert_eq!(slot.observation_count, 3);
    assert_eq!(slot.monomorphic_type(), Some(ObservedType::Integer));
}

#[test]
fn enrichment_type_feedback_slot_two_types_polymorphic() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    assert!(slot.is_polymorphic());
    assert_eq!(slot.monomorphic_type(), None);
}

#[test]
fn enrichment_type_feedback_slot_stability_unobserved_zero() {
    let slot = TypeFeedbackSlot::new(0, 0);
    assert_eq!(slot.stability_millionths(), 0);
}

#[test]
fn enrichment_type_feedback_slot_stability_monomorphic_full() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Boolean);
    assert_eq!(slot.stability_millionths(), 1_000_000);
}

#[test]
fn enrichment_type_feedback_slot_stability_two_types_half() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    assert_eq!(slot.stability_millionths(), 500_000);
}

#[test]
fn enrichment_type_feedback_slot_stability_three_types() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    slot.record(ObservedType::String);
    assert_eq!(slot.stability_millionths(), 333_333);
}

#[test]
fn enrichment_type_feedback_slot_serde_roundtrip() {
    let mut slot = TypeFeedbackSlot::new(42, 3);
    slot.record(ObservedType::Object);
    slot.record(ObservedType::Symbol);
    let json = serde_json::to_string(&slot).unwrap();
    let back: TypeFeedbackSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, back);
}

#[test]
fn enrichment_type_feedback_slot_display_format() {
    let mut slot = TypeFeedbackSlot::new(20, 1);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    let display = format!("{slot}");
    assert!(display.contains("20"), "should include instruction_offset");
    assert!(display.contains("[1]"), "should include operand_index");
    assert!(display.contains("n=2"), "should include observation count");
}

#[test]
fn enrichment_type_feedback_slot_display_empty() {
    let slot = TypeFeedbackSlot::new(0, 0);
    let display = format!("{slot}");
    assert!(display.contains("n=0"));
}

// ---------------------------------------------------------------------------
// QuickeningPolicy — defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_policy_default_values() {
    let policy = QuickeningPolicy::default();
    assert_eq!(policy.warm_threshold, 8);
    assert_eq!(policy.hot_threshold, 64);
    assert_eq!(policy.min_stability_millionths, 500_000);
    assert_eq!(policy.min_ic_hit_rate_millionths, 600_000);
    assert_eq!(policy.max_polymorphic_types, 3);
    assert!(policy.deopt_resets_to_cold);
}

#[test]
fn enrichment_quickening_policy_serde_roundtrip() {
    let policy = QuickeningPolicy {
        warm_threshold: 10,
        hot_threshold: 100,
        min_stability_millionths: 750_000,
        min_ic_hit_rate_millionths: 800_000,
        max_polymorphic_types: 2,
        deopt_resets_to_cold: false,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: QuickeningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_quickening_policy_hash_deterministic() {
    let p1 = QuickeningPolicy::default();
    let p2 = QuickeningPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
    assert!(!p1.policy_hash().is_empty());
}

#[test]
fn enrichment_quickening_policy_hash_changes_with_field() {
    let p1 = QuickeningPolicy::default();
    let mut p2 = QuickeningPolicy::default();
    p2.warm_threshold = 999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// InstructionFeedback — construction and recording
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instruction_feedback_new_defaults() {
    let fb = InstructionFeedback::new(0, "add");
    assert_eq!(fb.instruction_offset, 0);
    assert_eq!(fb.opcode, "add");
    assert_eq!(fb.level, QuickeningLevel::Cold);
    assert_eq!(fb.execution_count, 0);
    assert!(fb.type_slots.is_empty());
    assert_eq!(fb.ic_hit_rate_millionths, 0);
    assert_eq!(fb.deopt_count, 0);
    assert_eq!(fb.quickened_opcode, None);
}

#[test]
fn enrichment_instruction_feedback_record_execution_increments() {
    let mut fb = InstructionFeedback::new(0, "sub");
    for i in 1..=10 {
        fb.record_execution();
        assert_eq!(fb.execution_count, i);
    }
}

#[test]
fn enrichment_instruction_feedback_record_type_creates_slot() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_type(0, ObservedType::Integer);
    assert_eq!(fb.type_slots.len(), 1);
    assert!(fb.type_slots[0].is_monomorphic());
}

#[test]
fn enrichment_instruction_feedback_record_type_reuses_existing_slot() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_type(0, ObservedType::Integer);
    fb.record_type(0, ObservedType::Float);
    // Should still only have 1 slot for operand 0
    assert_eq!(fb.type_slots.len(), 1);
    assert!(fb.type_slots[0].is_polymorphic());
}

#[test]
fn enrichment_instruction_feedback_record_type_multiple_operands() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_type(0, ObservedType::Integer);
    fb.record_type(1, ObservedType::Float);
    fb.record_type(2, ObservedType::String);
    assert_eq!(fb.type_slots.len(), 3);
}

#[test]
fn enrichment_instruction_feedback_update_ic_hit_rate() {
    let mut fb = InstructionFeedback::new(0, "load");
    fb.update_ic_hit_rate(750_000);
    assert_eq!(fb.ic_hit_rate_millionths, 750_000);
    fb.update_ic_hit_rate(900_000);
    assert_eq!(fb.ic_hit_rate_millionths, 900_000);
}

#[test]
fn enrichment_instruction_feedback_min_stability_no_slots() {
    let fb = InstructionFeedback::new(0, "nop");
    assert_eq!(fb.min_stability_millionths(), 0);
}

#[test]
fn enrichment_instruction_feedback_min_stability_with_slots() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_type(0, ObservedType::Integer); // mono = 1M
    fb.record_type(1, ObservedType::Integer);
    fb.record_type(1, ObservedType::Float); // poly = 500K
    assert_eq!(fb.min_stability_millionths(), 500_000);
}

// ---------------------------------------------------------------------------
// InstructionFeedback — evaluate transitions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instruction_feedback_evaluate_cold_to_warm() {
    let policy = QuickeningPolicy::default();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..8 {
        fb.record_execution();
    }
    let t = fb.evaluate(&policy);
    assert!(t.advanced);
    assert_eq!(t.from, QuickeningLevel::Cold);
    assert_eq!(t.to, QuickeningLevel::Warm);
    assert_eq!(fb.level, QuickeningLevel::Warm);
}

#[test]
fn enrichment_instruction_feedback_evaluate_cold_stays_below_threshold() {
    let policy = QuickeningPolicy::default();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..7 {
        fb.record_execution();
    }
    let t = fb.evaluate(&policy);
    assert!(!t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Cold);
}

#[test]
fn enrichment_instruction_feedback_evaluate_warm_to_hot() {
    let policy = QuickeningPolicy::default();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..64 {
        fb.record_execution();
    }
    fb.evaluate(&policy); // Cold -> Warm
    let t = fb.evaluate(&policy); // Warm -> Hot
    assert!(t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Hot);
}

#[test]
fn enrichment_instruction_feedback_evaluate_hot_to_quickened_no_slots() {
    // With no type slots, ic_ok defaults to true (type_slots.is_empty())
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 600_000,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    };
    let mut fb = InstructionFeedback::new(0, "nop");
    for _ in 0..5 {
        fb.record_execution();
    }
    fb.evaluate(&policy); // Cold -> Warm
    fb.evaluate(&policy); // Warm -> Hot
    let t = fb.evaluate(&policy); // Hot -> Quickened (no slots = stable, ic_ok = true)
    assert!(t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Quickened);
}

#[test]
fn enrichment_instruction_feedback_evaluate_hot_blocked_by_low_ic() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 600_000,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    };
    let mut fb = InstructionFeedback::new(0, "load");
    for _ in 0..10 {
        fb.record_execution();
        fb.record_type(0, ObservedType::Integer);
    }
    fb.update_ic_hit_rate(100_000); // too low
    fb.evaluate(&policy); // Cold -> Warm
    fb.evaluate(&policy); // Warm -> Hot
    let t = fb.evaluate(&policy); // Hot stays Hot (IC rate too low)
    assert!(!t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Hot);
}

#[test]
fn enrichment_instruction_feedback_evaluate_hot_blocked_by_too_many_types() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 2,
        deopt_resets_to_cold: true,
    };
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..10 {
        fb.record_execution();
    }
    fb.record_type(0, ObservedType::Integer);
    fb.record_type(0, ObservedType::Float);
    fb.record_type(0, ObservedType::String); // 3 types > max 2
    fb.evaluate(&policy);
    fb.evaluate(&policy);
    let t = fb.evaluate(&policy);
    assert!(!t.advanced, "should not quicken with too many poly types");
    assert_eq!(fb.level, QuickeningLevel::Hot);
}

#[test]
fn enrichment_instruction_feedback_evaluate_quickened_stays() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..10 {
        fb.record_execution();
    }
    fb.evaluate(&policy); // Cold -> Warm
    fb.evaluate(&policy); // Warm -> Hot
    fb.evaluate(&policy); // Hot -> Quickened
    assert_eq!(fb.level, QuickeningLevel::Quickened);
    let t = fb.evaluate(&policy); // Quickened stays
    assert!(!t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Quickened);
}

// ---------------------------------------------------------------------------
// InstructionFeedback — deopt
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instruction_feedback_deopt_resets_to_cold() {
    let policy = QuickeningPolicy {
        deopt_resets_to_cold: true,
        ..QuickeningPolicy::default()
    };
    let mut fb = InstructionFeedback::new(0, "add");
    fb.quickened_opcode = Some("fast_add".into());
    fb.record_deopt(&policy);
    assert_eq!(fb.level, QuickeningLevel::Cold);
    assert_eq!(fb.quickened_opcode, None);
    assert_eq!(fb.deopt_count, 1);
}

#[test]
fn enrichment_instruction_feedback_deopt_resets_to_warm() {
    let policy = QuickeningPolicy {
        deopt_resets_to_cold: false,
        ..QuickeningPolicy::default()
    };
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_deopt(&policy);
    assert_eq!(fb.level, QuickeningLevel::Warm);
    assert_eq!(fb.quickened_opcode, None);
}

#[test]
fn enrichment_instruction_feedback_deopt_count_saturates() {
    let policy = QuickeningPolicy::default();
    let mut fb = InstructionFeedback::new(0, "add");
    fb.deopt_count = u32::MAX;
    fb.record_deopt(&policy);
    assert_eq!(fb.deopt_count, u32::MAX);
}

// ---------------------------------------------------------------------------
// InstructionFeedback — Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instruction_feedback_display_contains_fields() {
    let mut fb = InstructionFeedback::new(42, "load_const");
    fb.record_execution();
    fb.update_ic_hit_rate(500_000);
    let display = format!("{fb}");
    assert!(display.contains("load_const"), "should contain opcode");
    assert!(display.contains("42"), "should contain offset");
    assert!(display.contains("cold"), "should contain level");
}

#[test]
fn enrichment_instruction_feedback_serde_roundtrip() {
    let mut fb = InstructionFeedback::new(10, "sub");
    fb.record_execution();
    fb.record_type(0, ObservedType::Integer);
    fb.update_ic_hit_rate(800_000);
    let json = serde_json::to_string(&fb).unwrap();
    let back: InstructionFeedback = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

// ---------------------------------------------------------------------------
// QuickeningTransition — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_transition_serde_roundtrip() {
    let t = QuickeningTransition {
        instruction_offset: 100,
        from: QuickeningLevel::Warm,
        to: QuickeningLevel::Hot,
        execution_count: 64,
        advanced: true,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: QuickeningTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn enrichment_quickening_transition_not_advanced_when_same() {
    let policy = QuickeningPolicy::default();
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_execution(); // only 1, below warm_threshold=8
    let t = fb.evaluate(&policy);
    assert!(!t.advanced);
    assert_eq!(t.from, t.to);
}

// ---------------------------------------------------------------------------
// SuperInstructionPattern — construction and methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_superinstruction_pattern_sequence_length() {
    let p = SuperInstructionPattern {
        pattern_id: "test".into(),
        opcode_sequence: vec!["a".into(), "b".into(), "c".into()],
        fused_opcode: "abc".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_200_000,
    };
    assert_eq!(p.sequence_length(), 3);
}

#[test]
fn enrichment_superinstruction_pattern_hash_deterministic() {
    let p1 = SuperInstructionPattern {
        pattern_id: "si-test".into(),
        opcode_sequence: vec!["load".into(), "add".into()],
        fused_opcode: "load_and_add".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: true,
        estimated_speedup_millionths: 1_500_000,
    };
    let p2 = p1.clone();
    assert_eq!(p1.pattern_hash(), p2.pattern_hash());
}

#[test]
fn enrichment_superinstruction_pattern_hash_differs_on_change() {
    let p1 = SuperInstructionPattern {
        pattern_id: "si-a".into(),
        opcode_sequence: vec!["load".into()],
        fused_opcode: "fast_load".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    };
    let mut p2 = p1.clone();
    p2.estimated_speedup_millionths = 2_000_000;
    assert_ne!(p1.pattern_hash(), p2.pattern_hash());
}

#[test]
fn enrichment_superinstruction_pattern_display_format() {
    let p = SuperInstructionPattern {
        pattern_id: "si-test".into(),
        opcode_sequence: vec!["load_prop_cached".into(), "add".into()],
        fused_opcode: "load_and_add".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: true,
        estimated_speedup_millionths: 1_350_000,
    };
    let display = format!("{p}");
    assert!(display.contains("load_and_add"));
    assert!(display.contains("load_prop_cached"));
    assert!(display.contains("add"));
}

#[test]
fn enrichment_superinstruction_pattern_serde_roundtrip() {
    let mut constraints = BTreeMap::new();
    constraints.insert(0, ObservedType::Integer);
    constraints.insert(1, ObservedType::Float);
    let p = SuperInstructionPattern {
        pattern_id: "si-typed".into(),
        opcode_sequence: vec!["add".into(), "store".into()],
        fused_opcode: "add_and_store".into(),
        type_constraints: constraints,
        requires_monomorphic_ic: true,
        estimated_speedup_millionths: 1_400_000,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: SuperInstructionPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// SuperInstructionCatalog — construction and queries
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_default_has_five_patterns() {
    let catalog = SuperInstructionCatalog::default();
    assert_eq!(catalog.pattern_count(), 5);
}

#[test]
fn enrichment_catalog_default_schema_version() {
    let catalog = SuperInstructionCatalog::default();
    assert_eq!(
        catalog.schema_version,
        SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_catalog_new_computes_hash() {
    let catalog = SuperInstructionCatalog::new(vec![]);
    assert!(!catalog.catalog_hash.is_empty());
    assert_eq!(catalog.catalog_version, 1);
}

#[test]
fn enrichment_catalog_find_matching_exact() {
    let catalog = SuperInstructionCatalog::default();
    let matches = catalog.find_matching(&["load_prop_cached", "add"]);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].fused_opcode, "load_prop_and_add");
}

#[test]
fn enrichment_catalog_find_matching_no_match() {
    let catalog = SuperInstructionCatalog::default();
    let matches = catalog.find_matching(&["nonexistent_opcode"]);
    assert!(matches.is_empty());
}

#[test]
fn enrichment_catalog_find_matching_wrong_length() {
    let catalog = SuperInstructionCatalog::default();
    // The catalog pattern has 2 opcodes, searching with 3 should not match
    let matches = catalog.find_matching(&["load_prop_cached", "add", "extra"]);
    assert!(matches.is_empty());
}

#[test]
fn enrichment_catalog_patterns_starting_with() {
    let catalog = SuperInstructionCatalog::default();
    let matches = catalog.patterns_starting_with("load_prop_cached");
    // load+add, load+sub, load+load = at least 3
    assert!(matches.len() >= 3);
}

#[test]
fn enrichment_catalog_patterns_starting_with_no_match() {
    let catalog = SuperInstructionCatalog::default();
    let matches = catalog.patterns_starting_with("nonexistent");
    assert!(matches.is_empty());
}

#[test]
fn enrichment_catalog_add_pattern_bumps_version() {
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    assert_eq!(catalog.catalog_version, 1);
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-new".into(),
        opcode_sequence: vec!["a".into()],
        fused_opcode: "fast_a".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    });
    assert_eq!(catalog.catalog_version, 2);
}

#[test]
fn enrichment_catalog_add_pattern_updates_hash() {
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    let hash_before = catalog.catalog_hash.clone();
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-new".into(),
        opcode_sequence: vec!["x".into()],
        fused_opcode: "fast_x".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_200_000,
    });
    assert_ne!(catalog.catalog_hash, hash_before);
}

#[test]
fn enrichment_catalog_add_pattern_sorts() {
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-z".into(),
        opcode_sequence: vec!["z".into()],
        fused_opcode: "fast_z".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    });
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-a".into(),
        opcode_sequence: vec!["a".into()],
        fused_opcode: "fast_a".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    });
    // After sorting, si-a should come before si-z
    assert!(catalog.patterns[0].pattern_id <= catalog.patterns[1].pattern_id);
}

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let catalog = SuperInstructionCatalog::default();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: SuperInstructionCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

// ---------------------------------------------------------------------------
// default_superinstruction_patterns — coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_patterns_all_have_unique_ids() {
    let patterns = default_superinstruction_patterns();
    let ids: BTreeSet<String> = patterns.iter().map(|p| p.pattern_id.clone()).collect();
    assert_eq!(ids.len(), patterns.len(), "all pattern IDs must be unique");
}

#[test]
fn enrichment_default_patterns_all_have_unique_fused_opcodes() {
    let patterns = default_superinstruction_patterns();
    let fused: BTreeSet<String> = patterns.iter().map(|p| p.fused_opcode.clone()).collect();
    assert_eq!(
        fused.len(),
        patterns.len(),
        "all fused opcodes must be unique"
    );
}

#[test]
fn enrichment_default_patterns_speedup_above_one() {
    let patterns = default_superinstruction_patterns();
    for p in &patterns {
        assert!(
            p.estimated_speedup_millionths >= 1_000_000,
            "pattern {} should have speedup >= 1.0x",
            p.pattern_id
        );
    }
}

// ---------------------------------------------------------------------------
// QuickeningProfile — construction and recording
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_new_defaults() {
    let profile = QuickeningProfile::new("fn_test");
    assert_eq!(profile.function_id, "fn_test");
    assert_eq!(profile.entry_count(), 0);
    assert_eq!(profile.total_executions, 0);
    assert_eq!(profile.total_quickened, 0);
    assert_eq!(profile.total_deopts, 0);
    assert_eq!(profile.evaluation_epoch, 0);
}

#[test]
fn enrichment_quickening_profile_record_execution_creates_entry() {
    let mut profile = QuickeningProfile::new("fn_rec");
    profile.record_execution(0, "add");
    assert_eq!(profile.entry_count(), 1);
    assert_eq!(profile.total_executions, 1);
    let fb = profile.get(0).unwrap();
    assert_eq!(fb.execution_count, 1);
    assert_eq!(fb.opcode, "add");
}

#[test]
fn enrichment_quickening_profile_record_execution_reuses_entry() {
    let mut profile = QuickeningProfile::new("fn_reuse");
    profile.record_execution(0, "add");
    profile.record_execution(0, "add");
    assert_eq!(profile.entry_count(), 1);
    assert_eq!(profile.total_executions, 2);
    assert_eq!(profile.get(0).unwrap().execution_count, 2);
}

#[test]
fn enrichment_quickening_profile_record_type() {
    let mut profile = QuickeningProfile::new("fn_type");
    profile.record_type(0, "add", 0, ObservedType::Integer);
    let fb = profile.get(0).unwrap();
    assert_eq!(fb.type_slots.len(), 1);
    assert!(fb.type_slots[0].is_monomorphic());
}

#[test]
fn enrichment_quickening_profile_record_deopt_nonexistent_offset() {
    let policy = QuickeningPolicy::default();
    let mut profile = QuickeningProfile::new("fn_noop_deopt");
    // Deopt on non-existent offset should be a no-op
    profile.record_deopt(999, &policy);
    assert_eq!(profile.total_deopts, 0);
}

#[test]
fn enrichment_quickening_profile_record_deopt_existing() {
    let policy = QuickeningPolicy::default();
    let mut profile = QuickeningProfile::new("fn_deopt");
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    profile.record_deopt(0, &policy);
    assert_eq!(profile.total_deopts, 1);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Cold);
}

// ---------------------------------------------------------------------------
// QuickeningProfile — evaluate_all
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_evaluate_all_increments_epoch() {
    let policy = QuickeningPolicy::default();
    let mut profile = QuickeningProfile::new("fn_epoch");
    assert_eq!(profile.evaluation_epoch, 0);
    profile.evaluate_all(&policy);
    assert_eq!(profile.evaluation_epoch, 1);
    profile.evaluate_all(&policy);
    assert_eq!(profile.evaluation_epoch, 2);
}

#[test]
fn enrichment_quickening_profile_evaluate_all_transitions_returned() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 5,
        ..QuickeningPolicy::default()
    };
    let mut profile = QuickeningProfile::new("fn_trans");
    for _ in 0..10 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "sub");
    }
    let transitions = profile.evaluate_all(&policy);
    // Both should advance Cold -> Warm
    assert_eq!(transitions.len(), 2);
    for t in &transitions {
        assert!(t.advanced);
    }
}

#[test]
fn enrichment_quickening_profile_evaluate_all_no_transitions_when_no_progress() {
    let policy = QuickeningPolicy::default();
    let mut profile = QuickeningProfile::new("fn_stale");
    profile.record_execution(0, "add"); // only 1 exec, below warm=8
    let transitions = profile.evaluate_all(&policy);
    assert!(transitions.is_empty());
}

// ---------------------------------------------------------------------------
// QuickeningProfile — instructions_at_level
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_instructions_at_level_empty() {
    let profile = QuickeningProfile::new("fn_empty");
    let cold = profile.instructions_at_level(QuickeningLevel::Cold);
    assert!(cold.is_empty());
}

#[test]
fn enrichment_quickening_profile_instructions_at_level_mixed() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 100,
        ..QuickeningPolicy::default()
    };
    let mut profile = QuickeningProfile::new("fn_mixed");
    // offset 0: 5 execs -> will become Warm
    for _ in 0..5 {
        profile.record_execution(0, "add");
    }
    // offset 4: 0 execs after creation -> stays Cold
    profile.get_or_create(4, "nop");

    profile.evaluate_all(&policy);

    let warm = profile.instructions_at_level(QuickeningLevel::Warm);
    let cold = profile.instructions_at_level(QuickeningLevel::Cold);
    assert!(warm.contains(&0));
    assert!(cold.contains(&4));
}

// ---------------------------------------------------------------------------
// QuickeningProfile — summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_summary_empty() {
    let profile = QuickeningProfile::new("fn_empty_summary");
    let s = profile.summary();
    assert_eq!(s.total_sites, 0);
    assert_eq!(s.cold_count, 0);
    assert_eq!(s.warm_count, 0);
    assert_eq!(s.hot_count, 0);
    assert_eq!(s.quickened_count, 0);
    assert_eq!(s.total_executions, 0);
    assert_eq!(s.total_deopts, 0);
    assert_eq!(s.evaluation_epoch, 0);
}

#[test]
fn enrichment_quickening_profile_summary_counts_levels() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 5,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_sum");
    // offset 0: will become Quickened after 3 evals
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    // offset 4: cold, 0 execs
    profile.get_or_create(4, "nop");

    profile.evaluate_all(&policy); // 0: Cold->Warm, 4: stays Cold
    profile.evaluate_all(&policy); // 0: Warm->Hot
    profile.evaluate_all(&policy); // 0: Hot->Quickened

    let s = profile.summary();
    assert_eq!(s.total_sites, 2);
    assert_eq!(s.quickened_count, 1);
    assert_eq!(s.cold_count, 1);
}

// ---------------------------------------------------------------------------
// QuickeningProfile — profile_hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_hash_deterministic() {
    let mut p1 = QuickeningProfile::new("fn_hash");
    let mut p2 = QuickeningProfile::new("fn_hash");
    p1.record_execution(0, "add");
    p2.record_execution(0, "add");
    assert_eq!(p1.profile_hash(), p2.profile_hash());
}

#[test]
fn enrichment_quickening_profile_hash_changes_on_mutation() {
    let mut profile = QuickeningProfile::new("fn_hash_mut");
    let h1 = profile.profile_hash();
    profile.record_execution(0, "add");
    let h2 = profile.profile_hash();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// QuickeningProfile — superinstruction candidates
// ---------------------------------------------------------------------------

#[test]
fn enrichment_profile_superinstruction_candidates_empty_profile() {
    let profile = QuickeningProfile::new("fn_empty_si");
    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(candidates.is_empty());
}

#[test]
fn enrichment_profile_superinstruction_candidates_cold_not_eligible() {
    let mut profile = QuickeningProfile::new("fn_cold_si");
    profile.record_execution(0, "load_prop_cached");
    profile.record_execution(4, "add");
    // Both are Cold -> not eligible
    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(candidates.is_empty());
}

#[test]
fn enrichment_profile_superinstruction_requires_monomorphic_ic() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_ic_req");
    for _ in 0..10 {
        profile.record_execution(0, "load_prop_cached");
        profile.record_execution(4, "add");
    }
    // Evaluate to make them Hot
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    // IC rate is 0 -> patterns requiring monomorphic IC should NOT match
    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    // load_prop_cached+add requires monomorphic IC with >= 900_000
    let load_add: Vec<_> = candidates
        .iter()
        .filter(|c| c.fused_opcode == "load_prop_and_add")
        .collect();
    assert!(
        load_add.is_empty(),
        "should not match without sufficient IC rate"
    );
}

#[test]
fn enrichment_profile_superinstruction_store_jump_no_ic_requirement() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_store_jump");
    for _ in 0..10 {
        profile.record_execution(0, "store_prop");
        profile.record_execution(4, "jump");
    }
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    let store_jump: Vec<_> = candidates
        .iter()
        .filter(|c| c.fused_opcode == "store_prop_and_jump")
        .collect();
    assert!(!store_jump.is_empty(), "store+jump does not require IC");
}

// ---------------------------------------------------------------------------
// QuickeningProfile — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_serde_roundtrip_with_data() {
    let mut profile = QuickeningProfile::new("fn_serde_full");
    profile.record_execution(0, "add");
    profile.record_execution(4, "sub");
    profile.record_type(0, "add", 0, ObservedType::Integer);
    profile.record_type(0, "add", 1, ObservedType::Float);
    let json = serde_json::to_string(&profile).unwrap();
    let back: QuickeningProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile.function_id, back.function_id);
    assert_eq!(profile.total_executions, back.total_executions);
    assert_eq!(profile.entry_count(), back.entry_count());
}

// ---------------------------------------------------------------------------
// SuperInstructionCandidate — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_superinstruction_candidate_serde_roundtrip() {
    let c = SuperInstructionCandidate {
        start_offset: 42,
        pattern_id: "si-load-add".into(),
        fused_opcode: "load_prop_and_add".into(),
        estimated_speedup_millionths: 1_300_000,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: SuperInstructionCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// QuickeningSummary — serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_summary_serde_roundtrip() {
    let s = QuickeningSummary {
        total_sites: 10,
        cold_count: 3,
        warm_count: 2,
        hot_count: 4,
        quickened_count: 1,
        total_executions: 5000,
        total_deopts: 2,
        evaluation_epoch: 7,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: QuickeningSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// QuickeningDecision — build and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_decision_build_populates_all_fields() {
    let policy = QuickeningPolicy::default();
    let profile = QuickeningProfile::new("fn_decision_full");
    let transition = QuickeningTransition {
        instruction_offset: 0,
        from: QuickeningLevel::Cold,
        to: QuickeningLevel::Warm,
        execution_count: 10,
        advanced: true,
    };
    let candidate = SuperInstructionCandidate {
        start_offset: 0,
        pattern_id: "si-load-add".into(),
        fused_opcode: "load_prop_and_add".into(),
        estimated_speedup_millionths: 1_300_000,
    };
    let decision = QuickeningDecision::build(&profile, &policy, vec![transition], vec![candidate]);
    assert_eq!(decision.schema_version, QUICKENING_SCHEMA_VERSION);
    assert_eq!(decision.function_id, "fn_decision_full");
    assert!(!decision.policy_hash.is_empty());
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.transitions.len(), 1);
    assert_eq!(decision.superinstruction_candidates.len(), 1);
}

#[test]
fn enrichment_quickening_decision_serde_roundtrip() {
    let policy = QuickeningPolicy::default();
    let profile = QuickeningProfile::new("fn_decision_serde");
    let decision = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
    let json = serde_json::to_string(&decision).unwrap();
    let back: QuickeningDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn enrichment_quickening_decision_hash_deterministic() {
    let policy = QuickeningPolicy::default();
    let p1 = QuickeningProfile::new("fn_det");
    let p2 = QuickeningProfile::new("fn_det");
    let d1 = QuickeningDecision::build(&p1, &policy, vec![], vec![]);
    let d2 = QuickeningDecision::build(&p2, &policy, vec![], vec![]);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

// ---------------------------------------------------------------------------
// Constants — value checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_component() {
    assert_eq!(COMPONENT, "quickening_feedback_lattice");
}

#[test]
fn enrichment_constants_schema_version() {
    assert_eq!(
        QUICKENING_SCHEMA_VERSION,
        "franken-engine.quickening-feedback.v1"
    );
}

#[test]
fn enrichment_constants_catalog_schema_version() {
    assert_eq!(
        SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION,
        "franken-engine.superinstruction-catalog.v1"
    );
}

// ---------------------------------------------------------------------------
// Full lifecycle: profile -> evaluate -> decide
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_lifecycle_cold_to_quickened_with_decision() {
    let policy = QuickeningPolicy {
        warm_threshold: 2,
        hot_threshold: 5,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    };
    let catalog = SuperInstructionCatalog::default();
    let mut profile = QuickeningProfile::new("fn_full_lifecycle");

    // Record enough executions with monomorphic type feedback
    for _ in 0..20 {
        profile.record_execution(0, "add");
        profile.record_type(0, "add", 0, ObservedType::Integer);
    }

    // Evaluate step by step
    let t1 = profile.evaluate_all(&policy);
    assert_eq!(t1.len(), 1);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Warm);

    let t2 = profile.evaluate_all(&policy);
    assert_eq!(t2.len(), 1);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Hot);

    let t3 = profile.evaluate_all(&policy);
    assert_eq!(t3.len(), 1);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Quickened);

    // No more transitions
    let t4 = profile.evaluate_all(&policy);
    assert!(t4.is_empty());

    // Build decision
    let candidates = profile.find_superinstruction_candidates(&catalog);
    let decision = QuickeningDecision::build(&profile, &policy, t3, candidates);
    assert_eq!(decision.summary.quickened_count, 1);
    assert!(!decision.decision_hash.is_empty());
}

#[test]
fn enrichment_full_lifecycle_deopt_then_re_quicken() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_deopt_re_quicken");
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    // Advance to Quickened
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Quickened);
    assert_eq!(profile.total_quickened, 1);

    // Deopt
    profile.record_deopt(0, &policy);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Cold);
    assert_eq!(profile.total_deopts, 1);

    // Re-evaluate: should advance again
    profile.evaluate_all(&policy); // Cold -> Warm
    profile.evaluate_all(&policy); // Warm -> Hot
    profile.evaluate_all(&policy); // Hot -> Quickened
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Quickened);
}

// ---------------------------------------------------------------------------
// Edge: execution count saturation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_instruction_feedback_execution_count_saturates() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.execution_count = u64::MAX;
    fb.record_execution();
    assert_eq!(fb.execution_count, u64::MAX);
}

#[test]
fn enrichment_type_feedback_slot_observation_count_saturates() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.observation_count = u64::MAX;
    slot.record(ObservedType::Integer);
    assert_eq!(slot.observation_count, u64::MAX);
}

// ---------------------------------------------------------------------------
// Edge: catalog version saturation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_catalog_version_saturates_at_max() {
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    catalog.catalog_version = u32::MAX;
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-sat".into(),
        opcode_sequence: vec!["x".into()],
        fused_opcode: "fast_x".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    });
    assert_eq!(catalog.catalog_version, u32::MAX);
}

// ---------------------------------------------------------------------------
// Edge: type constraint mismatch blocks superinstruction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_profile_superinstruction_type_constraint_mismatch() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_type_mismatch");
    for _ in 0..10 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "jump_if_false");
    }
    // add+jump_if_false pattern requires operand 0 = Integer
    // but we record Float instead
    profile.record_type(0, "add", 0, ObservedType::Float);

    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    let add_branch: Vec<_> = candidates
        .iter()
        .filter(|c| c.fused_opcode == "add_and_branch")
        .collect();
    assert!(
        add_branch.is_empty(),
        "type constraint mismatch should block superinstruction"
    );
}

#[test]
fn enrichment_profile_superinstruction_type_constraint_match() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 10,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_type_match");
    for _ in 0..10 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "jump_if_false");
    }
    // add+jump_if_false requires operand 0 = Integer — provide Integer
    profile.record_type(0, "add", 0, ObservedType::Integer);

    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    let catalog = SuperInstructionCatalog::default();
    let candidates = profile.find_superinstruction_candidates(&catalog);
    let add_branch: Vec<_> = candidates
        .iter()
        .filter(|c| c.fused_opcode == "add_and_branch")
        .collect();
    assert!(
        !add_branch.is_empty(),
        "correct type constraint should allow superinstruction"
    );
}

// ---------------------------------------------------------------------------
// Edge: empty catalog
// ---------------------------------------------------------------------------

#[test]
fn enrichment_profile_superinstruction_empty_catalog() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        hot_threshold: 2,
        ..QuickeningPolicy::default()
    };
    let mut profile = QuickeningProfile::new("fn_empty_cat");
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    let catalog = SuperInstructionCatalog::new(vec![]);
    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(candidates.is_empty());
}

// ---------------------------------------------------------------------------
// QuickeningProfile — get_or_create idempotency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_get_or_create_idempotent() {
    let mut profile = QuickeningProfile::new("fn_idem");
    profile.get_or_create(0, "add");
    profile.get_or_create(0, "add");
    assert_eq!(profile.entry_count(), 1);
}

// ---------------------------------------------------------------------------
// Multiple offsets sorting in instructions_at_level
// ---------------------------------------------------------------------------

#[test]
fn enrichment_quickening_profile_instructions_at_level_sorted_output() {
    let policy = QuickeningPolicy {
        warm_threshold: 1,
        ..QuickeningPolicy::default()
    };
    let mut profile = QuickeningProfile::new("fn_sorted");
    for offset in [20, 4, 12, 0, 8] {
        for _ in 0..5 {
            profile.record_execution(offset, "add");
        }
    }
    profile.evaluate_all(&policy);
    let warm = profile.instructions_at_level(QuickeningLevel::Warm);
    // Because entries is BTreeMap, iteration order is by offset
    let mut sorted_warm = warm.clone();
    sorted_warm.sort();
    assert_eq!(
        warm, sorted_warm,
        "instructions_at_level should be in offset order"
    );
}
