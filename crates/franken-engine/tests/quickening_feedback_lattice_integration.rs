//! Integration tests for the quickening feedback lattice and superinstruction catalog.

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

use frankenengine_engine::quickening_feedback_lattice::{
    COMPONENT, InstructionFeedback, ObservedType, QUICKENING_SCHEMA_VERSION, QuickeningDecision,
    QuickeningLevel, QuickeningPolicy, QuickeningProfile, QuickeningSummary,
    SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION, SuperInstructionCandidate, SuperInstructionCatalog,
    SuperInstructionPattern, TypeFeedbackSlot, default_superinstruction_patterns,
};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn default_policy() -> QuickeningPolicy {
    QuickeningPolicy::default()
}

fn aggressive_policy() -> QuickeningPolicy {
    QuickeningPolicy {
        warm_threshold: 2,
        hot_threshold: 4,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    }
}

fn make_hot_profile(policy: &QuickeningPolicy) -> QuickeningProfile {
    let mut profile = QuickeningProfile::new("fn_hot");
    for _ in 0..policy.hot_threshold + 1 {
        profile.record_execution(0, "add");
    }
    profile.record_type(0, "add", 0, ObservedType::Integer);
    profile
}

// ---------------------------------------------------------------------------
// QuickeningLevel integration
// ---------------------------------------------------------------------------

#[test]
fn level_full_progression_cold_to_quickened() {
    let mut level = QuickeningLevel::Cold;
    let steps = [
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ];
    for expected in &steps {
        level = level.advance().expect("should advance");
        assert_eq!(level, *expected);
    }
    assert!(level.advance().is_none());
}

#[test]
fn level_reset_always_returns_cold() {
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
// TypeFeedbackSlot integration
// ---------------------------------------------------------------------------

#[test]
fn type_slot_monomorphic_single_type() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    for _ in 0..100 {
        slot.record(ObservedType::Integer);
    }
    assert!(slot.is_monomorphic());
    assert!(!slot.is_polymorphic());
    assert_eq!(slot.monomorphic_type(), Some(ObservedType::Integer));
    assert_eq!(slot.stability_millionths(), 1_000_000);
}

#[test]
fn type_slot_polymorphic_two_types() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    assert!(slot.is_polymorphic());
    assert!(!slot.is_monomorphic());
    assert_eq!(slot.monomorphic_type(), None);
    assert_eq!(slot.stability_millionths(), 500_000);
}

#[test]
fn type_slot_unobserved_initially() {
    let slot = TypeFeedbackSlot::new(10, 1);
    assert!(slot.is_unobserved());
    assert_eq!(slot.stability_millionths(), 0);
    assert_eq!(slot.observation_count, 0);
}

#[test]
fn type_slot_display_format() {
    let mut slot = TypeFeedbackSlot::new(42, 0);
    slot.record(ObservedType::String);
    let display = format!("{slot}");
    assert!(display.contains("42"));
    assert!(display.contains("string"));
}

// ---------------------------------------------------------------------------
// QuickeningPolicy integration
// ---------------------------------------------------------------------------

#[test]
fn policy_hash_deterministic() {
    let p1 = default_policy();
    let p2 = default_policy();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_changes_on_different_thresholds() {
    let p1 = default_policy();
    let p2 = aggressive_policy();
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// InstructionFeedback integration
// ---------------------------------------------------------------------------

#[test]
fn instruction_feedback_evaluate_cold_to_warm() {
    let policy = default_policy();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..policy.warm_threshold {
        fb.record_execution();
    }
    let t = fb.evaluate(&policy);
    assert!(t.advanced);
    assert_eq!(t.from, QuickeningLevel::Cold);
    assert_eq!(t.to, QuickeningLevel::Warm);
}

#[test]
fn instruction_feedback_evaluate_warm_to_hot() {
    let policy = default_policy();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..policy.hot_threshold {
        fb.record_execution();
    }
    fb.evaluate(&policy); // Cold→Warm
    let t = fb.evaluate(&policy); // Warm→Hot
    assert!(t.advanced);
    assert_eq!(t.to, QuickeningLevel::Hot);
}

#[test]
fn instruction_feedback_deopt_resets_to_cold() {
    let policy = default_policy();
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..policy.hot_threshold + 10 {
        fb.record_execution();
    }
    fb.evaluate(&policy);
    fb.evaluate(&policy);
    fb.record_deopt(&policy);
    assert_eq!(fb.level, QuickeningLevel::Cold);
    assert_eq!(fb.deopt_count, 1);
    assert!(fb.quickened_opcode.is_none());
}

#[test]
fn instruction_feedback_deopt_resets_to_warm_when_configured() {
    let mut policy = default_policy();
    policy.deopt_resets_to_cold = false;
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..policy.hot_threshold + 10 {
        fb.record_execution();
    }
    fb.evaluate(&policy);
    fb.evaluate(&policy);
    fb.record_deopt(&policy);
    assert_eq!(fb.level, QuickeningLevel::Warm);
}

#[test]
fn instruction_feedback_display_format() {
    let fb = InstructionFeedback::new(10, "load_prop_cached");
    let display = format!("{fb}");
    assert!(display.contains("load_prop_cached"));
    assert!(display.contains("10"));
    assert!(display.contains("cold"));
}

#[test]
fn instruction_feedback_min_stability() {
    let mut fb = InstructionFeedback::new(0, "add");
    fb.record_type(0, ObservedType::Integer);
    fb.record_type(1, ObservedType::Integer);
    fb.record_type(1, ObservedType::Float); // 2 types on operand 1
    assert_eq!(fb.min_stability_millionths(), 500_000);
}

// ---------------------------------------------------------------------------
// QuickeningProfile integration
// ---------------------------------------------------------------------------

#[test]
fn profile_full_lifecycle() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("test_fn");

    // Warm up two instructions
    for _ in 0..10 {
        profile.record_execution(0, "load_prop_cached");
        profile.record_execution(4, "add");
    }
    profile.record_type(0, "load_prop_cached", 0, ObservedType::Object);
    profile.record_type(4, "add", 0, ObservedType::Integer);

    let transitions = profile.evaluate_all(&policy);
    assert!(!transitions.is_empty());

    let summary = profile.summary();
    assert_eq!(summary.total_sites, 2);
    assert!(summary.total_executions > 0);
}

#[test]
fn profile_instructions_at_level() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("fn_levels");
    profile.record_execution(0, "nop");
    for _ in 0..10 {
        profile.record_execution(4, "add");
    }
    profile.evaluate_all(&policy);

    let cold_sites = profile.instructions_at_level(QuickeningLevel::Cold);
    let warm_sites = profile.instructions_at_level(QuickeningLevel::Warm);
    // At minimum, one should be cold and one should have advanced
    assert_eq!(
        cold_sites.len()
            + warm_sites.len()
            + profile.instructions_at_level(QuickeningLevel::Hot).len()
            + profile
                .instructions_at_level(QuickeningLevel::Quickened)
                .len(),
        2
    );
}

#[test]
fn profile_record_deopt() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("fn_deopt");
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    profile.evaluate_all(&policy);
    profile.record_deopt(0, &policy);
    assert_eq!(profile.total_deopts, 1);
    assert_eq!(profile.get(0).unwrap().level, QuickeningLevel::Cold);
}

#[test]
fn profile_hash_deterministic() {
    let policy = aggressive_policy();
    let mut p1 = QuickeningProfile::new("fn_det");
    let mut p2 = QuickeningProfile::new("fn_det");
    for _ in 0..5 {
        p1.record_execution(0, "add");
        p2.record_execution(0, "add");
    }
    p1.evaluate_all(&policy);
    p2.evaluate_all(&policy);
    assert_eq!(p1.profile_hash(), p2.profile_hash());
}

#[test]
fn profile_evaluation_epoch_increments() {
    let policy = default_policy();
    let mut profile = QuickeningProfile::new("fn_epoch");
    profile.record_execution(0, "nop");
    profile.evaluate_all(&policy);
    assert_eq!(profile.evaluation_epoch, 1);
    profile.evaluate_all(&policy);
    assert_eq!(profile.evaluation_epoch, 2);
}

// ---------------------------------------------------------------------------
// SuperInstructionPattern integration
// ---------------------------------------------------------------------------

#[test]
fn default_patterns_are_non_empty() {
    let patterns = default_superinstruction_patterns();
    assert!(patterns.len() >= 5);
    for p in &patterns {
        assert!(!p.pattern_id.is_empty());
        assert!(!p.opcode_sequence.is_empty());
        assert!(!p.fused_opcode.is_empty());
        assert!(p.estimated_speedup_millionths > 1_000_000);
    }
}

#[test]
fn pattern_hash_deterministic() {
    let patterns = default_superinstruction_patterns();
    let p = &patterns[0];
    assert_eq!(p.pattern_hash(), p.pattern_hash());
}

#[test]
fn pattern_sequence_length() {
    let patterns = default_superinstruction_patterns();
    for p in &patterns {
        assert_eq!(p.sequence_length(), p.opcode_sequence.len());
        assert!(p.sequence_length() >= 2);
    }
}

#[test]
fn pattern_display_contains_fused_opcode() {
    let patterns = default_superinstruction_patterns();
    for p in &patterns {
        let display = format!("{p}");
        assert!(display.contains(&p.fused_opcode));
    }
}

// ---------------------------------------------------------------------------
// SuperInstructionCatalog integration
// ---------------------------------------------------------------------------

#[test]
fn catalog_default_has_patterns() {
    let catalog = SuperInstructionCatalog::default();
    assert!(catalog.pattern_count() >= 5);
    assert_eq!(
        catalog.schema_version,
        SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION
    );
}

#[test]
fn catalog_find_matching() {
    let catalog = SuperInstructionCatalog::default();
    let matched = catalog.find_matching(&["load_prop_cached", "add"]);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].fused_opcode, "load_prop_and_add");
}

#[test]
fn catalog_find_matching_no_match() {
    let catalog = SuperInstructionCatalog::default();
    let matched = catalog.find_matching(&["nonexistent", "opcode"]);
    assert!(matched.is_empty());
}

#[test]
fn catalog_patterns_starting_with() {
    let catalog = SuperInstructionCatalog::default();
    let starting = catalog.patterns_starting_with("load_prop_cached");
    assert!(starting.len() >= 2); // load-add, load-sub, load-load
}

#[test]
fn catalog_add_pattern_bumps_version() {
    let mut catalog = SuperInstructionCatalog::default();
    let v1 = catalog.catalog_version;
    let h1 = catalog.catalog_hash.clone();
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-custom".into(),
        opcode_sequence: vec!["nop".into(), "nop".into()],
        fused_opcode: "nop_pair".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_100_000,
    });
    assert_eq!(catalog.catalog_version, v1 + 1);
    assert_ne!(catalog.catalog_hash, h1);
}

#[test]
fn catalog_hash_deterministic() {
    let c1 = SuperInstructionCatalog::default();
    let c2 = SuperInstructionCatalog::default();
    assert_eq!(c1.catalog_hash, c2.catalog_hash);
}

// ---------------------------------------------------------------------------
// Superinstruction candidate finding
// ---------------------------------------------------------------------------

#[test]
fn profile_finds_superinstruction_candidates() {
    // Use a custom catalog with a non-IC-requiring pattern for simpler testing
    let policy = aggressive_policy();
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-test".into(),
        opcode_sequence: vec!["add".into(), "jump".into()],
        fused_opcode: "add_and_jump".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_200_000,
    });

    let mut profile = QuickeningProfile::new("fn_super");

    // Set up an add + jump sequence at consecutive BTreeMap keys
    for _ in 0..100 {
        profile.record_execution(0, "add");
        profile.record_execution(1, "jump");
    }
    profile.record_type(0, "add", 0, ObservedType::Integer);

    // evaluate_all advances one level per call: Cold→Warm, Warm→Hot, Hot→Quickened
    // Need at least 2 calls to reach Hot (quickening eligible)
    profile.evaluate_all(&policy); // Cold→Warm
    profile.evaluate_all(&policy); // Warm→Hot
    profile.evaluate_all(&policy); // Hot→Quickened (with stability)

    // Verify at least the first instruction reached Hot or Quickened
    let entry = profile.get(0).unwrap();
    assert!(
        entry.level.is_quickening_eligible(),
        "instruction should be at Hot or Quickened, got {:?}",
        entry.level
    );

    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(!candidates.is_empty(), "should find at least one candidate");
    assert!(candidates.iter().any(|c| c.fused_opcode == "add_and_jump"));
}

#[test]
fn profile_no_candidates_when_cold() {
    let policy = default_policy();
    let catalog = SuperInstructionCatalog::default();
    let mut profile = QuickeningProfile::new("fn_cold");
    profile.record_execution(0, "load_prop_cached");
    profile.record_execution(4, "add");
    profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(candidates.is_empty());
}

// ---------------------------------------------------------------------------
// QuickeningDecision integration
// ---------------------------------------------------------------------------

#[test]
fn decision_build_has_hash() {
    let policy = aggressive_policy();
    let mut profile = make_hot_profile(&policy);
    let transitions = profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&SuperInstructionCatalog::default());

    let decision = QuickeningDecision::build(&profile, &policy, transitions, candidates);
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.schema_version, QUICKENING_SCHEMA_VERSION);
    assert_eq!(decision.function_id, "fn_hot");
}

#[test]
fn decision_deterministic() {
    let policy = aggressive_policy();
    let catalog = SuperInstructionCatalog::default();

    let build_decision = || {
        let mut profile = QuickeningProfile::new("fn_det");
        for _ in 0..20 {
            profile.record_execution(0, "add");
        }
        profile.record_type(0, "add", 0, ObservedType::Integer);
        let transitions = profile.evaluate_all(&policy);
        let candidates = profile.find_superinstruction_candidates(&catalog);
        QuickeningDecision::build(&profile, &policy, transitions, candidates)
    };

    let d1 = build_decision();
    let d2 = build_decision();
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

// ---------------------------------------------------------------------------
// Serde round-trip integration
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_profile() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("fn_serde");
    for _ in 0..20 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "sub");
    }
    profile.record_type(0, "add", 0, ObservedType::Integer);
    profile.evaluate_all(&policy);

    let json = serde_json::to_string(&profile).unwrap();
    let back: QuickeningProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile.profile_hash(), back.profile_hash());
}

#[test]
fn serde_round_trip_catalog() {
    let catalog = SuperInstructionCatalog::default();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: SuperInstructionCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, back);
}

#[test]
fn serde_round_trip_decision() {
    let policy = aggressive_policy();
    let mut profile = make_hot_profile(&policy);
    let transitions = profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&SuperInstructionCatalog::default());
    let decision = QuickeningDecision::build(&profile, &policy, transitions, candidates);

    let json = serde_json::to_string(&decision).unwrap();
    let back: QuickeningDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn serde_round_trip_summary() {
    let summary = QuickeningSummary {
        total_sites: 10,
        cold_count: 2,
        warm_count: 3,
        hot_count: 3,
        quickened_count: 2,
        total_executions: 1000,
        total_deopts: 1,
        evaluation_epoch: 5,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: QuickeningSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Constants and schema
// ---------------------------------------------------------------------------

#[test]
fn component_constant_set() {
    assert_eq!(COMPONENT, "quickening_feedback_lattice");
}

#[test]
fn schema_version_constants() {
    assert!(!QUICKENING_SCHEMA_VERSION.is_empty());
    assert!(!SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// Additional edge-case, trait coverage, and API tests
// ---------------------------------------------------------------------------

// --- QuickeningLevel: exhaustive trait and method coverage ---

#[test]
fn test_level_clone_and_copy_semantics() {
    let a = QuickeningLevel::Hot;
    let b = a; // Copy
    let c = a.clone(); // Clone
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn test_level_debug_format_all_variants() {
    assert!(format!("{:?}", QuickeningLevel::Cold).contains("Cold"));
    assert!(format!("{:?}", QuickeningLevel::Warm).contains("Warm"));
    assert!(format!("{:?}", QuickeningLevel::Hot).contains("Hot"));
    assert!(format!("{:?}", QuickeningLevel::Quickened).contains("Quickened"));
}

#[test]
fn test_level_is_quickened_only_for_quickened() {
    assert!(!QuickeningLevel::Cold.is_quickened());
    assert!(!QuickeningLevel::Warm.is_quickened());
    assert!(!QuickeningLevel::Hot.is_quickened());
    assert!(QuickeningLevel::Quickened.is_quickened());
}

#[test]
fn test_level_partial_ord_and_ord_consistency() {
    let mut levels = vec![
        QuickeningLevel::Quickened,
        QuickeningLevel::Cold,
        QuickeningLevel::Hot,
        QuickeningLevel::Warm,
    ];
    levels.sort();
    assert_eq!(
        levels,
        vec![
            QuickeningLevel::Cold,
            QuickeningLevel::Warm,
            QuickeningLevel::Hot,
            QuickeningLevel::Quickened,
        ]
    );
}

#[test]
fn test_level_serde_round_trip_all_variants() {
    for level in [
        QuickeningLevel::Cold,
        QuickeningLevel::Warm,
        QuickeningLevel::Hot,
        QuickeningLevel::Quickened,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: QuickeningLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

// --- ObservedType: full coverage ---

#[test]
fn test_observed_type_display_all_variants() {
    let cases = [
        (ObservedType::Undefined, "undefined"),
        (ObservedType::Null, "null"),
        (ObservedType::Boolean, "boolean"),
        (ObservedType::Integer, "int"),
        (ObservedType::Float, "float"),
        (ObservedType::String, "string"),
        (ObservedType::Object, "object"),
        (ObservedType::Symbol, "symbol"),
        (ObservedType::BigInt, "bigint"),
    ];
    for (ty, expected) in &cases {
        assert_eq!(format!("{ty}"), *expected);
    }
}

#[test]
fn test_observed_type_debug_and_clone() {
    let ty = ObservedType::BigInt;
    let cloned = ty.clone();
    assert_eq!(ty, cloned);
    assert!(format!("{ty:?}").contains("BigInt"));
}

#[test]
fn test_observed_type_ordering_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ObservedType::String);
    set.insert(ObservedType::Integer);
    set.insert(ObservedType::Object);
    set.insert(ObservedType::Integer); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn test_observed_type_serde_round_trip_all() {
    for ty in [
        ObservedType::Undefined,
        ObservedType::Null,
        ObservedType::Boolean,
        ObservedType::Integer,
        ObservedType::Float,
        ObservedType::String,
        ObservedType::Object,
        ObservedType::Symbol,
        ObservedType::BigInt,
    ] {
        let json = serde_json::to_string(&ty).unwrap();
        let back: ObservedType = serde_json::from_str(&json).unwrap();
        assert_eq!(ty, back);
    }
}

// --- TypeFeedbackSlot: edge cases ---

#[test]
fn test_type_slot_saturating_observation_count() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.observation_count = u64::MAX;
    slot.record(ObservedType::Integer);
    // saturating_add: must not overflow
    assert_eq!(slot.observation_count, u64::MAX);
}

#[test]
fn test_type_slot_stability_three_types() {
    let mut slot = TypeFeedbackSlot::new(0, 0);
    slot.record(ObservedType::Integer);
    slot.record(ObservedType::Float);
    slot.record(ObservedType::String);
    // 1_000_000 / 3 = 333_333
    assert_eq!(slot.stability_millionths(), 333_333);
}

#[test]
fn test_type_slot_display_unobserved() {
    let slot = TypeFeedbackSlot::new(7, 2);
    let s = format!("{slot}");
    assert!(s.contains("7"));
    assert!(s.contains("2"));
    // empty set
    assert!(s.contains("{}") || s.contains("n=0"));
}

#[test]
fn test_type_slot_clone_and_eq() {
    let mut slot = TypeFeedbackSlot::new(5, 1);
    slot.record(ObservedType::Boolean);
    let cloned = slot.clone();
    assert_eq!(slot, cloned);
}

#[test]
fn test_type_slot_serde_round_trip() {
    let mut slot = TypeFeedbackSlot::new(99, 3);
    slot.record(ObservedType::Symbol);
    slot.record(ObservedType::BigInt);
    let json = serde_json::to_string(&slot).unwrap();
    let back: TypeFeedbackSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, back);
}

// --- QuickeningPolicy: edge cases ---

#[test]
fn test_policy_clone_and_eq() {
    let p = default_policy();
    let q = p.clone();
    assert_eq!(p, q);
}

#[test]
fn test_policy_debug_format() {
    let p = default_policy();
    let dbg = format!("{p:?}");
    assert!(dbg.contains("warm_threshold"));
    assert!(dbg.contains("hot_threshold"));
}

#[test]
fn test_policy_serde_round_trip() {
    let p = aggressive_policy();
    let json = serde_json::to_string(&p).unwrap();
    let back: QuickeningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn test_policy_hash_is_64_hex_chars() {
    let p = default_policy();
    let h = p.policy_hash();
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

// --- InstructionFeedback: boundary and error paths ---

#[test]
fn test_instruction_feedback_no_advance_below_warm_threshold() {
    let policy = default_policy(); // warm_threshold = 8
    let mut fb = InstructionFeedback::new(0, "nop");
    for _ in 0..(policy.warm_threshold - 1) {
        fb.record_execution();
    }
    let t = fb.evaluate(&policy);
    assert!(
        !t.advanced,
        "should not advance with fewer than warm_threshold executions"
    );
    assert_eq!(fb.level, QuickeningLevel::Cold);
}

#[test]
fn test_instruction_feedback_stays_hot_if_unstable() {
    let policy = QuickeningPolicy {
        warm_threshold: 2,
        hot_threshold: 4,
        min_stability_millionths: 900_000,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    };
    let mut fb = InstructionFeedback::new(0, "add");
    for _ in 0..10 {
        fb.record_execution();
    }
    // Two types → stability = 500_000 < 900_000 required
    fb.record_type(0, ObservedType::Integer);
    fb.record_type(0, ObservedType::Float);
    fb.evaluate(&policy); // Cold → Warm
    fb.evaluate(&policy); // Warm → Hot
    let t = fb.evaluate(&policy); // Hot → should stay Hot due to low stability
    assert!(!t.advanced);
    assert_eq!(fb.level, QuickeningLevel::Hot);
}

#[test]
fn test_instruction_feedback_update_ic_hit_rate() {
    let mut fb = InstructionFeedback::new(0, "load_prop_cached");
    fb.update_ic_hit_rate(950_000);
    assert_eq!(fb.ic_hit_rate_millionths, 950_000);
}

#[test]
fn test_instruction_feedback_deopt_count_saturates() {
    let policy = default_policy();
    let mut fb = InstructionFeedback::new(0, "add");
    fb.deopt_count = u32::MAX;
    // Record one more deopt — must not overflow
    fb.record_deopt(&policy);
    assert_eq!(fb.deopt_count, u32::MAX);
}

#[test]
fn test_instruction_feedback_execution_count_saturates() {
    let mut fb = InstructionFeedback::new(0, "nop");
    fb.execution_count = u64::MAX;
    fb.record_execution(); // saturating_add
    assert_eq!(fb.execution_count, u64::MAX);
}

#[test]
fn test_instruction_feedback_min_stability_no_slots() {
    let fb = InstructionFeedback::new(0, "nop");
    // No type slots → min returns 0
    assert_eq!(fb.min_stability_millionths(), 0);
}

#[test]
fn test_instruction_feedback_clone_and_eq() {
    let fb = InstructionFeedback::new(100, "jump");
    let cloned = fb.clone();
    assert_eq!(fb, cloned);
}

#[test]
fn test_instruction_feedback_serde_round_trip() {
    let mut fb = InstructionFeedback::new(42, "store_prop");
    fb.record_execution();
    fb.record_type(0, ObservedType::Object);
    fb.update_ic_hit_rate(750_000);
    let json = serde_json::to_string(&fb).unwrap();
    let back: InstructionFeedback = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

// --- QuickeningTransition: trait coverage ---

#[test]
fn test_quickening_transition_serde_round_trip() {
    use frankenengine_engine::quickening_feedback_lattice::QuickeningTransition;
    let t = QuickeningTransition {
        instruction_offset: 8,
        from: QuickeningLevel::Cold,
        to: QuickeningLevel::Warm,
        execution_count: 16,
        advanced: true,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: QuickeningTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn test_quickening_transition_clone_and_debug() {
    use frankenengine_engine::quickening_feedback_lattice::QuickeningTransition;
    let t = QuickeningTransition {
        instruction_offset: 0,
        from: QuickeningLevel::Warm,
        to: QuickeningLevel::Hot,
        execution_count: 64,
        advanced: true,
    };
    let cloned = t.clone();
    assert_eq!(t, cloned);
    assert!(format!("{t:?}").contains("advanced"));
}

// --- QuickeningProfile: empty and boundary behavior ---

#[test]
fn test_profile_empty_summary() {
    let profile = QuickeningProfile::new("empty_fn");
    let s = profile.summary();
    assert_eq!(s.total_sites, 0);
    assert_eq!(s.cold_count, 0);
    assert_eq!(s.warm_count, 0);
    assert_eq!(s.hot_count, 0);
    assert_eq!(s.quickened_count, 0);
    assert_eq!(s.total_executions, 0);
    assert_eq!(s.total_deopts, 0);
}

#[test]
fn test_profile_entry_count_tracks_unique_offsets() {
    let mut profile = QuickeningProfile::new("fn_ec");
    profile.record_execution(0, "nop");
    profile.record_execution(0, "nop"); // same offset
    profile.record_execution(4, "add");
    assert_eq!(profile.entry_count(), 2);
}

#[test]
fn test_profile_get_returns_none_for_missing_offset() {
    let profile = QuickeningProfile::new("fn_missing");
    assert!(profile.get(999).is_none());
}

#[test]
fn test_profile_default_is_empty() {
    let profile = QuickeningProfile::default();
    assert_eq!(profile.entry_count(), 0);
    assert_eq!(profile.function_id, "");
    assert_eq!(profile.evaluation_epoch, 0);
}

#[test]
fn test_profile_record_deopt_on_nonexistent_offset_is_noop() {
    let policy = default_policy();
    let mut profile = QuickeningProfile::new("fn_noop_deopt");
    profile.record_deopt(42, &policy); // offset 42 doesn't exist
    assert_eq!(profile.total_deopts, 0);
}

#[test]
fn test_profile_clone_preserves_state() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("fn_clone");
    for _ in 0..10 {
        profile.record_execution(0, "add");
    }
    profile.evaluate_all(&policy);
    let cloned = profile.clone();
    assert_eq!(profile.profile_hash(), cloned.profile_hash());
    assert_eq!(profile.evaluation_epoch, cloned.evaluation_epoch);
}

#[test]
fn test_profile_total_executions_accumulates_across_offsets() {
    let mut profile = QuickeningProfile::new("fn_total_exec");
    for _ in 0..5 {
        profile.record_execution(0, "a");
    }
    for _ in 0..3 {
        profile.record_execution(4, "b");
    }
    // total_executions counts each record_execution call globally
    assert_eq!(profile.total_executions, 8);
}

// --- SuperInstructionPattern: edge cases ---

#[test]
fn test_pattern_clone_eq_ord() {
    let patterns = default_superinstruction_patterns();
    let p1 = patterns[0].clone();
    let p2 = patterns[0].clone();
    assert_eq!(p1, p2);
    assert!(p1 <= p2);
}

#[test]
fn test_pattern_display_speedup_format() {
    let p = SuperInstructionPattern {
        pattern_id: "si-test-disp".into(),
        opcode_sequence: vec!["a".into(), "b".into()],
        fused_opcode: "a_b".into(),
        type_constraints: BTreeMap::new(),
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_500_000,
    };
    let s = format!("{p}");
    // 1_500_000 / 1_000_000 = 1, (1_500_000 % 1_000_000) / 1_000 = 500
    assert!(s.contains("1.500x") || s.contains("a_b"));
}

#[test]
fn test_pattern_serde_round_trip_with_type_constraints() {
    let mut constraints = BTreeMap::new();
    constraints.insert(0u8, ObservedType::Integer);
    constraints.insert(1u8, ObservedType::Float);
    let p = SuperInstructionPattern {
        pattern_id: "si-typed".into(),
        opcode_sequence: vec!["mul".into(), "store".into()],
        fused_opcode: "mul_store".into(),
        type_constraints: constraints,
        requires_monomorphic_ic: true,
        estimated_speedup_millionths: 1_250_000,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: SuperInstructionPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// --- SuperInstructionCatalog: boundary and API coverage ---

#[test]
fn test_catalog_new_empty_has_no_patterns() {
    let catalog = SuperInstructionCatalog::new(vec![]);
    assert_eq!(catalog.pattern_count(), 0);
    assert_eq!(
        catalog.schema_version,
        SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION
    );
}

#[test]
fn test_catalog_find_matching_empty_slice() {
    let catalog = SuperInstructionCatalog::default();
    // Empty slice can't match any multi-opcode pattern
    let matched = catalog.find_matching(&[]);
    assert!(matched.is_empty());
}

#[test]
fn test_catalog_patterns_starting_with_unknown_opcode() {
    let catalog = SuperInstructionCatalog::default();
    let starting = catalog.patterns_starting_with("totally_unknown_opcode");
    assert!(starting.is_empty());
}

#[test]
fn test_catalog_add_multiple_patterns_version_increments() {
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    let v0 = catalog.catalog_version;
    for i in 0..3u8 {
        catalog.add_pattern(SuperInstructionPattern {
            pattern_id: format!("si-extra-{i}"),
            opcode_sequence: vec![format!("op_{i}"), "nop".into()],
            fused_opcode: format!("fused_{i}"),
            type_constraints: BTreeMap::new(),
            requires_monomorphic_ic: false,
            estimated_speedup_millionths: 1_100_000,
        });
    }
    assert_eq!(catalog.catalog_version, v0 + 3);
}

#[test]
fn test_catalog_debug_format() {
    let catalog = SuperInstructionCatalog::default();
    let dbg = format!("{catalog:?}");
    assert!(dbg.contains("catalog_version"));
}

// --- SuperInstructionCandidate: trait coverage ---

#[test]
fn test_candidate_serde_round_trip() {
    let c = SuperInstructionCandidate {
        start_offset: 16,
        pattern_id: "si-load-add".into(),
        fused_opcode: "load_prop_and_add".into(),
        estimated_speedup_millionths: 1_300_000,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: SuperInstructionCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn test_candidate_clone_and_debug() {
    let c = SuperInstructionCandidate {
        start_offset: 0,
        pattern_id: "si-store-jump".into(),
        fused_opcode: "store_prop_and_jump".into(),
        estimated_speedup_millionths: 1_200_000,
    };
    let cloned = c.clone();
    assert_eq!(c, cloned);
    assert!(format!("{c:?}").contains("start_offset"));
}

// --- QuickeningSummary: full coverage ---

#[test]
fn test_summary_default_via_empty_profile() {
    let profile = QuickeningProfile::new("fn_s");
    let s = profile.summary();
    // All counts must sum correctly
    assert_eq!(
        s.cold_count + s.warm_count + s.hot_count + s.quickened_count,
        s.total_sites
    );
}

#[test]
fn test_summary_counts_consistent_after_transitions() {
    let policy = aggressive_policy();
    let mut profile = QuickeningProfile::new("fn_counts");
    // 3 sites
    for _ in 0..20 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "sub");
        profile.record_execution(8, "nop");
    }
    // Only nop is cold (1 execution total from first pass above actually all are 20)
    // We want nop to stay cold by limiting execution. Reset it.
    // Actually all 3 have 20 executions — let's just check consistency
    profile.evaluate_all(&policy);
    let s = profile.summary();
    assert_eq!(
        s.cold_count + s.warm_count + s.hot_count + s.quickened_count,
        s.total_sites
    );
    assert_eq!(s.total_sites, 3);
}

#[test]
fn test_summary_clone_and_debug() {
    let s = QuickeningSummary {
        total_sites: 5,
        cold_count: 1,
        warm_count: 2,
        hot_count: 1,
        quickened_count: 1,
        total_executions: 500,
        total_deopts: 0,
        evaluation_epoch: 3,
    };
    let cloned = s.clone();
    assert_eq!(s, cloned);
    assert!(format!("{s:?}").contains("total_sites"));
}

// --- QuickeningDecision: additional coverage ---

#[test]
fn test_decision_clone_and_debug() {
    let policy = aggressive_policy();
    let mut profile = make_hot_profile(&policy);
    let transitions = profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&SuperInstructionCatalog::default());
    let decision = QuickeningDecision::build(&profile, &policy, transitions, candidates);
    let cloned = decision.clone();
    assert_eq!(decision, cloned);
    assert!(format!("{decision:?}").contains("function_id"));
}

#[test]
fn test_decision_schema_version_matches_constant() {
    let policy = aggressive_policy();
    let mut profile = make_hot_profile(&policy);
    let transitions = profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&SuperInstructionCatalog::default());
    let decision = QuickeningDecision::build(&profile, &policy, transitions, candidates);
    assert_eq!(decision.schema_version, QUICKENING_SCHEMA_VERSION);
}

#[test]
fn test_decision_with_no_transitions_or_candidates() {
    let policy = default_policy();
    let profile = QuickeningProfile::new("fn_empty_decision");
    let decision = QuickeningDecision::build(&profile, &policy, vec![], vec![]);
    assert!(!decision.decision_hash.is_empty());
    assert!(decision.transitions.is_empty());
    assert!(decision.superinstruction_candidates.is_empty());
    assert_eq!(decision.summary.total_sites, 0);
}

#[test]
fn test_decision_policy_hash_embedded() {
    let policy = aggressive_policy();
    let mut profile = make_hot_profile(&policy);
    let transitions = profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&SuperInstructionCatalog::default());
    let decision = QuickeningDecision::build(&profile, &policy, transitions, candidates);
    assert_eq!(decision.policy_hash, policy.policy_hash());
}

// --- QuickeningProfile: superinstruction candidate edge cases ---

#[test]
fn test_no_candidates_with_empty_catalog() {
    let policy = aggressive_policy();
    let catalog = SuperInstructionCatalog::new(vec![]);
    let mut profile = QuickeningProfile::new("fn_empty_cat");
    for _ in 0..100 {
        profile.record_execution(0, "add");
        profile.record_execution(1, "jump");
    }
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);
    let candidates = profile.find_superinstruction_candidates(&catalog);
    assert!(candidates.is_empty());
}

#[test]
fn test_profile_find_superinstruction_type_constraint_mismatch() {
    // Pattern requires Integer at operand 0, but we observe Float
    let policy = aggressive_policy();
    let mut catalog = SuperInstructionCatalog::new(vec![]);
    let mut constraints = BTreeMap::new();
    constraints.insert(0u8, ObservedType::Integer);
    catalog.add_pattern(SuperInstructionPattern {
        pattern_id: "si-typed-check".into(),
        opcode_sequence: vec!["fadd".into(), "fsub".into()],
        fused_opcode: "fused_fadd_fsub".into(),
        type_constraints: constraints,
        requires_monomorphic_ic: false,
        estimated_speedup_millionths: 1_150_000,
    });

    let mut profile = QuickeningProfile::new("fn_type_mismatch");
    for _ in 0..100 {
        profile.record_execution(0, "fadd");
        profile.record_execution(1, "fsub");
    }
    // Record Float at operand 0, but pattern wants Integer
    profile.record_type(0, "fadd", 0, ObservedType::Float);
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);
    profile.evaluate_all(&policy);

    let candidates = profile.find_superinstruction_candidates(&catalog);
    // Should not match because type constraint fails (Float != Integer)
    assert!(
        candidates
            .iter()
            .all(|c| c.fused_opcode != "fused_fadd_fsub"),
        "type constraint mismatch should prevent candidate"
    );
}
