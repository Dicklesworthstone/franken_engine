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
    SUPERINSTRUCTION_CATALOG_SCHEMA_VERSION, SuperInstructionCatalog, SuperInstructionPattern,
    TypeFeedbackSlot, default_superinstruction_patterns,
};
use std::collections::BTreeMap;

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
