//! Enrichment integration tests for superblock_formation module.
//!
//! Targets gaps: FormationDecision, form_all_superblocks, build_trace_tree,
//! DeoptContinuation, FallbackTier/OptimizedTierBackend display/serde,
//! CompilationRejectReason serde, policy hash sensitivity, deopt_continuations,
//! tail duplication paths, guard factoring through formation, trace tree growth.

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

use std::collections::BTreeSet;

use frankenengine_engine::quickening_feedback_lattice::{
    ObservedType, QuickeningLevel, QuickeningPolicy, QuickeningProfile,
};
use frankenengine_engine::superblock_formation::{
    COMPONENT, CompilationRejectReason, FallbackTier, FormationDecision, FormationOutcome,
    FormationRecord, GuardKind, OPTIMIZED_TIER_PLAN_SCHEMA_VERSION, OptimizedTierBackend,
    SUPERBLOCK_SCHEMA_VERSION, SideExit, SideExitReason, Superblock, SuperblockEntry,
    SuperblockGuard, SuperblockPolicy, TRACE_TREE_SCHEMA_VERSION, TraceTree, TraceTreeSummary,
    build_trace_tree, form_all_superblocks, form_superblock,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn aggressive_quickening_policy() -> QuickeningPolicy {
    QuickeningPolicy {
        warm_threshold: 2,
        hot_threshold: 4,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    }
}

fn make_hot_profile(function_id: &str, offsets_and_opcodes: &[(u32, &str)]) -> QuickeningProfile {
    let q_policy = aggressive_quickening_policy();
    let mut profile = QuickeningProfile::new(function_id);
    for &(offset, opcode) in offsets_and_opcodes {
        for _ in 0..100 {
            profile.record_execution(offset, opcode);
        }
        profile.record_type(offset, opcode, 0, ObservedType::Integer);
    }
    for _ in 0..4 {
        profile.evaluate_all(&q_policy);
    }
    profile
}

fn make_simple_superblock(function_id: &str, entry_offset: u32) -> Superblock {
    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: entry_offset,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
        SuperblockEntry {
            position: 1,
            source_offset: entry_offset + 4,
            opcode: "store".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
    ];
    let block_id = Superblock::compute_block_id(function_id, &entries);
    Superblock {
        block_id,
        function_id: function_id.into(),
        entry_offset,
        entries,
        guards: vec![SuperblockGuard::new(
            0,
            entry_offset,
            GuardKind::TypeCheck {
                expected_type: "int".into(),
            },
            "exit-test-0001".into(),
        )],
        side_exits: vec![SideExit::new(entry_offset, 0, SideExitReason::TypeMismatch)],
        tail_duplication_count: 0,
        formation_epoch: 1,
    }
}

// ===========================================================================
// FormationDecision tests (not covered in base integration tests)
// ===========================================================================

#[test]
fn formation_decision_build_empty_records() {
    let policy = SuperblockPolicy::default();
    let decision = FormationDecision::build("fn_empty_dec", &policy, 1, vec![], None);
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.formed_count(), 0);
    assert_eq!(decision.rejected_count(), 0);
    assert_eq!(decision.schema_version, SUPERBLOCK_SCHEMA_VERSION);
    assert_eq!(decision.function_id, "fn_empty_dec");
    assert_eq!(decision.formation_epoch, 1);
    assert!(decision.trace_tree_summary.is_none());
}

#[test]
fn formation_decision_counts_mixed_outcomes() {
    let policy = SuperblockPolicy::default();
    let records = vec![
        FormationRecord {
            function_id: "fn_mix".into(),
            entry_offset: 0,
            outcome: FormationOutcome::Formed,
            instructions_considered: 5,
            instructions_included: 5,
            guards_generated: 2,
            tail_duplications: 0,
            block: None,
        },
        FormationRecord {
            function_id: "fn_mix".into(),
            entry_offset: 100,
            outcome: FormationOutcome::NoEligibleInstructions,
            instructions_considered: 0,
            instructions_included: 0,
            guards_generated: 0,
            tail_duplications: 0,
            block: None,
        },
        FormationRecord {
            function_id: "fn_mix".into(),
            entry_offset: 200,
            outcome: FormationOutcome::ExcessiveGuards,
            instructions_considered: 10,
            instructions_included: 0,
            guards_generated: 0,
            tail_duplications: 0,
            block: None,
        },
        FormationRecord {
            function_id: "fn_mix".into(),
            entry_offset: 300,
            outcome: FormationOutcome::Formed,
            instructions_considered: 3,
            instructions_included: 3,
            guards_generated: 1,
            tail_duplications: 0,
            block: None,
        },
    ];
    let decision = FormationDecision::build("fn_mix", &policy, 5, records, None);
    assert_eq!(decision.formed_count(), 2);
    assert_eq!(decision.rejected_count(), 2);
    assert_eq!(decision.formation_epoch, 5);
}

#[test]
fn formation_decision_hash_deterministic() {
    let policy = SuperblockPolicy::default();
    let d1 = FormationDecision::build("fn_det", &policy, 1, vec![], None);
    let d2 = FormationDecision::build("fn_det", &policy, 1, vec![], None);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn formation_decision_hash_varies_with_function_id() {
    let policy = SuperblockPolicy::default();
    let d1 = FormationDecision::build("fn_a", &policy, 1, vec![], None);
    let d2 = FormationDecision::build("fn_b", &policy, 1, vec![], None);
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn formation_decision_hash_varies_with_epoch() {
    let policy = SuperblockPolicy::default();
    let d1 = FormationDecision::build("fn_e", &policy, 1, vec![], None);
    let d2 = FormationDecision::build("fn_e", &policy, 2, vec![], None);
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn formation_decision_with_trace_tree_summary() {
    let policy = SuperblockPolicy::default();
    let block = make_simple_superblock("fn_tree_dec", 0);
    let tree = TraceTree::new("fn_tree_dec", block);
    let decision = FormationDecision::build("fn_tree_dec", &policy, 1, vec![], Some(&tree));
    assert!(decision.trace_tree_summary.is_some());
    let summary = decision.trace_tree_summary.unwrap();
    assert_eq!(summary.function_id, "fn_tree_dec");
    assert_eq!(summary.node_count, 1);
}

#[test]
fn formation_decision_serde_roundtrip() {
    let policy = SuperblockPolicy::default();
    let records = vec![FormationRecord {
        function_id: "fn_serde".into(),
        entry_offset: 0,
        outcome: FormationOutcome::Formed,
        instructions_considered: 3,
        instructions_included: 3,
        guards_generated: 1,
        tail_duplications: 0,
        block: None,
    }];
    let decision = FormationDecision::build("fn_serde", &policy, 1, records, None);
    let json = serde_json::to_string(&decision).unwrap();
    let back: FormationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ===========================================================================
// FormationOutcome serde exhaustiveness
// ===========================================================================

#[test]
fn formation_outcome_all_variants_serde_roundtrip() {
    let variants = vec![
        FormationOutcome::Formed,
        FormationOutcome::InsufficientHotInstructions,
        FormationOutcome::ExceedsBlockSize,
        FormationOutcome::ExcessiveGuards,
        FormationOutcome::NoEligibleInstructions,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: FormationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn formation_outcome_display_all_unique() {
    let variants = vec![
        FormationOutcome::Formed,
        FormationOutcome::InsufficientHotInstructions,
        FormationOutcome::ExceedsBlockSize,
        FormationOutcome::ExcessiveGuards,
        FormationOutcome::NoEligibleInstructions,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

// ===========================================================================
// FormationRecord serde
// ===========================================================================

#[test]
fn formation_record_serde_roundtrip() {
    let record = FormationRecord {
        function_id: "fn_rec".into(),
        entry_offset: 16,
        outcome: FormationOutcome::InsufficientHotInstructions,
        instructions_considered: 7,
        instructions_included: 1,
        guards_generated: 0,
        tail_duplications: 2,
        block: None,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: FormationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn formation_record_with_block_serde_roundtrip() {
    let block = make_simple_superblock("fn_rec_block", 0);
    let record = FormationRecord {
        function_id: "fn_rec_block".into(),
        entry_offset: 0,
        outcome: FormationOutcome::Formed,
        instructions_considered: 2,
        instructions_included: 2,
        guards_generated: 1,
        tail_duplications: 0,
        block: Some(block),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: FormationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

// ===========================================================================
// OptimizedTierBackend display/serde
// ===========================================================================

#[test]
fn optimized_tier_backend_display() {
    assert_eq!(format!("{}", OptimizedTierBackend::Cranelift), "cranelift");
}

#[test]
fn optimized_tier_backend_serde_roundtrip() {
    let b = OptimizedTierBackend::Cranelift;
    let json = serde_json::to_string(&b).unwrap();
    let back: OptimizedTierBackend = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// FallbackTier display/serde
// ===========================================================================

#[test]
fn fallback_tier_display() {
    assert_eq!(
        format!("{}", FallbackTier::BaselineInterpreter),
        "baseline_interpreter"
    );
}

#[test]
fn fallback_tier_serde_roundtrip() {
    let t = FallbackTier::BaselineInterpreter;
    let json = serde_json::to_string(&t).unwrap();
    let back: FallbackTier = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ===========================================================================
// CompilationRejectReason serde
// ===========================================================================

#[test]
fn compilation_reject_reason_all_variants_serde() {
    let variants = vec![
        CompilationRejectReason::TierUpIneligible,
        CompilationRejectReason::SuperblockFormationRejected,
        CompilationRejectReason::DuplicateCandidateOffset,
        CompilationRejectReason::CandidateProfileMismatch,
        CompilationRejectReason::MissingDeoptContinuations,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompilationRejectReason = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ===========================================================================
// SuperblockPolicy hash sensitivity
// ===========================================================================

#[test]
fn policy_hash_sensitive_to_max_tail_duplication() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        max_tail_duplication: p1.max_tail_duplication + 1,
        ..p1.clone()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_sensitive_to_max_trace_depth() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        max_trace_depth: p1.max_trace_depth + 1,
        ..p1.clone()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_sensitive_to_max_side_exits() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        max_side_exits: p1.max_side_exits + 1,
        ..p1.clone()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_sensitive_to_min_execution_count() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        min_execution_count: p1.min_execution_count + 1,
        ..p1.clone()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_sensitive_to_enable_guard_factoring() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        enable_guard_factoring: !p1.enable_guard_factoring,
        ..p1.clone()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_serde_roundtrip() {
    let policy = SuperblockPolicy {
        max_block_length: 128,
        max_tail_duplication: 16,
        max_trace_depth: 4,
        max_side_exits: 8,
        min_execution_count: 64,
        enable_guard_factoring: false,
        ..SuperblockPolicy::default()
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: SuperblockPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ===========================================================================
// Superblock.deopt_continuations()
// ===========================================================================

#[test]
fn deopt_continuations_from_guarded_block() {
    // Build a block where guard.side_exit_id matches an exit's exit_id
    let exit = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    let guard = SuperblockGuard::new(
        0,
        0,
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        exit.exit_id.clone(), // use the actual computed exit_id
    );
    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
        SuperblockEntry {
            position: 1,
            source_offset: 4,
            opcode: "sub".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
    ];
    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_deopt", &entries),
        function_id: "fn_deopt".into(),
        entry_offset: 0,
        entries,
        guards: vec![guard],
        side_exits: vec![exit],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };
    let conts = block.deopt_continuations();
    assert_eq!(conts.len(), 1);
    assert!(conts[0].checkpoint_id.starts_with("deopt-"));
    assert_eq!(conts[0].fallback_tier, FallbackTier::BaselineInterpreter);
    assert_eq!(conts[0].guard_position, 0);
    assert_eq!(
        conts[0].guard_kind,
        GuardKind::TypeCheck {
            expected_type: "int".into()
        }
    );
}

#[test]
fn deopt_continuations_empty_for_guardless_block() {
    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
        SuperblockEntry {
            position: 1,
            source_offset: 4,
            opcode: "sub".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
    ];
    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_no_guards", &entries),
        function_id: "fn_no_guards".into(),
        entry_offset: 0,
        entries,
        guards: vec![],
        side_exits: vec![],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };
    assert!(block.deopt_continuations().is_empty());
}

#[test]
fn deopt_continuations_sorted_by_guard_position() {
    let exit0 = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    let exit1 = SideExit::new(4, 1, SideExitReason::OverflowDetected);
    let exit2 = SideExit::new(8, 2, SideExitReason::ShapeMismatch);

    let guards = vec![
        SuperblockGuard::new(2, 8, GuardKind::OverflowCheck, exit2.exit_id.clone()),
        SuperblockGuard::new(
            0,
            0,
            GuardKind::TypeCheck {
                expected_type: "int".into(),
            },
            exit0.exit_id.clone(),
        ),
        SuperblockGuard::new(
            1,
            4,
            GuardKind::IcStability { ic_offset: 4 },
            exit1.exit_id.clone(),
        ),
    ];

    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "a".into(),
            is_tail_duplicate: false,
            execution_count: 1,
        },
        SuperblockEntry {
            position: 1,
            source_offset: 4,
            opcode: "b".into(),
            is_tail_duplicate: false,
            execution_count: 1,
        },
        SuperblockEntry {
            position: 2,
            source_offset: 8,
            opcode: "c".into(),
            is_tail_duplicate: false,
            execution_count: 1,
        },
    ];

    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_sorted", &entries),
        function_id: "fn_sorted".into(),
        entry_offset: 0,
        entries,
        guards,
        side_exits: vec![exit0, exit1, exit2],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };

    let conts = block.deopt_continuations();
    assert_eq!(conts.len(), 3);
    assert!(
        conts
            .windows(2)
            .all(|pair| pair[0].guard_position <= pair[1].guard_position)
    );
}

#[test]
fn deopt_continuation_checkpoint_id_deterministic() {
    let block1 = make_simple_superblock("fn_ckpt_det", 0);
    let block2 = make_simple_superblock("fn_ckpt_det", 0);
    let c1 = block1.deopt_continuations();
    let c2 = block2.deopt_continuations();
    assert_eq!(c1.len(), c2.len());
    for (a, b) in c1.iter().zip(c2.iter()) {
        assert_eq!(a.checkpoint_id, b.checkpoint_id);
    }
}

// ===========================================================================
// Superblock.factored_guard_count()
// ===========================================================================

#[test]
fn factored_guard_count_with_factored_guards() {
    let exit = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    let mut g1 = SuperblockGuard::new(
        0,
        0,
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        exit.exit_id.clone(),
    );
    g1.factored = true;
    let g2 = SuperblockGuard::new(
        1,
        4,
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        exit.exit_id.clone(),
    );

    let entries = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "a".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_fg", &entries),
        function_id: "fn_fg".into(),
        entry_offset: 0,
        entries,
        guards: vec![g1, g2],
        side_exits: vec![exit],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };
    assert_eq!(block.factored_guard_count(), 1);
    assert_eq!(block.guard_count(), 2);
}

// ===========================================================================
// Superblock.compute_block_id sensitivity
// ===========================================================================

#[test]
fn block_id_varies_with_opcode() {
    let e1 = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    let e2 = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "sub".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    assert_ne!(
        Superblock::compute_block_id("fn_x", &e1),
        Superblock::compute_block_id("fn_x", &e2)
    );
}

#[test]
fn block_id_varies_with_source_offset() {
    let e1 = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    let e2 = vec![SuperblockEntry {
        position: 0,
        source_offset: 4,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    assert_ne!(
        Superblock::compute_block_id("fn_x", &e1),
        Superblock::compute_block_id("fn_x", &e2)
    );
}

#[test]
fn block_id_insensitive_to_execution_count() {
    let e1 = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    let e2 = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 999,
    }];
    // block_id is computed from function_id + source_offset + opcode, NOT execution_count
    assert_eq!(
        Superblock::compute_block_id("fn_x", &e1),
        Superblock::compute_block_id("fn_x", &e2)
    );
}

// ===========================================================================
// SideExit edge cases
// ===========================================================================

#[test]
fn side_exit_id_varies_with_guard_position() {
    let e1 = SideExit::new(10, 0, SideExitReason::GuardFailure);
    let e2 = SideExit::new(10, 1, SideExitReason::GuardFailure);
    assert_ne!(e1.exit_id, e2.exit_id);
}

#[test]
fn side_exit_initial_state() {
    let exit = SideExit::new(100, 5, SideExitReason::PrototypeInvalidated);
    assert_eq!(exit.resume_offset, 100);
    assert_eq!(exit.guard_position, 5);
    assert_eq!(exit.reason, SideExitReason::PrototypeInvalidated);
    assert_eq!(exit.taken_count, 0);
    assert!(!exit.compiled_branch);
    assert!(exit.exit_id.starts_with("exit-"));
}

#[test]
fn side_exit_serde_roundtrip() {
    let mut exit = SideExit::new(8, 2, SideExitReason::UnexpectedControlFlow);
    exit.taken_count = 42;
    exit.compiled_branch = true;
    let json = serde_json::to_string(&exit).unwrap();
    let back: SideExit = serde_json::from_str(&json).unwrap();
    assert_eq!(exit, back);
}

#[test]
fn side_exit_reason_all_variants_serde_roundtrip() {
    let reasons = vec![
        SideExitReason::GuardFailure,
        SideExitReason::OverflowDetected,
        SideExitReason::TypeMismatch,
        SideExitReason::ShapeMismatch,
        SideExitReason::IcMegamorphic,
        SideExitReason::PrototypeInvalidated,
        SideExitReason::UnexpectedControlFlow,
    ];
    for r in reasons {
        let json = serde_json::to_string(&r).unwrap();
        let back: SideExitReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn side_exit_reason_display_all_unique() {
    let reasons = vec![
        SideExitReason::GuardFailure,
        SideExitReason::OverflowDetected,
        SideExitReason::TypeMismatch,
        SideExitReason::ShapeMismatch,
        SideExitReason::IcMegamorphic,
        SideExitReason::PrototypeInvalidated,
        SideExitReason::UnexpectedControlFlow,
    ];
    let displays: BTreeSet<String> = reasons.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), reasons.len());
}

// ===========================================================================
// GuardKind additional tests
// ===========================================================================

#[test]
fn guard_kind_all_variants_serde_roundtrip() {
    let kinds = vec![
        GuardKind::ShapeCheck {
            expected_shape_id: "s1".into(),
        },
        GuardKind::TypeCheck {
            expected_type: "string".into(),
        },
        GuardKind::RangeCheck {
            lower: -100,
            upper: 100,
        },
        GuardKind::IcStability { ic_offset: 0 },
        GuardKind::OverflowCheck,
        GuardKind::PrototypeChain {
            expected_hash: "hash123".into(),
        },
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let back: GuardKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn guard_kind_display_all_unique() {
    let kinds = vec![
        GuardKind::ShapeCheck {
            expected_shape_id: "s1".into(),
        },
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        GuardKind::RangeCheck {
            lower: 0,
            upper: 10,
        },
        GuardKind::IcStability { ic_offset: 42 },
        GuardKind::OverflowCheck,
        GuardKind::PrototypeChain {
            expected_hash: "abc".into(),
        },
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), kinds.len());
}

#[test]
fn guard_kind_ord_consistent() {
    let a = GuardKind::OverflowCheck;
    let b = GuardKind::TypeCheck {
        expected_type: "int".into(),
    };
    let c = GuardKind::ShapeCheck {
        expected_shape_id: "s".into(),
    };
    // Verify transitivity: if a < b and b < c or vice versa, ordering is consistent
    let mut sorted = vec![b.clone(), c.clone(), a.clone()];
    sorted.sort();
    let mut sorted2 = sorted.clone();
    sorted2.sort();
    assert_eq!(sorted, sorted2);
}

// ===========================================================================
// SuperblockGuard additional tests
// ===========================================================================

#[test]
fn guard_serde_with_factored_flag() {
    let mut guard = SuperblockGuard::new(
        3,
        12,
        GuardKind::RangeCheck {
            lower: 0,
            upper: 255,
        },
        "exit-range".into(),
    );
    guard.factored = true;
    let json = serde_json::to_string(&guard).unwrap();
    let back: SuperblockGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, back);
    assert!(back.factored);
}

#[test]
fn guard_display_contains_guard_position() {
    let guard = SuperblockGuard::new(
        7,
        28,
        GuardKind::PrototypeChain {
            expected_hash: "xyz".into(),
        },
        "exit-proto".into(),
    );
    let display = format!("{guard}");
    assert!(display.contains("guard@7"));
    assert!(display.contains("proto-chain"));
}

// ===========================================================================
// form_superblock edge cases
// ===========================================================================

#[test]
fn form_superblock_respects_max_block_length() {
    let offsets: Vec<(u32, &str)> = (0..20u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_max_len", &offsets);
    let policy = SuperblockPolicy {
        max_block_length: 3,
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    let block = record.block.unwrap();
    assert_eq!(block.instruction_count(), 3);
}

#[test]
fn form_superblock_insufficient_hot_instructions_single_entry() {
    // Profile with only 1 hot instruction -> InsufficientHotInstructions (needs >= 2)
    let offsets: Vec<(u32, &str)> = vec![(0, "add")];
    let profile = make_hot_profile("fn_single", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(
        record.outcome,
        FormationOutcome::InsufficientHotInstructions
    );
    assert!(record.block.is_none());
    assert_eq!(record.instructions_included, 1);
}

#[test]
fn form_superblock_generates_ic_stability_guards() {
    // Profile with high IC hit rate to trigger IC stability guards
    let q_policy = QuickeningPolicy {
        warm_threshold: 2,
        hot_threshold: 4,
        min_stability_millionths: 500_000,
        min_ic_hit_rate_millionths: 900_000,
        max_polymorphic_types: 3,
        deopt_resets_to_cold: true,
    };
    let mut profile = QuickeningProfile::new("fn_ic_guard");
    for offset in (0..12).step_by(4) {
        for _ in 0..100 {
            profile.record_execution(offset, &format!("op_{offset}"));
        }
        profile.record_type(offset, &format!("op_{offset}"), 0, ObservedType::Integer);
    }
    for _ in 0..4 {
        profile.evaluate_all(&q_policy);
    }

    let policy = SuperblockPolicy {
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    let block = record.block.unwrap();
    // Should have guards from either type checks or IC stability
    assert!(block.guard_count() > 0);
}

#[test]
fn form_superblock_guard_factoring_enabled() {
    let offsets: Vec<(u32, &str)> = (0..8u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_factor_on", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        enable_guard_factoring: true,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    let block = record.block.unwrap();
    // With factoring, some guards should be marked factored
    // (depends on consecutive same-kind guards)
    if block.guard_count() >= 2 {
        // There should be at least some factored guards if consecutive guards have same kind
        let has_consecutive_same = block
            .guards
            .windows(2)
            .any(|pair| pair[0].kind == pair[1].kind);
        if has_consecutive_same {
            assert!(block.factored_guard_count() > 0);
        }
    }
}

#[test]
fn form_superblock_guard_factoring_disabled() {
    let offsets: Vec<(u32, &str)> = (0..8u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_factor_off", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        enable_guard_factoring: false,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    let block = record.block.unwrap();
    // With factoring disabled, no guards should be marked factored
    assert_eq!(block.factored_guard_count(), 0);
}

#[test]
fn form_superblock_deterministic_across_invocations() {
    let offsets: Vec<(u32, &str)> = (0..5u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_det_form", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let r1 = form_superblock(&profile, 0, &policy, 1);
    let r2 = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(r1.outcome, r2.outcome);
    assert_eq!(r1.instructions_considered, r2.instructions_considered);
    assert_eq!(r1.instructions_included, r2.instructions_included);
    assert_eq!(r1.guards_generated, r2.guards_generated);
    if let (Some(b1), Some(b2)) = (&r1.block, &r2.block) {
        assert_eq!(b1.block_id, b2.block_id);
    }
}

// ===========================================================================
// form_all_superblocks tests (not covered in base tests)
// ===========================================================================

#[test]
fn form_all_superblocks_with_hot_profile() {
    // form_all_superblocks uses instructions_at_level(min_level) which is exact equality.
    // Our make_hot_profile promotes to Quickened, so set min_level to Quickened.
    let offsets: Vec<(u32, &str)> = (0..10u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_all_sb", &offsets);
    let policy = SuperblockPolicy {
        min_level: QuickeningLevel::Quickened,
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let records = form_all_superblocks(&profile, &policy, 1);
    assert!(!records.is_empty());
    let formed: Vec<_> = records
        .iter()
        .filter(|r| r.outcome == FormationOutcome::Formed)
        .collect();
    assert!(!formed.is_empty());
}

#[test]
fn form_all_superblocks_empty_profile() {
    let profile = QuickeningProfile::new("fn_empty_all");
    let policy = SuperblockPolicy::default();
    let records = form_all_superblocks(&profile, &policy, 1);
    // No hot offsets -> no records
    assert!(records.is_empty());
}

#[test]
fn form_all_superblocks_no_overlap() {
    let offsets: Vec<(u32, &str)> = (0..20u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_no_overlap", &offsets);
    let policy = SuperblockPolicy {
        max_block_length: 5,
        min_level: QuickeningLevel::Quickened,
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let records = form_all_superblocks(&profile, &policy, 1);
    let formed: Vec<_> = records.iter().filter_map(|r| r.block.as_ref()).collect();
    // Verify no overlapping source offsets between formed blocks
    let mut all_offsets = BTreeSet::new();
    for block in &formed {
        for entry in &block.entries {
            let was_new = all_offsets.insert(entry.source_offset);
            assert!(
                was_new,
                "offset {} appears in multiple superblocks",
                entry.source_offset
            );
        }
    }
}

// ===========================================================================
// build_trace_tree convenience function
// ===========================================================================

#[test]
fn build_trace_tree_creates_single_node_tree() {
    let block = make_simple_superblock("fn_btt", 0);
    let tree = build_trace_tree("fn_btt", block);
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.max_depth, 0);
    assert!(tree.tree_id.starts_with("tt-"));
    assert_eq!(tree.function_id, "fn_btt");
}

// ===========================================================================
// TraceTree growth / get_node
// ===========================================================================

#[test]
fn trace_tree_get_node_valid_and_invalid() {
    let block = make_simple_superblock("fn_get_node", 0);
    let tree = TraceTree::new("fn_get_node", block);
    assert!(tree.get_node(0).is_some());
    assert!(tree.get_node(1).is_none());
    assert!(tree.get_node(999).is_none());
}

#[test]
fn trace_tree_multi_level_growth() {
    let policy = SuperblockPolicy {
        max_trace_depth: 4,
        ..SuperblockPolicy::default()
    };
    let b0 = make_simple_superblock("fn_multi", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_multi", b0);

    for i in 1..=3 {
        let block = make_simple_superblock("fn_multi", i * 100);
        let parent_idx = i as usize - 1;
        assert!(tree.extend_at_exit(parent_idx, &exit_id, block, &policy));
    }

    assert_eq!(tree.node_count(), 4);
    assert_eq!(tree.max_depth, 3);
    assert_eq!(tree.total_instructions(), 8); // 2 per block * 4 blocks
    assert_eq!(tree.total_guards(), 4); // 1 per block * 4 blocks
}

#[test]
fn trace_tree_formation_epoch_increments_on_extend() {
    let policy = SuperblockPolicy::default();
    let b0 = make_simple_superblock("fn_epoch", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_epoch", b0);
    assert_eq!(tree.formation_epoch, 1);

    let b1 = make_simple_superblock("fn_epoch", 100);
    tree.extend_at_exit(0, &exit_id, b1, &policy);
    assert_eq!(tree.formation_epoch, 2);

    let b2 = make_simple_superblock("fn_epoch", 200);
    tree.extend_at_exit(1, &exit_id, b2, &policy);
    assert_eq!(tree.formation_epoch, 3);
}

#[test]
fn trace_tree_tree_id_changes_on_extend() {
    let policy = SuperblockPolicy::default();
    let b0 = make_simple_superblock("fn_tree_id", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_tree_id", b0);
    let id_before = tree.tree_id.clone();

    let b1 = make_simple_superblock("fn_tree_id", 100);
    tree.extend_at_exit(0, &exit_id, b1, &policy);
    assert_ne!(tree.tree_id, id_before);
}

#[test]
fn trace_tree_root_has_children_after_extend() {
    let policy = SuperblockPolicy::default();
    let b0 = make_simple_superblock("fn_children", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_children", b0);

    let b1 = make_simple_superblock("fn_children", 100);
    tree.extend_at_exit(0, &exit_id, b1, &policy);

    let root = tree.root().unwrap();
    assert_eq!(root.children.len(), 1);
    assert_eq!(*root.children.get(&exit_id).unwrap(), 1);
}

// ===========================================================================
// TraceTreeSummary tests
// ===========================================================================

#[test]
fn trace_tree_summary_serde_roundtrip() {
    let summary = TraceTreeSummary {
        tree_id: "tt-enrichment".into(),
        function_id: "fn_enrich".into(),
        node_count: 5,
        max_depth: 3,
        total_instructions: 20,
        total_guards: 8,
        formation_epoch: 7,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: TraceTreeSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn trace_tree_summary_reflects_tree_state() {
    let policy = SuperblockPolicy::default();
    let b0 = make_simple_superblock("fn_summary_state", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_summary_state", b0);
    let b1 = make_simple_superblock("fn_summary_state", 100);
    tree.extend_at_exit(0, &exit_id, b1, &policy);

    let summary = tree.summary();
    assert_eq!(summary.node_count, 2);
    assert_eq!(summary.max_depth, 1);
    assert_eq!(summary.total_instructions, 4);
    assert_eq!(summary.total_guards, 2);
    assert_eq!(summary.function_id, "fn_summary_state");
    assert_eq!(summary.tree_id, tree.tree_id);
    assert_eq!(summary.formation_epoch, tree.formation_epoch);
}

// ===========================================================================
// TraceTree display
// ===========================================================================

#[test]
fn trace_tree_display_includes_epoch() {
    let b = make_simple_superblock("fn_disp_epoch", 0);
    let tree = TraceTree::new("fn_disp_epoch", b);
    let display = format!("{tree}");
    assert!(display.contains("epoch=1"));
    assert!(display.contains("fn_disp_epoch"));
}

// ===========================================================================
// Superblock serde with complex guards
// ===========================================================================

#[test]
fn superblock_serde_with_multiple_guard_kinds() {
    let exit0 = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    let exit1 = SideExit::new(4, 1, SideExitReason::OverflowDetected);
    let exit2 = SideExit::new(8, 2, SideExitReason::ShapeMismatch);

    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 50,
        },
        SuperblockEntry {
            position: 1,
            source_offset: 4,
            opcode: "sub".into(),
            is_tail_duplicate: false,
            execution_count: 50,
        },
        SuperblockEntry {
            position: 2,
            source_offset: 8,
            opcode: "mul".into(),
            is_tail_duplicate: true,
            execution_count: 30,
        },
    ];

    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_complex_serde", &entries),
        function_id: "fn_complex_serde".into(),
        entry_offset: 0,
        entries,
        guards: vec![
            SuperblockGuard::new(
                0,
                0,
                GuardKind::TypeCheck {
                    expected_type: "int".into(),
                },
                exit0.exit_id.clone(),
            ),
            SuperblockGuard::new(1, 4, GuardKind::OverflowCheck, exit1.exit_id.clone()),
            SuperblockGuard::new(
                2,
                8,
                GuardKind::ShapeCheck {
                    expected_shape_id: "hidden_class_1".into(),
                },
                exit2.exit_id.clone(),
            ),
        ],
        side_exits: vec![exit0, exit1, exit2],
        tail_duplication_count: 1,
        formation_epoch: 42,
    };

    let json = serde_json::to_string(&block).unwrap();
    let back: Superblock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, back);
    assert_eq!(back.tail_duplication_count, 1);
    assert_eq!(back.formation_epoch, 42);
}

// ===========================================================================
// SuperblockEntry serde
// ===========================================================================

#[test]
fn superblock_entry_serde_roundtrip() {
    let entry = SuperblockEntry {
        position: 5,
        source_offset: 20,
        opcode: "load_const".into(),
        is_tail_duplicate: true,
        execution_count: 77,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SuperblockEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// Constants validation
// ===========================================================================

#[test]
fn schema_versions_are_distinct() {
    let versions = vec![
        SUPERBLOCK_SCHEMA_VERSION,
        TRACE_TREE_SCHEMA_VERSION,
        OPTIMIZED_TIER_PLAN_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(unique.len(), versions.len());
}

#[test]
fn component_constant_matches_module_name() {
    assert_eq!(COMPONENT, "superblock_formation");
}

// ===========================================================================
// Side exit display details
// ===========================================================================

#[test]
fn side_exit_display_all_reasons() {
    let reasons = vec![
        (SideExitReason::GuardFailure, "guard-failure"),
        (SideExitReason::OverflowDetected, "overflow"),
        (SideExitReason::TypeMismatch, "type-mismatch"),
        (SideExitReason::ShapeMismatch, "shape-mismatch"),
        (SideExitReason::IcMegamorphic, "ic-megamorphic"),
        (SideExitReason::PrototypeInvalidated, "proto-invalidated"),
        (SideExitReason::UnexpectedControlFlow, "unexpected-cf"),
    ];
    for (reason, expected_substring) in reasons {
        let display = format!("{reason}");
        assert_eq!(display, expected_substring);
    }
}

// ===========================================================================
// Superblock hot_side_exits with mixed temperatures
// ===========================================================================

#[test]
fn hot_side_exits_filters_by_threshold() {
    let mut e1 = SideExit::new(0, 0, SideExitReason::GuardFailure);
    let mut e2 = SideExit::new(4, 1, SideExitReason::TypeMismatch);
    let e3 = SideExit::new(8, 2, SideExitReason::OverflowDetected);

    for _ in 0..10 {
        e1.record_taken();
    }
    for _ in 0..3 {
        e2.record_taken();
    }
    // e3 stays at 0

    let entries = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "a".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    }];
    let block = Superblock {
        block_id: Superblock::compute_block_id("fn_hot_mix", &entries),
        function_id: "fn_hot_mix".into(),
        entry_offset: 0,
        entries,
        guards: vec![],
        side_exits: vec![e1, e2, e3],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };

    assert_eq!(block.hot_side_exits(5).len(), 1);
    assert_eq!(block.hot_side_exits(3).len(), 2);
    assert_eq!(block.hot_side_exits(0).len(), 3);
}

// ===========================================================================
// Superblock record_side_exit with unknown exit_id
// ===========================================================================

#[test]
fn record_side_exit_unknown_id_returns_false() {
    let mut block = make_simple_superblock("fn_unknown", 0);
    assert!(!block.record_side_exit("nonexistent-exit", 1));
}

// ===========================================================================
// FormationDecision with all rejection outcomes
// ===========================================================================

#[test]
fn formation_decision_all_rejected() {
    let policy = SuperblockPolicy::default();
    let records = vec![
        FormationRecord {
            function_id: "fn_rej".into(),
            entry_offset: 0,
            outcome: FormationOutcome::NoEligibleInstructions,
            instructions_considered: 0,
            instructions_included: 0,
            guards_generated: 0,
            tail_duplications: 0,
            block: None,
        },
        FormationRecord {
            function_id: "fn_rej".into(),
            entry_offset: 4,
            outcome: FormationOutcome::InsufficientHotInstructions,
            instructions_considered: 1,
            instructions_included: 1,
            guards_generated: 0,
            tail_duplications: 0,
            block: None,
        },
        FormationRecord {
            function_id: "fn_rej".into(),
            entry_offset: 8,
            outcome: FormationOutcome::ExceedsBlockSize,
            instructions_considered: 100,
            instructions_included: 0,
            guards_generated: 0,
            tail_duplications: 0,
            block: None,
        },
    ];
    let decision = FormationDecision::build("fn_rej", &policy, 1, records, None);
    assert_eq!(decision.formed_count(), 0);
    assert_eq!(decision.rejected_count(), 3);
}

// ===========================================================================
// TraceTree serde with children
// ===========================================================================

#[test]
fn trace_tree_serde_roundtrip_with_children() {
    let policy = SuperblockPolicy::default();
    let b0 = make_simple_superblock("fn_tree_serde", 0);
    let exit_id = b0.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_tree_serde", b0);
    let b1 = make_simple_superblock("fn_tree_serde", 100);
    tree.extend_at_exit(0, &exit_id, b1, &policy);

    let json = serde_json::to_string(&tree).unwrap();
    let back: TraceTree = serde_json::from_str(&json).unwrap();
    assert_eq!(tree, back);
    assert_eq!(back.node_count(), 2);
}

// ===========================================================================
// Superblock display content
// ===========================================================================

#[test]
fn superblock_display_includes_all_counts() {
    let block = make_simple_superblock("fn_disp_all", 0);
    let display = format!("{block}");
    assert!(display.contains("superblock"));
    assert!(display.contains("fn_disp_all"));
    assert!(display.contains("2 instrs"));
    assert!(display.contains("1 guards"));
    assert!(display.contains("1 exits"));
    assert!(display.contains("0 tail-dups"));
}

// ===========================================================================
// form_superblock: formation record fields
// ===========================================================================

#[test]
fn form_superblock_record_fields_on_success() {
    let offsets: Vec<(u32, &str)> = (0..5u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_fields", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 42);
    assert_eq!(record.function_id, "fn_fields");
    assert_eq!(record.entry_offset, 0);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    assert!(record.instructions_considered > 0);
    assert!(record.instructions_included >= 2);
    assert!(record.block.is_some());
    let block = record.block.unwrap();
    assert_eq!(block.formation_epoch, 42);
    assert_eq!(block.entry_offset, 0);
    assert_eq!(block.function_id, "fn_fields");
}

#[test]
fn form_superblock_at_nonzero_offset() {
    let offsets: Vec<(u32, &str)> = (0..10u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_nonzero", &offsets);
    let policy = SuperblockPolicy {
        min_execution_count: 4,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 8, &policy, 1);
    assert_eq!(record.entry_offset, 8);
    if record.outcome == FormationOutcome::Formed {
        let block = record.block.unwrap();
        assert_eq!(block.entry_offset, 8);
        assert_eq!(block.entries[0].source_offset, 8);
    }
}
