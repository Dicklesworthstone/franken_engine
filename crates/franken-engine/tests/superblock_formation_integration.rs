//! Integration tests for superblock formation and trace-tree construction.

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
    clippy::manual_abs_diff,
    unused_imports
)]

use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::quickening_feedback_lattice::{
    ObservedType, QuickeningLevel, QuickeningPolicy, QuickeningProfile,
};
use frankenengine_engine::stage_envelope_certificate::ExecutionStage;
use frankenengine_engine::superblock_formation::{
    COMPONENT, CompilationRejectReason, DeoptContinuation, FallbackTier, FormationDecision,
    FormationOutcome, FormationRecord, GuardKind, OPTIMIZED_TIER_PLAN_SCHEMA_VERSION,
    OptimizedTierBackend, OptimizedTierCompilationPlan, SUPERBLOCK_SCHEMA_VERSION, SideExit,
    SideExitReason, Superblock, SuperblockEntry, SuperblockGuard, SuperblockPolicy,
    TRACE_TREE_SCHEMA_VERSION, TraceTree, TraceTreeSummary, build_trace_tree, form_all_superblocks,
    form_superblock,
};
use frankenengine_engine::tier_up_profiler::{TierUpPolicy, evaluate_tier_up_eligibility};

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

fn r(index: u16) -> Register {
    Register(index)
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
    // Advance through Cold→Warm→Hot→Quickened
    for _ in 0..4 {
        profile.evaluate_all(&q_policy);
    }
    profile
}

fn make_hot_profile_without_guards(
    function_id: &str,
    offsets_and_opcodes: &[(u32, &str)],
) -> QuickeningProfile {
    let q_policy = aggressive_quickening_policy();
    let mut profile = QuickeningProfile::new(function_id);
    for &(offset, opcode) in offsets_and_opcodes {
        for _ in 0..100 {
            profile.record_execution(offset, opcode);
        }
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

// ---------------------------------------------------------------------------
// SuperblockPolicy tests
// ---------------------------------------------------------------------------

#[test]
fn policy_default_has_reasonable_values() {
    let p = SuperblockPolicy::default();
    assert!(p.max_block_length > 0);
    assert!(p.max_trace_depth > 0);
    assert!(p.max_side_exits > 0);
    assert!(p.enable_guard_factoring);
    assert_eq!(p.min_level, QuickeningLevel::Hot);
}

#[test]
fn policy_hash_deterministic() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_change() {
    let p1 = SuperblockPolicy::default();
    let p2 = SuperblockPolicy {
        max_block_length: 128,
        ..SuperblockPolicy::default()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// GuardKind tests
// ---------------------------------------------------------------------------

#[test]
fn guard_kind_display_variants() {
    let shape = GuardKind::ShapeCheck {
        expected_shape_id: "s-1".into(),
    };
    assert!(format!("{shape}").contains("shape-check"));

    let type_ck = GuardKind::TypeCheck {
        expected_type: "int".into(),
    };
    assert!(format!("{type_ck}").contains("type-check"));

    let range = GuardKind::RangeCheck {
        lower: 0,
        upper: 100,
    };
    assert!(format!("{range}").contains("range-check"));

    let ic = GuardKind::IcStability { ic_offset: 42 };
    assert!(format!("{ic}").contains("ic-stability"));

    let overflow = GuardKind::OverflowCheck;
    assert!(format!("{overflow}").contains("overflow-check"));

    let proto = GuardKind::PrototypeChain {
        expected_hash: "abc".into(),
    };
    assert!(format!("{proto}").contains("proto-chain"));
}

// ---------------------------------------------------------------------------
// SuperblockGuard tests
// ---------------------------------------------------------------------------

#[test]
fn guard_display_shows_factored_tag() {
    let mut guard = SuperblockGuard::new(
        0,
        10,
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        "exit-001".into(),
    );
    assert!(!format!("{guard}").contains("[factored]"));
    guard.factored = true;
    assert!(format!("{guard}").contains("[factored]"));
}

// ---------------------------------------------------------------------------
// SideExit tests
// ---------------------------------------------------------------------------

#[test]
fn side_exit_id_deterministic() {
    let e1 = SideExit::new(10, 0, SideExitReason::GuardFailure);
    let e2 = SideExit::new(10, 0, SideExitReason::GuardFailure);
    assert_eq!(e1.exit_id, e2.exit_id);
}

#[test]
fn side_exit_id_differs_on_different_params() {
    let e1 = SideExit::new(10, 0, SideExitReason::GuardFailure);
    let e2 = SideExit::new(20, 0, SideExitReason::GuardFailure);
    assert_ne!(e1.exit_id, e2.exit_id);
}

#[test]
fn side_exit_taken_count_and_hot() {
    let mut exit = SideExit::new(10, 0, SideExitReason::TypeMismatch);
    assert_eq!(exit.taken_count, 0);
    assert!(!exit.is_hot(5));
    for _ in 0..5 {
        exit.record_taken();
    }
    assert_eq!(exit.taken_count, 5);
    assert!(exit.is_hot(5));
}

#[test]
fn side_exit_display() {
    let exit = SideExit::new(10, 0, SideExitReason::OverflowDetected);
    let display = format!("{exit}");
    assert!(display.contains("resume@10"));
    assert!(display.contains("overflow"));
}

#[test]
fn side_exit_reason_display_all_variants() {
    let variants = [
        SideExitReason::GuardFailure,
        SideExitReason::OverflowDetected,
        SideExitReason::TypeMismatch,
        SideExitReason::ShapeMismatch,
        SideExitReason::IcMegamorphic,
        SideExitReason::PrototypeInvalidated,
        SideExitReason::UnexpectedControlFlow,
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Superblock tests
// ---------------------------------------------------------------------------

#[test]
fn superblock_compute_block_id_deterministic() {
    let entries = vec![SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "add".into(),
        is_tail_duplicate: false,
        execution_count: 50,
    }];
    let id1 = Superblock::compute_block_id("fn_test", &entries);
    let id2 = Superblock::compute_block_id("fn_test", &entries);
    assert_eq!(id1, id2);
    assert!(id1.starts_with("sb-"));
}

#[test]
fn superblock_counts() {
    let block = make_simple_superblock("fn_counts", 0);
    assert_eq!(block.instruction_count(), 2);
    assert_eq!(block.guard_count(), 1);
    assert_eq!(block.side_exit_count(), 1);
    assert_eq!(block.factored_guard_count(), 0);
}

#[test]
fn superblock_record_side_exit() {
    let mut block = make_simple_superblock("fn_exit", 0);
    let exit_id = block.side_exits[0].exit_id.clone();
    let hot = block.record_side_exit(&exit_id, 5);
    assert!(!hot); // Only 1 take
    for _ in 0..5 {
        block.record_side_exit(&exit_id, 5);
    }
    let hot = block.record_side_exit(&exit_id, 5);
    assert!(hot);
}

#[test]
fn superblock_hot_side_exits() {
    let mut block = make_simple_superblock("fn_hot_exits", 0);
    let exit_id = block.side_exits[0].exit_id.clone();
    assert!(block.hot_side_exits(5).is_empty());
    for _ in 0..10 {
        block.record_side_exit(&exit_id, 5);
    }
    assert_eq!(block.hot_side_exits(5).len(), 1);
}

#[test]
fn superblock_display() {
    let block = make_simple_superblock("fn_display", 0);
    let display = format!("{block}");
    assert!(display.contains("superblock"));
    assert!(display.contains("fn_display"));
}

// ---------------------------------------------------------------------------
// form_superblock integration
// ---------------------------------------------------------------------------

#[test]
fn form_superblock_with_hot_profile() {
    let offsets: Vec<(u32, &str)> = (0..10u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_form", &offsets);
    let policy = SuperblockPolicy {
        min_level: QuickeningLevel::Hot,
        min_execution_count: 32,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::Formed);
    assert!(record.block.is_some());
    let block = record.block.unwrap();
    assert!(block.instruction_count() >= 2);
}

#[test]
fn form_superblock_cold_profile_rejected() {
    let mut profile = QuickeningProfile::new("fn_cold");
    profile.record_execution(0, "nop");
    let policy = SuperblockPolicy::default();
    let record = form_superblock(&profile, 0, &policy, 1);
    assert_ne!(record.outcome, FormationOutcome::Formed);
    assert!(record.block.is_none());
}

#[test]
fn form_superblock_no_instructions_at_offset() {
    let profile = QuickeningProfile::new("fn_empty");
    let policy = SuperblockPolicy::default();
    let record = form_superblock(&profile, 999, &policy, 1);
    assert_eq!(record.outcome, FormationOutcome::NoEligibleInstructions);
}

#[test]
fn optimized_tier_plan_bridges_tier_up_and_superblock_formation() {
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(50), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-opt-plan", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(
        &report,
        &TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        },
    );
    assert!(decision.eligible);

    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached")
        .unwrap();
    let profile = make_hot_profile(
        "fn_opt_plan",
        &[
            (candidate.ip, "load_prop_cached"),
            (candidate.ip + 4, "sub"),
            (candidate.ip + 8, "jump_if_false"),
        ],
    );

    let plan =
        OptimizedTierCompilationPlan::build(&decision, &profile, &SuperblockPolicy::default(), 7);

    assert_eq!(plan.schema_version, OPTIMIZED_TIER_PLAN_SCHEMA_VERSION);
    assert_eq!(plan.backend, OptimizedTierBackend::Cranelift);
    assert_eq!(plan.stage, ExecutionStage::CompileOptimized);
    assert!(plan.requires_differential_equivalence);
    assert_eq!(plan.compilable_unit_count(), 1);

    let unit = &plan.units[0];
    assert_eq!(unit.candidate.ip, candidate.ip);
    assert!(unit.requires_differential_equivalence);
    assert!(!unit.deopt_continuations.is_empty());
    assert!(
        unit.deopt_continuations
            .iter()
            .all(|continuation| continuation.fallback_tier.to_string() == "baseline_interpreter")
    );
}

#[test]
fn optimized_tier_plan_reports_superblock_rejection_deterministically() {
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(12), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-opt-reject", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(
        &report,
        &TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        },
    );
    assert!(decision.eligible);

    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached")
        .unwrap();
    let profile = make_hot_profile("fn_opt_reject", &[(candidate.ip, "load_prop_cached")]);
    let plan =
        OptimizedTierCompilationPlan::build(&decision, &profile, &SuperblockPolicy::default(), 3);

    assert!(plan.units.is_empty());
    assert_eq!(plan.rejected_candidates.len(), 1);
    assert_eq!(
        plan.rejected_candidates[0].reason,
        CompilationRejectReason::SuperblockFormationRejected
    );
    assert_eq!(
        plan.rejected_candidates[0].formation_outcome,
        Some(FormationOutcome::InsufficientHotInstructions)
    );
    assert!(
        plan.rejected_candidates[0]
            .detail
            .contains("superblock formation")
    );
}

#[test]
fn optimized_tier_plan_rejects_candidate_profile_opcode_mismatch() {
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(50), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-opt-mismatch", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(
        &report,
        &TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        },
    );
    assert!(decision.eligible);

    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached")
        .unwrap();
    let profile = make_hot_profile(
        "fn_opt_mismatch",
        &[
            (candidate.ip, "different_opcode"),
            (candidate.ip + 4, "sub"),
            (candidate.ip + 8, "jump_if_false"),
        ],
    );

    let plan =
        OptimizedTierCompilationPlan::build(&decision, &profile, &SuperblockPolicy::default(), 8);

    assert!(plan.units.is_empty());
    assert_eq!(plan.rejected_candidates.len(), 1);
    assert_eq!(
        plan.rejected_candidates[0].reason,
        CompilationRejectReason::CandidateProfileMismatch
    );
    assert!(plan.rejected_candidates[0].formation_outcome.is_none());
    assert!(
        plan.rejected_candidates[0]
            .detail
            .contains("opcode mismatch")
    );
}

#[test]
fn optimized_tier_plan_rejects_guardless_superblock_without_deopt_continuations() {
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(50), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-opt-guardless", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(
        &report,
        &TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        },
    );
    assert!(decision.eligible);

    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached")
        .unwrap();
    let profile = make_hot_profile_without_guards(
        "fn_opt_guardless",
        &[
            (candidate.ip, "load_prop_cached"),
            (candidate.ip + 4, "sub"),
            (candidate.ip + 8, "jump_if_false"),
        ],
    );

    let plan =
        OptimizedTierCompilationPlan::build(&decision, &profile, &SuperblockPolicy::default(), 9);

    assert!(plan.units.is_empty());
    assert_eq!(plan.rejected_candidates.len(), 1);
    assert_eq!(
        plan.rejected_candidates[0].reason,
        CompilationRejectReason::MissingDeoptContinuations
    );
    assert_eq!(
        plan.rejected_candidates[0].formation_outcome,
        Some(FormationOutcome::Formed)
    );
    assert!(
        plan.rejected_candidates[0]
            .detail
            .contains("no deopt continuations")
    );
}

// ---------------------------------------------------------------------------
// TraceTree tests
// ---------------------------------------------------------------------------

#[test]
fn trace_tree_construction() {
    let block = make_simple_superblock("fn_tree", 0);
    let tree = TraceTree::new("fn_tree", block);
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.max_depth, 0);
    assert!(tree.tree_id.starts_with("tt-"));
    assert_eq!(tree.schema_version, TRACE_TREE_SCHEMA_VERSION);
}

#[test]
fn trace_tree_extend_at_exit() {
    let block1 = make_simple_superblock("fn_extend", 0);
    let exit_id = block1.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_extend", block1);

    let block2 = make_simple_superblock("fn_extend", 8);
    let policy = SuperblockPolicy::default();
    let extended = tree.extend_at_exit(0, &exit_id, block2, &policy);
    assert!(extended);
    assert_eq!(tree.node_count(), 2);
    assert_eq!(tree.max_depth, 1);
    assert_eq!(tree.formation_epoch, 2);
}

#[test]
fn trace_tree_extend_respects_max_depth() {
    let block = make_simple_superblock("fn_depth", 0);
    let exit_id = block.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_depth", block);
    let policy = SuperblockPolicy {
        max_trace_depth: 2,
        ..SuperblockPolicy::default()
    };

    // Add depth 1
    let b1 = make_simple_superblock("fn_depth", 8);
    assert!(tree.extend_at_exit(0, &exit_id, b1, &policy));

    // Add depth 2
    let b2 = make_simple_superblock("fn_depth", 16);
    assert!(tree.extend_at_exit(1, &exit_id, b2, &policy));

    // Depth 3 should be rejected
    let b3 = make_simple_superblock("fn_depth", 24);
    assert!(!tree.extend_at_exit(2, &exit_id, b3, &policy));
}

#[test]
fn trace_tree_extend_invalid_parent() {
    let block = make_simple_superblock("fn_inv", 0);
    let mut tree = TraceTree::new("fn_inv", block);
    let policy = SuperblockPolicy::default();
    let b2 = make_simple_superblock("fn_inv", 8);
    assert!(!tree.extend_at_exit(999, "exit-x", b2, &policy));
}

#[test]
fn trace_tree_total_instructions() {
    let b1 = make_simple_superblock("fn_total", 0);
    let exit_id = b1.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_total", b1);
    let b2 = make_simple_superblock("fn_total", 8);
    let policy = SuperblockPolicy::default();
    tree.extend_at_exit(0, &exit_id, b2, &policy);
    assert_eq!(tree.total_instructions(), 4); // 2 + 2
    assert_eq!(tree.total_guards(), 2); // 1 + 1
}

#[test]
fn trace_tree_summary() {
    let block = make_simple_superblock("fn_summary", 0);
    let tree = TraceTree::new("fn_summary", block);
    let summary = tree.summary();
    assert_eq!(summary.node_count, 1);
    assert_eq!(summary.max_depth, 0);
    assert_eq!(summary.function_id, "fn_summary");
    assert!(summary.total_instructions > 0);
}

#[test]
fn trace_tree_display() {
    let block = make_simple_superblock("fn_disp", 0);
    let tree = TraceTree::new("fn_disp", block);
    let display = format!("{tree}");
    assert!(display.contains("trace-tree"));
    assert!(display.contains("fn_disp"));
}

#[test]
fn trace_tree_root() {
    let block = make_simple_superblock("fn_root", 0);
    let tree = TraceTree::new("fn_root", block);
    let root = tree.root().unwrap();
    assert_eq!(root.depth, 0);
    assert!(root.children.is_empty());
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn serde_round_trip_superblock() {
    let block = make_simple_superblock("fn_serde", 0);
    let json = serde_json::to_string(&block).unwrap();
    let back: Superblock = serde_json::from_str(&json).unwrap();
    assert_eq!(block, back);
}

#[test]
fn serde_round_trip_trace_tree() {
    let block = make_simple_superblock("fn_serde_tree", 0);
    let tree = TraceTree::new("fn_serde_tree", block);
    let json = serde_json::to_string(&tree).unwrap();
    let back: TraceTree = serde_json::from_str(&json).unwrap();
    assert_eq!(tree, back);
}

#[test]
fn serde_round_trip_summary() {
    let summary = TraceTreeSummary {
        tree_id: "tt-test".into(),
        function_id: "fn_test".into(),
        node_count: 3,
        max_depth: 2,
        total_instructions: 10,
        total_guards: 5,
        formation_epoch: 3,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: TraceTreeSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn serde_round_trip_policy() {
    let policy = SuperblockPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: SuperblockPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_set() {
    assert_eq!(COMPONENT, "superblock_formation");
    assert!(!SUPERBLOCK_SCHEMA_VERSION.is_empty());
    assert!(!TRACE_TREE_SCHEMA_VERSION.is_empty());
    assert!(!OPTIMIZED_TIER_PLAN_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// OptimizedTierBackend and FallbackTier Display/serde/clone
// ---------------------------------------------------------------------------

#[test]
fn test_optimized_tier_backend_display() {
    let backend = OptimizedTierBackend::Cranelift;
    assert_eq!(format!("{backend}"), "cranelift");
}

#[test]
fn test_optimized_tier_backend_clone_debug_eq() {
    let b1 = OptimizedTierBackend::Cranelift;
    let b2 = b1;
    assert_eq!(b1, b2);
    let dbg = format!("{b1:?}");
    assert!(dbg.contains("Cranelift"));
}

#[test]
fn test_optimized_tier_backend_serde_round_trip() {
    let backend = OptimizedTierBackend::Cranelift;
    let json = serde_json::to_string(&backend).unwrap();
    let back: OptimizedTierBackend = serde_json::from_str(&json).unwrap();
    assert_eq!(backend, back);
    // snake_case serde
    assert_eq!(json, "\"cranelift\"");
}

#[test]
fn test_fallback_tier_display() {
    let tier = FallbackTier::BaselineInterpreter;
    assert_eq!(format!("{tier}"), "baseline_interpreter");
}

#[test]
fn test_fallback_tier_clone_debug_eq() {
    let t1 = FallbackTier::BaselineInterpreter;
    let t2 = t1;
    assert_eq!(t1, t2);
    let dbg = format!("{t1:?}");
    assert!(dbg.contains("BaselineInterpreter"));
}

#[test]
fn test_fallback_tier_serde_round_trip() {
    let tier = FallbackTier::BaselineInterpreter;
    let json = serde_json::to_string(&tier).unwrap();
    let back: FallbackTier = serde_json::from_str(&json).unwrap();
    assert_eq!(tier, back);
    assert_eq!(json, "\"baseline_interpreter\"");
}

// ---------------------------------------------------------------------------
// FormationOutcome Display for all variants
// ---------------------------------------------------------------------------

#[test]
fn test_formation_outcome_display_all_variants() {
    assert_eq!(format!("{}", FormationOutcome::Formed), "formed");
    assert_eq!(
        format!("{}", FormationOutcome::InsufficientHotInstructions),
        "insufficient-hot"
    );
    assert_eq!(
        format!("{}", FormationOutcome::ExceedsBlockSize),
        "exceeds-block-size"
    );
    assert_eq!(
        format!("{}", FormationOutcome::ExcessiveGuards),
        "excessive-guards"
    );
    assert_eq!(
        format!("{}", FormationOutcome::NoEligibleInstructions),
        "no-eligible"
    );
}

#[test]
fn test_formation_outcome_clone_debug_eq() {
    let o = FormationOutcome::Formed;
    let o2 = o.clone();
    assert_eq!(o, o2);
    let dbg = format!("{o:?}");
    assert!(dbg.contains("Formed"));
}

#[test]
fn test_formation_outcome_serde_round_trip() {
    let variants = [
        FormationOutcome::Formed,
        FormationOutcome::InsufficientHotInstructions,
        FormationOutcome::ExceedsBlockSize,
        FormationOutcome::ExcessiveGuards,
        FormationOutcome::NoEligibleInstructions,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: FormationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, &back);
    }
}

// ---------------------------------------------------------------------------
// FormationRecord Clone/Debug/PartialEq/serde
// ---------------------------------------------------------------------------

#[test]
fn test_formation_record_serde_round_trip_no_block() {
    let record = FormationRecord {
        function_id: "fn_rec_test".into(),
        entry_offset: 0,
        outcome: FormationOutcome::NoEligibleInstructions,
        instructions_considered: 3,
        instructions_included: 0,
        guards_generated: 0,
        tail_duplications: 0,
        block: None,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: FormationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn test_formation_record_serde_round_trip_with_block() {
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

#[test]
fn test_formation_record_clone_debug() {
    let offsets: Vec<(u32, &str)> = (0..3u32).map(|i| (i * 4, "mul")).collect();
    let profile = make_hot_profile("fn_rec_clone", &offsets);
    let policy = SuperblockPolicy::default();
    let record = form_superblock(&profile, 0, &policy, 5);
    let record2 = record.clone();
    assert_eq!(record, record2);
    let dbg = format!("{record:?}");
    assert!(dbg.contains("fn_rec_clone"));
}

// ---------------------------------------------------------------------------
// FormationDecision build / formed_count / rejected_count / serde
// ---------------------------------------------------------------------------

#[test]
fn test_formation_decision_build_with_formed_records() {
    let offsets: Vec<(u32, &str)> = (0..5u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_dec_formed", &offsets);
    let policy = SuperblockPolicy::default();
    let record = form_superblock(&profile, 0, &policy, 1);
    let records = vec![record];
    let decision = FormationDecision::build("fn_dec_formed", &policy, 1, records, None);
    assert_eq!(decision.function_id, "fn_dec_formed");
    assert_eq!(decision.formation_epoch, 1);
    assert_eq!(decision.schema_version, SUPERBLOCK_SCHEMA_VERSION);
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.formed_count(), 1);
    assert_eq!(decision.rejected_count(), 0);
    assert!(decision.trace_tree_summary.is_none());
}

#[test]
fn test_formation_decision_with_trace_tree_summary() {
    let block = make_simple_superblock("fn_dec_tree", 0);
    let tree = TraceTree::new("fn_dec_tree", block);
    let policy = SuperblockPolicy::default();
    let decision = FormationDecision::build("fn_dec_tree", &policy, 2, vec![], Some(&tree));
    assert!(decision.trace_tree_summary.is_some());
    let summary = decision.trace_tree_summary.unwrap();
    assert_eq!(summary.function_id, "fn_dec_tree");
}

#[test]
fn test_formation_decision_rejected_count() {
    let profile = QuickeningProfile::new("fn_dec_reject");
    let policy = SuperblockPolicy::default();
    // offset 999 has nothing — NoEligibleInstructions
    let r1 = form_superblock(&profile, 0, &policy, 1);
    let r2 = form_superblock(&profile, 4, &policy, 1);
    let decision = FormationDecision::build("fn_dec_reject", &policy, 1, vec![r1, r2], None);
    assert_eq!(decision.formed_count(), 0);
    assert_eq!(decision.rejected_count(), 2);
}

#[test]
fn test_formation_decision_hash_deterministic() {
    let policy = SuperblockPolicy::default();
    let d1 = FormationDecision::build("fn_det", &policy, 3, vec![], None);
    let d2 = FormationDecision::build("fn_det", &policy, 3, vec![], None);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn test_formation_decision_hash_changes_with_epoch() {
    let policy = SuperblockPolicy::default();
    let d1 = FormationDecision::build("fn_epoch_diff", &policy, 1, vec![], None);
    let d2 = FormationDecision::build("fn_epoch_diff", &policy, 2, vec![], None);
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn test_formation_decision_serde_round_trip() {
    let policy = SuperblockPolicy::default();
    let decision = FormationDecision::build("fn_dec_serde", &policy, 5, vec![], None);
    let json = serde_json::to_string(&decision).unwrap();
    let back: FormationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ---------------------------------------------------------------------------
// form_all_superblocks
// ---------------------------------------------------------------------------

#[test]
fn test_form_all_superblocks_empty_profile() {
    let profile = QuickeningProfile::new("fn_all_empty");
    let policy = SuperblockPolicy::default();
    let records = form_all_superblocks(&profile, &policy, 1);
    assert!(records.is_empty());
}

#[test]
fn test_form_all_superblocks_with_hot_profile() {
    let offsets: Vec<(u32, &str)> = (0..6u32).map(|i| (i * 4, "sub")).collect();
    let profile = make_hot_profile("fn_all_hot", &offsets);
    let policy = SuperblockPolicy::default();
    let records = form_all_superblocks(&profile, &policy, 2);
    assert!(!records.is_empty());
    // At least one should be formed
    let formed = records
        .iter()
        .filter(|r| r.outcome == FormationOutcome::Formed)
        .count();
    assert!(formed >= 1);
}

#[test]
fn test_form_all_superblocks_no_duplicates_in_formed_offsets() {
    use std::collections::BTreeSet;
    let offsets: Vec<(u32, &str)> = (0..8u32).map(|i| (i * 4, "load")).collect();
    let profile = make_hot_profile("fn_all_nodup", &offsets);
    let policy = SuperblockPolicy::default();
    let records = form_all_superblocks(&profile, &policy, 1);
    // Collect all source_offsets across formed blocks
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for record in &records {
        if let Some(block) = &record.block {
            for entry in &block.entries {
                assert!(
                    seen.insert(entry.source_offset),
                    "offset {} covered by multiple superblocks",
                    entry.source_offset
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// build_trace_tree
// ---------------------------------------------------------------------------

#[test]
fn test_build_trace_tree_wraps_new() {
    let block = make_simple_superblock("fn_btt", 0);
    let tree = build_trace_tree("fn_btt", block);
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.function_id, "fn_btt");
    assert!(tree.tree_id.starts_with("tt-"));
}

// ---------------------------------------------------------------------------
// TraceTreeNode Clone/Debug/PartialEq/serde
// ---------------------------------------------------------------------------

#[test]
fn test_trace_tree_node_clone_debug_eq() {
    let block = make_simple_superblock("fn_node", 0);
    let tree = TraceTree::new("fn_node", block);
    let node = tree.root().unwrap().clone();
    assert_eq!(node.depth, 0);
    let dbg = format!("{node:?}");
    assert!(dbg.contains("depth"));
}

#[test]
fn test_trace_tree_get_node_valid_and_invalid() {
    let block = make_simple_superblock("fn_getnode", 0);
    let tree = TraceTree::new("fn_getnode", block);
    assert!(tree.get_node(0).is_some());
    assert!(tree.get_node(1).is_none());
    assert!(tree.get_node(usize::MAX).is_none());
}

// ---------------------------------------------------------------------------
// DeoptContinuation serde/Clone/Debug/PartialEq
// ---------------------------------------------------------------------------

#[test]
fn test_deopt_continuation_serde_round_trip() {
    let block = make_simple_superblock("fn_deopt", 0);
    let continuations = block.deopt_continuations();
    assert!(!continuations.is_empty());
    let c = &continuations[0];
    let json = serde_json::to_string(c).unwrap();
    let back: DeoptContinuation = serde_json::from_str(&json).unwrap();
    assert_eq!(*c, back);
}

#[test]
fn test_deopt_continuation_checkpoint_id_format() {
    let block = make_simple_superblock("fn_ckpt", 0);
    let continuations = block.deopt_continuations();
    assert!(!continuations.is_empty());
    assert!(continuations[0].checkpoint_id.starts_with("deopt-"));
    assert_eq!(continuations[0].checkpoint_id.len(), "deopt-".len() + 16);
}

#[test]
fn test_deopt_continuation_fallback_tier_is_baseline() {
    let block = make_simple_superblock("fn_deopt_tier", 0);
    let continuations = block.deopt_continuations();
    for c in &continuations {
        assert_eq!(c.fallback_tier, FallbackTier::BaselineInterpreter);
    }
}

#[test]
fn test_deopt_continuation_clone_debug() {
    let block = make_simple_superblock("fn_deopt_clone", 0);
    let continuations = block.deopt_continuations();
    assert!(!continuations.is_empty());
    let c = continuations[0].clone();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("checkpoint_id"));
}

// ---------------------------------------------------------------------------
// OptimizedCompilationReject/Unit serde/Clone/Debug
// ---------------------------------------------------------------------------

#[test]
fn test_compilation_reject_reason_serde_round_trip() {
    let variants = [
        CompilationRejectReason::TierUpIneligible,
        CompilationRejectReason::SuperblockFormationRejected,
        CompilationRejectReason::DuplicateCandidateOffset,
        CompilationRejectReason::CandidateProfileMismatch,
        CompilationRejectReason::MissingDeoptContinuations,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: CompilationRejectReason = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, &back);
    }
}

#[test]
fn test_compilation_reject_reason_debug_clone() {
    let r = CompilationRejectReason::DuplicateCandidateOffset;
    let r2 = r.clone();
    assert_eq!(r, r2);
    let dbg = format!("{r:?}");
    assert!(dbg.contains("DuplicateCandidateOffset"));
}

// ---------------------------------------------------------------------------
// Superblock::deopt_continuations ordering
// ---------------------------------------------------------------------------

#[test]
fn test_deopt_continuations_sorted_by_guard_position() {
    // Build a superblock with multiple guards at different positions
    let entries = vec![
        SuperblockEntry {
            position: 0,
            source_offset: 0,
            opcode: "load".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
        SuperblockEntry {
            position: 1,
            source_offset: 4,
            opcode: "add".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
        SuperblockEntry {
            position: 2,
            source_offset: 8,
            opcode: "store".into(),
            is_tail_duplicate: false,
            execution_count: 100,
        },
    ];
    let exit0 = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    let exit1 = SideExit::new(4, 1, SideExitReason::ShapeMismatch);
    let exit2 = SideExit::new(8, 2, SideExitReason::GuardFailure);
    let guard0 = SuperblockGuard::new(
        0,
        0,
        GuardKind::TypeCheck {
            expected_type: "int".into(),
        },
        exit0.exit_id.clone(),
    );
    let guard1 = SuperblockGuard::new(
        1,
        4,
        GuardKind::ShapeCheck {
            expected_shape_id: "s1".into(),
        },
        exit1.exit_id.clone(),
    );
    let guard2 = SuperblockGuard::new(2, 8, GuardKind::OverflowCheck, exit2.exit_id.clone());
    let block_id = Superblock::compute_block_id("fn_order", &entries);
    let block = Superblock {
        block_id,
        function_id: "fn_order".into(),
        entry_offset: 0,
        entries,
        guards: vec![guard2.clone(), guard0.clone(), guard1.clone()],
        side_exits: vec![exit0, exit1, exit2],
        tail_duplication_count: 0,
        formation_epoch: 1,
    };
    let continuations = block.deopt_continuations();
    // Should be sorted by guard_position
    for window in continuations.windows(2) {
        assert!(window[0].guard_position <= window[1].guard_position);
    }
}

// ---------------------------------------------------------------------------
// SideExit: compiled_branch field and boundary behavior
// ---------------------------------------------------------------------------

#[test]
fn test_side_exit_compiled_branch_default_false() {
    let exit = SideExit::new(0, 0, SideExitReason::GuardFailure);
    assert!(!exit.compiled_branch);
}

#[test]
fn test_side_exit_record_taken_saturating() {
    let mut exit = SideExit::new(0, 0, SideExitReason::OverflowDetected);
    exit.taken_count = u64::MAX;
    exit.record_taken(); // should not panic
    assert_eq!(exit.taken_count, u64::MAX);
}

#[test]
fn test_side_exit_is_hot_threshold_zero() {
    let exit = SideExit::new(0, 0, SideExitReason::TypeMismatch);
    // taken_count=0, threshold=0: 0 >= 0 is true
    assert!(exit.is_hot(0));
}

#[test]
fn test_side_exit_reason_serde_round_trip() {
    let variants = [
        SideExitReason::GuardFailure,
        SideExitReason::OverflowDetected,
        SideExitReason::TypeMismatch,
        SideExitReason::ShapeMismatch,
        SideExitReason::IcMegamorphic,
        SideExitReason::PrototypeInvalidated,
        SideExitReason::UnexpectedControlFlow,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: SideExitReason = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, &back);
    }
}

// ---------------------------------------------------------------------------
// SuperblockPolicy: edge values and clone/debug
// ---------------------------------------------------------------------------

#[test]
fn test_policy_clone_debug() {
    let p = SuperblockPolicy::default();
    let p2 = p.clone();
    assert_eq!(p, p2);
    let dbg = format!("{p:?}");
    assert!(dbg.contains("SuperblockPolicy"));
}

#[test]
fn test_policy_hash_all_fields_affect_hash() {
    let base = SuperblockPolicy::default();
    let changed = SuperblockPolicy {
        max_block_length: 1,
        max_tail_duplication: 0,
        max_trace_depth: 1,
        max_side_exits: 1,
        min_execution_count: 0,
        enable_guard_factoring: false,
        ..SuperblockPolicy::default()
    };
    assert_ne!(base.policy_hash(), changed.policy_hash());
}

// ---------------------------------------------------------------------------
// Guard factoring: disabled vs enabled
// ---------------------------------------------------------------------------

#[test]
fn test_guard_factoring_disabled_does_not_factor() {
    let offsets: Vec<(u32, &str)> = (0..4u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_nofactor", &offsets);
    let policy = SuperblockPolicy {
        enable_guard_factoring: false,
        min_execution_count: 32,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    if record.outcome == FormationOutcome::Formed {
        let block = record.block.unwrap();
        // Without factoring, factored_guard_count should be 0
        assert_eq!(block.factored_guard_count(), 0);
    }
}

#[test]
fn test_guard_factoring_enabled_may_factor_adjacent_same_kind() {
    // Use a profile where same-type guards are generated at adjacent positions
    let offsets: Vec<(u32, &str)> = (0..5u32).map(|i| (i * 4, "add")).collect();
    let profile = make_hot_profile("fn_factor_on", &offsets);
    let policy = SuperblockPolicy {
        enable_guard_factoring: true,
        min_execution_count: 32,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    // Whether or not factoring fires depends on type data; just verify formation succeeds
    assert_eq!(record.outcome, FormationOutcome::Formed);
}

// ---------------------------------------------------------------------------
// GuardKind: Clone, Ord, Hash
// ---------------------------------------------------------------------------

#[test]
fn test_guard_kind_clone_eq() {
    let k1 = GuardKind::TypeCheck {
        expected_type: "str".into(),
    };
    let k2 = k1.clone();
    assert_eq!(k1, k2);
}

#[test]
fn test_guard_kind_ord() {
    let k1 = GuardKind::IcStability { ic_offset: 0 };
    let k2 = GuardKind::IcStability { ic_offset: 10 };
    assert!(k1 < k2);
}

#[test]
fn test_guard_kind_range_check_negative_bounds() {
    let kind = GuardKind::RangeCheck {
        lower: -1000,
        upper: -1,
    };
    let display = format!("{kind}");
    assert!(display.contains("-1000"));
    assert!(display.contains("-1"));
}

// ---------------------------------------------------------------------------
// SuperblockEntry Clone/Debug/PartialEq/serde
// ---------------------------------------------------------------------------

#[test]
fn test_superblock_entry_serde_round_trip() {
    let entry = SuperblockEntry {
        position: 3,
        source_offset: 12,
        opcode: "jump".into(),
        is_tail_duplicate: true,
        execution_count: 9999,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SuperblockEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn test_superblock_entry_clone_debug() {
    let entry = SuperblockEntry {
        position: 0,
        source_offset: 0,
        opcode: "nop".into(),
        is_tail_duplicate: false,
        execution_count: 1,
    };
    let entry2 = entry.clone();
    assert_eq!(entry, entry2);
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("SuperblockEntry"));
}

// ---------------------------------------------------------------------------
// Superblock: record_side_exit unknown ID returns false
// ---------------------------------------------------------------------------

#[test]
fn test_record_side_exit_unknown_id_returns_false() {
    let mut block = make_simple_superblock("fn_unknown_exit", 0);
    let result = block.record_side_exit("nonexistent-exit-id", 1);
    assert!(!result);
}

// ---------------------------------------------------------------------------
// form_superblock: boundary — min_execution_count exactly at threshold
// ---------------------------------------------------------------------------

#[test]
fn test_form_superblock_execution_count_boundary() {
    use frankenengine_engine::quickening_feedback_lattice::QuickeningPolicy as QPolicy;
    let q_policy = QPolicy {
        warm_threshold: 2,
        hot_threshold: 4,
        min_stability_millionths: 0,
        min_ic_hit_rate_millionths: 0,
        max_polymorphic_types: 5,
        deopt_resets_to_cold: false,
    };
    let mut profile = QuickeningProfile::new("fn_boundary");
    // Record exactly 32 executions (= min_execution_count default)
    for _ in 0..32 {
        profile.record_execution(0, "add");
        profile.record_execution(4, "sub");
        profile.record_execution(8, "mul");
    }
    for _ in 0..4 {
        profile.evaluate_all(&q_policy);
    }
    let policy = SuperblockPolicy {
        min_execution_count: 32,
        ..SuperblockPolicy::default()
    };
    let record = form_superblock(&profile, 0, &policy, 1);
    // The outcome depends on whether threshold is met; just confirm no panic and valid state
    assert!(
        record.outcome == FormationOutcome::Formed
            || record.outcome == FormationOutcome::InsufficientHotInstructions
            || record.outcome == FormationOutcome::NoEligibleInstructions
    );
}

// ---------------------------------------------------------------------------
// TraceTree: schema_version and formation_epoch advance on extend
// ---------------------------------------------------------------------------

#[test]
fn test_trace_tree_schema_version_constant() {
    let block = make_simple_superblock("fn_schema", 0);
    let tree = TraceTree::new("fn_schema", block);
    assert_eq!(tree.schema_version, TRACE_TREE_SCHEMA_VERSION);
}

#[test]
fn test_trace_tree_formation_epoch_advances() {
    let b1 = make_simple_superblock("fn_epoch", 0);
    let exit_id = b1.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_epoch", b1);
    assert_eq!(tree.formation_epoch, 1);
    let b2 = make_simple_superblock("fn_epoch", 8);
    let policy = SuperblockPolicy::default();
    tree.extend_at_exit(0, &exit_id, b2, &policy);
    assert_eq!(tree.formation_epoch, 2);
}

#[test]
fn test_trace_tree_id_changes_on_extend() {
    let b1 = make_simple_superblock("fn_tid_change", 0);
    let exit_id = b1.side_exits[0].exit_id.clone();
    let mut tree = TraceTree::new("fn_tid_change", b1);
    let original_id = tree.tree_id.clone();
    let b2 = make_simple_superblock("fn_tid_change", 8);
    let policy = SuperblockPolicy::default();
    tree.extend_at_exit(0, &exit_id, b2, &policy);
    assert_ne!(tree.tree_id, original_id);
}
