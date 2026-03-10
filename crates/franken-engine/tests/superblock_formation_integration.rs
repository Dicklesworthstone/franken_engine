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
    clippy::manual_abs_diff
)]

use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::quickening_feedback_lattice::{
    ObservedType, QuickeningLevel, QuickeningPolicy, QuickeningProfile,
};
use frankenengine_engine::stage_envelope_certificate::ExecutionStage;
use frankenengine_engine::superblock_formation::{
    COMPONENT, CompilationRejectReason, FormationOutcome, GuardKind,
    OPTIMIZED_TIER_PLAN_SCHEMA_VERSION, OptimizedTierBackend, OptimizedTierCompilationPlan,
    SUPERBLOCK_SCHEMA_VERSION, SideExit, SideExitReason, Superblock, SuperblockEntry,
    SuperblockGuard, SuperblockPolicy, TRACE_TREE_SCHEMA_VERSION, TraceTree, TraceTreeSummary,
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
