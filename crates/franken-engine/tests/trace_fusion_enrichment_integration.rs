//! Enrichment integration tests for `trace_fusion`.
//!
//! Covers gaps: serde roundtrips for all enum variants and key structs,
//! motif recognition patterns, policy validation, trace lifecycle (enable/disable),
//! content hash determinism, engine fusion flow, diagnostics, and edge cases.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trace_fusion::{
    FusedInstruction, FusedTrace, FusedTraceSummary, FusionDisableReason, FusionGuard,
    FusionGuardKind, FusionOutcome, FusionPolicy, FusionProofLineage, FusionRecord,
    FusionTemplateCatalog, InstructionEntry, MotifKind, MotifRejectionReason, MotifValidation,
    TraceFusionDiagnostics, TraceFusionEngine, TRACE_FUSION_SCHEMA_VERSION, FusionMotif,
    MotifRecognizer,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn arith_entries(count: usize, exec_count: u64) -> Vec<InstructionEntry> {
    let ops = ["Add", "Sub", "Mul", "Div"];
    (0..count)
        .map(|i| InstructionEntry {
            offset: i as u32 * 4,
            opcode: ops[i % ops.len()].to_string(),
            execution_count: exec_count,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        })
        .collect()
}

fn prop_chain_entries(count: usize, exec_count: u64) -> Vec<InstructionEntry> {
    (0..count)
        .map(|i| InstructionEntry {
            offset: i as u32 * 4,
            opcode: "GetProperty".to_string(),
            execution_count: exec_count,
            type_stability_millionths: 960_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        })
        .collect()
}

fn make_proof_lineage() -> FusionProofLineage {
    FusionProofLineage::new(
        vec!["cap-proof-1".to_string()],
        vec!["flow-proof-1".to_string()],
        epoch(1),
    )
}

fn relaxed_policy() -> FusionPolicy {
    FusionPolicy {
        min_observation_count: 0,
        min_type_stability_millionths: 0,
        require_proof_lineage: false,
        allow_effectful_fusion: true,
        min_net_savings_millionths: 0,
        ..FusionPolicy::default()
    }
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_has_prefix() {
    assert!(TRACE_FUSION_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ===========================================================================
// MotifKind serde + min_instructions
// ===========================================================================

#[test]
fn enrichment_motif_kind_serde_roundtrip_all() {
    let all = [
        MotifKind::HostcallSequence,
        MotifKind::ArithmeticChain,
        MotifKind::PropertyChain,
        MotifKind::GuardElidedRegion,
        MotifKind::ComparisonBranch,
        MotifKind::AllocationInit,
        MotifKind::StringConcat,
        MotifKind::LoopInvariant,
    ];
    for k in &all {
        let json = serde_json::to_string(k).unwrap();
        let back: MotifKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_motif_kind_min_instructions_positive() {
    let all = [
        MotifKind::HostcallSequence,
        MotifKind::ArithmeticChain,
        MotifKind::PropertyChain,
        MotifKind::GuardElidedRegion,
        MotifKind::ComparisonBranch,
        MotifKind::AllocationInit,
        MotifKind::StringConcat,
        MotifKind::LoopInvariant,
    ];
    for k in &all {
        assert!(k.min_instructions() >= 1, "{k:?} should have min >= 1");
    }
}

#[test]
fn enrichment_motif_kind_arith_requires_three() {
    assert_eq!(MotifKind::ArithmeticChain.min_instructions(), 3);
}

#[test]
fn enrichment_motif_kind_loop_invariant_requires_one() {
    assert_eq!(MotifKind::LoopInvariant.min_instructions(), 1);
}

// ===========================================================================
// FusionMotif tests
// ===========================================================================

#[test]
fn enrichment_motif_new_has_content_addressed_id() {
    let motif = FusionMotif::new(
        MotifKind::ArithmeticChain,
        vec!["Add".into(), "Sub".into(), "Mul".into()],
        0,
        8,
    );
    assert!(motif.motif_id.starts_with("motif-"));
    assert_eq!(motif.instruction_count(), 3);
    assert!(motif.meets_minimum());
}

#[test]
fn enrichment_motif_below_minimum_does_not_meet() {
    let motif = FusionMotif::new(
        MotifKind::ArithmeticChain,
        vec!["Add".into(), "Sub".into()], // 2 < 3 required
        0,
        4,
    );
    assert!(!motif.meets_minimum());
}

#[test]
fn enrichment_motif_record_observation_increments() {
    let mut motif = FusionMotif::new(MotifKind::PropertyChain, vec!["GetProperty".into(), "GetProperty".into()], 0, 4);
    assert_eq!(motif.observation_count, 0);
    motif.record_observation();
    motif.record_observation();
    assert_eq!(motif.observation_count, 2);
}

#[test]
fn enrichment_motif_mark_effectful() {
    let mut motif = FusionMotif::new(MotifKind::HostcallSequence, vec!["HostCall".into(), "HostCall".into()], 0, 4);
    assert!(motif.side_effect_free);
    motif.mark_effectful();
    assert!(!motif.side_effect_free);
}

#[test]
fn enrichment_motif_require_capability() {
    let mut motif = FusionMotif::new(MotifKind::HostcallSequence, vec!["HostCall".into(), "HostCall".into()], 0, 4);
    motif.require_capability("fs.read");
    motif.require_capability("net.connect");
    assert_eq!(motif.required_capabilities.len(), 2);
    assert!(motif.required_capabilities.contains("fs.read"));
}

#[test]
fn enrichment_motif_content_hash_deterministic() {
    let m1 = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    let m2 = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_motif_content_hash_varies_with_kind() {
    let m1 = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    let m2 = FusionMotif::new(MotifKind::PropertyChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn enrichment_motif_serde_roundtrip() {
    let mut motif = FusionMotif::new(MotifKind::StringConcat, vec!["Concat".into(), "Concat".into()], 0, 4);
    motif.record_observation();
    motif.min_stability_millionths = 800_000;
    let json = serde_json::to_string(&motif).unwrap();
    let back: FusionMotif = serde_json::from_str(&json).unwrap();
    assert_eq!(motif.motif_id, back.motif_id);
    assert_eq!(motif.kind, back.kind);
    assert_eq!(motif.observation_count, back.observation_count);
}

// ===========================================================================
// FusionProofLineage tests
// ===========================================================================

#[test]
fn enrichment_proof_lineage_new_has_id() {
    let lineage = make_proof_lineage();
    assert!(lineage.lineage_id.starts_with("lineage-"));
    assert!(lineage.all_proofs_active);
    assert_eq!(lineage.proof_count(), 2);
}

#[test]
fn enrichment_proof_lineage_invalidate() {
    let mut lineage = make_proof_lineage();
    assert!(lineage.all_proofs_active);
    lineage.invalidate();
    assert!(!lineage.all_proofs_active);
}

#[test]
fn enrichment_proof_lineage_is_valid_at() {
    let lineage = make_proof_lineage(); // epoch 1
    assert!(lineage.is_valid_at(epoch(1)));
    assert!(lineage.is_valid_at(epoch(5)));
}

#[test]
fn enrichment_proof_lineage_invalid_not_valid() {
    let mut lineage = make_proof_lineage();
    lineage.invalidate();
    assert!(!lineage.is_valid_at(epoch(1)));
}

#[test]
fn enrichment_proof_lineage_serde_roundtrip() {
    let lineage = make_proof_lineage();
    let json = serde_json::to_string(&lineage).unwrap();
    let back: FusionProofLineage = serde_json::from_str(&json).unwrap();
    assert_eq!(lineage.lineage_id, back.lineage_id);
    assert_eq!(lineage.epoch, back.epoch);
}

// ===========================================================================
// FusedInstruction tests
// ===========================================================================

#[test]
fn enrichment_fused_instruction_passthrough() {
    let instr = FusedInstruction::passthrough(0, 100, "Add");
    assert!(!instr.is_super);
    assert_eq!(instr.fusion_factor(), 1);
    assert_eq!(instr.cost_millionths, 0);
    assert!(instr.guard.is_none());
}

#[test]
fn enrichment_fused_instruction_super() {
    let instr = FusedInstruction::super_instruction(0, vec![0, 4, 8], "SuperArithChain", 150_000);
    assert!(instr.is_super);
    assert_eq!(instr.fusion_factor(), 3);
    assert_eq!(instr.cost_millionths, 150_000);
}

#[test]
fn enrichment_fused_instruction_with_guard() {
    let guard = FusionGuard::new(FusionGuardKind::TypeStability { expected_type: "Integer".into() }, 100);
    let instr = FusedInstruction::passthrough(0, 0, "Add").with_guard(guard);
    assert!(instr.guard.is_some());
}

#[test]
fn enrichment_fused_instruction_serde_roundtrip() {
    let instr = FusedInstruction::super_instruction(3, vec![10, 14, 18], "SuperPropChain", 200_000);
    let json = serde_json::to_string(&instr).unwrap();
    let back: FusedInstruction = serde_json::from_str(&json).unwrap();
    assert_eq!(instr.opcode, back.opcode);
    assert_eq!(instr.source_offsets, back.source_offsets);
}

// ===========================================================================
// FusionGuard + FusionGuardKind tests
// ===========================================================================

#[test]
fn enrichment_guard_kind_serde_roundtrip_all() {
    let all = [
        FusionGuardKind::TypeStability { expected_type: "Integer".into() },
        FusionGuardKind::ShapeCheck { expected_shape_id: "shape-001".into() },
        FusionGuardKind::CapabilityValid { capability_name: "fs.read".into() },
        FusionGuardKind::LevelCheck { min_level: 3 },
        FusionGuardKind::ProofValid { lineage_id: "lineage-abc".into() },
    ];
    for k in &all {
        let json = serde_json::to_string(k).unwrap();
        let back: FusionGuardKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn enrichment_guard_new_has_id() {
    let guard = FusionGuard::new(FusionGuardKind::LevelCheck { min_level: 5 }, 42);
    assert!(guard.guard_id.starts_with("fg-"));
    assert_eq!(guard.side_exit_offset, 42);
    assert!(!guard.factored);
}

#[test]
fn enrichment_guard_mark_factored() {
    let mut guard = FusionGuard::new(FusionGuardKind::TypeStability { expected_type: "String".into() }, 0);
    guard.mark_factored();
    assert!(guard.factored);
}

#[test]
fn enrichment_guard_serde_roundtrip() {
    let guard = FusionGuard::new(FusionGuardKind::CapabilityValid { capability_name: "net.connect".into() }, 99);
    let json = serde_json::to_string(&guard).unwrap();
    let back: FusionGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard.guard_id, back.guard_id);
    assert_eq!(guard.kind, back.kind);
}

// ===========================================================================
// FusedTrace tests
// ===========================================================================

#[test]
fn enrichment_trace_new_defaults() {
    let trace = FusedTrace::new("fn_main", epoch(1));
    assert!(trace.trace_id.starts_with("ft-"));
    assert_eq!(trace.schema_version, TRACE_FUSION_SCHEMA_VERSION);
    assert!(trace.enabled);
    assert_eq!(trace.instruction_count(), 0);
    assert_eq!(trace.execution_count, 0);
}

#[test]
fn enrichment_trace_with_superblock() {
    let trace = FusedTrace::new("fn_main", epoch(1)).with_superblock("sb-123");
    assert_eq!(trace.source_superblock_id, Some("sb-123".to_string()));
}

#[test]
fn enrichment_trace_add_instruction() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    trace.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
    trace.add_instruction(FusedInstruction::super_instruction(1, vec![4, 8], "SuperArith", 100_000));
    assert_eq!(trace.instruction_count(), 2);
    assert_eq!(trace.super_instruction_count(), 1);
    assert_eq!(trace.fused_source_count(), 2);
}

#[test]
fn enrichment_trace_guard_count() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    let guard = FusionGuard::new(FusionGuardKind::TypeStability { expected_type: "Integer".into() }, 0);
    trace.add_instruction(FusedInstruction::passthrough(0, 0, "Add").with_guard(guard));
    trace.add_instruction(FusedInstruction::passthrough(1, 4, "Sub"));
    assert_eq!(trace.guard_count(), 1);
}

#[test]
fn enrichment_trace_disable_and_enable() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    assert!(trace.enabled);
    trace.disable(FusionDisableReason::OperatorDisabled { reason: "test".into() });
    assert!(!trace.enabled);
    assert!(trace.disable_reason.is_some());
    trace.enable();
    assert!(trace.enabled);
    assert!(trace.disable_reason.is_none());
}

#[test]
fn enrichment_trace_side_exit_ratio_zero_executions() {
    let trace = FusedTrace::new("fn_main", epoch(1));
    assert_eq!(trace.side_exit_ratio_millionths(), 0);
}

#[test]
fn enrichment_trace_side_exit_ratio_computation() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    for _ in 0..10 {
        trace.record_execution();
    }
    for _ in 0..3 {
        trace.record_side_exit();
    }
    // 3/10 = 300_000 millionths
    assert_eq!(trace.side_exit_ratio_millionths(), 300_000);
}

#[test]
fn enrichment_trace_is_degraded() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    for _ in 0..10 {
        trace.record_execution();
    }
    for _ in 0..3 {
        trace.record_side_exit();
    }
    assert!(trace.is_degraded(200_000)); // 300k > 200k threshold
    assert!(!trace.is_degraded(400_000)); // 300k < 400k threshold
}

#[test]
fn enrichment_trace_content_hash_deterministic() {
    let mut t1 = FusedTrace::new("fn_main", epoch(1));
    let mut t2 = FusedTrace::new("fn_main", epoch(1));
    t1.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
    t2.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_trace_content_hash_varies_with_function() {
    let t1 = FusedTrace::new("fn_a", epoch(1));
    let t2 = FusedTrace::new("fn_b", epoch(1));
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_trace_summary_fields() {
    let mut trace = FusedTrace::new("fn_main", epoch(1));
    trace.add_instruction(FusedInstruction::passthrough(0, 0, "Add"));
    trace.record_fused_motif("motif-abc");
    let summary = trace.summary();
    assert_eq!(summary.function_id, "fn_main");
    assert_eq!(summary.instruction_count, 1);
    assert_eq!(summary.motif_count, 1);
    assert!(summary.enabled);
}

#[test]
fn enrichment_trace_serde_roundtrip() {
    let mut trace = FusedTrace::new("fn_test", epoch(5));
    trace.add_instruction(FusedInstruction::passthrough(0, 0, "Sub"));
    let json = serde_json::to_string(&trace).unwrap();
    let back: FusedTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace.trace_id, back.trace_id);
    assert_eq!(trace.function_id, back.function_id);
}

// ===========================================================================
// FusionDisableReason serde
// ===========================================================================

#[test]
fn enrichment_disable_reason_serde_roundtrip_all() {
    let all: Vec<FusionDisableReason> = vec![
        FusionDisableReason::ProofInvalidated { lineage_id: "l-1".into() },
        FusionDisableReason::ExcessiveSideExits { ratio_millionths: 300_000, threshold_millionths: 200_000 },
        FusionDisableReason::EpochAdvanced { formation: 1, current: 5 },
        FusionDisableReason::OperatorDisabled { reason: "manual".into() },
        FusionDisableReason::SuperblockInvalidated { superblock_id: "sb-1".into() },
        FusionDisableReason::TypeAssumptionBroken { detail: "shape changed".into() },
        FusionDisableReason::NegativeNetGain { net_gain_millionths: -50_000 },
        FusionDisableReason::InterferenceDetected { other_trace_id: "ft-x".into() },
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: FusionDisableReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// FusionPolicy tests
// ===========================================================================

#[test]
fn enrichment_policy_default_values() {
    let policy = FusionPolicy::default();
    assert_eq!(policy.min_observation_count, 100);
    assert_eq!(policy.min_type_stability_millionths, 900_000);
    assert!(policy.require_proof_lineage);
    assert!(!policy.allow_effectful_fusion);
}

#[test]
fn enrichment_policy_hash_deterministic() {
    let p1 = FusionPolicy::default();
    let p2 = FusionPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies() {
    let p1 = FusionPolicy::default();
    let mut p2 = FusionPolicy::default();
    p2.min_observation_count = 999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_validate_motif_accepted() {
    let mut policy = FusionPolicy::default();
    policy.min_observation_count = 0;
    policy.min_type_stability_millionths = 0;
    let motif = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    assert_eq!(policy.validate_motif(&motif), MotifValidation::Accepted);
}

#[test]
fn enrichment_policy_validate_insufficient_instructions() {
    let policy = FusionPolicy::default();
    let motif = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into()], 0, 0); // 1 < 3
    assert_eq!(
        policy.validate_motif(&motif),
        MotifValidation::Rejected(MotifRejectionReason::InsufficientInstructions)
    );
}

#[test]
fn enrichment_policy_validate_insufficient_observations() {
    let policy = FusionPolicy::default(); // needs 100 observations
    let motif = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    // observation_count = 0 < 100
    assert_eq!(
        policy.validate_motif(&motif),
        MotifValidation::Rejected(MotifRejectionReason::InsufficientObservations)
    );
}

#[test]
fn enrichment_policy_validate_effectful_rejected() {
    let mut policy = FusionPolicy::default();
    policy.min_observation_count = 0;
    policy.min_type_stability_millionths = 0;
    policy.allow_effectful_fusion = false;
    let mut motif = FusionMotif::new(MotifKind::HostcallSequence, vec!["HostCall".into(), "HostCall".into()], 0, 4);
    motif.mark_effectful();
    assert_eq!(
        policy.validate_motif(&motif),
        MotifValidation::Rejected(MotifRejectionReason::EffectfulMotif)
    );
}

#[test]
fn enrichment_policy_serde_roundtrip() {
    let policy = FusionPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: FusionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ===========================================================================
// MotifValidation + MotifRejectionReason serde
// ===========================================================================

#[test]
fn enrichment_motif_validation_serde_roundtrip() {
    let accepted = MotifValidation::Accepted;
    let json = serde_json::to_string(&accepted).unwrap();
    let back: MotifValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(accepted, back);
}

#[test]
fn enrichment_rejection_reason_serde_roundtrip_all() {
    let all = [
        MotifRejectionReason::InsufficientInstructions,
        MotifRejectionReason::InsufficientObservations,
        MotifRejectionReason::InsufficientStability,
        MotifRejectionReason::EffectfulMotif,
        MotifRejectionReason::UnauthorizedCapabilities,
        MotifRejectionReason::MotifLimitExceeded,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: MotifRejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// FusionOutcome serde
// ===========================================================================

#[test]
fn enrichment_fusion_outcome_serde_roundtrip_all() {
    let all: Vec<FusionOutcome> = vec![
        FusionOutcome::Formed,
        FusionOutcome::NoFusibleMotifs,
        FusionOutcome::AllMotifsRejected,
        FusionOutcome::InsufficientSavings { net_millionths: 10_000 },
        FusionOutcome::TraceLimitExceeded { function_id: "fn_x".into() },
        FusionOutcome::MissingProofLineage,
        FusionOutcome::InterferenceBlocked { existing_trace_id: "ft-y".into() },
    ];
    for o in &all {
        let json = serde_json::to_string(o).unwrap();
        let back: FusionOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ===========================================================================
// FusionRecord tests
// ===========================================================================

#[test]
fn enrichment_fusion_record_new_defaults() {
    let record = FusionRecord::new("fn_test", epoch(1));
    assert!(record.record_id.starts_with("fr-"));
    assert_eq!(record.function_id, "fn_test");
    assert!(record.considered_motifs.is_empty());
    assert_eq!(record.outcome, FusionOutcome::NoFusibleMotifs);
    assert!(record.trace_id.is_none());
}

#[test]
fn enrichment_fusion_record_serde_roundtrip() {
    let record = FusionRecord::new("fn_test", epoch(5));
    let json = serde_json::to_string(&record).unwrap();
    let back: FusionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record.record_id, back.record_id);
    assert_eq!(record.function_id, back.function_id);
}

// ===========================================================================
// MotifRecognizer tests
// ===========================================================================

#[test]
fn enrichment_recognizer_empty() {
    let recognizer = MotifRecognizer::new();
    assert_eq!(recognizer.entry_count(), 0);
    assert!(recognizer.recognize().is_empty());
}

#[test]
fn enrichment_recognizer_arith_chain() {
    let mut recognizer = MotifRecognizer::new();
    for entry in arith_entries(5, 100) {
        recognizer.add_entry(entry);
    }
    let motifs = recognizer.recognize();
    let arith_motifs: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::ArithmeticChain).collect();
    assert!(!arith_motifs.is_empty(), "should recognize arithmetic chain of 5 ops");
}

#[test]
fn enrichment_recognizer_property_chain() {
    let mut recognizer = MotifRecognizer::new();
    for entry in prop_chain_entries(3, 100) {
        recognizer.add_entry(entry);
    }
    let motifs = recognizer.recognize();
    let prop_motifs: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::PropertyChain).collect();
    assert!(!prop_motifs.is_empty(), "should recognize property chain");
}

// ===========================================================================
// FusionTemplateCatalog tests
// ===========================================================================

#[test]
fn enrichment_catalog_defaults_non_empty() {
    let catalog = FusionTemplateCatalog::new();
    assert!(catalog.template_count() >= 4, "should have default templates");
}

#[test]
fn enrichment_catalog_find_template_for_arith() {
    let catalog = FusionTemplateCatalog::new();
    let motif = FusionMotif::new(MotifKind::ArithmeticChain, vec!["Add".into(), "Sub".into(), "Mul".into()], 0, 8);
    let template = catalog.find_template(&motif);
    assert!(template.is_some());
    assert_eq!(template.unwrap().opcode, "SuperArithChain");
}

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let catalog = FusionTemplateCatalog::new();
    let json = serde_json::to_string(&catalog).unwrap();
    let back: FusionTemplateCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog.template_count(), back.template_count());
}

// ===========================================================================
// TraceFusionEngine tests
// ===========================================================================

#[test]
fn enrichment_engine_new_empty() {
    let engine = TraceFusionEngine::new(epoch(1));
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.total_count(), 0);
    assert_eq!(engine.record_count(), 0);
}

#[test]
fn enrichment_engine_fuse_no_motifs() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    // Single non-fusible instruction
    let entries = vec![InstructionEntry {
        offset: 0,
        opcode: "Return".into(),
        execution_count: 100,
        type_stability_millionths: 1_000_000,
        has_side_effects: false,
        capabilities: BTreeSet::new(),
    }];
    let outcome = engine.fuse("fn_test", &entries, None);
    assert_eq!(outcome, FusionOutcome::NoFusibleMotifs);
    assert_eq!(engine.record_count(), 1);
}

#[test]
fn enrichment_engine_fuse_arith_formed() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    let outcome = engine.fuse("fn_arith", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
    assert_eq!(engine.total_count(), 1);
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn enrichment_engine_fuse_missing_proof_lineage() {
    let mut engine = TraceFusionEngine::new(epoch(1)); // default policy requires proof
    let entries = arith_entries(5, 200);
    let outcome = engine.fuse("fn_test", &entries, None);
    assert_eq!(outcome, FusionOutcome::MissingProofLineage);
}

#[test]
fn enrichment_engine_fuse_with_proof_lineage() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    let mut policy = engine.policy.clone();
    policy.min_observation_count = 0;
    policy.min_type_stability_millionths = 0;
    policy.min_net_savings_millionths = 0;
    engine.policy = policy;
    let entries = arith_entries(5, 200);
    let lineage = make_proof_lineage();
    let outcome = engine.fuse("fn_test", &entries, Some(lineage));
    assert_eq!(outcome, FusionOutcome::Formed);
}

#[test]
fn enrichment_engine_trace_limit_exceeded() {
    let mut policy = relaxed_policy();
    policy.max_traces_per_function = 1;
    let mut engine = TraceFusionEngine::with_policy(policy, epoch(1));
    let entries1 = arith_entries(5, 100);
    assert_eq!(engine.fuse("fn_test", &entries1, None), FusionOutcome::Formed);
    // Offset entries to avoid interference
    let entries2: Vec<_> = arith_entries(5, 100).into_iter().enumerate().map(|(i, mut e)| {
        e.offset = (i as u32 + 100) * 4;
        e
    }).collect();
    let outcome = engine.fuse("fn_test", &entries2, None);
    assert!(matches!(outcome, FusionOutcome::TraceLimitExceeded { .. }));
}

#[test]
fn enrichment_engine_disable_trace() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    let trace_id = engine.active_traces.keys().next().unwrap().clone();
    assert!(engine.disable_trace(&trace_id, FusionDisableReason::OperatorDisabled { reason: "test".into() }));
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.total_count(), 1);
}

#[test]
fn enrichment_engine_enable_trace() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    let trace_id = engine.active_traces.keys().next().unwrap().clone();
    engine.disable_trace(&trace_id, FusionDisableReason::OperatorDisabled { reason: "test".into() });
    assert!(engine.enable_trace(&trace_id));
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn enrichment_engine_advance_epoch_disables_old() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    assert_eq!(engine.active_count(), 1);
    engine.advance_epoch(epoch(5));
    assert_eq!(engine.active_count(), 0);
}

#[test]
fn enrichment_engine_record_execution() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    let trace_id = engine.active_traces.keys().next().unwrap().clone();
    assert!(engine.record_execution(&trace_id));
    assert!(!engine.record_execution("nonexistent"));
}

#[test]
fn enrichment_engine_record_side_exit_auto_disable() {
    let mut policy = relaxed_policy();
    policy.max_exit_ratio_millionths = 100_000; // 10%
    let mut engine = TraceFusionEngine::with_policy(policy, epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    let trace_id = engine.active_traces.keys().next().unwrap().clone();
    // 1 execution, 1 side exit = 100% > 10% → should auto-disable
    engine.record_execution(&trace_id);
    engine.record_side_exit(&trace_id);
    assert_eq!(engine.active_count(), 0); // auto-disabled
}

#[test]
fn enrichment_engine_traces_for_function() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_a", &entries, None);
    assert_eq!(engine.traces_for_function("fn_a").len(), 1);
    assert_eq!(engine.traces_for_function("fn_b").len(), 0);
}

#[test]
fn enrichment_engine_diagnostics() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    let entries = arith_entries(5, 100);
    engine.fuse("fn_test", &entries, None);
    let diag = engine.diagnostics();
    assert_eq!(diag.total_traces, 1);
    assert_eq!(diag.active_traces, 1);
    assert_eq!(diag.disabled_traces, 0);
    assert_eq!(diag.fusion_attempts, 1);
    assert_eq!(diag.fusion_successes, 1);
    assert!(!diag.policy_hash.is_empty());
}

#[test]
fn enrichment_diagnostics_serde_roundtrip() {
    let engine = TraceFusionEngine::new(epoch(1));
    let diag = engine.diagnostics();
    let json = serde_json::to_string(&diag).unwrap();
    let back: TraceFusionDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag.total_traces, back.total_traces);
    assert_eq!(diag.policy_hash, back.policy_hash);
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let trace = FusedTrace::new("fn_test", epoch(1));
    let summary = trace.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: FusedTraceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.trace_id, back.trace_id);
}

#[test]
fn enrichment_engine_invalidate_proof() {
    let mut engine = TraceFusionEngine::with_policy(relaxed_policy(), epoch(1));
    // Need proof lineage but relaxed policy doesn't require it — add one anyway
    let mut policy = relaxed_policy();
    policy.require_proof_lineage = false;
    engine.policy = policy;
    let entries = arith_entries(5, 100);
    let lineage = make_proof_lineage();
    engine.fuse("fn_test", &entries, Some(lineage));
    assert_eq!(engine.active_count(), 1);
    engine.invalidate_proof("cap-proof-1");
    assert_eq!(engine.active_count(), 0);
}
