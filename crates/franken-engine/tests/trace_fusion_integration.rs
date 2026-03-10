//! Integration tests for proof-guided trace fusion and superinstructions.
//!
//! Tests the full trace fusion pipeline: motif recognition → policy validation →
//! superinstruction formation → proof lineage → disable/enable lifecycle.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trace_fusion::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn arith_entries(count: usize, exec_count: u64, base_offset: u32) -> Vec<InstructionEntry> {
    let ops = ["Add", "Sub", "Mul", "Div"];
    (0..count)
        .map(|i| InstructionEntry {
            offset: base_offset + i as u32 * 4,
            opcode: ops[i % ops.len()].to_string(),
            execution_count: exec_count,
            type_stability_millionths: 950_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        })
        .collect()
}

fn prop_chain_entries(count: usize, exec_count: u64, base_offset: u32) -> Vec<InstructionEntry> {
    (0..count)
        .map(|i| InstructionEntry {
            offset: base_offset + i as u32 * 4,
            opcode: "GetProperty".to_string(),
            execution_count: exec_count,
            type_stability_millionths: 960_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        })
        .collect()
}

fn hostcall_entries(count: usize, exec_count: u64, base_offset: u32) -> Vec<InstructionEntry> {
    (0..count)
        .map(|i| {
            let mut caps = BTreeSet::new();
            caps.insert("fs.read".to_string());
            InstructionEntry {
                offset: base_offset + i as u32 * 4,
                opcode: "HostCall".to_string(),
                execution_count: exec_count,
                type_stability_millionths: 1_000_000,
                has_side_effects: true,
                capabilities: caps,
            }
        })
        .collect()
}

fn cmp_branch_entries(exec_count: u64, base_offset: u32) -> Vec<InstructionEntry> {
    vec![
        InstructionEntry {
            offset: base_offset,
            opcode: "Lt".to_string(),
            execution_count: exec_count,
            type_stability_millionths: 990_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        },
        InstructionEntry {
            offset: base_offset + 4,
            opcode: "JumpIf".to_string(),
            execution_count: exec_count,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        },
    ]
}

fn alloc_init_entries(prop_count: usize, exec_count: u64, base_offset: u32) -> Vec<InstructionEntry> {
    let mut entries = vec![InstructionEntry {
        offset: base_offset,
        opcode: "NewObject".to_string(),
        execution_count: exec_count,
        type_stability_millionths: 1_000_000,
        has_side_effects: false,
        capabilities: BTreeSet::new(),
    }];
    for i in 0..prop_count {
        entries.push(InstructionEntry {
            offset: base_offset + (i as u32 + 1) * 4,
            opcode: "SetProperty".to_string(),
            execution_count: exec_count,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
    }
    entries
}

fn make_proof_lineage(cap_proofs: &[&str], flow_proofs: &[&str]) -> FusionProofLineage {
    FusionProofLineage::new(
        cap_proofs.iter().map(|s| s.to_string()).collect(),
        flow_proofs.iter().map(|s| s.to_string()).collect(),
        epoch(1),
    )
}

fn relaxed_policy() -> FusionPolicy {
    FusionPolicy {
        require_proof_lineage: false,
        ..FusionPolicy::default()
    }
}

// ---------------------------------------------------------------------------
// Motif recognition pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_arithmetic_chain_recognition_pipeline() {
    let mut rec = MotifRecognizer::new();
    for entry in arith_entries(6, 200, 0) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let arith: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::ArithmeticChain).collect();
    assert_eq!(arith.len(), 1);
    assert_eq!(arith[0].instruction_count(), 6);
    assert_eq!(arith[0].observation_count, 200);
    assert!(arith[0].side_effect_free);
}

#[test]
fn test_property_chain_recognition_pipeline() {
    let mut rec = MotifRecognizer::new();
    for entry in prop_chain_entries(5, 300, 0) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let props: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::PropertyChain).collect();
    assert_eq!(props.len(), 1);
    assert_eq!(props[0].instruction_count(), 5);
}

#[test]
fn test_hostcall_sequence_recognition() {
    let mut rec = MotifRecognizer::new();
    for entry in hostcall_entries(4, 200, 0) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let hc: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::HostcallSequence).collect();
    assert_eq!(hc.len(), 1);
    assert!(!hc[0].side_effect_free);
    assert!(hc[0].required_capabilities.contains("fs.read"));
}

#[test]
fn test_comparison_branch_recognition() {
    let mut rec = MotifRecognizer::new();
    for entry in cmp_branch_entries(500, 0) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let cmps: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::ComparisonBranch).collect();
    assert_eq!(cmps.len(), 1);
    assert_eq!(cmps[0].instruction_count(), 2);
}

#[test]
fn test_allocation_init_recognition() {
    let mut rec = MotifRecognizer::new();
    for entry in alloc_init_entries(3, 200, 0) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let allocs: Vec<_> = motifs.iter().filter(|m| m.kind == MotifKind::AllocationInit).collect();
    assert_eq!(allocs.len(), 1);
    assert_eq!(allocs[0].instruction_count(), 4); // NewObject + 3 SetProperty
}

#[test]
fn test_multiple_motif_types_in_stream() {
    let mut rec = MotifRecognizer::new();
    // Arith chain: 0..16
    for entry in arith_entries(4, 200, 0) {
        rec.add_entry(entry);
    }
    // Separator
    rec.add_entry(InstructionEntry {
        offset: 16,
        opcode: "LoadInt".to_string(),
        execution_count: 200,
        type_stability_millionths: 1_000_000,
        has_side_effects: false,
        capabilities: BTreeSet::new(),
    });
    // Property chain: 20..32
    for entry in prop_chain_entries(3, 200, 20) {
        rec.add_entry(entry);
    }
    let motifs = rec.recognize();
    let arith_count = motifs.iter().filter(|m| m.kind == MotifKind::ArithmeticChain).count();
    let prop_count = motifs.iter().filter(|m| m.kind == MotifKind::PropertyChain).count();
    assert_eq!(arith_count, 1);
    assert_eq!(prop_count, 1);
}

#[test]
fn test_no_motifs_in_heterogeneous_stream() {
    let mut rec = MotifRecognizer::new();
    let ops = ["LoadInt", "Add", "Return", "GetProperty", "Call"];
    for (i, op) in ops.iter().enumerate() {
        rec.add_entry(InstructionEntry {
            offset: i as u32 * 4,
            opcode: op.to_string(),
            execution_count: 200,
            type_stability_millionths: 1_000_000,
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        });
    }
    let motifs = rec.recognize();
    assert!(motifs.is_empty());
}

// ---------------------------------------------------------------------------
// Full fusion pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_full_arithmetic_fusion_pipeline() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(5, 200, 0);
    let outcome = engine.fuse("fn_hot_loop", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);

    let traces = engine.traces_for_function("fn_hot_loop");
    assert_eq!(traces.len(), 1);
    let trace = traces[0];
    assert!(trace.enabled);
    assert!(trace.super_instruction_count() > 0);
    assert!(trace.cost_savings_millionths > 0);
}

#[test]
fn test_full_property_chain_fusion() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = prop_chain_entries(4, 300, 0);
    let outcome = engine.fuse("fn_obj_access", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);

    let trace = engine.active_traces.values().next().unwrap();
    assert!(trace.super_instruction_count() > 0);
    assert!(trace.fused_motifs.len() > 0);
}

#[test]
fn test_fusion_with_proof_lineage() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    let entries = arith_entries(4, 200, 0);
    let lineage = make_proof_lineage(&["cap-proof-1"], &["flow-proof-1"]);
    let outcome = engine.fuse("fn_secured", &entries, Some(lineage));
    assert_eq!(outcome, FusionOutcome::Formed);

    let trace = engine.active_traces.values().next().unwrap();
    assert!(trace.proof_lineage.is_some());
    let pl = trace.proof_lineage.as_ref().unwrap();
    assert!(pl.all_proofs_active);
    assert_eq!(pl.proof_count(), 2);
}

#[test]
fn test_fusion_requires_proof_when_policy_set() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    assert!(engine.policy.require_proof_lineage);
    let entries = arith_entries(4, 200, 0);
    let outcome = engine.fuse("fn_test", &entries, None);
    assert_eq!(outcome, FusionOutcome::MissingProofLineage);
    assert_eq!(engine.total_count(), 0);
}

#[test]
fn test_fusion_rejects_low_observations() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 10, 0); // Only 10 observations
    let outcome = engine.fuse("fn_cold", &entries, None);
    assert_eq!(outcome, FusionOutcome::AllMotifsRejected);
}

#[test]
fn test_fusion_rejects_low_stability() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries: Vec<InstructionEntry> = (0..4)
        .map(|i| InstructionEntry {
            offset: i * 4,
            opcode: "Add".to_string(),
            execution_count: 200,
            type_stability_millionths: 500_000, // 50%, below 90% threshold
            has_side_effects: false,
            capabilities: BTreeSet::new(),
        })
        .collect();
    let outcome = engine.fuse("fn_unstable", &entries, None);
    assert_eq!(outcome, FusionOutcome::AllMotifsRejected);
}

#[test]
fn test_effectful_fusion_default_rejected() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = hostcall_entries(3, 200, 0);
    let outcome = engine.fuse("fn_hostcall", &entries, None);
    assert_eq!(outcome, FusionOutcome::AllMotifsRejected);
}

#[test]
fn test_effectful_fusion_allowed_by_policy() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = FusionPolicy {
        require_proof_lineage: false,
        allow_effectful_fusion: true,
        ..FusionPolicy::default()
    };
    let entries = hostcall_entries(3, 200, 0);
    let outcome = engine.fuse("fn_hostcall", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
}

// ---------------------------------------------------------------------------
// Trace lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_trace_execution_tracking() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);
    let tid = engine.active_traces.keys().next().unwrap().clone();

    for _ in 0..50 {
        engine.record_execution(&tid);
    }
    let trace = engine.get_trace(&tid).unwrap();
    assert_eq!(trace.execution_count, 50);
}

#[test]
fn test_side_exit_tracking_and_auto_disable() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_exit_ratio_millionths = 100_000; // 10%
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);
    let tid = engine.active_traces.keys().next().unwrap().clone();

    // 5 executions, 1 exit = 20% > 10%
    for _ in 0..5 {
        engine.record_execution(&tid);
    }
    engine.record_side_exit(&tid);

    let trace = engine.get_trace(&tid).unwrap();
    assert!(!trace.enabled);
    assert!(matches!(
        trace.disable_reason,
        Some(FusionDisableReason::ExcessiveSideExits { .. })
    ));
}

#[test]
fn test_disable_and_reenable_trace() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);
    let tid = engine.active_traces.keys().next().unwrap().clone();

    assert_eq!(engine.active_count(), 1);
    engine.disable_trace(&tid, FusionDisableReason::OperatorDisabled {
        reason: "maintenance".to_string(),
    });
    assert_eq!(engine.active_count(), 0);
    assert_eq!(engine.total_count(), 1);

    engine.enable_trace(&tid);
    assert_eq!(engine.active_count(), 1);
}

#[test]
fn test_proof_invalidation_disables_affected_traces() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    let entries = arith_entries(4, 200, 0);
    let lineage = make_proof_lineage(&["cap-1", "cap-2"], &["flow-1"]);
    engine.fuse("fn_test", &entries, Some(lineage));

    let tid = engine.active_traces.keys().next().unwrap().clone();
    assert!(engine.get_trace(&tid).unwrap().enabled);

    engine.invalidate_proof("cap-1");
    assert!(!engine.get_trace(&tid).unwrap().enabled);
}

#[test]
fn test_proof_invalidation_spares_unrelated_traces() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy.max_traces_per_function = 10;

    let entries1 = arith_entries(4, 200, 0);
    let lineage1 = make_proof_lineage(&["cap-A"], &[]);
    engine.fuse("fn_a", &entries1, Some(lineage1));

    let entries2 = prop_chain_entries(3, 200, 100);
    let lineage2 = make_proof_lineage(&["cap-B"], &[]);
    engine.fuse("fn_b", &entries2, Some(lineage2));

    engine.invalidate_proof("cap-A");
    let traces: Vec<_> = engine.active_traces.values().collect();
    let disabled = traces.iter().filter(|t| !t.enabled).count();
    let enabled = traces.iter().filter(|t| t.enabled).count();
    assert_eq!(disabled, 1);
    assert_eq!(enabled, 1);
}

#[test]
fn test_epoch_advance_disables_old_traces() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);

    engine.advance_epoch(epoch(5));
    let trace = engine.active_traces.values().next().unwrap();
    assert!(!trace.enabled);
    assert!(matches!(
        trace.disable_reason,
        Some(FusionDisableReason::EpochAdvanced { formation: 1, current: 5 })
    ));
}

// ---------------------------------------------------------------------------
// Interference detection
// ---------------------------------------------------------------------------

#[test]
fn test_overlapping_offsets_detected_as_interference() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_traces_per_function = 10;
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);

    let outcome2 = engine.fuse("fn_test", &entries, None);
    assert!(matches!(outcome2, FusionOutcome::InterferenceBlocked { .. }));
}

#[test]
fn test_nonoverlapping_offsets_allowed() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_traces_per_function = 10;

    let entries1 = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries1, None);

    let entries2 = prop_chain_entries(3, 200, 1000);
    let outcome2 = engine.fuse("fn_test", &entries2, None);
    assert_eq!(outcome2, FusionOutcome::Formed);
    assert_eq!(engine.total_count(), 2);
}

#[test]
fn test_different_functions_no_interference() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_a", &entries, None);

    let outcome = engine.fuse("fn_b", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
    assert_eq!(engine.total_count(), 2);
}

// ---------------------------------------------------------------------------
// Trace limits
// ---------------------------------------------------------------------------

#[test]
fn test_per_function_trace_limit() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_traces_per_function = 2;

    let e1 = arith_entries(4, 200, 0);
    let e2 = prop_chain_entries(3, 200, 1000);
    let e3 = arith_entries(4, 200, 2000);

    assert_eq!(engine.fuse("fn_test", &e1, None), FusionOutcome::Formed);
    assert_eq!(engine.fuse("fn_test", &e2, None), FusionOutcome::Formed);
    assert!(matches!(
        engine.fuse("fn_test", &e3, None),
        FusionOutcome::TraceLimitExceeded { .. }
    ));
}

#[test]
fn test_per_function_limit_independent() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_traces_per_function = 1;

    let e1 = arith_entries(4, 200, 0);
    let e2 = arith_entries(4, 200, 0);

    assert_eq!(engine.fuse("fn_a", &e1, None), FusionOutcome::Formed);
    assert_eq!(engine.fuse("fn_b", &e2, None), FusionOutcome::Formed);
    assert_eq!(engine.total_count(), 2);
}

// ---------------------------------------------------------------------------
// Diagnostics and summaries
// ---------------------------------------------------------------------------

#[test]
fn test_engine_diagnostics_after_mixed_operations() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();

    // Success
    let e1 = arith_entries(4, 200, 0);
    engine.fuse("fn_a", &e1, None);

    // Rejection (low obs)
    let e2 = arith_entries(4, 5, 1000);
    engine.fuse("fn_b", &e2, None);

    let diag = engine.diagnostics();
    assert_eq!(diag.total_traces, 1);
    assert_eq!(diag.active_traces, 1);
    assert_eq!(diag.fusion_attempts, 2);
    assert_eq!(diag.fusion_successes, 1);
    assert_eq!(diag.fusion_rejections, 1);
    assert!(diag.total_cost_savings_millionths > 0);
}

#[test]
fn test_trace_summary_fields() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(5, 200, 0);
    engine.fuse("fn_test", &entries, None);

    let summaries = engine.active_summaries();
    assert_eq!(summaries.len(), 1);
    let s = &summaries[0];
    assert!(s.trace_id.starts_with("ft-"));
    assert_eq!(s.function_id, "fn_test");
    assert!(s.super_instruction_count > 0);
    assert!(s.cost_savings_millionths > 0);
    assert!(s.enabled);
}

#[test]
fn test_all_summaries_includes_disabled() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);
    let tid = engine.active_traces.keys().next().unwrap().clone();
    engine.disable_trace(&tid, FusionDisableReason::OperatorDisabled {
        reason: "test".into(),
    });

    assert_eq!(engine.active_summaries().len(), 0);
    assert_eq!(engine.all_summaries().len(), 1);
    assert!(!engine.all_summaries()[0].enabled);
}

// ---------------------------------------------------------------------------
// Content hashing and determinism
// ---------------------------------------------------------------------------

#[test]
fn test_trace_content_hash_deterministic() {
    let mut e1 = TraceFusionEngine::new(epoch(1));
    e1.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    e1.fuse("fn_test", &entries, None);

    let mut e2 = TraceFusionEngine::new(epoch(1));
    e2.policy = relaxed_policy();
    e2.fuse("fn_test", &entries, None);

    let h1 = e1.active_traces.values().next().unwrap().content_hash();
    let h2 = e2.active_traces.values().next().unwrap().content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn test_motif_content_hash_stability() {
    let m1 = FusionMotif::new(
        MotifKind::PropertyChain,
        vec!["GetProperty".into(), "GetProperty".into(), "GetProperty".into()],
        0,
        8,
    );
    let m2 = FusionMotif::new(
        MotifKind::PropertyChain,
        vec!["GetProperty".into(), "GetProperty".into(), "GetProperty".into()],
        0,
        8,
    );
    assert_eq!(m1.content_hash(), m2.content_hash());
    assert_eq!(m1.motif_id, m2.motif_id);
}

#[test]
fn test_policy_hash_changes_with_params() {
    let p1 = FusionPolicy::default();
    let mut p2 = FusionPolicy::default();
    p2.min_observation_count = 500;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// Serialization roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_full_engine_state_roundtrip() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = arith_entries(4, 200, 0);
    engine.fuse("fn_test", &entries, None);

    let json = serde_json::to_string(&engine).unwrap();
    let decoded: TraceFusionEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total_count(), 1);
    assert_eq!(decoded.active_count(), 1);
}

#[test]
fn test_fused_trace_with_proof_roundtrip() {
    let mut trace = FusedTrace::new("fn_test", epoch(1));
    trace.set_proof_lineage(make_proof_lineage(&["p1", "p2"], &["f1"]));
    trace.add_instruction(FusedInstruction::super_instruction(
        0,
        vec![0, 4, 8],
        "SuperArithChain",
        150_000,
    ));
    trace.cost_savings_millionths = 150_000;

    let json = serde_json::to_string(&trace).unwrap();
    let decoded: FusedTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.proof_lineage.as_ref().unwrap().proof_count(), 3);
    assert_eq!(decoded.super_instruction_count(), 1);
}

#[test]
fn test_fusion_record_roundtrip() {
    let mut record = FusionRecord::new("fn_test", epoch(1));
    record.outcome = FusionOutcome::Formed;
    record.cost_savings_millionths = 200_000;
    record.trace_id = Some("ft-abc123".to_string());

    let json = serde_json::to_string(&record).unwrap();
    let decoded: FusionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.outcome, FusionOutcome::Formed);
    assert_eq!(decoded.cost_savings_millionths, 200_000);
}

// ---------------------------------------------------------------------------
// Template catalog
// ---------------------------------------------------------------------------

#[test]
fn test_catalog_default_templates() {
    let catalog = FusionTemplateCatalog::new();
    assert!(catalog.template_count() >= 6);

    let arith_motif = FusionMotif::new(
        MotifKind::ArithmeticChain,
        vec!["Add".into(), "Sub".into(), "Mul".into()],
        0, 8,
    );
    assert!(catalog.find_template(&arith_motif).is_some());
}

#[test]
fn test_catalog_custom_template() {
    let mut catalog = FusionTemplateCatalog::new();
    catalog.register(SuperInstructionTemplate {
        opcode: "CustomSuper".into(),
        motif_kind: MotifKind::LoopInvariant,
        min_opcodes: 1,
        max_opcodes: 4,
        savings_millionths: 50_000,
        required_guard: None,
    });

    let motif = FusionMotif::new(
        MotifKind::LoopInvariant,
        vec!["LoadInt".into()],
        0, 0,
    );
    let t = catalog.find_template(&motif);
    assert!(t.is_some());
    assert_eq!(t.unwrap().opcode, "CustomSuper");
}

#[test]
fn test_catalog_no_template_for_oversized_motif() {
    let catalog = FusionTemplateCatalog::new();
    let motif = FusionMotif::new(
        MotifKind::ArithmeticChain,
        (0..20).map(|_| "Add".to_string()).collect(), // 20 > max_opcodes=16
        0, 76,
    );
    assert!(catalog.find_template(&motif).is_none());
}

// ---------------------------------------------------------------------------
// Proof lineage lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_proof_lineage_validity_window() {
    let lineage = FusionProofLineage::new(
        vec!["p1".into()],
        vec![],
        epoch(3),
    );
    assert!(!lineage.is_valid_at(epoch(1))); // Before epoch
    assert!(!lineage.is_valid_at(epoch(2)));
    assert!(lineage.is_valid_at(epoch(3)));   // At epoch
    assert!(lineage.is_valid_at(epoch(100))); // After epoch
}

#[test]
fn test_proof_lineage_invalidation_permanent() {
    let mut lineage = make_proof_lineage(&["p1"], &["f1"]);
    lineage.invalidate();
    assert!(!lineage.is_valid_at(epoch(1)));
    assert!(!lineage.is_valid_at(epoch(100)));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_empty_instruction_stream() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    assert_eq!(engine.fuse("fn_test", &[], None), FusionOutcome::NoFusibleMotifs);
}

#[test]
fn test_single_instruction_stream() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = vec![InstructionEntry {
        offset: 0,
        opcode: "Return".into(),
        execution_count: 200,
        type_stability_millionths: 1_000_000,
        has_side_effects: false,
        capabilities: BTreeSet::new(),
    }];
    assert_eq!(engine.fuse("fn_test", &entries, None), FusionOutcome::NoFusibleMotifs);
}

#[test]
fn test_disable_nonexistent_trace() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    assert!(!engine.disable_trace("nonexistent", FusionDisableReason::OperatorDisabled {
        reason: "test".into(),
    }));
}

#[test]
fn test_enable_nonexistent_trace() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    assert!(!engine.enable_trace("nonexistent"));
}

#[test]
fn test_record_execution_nonexistent() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    assert!(!engine.record_execution("nonexistent"));
}

#[test]
fn test_record_side_exit_nonexistent() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    assert!(!engine.record_side_exit("nonexistent"));
}

#[test]
fn test_side_exit_ratio_zero_executions() {
    let trace = FusedTrace::new("fn_test", epoch(1));
    assert_eq!(trace.side_exit_ratio_millionths(), 0);
    assert!(!trace.is_degraded(200_000));
}

#[test]
fn test_fusion_record_audit_trail() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();

    // Successful fusion
    engine.fuse("fn_a", &arith_entries(4, 200, 0), None);
    // Failed fusion (low obs)
    engine.fuse("fn_b", &arith_entries(4, 5, 0), None);

    assert_eq!(engine.record_count(), 2);
    let success = &engine.records[0];
    assert_eq!(success.outcome, FusionOutcome::Formed);
    assert!(success.trace_id.is_some());

    let failure = &engine.records[1];
    assert_eq!(failure.outcome, FusionOutcome::AllMotifsRejected);
    assert!(failure.trace_id.is_none());
}

#[test]
fn test_comparison_branch_fusion() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = cmp_branch_entries(200, 0);
    let outcome = engine.fuse("fn_cmp", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
}

#[test]
fn test_allocation_init_fusion() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    let entries = alloc_init_entries(5, 200, 0);
    let outcome = engine.fuse("fn_alloc", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
}

#[test]
fn test_traces_for_nonexistent_function() {
    let engine = TraceFusionEngine::new(epoch(1));
    assert!(engine.traces_for_function("nonexistent").is_empty());
}

#[test]
fn test_high_savings_threshold_rejects_small_motifs() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.min_net_savings_millionths = 10_000_000; // Very high
    let entries = arith_entries(4, 200, 0);
    let outcome = engine.fuse("fn_test", &entries, None);
    assert!(matches!(outcome, FusionOutcome::InsufficientSavings { .. }));
}

#[test]
fn test_schema_version_in_trace() {
    let trace = FusedTrace::new("fn_test", epoch(1));
    assert_eq!(trace.schema_version, TRACE_FUSION_SCHEMA_VERSION);
}

#[test]
fn test_trace_with_superblock_source() {
    let trace = FusedTrace::new("fn_test", epoch(1)).with_superblock("sb-abc123");
    assert_eq!(trace.source_superblock_id.as_deref(), Some("sb-abc123"));
}

#[test]
fn test_mixed_stream_partial_fusion_coverage() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();

    let mut entries = vec![];
    // Prefix: LoadInt (non-fusible)
    entries.push(InstructionEntry {
        offset: 0, opcode: "LoadInt".into(), execution_count: 200,
        type_stability_millionths: 1_000_000, has_side_effects: false,
        capabilities: BTreeSet::new(),
    });
    // Arith chain (fusible)
    for i in 1..=4 {
        entries.push(InstructionEntry {
            offset: i * 4, opcode: ["Add", "Sub", "Mul", "Div"][(i as usize - 1) % 4].into(),
            execution_count: 200, type_stability_millionths: 950_000,
            has_side_effects: false, capabilities: BTreeSet::new(),
        });
    }
    // Suffix: Return (non-fusible)
    entries.push(InstructionEntry {
        offset: 20, opcode: "Return".into(), execution_count: 200,
        type_stability_millionths: 1_000_000, has_side_effects: false,
        capabilities: BTreeSet::new(),
    });

    let outcome = engine.fuse("fn_mixed", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
    let trace = engine.active_traces.values().next().unwrap();
    // Should have passthrough + super + passthrough
    assert!(trace.instruction_count() < entries.len());
    assert!(trace.super_instruction_count() >= 1);
}

#[test]
fn test_guard_count_respects_policy_limit() {
    let mut engine = TraceFusionEngine::new(epoch(1));
    engine.policy = relaxed_policy();
    engine.policy.max_guards = 1;
    engine.policy.max_traces_per_function = 10;
    engine.policy.max_motifs_per_trace = 10;

    // Two separate fusible regions
    let mut entries = arith_entries(4, 200, 0);
    entries.push(InstructionEntry {
        offset: 16, opcode: "LoadInt".into(), execution_count: 200,
        type_stability_millionths: 1_000_000, has_side_effects: false,
        capabilities: BTreeSet::new(),
    });
    entries.extend(prop_chain_entries(3, 200, 20));

    let outcome = engine.fuse("fn_test", &entries, None);
    assert_eq!(outcome, FusionOutcome::Formed);
    let trace = engine.active_traces.values().next().unwrap();
    assert!(trace.guard_count() <= 1);
}
