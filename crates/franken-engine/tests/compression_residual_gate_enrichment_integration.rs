//! Enrichment integration tests for `compression_residual_gate`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default coverage, JSON field-name stability,
//! std::error::Error trait, computation methods, ledger operations, gate
//! evaluation paths, all claim surfaces, blocking reasons, caveats.
#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeSet;

use frankenengine_engine::compression_residual_gate::{
    ArtifactRecord, BuildArtifactInput, COMPRESSION_RESIDUAL_GATE_BEAD_ID,
    COMPRESSION_RESIDUAL_GATE_COMPONENT, COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION,
    ClaimBlockingReason, ClaimSurface, CompressionClaimVerdict, CompressionPassKind,
    CompressionPassResult, CompressionResidualError, CompressionResidualGate, DecisionReceipt,
    GateConfig, GateInput, GateSummary, HiddenExpansionRecord, LedgerAppendInput, ResidualLedger,
    ReversibilityCheck, SupportCostRecord, build_artifact_record, build_pass_result,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ──────────────────────────────────────────────────────────

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn ts() -> u64 {
    1_000_000_000
}

fn make_artifact(id: &str, orig: u64, comp: u64, reversible: bool) -> ArtifactRecord {
    build_artifact_record(&BuildArtifactInput {
        artifact_id: id.to_string(),
        original_size: orig,
        compressed_size: comp,
        pass_kind: CompressionPassKind::Deduplication,
        reversible,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    })
}

fn make_pass(artifacts: Vec<ArtifactRecord>) -> CompressionPassResult {
    build_pass_result(
        "pass-1",
        CompressionPassKind::Deduplication,
        artifacts,
        epoch(),
        ts(),
    )
}

fn make_reversibility_check(id: &str, exact: bool) -> ReversibilityCheck {
    let hash = ContentHash::compute(id.as_bytes());
    ReversibilityCheck {
        artifact_id: id.to_string(),
        original_hash: hash,
        restored_hash: if exact {
            hash
        } else {
            ContentHash::compute(b"different")
        },
        exact_match: exact,
        fidelity_millionths: if exact { 1_000_000 } else { 900_000 },
        divergent_bytes: if exact { 0 } else { 100 },
        total_bytes: 1000,
        restoration_time_us: 50,
    }
}

fn make_hidden_expansion(id: &str, saved: u64, hidden: u64) -> HiddenExpansionRecord {
    let net = saved as i64 - hidden as i64;
    HiddenExpansionRecord {
        source_id: id.to_string(),
        memory_saved_bytes: saved,
        hidden_cost_bytes: hidden,
        net_change_bytes: net,
        cost_explanation: "test expansion".to_string(),
    }
}

fn make_support_cost(id: &str, baseline: i64, overhead: i64) -> SupportCostRecord {
    SupportCostRecord {
        source_id: id.to_string(),
        baseline_cost_millionths: baseline,
        compression_overhead_millionths: overhead,
        indirection_layers: 1,
        debug_readable: true,
        stack_traces_accurate: true,
        explanation: "test cost".to_string(),
    }
}

fn make_ledger_input(id: &str, orig: u64, comp: u64, reversible: bool) -> LedgerAppendInput {
    LedgerAppendInput {
        artifact_id: id.to_string(),
        pass_kind: CompressionPassKind::Deduplication,
        original_size_bytes: orig,
        compressed_size_bytes: comp,
        duplicate_mass_removed_bytes: 10,
        duplicate_mass_remaining_bytes: 2,
        reversible,
        bytes_lost: if reversible {
            0
        } else {
            orig.saturating_sub(comp)
        },
        restoration_overhead_us: 100,
        epoch: epoch(),
        timestamp_ns: ts(),
    }
}

fn cold_start_input(pass: CompressionPassResult) -> GateInput {
    GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: vec![pass],
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 0,
    }
}

fn memory_input(pass: CompressionPassResult, expansions: Vec<HiddenExpansionRecord>) -> GateInput {
    GateInput {
        surface: ClaimSurface::Memory,
        pass_results: vec![pass],
        hidden_expansions: expansions,
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 0,
        proof_total_size_bytes: 0,
    }
}

fn proof_input(pass: CompressionPassResult) -> GateInput {
    GateInput {
        surface: ClaimSurface::ProofSurface,
        pass_results: vec![pass],
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 0,
        proof_total_size_bytes: 10_000,
    }
}

// -----------------------------------------------------------------------
// 1. Copy semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_copy() {
    let a = ClaimSurface::ColdStart;
    let b = a;
    assert_eq!(a, b);
    let c = ClaimSurface::Memory;
    let d = c;
    assert_eq!(c, d);
    let e = ClaimSurface::ProofSurface;
    let f = e;
    assert_eq!(e, f);
}

#[test]
fn enrichment_compression_pass_kind_copy() {
    let a = CompressionPassKind::Deduplication;
    let b = a;
    assert_eq!(a, b);
    let c = CompressionPassKind::SemanticFolding;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_compression_claim_verdict_copy() {
    let a = CompressionClaimVerdict::Approved;
    let b = a;
    assert_eq!(a, b);
    let c = CompressionClaimVerdict::Blocked;
    let d = c;
    assert_eq!(c, d);
}

// -----------------------------------------------------------------------
// 2. Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_artifact_record_clone_independence() {
    let a = make_artifact("art1", 1000, 500, true);
    let mut b = a.clone();
    b.artifact_id = "art2".to_string();
    b.original_size_bytes = 2000;
    assert_eq!(a.artifact_id, "art1");
    assert_eq!(a.original_size_bytes, 1000);
}

#[test]
fn enrichment_hidden_expansion_clone_independence() {
    let a = make_hidden_expansion("src1", 1000, 200);
    let mut b = a.clone();
    b.source_id = "src2".to_string();
    b.hidden_cost_bytes = 999;
    assert_eq!(a.source_id, "src1");
    assert_eq!(a.hidden_cost_bytes, 200);
}

#[test]
fn enrichment_support_cost_clone_independence() {
    let a = make_support_cost("s1", 100_000, 20_000);
    let mut b = a.clone();
    b.source_id = "s2".to_string();
    b.indirection_layers = 5;
    assert_eq!(a.source_id, "s1");
    assert_eq!(a.indirection_layers, 1);
}

#[test]
fn enrichment_reversibility_check_clone_independence() {
    let a = make_reversibility_check("rc1", true);
    let mut b = a.clone();
    b.artifact_id = "rc2".to_string();
    b.exact_match = false;
    assert_eq!(a.artifact_id, "rc1");
    assert!(a.exact_match);
}

#[test]
fn enrichment_gate_config_clone_independence() {
    let a = GateConfig::default();
    let mut b = a.clone();
    b.require_full_reversibility = false;
    b.max_cold_start_restoration_us = 999;
    assert!(a.require_full_reversibility);
    assert_eq!(a.max_cold_start_restoration_us, 500_000);
    assert!(!b.require_full_reversibility);
    assert_eq!(b.max_cold_start_restoration_us, 999);
}

#[test]
fn enrichment_compression_pass_result_clone_independence() {
    let art = make_artifact("a1", 1000, 500, true);
    let a = make_pass(vec![art]);
    let mut b = a.clone();
    b.pass_id = "pass-2".to_string();
    assert_eq!(a.pass_id, "pass-1");
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(ClaimSurface::ProofSurface);
    set.insert(ClaimSurface::ColdStart);
    set.insert(ClaimSurface::Memory);
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(ordered[0], ClaimSurface::ColdStart);
}

#[test]
fn enrichment_compression_pass_kind_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(CompressionPassKind::SemanticFolding);
    set.insert(CompressionPassKind::Deduplication);
    set.insert(CompressionPassKind::EntropyCoding);
    set.insert(CompressionPassKind::Deduplication); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_verdict_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(CompressionClaimVerdict::Blocked);
    set.insert(CompressionClaimVerdict::Approved);
    set.insert(CompressionClaimVerdict::Insufficient);
    set.insert(CompressionClaimVerdict::ApprovedWithCaveats);
    assert_eq!(set.len(), 4);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_serde_roundtrip() {
    for surface in ClaimSurface::ALL {
        let json = serde_json::to_string(&surface).unwrap();
        let back: ClaimSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(back, surface);
    }
}

#[test]
fn enrichment_compression_pass_kind_serde_roundtrip() {
    let kinds = [
        CompressionPassKind::Deduplication,
        CompressionPassKind::StructuralSharing,
        CompressionPassKind::DeltaEncoding,
        CompressionPassKind::EntropyCoding,
        CompressionPassKind::ProofCompaction,
        CompressionPassKind::SemanticFolding,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).unwrap();
        let back: CompressionPassKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn enrichment_verdict_serde_roundtrip() {
    let verdicts = [
        CompressionClaimVerdict::Approved,
        CompressionClaimVerdict::ApprovedWithCaveats,
        CompressionClaimVerdict::Blocked,
        CompressionClaimVerdict::Insufficient,
    ];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let back: CompressionClaimVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn enrichment_artifact_record_serde_roundtrip() {
    let rec = make_artifact("a1", 2000, 800, true);
    let json = serde_json::to_string(&rec).unwrap();
    let back: ArtifactRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn enrichment_hidden_expansion_serde_roundtrip() {
    let rec = make_hidden_expansion("src1", 5000, 500);
    let json = serde_json::to_string(&rec).unwrap();
    let back: HiddenExpansionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn enrichment_support_cost_serde_roundtrip() {
    let rec = make_support_cost("s1", 200_000, 50_000);
    let json = serde_json::to_string(&rec).unwrap();
    let back: SupportCostRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn enrichment_reversibility_check_serde_roundtrip() {
    let rec = make_reversibility_check("rc1", true);
    let json = serde_json::to_string(&rec).unwrap();
    let back: ReversibilityCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rec);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn enrichment_compression_pass_result_serde_roundtrip() {
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let json = serde_json::to_string(&pass).unwrap();
    let back: CompressionPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pass);
}

#[test]
fn enrichment_residual_ledger_serde_roundtrip() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    let json = serde_json::to_string(&ledger).unwrap();
    let back: ResidualLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ledger);
}

#[test]
fn enrichment_gate_serde_roundtrip() {
    let gate = CompressionResidualGate::new();
    let json = serde_json::to_string(&gate).unwrap();
    let back: CompressionResidualGate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, gate);
}

#[test]
fn enrichment_gate_summary_serde_roundtrip() {
    let gate = CompressionResidualGate::new();
    let summary = gate.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: GateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

#[test]
fn enrichment_error_serde_roundtrip() {
    let err = CompressionResidualError::LedgerFull {
        count: 10_000,
        max: 10_000,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: CompressionResidualError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn enrichment_claim_blocking_reason_serde_roundtrip() {
    let reasons = [
        ClaimBlockingReason::NoCompressionData,
        ClaimBlockingReason::IrreversibleArtifact {
            artifact_id: "x".to_string(),
        },
        ClaimBlockingReason::DecompressionCostExceedsBudget {
            observed_millionths: 100_000,
            budget_millionths: 50_000,
        },
        ClaimBlockingReason::NetMemoryExpansion {
            net_change_bytes: -500,
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: ClaimBlockingReason = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, reason);
    }
}

#[test]
fn enrichment_build_artifact_input_serde_roundtrip() {
    let input = BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::DeltaEncoding,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: BuildArtifactInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);
}

// -----------------------------------------------------------------------
// 5. Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_display() {
    assert_eq!(ClaimSurface::ColdStart.to_string(), "cold_start");
    assert_eq!(ClaimSurface::Memory.to_string(), "memory");
    assert_eq!(ClaimSurface::ProofSurface.to_string(), "proof_surface");
}

#[test]
fn enrichment_compression_pass_kind_display() {
    assert_eq!(
        CompressionPassKind::Deduplication.to_string(),
        "deduplication"
    );
    assert_eq!(
        CompressionPassKind::StructuralSharing.to_string(),
        "structural_sharing"
    );
    assert_eq!(
        CompressionPassKind::DeltaEncoding.to_string(),
        "delta_encoding"
    );
    assert_eq!(
        CompressionPassKind::EntropyCoding.to_string(),
        "entropy_coding"
    );
    assert_eq!(
        CompressionPassKind::ProofCompaction.to_string(),
        "proof_compaction"
    );
    assert_eq!(
        CompressionPassKind::SemanticFolding.to_string(),
        "semantic_folding"
    );
}

#[test]
fn enrichment_verdict_display() {
    assert_eq!(CompressionClaimVerdict::Approved.to_string(), "approved");
    assert_eq!(
        CompressionClaimVerdict::ApprovedWithCaveats.to_string(),
        "approved_with_caveats"
    );
    assert_eq!(CompressionClaimVerdict::Blocked.to_string(), "blocked");
    assert_eq!(
        CompressionClaimVerdict::Insufficient.to_string(),
        "insufficient"
    );
}

#[test]
fn enrichment_claim_blocking_reason_display_all_variants() {
    let reasons = [
        ClaimBlockingReason::DecompressionCostExceedsBudget {
            observed_millionths: 80_000,
            budget_millionths: 50_000,
        },
        ClaimBlockingReason::HiddenExpansionExceedsThreshold {
            observed_millionths: 150_000,
            threshold_millionths: 100_000,
        },
        ClaimBlockingReason::ProofOverheadExceedsThreshold {
            observed_millionths: 200_000,
            threshold_millionths: 150_000,
        },
        ClaimBlockingReason::ExcessiveDuplicateMass {
            remaining_millionths: 300_000,
            max_millionths: 200_000,
        },
        ClaimBlockingReason::IrreversibleArtifact {
            artifact_id: "art-x".to_string(),
        },
        ClaimBlockingReason::InsufficientFidelity {
            artifact_id: "art-y".to_string(),
            fidelity_millionths: 900_000,
            required_millionths: 999_000,
        },
        ClaimBlockingReason::SupportCostCeilingExceeded {
            observed_millionths: 250_000,
            ceiling_millionths: 200_000,
        },
        ClaimBlockingReason::NoCompressionData,
        ClaimBlockingReason::NetMemoryExpansion {
            net_change_bytes: -500,
        },
        ClaimBlockingReason::DebugReadabilityLost {
            source_id: "src-z".to_string(),
        },
        ClaimBlockingReason::StackTraceAccuracyLost {
            source_id: "src-w".to_string(),
        },
    ];
    for reason in &reasons {
        let s = reason.to_string();
        assert!(!s.is_empty(), "Display for {:?} is empty", reason);
    }
}

#[test]
fn enrichment_error_display() {
    let errs = [
        CompressionResidualError::LedgerFull {
            count: 10_000,
            max: 10_000,
        },
        CompressionResidualError::TooManyArtifacts {
            count: 1_001,
            max: 1_000,
        },
        CompressionResidualError::InvalidConfig {
            reason: "negative budget".to_string(),
        },
        CompressionResidualError::EmptyInput {
            context: "no passes".to_string(),
        },
    ];
    for err in &errs {
        let s = err.to_string();
        assert!(!s.is_empty());
    }
}

// -----------------------------------------------------------------------
// 6. std::error::Error trait
// -----------------------------------------------------------------------

#[test]
fn enrichment_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CompressionResidualError::LedgerFull {
        count: 100,
        max: 100,
    });
    assert!(!err.to_string().is_empty());
}

// -----------------------------------------------------------------------
// 7. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_debug() {
    for s in ClaimSurface::ALL {
        assert!(!format!("{s:?}").is_empty());
    }
}

#[test]
fn enrichment_compression_pass_kind_debug() {
    let kinds = [
        CompressionPassKind::Deduplication,
        CompressionPassKind::StructuralSharing,
        CompressionPassKind::DeltaEncoding,
        CompressionPassKind::EntropyCoding,
        CompressionPassKind::ProofCompaction,
        CompressionPassKind::SemanticFolding,
    ];
    for k in kinds {
        assert!(!format!("{k:?}").is_empty());
    }
}

#[test]
fn enrichment_verdict_debug() {
    let verdicts = [
        CompressionClaimVerdict::Approved,
        CompressionClaimVerdict::ApprovedWithCaveats,
        CompressionClaimVerdict::Blocked,
        CompressionClaimVerdict::Insufficient,
    ];
    for v in verdicts {
        assert!(!format!("{v:?}").is_empty());
    }
}

#[test]
fn enrichment_artifact_record_debug() {
    let rec = make_artifact("a1", 1000, 500, true);
    assert!(!format!("{rec:?}").is_empty());
}

#[test]
fn enrichment_hidden_expansion_debug() {
    let rec = make_hidden_expansion("src1", 1000, 200);
    assert!(!format!("{rec:?}").is_empty());
}

#[test]
fn enrichment_support_cost_debug() {
    let rec = make_support_cost("s1", 100_000, 20_000);
    assert!(!format!("{rec:?}").is_empty());
}

#[test]
fn enrichment_reversibility_check_debug() {
    let rc = make_reversibility_check("rc1", true);
    assert!(!format!("{rc:?}").is_empty());
}

#[test]
fn enrichment_gate_config_debug() {
    let cfg = GateConfig::default();
    assert!(!format!("{cfg:?}").is_empty());
}

#[test]
fn enrichment_gate_debug() {
    let gate = CompressionResidualGate::new();
    assert!(!format!("{gate:?}").is_empty());
}

#[test]
fn enrichment_gate_summary_debug() {
    let gate = CompressionResidualGate::new();
    let summary = gate.summary();
    assert!(!format!("{summary:?}").is_empty());
}

#[test]
fn enrichment_ledger_debug() {
    let ledger = ResidualLedger::new();
    assert!(!format!("{ledger:?}").is_empty());
}

// -----------------------------------------------------------------------
// 8. Default coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_gate_config_default() {
    let cfg = GateConfig::default();
    assert_eq!(cfg.cold_start_decompression_budget_millionths, 50_000);
    assert_eq!(cfg.memory_hidden_expansion_threshold_millionths, 100_000);
    assert_eq!(cfg.proof_overhead_threshold_millionths, 150_000);
    assert_eq!(cfg.support_cost_ceiling_millionths, 200_000);
    assert_eq!(cfg.reversibility_threshold_millionths, 999_000);
    assert_eq!(cfg.max_duplicate_mass_millionths, 200_000);
    assert!(cfg.require_full_reversibility);
    assert!(cfg.require_debug_readability);
    assert!(cfg.require_stack_trace_accuracy);
    assert_eq!(cfg.max_cold_start_restoration_us, 500_000);
}

#[test]
fn enrichment_residual_ledger_default() {
    let ledger = ResidualLedger::default();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
}

#[test]
fn enrichment_gate_default() {
    let gate = CompressionResidualGate::default();
    assert_eq!(gate.evaluations_run(), 0);
    assert_eq!(gate.claims_approved(), 0);
    assert_eq!(gate.claims_blocked(), 0);
    assert_eq!(gate.claims_with_caveats(), 0);
    assert_eq!(gate.claims_insufficient(), 0);
}

// -----------------------------------------------------------------------
// 9. Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION.is_empty());
    assert!(COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION.contains("compression"));
}

#[test]
fn enrichment_component_nonempty() {
    assert!(!COMPRESSION_RESIDUAL_GATE_COMPONENT.is_empty());
}

#[test]
fn enrichment_bead_id_nonempty() {
    assert!(!COMPRESSION_RESIDUAL_GATE_BEAD_ID.is_empty());
}

#[test]
fn enrichment_claim_surface_all_count() {
    assert_eq!(ClaimSurface::ALL.len(), 3);
}

// -----------------------------------------------------------------------
// 10. ArtifactRecord computation methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_artifact_compression_ratio_2x() {
    let art = make_artifact("a1", 1000, 500, true);
    // 500/1000 = 0.5 => 500_000 millionths
    assert_eq!(art.compression_ratio_millionths(), 500_000);
}

#[test]
fn enrichment_artifact_space_savings() {
    let art = make_artifact("a1", 1000, 500, true);
    // 1 - 0.5 = 0.5 => 500_000 millionths
    assert_eq!(art.space_savings_millionths(), 500_000);
}

#[test]
fn enrichment_artifact_compression_ratio_zero_original() {
    let art = make_artifact("a1", 0, 0, true);
    // Edge case: 0 original => ratio = 1_000_000
    assert_eq!(art.compression_ratio_millionths(), 1_000_000);
}

#[test]
fn enrichment_artifact_remaining_duplicate_mass() {
    let art = make_artifact("a1", 1000, 500, true);
    // duplicates_removed=10, duplicates_remaining=2 => 2/12 = 166_666
    assert_eq!(art.remaining_duplicate_mass_millionths(), 166_666);
}

#[test]
fn enrichment_artifact_remaining_duplicate_mass_zero_total() {
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::EntropyCoding,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 0,
        duplicates_remaining: 0,
    });
    assert_eq!(art.remaining_duplicate_mass_millionths(), 0);
}

// -----------------------------------------------------------------------
// 11. CompressionPassResult computation methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_pass_result_aggregate_ratio() {
    let art1 = make_artifact("a1", 1000, 500, true);
    let art2 = make_artifact("a2", 2000, 800, true);
    let pass = make_pass(vec![art1, art2]);
    // total_original = 3000, total_compressed = 1300 => 1300/3000 = 433_333
    assert_eq!(pass.aggregate_compression_ratio_millionths(), 433_333);
}

#[test]
fn enrichment_pass_result_aggregate_savings() {
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    assert_eq!(pass.aggregate_savings_millionths(), 500_000);
}

#[test]
fn enrichment_pass_result_fully_reversible() {
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    assert!(pass.fully_reversible());
}

#[test]
fn enrichment_pass_result_not_fully_reversible() {
    let art = make_artifact("a1", 1000, 500, false);
    let pass = make_pass(vec![art]);
    assert!(!pass.fully_reversible());
}

#[test]
fn enrichment_pass_result_remaining_duplicate_mass() {
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    // total_dup_removed=10, total_dup_remaining=2 => 2/12
    assert_eq!(pass.remaining_duplicate_mass_millionths(), 166_666);
}

#[test]
fn enrichment_pass_result_zero_original() {
    let art = make_artifact("a1", 0, 0, true);
    let pass = make_pass(vec![art]);
    assert_eq!(pass.aggregate_compression_ratio_millionths(), 1_000_000);
}

// -----------------------------------------------------------------------
// 12. HiddenExpansionRecord computation methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_hidden_expansion_ratio() {
    let rec = make_hidden_expansion("src1", 1000, 200);
    // 200/1000 = 0.2 => 200_000 millionths
    assert_eq!(rec.expansion_ratio_millionths(), 200_000);
}

#[test]
fn enrichment_hidden_expansion_is_net_savings_true() {
    let rec = make_hidden_expansion("src1", 1000, 200);
    assert!(rec.is_net_savings());
}

#[test]
fn enrichment_hidden_expansion_is_net_savings_false() {
    let rec = make_hidden_expansion("src1", 200, 500);
    assert!(!rec.is_net_savings());
}

#[test]
fn enrichment_hidden_expansion_zero_saved_zero_hidden() {
    let rec = make_hidden_expansion("src1", 0, 0);
    assert_eq!(rec.expansion_ratio_millionths(), 0);
}

#[test]
fn enrichment_hidden_expansion_zero_saved_nonzero_hidden() {
    let rec = HiddenExpansionRecord {
        source_id: "src1".to_string(),
        memory_saved_bytes: 0,
        hidden_cost_bytes: 100,
        net_change_bytes: -100,
        cost_explanation: "bad".to_string(),
    };
    // Cap at 2x
    assert_eq!(rec.expansion_ratio_millionths(), 2_000_000);
}

// -----------------------------------------------------------------------
// 13. SupportCostRecord computation methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_support_cost_total() {
    let rec = make_support_cost("s1", 200_000, 50_000);
    assert_eq!(rec.total_cost_millionths(), 250_000);
}

#[test]
fn enrichment_support_cost_overhead_ratio() {
    let rec = make_support_cost("s1", 200_000, 50_000);
    // 50_000/200_000 = 0.25 => 250_000
    assert_eq!(rec.overhead_ratio_millionths(), 250_000);
}

#[test]
fn enrichment_support_cost_zero_baseline_nonzero_overhead() {
    let rec = make_support_cost("s1", 0, 50_000);
    assert_eq!(rec.overhead_ratio_millionths(), 2_000_000);
}

#[test]
fn enrichment_support_cost_zero_baseline_zero_overhead() {
    let rec = make_support_cost("s1", 0, 0);
    assert_eq!(rec.overhead_ratio_millionths(), 0);
}

// -----------------------------------------------------------------------
// 14. ReversibilityCheck
// -----------------------------------------------------------------------

#[test]
fn enrichment_reversibility_meets_threshold_exact() {
    let rc = make_reversibility_check("rc1", true);
    assert!(rc.meets_fidelity_threshold(999_000));
    assert!(rc.meets_fidelity_threshold(1_000_000));
}

#[test]
fn enrichment_reversibility_fails_threshold() {
    let rc = make_reversibility_check("rc1", false);
    // fidelity = 900_000
    assert!(!rc.meets_fidelity_threshold(999_000));
    assert!(rc.meets_fidelity_threshold(900_000));
}

// -----------------------------------------------------------------------
// 15. ResidualLedger operations
// -----------------------------------------------------------------------

#[test]
fn enrichment_ledger_new_is_empty() {
    let ledger = ResidualLedger::new();
    assert!(ledger.is_empty());
    assert_eq!(ledger.len(), 0);
    assert_eq!(ledger.total_original_bytes(), 0);
    assert_eq!(ledger.total_compressed_bytes(), 0);
    assert_eq!(ledger.total_bytes_lost(), 0);
    assert_eq!(ledger.aggregate_compression_ratio_millionths(), 1_000_000);
    assert_eq!(ledger.aggregate_duplicate_mass_millionths(), 0);
    assert_eq!(ledger.distinct_artifact_count(), 0);
    assert!(!ledger.has_irreversible_entries());
    assert_eq!(ledger.irreversible_count(), 0);
    assert_eq!(ledger.total_restoration_overhead_us(), 0);
}

#[test]
fn enrichment_ledger_append_and_query() {
    let mut ledger = ResidualLedger::new();
    let seq = ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    assert_eq!(seq, 0);
    assert_eq!(ledger.len(), 1);
    assert!(!ledger.is_empty());
    assert_eq!(ledger.total_original_bytes(), 1000);
    assert_eq!(ledger.total_compressed_bytes(), 500);
    assert_eq!(ledger.total_bytes_lost(), 0);
    assert_eq!(ledger.distinct_artifact_count(), 1);
    assert!(!ledger.has_irreversible_entries());
}

#[test]
fn enrichment_ledger_append_multiple() {
    let mut ledger = ResidualLedger::new();
    let s0 = ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    let s1 = ledger
        .append(&make_ledger_input("a2", 2000, 800, false))
        .unwrap();
    assert_eq!(s0, 0);
    assert_eq!(s1, 1);
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.distinct_artifact_count(), 2);
    assert!(ledger.has_irreversible_entries());
    assert_eq!(ledger.irreversible_count(), 1);
}

#[test]
fn enrichment_ledger_entries_for_artifact() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    ledger
        .append(&make_ledger_input("a2", 2000, 800, true))
        .unwrap();
    ledger
        .append(&make_ledger_input("a1", 500, 250, true))
        .unwrap();
    let a1_entries = ledger.entries_for_artifact("a1");
    assert_eq!(a1_entries.len(), 2);
    assert_eq!(a1_entries[0].sequence, 0);
    assert_eq!(a1_entries[1].sequence, 2);
    let a2_entries = ledger.entries_for_artifact("a2");
    assert_eq!(a2_entries.len(), 1);
    let missing = ledger.entries_for_artifact("nonexistent");
    assert!(missing.is_empty());
}

#[test]
fn enrichment_ledger_entries_slice() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    let entries = ledger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].artifact_id, "a1");
}

#[test]
fn enrichment_ledger_aggregate_compression_ratio() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&make_ledger_input("a1", 1000, 500, true))
        .unwrap();
    // 500/1000 = 500_000
    assert_eq!(ledger.aggregate_compression_ratio_millionths(), 500_000);
}

#[test]
fn enrichment_ledger_irreversible_bytes_lost() {
    let mut ledger = ResidualLedger::new();
    ledger
        .append(&make_ledger_input("a1", 1000, 600, false))
        .unwrap();
    // bytes_lost = 1000 - 600 = 400
    assert_eq!(ledger.total_bytes_lost(), 400);
}

// -----------------------------------------------------------------------
// 16. Gate config validation
// -----------------------------------------------------------------------

#[test]
fn enrichment_gate_with_config_valid() {
    let cfg = GateConfig::default();
    let gate = CompressionResidualGate::with_config(cfg);
    assert!(gate.is_ok());
}

#[test]
fn enrichment_gate_with_config_negative_cold_start_budget() {
    let mut cfg = GateConfig::default();
    cfg.cold_start_decompression_budget_millionths = -1;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_with_config_negative_memory_threshold() {
    let mut cfg = GateConfig::default();
    cfg.memory_hidden_expansion_threshold_millionths = -1;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_with_config_negative_proof_threshold() {
    let mut cfg = GateConfig::default();
    cfg.proof_overhead_threshold_millionths = -1;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_with_config_negative_support_ceiling() {
    let mut cfg = GateConfig::default();
    cfg.support_cost_ceiling_millionths = -1;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_with_config_reversibility_above_million() {
    let mut cfg = GateConfig::default();
    cfg.reversibility_threshold_millionths = 1_000_001;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

#[test]
fn enrichment_gate_with_config_negative_duplicate_mass() {
    let mut cfg = GateConfig::default();
    cfg.max_duplicate_mass_millionths = -1;
    let result = CompressionResidualGate::with_config(cfg);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 17. Gate evaluation — approved cold-start claim
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_cold_start_approved() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
    assert!(receipt.blocking_reasons.is_empty());
    assert!(receipt.caveats.is_empty());
    assert_eq!(receipt.surface, ClaimSurface::ColdStart);
    assert_eq!(gate.evaluations_run(), 1);
    assert_eq!(gate.claims_approved(), 1);
}

#[test]
fn enrichment_evaluate_receipt_fields_populated() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.schema_version,
        COMPRESSION_RESIDUAL_GATE_SCHEMA_VERSION
    );
    assert_eq!(receipt.component, COMPRESSION_RESIDUAL_GATE_COMPONENT);
    assert_eq!(receipt.bead_id, COMPRESSION_RESIDUAL_GATE_BEAD_ID);
    assert_eq!(receipt.passes_considered, 1);
    assert_eq!(receipt.artifacts_considered, 1);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.timestamp_ns, ts());
}

// -----------------------------------------------------------------------
// 18. Gate evaluation — insufficient (no data)
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_insufficient_no_passes() {
    let mut gate = CompressionResidualGate::new();
    let input = GateInput {
        surface: ClaimSurface::ColdStart,
        pass_results: Vec::new(),
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 0,
    };
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Insufficient);
    assert_eq!(gate.claims_insufficient(), 1);
}

// -----------------------------------------------------------------------
// 19. Gate evaluation — blocked by irreversible artifact
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_blocked_irreversible() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, false);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::IrreversibleArtifact { .. }))
    );
    assert_eq!(gate.claims_blocked(), 1);
}

// -----------------------------------------------------------------------
// 20. Gate evaluation — blocked by fidelity
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_blocked_low_fidelity() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let mut input = cold_start_input(pass);
    input.reversibility_checks = vec![make_reversibility_check("a1", false)];
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::InsufficientFidelity { .. }))
    );
}

// -----------------------------------------------------------------------
// 21. Memory surface — hidden expansion blocks
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_memory_hidden_expansion_blocks() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    // hidden cost exceeds 10% threshold: 200/1000 = 20%
    let exp = make_hidden_expansion("src1", 1000, 200);
    let input = memory_input(pass, vec![exp]);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(receipt.blocking_reasons.iter().any(|r| matches!(
        r,
        ClaimBlockingReason::HiddenExpansionExceedsThreshold { .. }
    )));
}

#[test]
fn enrichment_evaluate_memory_net_expansion_blocks() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    // net expansion: hidden > saved
    let exp = make_hidden_expansion("src1", 200, 500);
    let input = memory_input(pass, vec![exp]);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Blocked);
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::NetMemoryExpansion { .. }))
    );
}

// -----------------------------------------------------------------------
// 22. Memory surface — debug readability lost blocks
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_memory_debug_readability_lost() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let mut input = memory_input(pass, Vec::new());
    input.support_costs = vec![SupportCostRecord {
        source_id: "s1".to_string(),
        baseline_cost_millionths: 100_000,
        compression_overhead_millionths: 10_000,
        indirection_layers: 1,
        debug_readable: false, // not readable
        stack_traces_accurate: true,
        explanation: "test".to_string(),
    }];
    let receipt = gate.evaluate(&input).unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::DebugReadabilityLost { .. }))
    );
}

// -----------------------------------------------------------------------
// 23. Support cost ceiling exceeded
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_support_cost_ceiling_exceeded() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let mut input = cold_start_input(pass);
    // overhead / baseline = 300_000 / 100_000 = 3.0 => 3_000_000 millionths > 200_000 ceiling
    input.support_costs = vec![make_support_cost("s1", 100_000, 300_000)];
    let receipt = gate.evaluate(&input).unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::SupportCostCeilingExceeded { .. }))
    );
}

// -----------------------------------------------------------------------
// 24. Stack trace accuracy lost blocks
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_stack_trace_accuracy_lost() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let mut input = cold_start_input(pass);
    input.support_costs = vec![SupportCostRecord {
        source_id: "s1".to_string(),
        baseline_cost_millionths: 100_000,
        compression_overhead_millionths: 10_000,
        indirection_layers: 1,
        debug_readable: true,
        stack_traces_accurate: false,
        explanation: "test".to_string(),
    }];
    let receipt = gate.evaluate(&input).unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::StackTraceAccuracyLost { .. }))
    );
}

// -----------------------------------------------------------------------
// 25. Proof surface evaluation
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_proof_surface_approved() {
    let mut gate = CompressionResidualGate::new();
    // compressed < original => no overhead
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = proof_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(receipt.verdict, CompressionClaimVerdict::Approved);
}

#[test]
fn enrichment_evaluate_proof_surface_overhead_blocks() {
    let mut gate = CompressionResidualGate::new();
    // compressed > original => overhead = 3000-1000 = 2000 bytes
    // overhead ratio = 2000/10000 = 200_000 > 150_000 threshold
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 3000,
        pass_kind: CompressionPassKind::ProofCompaction,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    let pass = build_pass_result(
        "pass-1",
        CompressionPassKind::ProofCompaction,
        vec![art],
        epoch(),
        ts(),
    );
    let input = proof_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::ProofOverheadExceedsThreshold { .. }))
    );
}

// -----------------------------------------------------------------------
// 26. Cold-start decompression budget exceeded
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_cold_start_decompression_exceeds_budget() {
    let mut gate = CompressionResidualGate::new();
    // restoration_us per artifact = high => exceeds ratio
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100_000, // 100ms of 1s budget = 10% > 5% threshold
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    let pass = build_pass_result(
        "pass-1",
        CompressionPassKind::Deduplication,
        vec![art],
        epoch(),
        ts(),
    );
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert!(receipt.blocking_reasons.iter().any(|r| matches!(
        r,
        ClaimBlockingReason::DecompressionCostExceedsBudget { .. }
    )));
}

// -----------------------------------------------------------------------
// 27. Evaluate all surfaces
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_all_surfaces() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let template = GateInput {
        surface: ClaimSurface::ColdStart, // ignored by evaluate_all_surfaces
        pass_results: vec![pass],
        hidden_expansions: Vec::new(),
        support_costs: Vec::new(),
        reversibility_checks: Vec::new(),
        epoch: epoch(),
        timestamp_ns: ts(),
        cold_start_total_budget_us: 1_000_000,
        proof_total_size_bytes: 10_000,
    };
    let results = gate.evaluate_all_surfaces(&template).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].surface, ClaimSurface::ColdStart);
    assert_eq!(results[1].surface, ClaimSurface::Memory);
    assert_eq!(results[2].surface, ClaimSurface::ProofSurface);
    assert_eq!(gate.evaluations_run(), 3);
}

// -----------------------------------------------------------------------
// 28. Gate summary
// -----------------------------------------------------------------------

#[test]
fn enrichment_gate_summary_after_evaluations() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    gate.evaluate(&input).unwrap();
    let summary = gate.summary();
    assert_eq!(summary.evaluations_run, 1);
    assert_eq!(summary.claims_approved, 1);
    assert_eq!(summary.ledger_entries, 1);
    assert_eq!(summary.distinct_artifacts, 1);
}

// -----------------------------------------------------------------------
// 29. Receipt hash determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_receipt_hash_deterministic() {
    let mut gate1 = CompressionResidualGate::new();
    let mut gate2 = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass1 = make_pass(vec![art.clone()]);
    let pass2 = make_pass(vec![art]);
    let input1 = cold_start_input(pass1);
    let input2 = cold_start_input(pass2);
    let r1 = gate1.evaluate(&input1).unwrap();
    let r2 = gate2.evaluate(&input2).unwrap();
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

// -----------------------------------------------------------------------
// 30. Ledger records from evaluation
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_populates_ledger() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    gate.evaluate(&input).unwrap();
    assert_eq!(gate.ledger().len(), 1);
    let entries = gate.ledger().entries_for_artifact("a1");
    assert_eq!(entries.len(), 1);
}

// -----------------------------------------------------------------------
// 31. Receipts accumulate
// -----------------------------------------------------------------------

#[test]
fn enrichment_receipts_accumulate() {
    let mut gate = CompressionResidualGate::new();
    for i in 0..3 {
        let art = make_artifact(&format!("a{i}"), 1000, 500, true);
        let pass = make_pass(vec![art]);
        let input = cold_start_input(pass);
        gate.evaluate(&input).unwrap();
    }
    assert_eq!(gate.receipts().len(), 3);
    assert_eq!(gate.evaluations_run(), 3);
}

// -----------------------------------------------------------------------
// 32. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_claim_surface_json_fields() {
    let json = serde_json::to_string(&ClaimSurface::ColdStart).unwrap();
    assert!(json.contains("cold_start"));
}

#[test]
fn enrichment_artifact_record_json_fields() {
    let rec = make_artifact("a1", 1000, 500, true);
    let json = serde_json::to_string(&rec).unwrap();
    assert!(json.contains("\"artifact_id\""));
    assert!(json.contains("\"original_size_bytes\""));
    assert!(json.contains("\"compressed_size_bytes\""));
    assert!(json.contains("\"original_hash\""));
    assert!(json.contains("\"compressed_hash\""));
    assert!(json.contains("\"pass_kind\""));
    assert!(json.contains("\"reversible\""));
    assert!(json.contains("\"restoration_overhead_us\""));
}

#[test]
fn enrichment_hidden_expansion_json_fields() {
    let rec = make_hidden_expansion("src1", 1000, 200);
    let json = serde_json::to_string(&rec).unwrap();
    assert!(json.contains("\"source_id\""));
    assert!(json.contains("\"memory_saved_bytes\""));
    assert!(json.contains("\"hidden_cost_bytes\""));
    assert!(json.contains("\"net_change_bytes\""));
    assert!(json.contains("\"cost_explanation\""));
}

#[test]
fn enrichment_support_cost_json_fields() {
    let rec = make_support_cost("s1", 100_000, 20_000);
    let json = serde_json::to_string(&rec).unwrap();
    assert!(json.contains("\"source_id\""));
    assert!(json.contains("\"baseline_cost_millionths\""));
    assert!(json.contains("\"compression_overhead_millionths\""));
    assert!(json.contains("\"indirection_layers\""));
    assert!(json.contains("\"debug_readable\""));
    assert!(json.contains("\"stack_traces_accurate\""));
}

#[test]
fn enrichment_gate_config_json_fields() {
    let cfg = GateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"cold_start_decompression_budget_millionths\""));
    assert!(json.contains("\"memory_hidden_expansion_threshold_millionths\""));
    assert!(json.contains("\"reversibility_threshold_millionths\""));
    assert!(json.contains("\"require_full_reversibility\""));
}

#[test]
fn enrichment_decision_receipt_json_fields() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"blocking_reasons\""));
    assert!(json.contains("\"aggregate_compression_ratio_millionths\""));
    assert!(json.contains("\"receipt_hash\""));
}

#[test]
fn enrichment_gate_summary_json_fields() {
    let gate = CompressionResidualGate::new();
    let summary = gate.summary();
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("\"evaluations_run\""));
    assert!(json.contains("\"claims_approved\""));
    assert!(json.contains("\"claims_blocked\""));
    assert!(json.contains("\"ledger_entries\""));
    assert!(json.contains("\"total_bytes_lost\""));
}

// -----------------------------------------------------------------------
// 33. Caveats path — approaching but not exceeding threshold
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_cold_start_caveats() {
    let mut gate = CompressionResidualGate::new();
    // restoration = 40_000us out of 1_000_000us budget = 40_000 millionths
    // budget threshold = 50_000, 3/4 of that = 37_500
    // 40_000 > 37_500 so we get a caveat but not a block
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 40_000,
        duplicates_removed: 10,
        duplicates_remaining: 2,
    });
    let pass = build_pass_result(
        "pass-1",
        CompressionPassKind::Deduplication,
        vec![art],
        epoch(),
        ts(),
    );
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert_eq!(
        receipt.verdict,
        CompressionClaimVerdict::ApprovedWithCaveats
    );
    assert!(!receipt.caveats.is_empty());
    assert_eq!(gate.claims_with_caveats(), 1);
}

// -----------------------------------------------------------------------
// 34. Excessive duplicate mass blocks
// -----------------------------------------------------------------------

#[test]
fn enrichment_evaluate_excessive_duplicate_mass() {
    let mut gate = CompressionResidualGate::new();
    // Make artifact with high remaining duplicates
    let art = build_artifact_record(&BuildArtifactInput {
        artifact_id: "a1".to_string(),
        original_size: 1000,
        compressed_size: 500,
        pass_kind: CompressionPassKind::Deduplication,
        reversible: true,
        restoration_us: 100,
        duplicates_removed: 1,
        duplicates_remaining: 10, // 10/(1+10) ≈ 909_090 > 200_000 threshold
    });
    let pass = build_pass_result(
        "pass-1",
        CompressionPassKind::Deduplication,
        vec![art],
        epoch(),
        ts(),
    );
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    assert!(
        receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::ExcessiveDuplicateMass { .. }))
    );
}

// -----------------------------------------------------------------------
// 35. Decision receipt serde roundtrip
// -----------------------------------------------------------------------

#[test]
fn enrichment_decision_receipt_serde_roundtrip() {
    let mut gate = CompressionResidualGate::new();
    let art = make_artifact("a1", 1000, 500, true);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// -----------------------------------------------------------------------
// 36. build_artifact_record helper
// -----------------------------------------------------------------------

#[test]
fn enrichment_build_artifact_record_fields() {
    let input = BuildArtifactInput {
        artifact_id: "test-art".to_string(),
        original_size: 5000,
        compressed_size: 2000,
        pass_kind: CompressionPassKind::StructuralSharing,
        reversible: false,
        restoration_us: 500,
        duplicates_removed: 20,
        duplicates_remaining: 5,
    };
    let rec = build_artifact_record(&input);
    assert_eq!(rec.artifact_id, "test-art");
    assert_eq!(rec.original_size_bytes, 5000);
    assert_eq!(rec.compressed_size_bytes, 2000);
    assert_eq!(rec.pass_kind, CompressionPassKind::StructuralSharing);
    assert!(!rec.reversible);
    assert_eq!(rec.restoration_overhead_us, 500);
    assert_eq!(rec.duplicates_removed, 20);
    assert_eq!(rec.duplicates_remaining, 5);
}

// -----------------------------------------------------------------------
// 37. build_pass_result helper
// -----------------------------------------------------------------------

#[test]
fn enrichment_build_pass_result_aggregates() {
    let art1 = make_artifact("a1", 1000, 500, true);
    let art2 = make_artifact("a2", 2000, 800, false);
    let pass = build_pass_result(
        "p1",
        CompressionPassKind::DeltaEncoding,
        vec![art1, art2],
        epoch(),
        ts(),
    );
    assert_eq!(pass.pass_id, "p1");
    assert_eq!(pass.pass_kind, CompressionPassKind::DeltaEncoding);
    assert_eq!(pass.total_original_bytes, 3000);
    assert_eq!(pass.total_compressed_bytes, 1300);
    assert_eq!(pass.total_restoration_overhead_us, 200);
    assert_eq!(pass.total_duplicates_removed, 20);
    assert_eq!(pass.total_duplicates_remaining, 4);
    assert_eq!(pass.reversible_count, 1);
    assert_eq!(pass.irreversible_count, 1);
}

// -----------------------------------------------------------------------
// 38. Relaxed config allows claims that default config blocks
// -----------------------------------------------------------------------

#[test]
fn enrichment_relaxed_config_allows_irreversible() {
    let mut cfg = GateConfig::default();
    cfg.require_full_reversibility = false;
    let mut gate = CompressionResidualGate::with_config(cfg).unwrap();
    let art = make_artifact("a1", 1000, 500, false);
    let pass = make_pass(vec![art]);
    let input = cold_start_input(pass);
    let receipt = gate.evaluate(&input).unwrap();
    // Irreversibility no longer blocks, but low fidelity might...
    // Actually the pass itself has no reversibility_checks, so only IrreversibleArtifact matters.
    assert!(
        !receipt
            .blocking_reasons
            .iter()
            .any(|r| matches!(r, ClaimBlockingReason::IrreversibleArtifact { .. }))
    );
}
